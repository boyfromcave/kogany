#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .
"""Tests for qa/kogany_audit.py (run: python3 -m unittest discover -s qa -p 'test_kogany_*.py')."""

import os
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import kogany_audit as audit  # noqa: E402

# Built from parts, as in kogany_audit.py, so this file does not match the greps leg itself.
RETIRED = "Digi" + "Dollar"
TOOL = "Clau" + "de"


class LineFindingsTest(unittest.TestCase):
    def test_a_retired_name_in_code_is_a_finding(self):
        self.assertEqual(audit.line_findings("let x = %s::new();" % RETIRED), [RETIRED])

    def test_a_citation_of_an_upstream_file_is_allowed(self):
        line = "// as ref/digibyte/src/%s/validation.cpp:120 does" % RETIRED.lower()
        self.assertEqual(audit.line_findings(line), [])

    def test_a_url_is_not_a_citation(self):
        line = "see https://example.org/%s" % RETIRED
        self.assertEqual(audit.line_findings(line), [RETIRED])

    def test_attribution_is_never_allowed(self):
        line = "Co-" + "Authored-By: %s <noreply@example.org>" % TOOL
        self.assertEqual(len(audit.line_findings(line)), 2)
        self.assertEqual(audit.line_findings("path/to/%s.md" % TOOL.upper()), [])
        self.assertEqual(audit.line_findings("docs/%s/notes.md" % TOOL), [TOOL])

    def test_the_retired_rpc_prefix_matches_only_at_a_word_start(self):
        self.assertEqual(audit.line_findings("y" + "d_mint()"), ["y" + "d_"])
        self.assertEqual(audit.line_findings("let ready_set = 1;"), [])


class TestFunctionsTest(unittest.TestCase):
    def test_attributes_and_comments_between_test_and_fn(self):
        text = """
#[test]
fn plain() {}

#[tokio::test(flavor = "multi_thread")]
#[ignore]
// a comment
async fn awaited() {}

#[cfg(test)]
mod tests {}

#[test_case(1)]
fn not_counted(_: u8) {}

proptest! {
    #[test]
    fn property(x in 0u8..) {}
}
"""
        self.assertEqual(audit.test_functions(text), ["plain", "awaited", "property"])


class ListTest(unittest.TestCase):
    def test_prefix_and_glob_entries(self):
        entries = ["crates/zakura-script/", "crates/*/snapshots/*orchard*", "crates/zakura-chain/src/work.rs"]
        self.assertTrue(audit.matches("crates/zakura-script/src/lib.rs", entries))
        self.assertTrue(audit.matches("crates/zakura-rpc/src/methods/tests/snapshots/x_orchard@mainnet.snap", entries))
        self.assertTrue(audit.matches("crates/zakura-chain/src/work.rs", entries))
        self.assertFalse(audit.matches("crates/zakura-chain/src/work/difficulty.rs", entries))

    def test_lock_packages(self):
        lock = ('version = 4\n\n[[package]]\nname = "zakura-protocol"\nversion = "5.0.0-rc.2"\n'
                'source = "registry+https://github.com/rust-lang/crates.io-index"\n\n'
                '[[package]]\nname = "other"\nversion = "1.0.0"\n')
        found = audit.lock_packages(lock, {"zakura-protocol"})
        self.assertEqual(list(found), ["zakura-protocol"])
        self.assertIn('version = "5.0.0-rc.2"', found["zakura-protocol"][0])


class RepositoryTest(unittest.TestCase):
    """The legs against a throwaway repository with a `kogany-legacy` branch."""

    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.repo = self.dir.name
        self.git("init", "-q", "-b", "kogany-legacy")
        self.git("config", "user.name", "test")
        self.git("config", "user.email", "test@example.org")
        self.write("crates/zakura-chain/src/lib.rs", "#[test]\nfn kept() {}\n#[test]\nfn dropped() {}\n")
        self.write("crates/zakura-chain/src/orchard.rs", "pub struct Action;\n")
        self.write("qa/kogany-consensus-paths.txt", "crates/zakura-chain/src/orchard.rs\nlock: zakura-protocol\n")
        self.write("qa/kogany-frozen-files.txt", "crates/zakura-chain/src/orchard.rs\n")
        self.write(".github/kogany-workflows.txt", "kept lint.yml reason\n")
        self.write(".github/workflows/lint.yml", "name: Lint\n")
        self.git("add", "-A")
        self.git("commit", "-q", "-m", "upstream")
        self.git("checkout", "-q", "-b", "work")
        self.out = os.path.join(self.repo, "out")

    def tearDown(self):
        self.dir.cleanup()

    def git(self, *args):
        subprocess.run(["git", "-C", self.repo, *args], check=True, capture_output=True)

    def write(self, rel, text):
        path = os.path.join(self.repo, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)

    def run_legs(self, *legs):
        with open(os.devnull, "w") as null:
            stdout, sys.stdout = sys.stdout, null
            try:
                return audit.main(["--repo", self.repo, "--out", self.out, *legs])
            finally:
                sys.stdout = stdout

    def test_a_clean_tree_passes_every_leg(self):
        self.assertEqual(self.run_legs("all"), 0)

    def test_report_only_legs_report_but_pass(self):
        self.write("crates/zakura-chain/src/orchard.rs", "pub struct Action2;\n")
        self.git("commit", "-q", "-am", "touch a frozen consensus file")
        self.assertEqual(self.run_legs("consensus-diff", "frozen"), 0)
        with open(os.path.join(self.out, "frozen.md"), encoding="utf-8") as f:
            self.assertIn("orchard.rs", f.read())
        with open(os.path.join(self.out, "consensus-diff.patch"), encoding="utf-8") as f:
            self.assertIn("Action2", f.read())

    def test_a_deleted_upstream_test_fails_dormancy(self):
        self.write("crates/zakura-chain/src/lib.rs", "#[test]\nfn kept() {}\n")
        self.git("commit", "-q", "-am", "drop a test")
        self.assertEqual(self.run_legs("dormancy"), 1)

    def test_an_added_retired_name_or_attribution_fails_greps(self):
        self.write("crates/zakura-chain/src/new.rs", "// %s\n" % RETIRED)
        self.git("add", "-A")
        self.git("commit", "-q", "-m", "add a file")
        self.assertEqual(self.run_legs("greps"), 1)

    def test_attribution_in_a_commit_message_fails_greps(self):
        self.write("crates/zakura-chain/src/new.rs", "pub fn f() {}\n")
        self.git("add", "-A")
        self.git("commit", "-q", "-m", "add\n\nCo-" + "authored-by: someone")
        self.assertEqual(self.run_legs("greps"), 1)

    def test_an_unclassified_workflow_fails(self):
        self.write(".github/workflows/new.yml", "name: New\n")
        self.assertEqual(self.run_legs("workflows"), 1)


if __name__ == "__main__":
    unittest.main()
