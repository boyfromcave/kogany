#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .
"""Tests for qa/kogany_vault_params.py (run: python3 -m unittest discover -s qa -p 'test_kogany_*.py')."""

import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import kogany_vault_params as vault_params  # noqa: E402


class VaultParamsTest(unittest.TestCase):
    KOGANY = {"main": {"vault_activation_height": "NO_ACTIVATION_HEIGHT"},
              "test": {"fast": {"vault_activation_height": 510400}}}

    def test_kogany_keys_equal_and_the_rest_not_compared(self):
        cxx = {"main": {"vault_activation_height": "NO_ACTIVATION_HEIGHT", "pq_falcon_height": 0},
               "test": {"fast": {"vault_activation_height": 510400}}, "version": {"PROTOCOL_VERSION": 270200}}
        bad, skipped = vault_params.compare(self.KOGANY, cxx)
        self.assertEqual(bad, [])
        self.assertEqual(skipped, ["main.pq_falcon_height", "version.PROTOCOL_VERSION"])

    def test_a_different_height_is_reported(self):
        cxx = {"main": {"vault_activation_height": 3_100_000}, "test": {"fast": {"vault_activation_height": 510400}}}
        bad, _ = vault_params.compare(self.KOGANY, cxx)
        self.assertEqual(len(bad), 1)
        self.assertIn("main.vault_activation_height", bad[0])

    def test_a_missing_key_is_reported(self):
        bad, _ = vault_params.compare(self.KOGANY, {"main": {"vault_activation_height": "NO_ACTIVATION_HEIGHT"}})
        self.assertEqual(len(bad), 1)
        self.assertIn("missing on the C++ line", bad[0])

    def test_main_exit_codes(self):
        d = tempfile.mkdtemp()
        a, b = os.path.join(d, "a.json"), os.path.join(d, "b.json")
        with open(a, "w") as f:
            json.dump(self.KOGANY, f)
        with open(b, "w") as f:
            json.dump(self.KOGANY, f)
        with redirect_stdout(io.StringIO()):
            self.assertEqual(vault_params.main(["compare", a, b]), 0)
            with open(b, "w") as f:
                json.dump({}, f)
            self.assertEqual(vault_params.main(["compare", a, b]), 1)

    def test_a_ydf_mandate_end_kogany_lacks_fails(self):
        # beta3 item 5's cut gate: ycash6 prints the key, so kogany must, for every network.
        cxx = {"main": {"vault_activation_height": "NO_ACTIVATION_HEIGHT", "ydf_mandate_end_height": 2_275_000},
               "test": {"fast": {"vault_activation_height": 510400, "ydf_mandate_end_height": 600_000}}}
        bad, skipped = vault_params.compare(self.KOGANY, cxx)
        self.assertEqual(skipped, [])
        self.assertEqual(len(bad), 2)
        self.assertTrue(all("missing on kogany" in b for b in bad), bad)
        self.assertIn("test.fast.ydf_mandate_end_height", bad[1])

    def test_a_different_fast_ydf_mandate_end_is_reported(self):
        kogany = {"test": {"fast": {"ydf_mandate_end_height": 512_345}}}
        bad, _ = vault_params.compare(kogany, {"test": {"fast": {"ydf_mandate_end_height": 512_346}}})
        self.assertEqual(bad, ["test.fast.ydf_mandate_end_height: 512345 != 512346"])

    def test_the_real_extractor_shape_compares(self):
        both = {"main": {"vault_activation_height": "NO_ACTIVATION_HEIGHT", "ydf_mandate_end_height": 2_275_000},
                "regtest": {"vault_activation_height": "NO_ACTIVATION_HEIGHT", "ydf_mandate_end_height": 5},
                "test": {s: {"vault_activation_height": "NO_ACTIVATION_HEIGHT", "ydf_mandate_end_height": 2_275_000}
                         for s in ("legacy", "slow")}}
        both["test"]["fast"] = {"vault_activation_height": 510400, "ydf_mandate_end_height": 600_000}
        cxx = json.loads(json.dumps(both))
        cxx["test"]["slow"]["shadow_split_height"] = 3_079_999
        bad, skipped = vault_params.compare(both, cxx)
        self.assertEqual(bad, [])
        self.assertEqual(skipped, ["test.slow.shadow_split_height"])


class ReleaseGuardTest(unittest.TestCase):
    """The rc/final guard on testnet-yb-fast's provisional mandate end (ycash6's R9)."""

    SOURCE = "    pub const TESTNET_FAST: Height = Height(%s);\n"

    def test_stage_of_tags(self):
        self.assertEqual(vault_params.stage_of("v1.8.0-ycash.beta3"), "beta")
        self.assertEqual(vault_params.stage_of("v1.8.0-ycash.rc1"), "rc")
        self.assertEqual(vault_params.stage_of("v1.8.0-ycash.1"), "final")
        for bad in ("v1.8.0", "1.8.0-ycash.rc1", "v1.8.0-ycash.rc", "v1.8.0-ycash.alpha1", "v1.8.0-ycash.rc1 "):
            self.assertIsNone(vault_params.stage_of(bad), bad)

    def test_provisional_height_refuses_rc_and_final(self):
        p = vault_params.PROVISIONAL_FAST_YDF_MANDATE_END_HEIGHT
        self.assertEqual(p, 600_000)
        for stage in ("rc", "final"):
            problems = vault_params.release_problems(p, stage)
            self.assertEqual(len(problems), 1)
            self.assertIn("provisional 600000", problems[0])

    def test_r9_binds_a_beta_from_beta3_on(self):
        # ycash6's R9_BETA_FROM (6.22.0-beta3) and kogany's are the same cut.
        self.assertEqual(vault_params.R9_BETA_FROM, (1, 8, 0, 3))
        p = vault_params.PROVISIONAL_FAST_YDF_MANDATE_END_HEIGHT
        for old in ("v1.8.0-ycash.beta1", "v1.8.0-ycash.beta2", "v1.7.9-ycash.beta9"):
            self.assertFalse(vault_params.r9_applies("beta", old), old)
            self.assertEqual(vault_params.release_problems(p, "beta", old), [], old)
            self.assertEqual(vault_params.release_problems(None, "beta", old), [], old)
        for new in ("v1.8.0-ycash.beta3", "v1.8.0-ycash.beta10", "v1.8.1-ycash.beta1", "v2.0.0-ycash.beta1"):
            self.assertTrue(vault_params.r9_applies("beta", new), new)
            problems = vault_params.release_problems(p, "beta", new)
            self.assertEqual(len(problems), 1, new)
            self.assertIn("provisional 600000", problems[0])
            self.assertIn("unset", vault_params.release_problems(None, "beta", new)[0])
            self.assertEqual(vault_params.release_problems(512_345, "beta", new), [], new)
        # The strictest reading: a beta named by no tag, or by another shape, is bound.
        for unnamed in (None, "", "v1.8.0-ycash.beta02", "1.8.0-ycash.beta1"):
            self.assertTrue(vault_params.r9_applies("beta", unnamed), unnamed)
        self.assertEqual(len(vault_params.release_problems(p, "beta")), 1)
        for stage in ("rc", "final"):
            self.assertTrue(vault_params.r9_applies(stage, "v1.8.0-ycash.beta1"))

    def test_a_set_height_passes_and_an_unset_one_refuses(self):
        self.assertEqual(vault_params.release_problems(512_345, "rc"), [])
        self.assertEqual(vault_params.release_problems(512_345, "final"), [])
        for unset in (None, 0, -1, True, "NO_ACTIVATION_HEIGHT"):
            self.assertIn("unset", vault_params.release_problems(unset, "rc")[0], unset)

    def test_source_parse_is_exact(self):
        self.assertEqual(vault_params.fast_ydf_end_from_source(self.SOURCE % "600_000"), 600_000)
        with self.assertRaises(ValueError):
            vault_params.fast_ydf_end_from_source("")
        with self.assertRaises(ValueError):
            vault_params.fast_ydf_end_from_source(self.SOURCE % "1" + self.SOURCE % "2")

    def test_the_real_source_parses(self):
        root = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
        with open(os.path.join(root, vault_params.YDF_SOURCE), encoding="utf-8") as f:
            self.assertIsInstance(vault_params.fast_ydf_end_from_source(f.read()), int)

    def _tree(self, height, notes=("v1.8.0-ycash.beta3", "v1.8.0-ycash.rc1", "v1.8.0-ycash.1")):
        d = tempfile.mkdtemp()
        path = os.path.join(d, vault_params.YDF_SOURCE)
        os.makedirs(os.path.dirname(path))
        with open(path, "w", encoding="utf-8") as f:
            f.write(self.SOURCE % height)
        os.makedirs(os.path.join(d, "doc", "release-notes"))
        for tag in notes:   # R10: finished notes for every tag a test cuts
            with open(os.path.join(d, vault_params.NOTES_FILE % tag), "w", encoding="utf-8") as f:
                f.write("koganyd %s\n\nThe mandate ends at 512,345.\n" % tag)
        return d

    def test_r10_release_notes(self):
        self.assertEqual(vault_params.notes_problems("koganyd\n\nends at 512,345\n", "n.md"), [])
        for marker in vault_params.NOTES_PLACEHOLDERS:
            self.assertEqual(vault_params.notes_problems("t\n\nx %s y\n" % marker, "n.md"),
                             ["R10: n.md line 3 still holds the placeholder %r" % marker], marker)
        # The forms the beta3 notes carried before the cut.
        for line in ("`<HEIGHT, set at the release-candidate cut>`", "yew `<YEW COMMIT, set at the release>`",
                     "git checkout <YEW COMMIT>"):
            self.assertEqual(len(vault_params.notes_problems(line, "n.md")), 1, line)
        self.assertIn("missing", vault_params.notes_problems(None, "n.md")[0])
        self.assertIn("empty", vault_params.notes_problems("\n", "n.md")[0])
        cut = self._tree("512_345")
        tag = "v1.8.0-ycash.beta3"
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            self.assertEqual(vault_params.main(["release", tag, "--root", cut]), 0)
            with open(os.path.join(cut, vault_params.NOTES_FILE % tag), "a", encoding="utf-8") as f:
                f.write("git checkout <YEW COMMIT>\n")
            self.assertEqual(vault_params.main(["release", tag, "--root", cut]), 1)
            os.remove(os.path.join(cut, vault_params.NOTES_FILE % tag))
            self.assertEqual(vault_params.main(["release", tag, "--root", cut]), 1)
            # beta1 and beta2 predate R10 (and R9): no notes needed.
            self.assertEqual(vault_params.main(["release", "v1.8.0-ycash.beta2", "--root", self._tree("600_000", notes=())]), 0)
        out = io.StringIO()
        with redirect_stdout(out):
            vault_params.main(["release", tag, "--root", cut])
        self.assertIn("R10: no release notes: doc/release-notes/v1.8.0-ycash.beta3.md is missing", out.getvalue())

    def test_main_release_exit_codes(self):
        provisional, cut = self._tree("600_000"), self._tree("512_345")
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            self.assertEqual(vault_params.main(["release", "v1.8.0-ycash.beta2", "--root", provisional]), 0)
            self.assertEqual(vault_params.main(["release", "v1.8.0-ycash.beta3", "--root", provisional]), 1)
            self.assertEqual(vault_params.main(["release", "v1.8.0-ycash.beta3", "--root", cut]), 0)
            self.assertEqual(vault_params.main(["release", "v1.8.0-ycash.rc1", "--root", provisional]), 1)
            self.assertEqual(vault_params.main(["release", "v1.8.0-ycash.1", "--root", provisional]), 1)
            self.assertEqual(vault_params.main(["release", "v1.8.0-ycash.rc1", "--root", cut]), 0)
            self.assertEqual(vault_params.main(["release", "not-a-tag", "--root", cut]), 2)
            self.assertEqual(vault_params.main(["release", "v1.8.0-ycash.rc1", "--root", tempfile.mkdtemp()]), 2)
            params = os.path.join(tempfile.mkdtemp(), "k.json")
            with open(params, "w") as f:
                json.dump({"test": {"fast": {"ydf_mandate_end_height": 600_000}}}, f)
            self.assertEqual(vault_params.main(["release", "v1.8.0-ycash.rc1", "--params", params]), 1)


if __name__ == "__main__":
    unittest.main()
