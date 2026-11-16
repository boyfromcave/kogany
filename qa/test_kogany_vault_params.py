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

    def test_provisional_height_refuses_rc_and_final_and_passes_beta(self):
        p = vault_params.PROVISIONAL_FAST_YDF_MANDATE_END_HEIGHT
        self.assertEqual(p, 600_000)
        self.assertEqual(vault_params.release_problems(p, "beta"), [])
        for stage in ("rc", "final"):
            problems = vault_params.release_problems(p, stage)
            self.assertEqual(len(problems), 1)
            self.assertIn("provisional 600000", problems[0])

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

    def _tree(self, height):
        d = tempfile.mkdtemp()
        path = os.path.join(d, vault_params.YDF_SOURCE)
        os.makedirs(os.path.dirname(path))
        with open(path, "w", encoding="utf-8") as f:
            f.write(self.SOURCE % height)
        return d

    def test_main_release_exit_codes(self):
        provisional, cut = self._tree("600_000"), self._tree("512_345")
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            self.assertEqual(vault_params.main(["release", "v1.8.0-ycash.beta3", "--root", provisional]), 0)
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
