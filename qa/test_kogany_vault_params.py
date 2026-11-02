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
from contextlib import redirect_stdout

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


if __name__ == "__main__":
    unittest.main()
