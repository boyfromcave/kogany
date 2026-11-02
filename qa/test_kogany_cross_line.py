#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .
"""Tests for qa/yellowback-cross-line.py (run: python3 -m unittest discover -s qa -p 'test_kogany_*.py')."""

import hashlib
import importlib.util
import io
import os
import tempfile
import unittest
from contextlib import redirect_stdout

HERE = os.path.dirname(os.path.abspath(__file__))


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, os.path.join(HERE, filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


cross_line = load("yellowback_cross_line", "yellowback-cross-line.py")


class CrossLineTest(unittest.TestCase):
    def tree(self, files, pin_rows):
        root = tempfile.mkdtemp()
        os.makedirs(os.path.join(root, cross_line.VECTOR_DIR))
        for name, data in files.items():
            with open(os.path.join(root, cross_line.VECTOR_DIR, name), "wb") as f:
                f.write(data)
        with open(os.path.join(root, cross_line.PIN), "w", encoding="utf-8") as f:
            f.write("# header\n" + "".join("%s  %s  %s\n" % row for row in pin_rows))
        return root

    def run_main(self, root):
        out = io.StringIO()
        with redirect_stdout(out):
            code = cross_line.main(["--this-line", "kogany", "--root", root])
        return code, out.getvalue()

    def test_the_pinned_tree_is_identical(self):
        data = b"{}"
        digest = hashlib.sha256(data).hexdigest()
        root = self.tree({"v.json": data, "CHECKLIST.md": b"x"},
                         [(digest, "testdata/yellowback/v.json", "src/test/data/v.json")])
        self.assertEqual(self.run_main(root)[0], 0)

    def test_an_edited_vector_differs(self):
        digest = hashlib.sha256(b"{}").hexdigest()
        root = self.tree({"v.json": b"[]"}, [(digest, "testdata/yellowback/v.json", "src/test/data/v.json")])
        code, out = self.run_main(root)
        self.assertEqual(code, 1)
        self.assertIn("v.json: sha256", out)

    def test_an_unpinned_file_is_a_difference(self):
        data = b"{}"
        digest = hashlib.sha256(data).hexdigest()
        root = self.tree({"v.json": data, "extra.json": data},
                         [(digest, "testdata/yellowback/v.json", "src/test/data/v.json")])
        code, out = self.run_main(root)
        self.assertEqual(code, 1)
        self.assertIn("extra.json: not pinned", out)

    def test_a_malformed_pin_is_a_usage_error(self):
        with self.assertRaises(cross_line.PinError):
            cross_line.parse_pin("abc testdata/yellowback/v.json src/v.json\n")
        with self.assertRaises(cross_line.PinError):
            cross_line.parse_pin("%s elsewhere/v.json src/v.json\n" % ("0" * 64))

    def test_the_real_pin_parses(self):
        with open(os.path.join(HERE, "..", cross_line.PIN), encoding="utf-8") as f:
            rows = cross_line.parse_pin(f.read())
        self.assertEqual(len(rows), 9)


if __name__ == "__main__":
    unittest.main()
