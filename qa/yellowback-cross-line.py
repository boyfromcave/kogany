#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""Byte identity of kogany's pinned cross-line vectors with the C++ lines (audit leg (c)).

  qa/yellowback-cross-line.py --this-line kogany [--other-dir DIR --other-rev REV]

kogany's counterpart of ycash6's qa/yellowback-cross-line.py (which knows `dd` and `y6`). Its
path map is testdata/yellowback/PIN: each row is `sha256 kogany-path ycash6-path`. The check:

  - every PIN row's kogany file exists and has the pinned SHA-256;
  - testdata/yellowback/ holds exactly the pinned files, PIN and CHECKLIST.md (no unpinned vector);
  - with --other-dir and --other-rev (a ycash6 or ycash-dd checkout and a revision), the other
    line's file at the row's C++ path has the same SHA-256 (`git -C DIR show REV:PATH`).

kogany never generates or edits a vector (plan docs/plans/kogany/kogany-yellowback-plan.md §4.2
rule 4): a change on the C++ lines is one change set with a PIN bump here. Run from the
repository root. Exit 0 when identical, 1 on a difference, 2 on a usage or parse error. Python 3
standard library only.
"""

import argparse
import hashlib
import os
import subprocess
import sys

PIN = "testdata/yellowback/PIN"
VECTOR_DIR = "testdata/yellowback"
# Files in VECTOR_DIR that are kogany's own, not pinned copies.
OWN_FILES = {"PIN", "CHECKLIST.md"}
HEX64 = set("0123456789abcdef")


class PinError(Exception):
    pass


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def parse_pin(text):
    """[(sha256, kogany_path, cxx_path)] of the PIN rows; raises PinError on a malformed row."""
    rows, seen = [], set()
    for lineno, raw in enumerate(text.splitlines(), 1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        fields = line.split()
        if len(fields) != 3:
            raise PinError("%s:%d: want 'sha256 kogany-path ycash6-path'" % (PIN, lineno))
        digest, ours, theirs = fields
        if len(digest) != 64 or set(digest) - HEX64:
            raise PinError("%s:%d: sha256 must be 64 lowercase hex digits" % (PIN, lineno))
        if not ours.startswith(VECTOR_DIR + "/"):
            raise PinError("%s:%d: %s is not under %s/" % (PIN, lineno, ours, VECTOR_DIR))
        if ours in seen:
            raise PinError("%s:%d: %s pinned twice" % (PIN, lineno, ours))
        seen.add(ours)
        rows.append((digest, ours, theirs))
    if not rows:
        raise PinError("%s: no rows" % PIN)
    return rows


def other_blob(other_dir, rev, path):
    proc = subprocess.run(["git", "-C", other_dir, "show", "%s:%s" % (rev, path)],
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if proc.returncode:
        detail = proc.stderr.decode("utf-8", "replace").strip().splitlines()
        return None, detail[-1] if detail else "git show failed"
    return proc.stdout, None


def check(root, rows, other_dir=None, other_rev=None):
    """The list of differences (empty when identical); prints one line per checked file."""
    errors = []
    for digest, ours, theirs in rows:
        try:
            with open(os.path.join(root, ours), "rb") as f:
                here = sha256(f.read())
        except OSError as exc:
            errors.append("%s: missing (%s)" % (ours, exc))
            continue
        if here != digest:
            errors.append("%s: sha256 %s, PIN %s" % (ours, here, digest))
            continue
        if other_dir is not None:
            blob, why = other_blob(other_dir, other_rev, theirs)
            if blob is None:
                errors.append("%s: unreadable on the other line (%s)" % (theirs, why))
                continue
            if sha256(blob) != digest:
                errors.append("%s differs from %s@%s:%s (%s)" % (ours, other_dir, other_rev, theirs, sha256(blob)))
                continue
        print("  identical %s%s" % (ours, "" if other_dir is None else " = %s" % theirs))
    pinned = {os.path.basename(ours) for _, ours, _ in rows}
    try:
        present = set(os.listdir(os.path.join(root, VECTOR_DIR)))
    except OSError as exc:
        errors.append("%s: unreadable (%s)" % (VECTOR_DIR, exc))
        present = set()
    for extra in sorted(present - pinned - OWN_FILES):
        errors.append("%s/%s: not pinned in PIN" % (VECTOR_DIR, extra))
    return errors


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--this-line", required=True, choices=("kogany",))
    parser.add_argument("--other-dir", help="a ycash6 or ycash-dd checkout")
    parser.add_argument("--other-rev", help="the revision of --other-dir to compare with")
    parser.add_argument("--root", default=".", help="the kogany checkout (default: .)")
    args = parser.parse_args(argv)
    if (args.other_dir is None) != (args.other_rev is None):
        parser.error("pass --other-dir and --other-rev together")
    try:
        with open(os.path.join(args.root, PIN), encoding="utf-8") as f:
            rows = parse_pin(f.read())
    except (OSError, PinError) as exc:
        print("  error: %s" % exc)
        return 2
    errors = check(args.root, rows, args.other_dir, args.other_rev)
    print("  summary: %d pinned, %d difference(s)" % (len(rows), len(errors)))
    for msg in errors:
        print("  error: %s" % msg)
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
