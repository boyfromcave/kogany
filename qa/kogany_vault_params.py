#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""Compare kogany's Vault chain parameters with a C++ line's (audit leg (d)).

  qa/kogany_vault_params.py compare KOGANY.json CXX.json

KOGANY.json is the output of
`cargo run -p zakura-chain --features ycash --example kogany_vault_params`; CXX.json is ycash6's
(or ycash-dd's) `qa/yellowback-vault-params.py extract`. Every key kogany prints must be present in
CXX.json with the same value; the C++ document's other keys (the protocol version, the Falcon
height, the set maturity, the YED columns, testnet-legacy) are not kogany's yet and are listed as
"not compared". ycash6's own `compare` is strict on both key sets, so it cannot take a kogany
document. Exit 0 when equal, 1 on a difference, 2 on a usage or parse error. Python 3 standard
library only.
"""

import argparse
import json
import sys


def flatten(doc, prefix=""):
    for key, value in sorted(doc.items()):
        if isinstance(value, dict):
            yield from flatten(value, prefix + key + ".")
        else:
            yield prefix + key, value


def compare(kogany, cxx):
    """(differences, not compared): kogany's keys against the C++ document's."""
    ours, theirs = dict(flatten(kogany)), dict(flatten(cxx))
    if not ours:
        raise ValueError("the kogany document has no keys")
    bad = []
    for key, value in sorted(ours.items()):
        if key not in theirs:
            bad.append("%s: %r on kogany, missing on the C++ line" % (key, value))
        elif theirs[key] != value:
            bad.append("%s: %r != %r" % (key, value, theirs[key]))
    return bad, sorted(set(theirs) - set(ours))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    sub = parser.add_subparsers(dest="cmd", required=True)
    cp = sub.add_parser("compare")
    cp.add_argument("kogany")
    cp.add_argument("cxx")
    args = parser.parse_args(argv)
    try:
        with open(args.kogany, encoding="utf-8") as fa, open(args.cxx, encoding="utf-8") as fb:
            kogany, cxx = json.load(fa), json.load(fb)
        bad, skipped = compare(kogany, cxx)
    except (OSError, ValueError) as exc:
        print("kogany_vault_params: %s" % exc, file=sys.stderr)
        return 2
    for key in skipped:
        print("not compared %s" % key)
    for line in bad:
        print("DIFFERENT %s" % line)
    if bad:
        return 1
    print("Vault chain parameters identical on kogany and the C++ line")
    return 0


if __name__ == "__main__":
    sys.exit(main())
