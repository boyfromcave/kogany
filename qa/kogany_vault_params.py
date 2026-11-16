#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""Compare kogany's Vault chain parameters with a C++ line's (audit leg (d)), and guard a release.

  qa/kogany_vault_params.py compare KOGANY.json CXX.json
  qa/kogany_vault_params.py release TAG [--root DIR | --params KOGANY.json]

KOGANY.json is the output of
`cargo run -p zakura-chain --features ycash --example kogany_vault_params`; CXX.json is ycash6's
(or ycash-dd's) `qa/yellowback-vault-params.py extract`. Every key kogany prints must be present in
CXX.json with the same value. Of the C++ document's other keys, those named in `REQUIRED_KEYS`
(`ydf_mandate_end_height`, the cut gate of beta3 item 5) must be printed by kogany too: one kogany
lacks is a difference. The rest (the protocol version, the Falcon height, the set maturity, the
branch ids, the shadow split, the YED columns) are not kogany's yet and are listed as "not
compared". ycash6's own `compare` is strict on both key sets, so it cannot take a kogany document.

`release TAG` is the release guard of `kogany-release.yml` (ycash6's rule R9, `release_problems`
and `r9_applies` in its `qa/yellowback-vault-params.py`): a `-ycash.rcN` or final tag, and a
`-ycash.betaN` tag from v1.8.0-ycash.beta3 on, is refused while testnet-yb-fast's YDF mandate end
is unset or still the provisional 600,000 the tree carries until the release-candidate cut. The
fast testnet runs betas, so a beta that kept the provisional value would never end the mandate
there; v1.8.0-ycash.beta1 and -beta2 predate the value and still pass. The height is read from the source
(`mandate_end::TESTNET_FAST` in `YDF_SOURCE`, under `--root`, default `.`) or, with `--params`,
from an extractor document.

Exit 0 when equal (or the tag may be cut), 1 on a difference (or a refused tag), 2 on a usage or
parse error. Python 3 standard library only.
"""

import argparse
import json
import os
import re
import sys

# The C++ keys kogany must print as well (the last component of a flattened key): a key ycash6
# prints and kogany lacks fails the comparison instead of being "not compared".
REQUIRED_KEYS = ("ydf_mandate_end_height",)

# testnet-yb-fast's mandate end in kogany (beta3 item 5, B3-D4), and the provisional value the tree
# carries until the release-candidate cut (ycash6 qa/yellowback-vault-params.py, the same name).
YDF_SOURCE = "crates/zakura-chain/src/parameters/ycash/ydf.rs"
FAST_YDF_CONSTANT = "mandate_end::TESTNET_FAST"
PROVISIONAL_FAST_YDF_MANDATE_END_HEIGHT = 600000
# The first beta R9 binds (ycash6's R9_BETA_FROM is 6.22.0-beta3, the same cut): (X, Y, Z, N) of
# vX.Y.Z-ycash.betaN.
R9_BETA_FROM = (1, 8, 0, 3)
BETA_TAG = re.compile(r"^v([0-9]+)\.([0-9]+)\.([0-9]+)-ycash\.beta([1-9][0-9]*)\Z")

STAGES = ("beta", "rc", "final")
# kogany's release tags (.github/README-kogany.md, "Cutting a pre-release").
TAG_PATTERN = re.compile(r"^v[0-9]{1,5}\.[0-9]{1,5}\.[0-9]{1,5}-ycash\.(?:(beta|rc)[0-9]{1,5}|[0-9]{1,5})$")


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
    skipped = []
    for key in sorted(set(theirs) - set(ours)):
        if key.rsplit(".", 1)[-1] in REQUIRED_KEYS:
            bad.append("%s: %r on the C++ line, missing on kogany" % (key, theirs[key]))
        else:
            skipped.append(key)
    return bad, skipped


def stage_of(tag):
    """The release stage of a kogany tag (`beta`, `rc` or `final`), or None for any other text."""
    m = TAG_PATTERN.match(tag)
    if m is None:
        return None
    return m.group(1) or "final"


def fast_ydf_end_from_source(text):
    """`mandate_end::TESTNET_FAST`'s height in ydf.rs: exactly one definition, else ValueError."""
    found = re.findall(r"\bpub const TESTNET_FAST: Height = Height\(([0-9_]+)\);", text)
    if len(found) != 1:
        raise ValueError("%s: expected one `pub const TESTNET_FAST: Height = Height(N);`, found %d"
                         % (YDF_SOURCE, len(found)))
    return int(found[0].replace("_", ""))


def fast_ydf_end_from_params(doc):
    """test.fast.ydf_mandate_end_height of an extractor document (None when absent)."""
    return doc.get("test", {}).get("fast", {}).get("ydf_mandate_end_height")


def r9_applies(stage, tag=None):
    """Whether R9 binds a tag at STAGE named TAG (ycash6's `r9_applies`): always on an rc or a final
    tag; on a beta from R9_BETA_FROM on, and on a beta whose tag is not given or not of the
    vX.Y.Z-ycash.betaN shape (the strictest reading: only a beta older than R9_BETA_FROM is exempt)."""
    if stage != "beta":
        return True
    m = BETA_TAG.match(tag or "")
    if not m:
        return True
    return tuple(int(g) for g in m.groups()) >= R9_BETA_FROM


def release_problems(fast_ydf_end, stage, tag=None):
    """Why a tag of STAGE, named TAG when known, may not be cut with this fast-testnet mandate end
    (ycash6's R9)."""
    if stage not in STAGES:
        raise ValueError("unknown release stage %r" % (stage,))
    if not r9_applies(stage, tag):
        return []
    if not isinstance(fast_ydf_end, int) or isinstance(fast_ydf_end, bool) or fast_ydf_end <= 0:
        return ["R9: testnet-yb-fast's YDF mandate end (%s) is unset" % FAST_YDF_CONSTANT]
    if fast_ydf_end == PROVISIONAL_FAST_YDF_MANDATE_END_HEIGHT:
        return ["R9: testnet-yb-fast's YDF mandate end (%s) is still the provisional %d; set it at the "
                "release-candidate cut (the fast-testnet tip plus 400 blocks), the same value as ycash6's"
                % (FAST_YDF_CONSTANT, PROVISIONAL_FAST_YDF_MANDATE_END_HEIGHT)]
    return []


def release(args):
    stage = stage_of(args.tag)
    if stage is None:
        print("kogany_vault_params: %r is not a kogany release tag (v<X.Y.Z>-ycash.<beta|rc><n>)" % args.tag,
              file=sys.stderr)
        return 2
    try:
        if args.params:
            with open(args.params, encoding="utf-8") as f:
                end = fast_ydf_end_from_params(json.load(f))
        else:
            with open(os.path.join(args.root, YDF_SOURCE), encoding="utf-8") as f:
                end = fast_ydf_end_from_source(f.read())
    except (OSError, ValueError) as exc:
        print("kogany_vault_params: %s" % exc, file=sys.stderr)
        return 2
    problems = release_problems(end, stage, args.tag)
    for line in problems:
        print("REFUSED %s: %s" % (args.tag, line))
    if problems:
        return 1
    print("%s (%s): testnet-yb-fast's YDF mandate end is %s; the tag may be cut" % (args.tag, stage, end))
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    sub = parser.add_subparsers(dest="cmd", required=True)
    cp = sub.add_parser("compare")
    cp.add_argument("kogany")
    cp.add_argument("cxx")
    rp = sub.add_parser("release")
    rp.add_argument("tag")
    src = rp.add_mutually_exclusive_group()
    src.add_argument("--root", default=".", help="the kogany tree whose %s is read (default .)" % YDF_SOURCE)
    src.add_argument("--params", help="an extractor document to read test.fast.ydf_mandate_end_height from")
    args = parser.parse_args(argv)
    if args.cmd == "release":
        return release(args)
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
