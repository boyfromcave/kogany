#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .
"""Record the ycash6 verdicts that kogany's vault fuzz replay checks (qa/fuzz/vault/README.md).

  record_verdicts.py [--ycash6-build DIR] [--ycash6-repo DIR] [--commit SHA] [--out DIR]

Run once per ycash6 pin, never by CI: the verdicts are committed (plan
docs/plans/kogany/kogany-yellowback-plan.md W3-e, lane-E survey §3 rule 4). It

  1. checks that --ycash6-build is a configured and built ycash6 tree whose src/ is --commit's;
  2. compiles recorder/record_verdicts.cpp against that tree's libraries;
  3. takes the inputs: the C++ fuzz corpora src/fuzzing/<Target>/input at --commit (read from
     --ycash6-repo's object store, not its working tree), the pinned TX_PQCHANNEL / TX_PQPKH
     matcher scripts (testdata/yellowback/yellowback_pq_vectors.json "scripts", PIN-checked), and
     a deterministic TX_PQPKH neighbourhood built here (the corpora hold no TX_PQPKH script);
  4. runs every input through the recorder and writes verdicts/<Corpus>.tsv:
     `name <TAB> sha256(input) <TAB> hex(input) <TAB> verdict`, sorted by name.

The verdict is the outcome of each parser the C++ fuzz target of the corpus runs, as one string of
`key=value` fields; qa/fuzz/vault/src/verdict.rs builds the same string from kogany's parsers.
Stdlib only; run it with the workspace venv.
"""

import argparse
import hashlib
import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
KOGANY = os.path.normpath(os.path.join(HERE, "..", "..", ".."))
WS = os.path.normpath(os.path.join(KOGANY, "..", ".."))
COMMIT = "65cb4ae0ff19094d9185b00c264c7dc8c1610f63"
HOST = "aarch64-apple-darwin25.0.0"
SDK = "/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk"

# Corpus -> (recorder target, where the inputs come from).
CORPORA = {
    "Vault": ("Vault", "fuzzing"),
    "YellowbackScript": ("YellowbackScript", "fuzzing"),
    "YellowbackPayload": ("YellowbackPayload", "fuzzing"),
    "YellowbackTag": ("YellowbackTag", "fuzzing"),
    "PQVectors": ("YellowbackScript", "pq_vectors"),
    "PQPKH": ("YellowbackScript", "pqpkh"),
}

# The C++ corpora not replayed here, and why (README.md "Coverage").
NOT_REPLAYED = {
    "PQScript": "an OP_CHECKPQSIG stack grammar for the interpreter (W3-a/W3-c's fork interpreter cases)",
    "VaultState": "the set state machine over act sequences (W4-b/W4-e)",
    "YellowbackEvaluate": "the YED module's block evaluation (W5-d/W5-f)",
    "YellowbackBundle": "attestation bundles (W5-c)",
    "YellowbackPayee": "the payee schedule (W5-d)",
}


def run(cmd, **kw):
    return subprocess.run(cmd, check=True, capture_output=True, **kw)


def git(repo, *args):
    return run(["git", "-C", repo] + list(args)).stdout


def check_build(build, commit):
    if not os.path.exists(os.path.join(build, "src", "libbitcoin_common.a")):
        sys.exit("%s is not a built ycash6 tree (no src/libbitcoin_common.a)" % build)
    diff = subprocess.run(["git", "-C", build, "diff", "--quiet", commit, "--", "src"])
    if diff.returncode != 0:
        sys.exit("%s/src differs from %s" % (build, commit))


def compile_recorder(build, out):
    s = os.path.join(build, "src")
    d = os.path.join(build, "depends", HOST)
    rust = os.path.join(build, "target", "aarch64-apple-darwin", "release", "librustzcash.a")
    flags = ["-target", HOST, "-mmacosx-version-min=10.14", "-stdlib=libc++", "--sysroot", SDK, "-pthread"]
    obj = out + ".o"
    run(["clang++"] + flags + ["-std=c++17", "-DHAVE_CONFIG_H", "-DMAC_OSX", "-D__STDC_FORMAT_MACROS", "-O1",
         "-fwrapv", "-fno-strict-aliasing"] + ["-I" + p for p in [
             s, s + "/config", s + "/obj", d + "/include", s + "/leveldb/include", s + "/rust/include",
             s + "/rust/gen/include", s + "/secp256k1/include", s + "/univalue/include"]] +
        ["-c", os.path.join(HERE, "recorder", "record_verdicts.cpp"), "-o", obj])
    libs = ["univalue/.libs/libunivalue.a", "libbitcoin_common.a", "libbitcoin_util.a", "libbitcoin_consensus.a",
            "libbitcoin_script.a", "libcxxbridge.a", "secp256k1/.libs/libsecp256k1.a",
            "secp256k1/.libs/libsecp256k1_precomputed.a"]
    run(["clang++"] + flags + ["-o", out, obj] + [os.path.join(s, l) for l in libs] +
        [rust, os.path.join(s, "libzcash.a"), os.path.join(s, "crypto/libbitcoin_crypto.a"),
         os.path.join(s, "crypto/libbitcoin_crypto_arm_shani.a"), "-L" + d + "/lib", "-lsodium", "-ldl",
         "-lboost_filesystem", "-lboost_program_options", "-lboost_thread", "-lboost_chrono", "-Wl,-dead_strip"])


def fuzzing_inputs(repo, commit, target):
    prefix = "src/fuzzing/%s/input/" % target
    names = git(repo, "ls-tree", "-r", "--name-only", commit, "--", prefix).decode().split()
    return [(n[len(prefix):], git(repo, "cat-file", "blob", "%s:%s" % (commit, n))) for n in names]


def pq_vector_inputs():
    path = os.path.join(KOGANY, "testdata", "yellowback", "yellowback_pq_vectors.json")
    data = open(path, "rb").read()
    pinned = [l.split()[0] for l in open(os.path.join(KOGANY, "testdata", "yellowback", "PIN"))
              if l.strip().endswith("src/test/data/yellowback_pq_vectors.json")]
    if pinned != [hashlib.sha256(data).hexdigest()]:
        sys.exit("%s does not match its PIN" % path)
    return [("%03d %s" % (i, s["name"]), bytes.fromhex(s["hex"]))
            for i, s in enumerate(json.loads(data)["scripts"])]


def pqpkh_inputs():
    """The TX_PQPKH `20 <keyHash:32> OP_1|OP_2 OP_CHECKPQSIG` and its byte neighbourhood, plus the
    other destination kinds Solver/ExtractDestination name (P2PKH, P2SH, P2PK, multisig)."""
    hashes = {"zero": bytes(32), "ff": b"\xff" * 32, "seq": bytes(range(32)),
              "key": hashlib.sha256(b"\x02kogany").digest()}
    out = []
    for hn, h in sorted(hashes.items()):
        base = bytes([0x20]) + h + bytes([0x52, 0xc2])
        out.append(("pqpkh %s s2" % hn, base))
        out.append(("pqpkh %s s1" % hn, bytes([0x20]) + h + bytes([0x51, 0xc2])))
        for b in range(256):
            out.append(("pqpkh %s scheme-op %02x" % (hn, b), base[:33] + bytes([b, 0xc2])))
        if hn != "seq":
            continue
        for b in range(256):
            out.append(("pqpkh %s last-op %02x" % (hn, b), base[:34] + bytes([b])))
            out.append(("pqpkh %s first %02x" % (hn, b), bytes([b]) + base[1:]))
            out.append(("pqpkh %s append %02x" % (hn, b), base + bytes([b])))
        for n in range(len(base)):
            out.append(("pqpkh %s prefix %02d" % (hn, n), base[:n]))
        out.append(("pqpkh %s pushdata1" % hn, bytes([0x4c, 0x20]) + h + bytes([0x52, 0xc2])))
        out.append(("pqpkh %s hash31" % hn, bytes([0x1f]) + h[:31] + bytes([0x52, 0xc2])))
        out.append(("pqpkh %s hash33" % hn, bytes([0x21]) + h + b"\x00" + bytes([0x52, 0xc2])))
        out.append(("pqpkh %s twice" % hn, base + base))
        out.append(("pqpkh %s op_return" % hn, bytes([0x6a]) + base))
    k20 = bytes(range(1, 21))
    out.append(("p2pkh", bytes([0x76, 0xa9, 0x14]) + k20 + bytes([0x88, 0xac])))
    out.append(("p2sh", bytes([0xa9, 0x14]) + k20 + bytes([0x87])))
    g = bytes.fromhex("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
    gu = bytes.fromhex("0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
                       "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8")
    for hdr in (0x00, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07):
        out.append(("p2pk33 %02x" % hdr, bytes([0x21, hdr]) + g[1:] + bytes([0xac])))
        out.append(("p2pk65 %02x" % hdr, bytes([0x41, hdr]) + gu[1:] + bytes([0xac])))
    out.append(("p2pk33 offcurve", bytes([0x21, 0x02]) + b"\x00" * 32 + bytes([0xac])))
    out.append(("multisig 1of1", bytes([0x51, 0x21]) + g + bytes([0x51, 0xae])))
    out.append(("multisig 1of2", bytes([0x51, 0x21]) + g + bytes([0x41]) + gu + bytes([0x52, 0xae])))
    out.append(("multisig 2of1", bytes([0x52, 0x21]) + g + bytes([0x51, 0xae])))
    out.append(("multisig badkey", bytes([0x51, 0x21, 0x05]) + g[1:] + bytes([0x51, 0xae])))
    out.append(("nulldata empty", bytes([0x6a])))
    out.append(("nulldata push", bytes([0x6a, 0x04]) + b"YV\x01\x01"))
    out.append(("nulldata nonpush", bytes([0x6a, 0x61])))
    out.append(("nulldata pushdata4 short", bytes([0x6a, 0x4e, 0x01])))
    return out


def record(binary, target, inputs, tmp):
    paths = []
    for i, (_, data) in enumerate(inputs):
        p = os.path.join(tmp, "%06d" % i)
        with open(p, "wb") as f:
            f.write(data)
        paths.append(p)
    verdicts = {}
    for i in range(0, len(paths), 200):
        out = run([binary, target] + paths[i:i + 200]).stdout.decode()
        for line in out.splitlines():
            p, v = line.split("\t", 1)
            verdicts[p] = v
    return [verdicts[p] for p in paths]


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--ycash6-build", default=os.path.join(WS, "wt", "kc-harness"))
    ap.add_argument("--ycash6-repo", default=os.path.join(WS, "ycash6"))
    ap.add_argument("--commit", default=COMMIT)
    ap.add_argument("--out", default=os.path.join(HERE, "verdicts"))
    args = ap.parse_args(argv)
    check_build(args.ycash6_build, args.commit)
    os.makedirs(args.out, exist_ok=True)
    with tempfile.TemporaryDirectory() as tmp:
        binary = os.path.join(tmp, "record_verdicts")
        compile_recorder(args.ycash6_build, binary)
        for corpus, (target, source) in CORPORA.items():
            if source == "fuzzing":
                inputs = fuzzing_inputs(args.ycash6_repo, args.commit, corpus)
                origin = "ycash6 src/fuzzing/%s/input @ %s" % (corpus, args.commit)
            elif source == "pq_vectors":
                inputs = pq_vector_inputs()
                origin = "testdata/yellowback/yellowback_pq_vectors.json \"scripts\" (PIN)"
            else:
                inputs = pqpkh_inputs()
                origin = "record_verdicts.py pqpkh_inputs()"
            names = [n for n, _ in inputs]
            if len(set(names)) != len(names):
                sys.exit("%s: duplicate input names" % corpus)
            d = os.path.join(tmp, corpus)
            os.makedirs(d)
            verdicts = record(binary, target, inputs, d)
            rows = sorted(zip(names, [x for _, x in inputs], verdicts))
            path = os.path.join(args.out, corpus + ".tsv")
            with open(path, "w") as f:
                f.write("# kogany vault fuzz verdicts, recorded from ycash6 %s by qa/fuzz/vault/record_verdicts.py.\n"
                        % args.commit)
                f.write("# Inputs: %s. Verdict format: %s (recorder/record_verdicts.cpp).\n" % (origin, target))
                f.write("# Never edit; re-record on a ycash6 pin bump.\n")
                f.write("# name\tsha256\thex\tverdict\n")
                for n, data, v in rows:
                    f.write("%s\t%s\t%s\t%s\n" % (n, hashlib.sha256(data).hexdigest(), data.hex(), v))
            print("%-18s %5d inputs -> %s" % (corpus, len(rows), os.path.relpath(path, KOGANY)))
    for corpus, why in NOT_REPLAYED.items():
        print("%-18s not replayed: %s" % (corpus, why))
    return 0


if __name__ == "__main__":
    sys.exit(main())
