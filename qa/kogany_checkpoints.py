#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .
"""Ycash checkpoint lists for kogany's `ycash` profile (plan W1-Y4, decisions K-9, K-12; M24-14).

  qa/kogany_checkpoints.py mainnet  --rpc URL --rpcuser U --rpcpassword P [--out FILE] [--append]
  qa/kogany_checkpoints.py testnet  [--out FILE]
  qa/kogany_checkpoints.py check    FILE --network mainnet|testnet

`mainnet` regenerates `crates/zakura-chain/src/parameters/checkpoint/ycash-main-checkpoints.txt`
from a ycashd node's JSON-RPC (`getblockchaininfo`, `getblock <h> 1`). It is the equivalent of
upstream's `zakura-checkpoints --backend zcashd` (`crates/zakura-utils/src/bin/zakura-checkpoints/
main.rs`), with the same selection rule, so the shared Zcash/Ycash history below the fork comes
out line for line as Zakura's own `main-checkpoints.txt` (the `check` subcommand asserts it):

  * genesis is a checkpoint; then a block is a checkpoint when the gap since the previous one
    reaches MAX_CHECKPOINT_HEIGHT_GAP (400) or the serialized bytes since it reach
    MAX_CHECKPOINT_BYTE_COUNT (32 MiB) (`crates/zakura-chain/src/parameters/checkpoint/
    constants.rs`);
  * blocks within MAX_BLOCK_REORG_HEIGHT (1000) of the node's tip are never checkpointed.

Two Ycash rules are added on top:

  * every hash ycashd pins (`checkpointData`, the fork block `UPGRADE_YCASH.hashActivationBlock`
    and the chain-supply checkpoint block, ycash6 `src/chainparams.cpp` at 65cb4ae0f) is a
    checkpoint, and the node's hash at that height must equal the pin: a mismatch aborts;
  * the list never reaches the Vault epoch (M24-14, K-9): it stops below `--stop-below`, which
    defaults to the network's Vault height (mainnet: none compiled in; `fast` testnet: 510,400).

A list the node has not fully synced is written with a `# PARTIAL` header line naming the height
it reaches; kogany parses `#` lines as comments in a `ycash` build only. Rerun with `--append` as
the node syncs: it resumes after the last checkpoint, exactly as `--last-checkpoint` does.

`testnet` writes `ycash-test-checkpoints.txt`: the re-forked Ycash testnet shares Zcash testnet's
history through 510,247 (`ycash/LAST_SHARED_HEIGHT`, ycash6 `src/chainparams.cpp:571-583`, the
testnet-prefix-v1 manifest). The list is Zakura's `test-checkpoints.txt` cut at that height, then
the fast profile's mandatory checkpoint at 510,253 (Canopy minus one, the hash both
testnet-yb-fast seeds serve). ycashd's 510,247 pin stays out of the list: 510,253 is 6 blocks
later, under the 17-block minimum gap, and the hash chain from 510,000 through 510,253 covers it.
Blocks from Canopy (510,254) on are verified semantically.

Stdlib only; `main(argv=None)`.
"""

import argparse
import base64
import json
import os
import sys
import http.client
import time
import urllib.parse

MAX_CHECKPOINT_HEIGHT_GAP = 400
MAX_CHECKPOINT_BYTE_COUNT = 32 * 1024 * 1024
MAX_BLOCK_REORG_HEIGHT = 1000
# ceil(MAX_CHECKPOINT_BYTE_COUNT / MAX_BLOCK_BYTES): the list test's lower gap bound
# (`checkpoint/list/tests.rs`, `checkpoint_list_hard_coded_max_gap`).
MAX_BLOCK_BYTES = 2_000_000
MIN_CHECKPOINT_HEIGHT_GAP = -(-MAX_CHECKPOINT_BYTE_COUNT // MAX_BLOCK_BYTES)

CHECKPOINT_DIR = "crates/zakura-chain/src/parameters/checkpoint"
UPSTREAM_MAINNET = CHECKPOINT_DIR + "/main-checkpoints.txt"
UPSTREAM_TESTNET = CHECKPOINT_DIR + "/test-checkpoints.txt"
YCASH_MAINNET = CHECKPOINT_DIR + "/ycash-main-checkpoints.txt"
YCASH_TESTNET = CHECKPOINT_DIR + "/ycash-test-checkpoints.txt"

# Ycash mainnet: the fork block (UPGRADE_YCASH), then the shared/Ycash history ycashd fails on
# (`ycash6 src/chainparams.cpp:131-132, 252-283, 378-384` at 65cb4ae0f).
YCASH_FORK_HEIGHT = 570_000
MAINNET_PINS = {
    0: "00040fe8ec8471911baa1db1266ea15dd06b4a8a5c453883c000b031973dce08",
    2500: "00000006dc968f600be11a86cbfbf7feb61c7577f45caced2e82b6d261d19744",
    15000: "00000000b6bc56656812a5b8dcad69d6ad4446dec23b5ec456c18641fb5381ba",
    67500: "000000006b366d2c1649a6ebb4787ac2b39c422f451880bc922e3a6fbd723616",
    100000: "000000001c5c82cd6baccfc0879e3830fd50d5ede17fa2c37a9a253c610eb285",
    133337: "0000000002776ccfaf06cc19857accf3e20c01965282f916b8a886e3e4a05be9",
    180000: "000000001205b742eac4a1b3959635bdf8aeada078d6a996df89740f7b54351d",
    222222: "000000000cafb9e56445a6cabc8057b57ee6fcc709e7adbfa195e5c7fac61343",
    270000: "00000000025c1cfa0258e33ab050aaa9338a3d4aaa3eb41defefc887779a9729",
    304600: "00000000028324e022a45014c4a4dc51e95d41e6bceb6ad554c5b65d5cea3ea5",
    410100: "0000000002c565958f783a24a4ac17cde898ff525e75ed9baf66861b0b9fcada",
    497000: "0000000000abd333f0acca6ffdf78a167699686d6a7d25c33fca5f295061ffff",
    525000: "0000000001a36c500378be8862d9bf1bea8f1616da6e155971b608139cc7e39b",
    570000: "0000014fbc5917ba8bcacf3336faf588d86b32443aa3a490a587af5750c77ec5",
    572760: "00000008db657f58222e38e354c18ccbb6c74cf525ef4f3a95f0f8a324a3166d",
    980000: "00000510ccc6bae2ddb38b9313ffb9686397f6cd0dee243462baeaf8911d0791",
    1035353: "00000543378a75f173914390c672838c9fbd9dc86ae647ffae18ed6b626edb30",
    1575000: "000002b856230b06caa3412058e6490fab256cee9d9d9fb68eae59b4ebd94471",
    2250000: "000003f98b7497fdcd8a6b6d10a93a887c5d47127e24a9dc3a40cb65754d21e7",
    2800000: "000003170414909d5104f4a71708eca4e5b545d231c412c2d3e0e3f33874facb",
}
# Ycash mainnet has no Vault height compiled in (set by the gate-passing release, upgrade plan P8).
MAINNET_VAULT_HEIGHT = None

# The re-forked Ycash testnet (`ycash6 src/chainparams.cpp:571-583`).
TESTNET_LAST_SHARED_HEIGHT = 510_247
# ycashd's fork pin. Not a list entry: Canopy-1 is only 6 blocks later.
TESTNET_FORK_PIN = "0000ec904003d5591290064b0b4d3ccddffe87ef2a3a131284438959bf68fb31"
# Fast profile: Canopy activates at 510,254, so the mandatory checkpoint is 510,253.
TESTNET_MANDATORY_HEIGHT = 510_253
TESTNET_PINS = {
    0: "05a60a92d99d85997cce3b87616c089f6124d7342af37106edc76126334a2c38",
    38000: "001e9a2d2e2892b88e9998cf7b079b41d59dd085423a921fe8386cecc42287b8",
    510253: "0297aad933fdf3f5e07acff13992e138ab4fec56033cdfa3a3815535ff049dbb",
}
# `fast` profile Vault height (`ycash6 src/chainparams.cpp:640`); the `slow` profile has none.
TESTNET_VAULT_HEIGHT = 510_400


class CheckpointError(Exception):
    pass


def read_list(path):
    """(header comment lines, [(height, hash)]) of a checkpoint file."""
    header, entries = [], []
    with open(path) as f:
        for n, line in enumerate(f, 1):
            line = line.rstrip("\n")
            if line.startswith("#"):
                header.append(line)
                continue
            fields = line.split(" ")
            if len(fields) != 2 or len(fields[1]) != 64:
                raise CheckpointError("%s:%d: not `height hash`: %r" % (path, n, line))
            entries.append((int(fields[0]), fields[1]))
    return header, entries


def write_list(path, header, entries):
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        for line in header:
            f.write(line + "\n")
        for height, block_hash in entries:
            f.write("%d %s\n" % (height, block_hash))
    os.replace(tmp, path)


def check_list(entries, pins, stop_below, upstream=None, shared_below=None):
    """The invariants kogany's Rust tests also assert, plus the pins and the shared prefix."""
    if not entries or entries[0][0] != 0:
        raise CheckpointError("the list must start at genesis")
    heights = [h for h, _ in entries]
    if heights != sorted(set(heights)):
        raise CheckpointError("heights must be unique and increasing")
    if len({b for _, b in entries}) != len(entries):
        raise CheckpointError("hashes must be unique")
    for (h0, _), (h1, _) in zip(entries, entries[1:]):
        if not MIN_CHECKPOINT_HEIGHT_GAP <= h1 - h0 <= MAX_CHECKPOINT_HEIGHT_GAP:
            raise CheckpointError("gap %d..%d = %d outside [%d, %d]" % (
                h0, h1, h1 - h0, MIN_CHECKPOINT_HEIGHT_GAP, MAX_CHECKPOINT_HEIGHT_GAP))
    if stop_below is not None and heights[-1] >= stop_below:
        raise CheckpointError("checkpoint %d reaches the Vault epoch (>= %d, M24-14)" % (heights[-1], stop_below))
    have = dict(entries)
    top = heights[-1]
    for height, pin in sorted(pins.items()):
        if height > top:
            continue
        if have.get(height) != pin:
            raise CheckpointError("pin %d: list has %s, ycashd pins %s" % (height, have.get(height), pin))
    if upstream is not None:
        # Below the fork both chains are one chain: every upstream checkpoint in range is ours.
        limit = min(top, shared_below - 1)
        for height, block_hash in upstream:
            if height > limit:
                break
            if have.get(height) != block_hash:
                raise CheckpointError("shared history: upstream %d %s, ours %s" % (height, block_hash, have.get(height)))
    return {"checkpoints": len(entries), "max_height": top,
            "pins_covered": sorted(h for h in pins if h <= top),
            "pins_pending": sorted(h for h in pins if h > top)}


class Rpc:
    """JSON-RPC over one kept-alive HTTP connection (a connection per batch exhausts the
    ephemeral ports on a busy machine: EADDRNOTAVAIL); a dropped connection, a node restart or
    its warm-up (-28) is retried with a backoff."""

    RETRIES = 30

    def __init__(self, url, user, password, timeout=300):
        self.url = url
        parts = urllib.parse.urlsplit(url)
        self.host, self.port = parts.hostname, parts.port or 80
        self.path = parts.path or "/"
        self.auth = "Basic " + base64.b64encode(("%s:%s" % (user, password)).encode()).decode()
        self.timeout = timeout
        self.next_id = 0
        self.conn = None

    def _post(self, payload):
        if self.conn is None:
            self.conn = http.client.HTTPConnection(self.host, self.port, timeout=self.timeout)
        self.conn.request("POST", self.path, body=payload,
                          headers={"Authorization": self.auth, "Content-Type": "application/json"})
        r = self.conn.getresponse()
        data = r.read()
        if r.status not in (200, 500):
            raise OSError("HTTP %d %r" % (r.status, data[:200]))
        return json.loads(data)

    def batch(self, calls):
        body = []
        for method, params in calls:
            self.next_id += 1
            body.append({"jsonrpc": "1.0", "id": self.next_id, "method": method, "params": params})
        payload = json.dumps(body).encode()
        for attempt in range(self.RETRIES):
            try:
                replies = self._post(payload)
                if isinstance(replies, dict) and (replies.get("error") or {}).get("code") == -28:
                    raise OSError("node warming up: %s" % replies["error"].get("message"))
                if isinstance(replies, list) and any((x.get("error") or {}).get("code") == -28 for x in replies):
                    raise OSError("node warming up")
                break
            except (OSError, http.client.HTTPException, ValueError) as e:
                if self.conn is not None:
                    self.conn.close()
                self.conn = None
                if attempt == self.RETRIES - 1:
                    raise CheckpointError("rpc failed after %d attempts: %s" % (self.RETRIES, e))
                time.sleep(min(60, 2 * (attempt + 1)))
        by_id = {x["id"]: x for x in replies}
        out = []
        for i in range(self.next_id - len(calls) + 1, self.next_id + 1):
            x = by_id[i]
            if x.get("error"):
                raise CheckpointError("rpc error: %s" % x["error"])
            out.append(x["result"])
        return out

    def call(self, method, *params):
        return self.batch([(method, list(params))])[0]


def generate(rpc, pins, stop_below, entries, batch_size=200, progress=None):
    """Extend `entries` (a list starting at genesis, or empty) to the node's settled tip."""
    tip = rpc.call("getblockchaininfo")["blocks"]
    limit = tip - MAX_BLOCK_REORG_HEIGHT  # exclusive, as zakura-checkpoints
    if stop_below is not None:
        limit = min(limit, stop_below)
    entries = list(entries)
    # Resume from the last checkpoint the selection rule chose: trailing pins are re-added.
    while len(entries) > 1 and entries[-1][0] in pins:
        entries.pop()
    start = entries[-1][0] + 1 if entries else 0
    last = entries[-1][0] if entries else 0
    cumulative = 0
    h = start
    while h < limit:
        heights = list(range(h, min(h + batch_size, limit)))
        blocks = rpc.batch([("getblock", [str(x), 1]) for x in heights])
        for height, block in zip(heights, blocks):
            if block["height"] != height:
                raise CheckpointError("node returned block %d for %d" % (block["height"], height))
            cumulative += block["size"]
            pin = pins.get(height)
            if pin is not None and block["hash"] != pin:
                raise CheckpointError("node hash at pin %d is %s, ycashd pins %s: wrong chain" % (height, block["hash"], pin))
            if (height == 0 or cumulative >= MAX_CHECKPOINT_BYTE_COUNT
                    or height - last >= MAX_CHECKPOINT_HEIGHT_GAP):
                entries.append((height, block["hash"]))
                cumulative = 0
                last = height
            elif pin is not None:
                # A pin is an extra checkpoint: the selection rule's own sequence is unchanged,
                # so the shared history stays line for line Zakura's list.
                entries.append((height, block["hash"]))
        h = heights[-1] + 1
        if progress:
            progress(h, limit)
    return entries, tip, limit


def mainnet_header(through, tip, complete):
    lines = [
        "# Ycash mainnet checkpoints for kogany's `ycash` profile (W1-Y4; decisions K-9, K-12; M24-14).",
        "# Generated by qa/kogany_checkpoints.py from a ycash6 node (65cb4ae0f) over JSON-RPC, with",
        "# zakura-checkpoints' selection rule plus every hash ycashd pins; never into the Vault epoch.",
    ]
    if complete:
        lines.append("# COMPLETE: generated through height %d (node tip %d)." % (through, tip))
    else:
        lines.append("# PARTIAL: generated through height %d (node tip %d, still syncing); "
                     "regenerate with --append when the node has synced." % (through, tip))
    return lines


def cmd_mainnet(args, repo):
    out = args.out or os.path.join(repo, YCASH_MAINNET)
    entries = []
    if args.append and os.path.exists(out):
        _, entries = read_list(out)
    rpc = Rpc(args.rpc, args.rpcuser, args.rpcpassword)

    def progress(h, limit):
        if args.verbose:
            print("  %d / %d" % (h, limit), file=sys.stderr)

    entries, tip, _ = generate(rpc, MAINNET_PINS, MAINNET_VAULT_HEIGHT, entries, progress=progress)
    info = rpc.call("getblockchaininfo")
    complete = bool(info.get("initial_block_download_complete")) and info["blocks"] >= info.get("headers", 0)
    _, upstream = read_list(os.path.join(repo, UPSTREAM_MAINNET))
    summary = check_list(entries, MAINNET_PINS, MAINNET_VAULT_HEIGHT, upstream, YCASH_FORK_HEIGHT)
    write_list(out, mainnet_header(entries[-1][0], tip, complete), entries)
    print(json.dumps(dict(summary, file=out, node_tip=tip, complete=complete)))
    return 0


def fast_testnet_checkpoint_list(repo):
    """Header and entries of `ycash-test-checkpoints.txt`.

    Shared Zcash testnet history through the fork, then the fast mandatory
    checkpoint. The fork pin is not an entry: it is 6 blocks under that
    checkpoint, and the minimum gap is 17.
    """
    _, upstream = read_list(os.path.join(repo, UPSTREAM_TESTNET))
    entries = [(h, b) for h, b in upstream if h <= TESTNET_LAST_SHARED_HEIGHT]
    entries.append((TESTNET_MANDATORY_HEIGHT, TESTNET_PINS[TESTNET_MANDATORY_HEIGHT]))
    header = [
        "# Ycash testnet checkpoints for kogany's `ycash` profile, `fast` and `slow` (W1-Y4; K-9, K-10; M24-14).",
        "# Zcash testnet's shared history through %d (Zakura's test-checkpoints.txt cut there) plus" % TESTNET_LAST_SHARED_HEIGHT,
        "# the re-forked testnet's Canopy-1 block %d (the mandatory checkpoint), as served by both" % TESTNET_MANDATORY_HEIGHT,
        "# testnet-yb-fast seeds. Its chain passes through ycashd's %d pin (ycash6" % TESTNET_LAST_SHARED_HEIGHT,
        "# src/chainparams.cpp:571-583, testnet-prefix-v1), which the 17-block minimum gap keeps out of the",
        "# list. Blocks from Canopy (%d) on are verified semantically; never at or above Vault (%d)." % (TESTNET_MANDATORY_HEIGHT + 1, TESTNET_VAULT_HEIGHT),
        "# PARTIAL: for a configured testnet that reuses this list with a later Canopy, the list stops",
        "# below its mandatory checkpoint (W1-Y4).",
    ]
    return header, entries, upstream


def cmd_testnet(args, repo):
    out = args.out or os.path.join(repo, YCASH_TESTNET)
    header, entries, upstream = fast_testnet_checkpoint_list(repo)
    summary = check_list(entries, TESTNET_PINS, TESTNET_VAULT_HEIGHT, upstream, TESTNET_LAST_SHARED_HEIGHT + 1)
    write_list(out, header, entries)
    print(json.dumps(dict(summary, file=out)))
    return 0


def cmd_check(args, repo):
    _, entries = read_list(args.file)
    if args.network == "mainnet":
        _, upstream = read_list(os.path.join(repo, UPSTREAM_MAINNET))
        summary = check_list(entries, MAINNET_PINS, MAINNET_VAULT_HEIGHT, upstream, YCASH_FORK_HEIGHT)
    else:
        _, upstream = read_list(os.path.join(repo, UPSTREAM_TESTNET))
        summary = check_list(entries, TESTNET_PINS, TESTNET_VAULT_HEIGHT, upstream, TESTNET_LAST_SHARED_HEIGHT + 1)
    print(json.dumps(summary))
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    m = sub.add_parser("mainnet")
    m.add_argument("--rpc", default="http://127.0.0.1:8832/")
    m.add_argument("--rpcuser", default=os.environ.get("YCASH_RPCUSER", ""))
    m.add_argument("--rpcpassword", default=os.environ.get("YCASH_RPCPASSWORD", ""))
    m.add_argument("--out")
    m.add_argument("--append", action="store_true", help="resume after the file's last checkpoint")
    m.add_argument("--verbose", action="store_true")
    t = sub.add_parser("testnet")
    t.add_argument("--out")
    c = sub.add_parser("check")
    c.add_argument("file")
    c.add_argument("--network", choices=["mainnet", "testnet"], required=True)
    ap.add_argument("--repo", default=None)
    args = ap.parse_args(argv)
    repo = args.repo or os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    try:
        return {"mainnet": cmd_mainnet, "testnet": cmd_testnet, "check": cmd_check}[args.cmd](args, repo)
    except CheckpointError as e:
        print("kogany_checkpoints.py: %s" % e, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
