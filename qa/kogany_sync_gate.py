#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .
"""The W1-Y8 sync gate: kogany against a ycash6 node, block by block (plan §3 W1, lane E).

  qa/kogany_sync_gate.py --kogany URL --ycash URL --ycash-user U --ycash-password P
                         [--from H] [--to H] [--state FILE] [--follow SECONDS]
                         [--treestate-every N] [--kogany-log FILE]

Both nodes sync the same network independently (kogany from live peers, ycash6 from its own).
For every height up to the lower of the two tips (or `--to`) the driver asks both nodes over
JSON-RPC and requires byte-identical answers for:

  * the block hash (`getblockhash`), hence the whole header and, through the merkle root, the body;
  * `getblock <h> 1`: `finalsaplingroot`, `chainSupply`, and each value pool's `chainValueZat`
    and `valueDeltaZat` (`valuePools`, by `id`, where ycash6 marks the pool `monitored`);
  * from Heartwood (1,100,003 on mainnet) the ZIP-221 commitment: `blockcommitments` on both,
    and ycash6's `chainhistoryroot` at h against the `blockcommitments` of h+1 (before NU5 the
    header commits to the previous block's history root);
  * `z_gettreestate <h>` at sampled heights (every `--treestate-every`, every activation
    boundary, and the last height compared): each tree's `finalState` and `finalRoot` that both
    nodes report.

With `--kogany-log`, the gate also counts kogany's rejected blocks (`could not be checkpointed`,
`could not be full-verified`) at or below the compared height: the gate wants zero. A rejection
`TooHigh` above a partial checkpoint list's end is the list ending, not a rejected block, and is
counted separately.

Progress is kept in `--state` (JSON), so a rerun resumes after the last compared height; with
`--follow` the driver keeps comparing as the tips advance, sleeping between rounds. Exit 0 when
everything compared is identical and no block was rejected, 1 on a mismatch or a rejection,
2 on an error. Stdlib only; `main(argv=None)`.
"""

import argparse
import base64
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request

MAINNET_BOUNDARIES = (347_500, 419_200, 569_999, 570_000, 570_001,
                      1_100_000, 1_100_002, 1_100_003, 1_100_005, 1_100_006)
MAINNET_HEARTWOOD = 1_100_003
TREES = ("sprout", "sapling", "orchard")


class GateError(Exception):
    pass


class Rpc:
    """A minimal JSON-RPC 1.0 client; batches when the server takes them."""

    def __init__(self, url, user=None, password=None, timeout=120):
        self.url = url
        self.headers = {"Content-Type": "application/json"}
        if user is not None:
            token = base64.b64encode(("%s:%s" % (user, password or "")).encode()).decode()
            self.headers["Authorization"] = "Basic " + token
        self.timeout = timeout
        self.batching = True
        self.next_id = 0

    def _post(self, body):
        req = urllib.request.Request(self.url, data=json.dumps(body).encode(), headers=self.headers)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                return json.loads(r.read())
        except urllib.error.HTTPError as e:
            # zcashd answers an RPC error with HTTP 500 and the JSON body.
            payload = e.read()
            try:
                return json.loads(payload)
            except ValueError:
                raise GateError("%s: HTTP %d %r" % (self.url, e.code, payload[:200]))

    def _one(self, method, params):
        self.next_id += 1
        reply = self._post({"jsonrpc": "1.0", "id": self.next_id, "method": method, "params": params})
        return reply.get("result"), reply.get("error")

    def batch(self, calls):
        """[(result, error)] for `calls` = [(method, params)]."""
        if self.batching and len(calls) > 1:
            body = []
            for method, params in calls:
                self.next_id += 1
                body.append({"jsonrpc": "1.0", "id": self.next_id, "method": method, "params": params})
            replies = self._post(body)
            if isinstance(replies, list):
                by_id = {x.get("id"): x for x in replies}
                first = self.next_id - len(calls) + 1
                if all(i in by_id for i in range(first, self.next_id + 1)):
                    return [(by_id[i].get("result"), by_id[i].get("error"))
                            for i in range(first, self.next_id + 1)]
            self.batching = False
        return [self._one(method, params) for method, params in calls]

    def call(self, method, *params):
        result, error = self._one(method, list(params))
        if error:
            raise GateError("%s %s: %s" % (method, params, error))
        return result


def pools(block):
    """{id: {field: value}} of the value pools both lines report."""
    out = {}
    for pool in block.get("valuePools") or []:
        if pool.get("monitored") is False:
            continue
        out[pool["id"]] = {k: pool[k] for k in ("chainValueZat", "valueDeltaZat") if k in pool}
    return out


def compare_blocks(height, k_block, y_block):
    """The list of differences between the two `getblock <h> 1` answers."""
    diffs = []
    for field in ("hash", "finalsaplingroot"):
        if k_block.get(field) != y_block.get(field):
            diffs.append((field, k_block.get(field), y_block.get(field)))
    if height >= MAINNET_HEARTWOOD and "blockcommitments" in k_block and "blockcommitments" in y_block:
        if k_block["blockcommitments"] != y_block["blockcommitments"]:
            diffs.append(("blockcommitments", k_block["blockcommitments"], y_block["blockcommitments"]))
    k_supply, y_supply = k_block.get("chainSupply"), y_block.get("chainSupply")
    if k_supply and y_supply and y_supply.get("monitored") is not False:
        for field in ("chainValueZat", "valueDeltaZat"):
            if field in k_supply and field in y_supply and k_supply[field] != y_supply[field]:
                diffs.append(("chainSupply.%s" % field, k_supply[field], y_supply[field]))
    k_pools, y_pools = pools(k_block), pools(y_block)
    for pool_id in sorted(set(k_pools) & set(y_pools)):
        for field in sorted(set(k_pools[pool_id]) & set(y_pools[pool_id])):
            if k_pools[pool_id][field] != y_pools[pool_id][field]:
                diffs.append(("valuePools.%s.%s" % (pool_id, field),
                              k_pools[pool_id][field], y_pools[pool_id][field]))
    return diffs


def tree_fields(treestate):
    out = {}
    for tree in TREES:
        commitments = ((treestate or {}).get(tree) or {}).get("commitments") or {}
        for field in ("finalState", "finalRoot"):
            if commitments.get(field):
                out["%s.%s" % (tree, field)] = commitments[field]
    return out


def compare_treestates(k_state, y_state):
    k_fields, y_fields = tree_fields(k_state), tree_fields(y_state)
    shared = sorted(set(k_fields) & set(y_fields))
    diffs = [(f, k_fields[f], y_fields[f]) for f in shared if k_fields[f] != y_fields[f]]
    return shared, diffs


REJECTED = re.compile(r"could not be (checkpointed|full-verified)")
TOO_HIGH = re.compile(r"higher than the maximum checkpoint")
HEIGHT = re.compile(r"[Hh]eight\((\d+)\)")


def scan_log(path, through):
    """(rejected at or below `through`, rejections above it or past the list's end, samples)."""
    rejected, beyond, samples = 0, 0, []
    if not path or not os.path.exists(path):
        return rejected, beyond, samples
    with open(path, errors="replace") as f:
        for line in f:
            if not REJECTED.search(line):
                continue
            m = HEIGHT.search(line)
            height = int(m.group(1)) if m else None
            if TOO_HIGH.search(line) or (height is not None and height > through):
                beyond += 1
                continue
            rejected += 1
            if len(samples) < 5:
                samples.append(line.strip()[:400])
    return rejected, beyond, samples


def load_state(path):
    if path and os.path.exists(path):
        with open(path) as f:
            return json.load(f)
    return {"compared_through": -1, "mismatches": [], "treestate_samples": [], "rounds": 0}


def save_state(path, state):
    if not path:
        return
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(state, f, indent=1, sort_keys=True)
    os.replace(tmp, path)


def run_round(kogany, ycash, state, args):
    k_tip = kogany.call("getblockchaininfo")["blocks"]
    y_tip = ycash.call("getblockchaininfo")["blocks"]
    top = min(k_tip, y_tip)
    if args.to is not None:
        top = min(top, args.to)
    start = max(state["compared_through"] + 1, args.start)
    state.update(kogany_tip=k_tip, ycash_tip=y_tip)
    h = start
    batch = args.batch
    while h <= top:
        heights = list(range(h, min(h + batch, top + 1)))
        calls = [("getblock", [str(x), 1]) for x in heights]
        k_blocks = kogany.batch(calls)
        y_blocks = ycash.batch(calls)
        for height, (k_block, k_err), (y_block, y_err) in zip(heights, k_blocks, y_blocks):
            if k_err or y_err or k_block is None or y_block is None:
                raise GateError("getblock %d: kogany %s, ycash6 %s" % (height, k_err, y_err))
            diffs = compare_blocks(height, k_block, y_block)
            prev = state.get("_prev_chainhistoryroot")
            if height > MAINNET_HEARTWOOD and prev and y_block.get("blockcommitments") \
                    and prev != y_block["blockcommitments"]:
                diffs.append(("zip221 chainhistoryroot(h-1) vs blockcommitments(h)", prev, y_block["blockcommitments"]))
            state["_prev_chainhistoryroot"] = y_block.get("chainhistoryroot")
            if diffs:
                state["mismatches"].append({"height": height, "diffs": diffs})
            sample = (height % args.treestate_every == 0) or (height in MAINNET_BOUNDARIES) or height == top
            if sample:
                k_ts = kogany.call("z_gettreestate", str(height))
                y_ts = ycash.call("z_gettreestate", str(height))
                shared, ts_diffs = compare_treestates(k_ts, y_ts)
                state["treestate_samples"].append({"height": height, "fields": shared,
                                                   "identical": not ts_diffs})
                if ts_diffs:
                    state["mismatches"].append({"height": height, "diffs": ts_diffs, "rpc": "z_gettreestate"})
            state["compared_through"] = height
        h = heights[-1] + 1
        save_state(args.state, state)
        if args.verbose:
            print("compared through %d / %d" % (state["compared_through"], top), file=sys.stderr)
        if args.fail_fast and state["mismatches"]:
            break
    state["rounds"] += 1
    rejected, beyond, samples = scan_log(args.kogany_log, state["compared_through"])
    state.update(rejected_blocks=rejected, rejections_beyond=beyond, rejected_samples=samples,
                 updated=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
    save_state(args.state, state)


def summary(state):
    keep = ("compared_through", "kogany_tip", "ycash_tip", "rounds", "rejected_blocks",
            "rejections_beyond", "updated")
    out = {k: state.get(k) for k in keep}
    out["mismatches"] = len(state["mismatches"])
    out["first_mismatches"] = state["mismatches"][:3]
    out["treestate_samples"] = len(state["treestate_samples"])
    out["treestate_fields"] = sorted({f for s in state["treestate_samples"] for f in s["fields"]})
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--kogany", required=True, help="kogany's RPC URL (cookie auth off)")
    ap.add_argument("--kogany-user")
    ap.add_argument("--kogany-password")
    ap.add_argument("--ycash", required=True, help="the ycash6 node's RPC URL")
    ap.add_argument("--ycash-user", default=os.environ.get("YCASH_RPCUSER"))
    ap.add_argument("--ycash-password", default=os.environ.get("YCASH_RPCPASSWORD"))
    ap.add_argument("--from", dest="start", type=int, default=0)
    ap.add_argument("--to", type=int)
    ap.add_argument("--state", help="progress file (JSON); a rerun resumes from it")
    ap.add_argument("--follow", type=float, metavar="SECONDS",
                    help="keep comparing as the tips advance, sleeping SECONDS between rounds")
    ap.add_argument("--treestate-every", type=int, default=10_000)
    ap.add_argument("--batch", type=int, default=100)
    ap.add_argument("--kogany-log", help="kogany's log file, scanned for rejected blocks")
    ap.add_argument("--fail-fast", action="store_true")
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args(argv)

    kogany = Rpc(args.kogany, args.kogany_user, args.kogany_password)
    ycash = Rpc(args.ycash, args.ycash_user, args.ycash_password)
    state = load_state(args.state)
    try:
        while True:
            run_round(kogany, ycash, state, args)
            print(json.dumps(summary(state)), flush=True)
            if not args.follow or (args.fail_fast and state["mismatches"]):
                break
            if args.to is not None and state["compared_through"] >= args.to:
                break
            time.sleep(args.follow)
    except (GateError, OSError) as e:
        save_state(args.state, state)
        print("kogany_sync_gate.py: %s" % e, file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        save_state(args.state, state)
        return 2
    return 1 if state["mismatches"] or state.get("rejected_blocks") else 0


if __name__ == "__main__":
    sys.exit(main())
