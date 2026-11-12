#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""kogany templates and mines every mixed shape; both C++ lines accept its blocks (beta2 list
item 20, mining).

    python testdata/mixed-shapes/kogany_mines_shapes.py --koganyd <koganyd, the --features ycash build> \\
        --ycash6-bin <dir with ycashd> --ycash-dd-bin <dir with ycashd> \\
        --solver-dir <ycash6 tree>/qa/rpc-tests [--fixture chain.json --fixture chain2.json] \\
        [--workdir DIR] [--port-base N]

For each recorded chain (`chain.json`, `chain2.json`) it starts a koganyd, a ycash6 node and a
ycash-dd node on the recording's regtest (every upgrade through Canopy at 1, Vault as recorded),
none of them peered, and gives all three the recorded setup chain by `submitblock`. Then, in the
recorded order, each shape goes to kogany's mempool (`sendrawtransaction`, the recorded bytes),
kogany's `getblocktemplate` must carry it, the template is solved outside the node (kogany checks
only the solution's shape on regtest and never solves; `crates/kogany-rpc/qa/kogany_mines.py`'s
solver: ycash6's pure-Python (48,5) Equihash, imported read-only), and the block goes to kogany,
ycash6 and ycash-dd by `submitblock`: every answer must be an acceptance and the three tips equal.
So each C++ line accepts a kogany-built block of each shape, kogany's coinbase and its template's
fee and commitments included.

Run by hand (it needs both C++ binaries and a koganyd), not in CI; stdlib only, plus `record.py`
and `kogany_mines.py`.
"""

import argparse
import json
import os
import shutil
import sys
import tempfile
import time

sys.dont_write_bytecode = True  # the solver is imported from another tree: leave it untouched
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, '..', '..', 'crates', 'kogany-rpc', 'qa'))
import record as r1  # noqa: E402
import kogany_mines as km  # noqa: E402

AWARE = '-i-am-aware-zcashd-will-be-replaced-by-zebrad-and-zallet-in-2025'


def raw_shapes(doc):
    """(name, txid, the recorded transaction hex) in the recorded order."""
    shapes = sorted(doc['shapes'].items(), key=lambda kv: kv[1]['height'])
    out = []
    for name, shape in shapes:
        block = bytes.fromhex(doc['blocks'][shape['height'] - 1])
        out.append((name, shape['txid'], second_tx_hex(block)))
    return out


def second_tx_hex(block):
    """The block's second transaction (each shape is mined alone beside the coinbase)."""
    at = 140
    size, at = r1_read_compact(block, at)          # the Equihash solution
    at += size
    count, at = r1_read_compact(block, at)
    assert count == 2, 'a shape block has two transactions'
    return block[at + tx_length(block, at):].hex()


def r1_read_compact(b, at):
    first = b[at]
    if first < 0xfd:
        return first, at + 1
    size = {0xfd: 2, 0xfe: 4, 0xff: 8}[first]
    return int.from_bytes(b[at + 1:at + 1 + size], 'little'), at + 1 + size


def tx_length(b, start):
    """The length of the v4 coinbase at `start` (no shielded parts, no JoinSplits)."""
    at = start + 8
    n, at = r1_read_compact(b, at)
    for _ in range(n):
        size, at = r1_read_compact(b, at + 36)
        at += size + 4
    n, at = r1_read_compact(b, at)
    for _ in range(n):
        size, at = r1_read_compact(b, at + 8)
        at += size
    at += 4 + 4 + 8                                 # lock time, expiry, valueBalance
    for _ in range(3):                              # spends, outputs, JoinSplits: none
        n, at = r1_read_compact(b, at)
        assert n == 0, 'a coinbase without shielded parts'
    return at - start


def kogany_toml(workdir, p2p, rpc, v2, vault, miner):
    root = os.path.join(workdir, 'kogany')
    # Falcon from 0 as recorded (ycashd's -pqfalcon=1); without the key an FN-DSA-512 output is
    # non-standard (`64: scriptpubkey`) on kogany's regtest.
    heights = '\n'.join(['%s = 1' % k for k in km.ACTIVATION_KEYS]
                        + ['Vault = %d' % vault, 'pq_falcon_height = 0'])
    return '''[network]
listen_addr = "127.0.0.1:{p2p}"
initial_testnet_peers = []
p2p_stack = "legacy"
cache_dir = "{root}/network"
identity_dir = "{root}/identity"

[network.network]
regtest = true

[network.network.params.activation_heights]
{heights}

[network.zakura]
listen_addr = "127.0.0.1:{v2}"

[rpc]
listen_addr = "127.0.0.1:{rpc}"
enable_cookie_auth = false
cookie_dir = "{root}/rpc"

[state]
cache_dir = "{root}/state"
ephemeral = false

[mempool]
debug_enable_at_height = 0
accept_non_standard = false

[mining]
internal_miner = false
miner_address = "{miner}"

[tracing]
use_color = false
filter = "info"
'''.format(p2p=p2p, rpc=rpc, v2=v2, root=root, heights=heights, miner=miner)


def stop_node(node, proc):
    try:
        node.call('stop')
    except (OSError, r1.RpcError, km.RpcError):
        pass
    deadline = time.time() + 60
    while proc.poll() is None and time.time() < deadline:
        time.sleep(0.5)
    r1.stop(proc)


def run_fixture(args, solver, fixture, workdir, pb):
    with open(os.path.join(HERE, fixture)) as f:
        doc = json.load(f)
    assert doc['vaultActivation'] == r1.VAULT_HEIGHT and doc['pqFalconHeight'] == 0
    print(fixture)
    nodes = []
    try:
        y6 = r1.start(args.ycash6_bin, workdir, 'ycash6', pb + 1, pb + 2,
                      ['-listen=0', '-connect=0', AWARE])
        nodes.append((r1.Node('ycash6', pb + 2), y6))
        dd = r1.start(args.ycash_dd_bin, workdir, 'ycash-dd', pb + 3, pb + 4,
                      ['-listen=0', '-connect=0'])
        nodes.append((r1.Node('ycash-dd', pb + 4), dd))
        for node, _ in nodes:
            r1.wait(lambda: node.ok('getblockcount') == 0, node.name)
        miner = nodes[0][0].ok('getnewaddress')
        z = km.Node('kogany', pb + 6)
        zp = km.start_zakurad(args.koganyd, workdir,
                              kogany_toml(workdir, pb + 5, pb + 6, pb + 7, doc['vaultActivation'],
                                          miner), False)
        km.wait_up(z, zp, 'koganyd')
        nodes.append((z, zp))
        cxx = [n for n, _ in nodes[:2]]

        for h, block in enumerate(doc['blocks'][:doc['setupTip']], 1):
            for node in cxx + [z]:
                answer = node.ok('submitblock', block)
                if answer is not None:
                    raise km.Failure('%s: setup block %d answered %r' % (node.name, h, answer))
        for node in cxx + [z]:
            r1.wait(lambda: node.ok('getblockcount') == doc['setupTip'], node.name + ' setup')

        for name, txid, raw in raw_shapes(doc):
            km.check(z.ok('sendrawtransaction', raw) == txid, '%s: kogany took it' % name)
            t = z.ok('getblocktemplate')
            km.check(any(tx['hash'] == txid for tx in t['transactions']),
                     '%s is in kogany\'s template' % name)
            header, tries = km.solve(t, solver)
            block = km.block_hex(header, t)
            for node in [z] + cxx:
                answer = node.ok('submitblock', block)
                km.check(answer is None, '%s: %s answered %r to kogany\'s block' % (name, node.name, answer))
            tips = {node.name: node.ok('getbestblockhash') for node in [z] + cxx}
            km.check(len(set(tips.values())) == 1, '%s: one tip: %r' % (name, tips))
            print('  %-40s kogany templated it; ycash6 and ycash-dd accept block %d (%d nonces)'
                  % (name, t['height'], tries))
    finally:
        for node, proc in reversed(nodes):
            stop_node(node, proc)


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('--koganyd', required=True)
    p.add_argument('--ycash6-bin', required=True)
    p.add_argument('--ycash-dd-bin', required=True)
    p.add_argument('--solver-dir', required=True, help="ycash6's qa/rpc-tests (test_framework/equihash.py)")
    p.add_argument('--fixture', action='append', help='default: chain.json and chain2.json')
    p.add_argument('--workdir')
    p.add_argument('--port-base', type=int, default=24760)
    args = p.parse_args(argv)
    solver = km.load_solver(args.solver_dir)
    workdir = args.workdir or tempfile.mkdtemp(prefix='kogany-mines-shapes-')
    try:
        for k, fixture in enumerate(args.fixture or ['chain.json', 'chain2.json']):
            sub = os.path.join(workdir, fixture.replace('.json', ''))
            os.makedirs(sub, exist_ok=True)
            run_fixture(args, solver, fixture, sub, args.port_base + 10 * k)
    finally:
        if not args.workdir:
            shutil.rmtree(workdir, ignore_errors=True)
    return 0


if __name__ == '__main__':
    sys.exit(main())
