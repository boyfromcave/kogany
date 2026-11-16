#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .
"""kogany's `transparentPools` and `transactions`, checked against ycashd on the chain of the
C++ lines' functional test (beta3 items 2 and 11; workspace docs/plans/beta3/value-pools.md §5,
"ycash6 = kogany").

    python crates/kogany-rpc/qa/value_pools_parity.py --koganyd <koganyd, the --features ycash build> \\
        --ycashd-bin <a directory holding a ycashd with transparentPools> \\
        --ycash6-qa <ycash6's qa/rpc-tests, the same commit as that ycashd> \\
        [--scenario-datadir <node 0 of an earlier run, instead of --ycash6-qa>] \\
        [--python <the interpreter that runs ycash6's test>] [--extra-blocks 1010] \\
        [--workdir DIR] [--keep] [--port-base N]

THE CHAIN. The script first runs ycash6's `value_pools_by_type.py` as it is, with `--nocleanup`:
ycashd mines a regtest chain (Vault and FN-DSA-512 at height 200) that creates and spends every
class: P2PKH, P2SH, TX_PQPKH in both schemes, a PQ channel, a YED-tagged vault and intent, a vault
and an intent under another tag, and OP_RETURN with value, with a reorganisation on the way. The
test must pass. ycashd is then started again on that test's node 0, and a fresh koganyd is given
the chain one block at a time (`submitblock`, which must answer null for every block: a refusal
is a consensus difference and stops the run).

THE CHECKS, at every height:

1. `getblock <h> 1` and `getblock <h> 2`: kogany's `transparentPools` is ycashd's, compared as
   JSON text: the same names in the same order, the same shape, the same numbers.
2. `getblockchaininfo` on kogany when the block is its tip: `transparentPools` is ycashd's record
   of that block without the deltas, and `transactions` is the number of transactions in
   ycashd's chain up to that block (ycashd's `nChainTx`, summed here from its blocks).
3. kogany's own figures agree: `transparent` is its `valuePools` transparent entry.

At the tip both nodes answer `getblockchaininfo`, and `transparentPools` and `transactions` are
compared directly; `vault` is `vault_getinfo.lockedvalue` on both.

FINALIZED AND NON-FINALIZED. kogany keeps the last blocks in memory and derives their figures on
each read; older blocks have rows on disk. The scenario's chain is shorter than that window, so
every check above runs first against derived figures. ycashd then mines `--extra-blocks` more
(default 1,010, past kogany's regtest window of 1,000), kogany takes them, and every height is
checked again: the scenario's blocks are now answered from rows. Last, kogany is stopped and
started, is given again any block above the height it comes back at, and every height is checked
a third time.

Exit 0 when every check passes, 1 on a failed check, 2 on an RPC or startup error. Stdlib only.
"""

import argparse
import base64
import json
import os
import shutil
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from collections import OrderedDict

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from kogany_mines import VAULT_BRANCH, Failure, check, wait_for  # noqa: E402
from rpc_ycash_parity import ACTIVATION_KEYS, NUPARAMS, Node, RpcError, stop, wait_up  # noqa: E402

SCENARIO = 'value_pools_by_type.py'
VAULT = 200                  # ycash6 qa/rpc-tests/test_framework/vault_harness.py ACTIVATION
DELTA_KEYS = ('valueDelta', 'valueDeltaZat')


class OrderedNode(Node):
    """A node whose answers keep the key order the node wrote."""

    def call(self, method, *params):
        body = json.dumps({'jsonrpc': '1.0', 'id': 1, 'method': method, 'params': list(params)}).encode()
        req = urllib.request.Request('http://127.0.0.1:%d/' % self.port, body, {'Content-Type': 'application/json'})
        if self.auth:
            req.add_header('Authorization', 'Basic ' + base64.b64encode(self.auth.encode()).decode())
        try:
            raw = urllib.request.urlopen(req, timeout=300).read()
        except urllib.error.HTTPError as e:
            raw = e.read()
        except (urllib.error.URLError, ConnectionError) as e:
            raise RpcError('%s: %s: %s' % (self.name, method, e))
        answer = json.loads(raw, object_pairs_hook=OrderedDict)
        return answer.get('result'), answer.get('error')


def text(value):
    """The JSON text of a value, key order kept: equal texts are equal names, order and numbers."""
    return json.dumps(value, separators=(',', ':'))


def without_deltas(pools):
    """A getblock `transparentPools` as getblockchaininfo writes it: no per-block deltas."""
    def strip(entry):
        return OrderedDict((k, v) for k, v in entry.items() if k not in DELTA_KEYS)
    out = OrderedDict()
    for key, value in pools.items():
        out[key] = strip(value) if isinstance(value, dict) else \
            [strip(e) for e in value] if isinstance(value, list) else value
    return out


def run_scenario(args, workdir):
    """Runs ycash6's functional test and returns its node 0 data directory."""
    script = os.path.join(args.ycash6_qa, SCENARIO)
    check(os.path.exists(script), '%s is not in %s' % (SCENARIO, args.ycash6_qa))
    tmpdir = os.path.join(workdir, 'scenario')
    env = dict(os.environ, ZCASHD=os.path.join(args.ycashd_bin, 'ycashd'))
    cmd = [args.python, '-u', script, '--srcdir=' + args.ycashd_bin, '--tmpdir=' + tmpdir,
           '--portseed=%d' % args.port_base, '--nocleanup']
    with open(os.path.join(workdir, 'scenario.out'), 'w') as log:
        code = subprocess.call(cmd, cwd=args.ycash6_qa, env=env, stdout=log, stderr=subprocess.STDOUT)
    check(code == 0, "ycash6's %s failed (exit %d): see %s" % (SCENARIO, code, os.path.join(workdir, 'scenario.out')))
    # The framework works in a subdirectory named after the port seed.
    for datadir in (os.path.join(tmpdir, str(args.port_base), 'node0'), os.path.join(tmpdir, 'node0')):
        if os.path.isdir(datadir):
            return datadir
    raise Failure('no node0 under %s' % tmpdir)


def conf_of(datadir):
    """The rpcuser and rpcpassword of the test's node."""
    for name in ('ycash.conf', 'zcash.conf'):
        path = os.path.join(datadir, name)
        if os.path.exists(path):
            conf = dict(line.strip().split('=', 1) for line in open(path, encoding='utf8') if '=' in line)
            return conf['rpcuser'], conf['rpcpassword']
    raise Failure('no ycash.conf in %s' % datadir)


def start_ycashd(bindir, datadir, workdir, port, rpcport):
    """ycashd on the scenario's data directory, with the scenario's consensus arguments."""
    args = [os.path.join(bindir, 'ycashd'), '-datadir=' + datadir, '-discover=0', '-listen=0',
            '-port=%d' % port, '-rpcport=%d' % rpcport, '-experimentalfeatures',
            '-i-am-aware-zcashd-will-be-replaced-by-zebrad-and-zallet-in-2025']
    # test_framework/util.py start_node and yellowback_util.py YCASH_UPGRADE_ARGS: every upgrade
    # through Canopy at height 1; vault_harness.py: Vault at ACTIVATION; the scenario's own -pqfalcon=1.
    args += ['-nuparams=%s:1' % b for b in NUPARAMS]
    args += ['-nuparams=%s:%d' % (VAULT_BRANCH, VAULT), '-pqfalcon=1']
    log = open(os.path.join(workdir, 'ycashd.out'), 'a')
    return subprocess.Popen(args, stdout=log, stderr=subprocess.STDOUT)


def koganyd_toml(workdir, p2p, rpc, v2):
    root = os.path.join(workdir, 'koganyd')
    heights = '\n'.join(['%s = 1' % k for k in ACTIVATION_KEYS]
                        + ['Vault = %d' % VAULT, 'pq_falcon_height = %d' % VAULT])
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

[mining]
internal_miner = false

[tracing]
use_color = false
filter = "info"
'''.format(p2p=p2p, rpc=rpc, v2=v2, root=root, heights=heights)


def start_koganyd(binary, workdir, toml):
    path = os.path.join(workdir, 'koganyd.toml')
    with open(path, 'w') as f:
        f.write(toml)
    log = open(os.path.join(workdir, 'koganyd.out'), 'a')
    return subprocess.Popen([binary, '-c', path, 'start'], stdout=log, stderr=subprocess.STDOUT)


class Chain:
    """ycashd's chain, read once per height: the block, its record and the running count."""

    def __init__(self, y):
        self.y, self.hashes, self.raw, self.pools, self.chain_tx = y, [], [], [], []

    def extend(self):
        tip = self.y.ok('getblockcount')
        for h in range(len(self.hashes), tip + 1):
            block_hash = self.y.ok('getblockhash', h)
            block = self.y.ok('getblock', block_hash, 1)
            check('transparentPools' in block, 'the ycashd under test has no transparentPools')
            self.hashes.append(block_hash)
            self.raw.append(self.y.ok('getblock', block_hash, 0))
            self.pools.append(block['transparentPools'])
            self.chain_tx.append((self.chain_tx[-1] if self.chain_tx else 0) + len(block['tx']))
        return tip


def transparent_entry(value_pools):
    return next(e for e in value_pools if e.get('id') == 'transparent')


def check_tip_info(z, chain, h):
    """Check 2 and the tip half of check 3, when block `h` is kogany's tip."""
    info = z.ok('getblockchaininfo')
    check(info['blocks'] == h and info['bestblockhash'] == chain.hashes[h],
          'kogany is at %s %s, not at height %d' % (info['blocks'], info['bestblockhash'], h))
    check(text(info.get('transparentPools')) == text(without_deltas(chain.pools[h])),
          'getblockchaininfo.transparentPools at height %d:\n  ycashd %s\n  kogany %s'
          % (h, text(without_deltas(chain.pools[h])), text(info.get('transparentPools'))))
    check(info.get('transactions') == chain.chain_tx[h],
          'getblockchaininfo.transactions at height %d: ycashd %d, kogany %r'
          % (h, chain.chain_tx[h], info.get('transactions')))
    check(info['transparentPools']['transparent']['chainValueZat'] == transparent_entry(info['valuePools'])['chainValueZat'],
          'kogany at height %d: transparentPools.transparent is not its valuePools transparent entry' % h)


def check_heights(z, chain, heights, context):
    """Check 1 and the getblock half of check 3."""
    for h in heights:
        want = text(chain.pools[h])
        for verbosity in (1, 2):
            block = z.ok('getblock', chain.hashes[h], verbosity)
            check(text(block.get('transparentPools')) == want,
                  '%s: getblock %d %d transparentPools:\n  ycashd %s\n  kogany %s'
                  % (context, h, verbosity, want, text(block.get('transparentPools'))))
        check(block['transparentPools']['transparent']['chainValueZat'] == transparent_entry(block['valuePools'])['chainValueZat'],
              '%s: kogany at height %d: transparentPools.transparent is not its valuePools transparent entry'
              % (context, h))
    # The same block by height.
    for h in (heights[0], heights[-1]):
        block = z.ok('getblock', str(h), 1)
        check(text(block.get('transparentPools')) == text(chain.pools[h]), '%s: getblock by height %d' % (context, h))


def feed(z, chain, start, per_block):
    """Gives kogany the blocks from `start`; each must be accepted and become its tip."""
    for h in range(start, len(chain.hashes)):
        result, error = z.call('submitblock', chain.raw[h])
        check(error is None and result is None,
              'CONSENSUS DIFFERENCE: kogany refuses block %d %s that ycashd mined: %r %r'
              % (h, chain.hashes[h], result, error))
        wait_for('kogany at height %d' % h, lambda: z.ok('getbestblockhash') == chain.hashes[h])
        if per_block:
            check_tip_info(z, chain, h)


def classes_seen(chain):
    """The scenario must really exercise every class: the comparison is of non-zero numbers."""
    seen = set()
    for pools in chain.pools:
        seen.update(e['id'] for e in pools['pools'] if e['chainValueZat'] > 0)
        seen.update('scheme %d' % e['pqscheme'] for e in pools['pq_by_scheme'] if e['chainValueZat'] > 0)
        seen.update('module ' + e['module'] for e in pools['vault_by_module'] if e['chainValueZat'] > 0)
    want = {'transparent_ecc', 'transparent_pq', 'pq_channel', 'vault', 'vault_intent', 'scheme 1', 'scheme 2',
            'module YED'}
    check(seen == want, 'the chain does not exercise %s' % sorted(want - seen))


def main():
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    ap.add_argument('--koganyd', required=True)
    ap.add_argument('--ycashd-bin', required=True)
    ap.add_argument('--ycash6-qa', help="ycash6's qa/rpc-tests; required unless --scenario-datadir is given")
    ap.add_argument('--scenario-datadir',
                    help='node 0 of an earlier run of the scenario (kept with --keep or --workdir); the run mines on it')
    ap.add_argument('--python', default=sys.executable)
    ap.add_argument('--extra-blocks', type=int, default=1010)
    ap.add_argument('--workdir')
    ap.add_argument('--keep', action='store_true')
    ap.add_argument('--port-base', type=int, default=21800)
    args = ap.parse_args()
    if not (args.ycash6_qa or args.scenario_datadir):
        ap.error('one of --ycash6-qa and --scenario-datadir is required')

    workdir = args.workdir or tempfile.mkdtemp(prefix='kogany-value-pools-')
    os.makedirs(workdir, exist_ok=True)
    base = args.port_base
    procs = []
    try:
        if args.scenario_datadir:
            datadir = args.scenario_datadir
            print('ok   the chain of an earlier run of %s: %s' % (SCENARIO, datadir))
        else:
            datadir = run_scenario(args, workdir)
            print('ok   ycash6 %s passed' % SCENARIO)
        y = OrderedNode('ycashd', base + 1, '%s:%s' % conf_of(datadir))
        z = OrderedNode('kogany', base + 3)
        procs.append(start_ycashd(args.ycashd_bin, datadir, workdir, base, base + 1))
        wait_up(y, procs[-1], 'ycashd')
        toml = koganyd_toml(workdir, base + 2, base + 3, base + 4)
        procs.append(start_koganyd(args.koganyd, workdir, toml))
        wait_up(z, procs[-1], 'koganyd')

        chain = Chain(y)
        tip = chain.extend()
        classes_seen(chain)
        check(z.ok('getblockhash', 0) == chain.hashes[0], 'the two nodes are on different regtest chains')
        check_tip_info(z, chain, 0)
        feed(z, chain, 1, per_block=True)
        check_heights(z, chain, range(0, tip + 1), 'derived')
        print('ok   %d blocks: transparentPools and transactions equal at every height (non-finalized)' % (tip + 1))

        # The tip, node against node.
        yi, zi = y.ok('getblockchaininfo'), z.ok('getblockchaininfo')
        check(text(yi['transparentPools']) == text(zi['transparentPools']), 'getblockchaininfo.transparentPools at the tip')
        check(yi['transactions'] == zi['transactions'], 'getblockchaininfo.transactions at the tip: ycashd %r, kogany %r'
              % (yi['transactions'], zi.get('transactions')))
        locked = [int(round(float(n.ok('vault_getinfo')['lockedvalue']) * 1e8)) for n in (y, z)]
        vault = next(e for e in zi['transparentPools']['pools'] if e['id'] == 'vault')['chainValueZat']
        check(locked == [vault, vault], 'vault %d is not vault_getinfo.lockedvalue %r' % (vault, locked))
        print('ok   the tip: transparentPools, transactions (%d) and vault = lockedvalue (%d zat) on both nodes'
              % (zi['transactions'], vault))

        # Past kogany's non-finalized window: the scenario's blocks are now rows on disk.
        mined = 0
        while mined < args.extra_blocks:
            n = min(100, args.extra_blocks - mined)
            y.ok('generate', n)
            mined += n
        first_new = tip + 1
        tip = chain.extend()
        feed(z, chain, first_new, per_block=False)
        check_tip_info(z, chain, tip)
        check_heights(z, chain, range(0, tip + 1), 'finalized')
        print('ok   %d blocks: equal at every height again (the first %d from rows on disk)'
              % (tip + 1, max(0, tip + 1 - 1000)))

        # A restart: kogany takes again any block above the height it comes back at.
        stop(procs.pop())
        procs.append(start_koganyd(args.koganyd, workdir, toml))
        wait_up(z, procs[-1], 'koganyd')
        back_at = z.ok('getblockcount')
        check(0 < back_at <= tip, 'kogany restarted at height %d' % back_at)
        check(z.ok('getbestblockhash') == chain.hashes[back_at], 'kogany restarted on another chain')
        check_tip_info(z, chain, back_at)
        feed(z, chain, back_at + 1, per_block=False)
        check_tip_info(z, chain, tip)
        check_heights(z, chain, range(0, tip + 1), 'restarted')
        print('ok   a restart at height %d: equal at every height again' % back_at)
        print('PASS')
        return 0
    except Failure as e:
        print('FAIL %s' % e)
        return 1
    except RpcError as e:
        print('ERROR %s' % e)
        return 2
    finally:
        for p in reversed(procs):
            stop(p)
        if not args.keep and not args.workdir:
            shutil.rmtree(workdir, ignore_errors=True)


if __name__ == '__main__':
    sys.exit(main())
