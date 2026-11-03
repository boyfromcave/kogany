#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""kogany mines: kogany templates solved by the Python (48,5) solver, relayed to ycashd (W8-c).

    python crates/kogany-rpc/qa/kogany_mines.py --koganyd <koganyd, the --features ycash build> \\
        [--ycash6-bin $WS/wt/.bin/ycash6-65cb4ae0f] [--solver-dir $WS/ycash6/qa/rpc-tests] \\
        [--rounds 20] [--premine 101] [--vault-height H] [--no-yed-mock] [--workdir DIR] [--keep]

kogany validates Equihash (192,7) and never solves it, and on regtest it checks the solution shape
only (plan K-16, mapping M24-20), so a kogany-built regtest block is solved here, outside the
node, by the test framework's pure-Python Wagner solver (ycash6
`qa/rpc-tests/test_framework/equihash.py`, `gbp_basic`; the solver the `stratum-miner` uses) and
checked by the C++ node, which does verify (48,5).

It starts a ycashd and a zakurad on one Ycash regtest, every upgrade through Canopy at height 1
and Vault (`6d5b7a31`) at `--vault-height` (default: the middle of the rounds), the two peered
over P2P (kogany dials ycashd). ycashd generates `--premine` blocks, which kogany takes by
`submitblock`. Then each of `--rounds` rounds:

1. every `--tx-every` rounds (except the four before Vault, where ycashd's expiry cap at the
   upgrade makes the spend expire too soon to relay), ycashd's wallet signs a one-in one-out spend at the ZIP 317 fee and
   kogany's mempool takes it by `sendrawtransaction`; the next kogany template must carry it;
2. from `--quote-height` on (default: two blocks after the Vault activation) kogany holds a
   node-local quote (`yed_setquote`): the template's `coinbaseaux.flags` must be the 37-byte
   `YED!` tag push and the coinbase input script must end with it; before it, no `YED!` anywhere;
3. kogany's `getblocktemplate` becomes a header, the solver finds a (48,5) solution whose block
   hash meets the template target, and the block goes back to kogany by `submitblock` (answer
   `null`);
4. ycashd must reach that block **by P2P relay from kogany** (never fed to it), and both tips
   must be equal.

At the end both nodes report Vault active at the configured height and the tip's branch
`6d5b7a31`, and every kogany-built block is on ycashd's main chain.

The YED tag needs a live Yellowback state in kogany. Until plan W5-f registers the module, kogany
serves `MockYedState` under `KOGANY_YED_RPC_MOCK=1` (the default here; `--no-yed-mock` runs
without it, and then no template carries a tag and the tag checks are skipped). The mock's payout
key is a fixture (`0x51` x 20), not the miner address: ycashd accepts the tag as plain coinbase
bytes (the tag is node policy, not consensus, TAG-4). ycashd here has no YED attestor set, so
its Yellowback is not live; the tag is decoded by this script.

Exit 0 when every round passes, 1 on a failed assertion, 2 on an RPC or startup error.
"""

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from rpc_ycash_parity import (  # noqa: E402
    ACTIVATION_KEYS, NUPARAMS, Node, RpcError, decode_coinbase, internal, stop, wait_up)

VAULT_BRANCH = '6d5b7a31'
COINBASE_MATURITY = 100
TAG_MAGIC = b'YED!'
TAG_SIZE = 36                  # magic 4 | version 1 | flags 1 | price 8 | mask 2 | payout key 20
QUOTE_MICRO_USD = 50_000       # $0.05, the yolo regtest test's quote
QUOTE_SOURCES = 1
N, K = 48, 5                   # Equihash on Ycash regtest (ycash6 src/chainparams.cpp)
ZIP317_FEE = 10_000            # two grace actions at 5,000 zatoshis


class Failure(Exception):
    pass


def find_up(*parts):
    """The first ancestor of this script (or `$WS`) holding `parts`, joined; None when none does."""
    roots = [os.getenv('WS')] if os.getenv('WS') else []
    d = HERE
    while True:
        roots.append(d)
        parent = os.path.dirname(d)
        if parent == d:
            break
        d = parent
    for r in roots:
        p = os.path.join(r, *parts)
        if os.path.exists(p):
            return p
    return None


def load_solver(solver_dir):
    sys.path.insert(0, solver_dir)
    from test_framework.equihash import gbp_basic, gbp_validate, zcash_person
    return gbp_basic, gbp_validate, zcash_person


def compact_size(n):
    if n < 0xfd:
        return bytes([n])
    if n <= 0xffff:
        return b'\xfd' + n.to_bytes(2, 'little')
    return b'\xfe' + n.to_bytes(4, 'little')


def sha256d(b):
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def header_prefix(t):
    """The 108 header bytes before the nonce: version, prev, merkle root, the header commitment
    (`blockcommitmentshash`: the chain history root before NU5), time, bits."""
    return (int(t['version']).to_bytes(4, 'little')
            + internal(t['previousblockhash'])
            + internal(t['defaultroots']['merkleroot'])
            + internal(t['blockcommitmentshash'])
            + int(t['curtime']).to_bytes(4, 'little')
            + int(t['bits'], 16).to_bytes(4, 'little'))


def solve(t, solver, start_nonce=0, max_nonces=100_000):
    """A full header (with nonce and compact-size solution) whose hash meets the template target."""
    gbp_basic, gbp_validate, zcash_person = solver
    prefix = header_prefix(t)
    target = int(t['target'], 16)
    base = hashlib.blake2b(digest_size=(512 // N) * N // 8, person=zcash_person(N, K))
    base.update(prefix)
    for i in range(start_nonce, start_nonce + max_nonces):
        nonce = i.to_bytes(32, 'little')
        digest = base.copy()
        digest.update(nonce)
        for soln in gbp_basic(digest, N, K):
            if not gbp_validate(digest, soln, N, K):
                raise Failure('the solver returned an invalid solution')
            header = prefix + nonce + compact_size(len(soln)) + soln
            if int.from_bytes(sha256d(header), 'little') <= target:
                return header, i - start_nonce + 1
    raise Failure('no (48,5) solution under the target in %d nonces' % max_nonces)


def block_hex(header, t):
    txs = [t['coinbasetxn']['data']] + [tx['data'] for tx in t['transactions']]
    return (header + compact_size(len(txs))).hex() + ''.join(txs)


def start_ycashd(bindir, workdir, port, rpcport, vault_height):
    datadir = os.path.join(workdir, 'ycashd')
    os.makedirs(datadir, exist_ok=True)
    with open(os.path.join(datadir, 'ycash.conf'), 'w') as f:
        f.write('regtest=1\nshowmetrics=0\nrpcuser=u\nrpcpassword=p\nport=%d\nrpcport=%d\n'
                'listen=1\nlistenonion=0\ndiscover=0\nrpcallowip=127.0.0.1\n' % (port, rpcport))
    args = [os.path.join(bindir, 'ycashd'), '-datadir=' + datadir, '-experimentalfeatures',
            '-i-am-aware-zcashd-will-be-replaced-by-zebrad-and-zallet-in-2025']
    args += ['-nuparams=%s:1' % b for b in NUPARAMS]
    args.append('-nuparams=%s:%d' % (VAULT_BRANCH, vault_height))
    log = open(os.path.join(workdir, 'ycashd.out'), 'a')
    return subprocess.Popen(args, stdout=log, stderr=subprocess.STDOUT)


def zakurad_toml(workdir, p2p, rpc, v2, peer_p2p, vault_height, miner_address):
    root = os.path.join(workdir, 'zakurad')
    heights = '\n'.join(['%s = 1' % k for k in ACTIVATION_KEYS] + ['Vault = %d' % vault_height])
    return '''[network]
listen_addr = "127.0.0.1:{p2p}"
initial_testnet_peers = ["127.0.0.1:{peer}"]
p2p_stack = "legacy"
max_connections_per_ip = 1
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
miner_address = "{miner}"

[tracing]
use_color = false
filter = "info"
'''.format(p2p=p2p, rpc=rpc, v2=v2, peer=peer_p2p, root=root, heights=heights,
           miner=miner_address)


def start_zakurad(binary, workdir, toml, yed_mock):
    path = os.path.join(workdir, 'zakurad.toml')
    with open(path, 'w') as f:
        f.write(toml)
    env = dict(os.environ)
    env.pop('KOGANY_YED_RPC_MOCK', None)
    if yed_mock:
        env['KOGANY_YED_RPC_MOCK'] = '1'
    log = open(os.path.join(workdir, 'zakurad.out'), 'a')
    return subprocess.Popen([binary, '-c', path, 'start'], stdout=log, stderr=subprocess.STDOUT,
                            env=env)


def wait_for(what, pred, timeout=60, step=0.2):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if pred():
            return
        time.sleep(step)
    raise Failure('timed out (%d s) waiting for %s' % (timeout, what))


def check(cond, msg):
    if not cond:
        raise Failure(msg)


def script_sig_of(coinbase_hex):
    c = decode_coinbase(coinbase_hex)
    return bytes.fromhex(c['height_push'] + c['script_sig_tail'])


def zip317_spend(y, address, used):
    """A one-in one-out spend of a mature coin of ycashd's wallet at the ZIP 317 fee (kogany's
    mempool refuses ycashd's default fee: rpc_ycash_parity finding F-2). Returns (txid, hex)."""
    coins = [u for u in y.ok('listunspent', COINBASE_MATURITY + 1)
             if u['spendable'] and u['amount'] > 1 and (u['txid'], u['vout']) not in used]
    check(coins, 'ycashd has no mature coin left to spend')
    coin = coins[0]
    used.add((coin['txid'], coin['vout']))
    out = {address: float(round(coin['amount'] - ZIP317_FEE / 1e8, 8))}
    unsigned = y.ok('createrawtransaction', [{'txid': coin['txid'], 'vout': coin['vout']}], out)
    signed = y.ok('signrawtransaction', unsigned)
    check(signed['complete'], 'ycashd could not sign: %r' % signed)
    return signed['hex']


def run(args, solver):
    workdir = args.workdir or tempfile.mkdtemp(prefix='kogany-mines-')
    os.makedirs(workdir, exist_ok=True)
    base = args.port_base
    y = Node('ycash6', base + 1, 'u:p')
    z = Node('kogany', base + 11)
    first = args.premine + 1
    last = args.premine + args.rounds
    vault = args.vault_height or first + args.rounds // 2
    quote_height = args.quote_height or vault + 2
    check(first < vault <= last, 'the Vault height %d must fall inside the rounds %d..%d'
          % (vault, first, last))
    print('kogany_mines: workdir %s; rounds %d..%d, Vault at %d, quote from %d, YED mock %s'
          % (workdir, first, last, vault, quote_height, 'on' if args.yed_mock else 'off'))
    procs = []
    results = []
    try:
        procs.append(start_ycashd(args.ycash6_bin, workdir, base, base + 1, vault))
        wait_up(y, procs[-1], 'ycashd')
        miner = y.ok('getnewaddress')
        y.ok('generate', args.premine)
        procs.append(start_zakurad(args.zakurad, workdir,
                                   zakurad_toml(workdir, base + 10, base + 11, base + 12, base,
                                                vault, miner),
                                   args.yed_mock))
        wait_up(z, procs[-1], 'zakurad')

        # The premine: ycashd's blocks to kogany (submitblock; a block kogany already has from
        # the P2P peer is answered "duplicate").
        for h in range(1, args.premine + 1):
            raw = y.ok('getblock', y.ok('getblockhash', h), 0)
            res = z.ok('submitblock', raw)
            check(res in (None, 'duplicate', 'inconclusive'),
                  'kogany refused premine block %d: %r' % (h, res))
        want = y.ok('getbestblockhash')
        wait_for('kogany at the premine tip', lambda: z.ok('getbestblockhash') == want)
        wait_for('the kogany-ycashd P2P connection', lambda: len(y.ok('getpeerinfo')) > 0
                 and len(z.ok('getpeerinfo')) > 0, timeout=90)

        recipient = y.ok('getnewaddress')
        used = set()
        quote_payout = None
        tagged = 0
        for height in range(first, last + 1):
            rnd = height - first + 1
            pending = None
            if args.yed_mock and quote_payout is None and height >= quote_height:
                ack = z.ok('yed_setquote', QUOTE_MICRO_USD, QUOTE_SOURCES)
                quote_payout = (ack.get('nextTag') or {}).get('payoutAddress') or '(none)'
                print('  yed_setquote %d %d on kogany: %s' % (QUOTE_MICRO_USD, QUOTE_SOURCES,
                                                              json.dumps(ack, sort_keys=True)))
            # ycashd caps a transaction's expiry at the block before an upgrade, and a node refuses
            # one that expires within three blocks (`tx-expiring-soon`): no spend just before Vault.
            if args.tx_every and rnd % args.tx_every == 0 and not vault - 4 <= height < vault:
                raw = zip317_spend(y, recipient, used)
                pending = z.ok('sendrawtransaction', raw)
                y.call('sendrawtransaction', raw, True)
                wait_for('the spend in kogany\'s mempool',
                         lambda: pending in z.ok('getrawmempool'), timeout=30)

            t = z.ok('getblocktemplate')
            check(t['height'] == height, 'template height %s, want %d' % (t['height'], height))
            check(t['previousblockhash'] == y.ok('getbestblockhash'),
                  'the template does not build on ycashd\'s tip')
            in_template = [tx['hash'] for tx in t['transactions']]
            if pending:
                check(pending in in_template, 'height %d: the template leaves out %s (%r)'
                      % (height, pending, in_template))
            flags = bytes.fromhex(t.get('coinbaseaux', {}).get('flags', '') or '')
            script_sig = script_sig_of(t['coinbasetxn']['data'])
            if quote_payout is not None:
                check(len(flags) == TAG_SIZE + 1 and flags[0] == TAG_SIZE
                      and flags[1:5] == TAG_MAGIC,
                      'height %d: coinbaseaux.flags is not the YED! tag push: %s'
                      % (height, flags.hex()))
                check(script_sig.endswith(flags), 'height %d: the coinbase input script %s does '
                      'not end with the tag %s' % (height, script_sig.hex(), flags.hex()))
                price = int.from_bytes(flags[7:15], 'little')
                mask = int.from_bytes(flags[15:17], 'little')
                check((price, mask) == (QUOTE_MICRO_USD, QUOTE_SOURCES),
                      'height %d: tag quote %d/%d' % (height, price, mask))
                tagged += 1
            else:
                check(TAG_MAGIC not in script_sig and not flags,
                      'height %d: a YED! tag before any quote: %s' % (height, script_sig.hex()))

            started = time.time()
            header, tries = solve(t, solver, start_nonce=height << 20)
            block = block_hex(header, t)
            bhash = sha256d(header)[::-1].hex()
            res = z.ok('submitblock', block)
            check(res is None, 'height %d: kogany refused its own block: %r' % (height, res))
            try:
                wait_for('ycashd to receive block %s by relay' % bhash,
                         lambda: y.ok('getbestblockhash') == bhash, timeout=args.relay_timeout)
            except Failure:
                verdict = y.call('submitblock', block)
                raise Failure('height %d: ycashd did not reach kogany\'s block %s by relay '
                              '(ycashd tip %s; ycashd submitblock now says %r)'
                              % (height, bhash, y.ok('getbestblockhash'), verdict))
            check(z.ok('getbestblockhash') == bhash, 'height %d: kogany tip moved' % height)
            yb = y.ok('getblock', bhash, 1)
            check(yb['height'] == height and len(yb['tx']) == 1 + len(t['transactions']),
                  'height %d: ycashd block shape %r' % (height, {k: yb[k] for k in ('height',)}))
            if pending:
                check(pending in yb['tx'], 'height %d: the spend is not in the block' % height)
            branch = y.ok('getblockchaininfo')['consensus']['chaintip']
            results.append((height, bhash, len(yb['tx']), bool(quote_payout), branch, tries,
                            time.time() - started))
            print('  round %2d height %3d %s txs %d tag %-3s branch %s nonces %d %.2fs'
                  % (rnd, height, bhash[:16], len(yb['tx']), 'yes' if quote_payout else 'no',
                     branch, tries, time.time() - started))

        for node in (y, z):
            info = node.ok('getblockchaininfo')
            check(info['blocks'] == last, '%s at %s, want %d' % (node.name, info['blocks'], last))
            up = info['upgrades'].get(VAULT_BRANCH, {})
            check(up.get('status') == 'active' and up.get('activationheight') == vault,
                  '%s: Vault %r' % (node.name, up))
            check(info['consensus']['chaintip'] == VAULT_BRANCH,
                  '%s: tip branch %s' % (node.name, info['consensus']['chaintip']))
        check(y.ok('getbestblockhash') == z.ok('getbestblockhash'), 'the tips differ')
        for height, bhash, *_ in results:
            check(y.ok('getblockhash', height) == bhash,
                  'ycashd main chain at %d is not kogany\'s block' % height)
        pre = sum(1 for r in results if r[0] < vault)
        print('kogany_mines: ok: %d kogany blocks accepted by ycashd by relay (%d before Vault at '
              '%d, %d from it; %d with the YED! tag; %d with a spend), tips equal at %d'
              % (len(results), pre, vault, len(results) - pre, tagged,
                 sum(1 for r in results if r[2] > 1), last))
        if args.yed_mock:
            check(tagged > 0, 'no round carried the YED! tag')
            print('kogany_mines: tag payout address (the mock fixture key): %s' % quote_payout)
    finally:
        for p in reversed(procs):
            stop(p)
        if not args.keep and not args.workdir:
            shutil.rmtree(workdir, ignore_errors=True)
    return results


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    ap.add_argument('--koganyd', '--zakurad', dest='zakurad', default=os.getenv('KOGANY_BIN'),
                    help='koganyd (the --features ycash build; --zakurad is its old name)')
    ap.add_argument('--ycash6-bin', default=find_up('wt', '.bin', 'ycash6-65cb4ae0f'),
                    help='directory holding ycashd')
    ap.add_argument('--solver-dir', default=find_up('ycash6', 'qa', 'rpc-tests'),
                    help='the ycash6 qa/rpc-tests directory (test_framework/equihash.py)')
    ap.add_argument('--rounds', type=int, default=20)
    ap.add_argument('--premine', type=int, default=COINBASE_MATURITY + 1,
                    help='blocks ycashd generates first (101: mature coins for the spends)')
    ap.add_argument('--vault-height', type=int, help='default: the middle of the rounds')
    ap.add_argument('--quote-height', type=int, help='default: two blocks after Vault')
    ap.add_argument('--tx-every', type=int, default=4, help='a spend every N rounds (0: none)')
    ap.add_argument('--no-yed-mock', dest='yed_mock', action='store_false',
                    help='run kogany without KOGANY_YED_RPC_MOCK=1 (no tag)')
    ap.add_argument('--relay-timeout', type=int, default=60)
    ap.add_argument('--workdir', help='keep the datadirs here (default: a temporary directory)')
    ap.add_argument('--keep', action='store_true', help='keep the temporary directory')
    ap.add_argument('--port-base', type=int, default=29700)
    args = ap.parse_args(argv)
    if not args.zakurad:
        ap.error('--koganyd (or KOGANY_BIN) is required')
    if not args.ycash6_bin or not os.path.exists(os.path.join(args.ycash6_bin, 'ycashd')):
        ap.error('--ycash6-bin: no ycashd in %r' % args.ycash6_bin)
    if not args.solver_dir or not os.path.exists(
            os.path.join(args.solver_dir, 'test_framework', 'equihash.py')):
        ap.error('--solver-dir: no test_framework/equihash.py in %r' % args.solver_dir)
    if args.premine < COINBASE_MATURITY + 1 and args.tx_every:
        ap.error('spends need --premine of at least %d (or --tx-every 0)' % (COINBASE_MATURITY + 1))
    solver = load_solver(args.solver_dir)
    try:
        run(args, solver)
    except Failure as e:
        print('kogany_mines: FAIL: %s' % e, file=sys.stderr)
        return 1
    except RpcError as e:
        print('kogany_mines: %s' % e, file=sys.stderr)
        return 2
    return 0


if __name__ == '__main__':
    sys.exit(main())
