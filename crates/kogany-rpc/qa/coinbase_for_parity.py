#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""kogany's getcoinbasetemplatefor, checked against ycashd on one Ycash regtest (beta3 item 3).

    python crates/kogany-rpc/qa/coinbase_for_parity.py --koganyd <koganyd, the --features ycash build> \\
        --ycashd-bin <a directory holding ycashd> [--solver-dir $WS/ycash6/qa/rpc-tests] \\
        [--ydf N] [--sapling-output-params FILE] [--workdir DIR] [--keep] [--port-base N]

The script plays the pool. kogany is the pool's node; ycashd is the other node line, peered with
it, and its wallet owns every payout address. Every block below is made of kogany's STOCK
getblocktemplate reply (header fields and transactions) and the coinbase kogany's
getcoinbasetemplatefor returned, solved here by the test framework's (48,5) solver, and given to
ycashd's submitblock, which must answer null: a kogany-built coinbase of every address kind
(P2PKH, P2SH, Sapling, post-quantum FN-DSA-512 and SLH-DSA-SHA2-128s) is accepted by the C++ line.

THE AMOUNT. For every address kind the script computes, from ycashd alone,

    amount = subsidy(height) - fund + fees     subsidy: ycashd's getblocksubsidy
                                               fees:    ycashd's mempool fee of every named transaction

and requires kogany's answer, the coinbase's outputs as ycashd decodes them, and the mined block
(for a Sapling address: the note ycashd's wallet finds) to show exactly that number. `fund` is the
development-fund output of the node's own coinbase: subsidy / 20 inside the mandate (regtest:
below height 5) whatever the node's share says, subsidy * ydf / 100 after it (`--ydf N` starts
both nodes with that share: ycashd `-ydf=N`, koganyd `mining.ydf = N`; the default is 0, no
output), and it must be the stock coinbase's own output, value and script.

Phases (regtest; every upgrade through Canopy at 1, Vault and FN-DSA-512 at 4):

1. inside the mandate, heights 2 to 4: every payable kind, `fundrule` "mandated"; a post-quantum
   address is refused before Vault (the contract's row 8); one block per height is mined;
2. past the mandate, with a fee-paying transaction in every template: every kind, `fundrule`
   "none" or "optional"; the stock template is the same before and after the calls;
3. the refusals of the contract (rows 1 to 7, 10, 11), a stale reference after a block, and that
   no key and no parameter can carry an amount;
4. several Sapling calls at once while the node answers getblockcount;
5. with a held quote (kogany's YED mock), the coinbase carries the tag and `flags` is the
   template's `coinbaseaux.flags`;
6. the other direction, when the ycashd under test has the call: a block of ycashd's stock
   template and ycashd's coinbase for a Sapling, a post-quantum and a P2PKH address is accepted
   by kogany;
7. kogany restarted WITHOUT the Sapling output parameters: a Sapling call answers the contract's
   row 17, transparent and post-quantum calls still answer;
8. kogany restarted with a Sapling `mining.miner_address` (and the parameters): its own
   getblocktemplate coinbase pays the address, and ycashd accepts the block;
9. a reference heavy in post-quantum POLICY sigops (six spends of a P2SH redeem script with 199
   unexecuted `OP_CHECKPQSIG`, 3,980 policy sigops each, none for block validity): the call
   answers on both lines, because its fit check counts what block validity counts (legacy and
   P2SH), and the block of all six is accepted by ycashd and by kogany.

Exit 0 when every check passes, 1 on a failed check, 2 on an RPC or startup error. Stdlib only.
"""

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from decimal import Decimal

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from kogany_mines import (  # noqa: E402
    COINBASE_MATURITY, VAULT_BRANCH, ZIP317_FEE, Failure, check, compact_size, find_up, load_solver,
    sha256d, solve, wait_for, zip317_spend)
from rpc_ycash_parity import (  # noqa: E402
    ACTIVATION_KEYS, NUPARAMS, Node, RpcError, base58check, decode_coinbase, internal, stop,
    wait_up)

COIN = 100_000_000
YDF_MANDATE_END = 5          # ycash6 src/chainparams.cpp, regtest nYdfMandateEndHeight
VAULT = 4                    # a post-quantum address may be paid in a coinbase from here
TAG_SIZE = 36
QUOTE_MICRO_USD, QUOTE_SOURCES = 50_000, 1

P2PKH, P2SH, SAPLING, PQ_FN, PQ_SLH = 'p2pkh', 'p2sh', 'sapling', 'pq FN-DSA-512', 'pq SLH-DSA-SHA2-128s'
KINDS = (P2PKH, P2SH, SAPLING, PQ_FN, PQ_SLH)
ADDRESSTYPE = {P2PKH: 'p2pkh', P2SH: 'p2sh', SAPLING: 'sapling', PQ_FN: 'pq', PQ_SLH: 'pq'}

BAD_TEMPLATE = 'template must be an object with exactly the keys previousblockhash and txids'
STALE_TIP = 'template-stale: previousblockhash is not the tip'
NOT_LOADED = 'coinbase construction failed: Sapling output parameters are not loaded'

# Phase 9: OP_0 OP_IF <OP_CHECKPQSIG x 199> OP_ENDIF OP_1, a redeem script that needs no signature
# and costs 199 * 20 = 3,980 policy sigops (at most MAX_STANDARD_TX_SIGOPS, 4,000), none for
# block validity; six spends of it exceed MAX_BLOCK_SIGOPS (20,000) by the policy count only.
PQ_OPS_PER_SPEND, PQ_HEAVY_SPENDS = 199, 6
PQ_HEAVY_REDEEM = b'\x00\x63' + b'\xc2' * PQ_OPS_PER_SPEND + b'\x68\x51'
SAPLING_GROUP = 0x892F2085


def zat(x):
    return int(Decimal(str(x)) * COIN)


def reference(t):
    """What the pool sends back to name the template it holds: nothing but these two things."""
    return {'previousblockhash': t['previousblockhash'], 'txids': [tx['hash'] for tx in t['transactions']]}


def merkle_root(txs_hex):
    """The merkle root (internal byte order) of v4 transactions given as hex."""
    layer = [sha256d(bytes.fromhex(h)) for h in txs_hex]
    while len(layer) > 1:
        if len(layer) % 2:
            layer.append(layer[-1])
        layer = [sha256d(layer[i] + layer[i + 1]) for i in range(0, len(layer), 2)]
    return layer[0]


def paired_block(t, coinbase_hex, solver, nonce_seed):
    """The block a pool builds: the stock template's header fields and transactions and
    `coinbase_hex`, solved. Returns (block hex, block hash)."""
    txs = [coinbase_hex] + [tx['data'] for tx in t['transactions']]
    paired = dict(t, defaultroots=dict(t['defaultroots'], merkleroot=merkle_root(txs)[::-1].hex()))
    header, _ = solve(paired, solver, start_nonce=nonce_seed << 20)
    return (header + compact_size(len(txs))).hex() + ''.join(txs), sha256d(header)[::-1].hex()


def p2sh_spend(txid, n, redeem, value, script):
    """A v4 transaction spending the P2SH output (txid, n) with the scriptSig <redeem> (no
    signature) to one output of `value` zatoshis locked by `script`, no expiry."""
    script_sig = (bytes([len(redeem)]) if len(redeem) < 0x4c else b'\x4c' + bytes([len(redeem)])) + redeem
    b = (0x80000004).to_bytes(4, 'little') + SAPLING_GROUP.to_bytes(4, 'little')
    b += compact_size(1) + bytes.fromhex(txid)[::-1] + n.to_bytes(4, 'little')
    b += compact_size(len(script_sig)) + script_sig + (0xffffffff).to_bytes(4, 'little')
    b += compact_size(1) + value.to_bytes(8, 'little') + compact_size(len(script)) + script
    b += bytes(4) + bytes(4) + bytes(8) + b'\x00\x00\x00'
    return b.hex()


def expect_error(code, message, nodes, method, *params):
    """Every node of `nodes` (one node, or a list) refuses with exactly this code and message."""
    for node in nodes if isinstance(nodes, list) else [nodes]:
        result, error = node.call(method, *params)
        check(error is not None, '%s: %s: expected error %d %r, got %r' % (node.name, method, code, message, result))
        check((error['code'], error['message']) == (code, message),
              '%s: %s: expected error %d %r, got %r' % (node.name, method, code, message, error))


def start_ycashd(bindir, workdir, port, rpcport, ydf, mineraddress=None):
    datadir = os.path.join(workdir, 'ycashd')
    os.makedirs(datadir, exist_ok=True)
    with open(os.path.join(datadir, 'ycash.conf'), 'w') as f:
        f.write('regtest=1\nshowmetrics=0\nrpcuser=u\nrpcpassword=p\nport=%d\nrpcport=%d\n'
                'listen=1\nlistenonion=0\ndiscover=0\nrpcallowip=127.0.0.1\n' % (port, rpcport))
    args = [os.path.join(bindir, 'ycashd'), '-datadir=' + datadir, '-experimentalfeatures',
            '-i-am-aware-zcashd-will-be-replaced-by-zebrad-and-zallet-in-2025']
    args += ['-nuparams=%s:1' % b for b in NUPARAMS]
    args += ['-nuparams=%s:%d' % (VAULT_BRANCH, VAULT), '-pqfalconheight=%d' % VAULT]
    if ydf is not None:
        args.append('-ydf=%d' % ydf)
    if mineraddress:
        args.append('-mineraddress=' + mineraddress)
    log = open(os.path.join(workdir, 'ycashd.out'), 'a')
    return subprocess.Popen(args, stdout=log, stderr=subprocess.STDOUT)


def koganyd_toml(workdir, p2p, rpc, v2, peer_p2p, miner_address, ydf, params):
    root = os.path.join(workdir, 'zakurad')
    heights = '\n'.join(['%s = 1' % k for k in ACTIVATION_KEYS]
                        + ['Vault = %d' % VAULT, 'pq_falcon_height = %d' % VAULT])
    mining = 'internal_miner = false\nminer_address = "%s"\n' % miner_address
    if ydf is not None:
        mining += 'ydf = %d\n' % ydf
    if params is not None:
        mining += 'sapling_output_params = "%s"\n' % params
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
{mining}
[tracing]
use_color = false
filter = "info"
'''.format(p2p=p2p, rpc=rpc, v2=v2, peer=peer_p2p, root=root, heights=heights, mining=mining)


def start_koganyd(binary, workdir, toml):
    path = os.path.join(workdir, 'zakurad.toml')
    with open(path, 'w') as f:
        f.write(toml)
    env = dict(os.environ, KOGANY_YED_RPC_MOCK='1')     # the tag phase needs a held quote
    log = open(os.path.join(workdir, 'zakurad.out'), 'a')
    return subprocess.Popen([binary, '-c', path, 'start'], stdout=log, stderr=subprocess.STDOUT, env=env)


class Pool:
    """The pool's view of the two nodes."""

    def __init__(self, y, z, solver, ydf):
        self.y, self.z, self.solver = y, z, solver
        self.ydf = ydf if ydf is not None and 0 <= ydf <= 100 else 0
        self.used = set()
        self.timings = {}
        self.blocks = []            # (height, kind, hash, amount)
        self.compared = 0           # answers found equal to ycashd's own

    # ---- what the script knows without asking the call (all of it from ycashd) ----

    def subsidy(self, height):
        """ycashd's block subsidy at height in zat: miner plus founders, which no -ydf changes."""
        r = self.y.ok('getblocksubsidy', height)
        return zat(r['miner']) + zat(r['founders'])

    def fund(self, height):
        subsidy = self.subsidy(height)
        return subsidy // 20 if height < YDF_MANDATE_END else subsidy * self.ydf // 100

    def fundrule(self, height):
        if height < YDF_MANDATE_END:
            return 'mandated'
        return 'optional' if self.fund(height) else 'none'

    def fees(self, txids):
        """The sum of ycashd's mempool fees of txids, in zat."""
        pool = self.y.ok('getrawmempool', True)
        return sum(zat(pool[txid]['fee']) for txid in txids)

    def script_of(self, address):
        return self.y.ok('validateaddress', address)['scriptPubKey']

    def sync(self, want=None, timeout=60):
        want = want or self.y.ok('getbestblockhash')
        wait_for('both tips at %s' % want[:16],
                 lambda: self.y.ok('getbestblockhash') == want and self.z.ok('getbestblockhash') == want,
                 timeout=timeout)

    def generate(self, n):
        """ycashd mines n blocks; kogany takes them (by relay, or handed over)."""
        for h in self.y.ok('generate', n):
            res = self.z.ok('submitblock', self.y.ok('getblock', h, 0))
            check(res in (None, 'duplicate', 'inconclusive'), 'kogany refused ycashd\'s block %s: %r' % (h, res))
        self.sync()

    def pay_fee(self, recipient):
        """A fee-paying spend of ycashd's wallet, in both mempools. Returns its txid."""
        raw = zip317_spend(self.y, recipient, self.used)
        txid = self.z.ok('sendrawtransaction', raw)
        self.y.call('sendrawtransaction', raw, True)
        wait_for('the spend in both mempools',
                 lambda: txid in self.z.ok('getrawmempool') and txid in self.y.ok('getrawmempool'), timeout=30)
        return txid

    def template(self, txids=()):
        """kogany's stock template, once it carries exactly txids."""
        t = {}

        def ready():
            t.clear()
            t.update(self.z.ok('getblocktemplate'))
            return sorted(tx['hash'] for tx in t['transactions']) == sorted(txids)
        wait_for('kogany\'s template with %d transactions' % len(txids), ready, timeout=30)
        check(t['previousblockhash'] == self.y.ok('getbestblockhash'), 'the template does not build on ycashd\'s tip')
        return t

    def call(self, node, address, t):
        return node.ok('getcoinbasetemplatefor', address, reference(t))

    # ---- the amount ----

    def assert_paid_exactly(self, kind, address, t, res, node=None, stock_fund_index=1):
        """The answer `res` (for `address`, on the stock template `t` of `node`) pays the address
        exactly subsidy - fund + fees, and carries the fund output of the node's own coinbase."""
        node = node or self.z
        height = t['height']
        txids = [tx['hash'] for tx in t['transactions']]
        subsidy, fund, fees = self.subsidy(height), self.fund(height), self.fees(txids)
        amount = subsidy - fund + fees                      # <-- what the miner must receive

        check(fees == sum(tx['fee'] for tx in t['transactions']), 'the template prints other fees than ycashd\'s mempool')
        want = {'subsidy': subsidy, 'fund': fund, 'fundrule': self.fundrule(height), 'fees': fees,
                'amount': amount, 'txcount': len(txids), 'height': height,
                'previousblockhash': t['previousblockhash'], 'addresstype': ADDRESSTYPE[kind]}
        got = {k: res[k] for k in want}
        check(got == want, '%s at %d: the answer is %r, want %r' % (kind, height, got, want))
        check(sorted(res) == sorted(['data', 'hash', 'height', 'previousblockhash', 'addresstype', 'subsidy',
                                     'fund', 'fundrule', 'fees', 'amount', 'txcount', 'flags', 'sigops']),
              'the answer\'s keys are %r' % sorted(res))

        # the fund output is the stock coinbase's own: same value, same script
        stock = self.y.ok('decoderawtransaction', t['coinbasetxn']['data'])
        stock_outs = [(v['valueZat'], v['scriptPubKey']['hex']) for v in stock['vout']]
        stock_fund = stock_outs[stock_fund_index:stock_fund_index + 1] if fund else []
        check([v for v, _ in stock_fund] == ([fund] if fund else []),
              '%s at %d: the stock coinbase\'s fund output is %r, want %d' % (kind, height, stock_fund, fund))
        check(sum(v for v, _ in stock_outs) - stock.get('valueBalanceZat', 0) == subsidy + fees,
              'the stock coinbase does not pay subsidy plus fees')

        # the coinbase, as ycashd decodes it
        cb = self.y.ok('decoderawtransaction', res['data'])
        check(cb['txid'] == res['hash'], 'hash is not the transaction id')
        check((cb['version'], cb['locktime'], cb['expiryheight']) == (4, 0, 0),
              'version, lock time, expiry: %r' % ((cb['version'], cb['locktime'], cb['expiryheight']),))
        outs = [(v['valueZat'], v['scriptPubKey']['hex']) for v in cb['vout']]
        if kind == SAPLING:
            check(len(cb['vShieldedOutput']) == 1 and cb['valueBalanceZat'] == -amount,
                  'Sapling: %d outputs, valueBalance %r, want one and %d' % (len(cb['vShieldedOutput']), cb['valueBalanceZat'], -amount))
            check(outs == stock_fund, 'Sapling: the transparent outputs are %r, want only the fund output %r' % (outs, stock_fund))
        else:
            check(not cb.get('vShieldedOutput'), 'a transparent payout has a Sapling output')
            check(outs == [(amount, self.script_of(address))] + stock_fund,
                  '%s: the outputs are %r, want %r' % (kind, outs, [(amount, self.script_of(address))] + stock_fund))
        check(sum(v for v, _ in outs) - cb.get('valueBalanceZat', 0) == subsidy + fees,
              'the coinbase does not pay subsidy plus fees, to the zatoshi')

        # the input script is <height> OP_0 <flags>, the node's own coinbase's
        check(res['flags'] == t.get('coinbaseaux', {}).get('flags', ''), 'flags is not the template\'s')
        check(cb['vin'][0]['coinbase'] == stock['vin'][0]['coinbase'],
              'the input script %s is not the stock coinbase\'s %s' % (cb['vin'][0]['coinbase'], stock['vin'][0]['coinbase']))
        check(cb['vin'][0]['coinbase'].endswith('00' + res['flags']), 'the input script does not end with OP_0 <flags>')
        return amount

    def same_as_ycashd(self, kind, address, t, res, y_has_call):
        """ycashd's own call, asked for the same address and the same reference, gives the same
        answer: every field, and for a transparent or post-quantum address the same coinbase,
        byte for byte (a Sapling one differs in its output's randomness, so in data and hash)."""
        if not y_has_call:
            return
        theirs = self.call(self.y, address, t)
        skip = ('data', 'hash') if kind == SAPLING else ()
        mine = {k: v for k, v in res.items() if k not in skip}
        check(mine == {k: v for k, v in theirs.items() if k not in skip},
              '%s at %d: kogany answers %r, ycashd %r' % (kind, t['height'], mine, theirs))
        check(len(theirs['data']) == len(res['data']), 'the two coinbases differ in size')
        self.compared += 1

    def proposal_ok(self, t, res):
        """Both nodes find the paired block valid (proposal mode: everything but proof of work)."""
        txs = [res['data']] + [tx['data'] for tx in t['transactions']]
        header = (int(t['version']).to_bytes(4, 'little') + internal(t['previousblockhash']) + merkle_root(txs)
                  + internal(t['blockcommitmentshash']) + int(t['curtime']).to_bytes(4, 'little')
                  + int(t['bits'], 16).to_bytes(4, 'little') + bytes(32) + bytes([36]) + bytes(36))
        block = (header + compact_size(len(txs))).hex() + ''.join(txs)
        for node in (self.y, self.z):
            verdict, error = node.call('getblocktemplate', {'mode': 'proposal', 'data': block})
            check(error is None and verdict is None, '%s refuses the paired block: %r' % (node.name, error or verdict))

    def submit(self, kind, address, t, res, amount, first, second):
        """Mine the paired block; `first` must accept it (null), then `second`; the address was
        paid `amount` in it, as ycashd reads the block (and, for Sapling, its wallet)."""
        block, bhash = paired_block(t, res['data'], self.solver, t['height'])
        verdict = first.ok('submitblock', block)
        check(verdict is None, 'height %d, %s: %s refused the block: %r' % (t['height'], kind, first.name, verdict))
        verdict = second.ok('submitblock', block)
        check(verdict in (None, 'duplicate', 'inconclusive'),
              'height %d, %s: %s refused the block: %r' % (t['height'], kind, second.name, verdict))
        self.sync(bhash)
        mined = self.y.ok('getblock', bhash, 2)
        check(mined['height'] == t['height'], 'the block is at %d' % mined['height'])
        check([tx['txid'] for tx in mined['tx']] == [res['hash']] + [tx['hash'] for tx in t['transactions']],
              'the block does not carry the coinbase and the named transactions, in order')
        if kind == SAPLING:
            def notes():
                return [n for n in self.y.ok('z_listunspent', 1, 9999999, False, [address]) if n['txid'] == res['hash']]
            wait_for('ycashd\'s wallet to see the Sapling coinbase note', lambda: len(notes()) == 1, timeout=30)
            check(zat(notes()[0]['amount']) == amount, 'the note is %r, want %d zat' % (notes()[0]['amount'], amount))
        else:
            out = mined['tx'][0]['vout'][0]
            check((out['valueZat'], out['scriptPubKey']['hex']) == (amount, self.script_of(address)),
                  'vout[0] of the mined coinbase is %r' % out)
        self.blocks.append((t['height'], kind, bhash, amount))
        print('  height %3d %-22s accepted by %s then %s: paid %d = subsidy %d - fund %d (%s) + fees %d (%d txs)'
              % (t['height'], kind, first.name, second.name, amount, res['subsidy'], res['fund'], res['fundrule'],
                 res['fees'], res['txcount']))
        return bhash


def run(args, solver):
    workdir = args.workdir or tempfile.mkdtemp(prefix='coinbase-for-parity-')
    os.makedirs(workdir, exist_ok=True)
    base = args.port_base
    y = Node('ycashd', base + 1, 'u:p')
    z = Node('kogany', base + 11)
    pool = Pool(y, z, solver, args.ydf)
    procs = {}

    def start_kogany(miner_address, params):
        procs['z'] = start_koganyd(args.zakurad, workdir,
                                   koganyd_toml(workdir, base + 10, base + 11, base + 12, base, miner_address,
                                                args.ydf, params))
        wait_up(z, procs['z'], 'koganyd')

    def restart_kogany(miner_address, params):
        stop(procs['z'])
        start_kogany(miner_address, params)
        want = y.ok('getbestblockhash')
        wait_for('kogany back at the tip', lambda: z.ok('getbestblockhash') == want, timeout=120)
        wait_for('the kogany-ycashd P2P connection', lambda: len(y.ok('getpeerinfo')) > 0, timeout=90)

    try:
        procs['y'] = start_ycashd(args.ycashd_bin, workdir, base, base + 1, args.ydf)
        wait_up(y, procs['y'], 'ycashd')
        miner = y.ok('getnewaddress')
        addr = {
            P2PKH: y.ok('getnewaddress'),
            P2SH: base58check(bytes([0x1C, 0x2A]) + hashlib.sha256(b'getcoinbasetemplatefor').digest()[:20]),
            SAPLING: y.ok('z_getnewaddress', 'sapling'),
        }
        y.ok('generate', 1)                          # height 1: ycashd leaves initial block download
        start_kogany(miner, args.sapling_output_params)
        res = z.ok('submitblock', y.ok('getblock', y.ok('getblockhash', 1), 0))
        check(res in (None, 'duplicate', 'inconclusive'), 'kogany refused block 1: %r' % res)
        pool.sync()
        wait_for('the kogany-ycashd P2P connection',
                 lambda: len(y.ok('getpeerinfo')) > 0 and len(z.ok('getpeerinfo')) > 0, timeout=90)
        y_has_call = y.call('getcoinbasetemplatefor', addr[P2PKH], {})[1]['code'] != -32601
        print('coinbase_for_parity: workdir %s; ydf %d; ycashd %s getcoinbasetemplatefor'
              % (workdir, pool.ydf, 'has' if y_has_call else 'has NO'))
        both = [z, y] if y_has_call else [z]       # the nodes every refusal is asked of

        # ===== 1. inside the mandate (heights 2 to 4): the fund output is there =====
        print('1. inside the mandate')
        # post-quantum addresses from a key hash: a wallet makes them only once Vault is active
        pq_early = {PQ_FN: 'rqf2UsjFAdzsYwqphjSkcTigtzZv2jVWQc3F6XLvBUuVrY97KQTYq',
                    PQ_SLH: 'rqs2PNtFr55Bg27WkDzGpBBVYEQkVpDc65k4T4gYSQn6FNop3aVFk'}
        submit_kind = {2: P2SH, 3: SAPLING, 4: PQ_FN}
        for height in (2, 3, 4):
            t = pool.template()
            check(t['height'] == height, 'template height %d, want %d' % (t['height'], height))
            if height == VAULT:
                addr[PQ_FN] = y.ok('getnewaddress', '', 'pq')
                addr[PQ_SLH] = y.ok('getnewaddress', '', 'pqslh')
                check(addr[PQ_FN].startswith('rqf') and addr[PQ_SLH].startswith('rqs'), 'post-quantum prefixes')
            chosen = None
            for kind in KINDS:
                if ADDRESSTYPE[kind] == 'pq' and height < VAULT:
                    expect_error(-5, 'Address type cannot receive a coinbase at height %d: pq' % height,
                                 both, 'getcoinbasetemplatefor', pq_early[kind], reference(t))
                    continue
                res = pool.call(z, addr[kind], t)
                amount = pool.assert_paid_exactly(kind, addr[kind], t, res)
                pool.same_as_ycashd(kind, addr[kind], t, res, y_has_call)
                check((res['fund'], res['fundrule']) == (pool.subsidy(height) // 20, 'mandated'),
                      'inside the mandate the fund output is subsidy / 20')
                pool.proposal_ok(t, res)
                if kind == submit_kind[height]:
                    chosen = (kind, res, amount)
            kind, res, amount = chosen
            pool.submit(kind, addr[kind], t, res, amount, y, z)

        # ===== 2. past the mandate, with fee-paying transactions =====
        print('2. past the mandate, with fees')
        pool.generate(COINBASE_MATURITY + 20)
        recipient = y.ok('getnewaddress')
        for kind in KINDS:
            txid = pool.pay_fee(recipient)
            t = pool.template([txid])
            height = t['height']
            check(height >= YDF_MANDATE_END and all(tx['fee'] > 0 for tx in t['transactions']), 'a fee-paying template')
            started = time.time()
            res = pool.call(z, addr[kind], t)
            pool.timings.setdefault(kind, []).append(time.time() - started)
            amount = pool.assert_paid_exactly(kind, addr[kind], t, res)
            pool.same_as_ycashd(kind, addr[kind], t, res, y_has_call)
            fees = sum(tx['fee'] for tx in t['transactions'])
            subsidy = pool.subsidy(height)
            if pool.ydf == 0:
                check((res['fund'], res['fundrule'], amount) == (0, 'none', subsidy + fees),
                      'at the default share the miner is paid the whole subsidy and every fee')
            else:
                check((res['fund'], res['fundrule']) == (subsidy * pool.ydf // 100, 'optional')
                      and amount == subsidy - subsidy * pool.ydf // 100 + fees,
                      'with mining.ydf = %d the miner is paid the rest of the subsidy and every fee' % pool.ydf)
            # a second call gives a valid coinbase too: a Sapling one differs in its randomness only
            started = time.time()
            again = pool.call(z, addr[kind], t)
            pool.timings[kind].append(time.time() - started)
            check(pool.assert_paid_exactly(kind, addr[kind], t, again) == amount, 'the second call pays another amount')
            check((again['data'] == res['data']) == (kind != SAPLING), '%s: the second coinbase' % kind)
            pool.proposal_ok(t, again)
            # the stock template is what it was (the call rebuilt nothing): everything but the clock
            after = z.ok('getblocktemplate')
            check({k: v for k, v in after.items() if k != 'curtime'} == {k: v for k, v in t.items() if k != 'curtime'},
                  'getblocktemplate changed across the calls')
            pool.submit(kind, addr[kind], t, res, amount, y, z)
            check(z.ok('getrawmempool') == [], 'kogany\'s mempool still holds the mined spend')
        # an empty template past the mandate: the subsidy alone, less the node's share
        t = pool.template()
        res = pool.call(z, addr[SAPLING], t)
        amount = pool.assert_paid_exactly(SAPLING, addr[SAPLING], t, res)
        check(amount == pool.subsidy(t['height']) * (100 - pool.ydf) // 100, 'an empty template pays the subsidy')
        pool.submit(SAPLING, addr[SAPLING], t, res, amount, y, z)

        # ===== 3. the refusals of the contract =====
        print('3. refusals')
        txid = pool.pay_fee(recipient)
        t = pool.template([txid])
        ref = reference(t)
        a = addr[P2PKH]
        f = 'getcoinbasetemplatefor'
        # no way to ask for an amount: any key but the two is refused, and there is no third parameter
        for extra in ({'amount': 1}, {'fees': 0}, {'coinbasevalue': 1}):
            expect_error(-8, BAD_TEMPLATE, both, f, a, dict(ref, **extra))
        for node in both:
            # JSON null too: ycashd counts the parameters sent. Each line's usual usage error, which
            # the contract leaves to the line: kogany and ycash-dd -1, ycash6 -32602 "Too many
            # parameters" (docs/kogany.md, "Wrong argument counts"); always with the usage line.
            codes = (-1,) if node is z else (-1, -32602)
            for third in (1, None):
                result, error = node.call(f, a, ref, third)
                check(error is not None and error['code'] in codes and 'getcoinbasetemplatefor "address"' in error['message'],
                      '%s: a third parameter %r: %r' % (node.name, third, error or result))
        for bad in ({'previousblockhash': ref['previousblockhash']}, {'txids': []}, {}, [], 'x', 1,
                    {'previousblockhash': ref['previousblockhash'], 'amount': 1}):
            expect_error(-8, BAD_TEMPLATE, both, f, a, bad)
        for bad in ('00', ref['previousblockhash'][:-1], ref['previousblockhash'][:-1] + 'g', 1):
            expect_error(-8, 'previousblockhash must be 64 hex characters', both, f, a, dict(ref, previousblockhash=bad))
        for bad in ('x', {}, ['00'], [txid, 1], [txid[:-1] + 'z']):
            expect_error(-8, 'txids must be an array of strings of 64 hex characters', both, f, a, dict(ref, txids=bad))
        expect_error(-8, 'txids has more than 50000 entries', both, f, a, dict(ref, txids=['%064x' % k for k in range(50001)]))
        expect_error(-8, 'txids names a transaction twice: ' + txid, both, f, a, dict(ref, txids=ref['txids'] + [txid]))
        up = z.ok(f, a, {'previousblockhash': ref['previousblockhash'].upper(), 'txids': [x.upper() for x in ref['txids']]})
        check((up['previousblockhash'], up['fees']) == (ref['previousblockhash'], sum(tx['fee'] for tx in t['transactions'])),
              'upper-case hex is the same reference')
        yed = y.ok('yed_getnewaddress') if y.call('yed_getnewaddress')[1] is None else None
        for bad in ['', 'x', a[:-1], 1] + ([yed] if yed else []):
            expect_error(-5, 'Invalid address', both, f, bad, ref)
        sprout = base58check(bytes([0x16, 0x52]) + bytes(64))            # regtest ZCPAYMENT_ADDRESS
        expect_error(-5, 'Address type cannot receive a coinbase: sprout', both, f, sprout, ref)
        # the order of the checks: the shape of the reference, the address, then the tip
        expect_error(-8, BAD_TEMPLATE, both, f, 'x', {})
        stale = dict(ref, previousblockhash='%064x' % 1)
        expect_error(-5, 'Invalid address', both, f, 'x', stale)
        expect_error(-1, STALE_TIP, both, f, a, stale)
        unknown = '%064x' % 2
        missing = 'template-stale: transaction is not in the mempool: '
        expect_error(-1, missing + unknown, both, f, a, dict(ref, txids=[txid, unknown]))
        expect_error(-1, missing + unknown, both, f, a, dict(ref, txids=[unknown, unknown]))
        # the reference goes stale when the tip moves, and the mined transaction has left the mempool
        res = pool.call(z, a, t)
        pool.proposal_ok(t, res)
        pool.generate(1)
        wait_for('kogany\'s mempool to drop the mined spend', lambda: z.ok('getrawmempool') == [], timeout=30)
        expect_error(-1, STALE_TIP, both, f, a, ref)
        expect_error(-1, STALE_TIP, both, f, addr[SAPLING], ref)
        expect_error(-1, missing + txid, both, f, a, {'previousblockhash': y.ok('getbestblockhash'), 'txids': [txid]})
        print('  refusals: as the contract')

        # ===== 4. Sapling calls at once =====
        print('4. parallel Sapling calls')
        txid = pool.pay_fee(recipient)
        t = pool.template([txid])
        zaddrs = [y.ok('z_getnewaddress', 'sapling') for _ in range(args.parallel)]
        results, errors = {}, []

        def worker(zaddr):
            try:
                results[zaddr] = Node('kogany', base + 11).ok('getcoinbasetemplatefor', zaddr, reference(t))
            except Exception as e:              # reported below, on the main thread
                errors.append(repr(e))
        threads = [threading.Thread(target=worker, args=(zaddr,)) for zaddr in zaddrs]
        started = time.time()
        for th in threads:
            th.start()
        slowest = 0.0
        while any(th.is_alive() for th in threads):
            t1 = time.time()
            z.ok('getblockcount')
            slowest = max(slowest, time.time() - t1)
            time.sleep(0.02)
        elapsed = time.time() - started
        check(errors == [], 'parallel calls failed: %r' % errors)
        check(len(set(r['data'] for r in results.values())) == len(zaddrs), 'two parallel calls returned one coinbase')
        for zaddr in zaddrs:
            pool.assert_paid_exactly(SAPLING, zaddr, t, results[zaddr])
            pool.proposal_ok(t, results[zaddr])
        pool.submit(SAPLING, zaddrs[0], t, results[zaddrs[0]], results[zaddrs[0]]['amount'], y, z)
        print('  %d Sapling calls at once: %.0f ms in all; the slowest getblockcount meanwhile %.0f ms'
              % (len(zaddrs), elapsed * 1000, slowest * 1000))

        # ===== 5. the tag =====
        print('5. the Yellowback tag')
        z.ok('yed_setquote', QUOTE_MICRO_USD, QUOTE_SOURCES)
        t = pool.template()
        flags = bytes.fromhex(t['coinbaseaux']['flags'])
        check(len(flags) == TAG_SIZE + 1 and flags[1:5] == b'YED!', 'the template carries no tag: %s' % flags.hex())
        for kind in (P2PKH, SAPLING):
            res = pool.call(z, addr[kind], t)
            amount = pool.assert_paid_exactly(kind, addr[kind], t, res)     # flags and the input script too
            check(res['flags'] == flags.hex(), 'flags is not the tag')
            pool.proposal_ok(t, res)
        pool.submit(SAPLING, addr[SAPLING], t, res, amount, y, z)

        # ===== 6. the other direction: ycashd's coinbase, accepted by kogany =====
        if y_has_call:
            print('6. ycashd-built coinbases, accepted by kogany')
            for kind in (SAPLING, PQ_FN, P2PKH):
                txid = pool.pay_fee(recipient)
                pool.template([txid])                   # kogany's mempool has it
                ty = {}

                def ready():
                    ty.clear()
                    ty.update(y.ok('getblocktemplate'))
                    return [tx['hash'] for tx in ty['transactions']] == [txid]
                wait_for('ycashd\'s template with the spend', ready, timeout=30)
                ty = dict(ty, blockcommitmentshash=ty.get('blockcommitmentshash') or ty['finalsaplingroothash'],
                          defaultroots=ty.get('defaultroots') or {'merkleroot': ''})
                res = pool.call(y, addr[kind], ty)
                amount = pool.assert_paid_exactly(kind, addr[kind], ty, res, node=y)
                pool.submit(kind, addr[kind], ty, res, amount, z, y)
        else:
            print('6. SKIPPED: the ycashd under test has no getcoinbasetemplatefor')

        # ===== 7. kogany without the Sapling output parameters =====
        print('7. kogany without the Sapling output parameters')
        restart_kogany(addr[SAPLING], os.path.join(workdir, 'absent', 'sapling-output.params'))
        txid = pool.pay_fee(recipient)
        wait_for('the spend in kogany\'s mempool', lambda: txid in z.ok('getrawmempool'), timeout=30)
        ref = {'previousblockhash': y.ok('getbestblockhash'), 'txids': [txid]}
        expect_error(-32603, NOT_LOADED, z, f, addr[SAPLING], ref)
        expect_error(-1, missing + unknown, z, f, addr[SAPLING], dict(ref, txids=[unknown]))
        for kind in (P2PKH, P2SH, PQ_FN, PQ_SLH):
            res = z.ok(f, addr[kind], ref)
            check((res['addresstype'], res['txcount'], res['amount']) ==
                  (ADDRESSTYPE[kind], 1, pool.subsidy(res['height']) - pool.fund(res['height']) + pool.fees([txid])),
                  '%s without the parameters: %r' % (kind, res))
        result, error = z.call('getblocktemplate')
        check(error is not None and 'Sapling output parameters are not loaded' in error['message'],
              'getblocktemplate with a Sapling miner address and no parameters: %r' % (error or 'answered'))
        print('  a Sapling call: %d %r; the other kinds answer' % (-32603, NOT_LOADED))

        # ===== 8. kogany's own coinbase for a Sapling miner address =====
        print('8. kogany\'s own getblocktemplate with a Sapling miner address')
        restart_kogany(addr[SAPLING], args.sapling_output_params)
        wait_for('the spend in kogany\'s mempool', lambda: txid in z.ok('getrawmempool'), timeout=60)
        t = pool.template([txid])
        cb = y.ok('decoderawtransaction', t['coinbasetxn']['data'])
        height = t['height']
        amount = pool.subsidy(height) - pool.fund(height) + pool.fees([txid])
        check(len(cb['vShieldedOutput']) == 1 and cb['valueBalanceZat'] == -amount,
              'the stock Sapling coinbase: valueBalance %r, want %d' % (cb['valueBalanceZat'], -amount))
        check([v['valueZat'] for v in cb['vout']] == ([pool.fund(height)] if pool.fund(height) else []),
              'the stock Sapling coinbase\'s transparent outputs: %r' % cb['vout'])
        stock = {'data': t['coinbasetxn']['data'], 'hash': t['coinbasetxn']['hash'], 'subsidy': pool.subsidy(height),
                 'fund': pool.fund(height), 'fundrule': pool.fundrule(height), 'fees': pool.fees([txid]), 'txcount': 1}
        # and the call on this node builds the same payout
        res = pool.call(z, addr[SAPLING], t)
        pool.assert_paid_exactly(SAPLING, addr[SAPLING], t, res, stock_fund_index=0)
        pool.submit(SAPLING, addr[SAPLING], t, stock, amount, y, z)

        # ===== 9. post-quantum policy sigops are not block sigops =====
        print('9. a reference heavy in post-quantum policy sigops')
        p2sh_addr = y.ok('decodescript', PQ_HEAVY_REDEEM.hex())['p2sh']
        p2sh_script = pool.script_of(p2sh_addr)
        funding = [y.ok('sendtoaddress', p2sh_addr, 1) for _ in range(PQ_HEAVY_SPENDS)]
        pool.generate(1)
        heavy = {}
        for ftxid in funding:
            n = next(o['n'] for o in y.ok('getrawtransaction', ftxid, 1)['vout']
                     if o['scriptPubKey']['hex'] == p2sh_script)
            raw = p2sh_spend(ftxid, n, PQ_HEAVY_REDEEM, COIN - ZIP317_FEE, bytes.fromhex(pool.script_of(recipient)))
            heavy[z.ok('sendrawtransaction', raw)] = raw
            y.call('sendrawtransaction', raw, True)
        wait_for('the six spends in both mempools',
                 lambda: set(heavy) <= set(z.ok('getrawmempool')) and set(heavy) <= set(y.ok('getrawmempool')),
                 timeout=30)
        t = z.ok('getblocktemplate')
        check(t['previousblockhash'] == y.ok('getbestblockhash'), 'the template does not build on ycashd\'s tip')
        selected = len([tx for tx in t['transactions'] if tx['hash'] in heavy])
        t6 = dict(t, transactions=[{'hash': txid, 'data': raw, 'fee': ZIP317_FEE} for txid, raw in heavy.items()])
        height = t['height']
        fees = pool.fees(list(heavy))
        check(fees == PQ_HEAVY_SPENDS * ZIP317_FEE, 'ycashd\'s mempool fees of the six: %d' % fees)
        for kind in (P2PKH, SAPLING):
            res = pool.call(z, addr[kind], t6)      # kogany answers (it refused here before)
            amount = pool.subsidy(height) - pool.fund(height) + fees
            check((res['height'], res['fees'], res['amount'], res['txcount'], res['addresstype']) ==
                  (height, fees, amount, PQ_HEAVY_SPENDS, ADDRESSTYPE[kind]),
                  '%s with %d post-quantum-heavy spends: %r' % (kind, PQ_HEAVY_SPENDS, res))
            pool.same_as_ycashd(kind, addr[kind], t6, res, y_has_call)
        res = pool.call(z, addr[P2PKH], t6)
        pool.proposal_ok(t6, res)
        pool.submit(P2PKH, addr[P2PKH], t6, res, res['amount'], y, z)
        print('  %d spends, %d policy sigops (kogany\'s own template selected %d of them): answered on %s, '
              'the block accepted by both'
              % (PQ_HEAVY_SPENDS, PQ_HEAVY_SPENDS * PQ_OPS_PER_SPEND * 20, selected,
                 'both lines' if y_has_call else 'kogany'))

        for kind in KINDS:
            ts = sorted(pool.timings[kind])
            print('time of one kogany call, %-22s %.1f ms and %.1f ms' % (kind + ':', ts[0] * 1000, ts[-1] * 1000))
        by_kind = {}
        for _, kind, _, _ in pool.blocks:
            by_kind[kind] = by_kind.get(kind, 0) + 1
        print('coinbase_for_parity: ok: %d paired blocks accepted on both lines (%s), %d answers equal to '
              'ycashd\'s own, ydf %d, tips equal at %d'
              % (len(pool.blocks), ', '.join('%s %d' % kv for kv in sorted(by_kind.items())), pool.compared,
                 pool.ydf, y.ok('getblockcount')))
    finally:
        for p in procs.values():
            stop(p)
        if not args.keep and not args.workdir:
            shutil.rmtree(workdir, ignore_errors=True)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    ap.add_argument('--koganyd', '--zakurad', dest='zakurad', default=os.getenv('KOGANY_BIN'),
                    help='koganyd (the --features ycash build)')
    ap.add_argument('--ycashd-bin', '--ycash6-bin', dest='ycashd_bin', help='directory holding ycashd')
    ap.add_argument('--solver-dir', default=find_up('ycash6', 'qa', 'rpc-tests'),
                    help='the ycash6 qa/rpc-tests directory (test_framework/equihash.py)')
    ap.add_argument('--ydf', type=int, help='the development-fund share both nodes run with (default: theirs, 0)')
    ap.add_argument('--sapling-output-params',
                    help='koganyd\'s mining.sapling_output_params (default: ycashd\'s parameter directory)')
    ap.add_argument('--parallel', type=int, default=6, help='Sapling calls at once in phase 4')
    ap.add_argument('--workdir', help='keep the datadirs here (default: a temporary directory)')
    ap.add_argument('--keep', action='store_true', help='keep the temporary directory')
    ap.add_argument('--port-base', type=int, default=29800)
    args = ap.parse_args(argv)
    if not args.zakurad:
        ap.error('--koganyd (or KOGANY_BIN) is required')
    if not args.ycashd_bin or not os.path.exists(os.path.join(args.ycashd_bin, 'ycashd')):
        ap.error('--ycashd-bin: no ycashd in %r' % args.ycashd_bin)
    if not args.solver_dir or not os.path.exists(os.path.join(args.solver_dir, 'test_framework', 'equihash.py')):
        ap.error('--solver-dir: no test_framework/equihash.py in %r' % args.solver_dir)
    solver = load_solver(args.solver_dir)
    try:
        run(args, solver)
    except Failure as e:
        print('coinbase_for_parity: FAIL: %s' % e, file=sys.stderr)
        return 1
    except RpcError as e:
        print('coinbase_for_parity: %s' % e, file=sys.stderr)
        return 2
    return 0


if __name__ == '__main__':
    sys.exit(main())
