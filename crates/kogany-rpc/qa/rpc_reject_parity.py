#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""kogany's reject codes and texts against ycash6's, string for string, on one Ycash regtest
chain with the Vault upgrade active (W7-e), and `setmocktime`.

    python crates/kogany-rpc/qa/rpc_reject_parity.py --koganyd <koganyd, the --features ycash build> \\
        [--ycash6-bin $WS/wt/.bin/ycash6-65cb4ae0f] [--workdir DIR] [--keep] [--json FILE]

It starts a ycashd (`-mocktime`) and a zakurad on Ycash regtest with every upgrade through Vault
at height 1 (blocks mined on ycashd and fed to zakurad, as in `rpc_ycash_parity.py`), then
provokes, on both nodes, each reject string the shared regtest scripts match
(`qa/rpc-tests/vault_*.py`, `yellowback_*.py`) that kogany can produce before the mempool checks
the vault rules (W6) and the YED module is registered (W5-f):

- `sendrawtransaction`: `64: non-final`, `64: non-BIP68-final`, `16: bad-txns-vault-timelock`,
  `tx-expiring-soon: …`, `-25 Missing inputs`, `-27 transaction already in block chain`, the
  txid for a transaction already in the mempool, `256: absurdly-high-fee, …` and the
  `16: mandatory-script-verify-flag-failed (…)` texts of a false signature, `OP_VERIFY`, a bad
  opcode, `OP_CHECKSEQUENCEVERIFY` and `OP_CHECKSETSIG`;
- `submitblock` (blocks assembled and solved in Python with ycash6's `test_framework.mininode`):
  `bad-txns-nonfinal` (a lock time and a BIP68 lock), `bad-txns-vault-timelock`, a script failure
  (`rejected`: ycashd checks a block's scripts in parallel, without a reason), the vault act rules
  (`bad-vault-act-version`, `bad-vault-act-type`, W4-d) and `-22 Block decode failed`;
- `setmocktime`: `getblocktemplate.curtime` follows it on both nodes.

The answers must be equal: the error code and message of `sendrawtransaction`, the result of
`submitblock`. The table is printed at the end, and with `--json` written as JSON. The scripts'
other reject strings (the vault primitive's `bad-vault-*`/`bad-txns-vault-*` and the YED
`bad-yellowback-*`) have their mapping tested in zakura-rpc (`ycash_reject` tests); in the mempool
they wait for W6 and W5-f.

The node plumbing is `rpc_ycash_parity.py`'s and `mempool_ycash_parity.py`'s; block assembly
imports ycash6's `qa/rpc-tests/test_framework` (`--ycash6-qa`, default the harness worktree).
"""

import argparse
import json
import os
import shutil
import sys
import tempfile
import time
from io import BytesIO

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import rpc_ycash_parity as base  # noqa: E402
import mempool_ycash_parity as mp  # noqa: E402

VAULT_VECTORS = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', '..', 'testdata',
                             'yellowback', 'vault_vectors.json')
DEFAULT_YCASH6_QA = os.path.join(os.getenv('WS', ''), 'wt', 'kc-ycash6-int', 'qa', 'rpc-tests')
VAULT_BRANCH = '6d5b7a31'
COIN = mp.COIN
SEQUENCE_TYPE_FLAG = 1 << 22      # BIP68's time-based flag, invalid from Vault (bad-txns-vault-timelock)
OP_CSV, OP_CHECKSETSIG = b'\xb2', b'\xc0'


def push(data):
    return bytes([len(data)]) + data if len(data) < 0x4c else b'\x4c' + bytes([len(data)]) + data


def p2sh_of(y, redeem):
    """The P2SH scriptPubKey of `redeem`, from ycashd."""
    address = y.ok('decodescript', redeem.hex())['p2sh']
    return bytes.fromhex(y.ok('validateaddress', address)['scriptPubKey'])


class Cases:
    def __init__(self, y, z, chain, qa):
        self.y, self.z, self.chain, self.qa = y, z, chain, qa
        self.rows = []

    def record(self, case, a, b, want=None):
        ok = a == b and (want is None or want(a))
        self.rows.append((case, a, b, ok))
        print('%-34s %s' % (case, 'ok' if ok else 'FAIL'))
        print('    ycash6: %s\n    kogany: %s' % (json.dumps(a), json.dumps(b)))

    @staticmethod
    def answer(result_error):
        result, error = result_error
        if error:
            return {'code': error.get('code'), 'message': error.get('message')}
        return {'result': result}

    def tx(self, case, hexdata, want=None):
        a = self.answer(self.y.call('sendrawtransaction', hexdata))
        b = self.answer(self.z.call('sendrawtransaction', hexdata))
        self.record('tx/' + case, a, b, want)
        return a, b

    def block(self, case, txs_hex):
        block_hex = self.solve(txs_hex)
        a = self.answer(self.y.call('submitblock', block_hex))
        b = self.answer(self.z.call('submitblock', block_hex))
        self.record('block/' + case, a, b, lambda r: r.get('result') not in (None, 'duplicate'))

    def solve(self, txs_hex):
        """A block on the common tip carrying `txs_hex`: ycashd's template header and coinbase
        (less the template transactions' fees), solved for regtest Equihash (48, 5)."""
        from test_framework.mininode import CBlock, CTransaction
        gbt = self.y.ok('getblocktemplate')
        cb = CTransaction()
        cb.deserialize(BytesIO(bytes.fromhex(gbt['coinbasetxn']['data'])))
        cb.vout[0].nValue -= sum(int(t.get('fee', 0)) for t in gbt.get('transactions', []))
        block = CBlock()
        block.nVersion = gbt['version']
        block.hashPrevBlock = int(gbt['previousblockhash'], 16)
        block.hashBlockCommitments = int(gbt['blockcommitmentshash'], 16)
        block.nTime = gbt['curtime']
        block.nBits = int(gbt['bits'], 16)
        block.vtx = [cb]
        for h in txs_hex:
            tx = CTransaction()
            tx.deserialize(BytesIO(bytes.fromhex(h)))
            block.vtx.append(tx)
        block.hashMerkleRoot = block.calc_merkle_root()
        block.solve()
        return block.serialize().hex()

    def failures(self):
        return [r for r in self.rows if not r[3]]


def fund(chain, script, value=COIN):
    """A confirmed output paying `script` (`value` zatoshis): (txid, n, value)."""
    signed = chain.build([(value, script)], 10000)
    txid = chain.y.ok('sendrawtransaction', signed, True)
    chain.z.call('sendrawtransaction', signed)
    return txid, 0, value


def spend_script(chain, coin, script_sig, sequence=mp.SEQUENCE_FINAL, fee=10000):
    """An unsigned spend of a P2SH or bare `coin` with `script_sig`, to the wallet."""
    txid, n, value = coin
    raw = mp.serialize(chain.group, [(txid, n, sequence)], [(value - fee, chain.change_script)], 0,
                       chain.tip() + 20)
    return _with_script_sig(raw, script_sig).hex()


def _with_script_sig(tx, script_sig):
    """A one-input serialised v4 transaction `tx` with an empty scriptSig, with `script_sig`."""
    i = 8
    nin, i = base.read_compact(tx, i)
    assert nin == 1
    start = i + 36
    assert tx[start] == 0
    return tx[:start] + mp.compact(len(script_sig)) + script_sig + tx[start + 1:]


def corrupt_signature(signed_hex):
    """`signed_hex` (one P2PKH input) with one bit of the signature's r flipped: still DER, false."""
    b = bytearray(bytes.fromhex(signed_hex))
    i = 8
    nin, i = base.read_compact(b, i)
    i += 36
    _slen, i = base.read_compact(b, i)
    sig_len = b[i]
    sig = i + 1
    assert b[sig] == 0x30 and sig_len > 8
    r_len = b[sig + 3]
    b[sig + 4 + r_len - 1] ^= 0x01
    return bytes(b).hex()


def run_cases(c, clock_base):
    chain, y, z = c.chain, c.y, c.z
    pay = chain.change_script
    tip = chain.tip()
    nxt = tip + 1

    # Coins for the lock-time cases, one block deep, and the script outputs.
    fresh = [fund(chain, pay, 2 * COIN) for _ in range(3)]
    redeem_verify = b'\x00\x69\x51'                  # OP_0 OP_VERIFY OP_1
    redeem_bad = b'\xbb'                             # an undefined opcode
    redeem_csv = b'\x55' + OP_CSV                    # OP_5 OP_CHECKSEQUENCEVERIFY
    redeem_setsig = push(bytes(range(32))) + b'\x51' + OP_CHECKSETSIG
    coins = {name: fund(chain, p2sh_of(y, r)) for name, r in
             (('verify', redeem_verify), ('bad', redeem_bad), ('csv', redeem_csv), ('setsig', redeem_setsig))}
    chain.mine()
    chain.mine()
    nxt = chain.tip() + 1

    final = mp.SEQUENCE_FINAL
    non_final = chain.build([(COIN, pay)], 10000, lock_time=nxt + 5, sequence=final - 1)
    c.tx('non-final', non_final)
    bip68 = chain.build([(COIN, pay)], 10000, sequence=50, coin=fresh[0])
    c.tx('non-BIP68-final', bip68)
    timelock = chain.build([(COIN, pay)], 10000, sequence=SEQUENCE_TYPE_FLAG | 1, coin=fresh[1])
    c.tx('bad-txns-vault-timelock', timelock)
    c.tx('tx-expiring-soon', chain.build([(COIN, pay)], 10000, expiry=nxt + 2))
    missing = mp.serialize(chain.group, [('11' * 32, 0, final)], [(COIN, pay)], 0, nxt + 20).hex()
    c.tx('Missing inputs', missing)
    c.tx('absurdly-high-fee', chain.build([(COIN, pay)], 20000000))
    c.tx('false-signature', corrupt_signature(chain.build([(COIN, pay)], 10000)))
    c.tx('OP_VERIFY', spend_script(chain, coins['verify'], push(redeem_verify)))
    c.tx('bad-opcode', spend_script(chain, coins['bad'], push(redeem_bad)))
    csv_spend = spend_script(chain, coins['csv'], push(redeem_csv), sequence=1)
    c.tx('OP_CHECKSEQUENCEVERIFY', csv_spend)
    setsig_spend = spend_script(chain, coins['setsig'], push(redeem_setsig))
    c.tx('OP_CHECKSETSIG', setsig_spend)

    accepted = chain.build([(COIN, pay)], 10000, coin=fresh[2])
    c.tx('accepted', accepted, lambda r: 'result' in r)
    c.tx('in-mempool', accepted, lambda r: 'result' in r)
    chain.mine()
    c.tx('already-in-chain', accepted, lambda r: r.get('code') == -27)

    # Blocks.
    c.block('non-final', [non_final])
    c.block('non-BIP68-final', [bip68])
    c.block('bad-txns-vault-timelock', [timelock])
    c.block('OP_CHECKSETSIG', [setsig_spend])
    # The vault primitive's act rules in a block (W4-d check::vault): a YV act whose version or
    # type does not decode (vault_vectors.json actsInvalid).
    acts = {a['name']: bytes.fromhex(a['payload']) for a in json.load(open(VAULT_VECTORS))['actsInvalid']}
    for name, reason in (('version-2', 'bad-vault-act-version'), ('type-7', 'bad-vault-act-type')):
        act_tx = chain.build([(0, b'\x6a' + push(acts[name]))], 10000)
        c.block(reason, [act_tx])
    a = c.answer(y.call('submitblock', '00'))
    b = c.answer(z.call('submitblock', '00'))
    c.record('block/decode-failed', a, b, lambda r: r.get('code') == -22)

    # setmocktime moves getblocktemplate.curtime on both nodes.
    mock = clock_base + 1801
    a = c.answer(y.call('setmocktime', mock))
    b = c.answer(z.call('setmocktime', mock))
    c.record('setmocktime', a, b, lambda r: r == {'result': None})
    a = {'curtime': y.ok('getblocktemplate')['curtime']}
    b = {'curtime': z.ok('getblocktemplate')['curtime']}
    c.record('setmocktime/curtime', a, b, lambda r: r['curtime'] == mock)
    z.ok('setmocktime', 0)
    now = int(time.time())
    curtime = z.ok('getblocktemplate')['curtime']
    c.record('setmocktime-0/curtime', {'near-now': True}, {'near-now': abs(curtime - now) <= 120})


def run(args):
    sys.path.insert(0, args.ycash6_qa)
    workdir = args.workdir or tempfile.mkdtemp(prefix='rpc-reject-parity-')
    os.makedirs(workdir, exist_ok=True)
    p = args.port_base
    y = base.Node('ycash6', p + 1, 'u:p')
    z = base.Node('kogany', p + 11)
    base.NUPARAMS = base.NUPARAMS + [VAULT_BRANCH]
    base.ACTIVATION_KEYS = base.ACTIVATION_KEYS + ['Vault']
    clock_base = int(time.time())
    yargs = ['-mocktime=%d' % clock_base]
    procs = []
    try:
        procs.append(mp.start_ycashd(args.ycash6_bin, workdir, p, p + 1, None, yargs))
        base.wait_up(y, procs[-1], 'ycashd')
        miner = y.ok('getnewaddress')
        base.stop(procs.pop())
        procs.append(mp.start_ycashd(args.ycash6_bin, workdir, p, p + 1, miner, yargs))
        base.wait_up(y, procs[-1], 'ycashd')
        procs.append(base.start_zakurad(args.zakurad, workdir, mp.kogany_toml(workdir, p, miner, [])))
        base.wait_up(z, procs[-1], 'zakurad')
        chain = mp.Chain(y, z)
        chain.mine(1)
        chain.mine(110)
        base.wait_balance(y, 50)
        raw = y.ok('getrawtransaction', y.ok('getblock', y.ok('getblockhash', 1), 1)['tx'][0], 0)
        chain.group = bytes.fromhex(raw)[4:8]
        chain.change_script = bytes.fromhex(y.ok('validateaddress', miner)['scriptPubKey'])
        c = Cases(y, z, chain, args.ycash6_qa)
        run_cases(c, clock_base)
    finally:
        for proc in reversed(procs):
            base.stop(proc)
        if not args.keep and not args.workdir:
            shutil.rmtree(workdir, ignore_errors=True)
    return c


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    ap.add_argument('--koganyd', '--zakurad', dest='zakurad', default=os.getenv('KOGANY_BIN'),
                    help='koganyd (the --features ycash build; --zakurad is its old name)')
    ap.add_argument('--ycash6-bin', default=base.DEFAULT_YCASH6_BIN, help='directory holding ycashd')
    ap.add_argument('--ycash6-qa', default=DEFAULT_YCASH6_QA, help="ycash6's qa/rpc-tests (test_framework)")
    ap.add_argument('--workdir', help='keep the datadirs here (default: a temporary directory)')
    ap.add_argument('--keep', action='store_true', help='keep the temporary directory')
    ap.add_argument('--port-base', type=int, default=29360)
    ap.add_argument('--json', help='write the answer table here')
    args = ap.parse_args(argv)
    if not args.zakurad:
        ap.error('--koganyd (or KOGANY_BIN) is required')
    try:
        c = run(args)
    except base.RpcError as e:
        print('rpc_reject_parity: %s' % e, file=sys.stderr)
        return 2
    fails = c.failures()
    print('\n%d answers compared, %d failing' % (len(c.rows), len(fails)))
    if args.json:
        with open(args.json, 'w') as f:
            json.dump([dict(zip(('case', 'ycash6', 'kogany', 'ok'), r)) for r in c.rows], f, indent=1)
    return 1 if fails else 0


if __name__ == '__main__':
    sys.exit(main())
