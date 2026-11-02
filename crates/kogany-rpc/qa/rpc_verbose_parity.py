#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""kogany's verbose transaction shapes against ycash6's on the scripts' fields (W7-e).

    python crates/kogany-rpc/qa/rpc_verbose_parity.py --zakurad <zakurad built with --features ycash> \\
        [--ycash6-bin $WS/wt/.bin/ycash6-65cb4ae0f] [--workdir DIR] [--keep] [--json FILE]

It starts a ycashd and a zakurad on one Ycash regtest chain as `rpc_ycash_parity.py` does, mines
transactions whose outputs cover every script kind ycashd's `Solver` names (P2PKH, P2SH, P2PK,
bare multisig with valid and invalid keys, OP_RETURN, the vault primitive's V and I templates
from the pinned `vault_vectors.json`, TX_PQPKH of each registered scheme and of an unregistered
one, the post-quantum channel and its near-misses from `yellowback_pq_vectors.json`, and
non-standard scripts) and whose inputs spend P2PKH, P2SH and bare scripts, then compares
`getrawtransaction 1`, `getblock 2` and `gettxout` on the fields the shared regtest scripts read:
`vin[].scriptSig`, `vin[].txid/vout/sequence` and `vout[].scriptPubKey`
(`asm`, `hex`, `type`, `reqSigs`, `addresses`), `vout[].value/valueZat/n`. Every difference on
those fields fails the run; the gate is an empty table. Fields outside them are
`rpc_ycash_parity.py`'s.

Stdlib only; the node plumbing is `rpc_ycash_parity.py`'s and the transaction builder
`mempool_ycash_parity.py`'s.
"""

import argparse
import json
import os
import re
import shutil
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import rpc_ycash_parity as base  # noqa: E402
import mempool_ycash_parity as mp  # noqa: E402

VECTORS = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', '..', 'testdata', 'yellowback')

# The compared fields (path regexes over the getrawtransaction / getblock tx / gettxout object).
FIELDS = re.compile(r'(\.tx\[\d+\])?\.(vin\[\d+\]\.(scriptSig(\.(asm|hex))?|txid|vout|sequence|coinbase)'
                    r'|vout\[\d+\]\.(scriptPubKey(\.(asm|hex|type|reqSigs|addresses(\[\d+\])?))?|value|valueZat|n)'
                    r'|scriptPubKey(\.(asm|hex|type|reqSigs|addresses(\[\d+\])?))?|value)$')


def push(data):
    if len(data) < 0x4c:
        return bytes([len(data)]) + data
    if len(data) <= 0xff:
        return b'\x4c' + bytes([len(data)]) + data
    return b'\x4d' + len(data).to_bytes(2, 'little') + data


def output_scripts():
    """(label, script bytes) for every script kind ycashd's Solver names."""
    vault = json.load(open(os.path.join(VECTORS, 'vault_vectors.json')))
    pq = json.load(open(os.path.join(VECTORS, 'yellowback_pq_vectors.json')))
    key = bytes.fromhex(vault['keys'][0]['pubkey'])
    key2 = bytes.fromhex(vault['keys'][1]['pubkey'])
    bad_key = b'\x05' + key[1:]
    owner = vault['pqOwner']['owner']
    falcon = vault['falconOwner']['owner']
    out = [
        ('p2pk', push(key) + b'\xac'),
        ('multisig-1of2', b'\x51' + push(key) + push(key2) + b'\x52\xae'),
        ('multisig-invalid-key', b'\x51' + push(key) + push(bad_key) + b'\x52\xae'),
        ('multisig-all-invalid', b'\x51' + push(bad_key) + b'\x51\xae'),
        ('op-return', b'\x6a' + push(b'kogany')),
        ('op-true', b'\x51'),
        ('nonstandard', b'\x51\x52\x93'),
        ('pqpkh-slhdsa', b'\x20' + bytes.fromhex(owner['hash']) + b'\x51\xc2'),
        ('pqpkh-falcon', b'\x20' + bytes.fromhex(falcon['hash']) + b'\x52\xc2'),
        ('pqpkh-scheme-3', b'\x20' + bytes.fromhex(owner['hash']) + b'\x53\xc2'),
    ]
    out += [('vault-' + v['name'], bytes.fromhex(v['script'])) for v in vault['vaults'][:3]]
    out += [('intent-' + v['name'], bytes.fromhex(v['script'])) for v in vault['intents'][:3]]
    by_type = {}
    for s in pq['scripts']:
        by_type.setdefault(s['type'], []).append(s)
    for t, n in (('pqpubkeyhash', 2), ('pqchannel', 4), ('other', 6)):
        out += [('pq-%s-%s' % (t, s['name']), bytes.fromhex(s['hex'])) for s in by_type.get(t, [])[:n]]
    return out


def compare(report, method, call, a, b):
    """Differences of `a` (ycash6) and `b` (kogany) on FIELDS only; each one fails."""
    report.calls += 1
    if a is None or b is None:
        if (a is None) != (b is None):
            report.rows.append((method, call, '=answer', 'presence', a, b, 'FAIL', 'one node has no answer'))
        return
    for path, kind, x, y in base.diff(a, b):
        if FIELDS.search(path):
            report.rows.append((method, call, path, kind, x, y, 'FAIL', 'a field the scripts read'))


def run(args):
    report = base.Report()
    workdir = args.workdir or tempfile.mkdtemp(prefix='rpc-verbose-parity-')
    os.makedirs(workdir, exist_ok=True)
    p = args.port_base
    y = base.Node('ycash6', p + 1, 'u:p')
    z = base.Node('kogany', p + 11)
    procs = []
    try:
        procs.append(mp.start_ycashd(args.ycash6_bin, workdir, p, p + 1, None, []))
        base.wait_up(y, procs[-1], 'ycashd')
        miner = y.ok('getnewaddress')
        base.stop(procs.pop())
        procs.append(mp.start_ycashd(args.ycash6_bin, workdir, p, p + 1, miner, []))
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

        # One transaction paying every script kind, plus a P2SH(OP_TRUE) for the input side.
        scripts = output_scripts()
        p2sh_true = b'\xa9\x14' + bytes.fromhex(_hash160_hex(y, '51')) + b'\x87'
        outs = [(10000, s) for _label, s in scripts] + [(100000, p2sh_true)]
        funding = chain.build(outs, 100000)
        fund_txid = y.ok('sendrawtransaction', funding, True)
        z.call('sendrawtransaction', funding)
        chain.mine()

        # Spends of the bare OP_TRUE (empty scriptSig) and the P2SH(OP_TRUE) (push of the
        # redeem script) outputs.
        n_true = [label for label, _ in scripts].index('op-true')
        n_p2sh = len(scripts)
        spend = mp.serialize(chain.group, [(fund_txid, n_true, mp.SEQUENCE_FINAL), (fund_txid, n_p2sh, mp.SEQUENCE_FINAL)],
                             [(100000, chain.change_script)], 0, chain.tip() + 20)
        spend = bytearray(spend)
        spend_hex = _with_script_sigs(spend, [b'', push(b'\x51')]).hex()
        spend_txid = y.ok('sendrawtransaction', spend_hex, True)
        z.call('sendrawtransaction', spend_hex)
        chain.mine()

        tip = y.ok('getbestblockhash')
        for txid in (fund_txid, spend_txid):
            call = txid[:16]
            compare(report, 'getrawtransaction', call, y.ok('getrawtransaction', txid, 1), z.ok('getrawtransaction', txid, 1))
        for h in (y.ok('getblockhash', y.ok('getblockcount') - 1), tip):
            compare(report, 'getblock', h[:16], y.ok('getblock', h, 2), z.ok('getblock', h, 2))
        for n in range(len(scripts) + 2):
            compare(report, 'gettxout', '%s:%d' % (fund_txid[:8], n),
                    y.ok('gettxout', fund_txid, n, False), z.ok('gettxout', fund_txid, n, False))
        types = sorted({o['scriptPubKey']['type'] for o in y.ok('getrawtransaction', fund_txid, 1)['vout']})
        print('script kinds compared: %s' % ', '.join(types))
    finally:
        for proc in reversed(procs):
            base.stop(proc)
        if not args.keep and not args.workdir:
            shutil.rmtree(workdir, ignore_errors=True)
    return report


def _hash160_hex(y, script_hex):
    """The P2SH hash of `script_hex`, from ycashd's decodescript."""
    address = y.ok('decodescript', script_hex)['p2sh']
    return y.ok('validateaddress', address)['scriptPubKey'][4:44]


def _with_script_sigs(tx, script_sigs):
    """`tx` (a serialised v4 transaction with empty scriptSigs) with `script_sigs` in place."""
    b = bytes(tx)
    head, i = b[:8], 8
    nin, i = base.read_compact(b, i)
    body = mp.compact(nin)
    for k in range(nin):
        outpoint = b[i:i + 36]
        i += 36
        slen, i = base.read_compact(b, i)
        i += slen
        seq = b[i:i + 4]
        i += 4
        body += outpoint + mp.compact(len(script_sigs[k])) + script_sigs[k] + seq
    return head + body + b[i:]


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    ap.add_argument('--zakurad', default=os.getenv('KOGANY_BIN'), help='zakurad built with --features ycash')
    ap.add_argument('--ycash6-bin', default=base.DEFAULT_YCASH6_BIN, help='directory holding ycashd')
    ap.add_argument('--workdir', help='keep the datadirs here (default: a temporary directory)')
    ap.add_argument('--keep', action='store_true', help='keep the temporary directory')
    ap.add_argument('--port-base', type=int, default=29340)
    ap.add_argument('--json', help='write the difference table here')
    args = ap.parse_args(argv)
    if not args.zakurad:
        ap.error('--zakurad (or KOGANY_BIN) is required')
    try:
        report = run(args)
    except base.RpcError as e:
        print('rpc_verbose_parity: %s' % e, file=sys.stderr)
        return 2
    report.print()
    if args.json:
        with open(args.json, 'w') as f:
            json.dump([dict(zip(('method', 'call', 'field', 'kind', 'ycash6', 'kogany', 'class', 'reason'), r))
                       for r in report.rows], f, indent=1, sort_keys=True)
    return 1 if report.failures() else 0


if __name__ == '__main__':
    sys.exit(main())
