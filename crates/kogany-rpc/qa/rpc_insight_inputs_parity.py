#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""kogany's insight input fields and `blockfee` against ycash6's (beta3 item 6).

    python crates/kogany-rpc/qa/rpc_insight_inputs_parity.py --koganyd <koganyd, the --features ycash build> \\
        [--ycash6-bin DIR] [--workdir DIR] [--keep] [--port-base N] [--json FILE]

It starts a `-insightexplorer` ycashd (Vault at 1, `-pqfalcon=1`) and a koganyd (archive, Vault at
1, Falcon at 0) on one regtest chain mined by ycashd, as `mempool_ycash_parity.py` does, and makes
inputs of every kind ycashd's spent index names (ycash6 `src/rpc/rawtransaction.cpp` `TxToJSON`,
`SpentInfoDestination`, #128):

- wallet spends from an FN-DSA-512, an SLH-DSA-SHA2-128s and an ECC P2PKH address;
- a bare P2PK spend and a P2SH spend;
- a chained spend of an unconfirmed post-quantum parent (both in the mempool, then in one block);
- a vault owner spend (a value, no address) and the coinbases (neither);

then compares, field by field, `vin[].value`, `vin[].valueSat`, `vin[].address` (and `txid`/`vout`
for the alignment), `vout[].valueSat`, `authdigest` and the block's `blockfee`, in
`getrawtransaction 1` (in the mempool and confirmed), `getblock 2` and `getblock 1` (`blockfee`)
for every block. Every difference fails the run; so does an input kind ycashd does not name as
the test expects (the run would compare nothing). `getblockdeltas`, `decoderawtransaction` and
REST are not served by koganyd and are not compared.

Stdlib only; the node plumbing is `rpc_ycash_parity.py`'s and `mempool_ycash_parity.py`'s.
"""

import argparse
import json
import os
import re
import shutil
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import rpc_ycash_parity as base  # noqa: E402
import mempool_ycash_parity as mp  # noqa: E402
import rpc_verbose_parity as vp  # noqa: E402

FIELDS = re.compile(r'(\.tx\[\d+\])?\.(vin\[\d+\]\.(value|valueSat|address|txid|vout|coinbase)'
                    r'|vin|vout\[\d+\]\.valueSat|authdigest|blockfee)$')
FUND = 2
SEND = 1


def compare(report, method, call, a, b):
    report.calls += 1
    if a is None or b is None:
        if (a is None) != (b is None):
            report.rows.append((method, call, '=answer', 'presence', a, b, 'FAIL', 'one node has no answer'))
        return
    for path, kind, x, y in base.diff(a, b):
        if FIELDS.search(path):
            report.rows.append((method, call, path, kind, x, y, 'FAIL', 'an insight input field'))


def expect(report, label, ok, detail):
    """A coverage check on ycashd's own answer: the run compares what it means to."""
    report.calls += 1
    if not ok:
        report.rows.append(('coverage', label, '-', 'expectation', detail, None, 'FAIL', 'ycashd does not name it'))


def relay(chain, txid):
    """Offers ycashd's mempool transaction `txid` to koganyd (refusals are reported, not fatal:
    the block carries it either way)."""
    raw = chain.y.ok('getrawtransaction', txid, 0)
    _, error = chain.z.call('sendrawtransaction', raw)
    if error:
        print('  koganyd refused %s in the mempool: %s' % (txid[:16], error))
    return error is None


def wait_mempool(z, txid, timeout=30):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if txid in z.ok('getrawmempool'):
            return True
        time.sleep(0.2)
    return False


def inputs_of(tx, prev_txid, prev_n=None):
    return [i for i in tx['vin'] if i.get('txid') == prev_txid and (prev_n is None or i.get('vout') == prev_n)]


def run(args):
    report = base.Report()
    workdir = args.workdir or tempfile.mkdtemp(prefix='rpc-insight-inputs-')
    os.makedirs(workdir, exist_ok=True)
    p = args.port_base
    y = base.Node('ycash6', p + 1, 'u:p')
    z = base.Node('kogany', p + 11)
    procs = []
    yextra = ['-insightexplorer', '-pqfalcon=1']
    try:
        procs.append(mp.start_ycashd(args.ycash6_bin, workdir, p, p + 1, None, yextra, vault=True))
        base.wait_up(y, procs[-1], 'ycashd')
        miner = y.ok('getnewaddress')
        base.stop(procs.pop())
        procs.append(mp.start_ycashd(args.ycash6_bin, workdir, p, p + 1, miner, yextra, vault=True))
        base.wait_up(y, procs[-1], 'ycashd')
        procs.append(base.start_zakurad(args.zakurad, workdir,
                                        mp.kogany_toml(workdir, p, miner, [], vault=True, falcon=True)))
        base.wait_up(z, procs[-1], 'koganyd')
        chain = mp.Chain(y, z)
        chain.mine(1)
        chain.mine(200)
        base.wait_balance(y, 100)
        raw = y.ok('getrawtransaction', y.ok('getblock', y.ok('getblockhash', 1), 1)['tx'][0], 0)
        chain.group = bytes.fromhex(raw)[4:8]
        chain.change_script = bytes.fromhex(y.ok('validateaddress', miner)['scriptPubKey'])
        first = chain.tip()

        print('fund an FN-DSA, an SLH-DSA and an ECC address, a bare P2PK and a P2SH(OP_TRUE)')
        src = {'fn': y.ok('getnewaddress', 'pq'), 'slh': y.ok('getnewaddress', 'pqslh'), 'ecc': y.ok('getnewaddress')}
        fund = y.ok('sendmany', '', {a: FUND for a in src.values()})
        relay(chain, fund)
        pubkey = bytes.fromhex(y.ok('validateaddress', y.ok('getnewaddress'))['pubkey'])
        p2pk = vp.push(pubkey) + b'\xac'
        p2sh_true = b'\xa9\x14' + bytes.fromhex(vp._hash160_hex(y, '51')) + b'\x87'
        bare = chain.build([(30000000, p2pk), (20000000, p2sh_true)], 100000)
        bare_txid = y.ok('sendrawtransaction', bare, True)
        z.call('sendrawtransaction', bare)
        chain.mine()
        fund_tx = y.ok('getrawtransaction', fund, 1)
        vout_of = {a: o['n'] for o in fund_tx['vout'] for a in o['scriptPubKey'].get('addresses', [])}
        mp.wait_until(lambda: len(y.ok('listunspent', 1, 9999999, list(src.values()))) == 3, 'the funded coins')

        print('spend each wallet coin from its address, and the P2PK and P2SH coins')
        spend = {}
        for k, a in src.items():
            opid = y.ok('z_sendmany', a, [{'address': y.ok('getnewaddress'), 'amount': SEND}], 1, None,
                        'AllowFullyTransparent')
            spend[k] = mp.wait_operation(y, opid)
            relay(chain, spend[k])
        expiry = chain.tip() + 20
        p2pk_spend = mp.serialize(chain.group, [(bare_txid, 0, mp.SEQUENCE_FINAL)],
                                  [(30000000 - 100000, chain.change_script)], 0, expiry)
        signed = y.ok('signrawtransaction', p2pk_spend.hex())
        assert signed.get('complete'), signed
        spend['p2pk'] = y.ok('sendrawtransaction', signed['hex'], True)
        z.call('sendrawtransaction', signed['hex'])
        p2sh_spend = mp.serialize(chain.group, [(bare_txid, 1, mp.SEQUENCE_FINAL)],
                                  [(20000000 - 100000, chain.change_script)], 0, expiry)
        p2sh_hex = vp._with_script_sigs(bytearray(p2sh_spend), [vp.push(b'\x51')]).hex()
        spend['p2sh'] = y.ok('sendrawtransaction', p2sh_hex, True)
        z.call('sendrawtransaction', p2sh_hex)

        prevout = {'fn': (fund, vout_of[src['fn']]), 'slh': (fund, vout_of[src['slh']]),
                   'ecc': (fund, vout_of[src['ecc']]), 'p2pk': (bare_txid, 0), 'p2sh': (bare_txid, 1)}

        def check_named(where, tx, k):
            ins = inputs_of(tx, *prevout[k])
            # every kind here names an address (the vault input, which names none, is checked below)
            expect(report, '%s %s' % (where, k),
                   len(ins) == 1 and 'valueSat' in ins[0] and 'address' in ins[0]
                   and (k not in src or ins[0].get('address') == src[k]),
                   ins)

        print('getrawtransaction 1 in the mempool')
        for k, txid in spend.items():
            if wait_mempool(z, txid):
                a, b = y.ok('getrawtransaction', txid, 1), z.ok('getrawtransaction', txid, 1)
                check_named('mempool', a, k)
                compare(report, 'getrawtransaction', 'mempool %s' % k, a, b)
            else:
                report.rows.append(('getrawtransaction', 'mempool %s' % k, '=mempool', 'presence', True, False,
                                    'FAIL', 'koganyd has not the spend in its mempool'))
        chain.mine()
        spend_block = y.ok('getbestblockhash')

        print('a chained spend of an unconfirmed post-quantum parent')
        fn2 = y.ok('getnewaddress', 'pq')
        mp.wait_until(lambda: [u['txid'] for u in y.ok('listunspent', 1, 9999999, [src['fn']])] == [spend['fn']],
                      'the FN-DSA change')
        parent = mp.wait_operation(y, y.ok('z_sendmany', src['fn'], [{'address': fn2, 'amount': 0.5}], 1, None,
                                            'AllowFullyTransparent'))
        relay(chain, parent)
        child = mp.wait_operation(y, y.ok('z_sendmany', fn2, [{'address': y.ok('getnewaddress'), 'amount': 0.25}], 0,
                                           None, 'AllowFullyTransparent'))
        relay(chain, child)
        pvout = [o['n'] for o in y.ok('getrawtransaction', parent, 1)['vout']
                 if o['scriptPubKey'].get('addresses') == [fn2]][0]
        a = y.ok('getrawtransaction', child, 1)
        ins = inputs_of(a, parent, pvout)
        expect(report, 'mempool chained', [(i.get('address'), i.get('valueSat')) for i in ins] == [(fn2, 50000000)], ins)
        if wait_mempool(z, child):
            compare(report, 'getrawtransaction', 'mempool chained', a, z.ok('getrawtransaction', child, 1))
        else:
            report.rows.append(('getrawtransaction', 'mempool chained', '=mempool', 'presence', True, False,
                                'FAIL', 'koganyd has not the chained child in its mempool'))

        print('a vault owner spend (a value, no address)')
        setid = y.ok('set_create', {'seats': 3, 'unlockthreshold': 2, 'cancelthreshold': 1, 'slashthreshold': 2,
                                    'maturity': 2, 'livenesswindow': 50, 'bondmin': 1, 'ratewindow': 20})['setid']
        chain.mine()
        lock = y.ok('vault_lock', {'tag': 'TEST', 'setid': setid, 'delay': 5,
                                   'ownerheight': chain.tip() + 1000, 'amount': 1})
        chain.mine()
        owner = y.ok('vault_ownerspend', lock['outpoint'], y.ok('getnewaddress'))['txid']
        relay(chain, owner)
        chain.mine()
        a = y.ok('getrawtransaction', owner, 1)
        v = inputs_of(a, lock['txid'])
        expect(report, 'vault', [('address' in i, i.get('valueSat')) for i in v] == [(False, 100000000)], v)

        print('confirmed: getrawtransaction 1, getblock 2 and getblock 1 of every block')
        for k, txid in list(spend.items()) + [('parent', parent), ('chained', child), ('vault', owner)]:
            a = y.ok('getrawtransaction', txid, 1)
            if k in prevout:
                check_named('confirmed', a, k)
            compare(report, 'getrawtransaction', 'confirmed %s' % k, a, z.ok('getrawtransaction', txid, 1))
        block = y.ok('getblock', spend_block, 2)
        expect(report, 'blockfee', block.get('blockfee', 0) > 0, block.get('blockfee'))
        expect(report, 'coinbase', [sorted(i) for i in block['tx'][0]['vin']] == [['coinbase', 'sequence']],
               block['tx'][0]['vin'])
        named = 0
        for h in range(first, chain.tip() + 1):
            bh = y.ok('getblockhash', h)
            a, b = y.ok('getblock', bh, 2), z.ok('getblock', bh, 2)
            named += sum(1 for t in a['tx'] for i in t['vin'] if 'address' in i)
            compare(report, 'getblock', '%d v2' % h, a, b)
        for h in range(0, chain.tip() + 1):
            bh = y.ok('getblockhash', h)
            compare(report, 'getblock', '%d v1' % h, {'blockfee': y.ok('getblock', bh, 1)['blockfee']},
                    {'blockfee': z.ok('getblock', bh, 1).get('blockfee')})
        print('blocks %d..%d compared at verbosity 2 (%d named inputs), 0..%d at verbosity 1'
              % (first, chain.tip(), named, chain.tip()))
    finally:
        for proc in reversed(procs):
            base.stop(proc)
        if not args.keep and not args.workdir:
            shutil.rmtree(workdir, ignore_errors=True)
    return report


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    ap.add_argument('--koganyd', '--zakurad', dest='zakurad', default=os.getenv('KOGANY_BIN'),
                    help='koganyd (the --features ycash build)')
    ap.add_argument('--ycash6-bin', default=base.DEFAULT_YCASH6_BIN, help='directory holding ycashd')
    ap.add_argument('--workdir', help='keep the datadirs here (default: a temporary directory)')
    ap.add_argument('--keep', action='store_true', help='keep the temporary directory')
    ap.add_argument('--port-base', type=int, default=29440)
    ap.add_argument('--json', help='write the difference table here')
    args = ap.parse_args(argv)
    if not args.zakurad:
        ap.error('--koganyd (or KOGANY_BIN) is required')
    try:
        report = run(args)
    except base.RpcError as e:
        print('rpc_insight_inputs_parity: %s' % e, file=sys.stderr)
        return 2
    report.print()
    if args.json:
        with open(args.json, 'w') as f:
            json.dump([dict(zip(('method', 'call', 'field', 'kind', 'ycash6', 'kogany', 'class', 'reason'), r))
                       for r in report.rows], f, indent=1, sort_keys=True)
    return 1 if report.failures() else 0


if __name__ == '__main__':
    sys.exit(main())
