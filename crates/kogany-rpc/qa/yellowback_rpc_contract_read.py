#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""The node-context (read) subset of ycash6's Yellowback RPC contract, checked against a running kogany (plan W7-b).

    python qa/yellowback_rpc_contract_read.py --url http://127.0.0.1:18232 --ycash6 $WS/ycash6
    python qa/yellowback_rpc_contract_read.py --url ... --ycash6 ... --expect-not-live

It reuses ycash6's own checker, unmodified: the `Contract` class of
`qa/rpc-tests/yellowback_rpc_contract.py` with its `OPTIONAL` and `NULLABLE` tables, over
`doc/yellowback-rpc-contract.json` (rpcversion 8). The 27 node-context methods are kogany's (the
25 reads and the node-state `yed_setquote` and `yed_addattestation`); the 25 wallet-context
methods are yewd's (plan K-3, K-20), and kogany must answer them `-32601`.

Against kogany's `MockYedState` (`KOGANY_YED_RPC_MOCK=1`) every node-context method's result is
checked against its documented shape, every node-side error identifier the mock can produce is
provoked, and every OP_RETURN payload and raw transaction of the pinned golden chain
(`testdata/yellowback/yellowback_golden.json`) is decoded. The report ends with the contract
cases that pass against the mock and those that need the real index (plan W5-e/W5-f).

With `--expect-not-live` (zakurad's default until W5-f) it checks the lightwalletd-dd probe
semantics instead: every `yed_*` method answers `-32601` with ycashd's "Yellowback is not active"
message, which `common/yellowback.go` `ProbeYellowback` reads as "no Yellowback".
"""

import argparse
import base64
import decimal
import hashlib
import importlib.util
import io
import json
import os
import sys
import urllib.parse
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
GOLDEN = os.path.join(HERE, '..', '..', '..', 'testdata', 'yellowback', 'yellowback_golden.json')

NOT_LIVE = 'Method not found (Yellowback is not active'

NODE_METHODS = [
    'yed_getinfo', 'yed_getstatehash', 'yed_verifyindex', 'yed_getstats', 'yed_getprice',
    'yed_getactivation', 'yed_listminers', 'yed_gettag', 'yed_setquote', 'yed_getfeepayee',
    'yed_getvault', 'yed_listvaults', 'yed_listclaimable', 'yed_listtokens', 'yed_gettxinfo',
    'yed_decodepayload', 'yed_validaterawtransaction', 'yed_getblockverdict',
    'yed_estimatecollateral', 'yed_estimatefee', 'yed_gethistory', 'yed_listattestors',
    'yed_getattestations', 'yed_addattestation', 'yed_buildbundle', 'yed_getselection',
    'yed_getnotice',
]

# Node-side error identifiers of the contract (`errors[*].raisedBy` names a node-context method),
# and why the mock cannot provoke the ones it does not.
NEEDS_REAL_STATE = {
    'bundle-insufficient': 'needs a pool short of M_SELECT fresh attestations for selected(R, selector) (W5-c selection, W5-e pool)',
    'mint10-diverged': 'needs an armed snapshot whose pFast and aMint diverge (W5-d price state)',
    'fee-no-eligible-payee': 'needs a refHeight with an empty E(refHeight) (FEE-2 over the Tags/Judgements of W5-e)',
    'verdict-parent-not-tip': 'needs a stored block whose parent is not the index tip (W5-e block store access)',
    'no-payout-address': 'needs a node without a payout key (W8 miner configuration)',
    'yellowback-unhealthy': 'needs a storage fault in the index (-yellowbacktestfault, W5-e); the allow-list itself is a kogany-rpc unit test',
    'vault-not-active': 'raised by the wallet commands only on a node-context call path (yed_getvault never raises it in ycash6)',
    'vault-not-owned': 'wallet ownership (yewd)',
}

# Values the mock cannot make meaningful, though their shapes pass (the cross-line invariant of
# plan §4.2 rule 4 (ii) compares them with ycash6 once W5-e serves the real index).
VALUE_CASES = [
    'yed_getstatehash.statehash equals ycash6 and yellowback_model.py at every sync point (§4.2 rule 4 (ii))',
    'yed_gethistory rows equal yellowback_model.py field for field',
    'yed_getstats / yed_verifyindex totals re-derived from Tokens and Vaults',
    'yed_listclaimable claimable/claimPath under the combined pClaim of the bundle this node would build',
    'yed_estimatecollateral requiredZat, sigmaMultBps and the MINTPOL-1 gate (mintBlockedReason)',
    'yed_validaterawtransaction verdicts and script validity at tip + 1',
    'yed_getblockverdict over a stored candidate block',
    'yed_listattestors weights and seat weights (256-bit decimal strings) at a height',
    'yed_addattestation signature verification (BYATTEST1 message, low-S compact ECDSA; the mock checks a placeholder)',
    'yed_getinfo.params.fees.network (the attested fee price, W6-b) and params.attest.bondMinZat (D-Q-30)',
]


B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'


def base58check(payload):
    """Base58Check of version || body (ycashd's EncodeBase58Check)."""
    data = payload + hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    n = int.from_bytes(data, 'big')
    out = ''
    while n:
        n, r = divmod(n, 58)
        out = B58[r] + out
    return '1' * (len(data) - len(data.lstrip(b'\0'))) + out


class Proxy:
    """A JSON-RPC client raising ycash6's JSONRPCException (see vault_rpc_contract_read.py)."""

    def __init__(self, url, error_class):
        u = urllib.parse.urlsplit(url)
        self.url = urllib.parse.urlunsplit((u.scheme, u.hostname + (':%d' % u.port if u.port else ''), u.path or '/', '', ''))
        self.auth = None
        if u.username is not None:
            pair = '%s:%s' % (urllib.parse.unquote(u.username), urllib.parse.unquote(u.password or ''))
            self.auth = 'Basic ' + base64.b64encode(pair.encode()).decode()
        self.error_class = error_class
        self.id = 0

    def call(self, method, *params):
        self.id += 1
        body = json.dumps({'jsonrpc': '2.0', 'id': self.id, 'method': method, 'params': list(params)})
        req = urllib.request.Request(self.url, body.encode(), {'Content-Type': 'application/json'})
        if self.auth:
            req.add_header('Authorization', self.auth)
        with urllib.request.urlopen(req, timeout=30) as r:
            assert r.headers.get_content_type() == 'application/json', r.headers
            response = json.loads(r.read().decode('utf8'), parse_float=decimal.Decimal)
        if response.get('error') is not None:
            raise self.error_class(response['error'])
        return response['result']


def load_checker(ycash6):
    """ycash6's `yellowback_rpc_contract` module (its Contract, OPTIONAL and NULLABLE), imported unmodified."""
    rpc_tests = os.path.join(ycash6, 'qa', 'rpc-tests')
    sys.path.insert(0, rpc_tests)
    spec = importlib.util.spec_from_file_location('yellowback_rpc_contract', os.path.join(rpc_tests, 'yellowback_rpc_contract.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    from test_framework.authproxy import JSONRPCException
    module.JSONRPCException = JSONRPCException
    return module


class Run:
    def __init__(self, proxy, checker, contract):
        self.n = proxy
        self.checker = checker
        self.c = contract
        self.provoked = set()

    def check(self, method, *params):
        return self.c.check(method, self.n.call(method, *params), ' %s' % json.dumps(params, default=str))

    def error(self, ident, code, method, *params):
        try:
            self.n.call(method, *params)
        except self.checker.JSONRPCException as e:
            assert e.error['code'] == code, (method, e.error)
            assert e.error['message'].startswith(ident + ':') or e.error['message'] == ident, (ident, e.error)
            self.provoked.add(ident)
            return e.error
        raise AssertionError('%s %r answered; expected %s' % (method, params, ident))


def golden_transactions(ycash6):
    """(height, raw tx hex, OP_RETURN script hexes) of every transaction of the pinned golden chain."""
    from test_framework.mininode import CTransaction
    with open(GOLDEN, encoding='utf-8') as f:
        g = json.load(f)
    for b in g['blocks']:
        for raw in b['txs']:
            tx = CTransaction()
            tx.deserialize(io.BytesIO(bytes.fromhex(raw)))
            scripts = [o.scriptPubKey.hex() for o in tx.vout if o.scriptPubKey[:1] == b'\x6a']
            yield b['height'], raw, scripts


# Well-formed arguments for every node-context method with required parameters: ycashd checks the
# arity before it asks whether Yellowback is live (a short call is -1 with the help text there and
# -1 "Invalid params" on kogany), so the not-live probe calls each with its full arity.
PROBE_ARGS = {
    'yed_gettag': ['1'], 'yed_setquote': [0, 0], 'yed_getfeepayee': [1], 'yed_getvault': ['00' * 32],
    'yed_listtokens': [['x']], 'yed_gettxinfo': ['00' * 32], 'yed_decodepayload': ['00'],
    'yed_validaterawtransaction': ['00'], 'yed_getblockverdict': ['00' * 32],
    'yed_estimatecollateral': [100000, 48], 'yed_estimatefee': [100000], 'yed_gethistory': [1, 1],
    'yed_addattestation': ['00'], 'yed_buildbundle': [1, ''], 'yed_getselection': [1, ''],
    'yed_getnotice': ['00' * 32],
}


def not_live(n, checker, wallet):
    for method in NODE_METHODS + wallet:
        try:
            n.call(method, *PROBE_ARGS.get(method, []))
            raise AssertionError('%s answered on a node without Yellowback' % method)
        except checker.JSONRPCException as e:
            assert e.error['code'] == -32601, (method, e.error)
            if method in NODE_METHODS:
                assert e.error['message'].startswith(NOT_LIVE), (method, e.error)
    # lightwalletd-dd's probe: btcd renders "-32601: <message>", split at the first ':'.
    try:
        n.call('yed_getinfo')
    except checker.JSONRPCException as e:
        rendered = '%d: %s' % (e.error['code'], e.error['message'])
        assert rendered.split(':', 1)[0].strip() == '-32601'
    print('not live: all %d node-context and %d wallet yed_* methods answer -32601 (%s ...)' % (len(NODE_METHODS), len(wallet), NOT_LIVE))
    print('lightwalletd-dd ProbeYellowback: Enabled=false, no error (the Yellowback service is not started)')
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    ap.add_argument('--url', required=True, help='kogany JSON-RPC URL, with credentials if any')
    ap.add_argument('--ycash6', required=True, help='a ycash6 tree (its contract and checker)')
    ap.add_argument('--expect-not-live', action='store_true',
                    help='the node serves UnavailableYedState: every yed_* method must answer -32601')
    args = ap.parse_args(argv)

    checker = load_checker(args.ycash6)
    contract = checker.Contract(os.path.join(args.ycash6, 'doc', 'yellowback-rpc-contract.json'))
    assert contract.doc['rpcversion'] == 8, contract.doc['rpcversion']
    documented = sorted(k for k in contract.doc if k.startswith('yed_'))
    wallet = sorted(set(documented) - set(NODE_METHODS))
    assert len(NODE_METHODS) == 27 and len(wallet) == 25, (len(NODE_METHODS), len(wallet))
    n = Proxy(args.url, checker.JSONRPCException)

    try:
        n.call('yed_nosuchmethod')
        raise AssertionError('an unknown method answered')
    except checker.JSONRPCException as e:
        assert e.error['code'] == -32601, e.error
    print('unknown method: -32601')

    if args.expect_not_live:
        return not_live(n, checker, wallet)

    r = Run(n, checker, contract)
    info = r.check('yed_getinfo')
    assert info['rpcversion'] == 8 and info['enabled'] is True, info
    tip = info['height']
    print('yed_getinfo: rpcversion %d, network %s, height %d, statehash at the tip below' % (info['rpcversion'], info['network'], tip))
    sh = r.check('yed_getstatehash')
    r.check('yed_getstatehash', tip)
    print('yed_getstatehash:', sh['statehash'])
    r.check('yed_verifyindex')
    r.check('yed_getstats')
    r.check('yed_getprice')
    r.check('yed_getprice', tip - 1)
    r.check('yed_getactivation')
    r.check('yed_listminers')
    r.check('yed_listminers', tip, 20)
    r.check('yed_gettag', str(tip))
    r.check('yed_gettag', info['blockhash'])
    r.check('yed_setquote', 2000000, 3)
    r.check('yed_setquote', 0, 0)
    ref = tip - info['params']['refLag']
    r.check('yed_getfeepayee', ref)
    vaults = r.check('yed_listvaults')
    for status in ('ACTIVE', 'CLAIMING', ''):
        r.check('yed_listvaults', status, 10, 0)
    for v in vaults:
        r.check('yed_getvault', v['txid'])
        r.check('yed_getnotice', v['txid'])
    r.check('yed_gettxinfo', vaults[0]['txid'])
    r.check('yed_listclaimable')
    r.check('yed_listclaimable', 1, 1)
    r.check('yed_listattestors')
    r.check('yed_listattestors', tip - 1)
    pool = r.check('yed_getattestations')
    r.check('yed_addattestation', pool[0]['hex'])
    r.check('yed_buildbundle', ref, '')
    r.check('yed_getselection', ref, '')
    r.check('yed_getselection', ref, '00' * 36)
    r.check('yed_estimatecollateral', 100000, 48)
    r.check('yed_estimatecollateral', 100000, 100, 2000000)
    r.check('yed_estimatefee', 100000)
    r.check('yed_estimatefee', 100000, 400000)
    r.check('yed_gethistory', tip - 10, tip)
    r.check('yed_getblockverdict', info['blockhash'])

    # yed_listtokens: the CLAIMING vault's refund holder (a P2PKH script) holds a token; ask by its
    # YED address, then by the two forms each returned row names (both name the same holder).
    holders = [v['refundHolder'] for v in vaults if 'refundHolder' in v]
    assert holders and holders[0].startswith('76a914') and holders[0].endswith('88ac'), holders
    yed_address = base58check(bytes.fromhex(info['params']['addressVersion'] + holders[0][6:46]))
    tokens = r.check('yed_listtokens', [yed_address])
    assert tokens and tokens[0]['address'] == yed_address, tokens
    for t in tokens:
        assert r.check('yed_listtokens', [t['transparentAddress']]) == tokens
    r.check('yed_listtokens', [yed_address], 0, 10, 0)

    # Golden-chain payloads: every OP_RETURN script and raw transaction of the pinned chain.
    decoded, raw_decoded, shapes, bundles = {}, {}, 0, 0
    for height, raw, scripts in golden_transactions(args.ycash6):
        for s in scripts:
            d = r.n.call('yed_decodepayload', s)
            decoded[d['type']] = decoded.get(d['type'], 0) + 1
            if d['valid'] and d['type'] == 'mint':
                r.c.check('yed_decodepayload', d, ' mint at %d' % height)
                shapes += 1
        d = r.n.call('yed_decodepayload', raw)
        raw_decoded[d['type']] = raw_decoded.get(d['type'], 0) + 1
        if 'bundle' in d:
            b = d['bundle']
            assert b['count'] == len(b['attestations']) and all(len(a['hex']) == 148 for a in b['attestations']), b
            bundles += 1
    print('yed_decodepayload over the golden OP_RETURN scripts:', json.dumps(decoded, sort_keys=True), '(%d MINT shapes checked)' % shapes)
    print('yed_decodepayload over the golden raw transactions:', json.dumps(raw_decoded, sort_keys=True), '(%d carrier bundles decoded)' % bundles)
    assert raw_decoded.get('mint', 0) == decoded.get('mint', 0), (raw_decoded, decoded)
    r.c.check('yed_decodepayload', r.n.call('yed_decodepayload', '00'))

    # A raw transaction: the golden chain's first non-coinbase one.
    for height, raw, _ in golden_transactions(args.ycash6):
        if height > 1:
            try:
                r.check('yed_validaterawtransaction', raw)
            except checker.JSONRPCException as e:
                raise AssertionError('yed_validaterawtransaction refused a golden transaction: %s' % e.error)
            break

    # Node-side error identifiers.
    unknown = '00' * 32
    r.error('vault-not-found', -8, 'yed_getvault', unknown)
    r.error('vault-not-found', -8, 'yed_getnotice', unknown)
    r.error('too-many-addresses', -8, 'yed_listtokens', [])
    r.error('too-many-addresses', -8, 'yed_listtokens', ['x'] * 101)
    r.error('invalid-address', -5, 'yed_listtokens', ['nonsense'])
    r.error('mint-bad-lock', -8, 'yed_estimatecollateral', 100000, 1)
    r.error('mint-unsatisfiable', -26, 'yed_estimatecollateral', info['params']['maxMintCents'], 145, 100)
    r.error('quote-out-of-range', -8, 'yed_setquote', 1, 0)
    r.error('attest-malformed', -8, 'yed_addattestation', '00')
    att = bytes.fromhex(pool[0]['hex'])
    bad_sig = att[:-1] + bytes([att[-1] ^ 1])
    r.error('attest-bad-sig', -26, 'yed_addattestation', bad_sig.hex())
    def attestation(seq, price, cited):
        sig = bytes([(seq ^ cited) & 0xff]) * 64      # the mock's placeholder signature
        return (seq.to_bytes(2, 'little') + price.to_bytes(4, 'little') + cited.to_bytes(4, 'little') + sig).hex()
    cited = pool[0]['citedHeight']
    r.error('attest-unknown-seq', -26, 'yed_addattestation', attestation(999, 1985000, cited))
    r.error('attest-not-eligible', -26, 'yed_addattestation', attestation(4, 1985000, cited))
    r.error('attest-stale', -26, 'yed_addattestation', attestation(1, 1985000, tip - 20))
    r.error('attest-range', -26, 'yed_addattestation', attestation(1, 1, cited))
    r.error('tx-not-found', -8, 'yed_gettxinfo', unknown)

    for method in wallet:
        try:
            n.call(method)
            raise AssertionError('%s (a wallet RPC) answered on kogany' % method)
        except checker.JSONRPCException as e:
            assert e.error['code'] == -32601, (method, e.error)
    print('wallet-context methods (yewd, K-3): all %d answer -32601' % len(wallet))

    missing = sorted(set(NODE_METHODS) - contract.checked)
    assert not missing, 'node-context methods never checked: %s' % missing
    node_errors = sorted(k for k, v in contract.doc['errors'].items()
                         if any(m in NODE_METHODS for m in v['raisedBy']) or 'every gated command' in v['raisedBy'])
    unprovoked = sorted(set(node_errors) - r.provoked - set(NEEDS_REAL_STATE))
    assert not unprovoked, 'node-side errors neither provoked nor listed as needing real state: %s' % unprovoked

    print()
    print('PASS against the mock:')
    print('  shapes (yellowback-rpc-contract.json, ycash6 Contract.check): %d of %d node-context methods: %s' % (
        len(contract.checked & set(NODE_METHODS)), len(NODE_METHODS), ', '.join(m for m in NODE_METHODS if m in contract.checked)))
    print('  error identifiers provoked: %s' % ', '.join(sorted(r.provoked)))
    print('  wallet-context methods refused -32601: %d' % len(wallet))
    print('NEED the real index (W5-e/W5-f):')
    for ident in sorted(set(node_errors) & set(NEEDS_REAL_STATE)):
        print('  error %s: %s' % (ident, NEEDS_REAL_STATE[ident]))
    for case in VALUE_CASES:
        print('  value %s' % case)
    return 0


if __name__ == '__main__':
    sys.exit(main())
