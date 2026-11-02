#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""The read subset of ycash6's vault RPC contract, checked against a running kogany (plan W7-a).

    python qa/vault_rpc_contract_read.py --url http://127.0.0.1:18232 --ycash6 $WS/ycash6

It reuses ycash6's own checker (`qa/rpc-tests/test_framework/vault_contract.py`, the `Contract`
class `qa/rpc-tests/vault_rpc_contract.py` uses) and contract (`doc/vault-rpc-contract.json`),
unmodified, with one recorded deviation: kogany has no wallet (plan K-3), so the `wallet` field of
a `Member` and of a `TemplateOut` is made optional before checking (the wallet in front of
kogany, yewd, adds it).

It checks every result of the five read methods (`vault_getinfo`, `set_list`, `set_getinfo`,
`vault_list`, `vault_decodescript`) against its documented shape, provokes the documented errors
the read methods raise (`unknown set`, `kind must be vault or intent`, `unregistered post-quantum
scheme`), decodes every vault, intent, bond and act script of the pinned vectors
(`testdata/yellowback/vault_vectors.json`), and checks that an unknown method is `-32601`.
Against `UnavailableVaultState` only `vault_getinfo` has a shape to check; the other reads must
answer `-32603`.
"""

import argparse
import base64
import decimal
import json
import os
import sys
import urllib.parse
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
VECTORS = os.path.join(HERE, '..', '..', '..', 'testdata', 'yellowback', 'vault_vectors.json')
READS = ['vault_getinfo', 'set_list', 'set_getinfo', 'vault_list', 'vault_decodescript']
READ_ERRORS = ['unknown set', 'kind must be vault or intent', 'unregistered post-quantum scheme']


class Proxy:
    """A JSON-RPC client that raises ycash6's JSONRPCException, as AuthServiceProxy does.

    ycash6's AuthServiceProxy refuses any Content-Type but exactly `application/json`, and Zakura
    answers `application/json; charset=utf-8` (a harness finding for plan W8, recorded in the
    W7-a report), so this client takes either.
    """

    def __init__(self, url, error_class):
        u = urllib.parse.urlsplit(url)
        self.url = urllib.parse.urlunsplit((u.scheme, u.hostname + (':%d' % u.port if u.port else ''), u.path or '/', '', ''))
        self.auth = None
        if u.username is not None:
            pair = '%s:%s' % (urllib.parse.unquote(u.username), urllib.parse.unquote(u.password or ''))
            self.auth = 'Basic ' + base64.b64encode(pair.encode()).decode()
        self.error_class = error_class
        self.id = 0

    def __getattr__(self, method):
        if method.startswith('__'):
            raise AttributeError(method)

        def call(*params):
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

        return call


def relax_wallet(t):
    """Make every object's `wallet` field optional (kogany has no wallet, K-3)."""
    if isinstance(t, dict):
        if t.get('type') == 'object' and 'wallet' in t.get('fields', {}):
            if 'wallet' not in t['optional']:
                t['optional'].append('wallet')
        for v in t.values():
            relax_wallet(v)
    elif isinstance(t, list):
        for v in t:
            relax_wallet(v)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    ap.add_argument('--url', required=True, help='kogany JSON-RPC URL, with credentials if any')
    ap.add_argument('--ycash6', required=True, help='a ycash6 tree (its contract and checker)')
    ap.add_argument('--expect-unavailable', action='store_true',
                    help='the node serves UnavailableVaultState: the db reads must answer -32603')
    args = ap.parse_args(argv)

    sys.path.insert(0, os.path.join(args.ycash6, 'qa', 'rpc-tests'))
    from test_framework.authproxy import JSONRPCException
    from test_framework.vault_contract import Contract

    c = Contract(os.path.join(args.ycash6, 'doc', 'vault-rpc-contract.json'))
    relax_wallet(c.doc)
    n = Proxy(args.url, JSONRPCException)

    try:
        n.vault_nosuchmethod()
        raise AssertionError('an unknown method answered')
    except JSONRPCException as e:
        assert e.error['code'] == -32601, e.error
    print('unknown method: -32601')

    info = c.call(n, 'vault_getinfo')
    print('vault_getinfo:', json.dumps(info, default=str))

    if args.expect_unavailable:
        assert 'statehash' not in info and info['dbtip'] is None, info
        for method, params in (('set_list', []), ('vault_list', []), ('set_getinfo', ['00' * 32])):
            try:
                getattr(n, method)(*params)
                raise AssertionError('%s answered without a vault database' % method)
            except JSONRPCException as e:
                assert e.error['code'] == -32603, e.error
                assert e.error['message'] == 'the vault database is not available', e.error
        print('unavailable state: set_list, set_getinfo, vault_list answer -32603')
        print('checked against the contract: vault_getinfo')
        return 0

    sets = c.call(n, 'set_list')
    for s in sets:
        c.call(n, 'set_getinfo', s['setid'])
        c.call(n, 'set_getinfo', s['setid'], info['height'] + 100)
    c.error('unknown set', n, 'set_getinfo', '00' * 32)

    outs = c.call(n, 'vault_list')
    for f in ({'kind': 'vault'}, {'kind': 'intent'}, {'tag': 'TEST'}, {'mine': False}):
        c.call(n, 'vault_list', f)
    if outs:
        c.call(n, 'vault_list', {'setid': outs[0]['setid'], 'owner': outs[0]['owner']})
    c.error('kind must be vault or intent', n, 'vault_list', {'kind': 'coin'})
    c.error('unregistered post-quantum scheme', n, 'vault_list', {'owner': '03' + '11' * 32})

    for o in outs:
        d = c.call(n, 'vault_decodescript', o['script'])
        assert d['type'] == o['kind'], (d, o)
        if o['kind'] == 'intent':
            assert c.call(n, 'vault_decodescript', o['origin'])['type'] == 'vault'
    with open(VECTORS, encoding='utf-8') as f:
        v = json.load(f)
    decoded = {}
    for key, field in (('vaults', 'script'), ('intents', 'script'), ('bonds', 'redeem'),
                       ('acts', 'script'), ('actScriptsInvalid', 'script'),
                       ('vaultsInvalid', 'script'), ('intentsInvalid', 'script')):
        for case in v[key]:
            if case[field] == '':
                # ycashd's ParseHexV refuses the empty string too (IsHex("") is false).
                try:
                    n.vault_decodescript('')
                    raise AssertionError('vault_decodescript accepted an empty script')
                except JSONRPCException as e:
                    assert e.error['code'] == -8, e.error
                continue
            t = c.call(n, 'vault_decodescript', case[field])['type']
            decoded[t] = decoded.get(t, 0) + 1
    assert c.call(n, 'vault_decodescript', '51')['type'] == 'none'
    print('vault_decodescript over the pinned vectors:', json.dumps(decoded, sort_keys=True))

    missing = sorted(set(READS) - c.checked)
    assert not missing, 'read methods never checked: %s' % missing
    unprovoked = sorted(set(READ_ERRORS) - c.provoked)
    assert not unprovoked, 'read errors never provoked: %s' % unprovoked
    print('checked against the contract:', ', '.join(m for m in READS if m in c.checked))
    print('documented errors provoked:', ', '.join(sorted(c.provoked)))
    print('deviation: `wallet` optional on Member and TemplateOut (kogany has no wallet, K-3)')
    return 0


if __name__ == '__main__':
    sys.exit(main())
