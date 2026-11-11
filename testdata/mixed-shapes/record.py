#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""Records `chain.json`: a Ycash regtest chain, built and mined by the C++ node lines, whose
transactions mix Sapling spends and outputs with the Vault upgrade's transparent scripts (beta2
address-interop plan W4.1, W4.2).

    python testdata/mixed-shapes/record.py --ycash-dd-bin <dir with ycashd> \\
        --ycash6-bin <dir with ycashd> --gen <mixed-shapes-gen binary> \\
        [--params ~/Library/Application\\ Support/ZcashParams] [--workdir DIR] [--port-base N]

Two nodes on one regtest chain, every upgrade through Canopy at height 1, Vault at
`VAULT_HEIGHT`, Falcon (`-pqfalcon`) from the Vault height: a ycash-dd (v4.5.0 line) node with the
wallet that builds and mines, and a ycash6 (6.x line) node connected to it that must accept every
transaction into its mempool and follow every block. Each mixed transaction is mined alone in its
own block, in the order below, so a node that replays the chain up to a shape's parent and then
mines the shape's transaction itself grows the same Sapling tree (the later shapes' anchors).

Shapes (each name is a key of `chain.json` `shapes`):

- `sapling-to-pq-slh`, `sapling-to-pq-falcon`: ycash-dd's `z_sendmany` from a Sapling address to a
  wallet PQ address (TX_PQPKH output, scheme 1 / 2), Sapling change.
- `pq-slh-to-sapling`, `pq-falcon-to-sapling`: a TX_PQPKH input (`OP_CHECKPQSIG`) and Sapling
  outputs only. No wallet builds this shape yet (plan §2), so `gen/` (the `mixed-shapes-gen`
  tool) builds the transaction, proves the Sapling output and signs it with the binding signature;
  ycashd's `signrawtransaction` then signs the PQ input with its wallet key over the ZIP-243
  digest that covers the Sapling parts.
- `sapling-to-vault`: Sapling spends (a note of the tool's key) and a vault-lock output (the
  template script of the wallet's own `vault_lock`, set and owner of that V), Sapling change. Built
  by the tool (`vault_lock` has no Sapling source yet).
- `sapling-and-pq-to-vault`: a Sapling spend and a TX_PQPKH input (SLH-DSA) together, paying a
  vault-lock output, a TX_PQPKH output (FN-DSA-512) and Sapling change: the PQ signature and the
  Sapling signatures over one digest.

For every PQ input `chain.json` records the input index, the spent script and amount, so the
replay can recompute the digest and check the C++-made signature against it. For every PQ
output it records what the ycash-dd node (with `-insightexplorer`) answers for its address:
`getrawtransaction` / `decoderawtransaction` addresses and `getaddressutxos` (plan W4.3).

Stdlib only, except the tool. Nothing here runs in CI; the replays do:
`crates/zakura-consensus/tests/mixed_shapes_chain.rs` (every block through the block pipeline),
`crates/zakura-consensus/src/transaction/tests/mixed_shapes.rs` (the transaction verifier, the
negative controls and the PQ signatures as sighash vectors) and
`crates/zakurad/tests/kogany_mixed_shapes.rs` (a running koganyd's mempool, block template and
miner). Recorded on 2026-11-10 with ycash-dd 99b4d8a47 (`wt/kc-cxx-fixes-dd`) and ycash6
436aefa5e (`wt/.bin/ycash6-s5-node`).
"""

import argparse
import base64
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from decimal import Decimal

VAULT_BRANCH_ID = '6d5b7a31'
NUPARAMS = ['5ba81b19', '76b809bb', '374d694f', '8e471bd6', '66314da3', '19bd2d2f']
VAULT_HEIGHT = 150
COIN = 100000000
FEE = 100000  # 0.001 YEC: well above the relay floor for an ~8 kB SLH-DSA spend on both lines
SEED = b'kogany mixed shapes fixture seed'.hex()
SEQUENCE = 0xfffffffe
HERE = os.path.dirname(os.path.abspath(__file__))


class RpcError(Exception):
    pass


class Node:
    def __init__(self, name, port):
        self.name, self.port = name, port

    def call(self, method, *params):
        body = json.dumps({'jsonrpc': '1.0', 'id': 1, 'method': method, 'params': list(params)},
                          default=float).encode()
        req = urllib.request.Request('http://127.0.0.1:%d/' % self.port, body,
                                     {'Content-Type': 'application/json'})
        req.add_header('Authorization', 'Basic ' + base64.b64encode(b'u:p').decode())
        try:
            raw = urllib.request.urlopen(req, timeout=600).read()
        except urllib.error.HTTPError as e:
            raw = e.read()
        answer = json.loads(raw, parse_float=Decimal)
        return answer.get('result'), answer.get('error')

    def ok(self, method, *params):
        result, error = self.call(method, *params)
        if error:
            shown = tuple(x[:80] + '...' if isinstance(x, str) and len(x) > 80 else x for x in params)
            raise RpcError('%s: %s%r: %s' % (self.name, method, shown, error))
        return result


def start(binary, workdir, name, port, rpcport, extra):
    datadir = os.path.join(workdir, name)
    os.makedirs(datadir, exist_ok=True)
    with open(os.path.join(datadir, 'ycash.conf'), 'w') as f:
        f.write('regtest=1\nshowmetrics=0\nrpcuser=u\nrpcpassword=p\nport=%d\nrpcport=%d\n'
                'listenonion=0\n' % (port, rpcport))
    args = [os.path.join(binary, 'ycashd'), '-datadir=' + datadir, '-discover=0', '-txindex',
            '-experimentalfeatures', '-insightexplorer', '-pqfalcon=1']
    args += ['-nuparams=%s:1' % b for b in NUPARAMS]
    args += ['-nuparams=%s:%d' % (VAULT_BRANCH_ID, VAULT_HEIGHT)]
    args += extra
    log = open(os.path.join(workdir, name + '.out'), 'a')
    return subprocess.Popen(args, stdout=log, stderr=subprocess.STDOUT)


def wait(predicate, what, timeout=120):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            if predicate():
                return
        except (RpcError, OSError, urllib.error.URLError):
            pass
        time.sleep(0.5)
    raise RpcError('timed out waiting for ' + what)


def stop(proc):
    if proc.poll() is None:
        proc.send_signal(signal.SIGTERM)
        try:
            proc.wait(60)
        except subprocess.TimeoutExpired:
            proc.kill()


def bech32_decode_payload(address):
    """The 43 data bytes of a Sapling bech32 address."""
    charset = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l'
    data = [charset.index(c) for c in address[address.rindex('1') + 1:]][:-6]
    acc, bits, out = 0, 0, []
    for v in data:
        acc = (acc << 5) | v
        bits += 5
        while bits >= 8:
            bits -= 8
            out.append((acc >> bits) & 0xff)
    assert len(out) == 43, address
    return bytes(out).hex()


class Recorder:
    def __init__(self, args, a, b):
        self.args, self.a, self.b = args, a, b
        self.shapes = {}

    def mine(self, n=1):
        hashes = self.a.ok('generate', n)
        tip = hashes[-1]
        wait(lambda: self.b.ok('getbestblockhash') == tip, 'ycash6 to follow ' + tip)
        return hashes

    def zat(self, value):
        return int(Decimal(value) * COIN)

    def gen(self, request):
        request = dict(request, seed=SEED, params=self.args.params)
        out = subprocess.run([self.args.gen], input=json.dumps(request).encode(),
                             stdout=subprocess.PIPE, check=True)
        answer = json.loads(out.stdout)
        if self.args.workdir and 'tx' in answer:
            with open(os.path.join(self.args.workdir, 'gen-%d.hex' % len(self.shapes)), 'w') as f:
                f.write(answer['tx'])
        return answer

    def sapling_chain(self):
        """Every transaction of the chain with Sapling outputs, in chain order."""
        txs = []
        for h in range(1, self.a.ok('getblockcount') + 1):
            block = self.a.ok('getblock', self.a.ok('getblockhash', h), 2)
            for tx in block['tx']:
                if tx.get('vShieldedOutput'):
                    txs.append(tx['hex'])
        return txs

    def coin(self, txid, script_hex):
        tx = self.a.ok('getrawtransaction', txid, 1)
        for out in tx['vout']:
            if out['scriptPubKey']['hex'] == script_hex:
                return {'txid': txid, 'vout': out['n'], 'value': self.zat(out['value']),
                        'script': script_hex}
        raise RpcError('%s pays no %s' % (txid, script_hex))

    def submit(self, name, txid_or_hex, pq_inputs, built_by):
        """Both mempools take the transaction, then a block mines it alone."""
        if len(txid_or_hex) == 64:
            txid = txid_or_hex
        else:
            txid = self.a.ok('sendrawtransaction', txid_or_hex)
        wait(lambda: txid in self.b.ok('getrawmempool'), 'ycash6 to accept ' + name)
        assert self.a.ok('getrawmempool') == [txid], 'the shape is mined alone'
        block = self.mine()[0]
        height = self.a.ok('getblock', block)['height']
        # The wallet has seen the block (its notes marked spent) before the next shape is built.
        # The wallet has seen the block (its notes marked spent) before the next shape is built:
        # ycash-dd's wallet catches up asynchronously, and a z_sendmany built before that picks
        # the note just spent (bad-txns-sapling-duplicate-nullifier).
        wait(lambda: self.a.ok('gettransaction', txid)['confirmations'] >= 1
             if self.a.call('gettransaction', txid)[1] is None else True,
             'the wallet to see ' + name)
        time.sleep(2)
        raw = self.a.ok('getrawtransaction', txid, 1)
        assert raw['height'] == height
        pq_outputs = []
        for out in raw['vout']:
            spk = out['scriptPubKey']
            if spk['hex'].endswith('c2') and len(spk['hex']) == 70:
                address = (spk.get('addresses') or [None])[0]
                pq_outputs.append({
                    'n': out['n'], 'script': spk['hex'], 'type': spk.get('type'),
                    'address': address,
                    'decoded': self.a.ok('decoderawtransaction', raw['hex'])['vout'][out['n']]
                    ['scriptPubKey'].get('addresses'),
                    'addressUtxos': self.a.ok('getaddressutxos', {'addresses': [address]})
                    if address else None,
                })
        self.shapes[name] = {
            'txid': txid, 'height': height, 'builtBy': built_by, 'pqInputs': pq_inputs,
            'pqOutputs': pq_outputs, 'saplingSpends': len(raw['vShieldedSpend']),
            'saplingOutputs': len(raw['vShieldedOutput']),
        }
        print('  %-26s height %d txid %s (%d bytes)' % (name, height, txid, len(raw['hex']) // 2))
        return txid

    def sign(self, unsigned, coins):
        """ycashd signs the PQ inputs (its wallet keys) of a tool-built transaction."""
        prevtxs = [{'txid': c['txid'], 'vout': c['vout'], 'scriptPubKey': c['script'],
                    'amount': Decimal(c['value']) / COIN} for c in coins]
        signed = self.a.ok('signrawtransaction', unsigned, prevtxs)
        assert signed['complete'], signed
        return signed['hex']

    def pq_input_record(self, n, coin, scheme):
        return {'nIn': n, 'scheme': scheme, 'scriptCode': coin['script'], 'amount': coin['value']}

    def run(self):
        a = self.a
        print('setup: coinbase, shield it into a Sapling address, mine to Vault + 2')
        self.mine(110)
        ys = a.ok('z_getnewaddress', 'sapling')
        opid = a.ok('z_shieldcoinbase', '*', ys, Decimal('0.0001'), 50)['opid']
        wait(lambda: a.ok('z_getoperationstatus', [opid])[0]['status'] == 'success', 'shielding')
        self.mine(VAULT_HEIGHT + 2 - a.ok('getblockcount'))
        print('  shielded: %s YEC' % a.ok('z_getbalance', ys))
        assert a.ok('z_getbalance', ys) > 8

        print('setup: a set and a transparent vault_lock (its template script is reused)')
        created = a.ok('set_create', {'seats': 1, 'unlockthreshold': 1, 'open': True})
        self.mine()
        owner_height = a.ok('getblockcount') + 30
        locked = a.ok('vault_lock', {'tag': 'TEST', 'setid': created['setid'], 'delay': 5,
                                     'ownerheight': owner_height, 'amount': 1})
        self.mine()
        vault_script = locked['script']

        slh = a.ok('getnewaddress', '', 'pqslh')
        falcon = a.ok('getnewaddress', '', 'pq')
        slh2 = a.ok('getnewaddress', '', 'pqslh')
        falcon2 = a.ok('getnewaddress', '', 'pq')
        script = {x: a.ok('validateaddress', x)['scriptPubKey'] for x in (slh, falcon, slh2, falcon2)}
        assert a.ok('validateaddress', slh)['pqscheme'] == 1
        assert a.ok('validateaddress', falcon)['pqscheme'] == 2
        # A transparent-funded SLH-DSA coin for the last shape, mined in the setup.
        slh2_txid = a.ok('sendtoaddress', slh2, 2)
        self.mine()
        slh2_coin = self.coin(slh2_txid, script[slh2])
        self.setup_tip = a.ok('getblockcount')

        print('shapes')
        to_slh = self.wait_op(a.ok('z_sendmany', ys, [{'address': slh, 'amount': 3}], 1,
                                   Decimal(FEE) / COIN))
        self.submit('sapling-to-pq-slh', to_slh, [], 'ycash-dd z_sendmany')
        to_falcon = self.wait_op(a.ok('z_sendmany', ys, [{'address': falcon, 'amount': 3}], 1,
                                      Decimal(FEE) / COIN))
        self.submit('sapling-to-pq-falcon', to_falcon, [], 'ycash-dd z_sendmany')

        self_address = self.gen({'mode': 'address'})['selfAddress']
        ys_payload = bech32_decode_payload(ys)
        for name, txid, addr, to in [('pq-slh-to-sapling', to_slh, slh, 'self'),
                                     ('pq-falcon-to-sapling', to_falcon, falcon, ys_payload)]:
            coin = self.coin(txid, script[addr])
            scheme = a.ok('validateaddress', addr)['pqscheme']
            built = self.gen({
                'mode': 'build', 'branchId': int(VAULT_BRANCH_ID, 16), 'lockTime': 0,
                'expiry': a.ok('getblockcount') + 20,
                'inputs': [{'txid': coin['txid'], 'vout': coin['vout'], 'sequence': SEQUENCE}],
                'outputs': [],
                'saplingOutputs': [{'to': to, 'value': coin['value'] - FEE}],
                'saplingSpends': [], 'saplingChain': [],
            })
            self.submit(name, self.sign(built['tx'], [coin]),
                        [self.pq_input_record(0, coin, scheme)],
                        'mixed-shapes-gen + ycash-dd signrawtransaction')
        assert a.ok('z_getbalance', ys) > 0
        to_self = self.shapes['pq-slh-to-sapling']['txid']

        print('  the tool owns the note of %s (address %s)' % (to_self, self_address))
        chain = self.sapling_chain()
        note_value = self.coin(to_slh, script[slh])['value'] - FEE
        built = self.gen({
            'mode': 'build', 'branchId': int(VAULT_BRANCH_ID, 16), 'lockTime': 0,
            'expiry': a.ok('getblockcount') + 20, 'inputs': [],
            'outputs': [{'value': COIN, 'script': vault_script}],
            'saplingOutputs': [{'to': 'self', 'value': note_value - COIN - FEE}],
            'saplingSpends': [{'txid': to_self}], 'saplingChain': chain,
        })
        assert built['anchor'] == a.ok('getblock', a.ok('getbestblockhash'))['finalsaplingroot']
        to_vault = self.submit('sapling-to-vault', built['tx'], [], 'mixed-shapes-gen')

        chain = self.sapling_chain()
        change = note_value - COIN - FEE
        built = self.gen({
            'mode': 'build', 'branchId': int(VAULT_BRANCH_ID, 16), 'lockTime': 0,
            'expiry': a.ok('getblockcount') + 20,
            'inputs': [{'txid': slh2_coin['txid'], 'vout': slh2_coin['vout'], 'sequence': SEQUENCE}],
            'outputs': [{'value': COIN, 'script': vault_script},
                        {'value': COIN, 'script': script[falcon2]}],
            'saplingOutputs': [{'to': 'self', 'value': change + slh2_coin['value'] - 2 * COIN - FEE}],
            'saplingSpends': [{'txid': to_vault}], 'saplingChain': chain,
        })
        assert built['anchor'] == a.ok('getblock', a.ok('getbestblockhash'))['finalsaplingroot']
        self.submit('sapling-and-pq-to-vault', self.sign(built['tx'], [slh2_coin]),
                    [self.pq_input_record(0, slh2_coin, 1)],
                    'mixed-shapes-gen + ycash-dd signrawtransaction')
        self.mine()

    def wait_op(self, opid):
        def done():
            status = self.a.ok('z_getoperationstatus', [opid])[0]
            if status['status'] == 'failed':
                raise SystemExit('operation failed: %r' % status)
            return status['status'] == 'success'
        wait(done, 'operation ' + opid)
        return self.a.ok('z_getoperationresult', [opid])[0]['result']['txid']

    def dump(self, path):
        a = self.a
        tip = a.ok('getblockcount')
        blocks = [a.ok('getblock', a.ok('getblockhash', h), 0) for h in range(1, tip + 1)]
        doc = {
            '_comment': 'Recorded by testdata/mixed-shapes/record.py; never edit by hand.',
            'recordedWith': {'ycash-dd': a.ok('getnetworkinfo')['subversion'],
                             'ycash6': self.b.ok('getnetworkinfo')['subversion']},
            'vaultActivation': VAULT_HEIGHT,
            'pqFalconHeight': 0,
            'branchId': int(VAULT_BRANCH_ID, 16),
            'setupTip': self.setup_tip,
            'shapes': self.shapes,
            'blocks': blocks,
        }
        with open(path, 'w') as f:
            json.dump(doc, f, indent=1, sort_keys=True, default=str)
            f.write('\n')
        print('wrote %s: %d blocks' % (path, tip))


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('--ycash-dd-bin', required=True)
    p.add_argument('--ycash6-bin', required=True)
    p.add_argument('--gen', required=True)
    p.add_argument('--params', default=os.path.expanduser('~/Library/Application Support/ZcashParams'))
    p.add_argument('--workdir')
    p.add_argument('--port-base', type=int, default=24700)
    p.add_argument('--out', default=os.path.join(HERE, 'chain.json'))
    args = p.parse_args(argv)
    workdir = args.workdir or tempfile.mkdtemp(prefix='mixed-shapes-')
    pb = args.port_base
    procs = []
    try:
        procs.append(start(args.ycash_dd_bin, workdir, 'ycash-dd', pb + 1, pb + 2, ['-listen=1']))
        procs.append(start(args.ycash6_bin, workdir, 'ycash6', pb + 3, pb + 4,
                           ['-listen=0', '-connect=127.0.0.1:%d' % (pb + 1),
                            '-i-am-aware-zcashd-will-be-replaced-by-zebrad-and-zallet-in-2025']))
        a, b = Node('ycash-dd', pb + 2), Node('ycash6', pb + 4)
        wait(lambda: a.ok('getblockcount') == 0 and b.ok('getblockcount') == 0, 'the nodes')
        wait(lambda: a.ok('getconnectioncount') == 1, 'the peer connection')
        r = Recorder(args, a, b)
        r.run()
        r.dump(args.out)
    finally:
        for proc in procs:
            stop(proc)
        if not args.workdir:
            shutil.rmtree(workdir, ignore_errors=True)
    return 0


if __name__ == '__main__':
    sys.exit(main())
