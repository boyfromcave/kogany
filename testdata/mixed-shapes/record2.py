#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""Records `chain2.json`: the second mixed-shape chain (beta2 list item 20 (a), (c)), built and
mined by a ycash6 (6.x line) wallet node with a ycash-dd (v4.5.0 line) node following, and the
C++ verdicts on malformed variants of its transactions.

    python testdata/mixed-shapes/record2.py --ycash6-bin <dir with ycashd> \\
        --ycash-dd-bin <dir with ycashd> --gen <mixed-shapes-gen binary> \\
        [--params ~/Library/Application\\ Support/ZcashParams] [--workdir DIR] [--port-base N]

The chain is laid out as `record.py`'s (every upgrade through Canopy at height 1, Vault at
`VAULT_HEIGHT`, Falcon from the Vault height, each shape mined alone in its own block, in the
order below), but the wallet that builds is ycash6's, so the shapes its wallet makes are 6.x
wallet shapes. ycash-dd must accept every transaction into its mempool and follow every block.
Both nodes enforce the relay standardness policy (`-acceptnonstdtxn=0`), as kogany's replay node
does (`accept_non_standard = false`).

Shapes (keys of `chain2.json` `shapes`), the ones `chain.json` does not have:

- `sapling-to-pq-slh`, `sapling-to-pq-falcon`: ycash6's `z_sendmany` from Sapling to a wallet PQ
  address (they fund the next two).
- `pq-slh-to-sapling-pq-change`, `pq-falcon-to-sapling-pq-change`: ycash6's `z_sendmany` from a
  PQ address (D-1) to a Sapling address, change back to the same PQ address (D-4): a TX_PQPKH
  input beside Sapling outputs and a TX_PQPKH change output.
- `pq-falcon-and-sapling-to-sapling`: an FN-DSA-512 input beside a Sapling spend, paying Sapling
  outputs only (`gen/` builds, ycash6's `signrawtransaction` signs the PQ input).
- `sapling-and-pq-slh-to-pq-with-pq-change`: a Sapling spend and an SLH-DSA input paying an
  FN-DSA-512 output and SLH-DSA change (a second TX_PQPKH output), Sapling change.
- `sapling-to-vault-from`: ycash6's `vault_lock` with a Sapling `from` (D-3): Sapling spends
  beside the vault-lock output.
- `vault-unlock-beside-sapling`: a vault UNLOCK (the template input, its intent and re-lock
  outputs as `vault_buildunlock` built them) whose fee is paid by a Sapling spend instead of the
  build's transparent fee input; the set signature (`set_signunlock`, SIGHASH_ALL|ANYONECANPAY)
  covers the Sapling parts.

Rejects (`chain2.json` `rejects`): before a shape is sent, malformed variants of it, or
transactions built on the same coins, are offered to both C++ mempools (`sendrawtransaction`) and
both answers recorded. Each must be refused by both. The kogany replays offer the same bytes at
the same height and compare:

- `bad-pq-signature`: one byte of the FN-DSA-512 signature flipped (beside a Sapling spend);
- `pq-signature-without-sapling`: the PQ input signed by ycash6 over the digest of the same
  transaction with its Sapling parts left out;
- `changed-sapling-output`: one `outCiphertext` byte flipped (covered by the binding and the PQ
  signature);
- `wrong-scheme-output`: a Sapling spend paying `0x20 <32 bytes> OP_3 OP_CHECKPQSIG`, a TX_PQPKH
  shape with a scheme byte that names no scheme;
- `wrong-branch-id`: a Sapling-only spend whose spend-authorization and binding signatures are
  over the Canopy branch's digest instead of Vault's (0x6d5b7a31);
- `vault-unlock-changed-sapling-output`: the vault unlock with one `outCiphertext` byte flipped
  after the set signed it.

Not recorded here: a YED token output spent as plain YEC and a Sapling-funded `yed_mint` need the
Yellowback module live (an attestor set, armed attestors, a price); kogany carries the
Sapling-funded mint in `crates/kogany-rpc/qa/yed_live_rig.py --mint-from-sapling`.

Stdlib only, except the tool, and `record.py` (its node plumbing). Nothing here runs in CI; the
replays read `chain2.json` beside `chain.json`. Recorded on 2026-11-11 with the ycash6 binary of
`wt/up6-b2-prefix` (branch up/b2-pq-prefix, `/YcashCpp:6.22.0-beta2/`, built 20:22 from the branch
before its merge commit 5826f9462) and the ycash-dd binary of `wt/up-b2-prefix` (branch
up/b2-pq-prefix, `/YcashCpp:4.5.0/`, built 18:57 from the branch before its merge commit
9af35d45d). Both carry the D-9 address prefixes, so the recorded address texts are D-9 texts; the
replays assert on scripts and key hashes only, never on address text.
"""

import argparse
import json
import os
import shutil
import sys
import tempfile
import time
from decimal import Decimal

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import record as r1  # noqa: E402

VAULT_BRANCH_ID = r1.VAULT_BRANCH_ID
CANOPY_BRANCH_ID = 0xe9ff75a6
VAULT_HEIGHT = r1.VAULT_HEIGHT
COIN = r1.COIN
FEE = r1.FEE
SEQUENCE = r1.SEQUENCE
HERE = r1.HERE
AWARE = '-i-am-aware-zcashd-will-be-replaced-by-zebrad-and-zallet-in-2025'


def read_compact(b, at):
    first = b[at]
    if first < 0xfd:
        return first, at + 1
    size = {0xfd: 2, 0xfe: 4, 0xff: 8}[first]
    return int.from_bytes(b[at + 1:at + 1 + size], 'little'), at + 1 + size


def compact(n):
    if n < 0xfd:
        return bytes([n])
    if n <= 0xffff:
        return b'\xfd' + n.to_bytes(2, 'little')
    return b'\xfe' + n.to_bytes(4, 'little')


def parse_v4(hex_tx):
    """A v4 transaction's transparent parts and the rest (from valueBalance on)."""
    b = bytes.fromhex(hex_tx)
    assert b[0:4] == (0x80000004).to_bytes(4, 'little'), 'a v4 transaction'
    n, at = read_compact(b, 8)
    vin = []
    for _ in range(n):
        prevout = b[at:at + 36]
        size, at = read_compact(b, at + 36)
        vin.append([prevout, b[at:at + size], b[at + size:at + size + 4]])
        at += size + 4
    n, at = read_compact(b, at)
    vout = []
    for _ in range(n):
        value = b[at:at + 8]
        size, at = read_compact(b, at + 8)
        vout.append([value, b[at:at + size]])
        at += size
    return {'header': b[0:8], 'vin': vin, 'vout': vout, 'times': b[at:at + 8], 'rest': b[at + 8:]}


def serialize_v4(tx):
    b = tx['header'] + compact(len(tx['vin']))
    for prevout, script, seq in tx['vin']:
        b += prevout + compact(len(script)) + script + seq
    b += compact(len(tx['vout']))
    for value, script in tx['vout']:
        b += value + compact(len(script)) + script
    return (b + tx['times'] + tx['rest']).hex()


def without_sapling(hex_tx):
    """The transaction with no Sapling parts: valueBalance 0, no spends, no outputs, no
    JoinSplits, no binding signature."""
    tx = parse_v4(hex_tx)
    tx['rest'] = (0).to_bytes(8, 'little') + b'\x00\x00\x00'
    return serialize_v4(tx)


def with_script_sig(hex_tx, n, script_sig):
    tx = parse_v4(hex_tx)
    tx['vin'][n][1] = script_sig
    return serialize_v4(tx)


def flip_script_sig_byte(hex_tx, n, offset=10):
    tx = parse_v4(hex_tx)
    script = bytearray(tx['vin'][n][1])
    script[offset] ^= 0x01
    tx['vin'][n][1] = bytes(script)
    return serialize_v4(tx)


def flip_from_end(hex_tx, offset):
    b = bytearray.fromhex(hex_tx)
    b[len(b) - offset] ^= 0x01
    return b.hex()


class Recorder(r1.Recorder):
    """`a` is the ycash6 wallet node that builds and mines; `b` the ycash-dd follower."""

    def __init__(self, args, a, b):
        super().__init__(args, a, b)
        self.rejects = []

    def mine(self, n=1):
        hashes = self.a.ok('generate', n)
        tip = hashes[-1]
        r1.wait(lambda: self.b.ok('getbestblockhash') == tip, 'ycash-dd to follow ' + tip)
        # ycash6's wallet sees a block asynchronously: wait until it holds the tip's coinbase,
        # so the next build does not pick a coin the block spent.
        coinbase = self.a.ok('getblock', tip)['tx'][0]
        r1.wait(lambda: self.a.ok('gettransaction', coinbase)['confirmations'] >= 1,
                'the wallet to see block ' + tip)
        return hashes

    def submit(self, name, txid_or_hex, pq_inputs, built_by, vault_inputs=()):
        txid = super().submit(name, txid_or_hex, pq_inputs, built_by)
        self.shapes[name]['vaultInputs'] = list(vault_inputs)
        return txid

    def offer(self, name, of, hex_tx, what):
        """Both C++ mempools must refuse `hex_tx`; their answers are recorded."""
        answers = {}
        for node, line in ((self.a, 'ycash6'), (self.b, 'ycash-dd')):
            result, error = node.call('sendrawtransaction', hex_tx)
            if error is None:
                raise r1.RpcError('%s accepted the %s variant %s: %s' % (line, of, name, result))
            answers[line] = {'code': error['code'], 'message': error['message']}
        self.rejects.append({'name': name, 'of': of, 'what': what, 'hex': hex_tx,
                             'tip': self.a.ok('getblockcount'), 'cxx': answers})
        print('  reject %-30s ycash6 %r, ycash-dd %r' % (
            name, answers['ycash6']['message'], answers['ycash-dd']['message']))

    def wait_balance(self, address, at_least):
        r1.wait(lambda: self.a.ok('z_getbalance', address, 1) >= at_least,
                'a balance of %s at %s' % (at_least, address))

    def self_note(self, coin, value):
        """A setup transaction: a wallet P2PKH coin to a note of the tool's key."""
        built = self.gen({
            'mode': 'build', 'branchId': int(VAULT_BRANCH_ID, 16), 'lockTime': 0,
            'expiry': self.a.ok('getblockcount') + 20,
            'inputs': [{'txid': coin['txid'], 'vout': coin['vout'], 'sequence': SEQUENCE}],
            'outputs': [], 'saplingOutputs': [{'to': 'self', 'value': value}],
            'saplingSpends': [], 'saplingChain': [],
        })
        txid = self.a.ok('sendrawtransaction', self.sign(built['tx'], [coin]))
        self.mine()
        return txid

    def build(self, inputs, outputs, sapling_spends, sapling_outputs, branch=None):
        return self.gen({
            'mode': 'build', 'branchId': branch or int(VAULT_BRANCH_ID, 16), 'lockTime': 0,
            'expiry': self.a.ok('getblockcount') + 20,
            'inputs': [{'txid': c['txid'], 'vout': c['vout'], 'sequence': SEQUENCE} for c in inputs],
            'outputs': outputs, 'saplingOutputs': sapling_outputs,
            'saplingSpends': [{'txid': t} for t in sapling_spends],
            'saplingChain': self.sapling_chain(),
        })

    def run(self):
        a = self.a
        print('setup: coinbase, shield it into a Sapling address, mine to Vault + 2')
        self.mine(110)
        ys = a.ok('z_getnewaddress', 'sapling')
        # ycash6's wallet sees the mined coinbases asynchronously.
        shield = []
        r1.wait(lambda: shield.append(a.ok('z_shieldcoinbase', '*', ys, Decimal('0.0001'), 50))
                or True, 'the wallet to see the coinbases')
        opid = shield[0]['opid']
        r1.wait(lambda: a.ok('z_getoperationstatus', [opid])[0]['status'] == 'success', 'shielding')
        self.mine(VAULT_HEIGHT + 2 - a.ok('getblockcount'))
        self.wait_balance(ys, 50)
        print('  shielded: %s YEC' % a.ok('z_getbalance', ys))

        print('setup: transparent coins, a set, a vault, the PQ coins of the tool-built shapes')
        taddr = a.ok('getnewaddress')
        self.wait_op(a.ok('z_sendmany', ys, [{'address': taddr, 'amount': 20}], 1, None,
                          'AllowRevealedRecipients'))
        self.mine()
        r1.wait(lambda: a.ok('getbalance') >= 20, 'the transparent funds')
        # A one-seat set whose member key is this wallet's, so the wallet signs the unlock.
        created = a.ok('set_create', {'seats': 1, 'unlockthreshold': 1, 'open': True,
                                      'maturity': 2})
        self.mine()
        a.ok('set_join', created['setid'], 1, a.ok('getblockcount') + 500)
        self.mine(3)
        a.ok('set_heartbeat', created['setid'])
        self.mine()
        locked = a.ok('vault_lock', {'tag': 'TEST', 'setid': created['setid'], 'delay': 5,
                                     'ownerheight': a.ok('getblockcount') + 300, 'amount': 2})
        self.mine()
        vault = {'txid': locked['txid'], 'vout': locked['vout'], 'script': locked['script']}

        slh = a.ok('getnewaddress', '', 'pqslh')
        falcon = a.ok('getnewaddress', '', 'pq')
        slh_b = a.ok('getnewaddress', '', 'pqslh')
        falcon_b = a.ok('getnewaddress', '', 'pq')
        falcon_c = a.ok('getnewaddress', '', 'pq')
        script = {x: a.ok('validateaddress', x)['scriptPubKey']
                  for x in (slh, falcon, slh_b, falcon_b, falcon_c)}
        scheme = {x: a.ok('validateaddress', x)['pqscheme'] for x in script}
        assert scheme[slh] == 1 and scheme[falcon] == 2
        coin = {}
        for x in (slh_b, falcon_b):
            txid = a.ok('sendtoaddress', x, 2)
            self.mine()
            coin[x] = self.coin(txid, script[x])
            # The wallet's own sends (sendtoaddress below) must leave the tool's PQ coins alone.
            assert a.ok('lockunspent', False, [{'txid': coin[x]['txid'], 'vout': coin[x]['vout']}])
        # Three notes of the tool's key, one per tool-built Sapling spend.
        notes = []
        for _ in range(3):
            t = a.ok('getnewaddress')
            txid = a.ok('sendtoaddress', t, 2)
            self.mine()
            p2pkh = self.coin(txid, a.ok('validateaddress', t)['scriptPubKey'])
            notes.append(self.self_note(p2pkh, p2pkh['value'] - FEE))
        note_value = 2 * COIN - 2 * FEE
        self.setup_tip = a.ok('getblockcount')

        print('shapes')
        for name, addr in (('sapling-to-pq-slh', slh), ('sapling-to-pq-falcon', falcon)):
            txid = self.wait_op(a.ok('z_sendmany', ys, [{'address': addr, 'amount': 3}], 1))
            self.submit(name, txid, [], 'ycash6 z_sendmany')
            r1.wait(lambda: a.ok('z_getbalance', addr, 1) >= 3, 'the PQ funds')

        for name, addr, funding in (('pq-slh-to-sapling-pq-change', slh, 'sapling-to-pq-slh'),
                                    ('pq-falcon-to-sapling-pq-change', falcon,
                                     'sapling-to-pq-falcon')):
            spent = self.coin(self.shapes[funding]['txid'], script[addr])
            txid = self.wait_op(a.ok('z_sendmany', addr, [{'address': ys, 'amount': 1}], 1))
            raw = a.ok('getrawtransaction', txid, 1)
            n = next(i for i, v in enumerate(raw['vin'])
                     if v['txid'] == spent['txid'] and v['vout'] == spent['vout'])
            assert any(o['scriptPubKey']['hex'] == script[addr] for o in raw['vout']), \
                'the change returns to the PQ address'
            self.submit(name, txid, [self.pq_input_record(n, spent, scheme[addr])],
                        'ycash6 z_sendmany')

        # An FN-DSA-512 input beside a Sapling spend, Sapling outputs only; and its variants.
        name = 'pq-falcon-and-sapling-to-sapling'
        fc = coin[falcon_b]
        built = self.build([fc], [], [notes[0]],
                           [{'to': 'self', 'value': note_value + fc['value'] - FEE}])
        assert built['anchor'] == a.ok('getblock', a.ok('getbestblockhash'))['finalsaplingroot']
        signed = self.sign(built['tx'], [fc])
        self.offer('bad-pq-signature', name, flip_script_sig_byte(signed, 0),
                   'one byte of the FN-DSA-512 signature flipped')
        bare = self.sign(without_sapling(built['tx']), [fc])
        self.offer('pq-signature-without-sapling', name,
                   with_script_sig(built['tx'], 0, parse_v4(bare)['vin'][0][1]),
                   'the PQ input signed over the digest with the Sapling parts left out')
        self.offer('changed-sapling-output', name, flip_from_end(signed, 64 + 1 + 192 + 40),
                   "one outCiphertext byte of the last Sapling output flipped")
        bad_scheme = '20' + '11' * 32 + '53c2'
        wrong = self.build([], [{'value': COIN, 'script': bad_scheme}], [notes[0]],
                           [{'to': 'self', 'value': note_value - COIN - FEE}])
        self.offer('wrong-scheme-output', name, wrong['tx'],
                   'a Sapling spend paying 0x20 <32 bytes> OP_3 OP_CHECKPQSIG')
        wrong = self.build([], [], [notes[0]], [{'to': 'self', 'value': note_value - FEE}],
                           branch=CANOPY_BRANCH_ID)
        self.offer('wrong-branch-id', name, wrong['tx'],
                   "a Sapling spend signed over the Canopy branch's digest after Vault")
        self.submit(name, signed, [self.pq_input_record(0, fc, 2)],
                    'mixed-shapes-gen + ycash6 signrawtransaction')

        name = 'sapling-and-pq-slh-to-pq-with-pq-change'
        sc = coin[slh_b]
        built = self.build([sc], [{'value': COIN, 'script': script[falcon_c]},
                                  {'value': sc['value'] - COIN, 'script': script[slh_b]}],
                           [notes[1]], [{'to': 'self', 'value': note_value - FEE}])
        self.submit(name, self.sign(built['tx'], [sc]), [self.pq_input_record(0, sc, 1)],
                    'mixed-shapes-gen + ycash6 signrawtransaction')

        name = 'sapling-to-vault-from'
        lock = a.ok('vault_lock', {'tag': 'TEST', 'setid': created['setid'], 'delay': 5,
                                   'ownerheight': a.ok('getblockcount') + 300, 'amount': 1,
                                   'from': ys})
        self.submit(name, lock['txid'], [], 'ycash6 vault_lock from a Sapling address')

        name = 'vault-unlock-beside-sapling'
        unlock = a.ok('vault_buildunlock', '%s:%d' % (vault['txid'], vault['vout']),
                      [{'address': taddr, 'amount': Decimal('0.5')}])
        decoded = a.ok('decoderawtransaction', unlock['hex'])
        keep = [i['vout'] for i in unlock['intents']]
        keep += [o['n'] for o in decoded['vout'] if o['scriptPubKey']['hex'] == vault['script']]
        outputs = [{'value': self.zat(o['value']), 'script': o['scriptPubKey']['hex']}
                   for o in decoded['vout'] if o['n'] in sorted(keep)]
        assert sum(o['value'] for o in outputs) == 2 * COIN, 'intent and re-lock carry the vault'
        vin = next(v for v in decoded['vin'] if v['txid'] == vault['txid'])
        built = self.gen({
            'mode': 'build', 'branchId': int(VAULT_BRANCH_ID, 16), 'lockTime': decoded['locktime'],
            'expiry': a.ok('getblockcount') + 20,
            'inputs': [{'txid': vault['txid'], 'vout': vault['vout'], 'sequence': vin['sequence']}],
            'outputs': outputs, 'saplingOutputs': [{'to': 'self', 'value': note_value - FEE}],
            'saplingSpends': [{'txid': notes[2]}], 'saplingChain': self.sapling_chain(),
        })
        signed = a.ok('set_signunlock', built['tx'])
        assert signed['complete'], signed
        self.offer('vault-unlock-changed-sapling-output', name,
                   flip_from_end(signed['hex'], 64 + 1 + 192 + 40),
                   'one outCiphertext byte of the unlock\'s last Sapling output flipped (the set '
                   'signature, SIGHASH_ALL|ANYONECANPAY, covers the Sapling outputs)')
        self.submit(name, signed['hex'], [], 'mixed-shapes-gen + ycash6 set_signunlock',
                    vault_inputs=[0])
        self.mine()

    def dump(self, path):
        super().dump(path)
        with open(path) as f:
            doc = json.load(f)
        doc['_comment'] = 'Recorded by testdata/mixed-shapes/record2.py; never edit by hand.'
        doc['recordedWith'] = {'ycash6 (wallet, miner)': self.a.ok('getnetworkinfo')['subversion'],
                               'ycash-dd (follower)': self.b.ok('getnetworkinfo')['subversion']}
        doc['rejects'] = self.rejects
        with open(path, 'w') as f:
            json.dump(doc, f, indent=1, sort_keys=True, default=str)
            f.write('\n')


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('--ycash6-bin', required=True)
    p.add_argument('--ycash-dd-bin', required=True)
    p.add_argument('--gen', required=True)
    p.add_argument('--params', default=os.path.expanduser('~/Library/Application Support/ZcashParams'))
    p.add_argument('--workdir')
    p.add_argument('--port-base', type=int, default=24720)
    p.add_argument('--out', default=os.path.join(HERE, 'chain2.json'))
    args = p.parse_args(argv)
    workdir = args.workdir or tempfile.mkdtemp(prefix='mixed-shapes-2-')
    pb = args.port_base
    procs = []
    a = b = None
    try:
        procs.append(r1.start(args.ycash6_bin, workdir, 'ycash6', pb + 1, pb + 2,
                              ['-listen=1', '-acceptnonstdtxn=0', AWARE]))
        procs.append(r1.start(args.ycash_dd_bin, workdir, 'ycash-dd', pb + 3, pb + 4,
                              ['-listen=0', '-acceptnonstdtxn=0',
                               '-connect=127.0.0.1:%d' % (pb + 1)]))
        a, b = r1.Node('ycash6', pb + 2), r1.Node('ycash-dd', pb + 4)
        r1.wait(lambda: a.ok('getblockcount') == 0 and b.ok('getblockcount') == 0, 'the nodes')
        r1.wait(lambda: a.ok('getconnectioncount') == 1, 'the peer connection')
        r = Recorder(args, a, b)
        r.run()
        r.dump(args.out)
    finally:
        # Each node is stopped by its own stop RPC; a signal only if that did not end it.
        for node in (a, b):
            if node is not None:
                try:
                    node.call('stop')
                except OSError:
                    pass
        deadline = time.time() + 60
        for proc in procs:
            while proc.poll() is None and time.time() < deadline:
                time.sleep(0.5)
            r1.stop(proc)
        if not args.workdir:
            shutil.rmtree(workdir, ignore_errors=True)
    return 0


if __name__ == '__main__':
    sys.exit(main())
