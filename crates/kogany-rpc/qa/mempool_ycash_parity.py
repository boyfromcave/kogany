#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""kogany's mempool verdicts against ycash6's, by class, on one Ycash regtest chain (W1-Y9).

    python crates/kogany-rpc/qa/mempool_ycash_parity.py --zakurad <zakurad built with --features ycash> \\
        [--ycash6-bin $WS/wt/.bin/ycash6-65cb4ae0f] [--workdir DIR] [--keep] [--json FILE]

It starts a ycashd and a zakurad on Ycash regtest as `rpc_ycash_parity.py` does (every upgrade
through Canopy at height 1, blocks mined on ycashd and fed to zakurad through `submitblock`), then
offers the same transactions to both nodes through `sendrawtransaction` and asserts that both
answer with the same verdict class (plan §4.2 rule 4 (iii)): `accept`, `reject-consensus`,
`reject-state` or `reject-policy`. Before each block, the two `getrawmempool` sets must be equal.

The transactions are those ycashd's wallet makes by default and the harness scripts' patterns
(`qa/rpc-tests/yellowback_*` / `vault_*` use `sendtoaddress`, `z_sendmany` and raw
transactions): default-fee transparent spends, a ZIP-317-fee spend, a `z_sendmany` Sapling output
and Sapling spend, fees at and below the minimum relay fee, OP_RETURN carriers of 80 and 1,200
bytes, a dust output, a 300 kB transaction and one above the 2 MB consensus limit, expired and
expiring-soon transactions at the boundaries, and non-final ones at the boundary. They run in
three policy modes, each a restart of both nodes:

- `default`: ycashd's regtest default (`-acceptnonstdtxn=1`: no `IsStandardTx`), kogany's
  `mempool.accept_non_standard` unset;
- `standard`: ycashd `-acceptnonstdtxn=0`, kogany `mempool.accept_non_standard = false`;
- `zip317`: ycashd `-txunpaidactionlimit=0`, kogany `mempool.tx_unpaid_action_limit = 0`.

Every rule where Zakura's ZIP-317 mempool and ycashd's pre-Vault relay policy differ is a row of
`ACCEPTED`: `ported` rows are the Ycash rule kogany now applies under `--features ycash` (each
exercised by a case named in the row), `open` rows are differences this chunk leaves, with the
chunk that owns them. A class difference on a case fails the run unless an `open` row names
the case. The table is printed at the end, and with `--json` written as JSON.

Stdlib only; the node plumbing is `rpc_ycash_parity.py`'s.
"""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import rpc_ycash_parity as base  # noqa: E402

ACCEPT = 'accept'
REJECT_CONSENSUS = 'reject-consensus'
REJECT_STATE = 'reject-state'
REJECT_POLICY = 'reject-policy'
UNCLASSIFIED = 'unclassified'

COIN = 100000000
SEQUENCE_FINAL = 0xffffffff
MAX_BLOCK_BYTES = 2000000

# (kind, rule, ycash6 source, Zakura before W1-Y9, kogany with --features ycash, cases)
ACCEPTED = [
    ('ported', 'ZIP-317 unpaid-action limit',
     'zip317.h:26-54 DEFAULT_TX_UNPAID_ACTION_LIMIT = SIZE_MAX; main.cpp:2150-2162',
     'limit 0 at a 400-zatoshi marginal fee (zip317.rs:48): a 244-zatoshi default-fee spend is refused',
     'no limit by default; mempool.tx_unpaid_action_limit (= -txunpaidactionlimit) counts at 500',
     ['default/wallet-default-fee', 'zip317/fee-999', 'zip317/fee-1000', 'zip317/raw-244']),
    ('ported', 'minimum relay fee',
     'main.cpp:2125 minRelayTxFee.GetFeeForRelay; amount.cpp:25-37 (100/kB, min(.., 1000))',
     'clamp(100 * size / 1000, 100, 800) (zip317.rs:189-192)',
     'ycash_relay::min_relay_fee: 100 * size / 1000 (the rate when 0), at most 1,000',
     ['default/min-relay-fee', 'default/below-min-relay-fee', 'default/zero-fee']),
    ('ported', 'per-Sapling-output fee floor',
     'policy/policy.cpp:26-46 PerSaplingOutputFees; main.cpp:2138-2147',
     'none', 'ycash_relay::per_sapling_output_fees in the verifier, before proofs',
     ['default/z_sendmany-t-to-z', 'default/z_sendmany-z-to-t']),
    ('ported', 'standardness on regtest',
     'main.cpp:1979,2070 RequireStandard(); chainparams.cpp:839,991-994 -acceptnonstdtxn',
     'IsStandardTx / AreInputsStandard on every network',
     'skipped on regtest unless mempool.accept_non_standard = false; always on mainnet/testnet',
     ['default/op-return-1200', 'default/dust-output', 'standard/op-return-1200', 'standard/dust-output']),
    ('ported', 'sigop limit without standardness', 'main.cpp:2079-2091 (not gated on RequireStandard)',
     'inside the standardness checks', 'ycash_policy::Policy::check, always',
     ['default/sigops-4000', 'default/sigops-4001']),
    ('ported', 'expiring soon', 'main.cpp:1969-1971 IsExpiringSoonTx (next + 3 > expiry); '
     'rpc/rawtransaction.cpp:1307-1317', 'none: only expired transactions are refused',
     'ycash_policy::Policy::check at the tip, reject-policy',
     ['default/expiry-next+2', 'default/expiry-next+3']),
    ('ported', 'mempool transaction size', 'consensus.h:29-34: no standard size limit below MAX_BLOCK_SIZE',
     'max_transaction_bytes 250,000 (policy)', 'DEFAULT_MAX_TRANSACTION_BYTES = MAX_BLOCK_BYTES',
     ['default/size-300k', 'standard/size-300k']),
    ('open', 'standard script verification flags',
     'main.cpp:2234 STANDARD_SCRIPT_VERIFY_FLAGS (LOW_S, STRICTENC, MINIMALDATA, NULLDUMMY, CLEANSTACK, '
     'DISCOURAGE_UPGRADABLE_NOPS) in every mempool, regtest included',
     'consensus flags only (zakura-script lib.rs:170)', 'unchanged: needs a policy flag set in '
     'zakura-script (W3-c) and its use for Request::Mempool (W6-a); wallet transactions never differ', []),
    ('open', 'absurd fee', 'rpc/rawtransaction.cpp:1346 fRejectAbsurdFee: maxTxFee 0.1 YEC unless allowhighfees',
     'allow_high_fees ignored (methods.rs send_raw_transaction)', 'unchanged: an RPC rule, W7-e', []),
    ('open', 'expiry eviction at the tip', 'txmempool.cpp:785-805 removeExpired(h): expiry < h',
     'storage.rs remove_expired: expiry <= tip', 'unchanged: ycashd keeps a transaction whose expiry is '
     'the tip for one more block, though no block can mine it; W6-c (tip-recheck)', []),
    ('open', 'template selection of low-fee transactions', 'miner.cpp:304 -blockunpaidactionlimit SIZE_MAX',
     'zip317.rs BLOCK_UNPAID_ACTION_LIMIT 0 in getblocktemplate', 'unchanged: kogany accepts a default-fee '
     'spend but its own template may leave it out; W8 (mining)', []),
    ('open', 'reject codes and texts', 'the reject code and reason in the RPC error',
     'Zakura texts, -25/-26/-22', 'unchanged: compared by class (KOGANY_REASON_MAP below); W7-e', []),
]

# ycashd's sendrawtransaction errors -> class (the harness's table: ycash6 qa/rpc-tests/test_framework/
# kogany.py REJECT_CODE_MAP, classify_cxx_tx). "<code>: <reason>" for an ATMP reject.
CXX_REASON_MAP = [
    ('tx-expiring-soon', REJECT_POLICY),
    ('Missing inputs', REJECT_STATE),
    ('non-final', REJECT_POLICY),
    ('bad-txns-inputs-spent', REJECT_STATE),
    ('bad-txns-', REJECT_CONSENSUS),
    ('TX decode failed', REJECT_CONSENSUS),
    ('coinbase', REJECT_CONSENSUS),
]

# kogany's sendrawtransaction errors -> class: the rows this chunk proposes for the harness's
# KOGANY_REASON_MAP (ycash6 qa/rpc-tests/test_framework/kogany.py). (message regex, class, source)
KOGANY_REASON_MAP = [
    (r'transaction is expiring soon', REJECT_POLICY, 'storage.rs NonStandardTransactionError::ExpiringSoon'),
    (r'unpaid actions than the configured limit', REJECT_POLICY, 'NonStandardTransactionError::UnpaidActionLimit'),
    (r'transaction (is dust|has an OP_RETURN|has multiple OP_RETURN|scriptPubKey is non-standard|'
     r'has a bare multisig|has too many signature|has non-standard inputs|scriptSig is)', REJECT_POLICY,
     'storage.rs NonStandardTransactionError'),
    (r'exceeding the configured mempool maximum', REJECT_POLICY, 'NonStandardTransactionError::TransactionTooLarge'),
    (r'ZIP-317 transaction rules', REJECT_POLICY, 'TransactionError::Zip317 (the Ycash fee rules ride it)'),
    (r'mempool transaction input .* (scriptSig|non-push-only)|non-standard inputs', REJECT_POLICY,
     'TransactionError::NonStandard*'),
    (r'(must not be mined until|lock ?time|locked until)', REJECT_POLICY, 'TransactionError::LockedUntilAfter* (non-final)'),
    (r'expired|expiry', REJECT_POLICY, 'TransactionError::ExpiredTransaction (ycashd: tx-expiring-soon at the RPC)'),
    (r'transaction is non-standard', REJECT_POLICY,
     'MempoolError::NonStandardTransaction: every storage-time Ycash and standardness rule'),
    (r'already exists in mempool', ACCEPT, 'MempoolError::InMempool: ycashd\'s sendrawtransaction answers the '
     'txid of a transaction its mempool holds (rawtransaction.cpp:1341-1344), as submitblock\'s duplicate'),
    (r'(Deserializ|deserializ|parse|decode)', REJECT_CONSENSUS, 'LegacyCode::Deserialization (-22)'),
    (r'.', REJECT_CONSENSUS, 'any other verifier error: a consensus rule'),
]


def classify_cxx(error):
    if error is None:
        return ACCEPT, ''
    message = error.get('message', '') if isinstance(error, dict) else str(error)
    head, sep, rest = message.partition(': ')
    if sep and head.isdigit():
        code, reason = int(head), rest.split(',')[0].strip()
        if code in (0x40, 0x41, 0x42, 0x12):
            return REJECT_POLICY, message
    else:
        reason = message.strip()
    for prefix, cls in CXX_REASON_MAP:
        if reason.startswith(prefix):
            return cls, message
    return UNCLASSIFIED, message


def classify_kogany(error):
    if error is None:
        return ACCEPT, ''
    message = error.get('message', '') if isinstance(error, dict) else str(error)
    for pattern, cls, _src in KOGANY_REASON_MAP:
        if re.search(pattern, message):
            return cls, message
    return UNCLASSIFIED, message


# Transaction building: a v4 (Sapling) transaction with transparent parts only, signed by ycashd.

def compact(n):
    if n < 0xfd:
        return bytes([n])
    if n <= 0xffff:
        return b'\xfd' + n.to_bytes(2, 'little')
    if n <= 0xffffffff:
        return b'\xfe' + n.to_bytes(4, 'little')
    return b'\xff' + n.to_bytes(8, 'little')


def serialize(group, vin, vout, lock_time, expiry):
    """vin: (txid display hex, n, sequence); vout: (zatoshis, script bytes)."""
    b = (0x80000004).to_bytes(4, 'little') + group
    b += compact(len(vin))
    for txid, n, seq in vin:
        b += bytes.fromhex(txid)[::-1] + n.to_bytes(4, 'little') + b'\x00' + seq.to_bytes(4, 'little')
    b += compact(len(vout))
    for value, script in vout:
        b += value.to_bytes(8, 'little', signed=True) + compact(len(script)) + script
    b += lock_time.to_bytes(4, 'little') + expiry.to_bytes(4, 'little')
    b += bytes(8) + b'\x00\x00\x00'      # valueBalance 0, no Sapling spends, outputs, JoinSplits
    return b


def op_return(data_len):
    data = bytes([0x5a]) * data_len
    if data_len < 0x4c:
        push = bytes([data_len])
    elif data_len <= 0xff:
        push = b'\x4c' + bytes([data_len])
    else:
        push = b'\x4d' + data_len.to_bytes(2, 'little')
    return b'\x6a' + push + data


def p2sh(i):
    return b'\xa9\x14' + i.to_bytes(20, 'little') + b'\x87'


class Chain:
    """The common chain: mining on ycashd, feeding kogany, and the wallet's coins."""

    def __init__(self, y, z):
        self.y, self.z = y, z
        self.used = set()
        self.group = None
        self.change_script = None

    def tip(self):
        return self.y.ok('getblockcount')

    def mine(self, n=1):
        for h in self.y.ok('generate', n):
            res = self.z.ok('submitblock', self.y.ok('getblock', h, 0))
            if res is not None:
                raise base.RpcError('kogany refused block %s: %r' % (h, res))
        want = self.y.ok('getbestblockhash')
        deadline = time.time() + 60
        while self.z.ok('getbestblockhash') != want:
            if time.time() > deadline:
                raise base.RpcError('kogany tip is not %s' % want)
            time.sleep(0.2)

    def catch_up(self, timeout=120):
        """After a restart kogany may come back at an earlier tip (its non-finalized blocks are
        in memory): feed it ycashd's blocks above its tip."""
        deadline = time.time() + timeout
        while True:
            have, want = self.z.ok('getblockcount'), self.tip()
            if self.z.ok('getbestblockhash') == self.y.ok('getbestblockhash'):
                return
            for h in range(have + 1, want + 1):
                self.z.call('submitblock', self.y.ok('getblock', self.y.ok('getblockhash', h), 0))
            if time.time() > deadline:
                raise base.RpcError('kogany stays at %d below ycashd %d' % (have, want))
            time.sleep(0.5)

    def coin(self):
        """A mature, unused transparent coin of ycashd's wallet: (txid, n, zatoshis)."""
        for u in sorted(self.y.ok('listunspent', 101), key=lambda u: (-u['confirmations'], u['txid'], u['vout'])):
            key = (u['txid'], u['vout'])
            if key in self.used or not u['spendable'] or u['amount'] < 1:
                continue
            if self.y.ok('gettxout', u['txid'], u['vout'], True) is None:
                continue
            self.used.add(key)
            return u['txid'], u['vout'], int(round(u['amount'] * COIN))
        raise base.RpcError('ycash6 wallet has no unused mature coin left')

    def build(self, outputs, fee, lock_time=0, expiry=None, sequence=SEQUENCE_FINAL, coin=None):
        """Spend one coin to `outputs` plus change to the wallet. `fee` is zatoshis, or a function
        of the signed size. Returns the signed hex."""
        txid, n, value = coin or self.coin()
        if expiry is None:
            expiry = self.tip() + 1 + 20
        fee_of = fee if callable(fee) else (lambda _size, f=fee: f)
        size, signed = 0, None
        for _ in range(4):
            f = fee_of(size)
            change = value - sum(v for v, _ in outputs) - f
            raw = serialize(self.group, [(txid, n, sequence)], list(outputs) + [(change, self.change_script)],
                            lock_time, expiry)
            res = self.y.ok('signrawtransaction', raw.hex())
            if not res.get('complete'):
                raise base.RpcError('ycash6 could not sign: %r' % res.get('errors'))
            signed = res['hex']
            if len(signed) // 2 == size or not callable(fee):
                break
            size = len(signed) // 2
        if callable(fee) and fee_of(len(signed) // 2) != fee_of(size):
            raise base.RpcError('the fee did not settle on the signed size')
        return signed


class Verdicts:
    def __init__(self):
        self.rows = []   # (case, ycash6 class, kogany class, expected, ycash6 message, kogany message, ok, why)

    def offer(self, chain, case, hexdata, expect=None):
        ry = chain.y.call('sendrawtransaction', hexdata)
        rz = chain.z.call('sendrawtransaction', hexdata)
        self.record(case, ry[1], rz[1], expect)
        return ry, rz

    def record(self, case, ey, ez, expect=None):
        cy, my = classify_cxx(ey)
        cz, mz = classify_kogany(ez)
        ok, why = cy == cz and cy != UNCLASSIFIED, ''
        if not ok:
            for kind, rule, _s, _z, _k, cases in ACCEPTED:
                if kind == 'open' and case in cases:
                    ok, why = True, 'open: ' + rule
        if expect is not None and cy != expect:
            ok, why = False, 'ycash6 answered %s where the case expects %s' % (cy, expect)
        self.rows.append((case, cy, cz, expect, my, mz, ok, why))
        print('%-36s ycash6 %-17s kogany %-17s %s%s' % (case, cy, cz, 'ok' if ok else 'FAIL',
              ('  (' + why + ')') if why else ''))
        if not ok:
            print('    ycash6: %s\n    kogany: %s' % (my or '-', mz or '-'))

    def failures(self):
        return [r for r in self.rows if not r[6]]


def mempool_point(chain, verdicts, label):
    a, b = set(chain.y.ok('getrawmempool')), set(chain.z.ok('getrawmempool'))
    ok = a == b
    verdicts.rows.append(('%s/mempool-set' % label, 'equal' if ok else 'differ', '', None,
                          sorted(a - b), sorted(b - a), ok, ''))
    print('%-36s %s (%d transactions)%s' % ('%s/mempool-set' % label, 'equal' if ok else 'DIFFER', len(a),
          '' if ok else '  only ycash6 %s, only kogany %s' % (sorted(a - b), sorted(b - a))))


def wait_until(predicate, what, timeout=60):
    """ycashd's wallet sees a block a moment after `generate` returns."""
    deadline = time.time() + timeout
    while not predicate():
        if time.time() > deadline:
            raise base.RpcError('ycash6 wallet: %s did not appear' % what)
        time.sleep(0.5)


def wait_operation(y, opid, timeout=300):
    deadline = time.time() + timeout
    while time.time() < deadline:
        for op in y.ok('z_getoperationresult', [opid]):
            if op['status'] == 'success':
                return op['result']['txid']
            if op['status'] in ('failed', 'cancelled'):
                raise base.RpcError('z_sendmany failed: %r' % op.get('error'))
        time.sleep(0.5)
    raise base.RpcError('z_sendmany did not finish')


# The cases, one function per mode.

def cases_common(chain, v, mode):
    """The cases every mode runs: the spends the wallet makes, the fee and size boundaries,
    OP_RETURN, dust, expiry and finality."""
    tip = chain.tip()
    nxt = tip + 1
    min_fee = lambda size: min(size * 100 // 1000 or 100, 1000)  # noqa: E731  GetFeeForRelay
    zip317 = mode == 'zip317'
    pay = chain.y.ok('validateaddress', chain.y.ok('getnewaddress'))['scriptPubKey']
    pay = bytes.fromhex(pay)

    if not zip317:
        # The wallet's default-fee spend (244 zatoshis at 1,000/kB): kogany's ZIP-317 mempool refused it.
        txid = chain.y.ok('sendtoaddress', chain.y.ok('getnewaddress'), 1.5)
        raw = chain.y.ok('getrawtransaction', txid, 0)
        for vin in chain.y.ok('getrawtransaction', txid, 1)['vin']:
            chain.used.add((vin['txid'], vin['vout']))
        ez = chain.z.call('sendrawtransaction', raw)[1]
        v.record('%s/wallet-default-fee' % mode, None, ez, ACCEPT)
    else:
        v.offer(chain, '%s/raw-244' % mode, chain.build([(COIN, pay)], 244), REJECT_POLICY)
        v.offer(chain, '%s/fee-999' % mode, chain.build([(COIN, pay)], 999), REJECT_POLICY)
        v.offer(chain, '%s/fee-1000' % mode, chain.build([(COIN, pay)], 1000), ACCEPT)

    # The ZIP-317 fee (10,000 zatoshis for 2 actions at 5,000): accepted by both.
    v.offer(chain, '%s/zip317-fee' % mode, chain.build([(COIN, pay)], 10000), ACCEPT)
    if not zip317:
        v.offer(chain, '%s/min-relay-fee' % mode, chain.build([(COIN, pay)], min_fee), ACCEPT)
        v.offer(chain, '%s/below-min-relay-fee' % mode,
                chain.build([(COIN, pay)], lambda s: min_fee(s) - 1), REJECT_POLICY)
        v.offer(chain, '%s/zero-fee' % mode, chain.build([(COIN, pay)], 0), REJECT_POLICY)

    # Under -txunpaidactionlimit=0 a 1,000-zatoshi fee pays two actions: the larger cases below
    # are refused by both for their unpaid actions, so only the class equality is asserted.
    big = None if zip317 else ACCEPT
    v.offer(chain, '%s/op-return-80' % mode, chain.build([(0, op_return(80))], 1000), big)
    v.offer(chain, '%s/op-return-1200' % mode, chain.build([(0, op_return(1200))], 1000),
            REJECT_POLICY if mode == 'standard' else big)
    v.offer(chain, '%s/dust-output' % mode, chain.build([(53, pay)], 1000),
            REJECT_POLICY if mode == 'standard' else ACCEPT)
    v.offer(chain, '%s/not-dust-output' % mode, chain.build([(54, pay)], 1000), ACCEPT)
    v.offer(chain, '%s/two-op-returns' % mode, chain.build([(0, op_return(10)), (0, op_return(10))], 1000),
            REJECT_POLICY if mode == 'standard' else big)

    # Sizes: 300 kB of P2SH outputs (no sigops, not dust) is standard on ycashd; above 2 MB is
    # invalid (bad-txns-oversize, or not decodable).
    n300 = 300000 // 32
    v.offer(chain, '%s/size-300k' % mode, chain.build([(60, p2sh(i)) for i in range(n300)], 100000), big)
    if mode == 'default':
        n2m = (MAX_BLOCK_BYTES + 40) // 32 + 1
        v.offer(chain, '%s/size-above-2mb' % mode, chain.build([(60, p2sh(i)) for i in range(n2m)], 100000),
                REJECT_CONSENSUS)

    # The sigop limit (MAX_STANDARD_TX_SIGOPS 4,000) holds without standardness too: a bare
    # OP_CHECKSIG run beside the P2PKH change (one sigop).
    if mode == 'default':
        v.offer(chain, '%s/sigops-4000' % mode, chain.build([(0, b'\xac' * 3999)], 1000), ACCEPT)
        v.offer(chain, '%s/sigops-4001' % mode, chain.build([(0, b'\xac' * 4000)], 1000), REJECT_POLICY)

    # Expiry at the tip (next + 3 > expiry refuses): expired, expiring soon, the first accepted.
    v.offer(chain, '%s/expiry-tip' % mode, chain.build([(COIN, pay)], 1000, expiry=tip), REJECT_POLICY)
    v.offer(chain, '%s/expiry-next+2' % mode, chain.build([(COIN, pay)], 1000, expiry=nxt + 2), REJECT_POLICY)
    v.offer(chain, '%s/expiry-next+3' % mode, chain.build([(COIN, pay)], 1000, expiry=nxt + 3), ACCEPT)

    # Finality: a height lock time below the next height is final; at the next height it is not.
    seq = SEQUENCE_FINAL - 1
    v.offer(chain, '%s/locktime-next' % mode, chain.build([(COIN, pay)], 1000, lock_time=nxt, sequence=seq),
            REJECT_POLICY)
    v.offer(chain, '%s/locktime-tip' % mode, chain.build([(COIN, pay)], 1000, lock_time=tip, sequence=seq),
            ACCEPT)
    v.offer(chain, '%s/locktime-next-final-seq' % mode,
            chain.build([(COIN, pay)], 1000, lock_time=nxt + 50, sequence=SEQUENCE_FINAL), ACCEPT)

    # A repeat of an accepted transaction: already in both mempools.
    again = chain.build([(COIN, pay)], 1000)
    v.offer(chain, '%s/accepted' % mode, again, ACCEPT)
    v.offer(chain, '%s/repeat' % mode, again, ACCEPT)


def cases_sapling(chain, v):
    """z_sendmany with the wallet's default fee: a Sapling output (t to z), then a Sapling spend
    (z to t). ycashd's wallet sends each to its own mempool; kogany is offered the same bytes."""
    y, z = chain.y, chain.z
    taddr = y.ok('getnewaddress')
    zaddr = y.ok('z_getnewaddress', 'sapling')
    txid = y.ok('sendtoaddress', taddr, 5)
    for vin in y.ok('getrawtransaction', txid, 1)['vin']:
        chain.used.add((vin['txid'], vin['vout']))
    z.call('sendrawtransaction', y.ok('getrawtransaction', txid, 0))
    chain.mine()
    wait_until(lambda: y.ok('z_getbalance', taddr, 1) >= 5, 'the funded address')
    txid = wait_operation(y, y.ok('z_sendmany', taddr, [{'address': zaddr, 'amount': 4}], 1, None))
    v.record('default/z_sendmany-t-to-z', None,
             z.call('sendrawtransaction', y.ok('getrawtransaction', txid, 0))[1], ACCEPT)
    mempool_point(chain, v, 'default/sapling-1')
    chain.mine()
    wait_until(lambda: y.ok('z_getbalance', zaddr, 1) >= 4, 'the Sapling note')
    txid = wait_operation(y, y.ok('z_sendmany', zaddr, [{'address': y.ok('getnewaddress'), 'amount': 1}],
                                  1, None, 'AllowRevealedRecipients'))
    v.record('default/z_sendmany-z-to-t', None,
             z.call('sendrawtransaction', y.ok('getrawtransaction', txid, 0))[1], ACCEPT)
    mempool_point(chain, v, 'default/sapling-2')
    chain.mine()


MODES = {
    'default': ([], []),
    'standard': (['-acceptnonstdtxn=0'], ['accept_non_standard = false']),
    'zip317': (['-txunpaidactionlimit=0'], ['tx_unpaid_action_limit = 0']),
}


def start_ycashd(bindir, workdir, port, rpcport, mineraddress, extra):
    datadir = os.path.join(workdir, 'ycashd')
    os.makedirs(datadir, exist_ok=True)
    with open(os.path.join(datadir, 'ycash.conf'), 'w') as f:
        f.write('regtest=1\nshowmetrics=0\nrpcuser=u\nrpcpassword=p\nport=%d\nrpcport=%d\nlistenonion=0\n'
                % (port, rpcport))
    args = [os.path.join(bindir, 'ycashd'), '-datadir=' + datadir, '-discover=0', '-listen=0', '-txindex',
            '-experimentalfeatures', '-i-am-aware-zcashd-will-be-replaced-by-zebrad-and-zallet-in-2025']
    args += ['-nuparams=%s:1' % b for b in base.NUPARAMS]
    if mineraddress:
        args.append('-mineraddress=' + mineraddress)
    args += extra
    log = open(os.path.join(workdir, 'ycashd.out'), 'a')
    return subprocess.Popen(args, stdout=log, stderr=subprocess.STDOUT)


def kogany_toml(workdir, base_port, miner, extra):
    toml = base.zakurad_toml(workdir, base_port + 10, base_port + 11, base_port + 12, miner)
    marker = '[mempool]\ndebug_enable_at_height = 0\n'
    assert marker in toml
    return toml.replace(marker, marker + ''.join(line + '\n' for line in extra))


def run(args):
    v = Verdicts()
    workdir = args.workdir or tempfile.mkdtemp(prefix='mempool-ycash-parity-')
    os.makedirs(workdir, exist_ok=True)
    p = args.port_base
    y = base.Node('ycash6', p + 1, 'u:p')
    z = base.Node('kogany', p + 11)
    procs = {}
    try:
        procs['y'] = start_ycashd(args.ycash6_bin, workdir, p, p + 1, None, [])
        base.wait_up(y, procs['y'], 'ycashd')
        miner = y.ok('getnewaddress')
        chain = Chain(y, z)
        first = True
        for mode in args.modes:
            yextra, zextra = MODES[mode]
            for k in list(procs):
                base.stop(procs.pop(k))
            procs['y'] = start_ycashd(args.ycash6_bin, workdir, p, p + 1, miner, yextra)
            base.wait_up(y, procs['y'], 'ycashd')
            procs['z'] = base.start_zakurad(args.zakurad, workdir, kogany_toml(workdir, p, miner, zextra))
            base.wait_up(z, procs['z'], 'zakurad')
            print('\n== mode %s: ycashd %s, kogany [mempool] %s' % (mode, yextra or '(defaults)', zextra or '(defaults)'))
            chain.catch_up()
            if first:
                chain.mine(1)
                chain.mine(200)
                base.wait_balance(y, 100)
                raw = y.ok('getrawtransaction', y.ok('getblock', y.ok('getblockhash', 1), 1)['tx'][0], 0)
                chain.group = bytes.fromhex(raw)[4:8]
                chain.change_script = bytes.fromhex(y.ok('validateaddress', miner)['scriptPubKey'])
                first = False
            else:
                chain.mine(1)
            # The restart empties neither mempool of transactions only one holds: mined above.
            mempool_point(chain, v, '%s/start' % mode)
            cases_common(chain, v, mode)
            mempool_point(chain, v, mode)
            chain.mine()
            mempool_point(chain, v, '%s/after-block' % mode)
            if mode == 'default' and not args.no_sapling:
                cases_sapling(chain, v)
    finally:
        for k in list(procs):
            base.stop(procs.pop(k))
        if not args.keep and not args.workdir:
            shutil.rmtree(workdir, ignore_errors=True)
    return v, workdir


def print_accepted():
    print('\nWhere Zakura\'s ZIP-317 mempool and ycashd\'s pre-Vault policy differ (ACCEPTED):')
    for kind, rule, src, zak, kog, cases in ACCEPTED:
        print('- [%s] %s\n    ycash6:  %s\n    Zakura:  %s\n    kogany:  %s%s'
              % (kind, rule, src, zak, kog, ('\n    cases:   ' + ', '.join(cases)) if cases else ''))


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    ap.add_argument('--zakurad', default=os.getenv('KOGANY_BIN'), help='zakurad built with --features ycash')
    ap.add_argument('--ycash6-bin', default=base.DEFAULT_YCASH6_BIN, help='directory holding ycashd')
    ap.add_argument('--workdir', help='keep the datadirs here (default: a temporary directory)')
    ap.add_argument('--keep', action='store_true', help='keep the temporary directory')
    ap.add_argument('--port-base', type=int, default=28700)
    ap.add_argument('--modes', default='default,standard,zip317', help='comma-separated: ' + ', '.join(MODES))
    ap.add_argument('--no-sapling', action='store_true', help='skip the z_sendmany cases')
    ap.add_argument('--json', help='write the verdict table here')
    args = ap.parse_args(argv)
    args.modes = [m for m in args.modes.split(',') if m]
    if not args.zakurad:
        ap.error('--zakurad (or KOGANY_BIN) is required')
    if any(m not in MODES for m in args.modes):
        ap.error('unknown mode in %r' % args.modes)
    try:
        v, _ = run(args)
    except base.RpcError as e:
        print('mempool_ycash_parity: %s' % e, file=sys.stderr)
        return 2
    print_accepted()
    fails = v.failures()
    print('\n%d verdicts and mempool points compared, %d failing' % (len(v.rows), len(fails)))
    if args.json:
        with open(args.json, 'w') as f:
            json.dump({'verdicts': [dict(zip(('case', 'ycash6', 'kogany', 'expected', 'ycash6_message',
                                              'kogany_message', 'ok', 'why'), r)) for r in v.rows],
                       'accepted': [dict(zip(('kind', 'rule', 'ycash6', 'zakura', 'kogany', 'cases'), a))
                                    for a in ACCEPTED],
                       'kogany_reason_map': [dict(zip(('pattern', 'class', 'source'), r)) for r in KOGANY_REASON_MAP]},
                      f, indent=1, sort_keys=True)
    return 1 if fails else 0


if __name__ == '__main__':
    sys.exit(main())
