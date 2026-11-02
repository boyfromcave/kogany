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
- `zip317`: ycashd `-txunpaidactionlimit=0`, kogany `mempool.tx_unpaid_action_limit = 0`;
- `vault` (W6-a): a second chain with the Vault upgrade at height 1 on both nodes (ycashd
  `-nuparams=6d5b7a31:1`, kogany `Vault = 1`) and standardness on (`-acceptnonstdtxn=0`,
  `accept_non_standard = false`). It exercises each Vault-era relay rule at its boundary: the
  83-byte carrier for other `OP_RETURN`s, the 1,200-byte `YV` act carrier, TX_PQPKH outputs at
  the PQ dust threshold, scheme-2 outputs before Falcon, real acts (`set_create`, `set_join`), a
  V (`vault_lock`) and its SLH-DSA owner spend (`vault_ownerspend`, ~8 kB), and the PQ input
  rules on dummy spends (the `s + p + 2` push count, the 9,000-byte scriptSig bound, the
  template selector shapes). A dummy spend at the boundary fails its script (reject-consensus
  on both) and one past it fails standardness first (reject-policy on both).
- `tip` (W6-c): a third chain with the Vault upgrade at height 1 and ycashd's miner limited to
  fully paid transactions (`-blockunpaidactionlimit=0`), for what happens to the mempool after
  admission when the tip moves: admit, mine or invalidate on both nodes, compare the sets. A
  low-fee transaction expiring at height E stays in both mempools at tip E and leaves both at
  E + 1 (ycashd's `removeExpired`); two `SET_JOIN`s for the last seat of an open set are both
  admitted, the block mines one, and the re-check at the new tip evicts the other on both nodes
  (`vault::RecheckMempool`, `bad-vault-act-seats`); a BIP68 spend admitted for the next block
  leaves both mempools when `invalidateblock` drops the tip below its lock (`removeForReorg`'s
  `CheckSequenceLocks`, kogany's re-verification after the reset); and a spend failing only its
  coin's `OP_CHECKLOCKTIMEVERIFY` is policy on both (ycashd's mempool retry drops
  `STANDARD_NOT_MANDATORY_VERIFY_FLAGS`, CLTV included; W6-a finding F-4).

Every mode also offers a P2PKH spend whose public key is pushed non-minimally: valid in a block,
refused by `STANDARD_SCRIPT_VERIFY_FLAGS` (`MINIMALDATA`) in every mempool, regtest included.

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
    ('ported', 'standard script verification flags',
     'main.cpp:2234 STANDARD_SCRIPT_VERIFY_FLAGS (LOW_S, STRICTENC, MINIMALDATA, NULLDUMMY, CLEANSTACK, '
     'DISCOURAGE_UPGRADABLE_NOPS) in every mempool, regtest included',
     'consensus flags only (zakura-script lib.rs:170)',
     'W6-a: zakura_script::ScriptContext::with_standard_policy in the mempool storage '
     '(ycash_standard::standard_script_check), non-mandatory-script-verify-flag',
     ['default/scriptsig-non-minimal', 'standard/scriptsig-non-minimal', 'zip317/scriptsig-non-minimal',
      'vault/scriptsig-non-minimal']),
    ('ported', 'the YV act carrier from Vault',
     'policy/policy.cpp IsStandardTx: vault::IsActOutput && size <= MAX_VAULT_ACT_BYTES (1,200) where '
     'UPGRADE_VAULT is active; other OP_RETURNs keep -datacarriersize (83)',
     'max_datacarrier_bytes 83 for every OP_RETURN',
     'W6-a: ycash_standard::is_standard_tx, in the verifier pre-check and the storage',
     ['vault/op-return-83', 'vault/op-return-84', 'vault/act-1200-badsig', 'vault/act-1201',
      'vault/set_create', 'vault/set_join']),
    ('ported', 'PQ and template outputs from Vault, Falcon outputs from the Falcon height, PQ dust',
     'policy/policy.cpp IsStandardTx: TX_VAULT/TX_VAULT_INTENT/TX_PQPKH/TX_PQCHANNEL only where Vault is '
     'active, scheme 2 only once Falcon is (A-1); GetPQDustThreshold (review A F8)',
     'none: V, I, TX_PQPKH and TX_PQCHANNEL are non-standard scriptPubKeys',
     'W6-a: ycash_standard::{solver, is_standard_tx, pq_dust_threshold}',
     ['vault/pqpkh-dust', 'vault/pqpkh-at-dust-threshold', 'vault/pqpkh-falcon-output', 'vault/vault_lock']),
    ('ported', 'PQ and template input standardness, the 9,000-byte PQ scriptSig',
     'policy/policy.cpp AreInputsStandard: s + p + 2 TX_PQPKH pushes (A-14), TX_PQCHANNEL s + p + 3/4, '
     'IsStandardTemplateScriptSig (01/V-4), MAX_STANDARD_PQ_SCRIPTSIG from Vault (F-6)',
     'solver kinds only; a 1,650-byte scriptSig bound; PQ prevouts non-standard',
     'W6-a: ycash_standard::{are_inputs_standard, mempool_standard_checks} before scripts',
     ['vault/pqpkh-spend-exact', 'vault/pqpkh-spend-extra-push', 'vault/pqpkh-spend-falcon-shape',
      'vault/v-owner-9000', 'vault/v-owner-9001', 'vault/v-owner-extra-push', 'vault/v-app-junk',
      'vault/v-no-selector', 'vault/vault_ownerspend']),
    ('open', 'output standardness before scripts',
     'main.cpp AcceptToMemoryPool: IsStandardTx (outputs included) before ContextualCheckInputs',
     'the verifier pre-checks inputs only; output rules run in the mempool storage, after scripts',
     'unchanged (W6-a finding F-3): a transaction with a non-standard output and a failing script is '
     'reject-policy on ycashd, reject-consensus on kogany; moving the output rules into the verifier '
     'breaks upstream verifier tests whose mock outputs are non-standard', []),
    ('ported', 'CHECKLOCKTIMEVERIFY failures in the mempool',
     'main.cpp ContextualCheckInputs: the retry drops STANDARD_NOT_MANDATORY_VERIFY_FLAGS, CLTV included, '
     'so a CLTV failure is non-mandatory-script-verify-flag (reject-policy)',
     'CLTV is a consensus flag of every script check',
     'W6-c (W6-a finding F-4): vault_mempool::non_mandatory_script_failure retries the first failing input '
     'with ScriptContext::with_mempool_mandatory_flags (no CLTV): TransactionError::NonMandatoryScriptFlag',
     ['tip/cltv-fails']),
    ('open', 'absurd fee', 'rpc/rawtransaction.cpp:1346 fRejectAbsurdFee: maxTxFee 0.1 YEC unless allowhighfees',
     'allow_high_fees ignored (methods.rs send_raw_transaction)', 'unchanged: an RPC rule, W7-e', []),
    ('ported', 'expiry eviction at the tip', 'txmempool.cpp:785-805 removeExpired(h): expiry < h',
     'storage.rs remove_expired: expiry <= tip', 'W6-c: storage.rs remove_expired keeps a transaction whose '
     'expiry is the tip for one more block (ycash); the template\'s FullTransactions leaves it out',
     ['tip/expiry-at-tip/mempool-set', 'tip/expiry-past-tip/mempool-set']),
    ('open', 'expiry at the tip across a reset', 'txmempool.cpp removeExpired(h) after a reorg: expiry < h',
     'a Reset re-verifies every stored transaction for tip + 1 (retry_after_tip_reset)',
     'unchanged (W6-c finding F-2): after a reorg, or several blocks between two mempool polls, kogany '
     'refuses a stored transaction whose expiry is the new tip one block before ycashd drops it; no block '
     'can mine it either way', []),
    ('ported', 'the re-check after the tip grows', 'main.cpp ConnectTip: RemoveInvalidVaultSpends, '
     'vault::RecheckMempool(tip + 1) (CheckTx and the template scripts at the new set state)',
     'nothing re-checks a stored transaction on Grow (mempool.rs TipAction::Grow)',
     'W6-c: mempool::tip_recheck re-verifies the vault-relevant transactions and sweeps the YED check; '
     'the failures are evicted with their descendants',
     ['tip/join-2/mempool-set', 'tip/join-after-block/mempool-set']),
    ('ported', 'BIP68 eviction on a reorg', 'txmempool.cpp removeForReorg: CheckSequenceLocks at the new tip',
     'no BIP68', 'W3-d + W6-c: a Reset re-verifies every transaction at the new height',
     ['tip/bip68-admitted/mempool-set', 'tip/bip68-after-invalidate/mempool-set']),
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
    ('mandatory-script-verify-flag-failed', REJECT_CONSENSUS),
    ('bad-vault-', REJECT_CONSENSUS),
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
    (r'mempool transaction input .* (scriptSig|non-push-only)|non-standard (transparent )?inputs|'
     r'mempool transaction is non-standard', REJECT_POLICY, 'TransactionError::NonStandard* (W6-a: the verifier\'s '
     'ycash_standard pre-check, before scripts)'),
    (r'non-mandatory-script-verify-flag', REJECT_POLICY,
     'NonStandardTransactionError::NonMandatoryScriptVerifyFlag (W6-a: STANDARD_SCRIPT_VERIFY_FLAGS)'),
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


def push(data):
    """A minimal push of `data` (`CScript << valtype`)."""
    n = len(data)
    if n < 0x4c:
        return bytes([n]) + data
    if n <= 0xff:
        return b'\x4c' + bytes([n]) + data
    return b'\x4d' + n.to_bytes(2, 'little') + data


def op_n(n):
    return bytes([0x50 + n])


def act_carrier(total_len):
    """A `YV`-prefixed OP_RETURN of `total_len` bytes (a PUSHDATA2 push): an act carrier, not
    a decodable act."""
    return b'\x6a' + push(b'YV' + b'\x00' * (total_len - 4 - 2))


# The post-quantum schemes (kogany-pq): (signature with its hash-type byte, public key).
PQ_SIZES = {1: (7856 + 1, 32), 2: (666 + 1, 897)}
MAX_CHUNK = 520


def pqpkh(scheme, key_hash):
    return b'\x20' + key_hash + op_n(scheme) + b'\xc2'


def pq_args(scheme, extra_pushes=0):
    """`<sig chunks> <s> <pk chunks> <p>` with dummy bytes of the scheme's sizes."""
    sig_len, pk_len = PQ_SIZES[scheme]
    out, s = b'', 0
    for i in range(0, sig_len, MAX_CHUNK):
        out += push(b'\x5a' * min(MAX_CHUNK, sig_len - i))
        s += 1
    out += op_n(s)
    p = 0
    for i in range(0, pk_len, MAX_CHUNK):
        out += push(b'\x6b' * min(MAX_CHUNK, pk_len - i))
        p += 1
    out += op_n(p) + push(b'\x07') * extra_pushes
    return out


def fee_at_rate(rate, size):
    """`CFeeRate(rate).GetFee(size)`."""
    fee = rate * size // 1000
    return rate if fee == 0 and rate > 0 else fee


def pq_spend_input_size(scheme):
    """`PQSpendInputSize`: outpoint, sequence, the compact size and the chunked scriptSig."""
    return 40 + 3 + len(pq_args(scheme))


def pq_dust_threshold(script):
    """`GetPQDustThreshold` of a TX_PQPKH output (value, compact size, script, the PQ spend)."""
    return 3 * fee_at_rate(100, 8 + 1 + len(script) + pq_spend_input_size(script[33] - 0x50))


def serialize_spend(group, vin, vout, lock_time, expiry):
    """As `serialize`, with each input's scriptSig given: vin is (txid, n, sequence, script)."""
    b = (0x80000004).to_bytes(4, 'little') + group
    b += compact(len(vin))
    for txid, n, seq, script in vin:
        b += bytes.fromhex(txid)[::-1] + n.to_bytes(4, 'little') + compact(len(script)) + script
        b += seq.to_bytes(4, 'little')
    b += compact(len(vout))
    for value, script in vout:
        b += value.to_bytes(8, 'little', signed=True) + compact(len(script)) + script
    b += lock_time.to_bytes(4, 'little') + expiry.to_bytes(4, 'little')
    b += bytes(8) + b'\x00\x00\x00'
    return b


def first_script_sig(raw):
    """(offset, length) of input 0's scriptSig in a one-byte-count transaction from `serialize`."""
    at = 4 + 4 + 1 + 36
    n = raw[at]
    assert n < 0xfd, 'a P2PKH scriptSig is short'
    return at + 1, n


def with_script_sig(raw, script):
    off, n = first_script_sig(raw)
    return raw[:off - 1] + compact(len(script)) + script + raw[off + n:]


def non_minimal_pubkey_push(hexdata):
    """The signed P2PKH spend with its public key pushed by OP_PUSHDATA1: the signature still
    holds (scriptSigs are not signed), MINIMALDATA fails."""
    raw = bytes.fromhex(hexdata)
    off, n = first_script_sig(raw)
    ss = raw[off:off + n]
    sig_len = ss[0]
    sig, rest = ss[:1 + sig_len], ss[1 + sig_len:]
    assert rest[0] == 33 and len(rest) == 34, 'a compressed key push'
    return with_script_sig(raw, sig + b'\x4c\x21' + rest[1:]).hex()


def corrupt_signature(hexdata):
    """The signed P2PKH spend with the last byte of its signature's r flipped (still DER)."""
    raw = bytearray(bytes.fromhex(hexdata))
    off, _ = first_script_sig(raw)
    # <len> 0x30 <len> 0x02 <rlen> r...
    rlen = raw[off + 4]
    raw[off + 4 + rlen] ^= 0x01
    return bytes(raw).hex()


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


def mempool_point(chain, verdicts, label, timeout=30):
    """`getrawmempool` set equality. kogany evicts what a new tip makes invalid in the
    background (W6-c's re-check, as ycashd's `ConnectTip` does synchronously), so the sets are
    compared until they agree or `timeout` seconds pass, as the mixed-line harness does."""
    deadline = time.time() + timeout
    while True:
        a, b = set(chain.y.ok('getrawmempool')), set(chain.z.ok('getrawmempool'))
        if a == b or time.time() > deadline:
            break
        time.sleep(0.25)
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


def wallet_send(y, address, amount, timeout=60):
    """`sendtoaddress`, retried while ycashd's wallet has not yet seen the last block's spends
    (it then picks a coin a mined transaction spent: bad-txns-inputs-spent)."""
    deadline = time.time() + timeout
    while True:
        txid, error = y.call('sendtoaddress', address, amount)
        if error is None:
            return txid
        if 'bad-txns-inputs-spent' not in str(error) or time.time() > deadline:
            raise base.RpcError('ycash6: sendtoaddress(%r, %r): %r' % (address, amount, error))
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
        txid = wallet_send(chain.y, chain.y.ok('getnewaddress'), 1.5)
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
            REJECT_POLICY if mode in STRICT_MODES else big)
    v.offer(chain, '%s/dust-output' % mode, chain.build([(53, pay)], 1000),
            REJECT_POLICY if mode in STRICT_MODES else ACCEPT)
    v.offer(chain, '%s/not-dust-output' % mode, chain.build([(54, pay)], 1000), ACCEPT)
    v.offer(chain, '%s/two-op-returns' % mode, chain.build([(0, op_return(10)), (0, op_return(10))], 1000),
            REJECT_POLICY if mode in STRICT_MODES else big)

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

    # STANDARD_SCRIPT_VERIFY_FLAGS in every mempool (W6-a): the public key pushed non-minimally
    # passes the consensus flags and fails MINIMALDATA.
    v.offer(chain, '%s/scriptsig-non-minimal' % mode,
            non_minimal_pubkey_push(chain.build([(COIN, pay)], 1000)), REJECT_POLICY)

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
    txid = wallet_send(y, taddr, 5)
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


def raw_of(chain, txid):
    """A ycashd wallet transaction's bytes, its inputs marked used."""
    for vin in chain.y.ok('getrawtransaction', txid, 1)['vin']:
        chain.used.add((vin['txid'], vin['vout']))
    return chain.y.ok('getrawtransaction', txid, 0)


def offer_wallet_tx(chain, v, case, txid):
    """A transaction ycashd's wallet built and accepted: kogany must accept the same bytes."""
    v.record(case, None, chain.z.call('sendrawtransaction', raw_of(chain, txid))[1], ACCEPT)


def dummy_spend(chain, coin, script_sig, fee=20000, lock_time=0):
    # lock_time 0: a template branch's CLTV then fails in the script, never as non-final.
    """A spend of `coin` (txid, n, zatoshis) with a hand-made scriptSig, paying the change script."""
    txid, n, value = coin
    raw = serialize_spend(chain.group, [(txid, n, SEQUENCE_FINAL - 1, script_sig)],
                          [(value - fee, chain.change_script)], lock_time, chain.tip() + 1 + 20)
    return raw.hex()


def output_index(chain, txid, script):
    for out in chain.y.ok('getrawtransaction', txid, 1)['vout']:
        if bytes.fromhex(out['scriptPubKey']['hex']) == script:
            return out['n'], int(round(out['value'] * COIN))
    raise base.RpcError('%s has no output %s' % (txid, script.hex()))


def cases_vault(chain, v):
    """The Vault-era relay rules at their boundaries (W6-a), Vault active at the next block."""
    y, z = chain.y, chain.z
    mode = 'vault'

    # Other OP_RETURNs keep the 83-byte carrier: op_return(80) is 83 bytes, op_return(81) 84.
    v.offer(chain, '%s/op-return-83' % mode, chain.build([(0, op_return(80))], 1000), ACCEPT)
    v.offer(chain, '%s/op-return-84' % mode, chain.build([(0, op_return(81))], 1000), REJECT_POLICY)

    # A `YV` carrier of 1,200 bytes passes standardness and then fails (its act does not decode on
    # ycashd; its signature, corrupted, on both: the signature check runs first); one of 1,201
    # bytes is non-standard, which both report before the act rules (W6-c).
    v.offer(chain, '%s/act-1200-badsig' % mode,
            corrupt_signature(chain.build([(0, act_carrier(1200))], 1000)), REJECT_CONSENSUS)
    v.offer(chain, '%s/act-1201' % mode, chain.build([(0, act_carrier(1201))], 1000), REJECT_POLICY)

    # TX_PQPKH outputs: standard from Vault, priced at the real spend's dust threshold; scheme 2
    # (Falcon) stays non-standard on regtest (no -pqfalcon on ycashd, no Falcon height on kogany).
    slh = pqpkh(1, bytes([0xab]) * 32)
    threshold = pq_dust_threshold(slh)
    v.offer(chain, '%s/pqpkh-dust' % mode, chain.build([(threshold - 1, slh)], 1000), REJECT_POLICY)
    pq_hex = chain.build([(threshold + 100000, slh)], 1000)
    v.offer(chain, '%s/pqpkh-at-dust-threshold' % mode, pq_hex, ACCEPT)
    pq_txid = y.ok('decoderawtransaction', pq_hex)['txid']
    v.offer(chain, '%s/pqpkh-falcon-output' % mode,
            chain.build([(100000, pqpkh(2, bytes([0xab]) * 32))], 1000), REJECT_POLICY)

    # Real acts from ycashd's wallet: SET_CREATE, then (an open set) SET_JOIN, above 83 bytes.
    created = y.ok('set_create', {'seats': 1, 'unlockthreshold': 1, 'open': True})
    offer_wallet_tx(chain, v, '%s/set_create' % mode, created['txid'])
    mempool_point(chain, v, '%s/acts-1' % mode)
    chain.mine()
    joined = y.ok('set_join', created['setid'], 1, chain.tip() + 500)
    if 'txid' not in joined:
        raise base.RpcError('set_join did not complete: %r' % joined)
    act = [o for o in y.ok('getrawtransaction', joined['txid'], 1)['vout']
           if o['scriptPubKey']['hex'].startswith('6a')]
    print('    SET_JOIN act output: %d bytes' % (len(act[0]['scriptPubKey']['hex']) // 2))
    offer_wallet_tx(chain, v, '%s/set_join' % mode, joined['txid'])
    mempool_point(chain, v, '%s/acts-2' % mode)
    chain.mine()

    # A V from ycashd's wallet (an SLH-DSA wallet owner), owner branch from ownerheight.
    owner_height = chain.tip() + 4
    locked = y.ok('vault_lock', {'tag': 'TEST', 'setid': created['setid'], 'delay': 5,
                                 'ownerheight': owner_height, 'amount': 1})
    offer_wallet_tx(chain, v, '%s/vault_lock' % mode, locked['txid'])
    mempool_point(chain, v, '%s/vault-1' % mode)
    chain.mine()
    vspk = bytes.fromhex(locked['script'])
    v_coin = (locked['txid'], locked['vout'], output_index(chain, locked['txid'], vspk)[1])
    pq_n, pq_value = output_index(chain, pq_txid, slh)
    pq_coin = (pq_txid, pq_n, pq_value)

    # TX_PQPKH input standardness on dummy spends: exactly s + p + 2 pushes reach the script
    # (which fails: dummy bytes); one more push, or a Falcon-shaped stack, is non-standard.
    v.offer(chain, '%s/pqpkh-spend-exact' % mode, dummy_spend(chain, pq_coin, pq_args(1)), REJECT_CONSENSUS)
    v.offer(chain, '%s/pqpkh-spend-extra-push' % mode, dummy_spend(chain, pq_coin, pq_args(1, 1)),
            REJECT_POLICY)
    v.offer(chain, '%s/pqpkh-spend-falcon-shape' % mode, dummy_spend(chain, pq_coin, pq_args(2)),
            REJECT_POLICY)

    # V input standardness: an owner spend (selector 2) may carry up to 9,000 bytes of scriptSig
    # with at most s + p + 2 pushes before the selector; the APP selector carries nothing; a
    # scriptSig without a selector is no template spend.
    big = lambda total: push(b'\x5a' * (total - 3 - 1)) + op_n(2)  # noqa: E731
    assert len(big(9000)) == 9000 and len(big(9001)) == 9001
    v.offer(chain, '%s/v-owner-9000' % mode, dummy_spend(chain, v_coin, big(9000)),
            REJECT_CONSENSUS)
    v.offer(chain, '%s/v-owner-9001' % mode, dummy_spend(chain, v_coin, big(9001)),
            REJECT_POLICY)
    v.offer(chain, '%s/v-owner-extra-push' % mode,
            dummy_spend(chain, v_coin, pq_args(1, 1) + op_n(2)), REJECT_POLICY)
    v.offer(chain, '%s/v-app-junk' % mode, dummy_spend(chain, v_coin, push(b'\x07') + op_n(4)), REJECT_POLICY)
    v.offer(chain, '%s/v-no-selector' % mode,
            dummy_spend(chain, v_coin, push(b'\x20' * 65) + push(b'\x20' * 65)), REJECT_POLICY)
    mempool_point(chain, v, '%s/dummies' % mode)

    # The real SLH-DSA owner spend (~8 kB), once the next block is above ownerheight.
    while chain.tip() + 1 <= owner_height:
        chain.mine()
    spent = y.ok('vault_ownerspend', '%s:%d' % (locked['txid'], locked['vout']), y.ok('getnewaddress'))
    raw = raw_of(chain, spent['txid'])
    print('    vault_ownerspend: selector %s, %d bytes' % (spent.get('selector'), len(raw) // 2))
    v.record('%s/vault_ownerspend' % mode, None, z.call('sendrawtransaction', raw)[1], ACCEPT)


def cases_tip(chain, v):
    """After admission, when the tip moves (W6-c): see the module documentation, mode `tip`."""
    y, z = chain.y, chain.z
    mode = 'tip'

    # 1. Expiry: ycashd keeps a transaction whose expiry height is the tip, and drops it once the
    #    tip passes it. A fee below the conventional one keeps it out of ycashd's blocks.
    expiry = chain.tip() + 1 + 4      # not expiring soon (TX_EXPIRING_SOON_THRESHOLD = 3)
    low = chain.build([], 400, expiry=expiry)   # 0 paid actions at ycashd's 500-zatoshi marginal fee
    v.offer(chain, '%s/expiry-low-fee' % mode, low, ACCEPT)
    mempool_point(chain, v, '%s/expiry-admitted' % mode)
    # One block at a time, each seen by kogany's mempool as a `Grow`: a `Reset` (a reorg, or
    # several blocks between two mempool polls) re-verifies every stored transaction for the next
    # block, which refuses one whose expiry is the tip (finding W6-c/F-2, an open row).
    while chain.tip() < expiry:
        chain.mine()
        chain.z.ok('getrawmempool')
    mempool_point(chain, v, '%s/expiry-at-tip' % mode)
    chain.mine()
    mempool_point(chain, v, '%s/expiry-past-tip' % mode)

    # 2. Two SET_JOINs for the one seat of an open set: both valid at the tip, so both are
    #    admitted; the block takes one, and the re-check at the new tip evicts the other.
    created = y.ok('set_create', {'seats': 1, 'unlockthreshold': 1, 'open': True})
    offer_wallet_tx(chain, v, '%s/set_create' % mode, created['txid'])
    chain.mine()
    joins = []
    for i in range(2):
        joined = y.ok('set_join', created['setid'], 1, chain.tip() + 500)
        if 'txid' not in joined:
            raise base.RpcError('set_join did not complete: %r' % joined)
        offer_wallet_tx(chain, v, '%s/join-%d' % (mode, i + 1), joined['txid'])
        joins.append(joined['txid'])
    mempool_point(chain, v, '%s/join-2' % mode)
    chain.mine()
    left = set(y.ok('getrawmempool')) & set(joins)
    print('    after the block: ycashd keeps %d of the two joins' % len(left))
    mempool_point(chain, v, '%s/join-after-block' % mode)

    # 3. BIP68 across a reorg: a coin at H, an empty block H + 1, then a spend locked for 2
    #    blocks (valid at H + 2, the next block); invalidating H + 1 makes the next block H + 1.
    coin_hex = chain.build([(100000000, chain.change_script)], 20000)
    coin_txid = y.ok('decoderawtransaction', coin_hex)['txid']
    v.offer(chain, '%s/bip68-coin' % mode, coin_hex, ACCEPT)
    chain.mine()
    n, value = output_index(chain, coin_txid, chain.change_script)
    chain.mine()       # H + 1, empty: invalidating it returns no transaction to either mempool
    locked = chain.build([], 20000, sequence=2, coin=(coin_txid, n, value))
    v.offer(chain, '%s/bip68-locked-2' % mode, locked, ACCEPT)
    mempool_point(chain, v, '%s/bip68-admitted' % mode)
    tip_hash = y.ok('getbestblockhash')
    for node in (y, z):
        node.ok('invalidateblock', tip_hash)
    deadline = time.time() + 60
    while z.ok('getbestblockhash') != y.ok('getbestblockhash'):
        if time.time() > deadline:
            raise base.RpcError('kogany did not follow the invalidation')
        time.sleep(0.2)
    time.sleep(2)      # kogany re-verifies its mempool after the reset
    mempool_point(chain, v, '%s/bip68-after-invalidate' % mode)
    for node in (y, z):
        node.ok('reconsiderblock', tip_hash)
    chain.catch_up()
    mempool_point(chain, v, '%s/bip68-reconsidered' % mode)

    # 4. A spend that fails only its coin's OP_CHECKLOCKTIMEVERIFY (W6-a F-4): policy on both.
    cltv_script = push(bytes([0xf4, 0x01])) + bytes([0xb1, 0x75, 0x51])   # 500 CLTV DROP TRUE
    cltv_hex = chain.build([(100000000, cltv_script)], 20000)
    cltv_txid = y.ok('decoderawtransaction', cltv_hex)['txid']
    v.offer(chain, '%s/cltv-coin' % mode, cltv_hex, ACCEPT)
    chain.mine()
    cn, cvalue = output_index(chain, cltv_txid, cltv_script)
    v.offer(chain, '%s/cltv-fails' % mode, dummy_spend(chain, (cltv_txid, cn, cvalue), b'', lock_time=0),
            REJECT_POLICY)
    mempool_point(chain, v, mode)


MODES = {
    'default': ([], []),
    'standard': (['-acceptnonstdtxn=0'], ['accept_non_standard = false']),
    'zip317': (['-txunpaidactionlimit=0'], ['tx_unpaid_action_limit = 0']),
    'vault': (['-acceptnonstdtxn=0'], ['accept_non_standard = false']),
    'tip': (['-blockunpaidactionlimit=0'], []),
}

# The modes whose ycashd applies IsStandardTx / AreInputsStandard (`-acceptnonstdtxn=0`).
STRICT_MODES = ('standard', 'vault')

# The Vault upgrade's branch ID and kogany's activation key (W6-a `vault` mode).
VAULT_BRANCH_ID = '6d5b7a31'


def start_ycashd(bindir, workdir, port, rpcport, mineraddress, extra, vault=False):
    datadir = os.path.join(workdir, 'ycashd')
    os.makedirs(datadir, exist_ok=True)
    with open(os.path.join(datadir, 'ycash.conf'), 'w') as f:
        f.write('regtest=1\nshowmetrics=0\nrpcuser=u\nrpcpassword=p\nport=%d\nrpcport=%d\nlistenonion=0\n'
                % (port, rpcport))
    args = [os.path.join(bindir, 'ycashd'), '-datadir=' + datadir, '-discover=0', '-listen=0', '-txindex',
            '-experimentalfeatures', '-i-am-aware-zcashd-will-be-replaced-by-zebrad-and-zallet-in-2025']
    args += ['-nuparams=%s:1' % b for b in base.NUPARAMS + ([VAULT_BRANCH_ID] if vault else [])]
    if mineraddress:
        args.append('-mineraddress=' + mineraddress)
    args += extra
    log = open(os.path.join(workdir, 'ycashd.out'), 'a')
    return subprocess.Popen(args, stdout=log, stderr=subprocess.STDOUT)


def kogany_toml(workdir, base_port, miner, extra, vault=False):
    toml = base.zakurad_toml(workdir, base_port + 10, base_port + 11, base_port + 12, miner)
    if vault:
        canopy = 'Canopy = 1\n'
        assert canopy in toml
        toml = toml.replace(canopy, canopy + 'Vault = 1\n')
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
        for mode in [m for m in args.modes if m not in ('vault', 'tip')]:
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
        for k in list(procs):
            base.stop(procs.pop(k))
        if 'vault' in args.modes:
            run_vault(args, v, os.path.join(workdir, 'vault'), procs)
        for k in list(procs):
            base.stop(procs.pop(k))
        if 'tip' in args.modes:
            run_vault(args, v, os.path.join(workdir, 'tip'), procs, mode='tip')
    finally:
        for k in list(procs):
            base.stop(procs.pop(k))
        if not args.keep and not args.workdir:
            shutil.rmtree(workdir, ignore_errors=True)
    return v, workdir


def run_vault(args, v, workdir, procs, mode='vault'):
    """The `vault` mode on its own chain: Vault at height 1 on both nodes, standardness on; or
    the `tip` mode (W6-c) on a third chain, Vault at height 1 and ycashd's regtest policy."""
    os.makedirs(workdir, exist_ok=True)
    p = args.port_base + (30 if mode == 'vault' else 60)
    y = base.Node('ycash6', p + 1, 'u:p')
    z = base.Node('kogany', p + 11)
    yextra, zextra = MODES[mode]
    procs['y'] = start_ycashd(args.ycash6_bin, workdir, p, p + 1, None, [], vault=True)
    base.wait_up(y, procs['y'], 'ycashd')
    miner = y.ok('getnewaddress')
    base.stop(procs.pop('y'))
    procs['y'] = start_ycashd(args.ycash6_bin, workdir, p, p + 1, miner, yextra, vault=True)
    base.wait_up(y, procs['y'], 'ycashd')
    procs['z'] = base.start_zakurad(args.zakurad, workdir, kogany_toml(workdir, p, miner, zextra, vault=True))
    base.wait_up(z, procs['z'], 'zakurad')
    print('\n== mode %s: ycashd %s -nuparams=%s:1, kogany [mempool] %s, Vault = 1'
          % (mode, yextra, VAULT_BRANCH_ID, zextra))
    chain = Chain(y, z)
    chain.mine(1)
    chain.mine(200)
    base.wait_balance(y, 100)
    raw = y.ok('getrawtransaction', y.ok('getblock', y.ok('getblockhash', 1), 1)['tx'][0], 0)
    chain.group = bytes.fromhex(raw)[4:8]
    chain.change_script = bytes.fromhex(y.ok('validateaddress', miner)['scriptPubKey'])
    if mode == 'tip':
        mempool_point(chain, v, 'tip/start')
        cases_tip(chain, v)
        chain.mine()
        mempool_point(chain, v, 'tip/after-block')
        return
    mempool_point(chain, v, 'vault/start')
    cases_common(chain, v, 'vault')
    mempool_point(chain, v, 'vault/common')
    chain.mine()
    mempool_point(chain, v, 'vault/common-after-block')
    cases_vault(chain, v)
    mempool_point(chain, v, 'vault')
    chain.mine()
    mempool_point(chain, v, 'vault/after-block')


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
    ap.add_argument('--modes', default='default,standard,zip317,vault,tip', help='comma-separated: ' + ', '.join(MODES))
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
