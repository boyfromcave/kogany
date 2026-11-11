// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

//! Ycash relay standardness, before and from the Vault upgrade (kogany W6-a `standardness`).
//!
//! On a Ycash network these functions replace Zakura's `IsStandardTx` / `AreInputsStandard`
//! ports ([`super::are_inputs_standard`], the mempool storage's `reject_if_non_standard_tx`);
//! Zcash networks (the feature-off build) keep those untouched. They are ported by meaning from
//! ycashd 6.22 (`ycash6` at `65cb4ae0f`), `src/policy/policy.cpp`, `src/script/standard.cpp` and
//! the `AcceptToMemoryPool` hooks in `src/main.cpp`:
//!
//! - [`is_standard_tx`] (`IsStandardTx`, at the next block's height): the scriptSig bound
//!   becomes [`MAX_STANDARD_PQ_SCRIPTSIG`] from Vault (every input; [`are_inputs_standard`]
//!   re-checks [`MAX_STANDARD_SCRIPTSIG`] for non-PQ prevouts, F-6); a `YV` act `OP_RETURN` may
//!   carry up to [`MAX_VAULT_ACT_BYTES`] from Vault (the carrier limit is height-dependent); V,
//!   I, TX_PQPKH and TX_PQCHANNEL outputs are standard only from Vault, and scheme-2 (Falcon) ones
//!   only from the Falcon height (A-1); TX_PQPKH / TX_PQCHANNEL dust prices the real PQ spend
//!   ([`pq_dust_threshold`], review A F8); bare multisig up to x-of-3 is standard
//!   (`-permitbaremultisig` defaults to true on ycashd, where Zakura refuses it);
//! - [`are_inputs_standard`] (`AreInputsStandard`): TX_PQPKH spends need exactly `s + p + 2`
//!   pushes (A-14), TX_PQCHANNEL spends `s + p + 4` (cooperative) or `s + p + 3` (refund), and a
//!   V/I input's scriptSig carries no more than its selector's branch consumes
//!   ([`is_standard_template_script_sig`], audit 01/V-4); a P2SH redeem script's
//!   `OP_CHECKPQSIG` costs [`kogany_pq::SIGOP_COST`] policy sigops (R-B2);
//! - [`pq_sig_op_count`] (`GetPQSigOpCount`): the policy sigops `AcceptToMemoryPool` adds to
//!   `MAX_STANDARD_TX_SIGOPS`;
//! - [`find_vault_template_input`], [`is_vault_set_state_script_error`] and
//!   [`vault_template_fails_on_set_state`]: `AcceptToMemoryPool`'s classification of a failed
//!   template-input script as set-state-dependent (DoS 0, audit 07/F-1), for the tip re-check
//!   (W6-c) to wire into the verifier's error scoring;
//! - [`require_standard`]: `chainparams.RequireStandard()`, which regtest turns off unless the
//!   mempool says otherwise (`-acceptnonstdtxn=0`).
//!
//! The standard script verification flags (`STANDARD_SCRIPT_VERIFY_FLAGS`, applied in every
//! mempool, regtest included) are [`zakura_script::standard_script_flags`]; the mempool storage
//! runs them through [`standard_script_check`].

use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

use kogany_vault::{
    act::{is_act_output, RECOVERABLE_SIG_SIZE},
    state::StateRead,
    template::{
        parse_intent, parse_selector, parse_template_spend, parse_vault, IntentParams,
        TemplateParams, VaultParams, ROLE_CANCEL, ROLE_UNLOCK, SEL_APP, SEL_OWNER, SEL_RELEASED,
        SEL_UNLOCK,
    },
    PqOwner, SetId,
};
use kogany_yellowback::codecs::script::{match_pq_channel, PqChannelParams};
use zakura_chain::{
    block::Height,
    parameters::{Network, NetworkUpgrade},
    transaction::Transaction,
    transparent::{self, PqKeyId},
};
use zcash_script::{
    interpreter,
    script::{self, Evaluable as _},
    solver,
};

use super::{ycash_standard_script_kind, YcashScriptKind, MAX_P2SH_SIGOPS};

/// `MAX_VAULT_ACT_BYTES` (ycash6 `policy/policy.h`): the largest `YV` act `OP_RETURN`
/// scriptPubKey relayed once the Vault upgrade is active (plan §15.5).
pub const MAX_VAULT_ACT_BYTES: usize = 1_200;

/// `MAX_STANDARD_PQ_SCRIPTSIG`: the largest standard scriptSig of an input spending TX_PQPKH,
/// TX_PQCHANNEL or a vault template once Vault is active (an SLH-DSA spend is 7,939 bytes).
pub const MAX_STANDARD_PQ_SCRIPTSIG: usize = 9_000;

/// `MAX_STANDARD_SCRIPTSIG`: the largest standard scriptSig of every other input.
pub const MAX_STANDARD_SCRIPTSIG: usize = 1_650;

/// `MAX_OP_RETURN_RELAY` (ycash6 `script/standard.h`): the default `-datacarriersize`.
pub const MAX_OP_RETURN_RELAY: usize = 83;

/// `ONE_THIRD_DUST_THRESHOLD_RATE` (ycash6 `policy/policy.h`), zatoshis per 1,000 bytes.
pub const ONE_THIRD_DUST_THRESHOLD_RATE: u64 = 100;

/// `MAX_STANDARD_TX_SIGOPS` (ycash6 `policy/policy.h`): `MAX_BLOCK_SIGOPS / 5`.
pub const MAX_STANDARD_TX_SIGOPS: u32 = 4_000;

/// `MAX_SCRIPT_ELEMENT_SIZE`: the largest push `EvalScript` accepts.
const MAX_SCRIPT_ELEMENT_SIZE: usize = 520;

/// `MAX_STACK_SIZE`: the deepest stack `EvalScript` accepts.
const MAX_STACK_SIZE: usize = 1_000;

/// `MAX_SCRIPT_SIZE`: the longest script `EvalScript` runs; longer is unspendable.
const MAX_SCRIPT_SIZE: usize = 10_000;

/// The serialized size of the input that spends a P2PKH output, `CTxOut::GetDustThreshold`'s
/// assumption.
const P2PKH_SPEND_INPUT_SIZE: usize = 148;

const OP_0: u8 = 0x00;
const OP_PUSHDATA1: u8 = 0x4c;
const OP_PUSHDATA2: u8 = 0x4d;
const OP_PUSHDATA4: u8 = 0x4e;
const OP_1NEGATE: u8 = 0x4f;
const OP_RESERVED: u8 = 0x50;
const OP_1: u8 = 0x51;
const OP_16: u8 = 0x60;
const OP_RETURN: u8 = 0x6a;
const OP_CHECKPQSIG: u8 = 0xc2;

// ---- the node's relay configuration -------------------------------------------------------

/// `!RequireStandard()` on regtest: true (ycashd's `-acceptnonstdtxn` default there) unless the
/// mempool was configured with `accept_non_standard = false`.
static REGTEST_ACCEPT_NON_STANDARD: AtomicBool = AtomicBool::new(true);

/// Records the mempool's `accept_non_standard` for the transaction verifier, which checks
/// standard inputs before script verification where [`require_standard`] holds (ycashd's
/// `fRequireStandard` is process-wide too). Called when the mempool storage is created for its
/// network.
pub fn configure_relay_policy(regtest_accept_non_standard: bool) {
    REGTEST_ACCEPT_NON_STANDARD.store(regtest_accept_non_standard, Ordering::Relaxed);
}

/// `chainparams.RequireStandard()`: always on mainnet and testnet; on regtest only when the
/// mempool was configured with `accept_non_standard = false`.
pub fn require_standard(network: &Network) -> bool {
    !network.is_regtest() || !REGTEST_ACCEPT_NON_STANDARD.load(Ordering::Relaxed)
}

/// The relay knobs [`is_standard_tx`] reads (ycashd's globals).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RelayPolicy {
    /// `nMaxDatacarrierBytes` (`-datacarriersize`, default [`MAX_OP_RETURN_RELAY`]).
    pub max_datacarrier_bytes: usize,
    /// `fAcceptDatacarrier` (`-datacarrier`, default true).
    pub accept_datacarrier: bool,
    /// `fIsBareMultisigStd` (`-permitbaremultisig`, default true).
    pub permit_bare_multisig: bool,
}

impl Default for RelayPolicy {
    fn default() -> Self {
        Self {
            max_datacarrier_bytes: MAX_OP_RETURN_RELAY,
            accept_datacarrier: true,
            permit_bare_multisig: true,
        }
    }
}

// ---- script helpers -------------------------------------------------------------------------

/// One opcode of `script` at `pos`: `(opcode, push data, next position)`; `None` when the push
/// runs past the end (`CScript::GetOp` failing).
fn get_op(script: &[u8], pos: usize) -> Option<(u8, &[u8], usize)> {
    let op = *script.get(pos)?;
    let pos = pos.checked_add(1)?;
    let (len, pos) = match op {
        0x01..=0x4b => (usize::from(op), pos),
        OP_PUSHDATA1 => (usize::from(*script.get(pos)?), pos.checked_add(1)?),
        OP_PUSHDATA2 => {
            let b = script.get(pos..pos.checked_add(2)?)?;
            (
                usize::from(u16::from_le_bytes([b[0], b[1]])),
                pos.checked_add(2)?,
            )
        }
        OP_PUSHDATA4 => {
            let b = script.get(pos..pos.checked_add(4)?)?;
            let n = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
            (usize::try_from(n).ok()?, pos.checked_add(4)?)
        }
        _ => (0, pos),
    };
    let end = pos.checked_add(len)?;
    Some((op, script.get(pos..end)?, end))
}

/// The stack `EvalScript(stack, scriptSig, SCRIPT_VERIFY_NONE, BaseSignatureChecker())` leaves
/// for a push-only script, or `None` where it fails: a push above 520 bytes, more than 1,000
/// stack items, an executed `OP_RESERVED`, a non-push opcode, a truncated push or a script above
/// 10,000 bytes.
pub fn push_only_stack(script: &[u8]) -> Option<Vec<Vec<u8>>> {
    if script.len() > MAX_SCRIPT_SIZE {
        return None;
    }
    let mut stack = Vec::new();
    let mut pos = 0;
    while pos < script.len() {
        let (op, data, next) = get_op(script, pos)?;
        pos = next;
        let item = match op {
            OP_0..=OP_PUSHDATA4 => {
                if data.len() > MAX_SCRIPT_ELEMENT_SIZE {
                    return None;
                }
                data.to_vec()
            }
            OP_1NEGATE => vec![0x81],
            OP_RESERVED => return None,
            OP_1..=OP_16 => vec![op - (OP_1 - 1)],
            _ => return None,
        };
        stack.push(item);
        if stack.len() > MAX_STACK_SIZE {
            return None;
        }
    }
    Some(stack)
}

/// `GetPQSigOpCount(script)`: [`kogany_pq::SIGOP_COST`] for each `OP_CHECKPQSIG` opcode (not
/// inside a push), up to the first unparsable opcode.
pub fn pq_sig_op_count_script(script: &[u8]) -> u32 {
    let mut n: u32 = 0;
    let mut pos = 0;
    while let Some((op, _, next)) = get_op(script, pos) {
        if op == OP_CHECKPQSIG {
            n = n.saturating_add(kogany_pq::SIGOP_COST);
        }
        pos = next;
    }
    n
}

/// `GetPQSigOpCount(tx, view)`: the policy sigops of `OP_CHECKPQSIG` in what each input
/// executes: its scriptSig, the spent scriptPubKey and, for P2SH, the redeem script (the
/// scriptSig's last push, when the scriptSig is push-only). `spent_outputs` is in input order.
pub fn pq_sig_op_count(tx: &Transaction, spent_outputs: &[transparent::Output]) -> u32 {
    if tx.is_coinbase() {
        return 0;
    }
    let mut n: u32 = 0;
    for (input, spent) in tx.inputs().iter().zip(spent_outputs) {
        let transparent::Input::PrevOut { unlock_script, .. } = input else {
            continue;
        };
        let script_sig = unlock_script.as_raw_bytes();
        let prev = spent.lock_script.as_raw_bytes();
        n = n
            .saturating_add(pq_sig_op_count_script(script_sig))
            .saturating_add(pq_sig_op_count_script(prev));
        if is_pay_to_script_hash(prev) {
            if let Some(redeem) = last_push_if_push_only(script_sig) {
                n = n.saturating_add(pq_sig_op_count_script(redeem));
            }
        }
    }
    n
}

/// `CScript::IsPayToScriptHash`: exactly `OP_HASH160 <20 bytes> OP_EQUAL`.
fn is_pay_to_script_hash(script: &[u8]) -> bool {
    matches!(script, [0xa9, 0x14, .., 0x87] if script.len() == 23)
}

/// The data of a push-only script's last opcode (empty for `OP_n`), as `GetSigOpCount(scriptSig)`
/// reads the redeem script; `None` when an opcode fails to parse or is above `OP_16`.
fn last_push_if_push_only(script: &[u8]) -> Option<&[u8]> {
    let mut last: &[u8] = &[];
    let mut pos = 0;
    while pos < script.len() {
        let (op, data, next) = get_op(script, pos)?;
        if op > OP_16 {
            return None;
        }
        last = data;
        pos = next;
    }
    Some(last)
}

/// `CScript::IsUnspendable`: begins with `OP_RETURN`, or is longer than 10,000 bytes.
fn is_unspendable(script: &[u8]) -> bool {
    script.first() == Some(&OP_RETURN) || script.len() > MAX_SCRIPT_SIZE
}

// ---- output kinds ---------------------------------------------------------------------------

/// ycash6 `Solver`'s kind of a scriptPubKey (`txnouttype`), with its parameters.
pub enum TxOutType {
    /// A kind the `zcash_script` solver recognises (P2PK with a valid key size, P2PKH, P2SH,
    /// multisig, `OP_RETURN` data).
    Solver(solver::ScriptKind),
    /// TX_PQPKH.
    PqPubKeyHash(PqKeyId),
    /// TX_PQCHANNEL (quantum spec D-Q-19).
    PqChannel(PqChannelParams),
    /// TX_VAULT: a vault V (exact template).
    Vault(VaultParams),
    /// TX_VAULT_INTENT: an intent I (exact template).
    Intent(IntentParams),
}

impl TxOutType {
    /// ycash6's `GetTxnOutputType` name.
    pub fn as_str(&self) -> &'static str {
        match self {
            TxOutType::Solver(kind) => kind.as_str(),
            TxOutType::PqPubKeyHash(_) => "pqpubkeyhash",
            TxOutType::PqChannel(_) => "pqchannel",
            TxOutType::Vault(_) => "vault",
            TxOutType::Intent(_) => "vaultintent",
        }
    }

    /// The post-quantum kinds (TX_PQPKH, TX_PQCHANNEL, V, I): standard only from Vault, and the
    /// spends that may carry [`MAX_STANDARD_PQ_SCRIPTSIG`].
    pub fn is_pq(&self) -> bool {
        !matches!(self, TxOutType::Solver(_))
    }

    /// `PQScriptScheme`: the owner or holder scheme of a TX_PQPKH, TX_PQCHANNEL, V or I.
    pub fn pq_scheme(&self) -> Option<u8> {
        match self {
            TxOutType::Solver(_) => None,
            TxOutType::PqPubKeyHash(id) => Some(id.scheme),
            TxOutType::PqChannel(cp) => Some(cp.client.scheme),
            TxOutType::Vault(vp) => Some(vp.owner.scheme),
            TxOutType::Intent(ip) => Some(ip.owner.scheme),
        }
    }
}

/// ycash6 `Solver`: the standard templates, then TX_PQPKH, TX_PQCHANNEL, V and I (disjoint
/// shapes). `None` is TX_NONSTANDARD. The `OP_RETURN` size is not checked here (`IsStandard`
/// does).
pub fn solver(spk: &transparent::Script) -> Option<TxOutType> {
    if let Some(kind) = ycash_standard_script_kind(spk) {
        return Some(match kind {
            YcashScriptKind::Solver(kind) => TxOutType::Solver(kind),
            YcashScriptKind::PqPubKeyHash(id) => TxOutType::PqPubKeyHash(id),
        });
    }
    let bytes = spk.as_raw_bytes();
    if let Some(cp) = match_pq_channel(bytes) {
        return Some(TxOutType::PqChannel(cp));
    }
    if let Some(vp) = parse_vault(bytes) {
        return Some(TxOutType::Vault(vp));
    }
    parse_intent(bytes).map(TxOutType::Intent)
}

/// `ScriptSigArgsExpected` for the solver kinds (the PQ and template kinds are -1: checked by
/// [`are_inputs_standard`] itself).
fn script_sig_args_expected(kind: &TxOutType) -> Option<usize> {
    match kind {
        TxOutType::Solver(kind) => super::script_sig_args_expected(kind),
        _ => None,
    }
}

// ---- dust -----------------------------------------------------------------------------------

/// `CFeeRate(rate_per_k).GetFee(size)`: `rate * size / 1000`, the rate itself when that rounds
/// to zero.
pub fn fee_at_rate(rate_per_k: u64, size: usize) -> u64 {
    let size = u64::try_from(size).unwrap_or(u64::MAX);
    let fee = rate_per_k.saturating_mul(size) / 1_000;
    if fee == 0 && rate_per_k > 0 {
        rate_per_k
    } else {
        fee
    }
}

/// `GetSerializeSize(txout, SER_DISK, 0)`: value, compact size and script.
fn output_serialized_size(output: &transparent::Output) -> usize {
    let len = output.lock_script.as_raw_bytes().len();
    let compact = match len {
        0..=0xfc => 1,
        0xfd..=0xffff => 3,
        _ => 5,
    };
    8usize.saturating_add(compact).saturating_add(len)
}

/// `CTxOut::GetDustThreshold`: 3 × the fee of the output plus a 148-byte spend at
/// [`ONE_THIRD_DUST_THRESHOLD_RATE`]; 0 for an unspendable output.
pub fn dust_threshold(output: &transparent::Output) -> u64 {
    if is_unspendable(output.lock_script.as_raw_bytes()) {
        return 0;
    }
    let size = output_serialized_size(output).saturating_add(P2PKH_SPEND_INPUT_SIZE);
    fee_at_rate(ONE_THIRD_DUST_THRESHOLD_RATE, size).saturating_mul(3)
}

/// `PQStackPushes(scheme)`: `s + p + 2`, the pushes of a post-quantum owner or holder stack
/// `<sig_1>..<sig_s> <s> <pk_1>..<pk_p> <p>`; 0 for an unregistered scheme.
pub fn pq_stack_pushes(scheme: u8) -> usize {
    pq_chunks(scheme).map_or(0, |(s, p)| s.saturating_add(p).saturating_add(2))
}

/// `(s, p)`: the chunk counts of a scheme's signature (with its hash-type byte) and key.
fn pq_chunks(scheme: u8) -> Option<(usize, usize)> {
    let sig = kogany_pq::sig_size(scheme);
    let pk = kogany_pq::pubkey_size(scheme);
    if sig == 0 || pk == 0 {
        return None;
    }
    Some((
        sig.saturating_add(1).div_ceil(kogany_pq::MAX_CHUNK),
        pk.div_ceil(kogany_pq::MAX_CHUNK),
    ))
}

/// The bytes of a minimal push of `len` data bytes: the opcode, its length field and the data.
fn push_size(len: usize) -> usize {
    let header = if len < usize::from(OP_PUSHDATA1) {
        1
    } else if len <= 0xff {
        2
    } else {
        3
    };
    len.saturating_add(header)
}

/// `PQSpendInputSize(scheme)`: the serialized size of the input that spends a TX_PQPKH output
/// of `scheme` (outpoint and sequence, the scriptSig's compact size and the chunked scriptSig:
/// SLH-DSA 7,938 + 43 bytes, Falcon 1,577 + 43); 0 for an unknown scheme.
pub fn pq_spend_input_size(scheme: u8) -> usize {
    if !kogany_pq::is_known_scheme(scheme) {
        return 0;
    }
    let chunked = |total: usize| {
        let mut size = 0usize;
        let mut left = total;
        while left > 0 {
            let c = left.min(kogany_pq::MAX_CHUNK);
            size = size.saturating_add(push_size(c));
            left = left.saturating_sub(c);
        }
        size
    };
    let script_sig = chunked(kogany_pq::sig_size(scheme).saturating_add(1))
        .saturating_add(chunked(kogany_pq::pubkey_size(scheme)))
        .saturating_add(2);
    let compact = if script_sig > 252 { 3 } else { 1 };
    40usize.saturating_add(compact).saturating_add(script_sig)
}

/// `GetPQDustThreshold(txout, CFeeRate(ONE_THIRD_DUST_THRESHOLD_RATE))`: a TX_PQPKH output
/// prices its real spend ([`pq_spend_input_size`]); a TX_PQCHANNEL its cooperative spend (the
/// client's PQ spend, the server's signature push of 74 bytes and the selector); any other
/// output [`dust_threshold`].
pub fn pq_dust_threshold(output: &transparent::Output) -> u64 {
    let spend = if let Some(cp) = match_pq_channel(output.lock_script.as_raw_bytes()) {
        pq_spend_input_size(cp.client.scheme).saturating_add(74 + 1)
    } else if let Some(id) = output.lock_script.pq_key_id() {
        pq_spend_input_size(id.scheme)
    } else {
        return dust_threshold(output);
    };
    let size = output_serialized_size(output).saturating_add(spend);
    fee_at_rate(ONE_THIRD_DUST_THRESHOLD_RATE, size).saturating_mul(3)
}

// ---- IsStandardTx ---------------------------------------------------------------------------

/// Why [`is_standard_tx`] refuses a transaction: ycashd's `reason` strings.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NonStandardReason {
    /// `scriptsig-size`.
    ScriptSigSize,
    /// `scriptsig-not-pushonly`.
    ScriptSigNotPushOnly,
    /// `scriptpubkey`: a non-standard output, or a PQ/template output before Vault (or a
    /// Falcon one before the Falcon height).
    ScriptPubKey,
    /// `scriptpubkey` for an `OP_RETURN` above the data carrier limit (or with the carrier off).
    DataCarrier,
    /// `bare-multisig` (only with `-permitbaremultisig=0`).
    BareMultisig,
    /// `dust`.
    Dust,
    /// `multi-op-return`.
    MultiOpReturn,
}

impl NonStandardReason {
    /// ycashd's reject reason.
    pub fn as_str(&self) -> &'static str {
        match self {
            NonStandardReason::ScriptSigSize => "scriptsig-size",
            NonStandardReason::ScriptSigNotPushOnly => "scriptsig-not-pushonly",
            NonStandardReason::ScriptPubKey | NonStandardReason::DataCarrier => "scriptpubkey",
            NonStandardReason::BareMultisig => "bare-multisig",
            NonStandardReason::Dust => "dust",
            NonStandardReason::MultiOpReturn => "multi-op-return",
        }
    }
}

/// `IsStandardTx`'s scriptSig rules for every input at `height`: at most
/// [`MAX_STANDARD_PQ_SCRIPTSIG`] bytes from Vault ([`MAX_STANDARD_SCRIPTSIG`] before), push-only.
/// Returns the failing input's index and the reason.
pub fn standard_script_sigs(
    tx: &Transaction,
    network: &Network,
    height: Height,
) -> Result<(), (usize, NonStandardReason)> {
    let limit = if network.is_vault_active(height) {
        MAX_STANDARD_PQ_SCRIPTSIG
    } else {
        MAX_STANDARD_SCRIPTSIG
    };
    for (index, input) in tx.inputs().iter().enumerate() {
        let transparent::Input::PrevOut { unlock_script, .. } = input else {
            continue;
        };
        if unlock_script.as_raw_bytes().len() > limit {
            return Err((index, NonStandardReason::ScriptSigSize));
        }
        if !script::Code(unlock_script.as_raw_bytes().to_vec()).is_push_only() {
            return Err((index, NonStandardReason::ScriptSigNotPushOnly));
        }
    }
    Ok(())
}

/// `IsStandard(scriptPubKey, whichType)` (the multisig and data carrier bounds) with the kind.
fn is_standard_output_script(
    spk: &transparent::Script,
    policy: &RelayPolicy,
) -> Result<TxOutType, NonStandardReason> {
    let kind = solver(spk).ok_or(NonStandardReason::ScriptPubKey)?;
    match &kind {
        TxOutType::Solver(solver::ScriptKind::MultiSig { required, pubkeys })
            if !(1..=3).contains(&pubkeys.len())
                || *required < 1
                || usize::from(*required) > pubkeys.len() =>
        {
            return Err(NonStandardReason::ScriptPubKey);
        }
        TxOutType::Solver(solver::ScriptKind::NullData { .. })
            if !policy.accept_datacarrier
                || spk.as_raw_bytes().len() > policy.max_datacarrier_bytes =>
        {
            return Err(NonStandardReason::DataCarrier);
        }
        _ => {}
    }
    Ok(kind)
}

/// `vault::IsActOutput(spk) && spk.size() <= MAX_VAULT_ACT_BYTES && spk.IsPushOnly(begin + 1)`.
fn is_relayable_act(spk: &[u8]) -> bool {
    is_act_output(spk)
        && spk.len() <= MAX_VAULT_ACT_BYTES
        && spk.get(1..).is_some_and(kogany_vault::script::is_push_only)
}

/// `IsStandardTx(tx, reason, chainparams, height)` without its version rules (Zakura's
/// consensus checks refuse every version ycashd's standardness does): the scriptSig rules
/// ([`standard_script_sigs`]), then each output in order, then one `OP_RETURN` at most.
/// `height` is the next block's height.
pub fn is_standard_tx(
    tx: &Transaction,
    network: &Network,
    height: Height,
    policy: &RelayPolicy,
) -> Result<(), NonStandardReason> {
    standard_script_sigs(tx, network, height).map_err(|(_, reason)| reason)?;

    let vault_active = network.is_vault_active(height);
    let falcon_active = zakura_script::is_pq_falcon_active(network, height);

    let mut data_out: u32 = 0;
    for output in tx.outputs() {
        let spk = output.lock_script.as_raw_bytes();
        if vault_active && policy.accept_datacarrier && is_relayable_act(spk) {
            data_out = data_out.saturating_add(1);
            continue;
        }
        let kind = is_standard_output_script(&output.lock_script, policy)?;
        if kind.is_pq() && !vault_active {
            return Err(NonStandardReason::ScriptPubKey);
        }
        // No new scheme-2 (FN-DSA-512) PQPKH, V or I output before Falcon is active (A-1).
        if !falcon_active && kind.pq_scheme() == Some(kogany_pq::Scheme::FnDsa512.byte()) {
            return Err(NonStandardReason::ScriptPubKey);
        }
        let value = u64::try_from(i64::from(output.value)).unwrap_or(0);
        match kind {
            TxOutType::Solver(solver::ScriptKind::NullData { .. }) => {
                data_out = data_out.saturating_add(1);
            }
            TxOutType::Solver(solver::ScriptKind::MultiSig { .. })
                if !policy.permit_bare_multisig =>
            {
                return Err(NonStandardReason::BareMultisig);
            }
            TxOutType::PqPubKeyHash(_) | TxOutType::PqChannel(_) => {
                if value < pq_dust_threshold(output) {
                    return Err(NonStandardReason::Dust);
                }
            }
            _ => {
                if value < dust_threshold(output) {
                    return Err(NonStandardReason::Dust);
                }
            }
        }
    }

    if data_out > 1 {
        return Err(NonStandardReason::MultiOpReturn);
    }
    Ok(())
}

// ---- AreInputsStandard ----------------------------------------------------------------------

/// The set-signed branch of a template spend: at least one push, every push a 65-byte
/// signature, and no more than the role's threshold when the set state is at hand (an unknown
/// set fails the script anyway).
fn set_signed_shape(
    pushes: &[Vec<u8>],
    set_id: &SetId,
    role: u8,
    state: Option<&dyn StateRead>,
) -> bool {
    if pushes.is_empty() || pushes.iter().any(|sig| sig.len() != RECOVERABLE_SIG_SIZE) {
        return false;
    }
    match state.and_then(|state| state.threshold(set_id, role)) {
        Some(k) => pushes.len() <= usize::from(k),
        None => true,
    }
}

/// The owner branch of a template spend: at most the owner scheme's `s + p + 2` pushes.
fn owner_shape(pushes: &[Vec<u8>], owner: &PqOwner) -> bool {
    pushes.len() <= pq_stack_pushes(owner.scheme)
}

/// `IsStandardTemplateScriptSig(spk, scriptSig, snapshot)` (audit 01/V-4): a template input's
/// scriptSig carries no more than its selector's branch consumes. Set-signed branches (V
/// selector 1, I selector 2): only 65-byte signatures, at most the role's threshold when
/// `state` is given; owner branches (V 2/3, I 3): at most the owner scheme's `s + p + 2`
/// pushes; the APP branch (V 4) and the RELEASE (I 1): the selector alone. Relay policy only.
pub fn is_standard_template_script_sig(
    spk: &[u8],
    script_sig: &[u8],
    state: Option<&dyn StateRead>,
) -> bool {
    let Some(ts) = parse_template_spend(spk, script_sig) else {
        // A MALFORMED-shaped coin is no template input: the size bound only; a template one
        // needs a selector.
        return parse_vault(spk).is_none() && parse_intent(spk).is_none();
    };
    let pushes = &ts.sigs;
    match (&ts.params, ts.selector) {
        (TemplateParams::Vault(v), SEL_UNLOCK) => {
            set_signed_shape(pushes, &v.set_id, ROLE_UNLOCK, state)
        }
        (TemplateParams::Vault(v), SEL_OWNER | SEL_RELEASED) => owner_shape(pushes, &v.owner),
        (TemplateParams::Vault(_), SEL_APP) => pushes.is_empty(),
        (TemplateParams::Intent(_), SEL_UNLOCK) => pushes.is_empty(),
        (TemplateParams::Intent(i), SEL_OWNER) => {
            set_signed_shape(pushes, &i.cancel_set_id, ROLE_CANCEL, state)
        }
        (TemplateParams::Intent(i), SEL_RELEASED) => owner_shape(pushes, &i.owner),
        _ => false,
    }
}

/// `AreInputsStandard(tx, view, branchId, snapshot)`. `spent_outputs` is in input order;
/// `state` is the set state at the tip (`None`: only the set signatures' size is checked).
///
/// Per input: the spent scriptPubKey must solve; the scriptSig is at most
/// [`MAX_STANDARD_PQ_SCRIPTSIG`] for a PQ or template prevout and [`MAX_STANDARD_SCRIPTSIG`]
/// otherwise; a template input passes [`is_standard_template_script_sig`]; a TX_PQPKH spend
/// leaves exactly `s + p + 2` items, a TX_PQCHANNEL spend `s + p + 4` (selector `OP_1`) or
/// `s + p + 3` (selector empty); every other kind its `ScriptSigArgsExpected`, a P2SH input
/// adding its redeem script's (a non-standard redeem script with at most [`MAX_P2SH_SIGOPS`]
/// sigops, `OP_CHECKPQSIG` counted at 20, accepts the transaction as ycashd does).
pub fn are_inputs_standard(
    tx: &Transaction,
    spent_outputs: &[transparent::Output],
    state: Option<&dyn StateRead>,
) -> bool {
    if tx.is_coinbase() {
        return true;
    }
    if tx.inputs().len() != spent_outputs.len() {
        return false;
    }
    for (input, prev) in tx.inputs().iter().zip(spent_outputs) {
        let transparent::Input::PrevOut { unlock_script, .. } = input else {
            continue;
        };
        let script_sig = unlock_script.as_raw_bytes();
        let Some(kind) = solver(&prev.lock_script) else {
            return false;
        };
        let limit = if kind.is_pq() {
            MAX_STANDARD_PQ_SCRIPTSIG
        } else {
            MAX_STANDARD_SCRIPTSIG
        };
        if script_sig.len() > limit {
            return false;
        }
        match &kind {
            TxOutType::Vault(_) | TxOutType::Intent(_) => {
                if !is_standard_template_script_sig(
                    prev.lock_script.as_raw_bytes(),
                    script_sig,
                    state,
                ) {
                    return false;
                }
                continue;
            }
            TxOutType::PqPubKeyHash(id) => {
                let Some((s, p)) = pq_chunks(id.scheme) else {
                    return false;
                };
                match push_only_stack(script_sig) {
                    Some(stack) if stack.len() == s.saturating_add(p).saturating_add(2) => {}
                    _ => return false,
                }
                continue;
            }
            TxOutType::PqChannel(cp) => {
                let Some((s, p)) = pq_chunks(cp.client.scheme) else {
                    return false;
                };
                let Some(stack) = push_only_stack(script_sig) else {
                    return false;
                };
                let want = match stack.last().map(Vec::as_slice) {
                    Some([0x01]) => s.saturating_add(p).saturating_add(4),
                    Some([]) => s.saturating_add(p).saturating_add(3),
                    _ => return false,
                };
                if stack.len() != want {
                    return false;
                }
                continue;
            }
            TxOutType::Solver(_) => {}
        }

        let Some(mut args_expected) = script_sig_args_expected(&kind) else {
            return false;
        };
        let Some(stack) = push_only_stack(script_sig) else {
            return false;
        };

        if matches!(
            kind,
            TxOutType::Solver(solver::ScriptKind::ScriptHash { .. })
        ) {
            let Some(redeem) = stack.last() else {
                return false;
            };
            match solver(&transparent::Script::new(redeem)) {
                Some(inner) => match script_sig_args_expected(&inner) {
                    Some(n) => args_expected = args_expected.saturating_add(n),
                    None => return false,
                },
                None => {
                    // Any other script with at most 15 sigops (OP_CHECKPQSIG's 20 included)
                    // is OK, and so is the rest of the transaction (ycashd returns here).
                    let sigops = script::Code(redeem.clone())
                        .sig_op_count(true)
                        .saturating_add(pq_sig_op_count_script(redeem));
                    return sigops <= MAX_P2SH_SIGOPS;
                }
            }
        }

        if stack.len() != args_expected {
            return false;
        }
    }
    true
}

/// The transaction verifier's standardness pre-check for a mempool transaction, where
/// [`require_standard`] holds: ycashd's input rules (`IsStandardTx`'s scriptSig rules at the
/// next block's `height`, then `AreInputsStandard`), before script verification as in
/// `AcceptToMemoryPool`. The output rules of `IsStandardTx` run in the mempool storage, as
/// Zakura's do, so a transaction with a non-standard output *and* a failing script is
/// reject-consensus here and reject-policy on ycashd (finding W6-a/F-3).
pub fn mempool_standard_checks(
    tx: &Transaction,
    spent_outputs: &[transparent::Output],
    network: &Network,
    height: Height,
) -> Result<(), crate::error::TransactionError> {
    use crate::error::TransactionError;

    if tx.inputs().len() != spent_outputs.len() {
        return Err(TransactionError::Other(format!(
            "spent_outputs must align with transaction inputs for non-coinbase txs: inputs={}, spent_outputs={}",
            tx.inputs().len(),
            spent_outputs.len(),
        )));
    }
    if let Err((input_index, reason)) = standard_script_sigs(tx, network, height) {
        return Err(match reason {
            NonStandardReason::ScriptSigSize => TransactionError::NonStandardScriptSigSize {
                input_index,
                size: tx.inputs().get(input_index).map_or(0, |input| match input {
                    transparent::Input::PrevOut { unlock_script, .. } => {
                        unlock_script.as_raw_bytes().len()
                    }
                    transparent::Input::Coinbase { .. } => 0,
                }),
            },
            _ => TransactionError::NonStandardScriptSigNotPushOnly { input_index },
        });
    }
    if !are_inputs_standard(tx, spent_outputs, None) {
        return Err(TransactionError::NonStandardInputs);
    }
    Ok(())
}

// ---- STANDARD_SCRIPT_VERIFY_FLAGS -------------------------------------------------------------

/// Verifies every input of `tx` with the standard script verification flags at `height` (the
/// next block's): `STANDARD_SCRIPT_VERIFY_FLAGS | GetVaultScriptFlags(height)`. A failure of a
/// transaction that passed consensus verification is ycashd's
/// `non-mandatory-script-verify-flag` (REJECT_NONSTANDARD, DoS 0).
///
/// Returns the first failing input and its error.
///
/// The input spending a vault template (V/I) is skipped: its scripts read the set state at the
/// tip, which this check does not have, and the transaction verifier has already run it with the
/// standard flags and that state (kogany W6-c, `vault_mempool::check_template_input`).
pub fn standard_script_check(
    tx: Arc<Transaction>,
    spent_outputs: Arc<Vec<transparent::Output>>,
    network: &Network,
    height: Height,
) -> Result<(), (usize, zakura_script::Error)> {
    if tx.is_coinbase() {
        return Ok(());
    }
    let nu = NetworkUpgrade::current(network, height);
    let inputs = tx.inputs().len();
    let template_input = find_vault_template_input(
        spent_outputs
            .iter()
            .map(|o| Some(o.lock_script.as_raw_bytes())),
    );
    let cached = zakura_script::CachedFfiTransaction::new_on(network, tx, spent_outputs, nu)
        .map_err(|error| (0, error))?;
    let context =
        zakura_script::ScriptContext::new(network.clone(), height, None).with_standard_policy();
    for input_index in 0..inputs {
        if template_input == Some(input_index) {
            continue;
        }
        cached
            .is_valid_in(input_index, &context)
            .map_err(|error| (input_index, error))?;
    }
    Ok(())
}

// ---- the set-state classification of a template input's script error ----------------------

/// `FindVaultTemplateInput(tx, view)`: the index of the first input whose spent coin is an
/// exact V or I (`ParseVault` / `ParseIntent`, a MALFORMED shape is none), given each input's
/// spent scriptPubKey (`None`: the coin is missing).
pub fn find_vault_template_input<'a>(
    spent_scripts: impl IntoIterator<Item = Option<&'a [u8]>>,
) -> Option<usize> {
    spent_scripts.into_iter().position(|spk| {
        spk.is_some_and(|spk| parse_vault(spk).is_some() || parse_intent(spk).is_some())
    })
}

/// `IsVaultSetStateScriptError(scriptSig, err)`: does the template input's script error depend
/// on the set state at this node's tip? `OP_CHECKSETSIG`'s / `OP_CHECKSETDORMANT`'s failure,
/// and a failed `OP_VERIFY` under selector 3 (OWNER-RELEASED, whose only `OP_VERIFY` follows
/// `OP_CHECKSETDORMANT`). Never `SetSigCount`.
///
/// The forked interpreter reports `OP_EQUALVERIFY` and `OP_CHECKSIGVERIFY` failures as
/// [`interpreter::Error::Verify`] too (ycash6 has distinct codes); the V and I templates
/// contain neither opcode, so a template input's `Verify` is its `OP_VERIFY`.
pub fn is_vault_set_state_script_error(script_sig: &[u8], err: &interpreter::Error) -> bool {
    match err {
        interpreter::Error::SetSig => true,
        interpreter::Error::Verify => {
            parse_selector(script_sig).is_some_and(|(selector, _)| selector == SEL_RELEASED)
        }
        _ => false,
    }
}

/// `VaultTemplateFailsOnSetState(scriptSig, branch, prevBranch, run)`: `run(branch_id)`
/// evaluates the template input alone under that consensus branch ID: `Ok(())` on success,
/// `Err(Some(error))` for an interpreter error, `Err(None)` for any other failure (the script
/// left false). True: refuse at DoS 0 (a set-state-dependent failure). False: the stock route.
/// A set-state error that disappears under the previous epoch's branch ID takes the stock
/// route (old-consensus-branch-id). `run` is called at most twice.
pub fn vault_template_fails_on_set_state(
    script_sig: &[u8],
    consensus_branch_id: u32,
    prev_consensus_branch_id: u32,
    mut run: impl FnMut(u32) -> Result<(), Option<interpreter::Error>>,
) -> bool {
    let Err(Some(err)) = run(consensus_branch_id) else {
        return false;
    };
    if !is_vault_set_state_script_error(script_sig, &err) {
        return false;
    }
    if prev_consensus_branch_id != consensus_branch_id && run(prev_consensus_branch_id).is_ok() {
        return false;
    }
    true
}

#[cfg(test)]
mod tests;
