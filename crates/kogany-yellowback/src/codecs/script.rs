// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

//! Yellowback scripts (ycash6 `src/yellowback/script.{h,cpp}`; `MatchPQChannel` /
//! `GetScriptForPQChannel` / `GetScriptForPQKey` from `src/script/standard.cpp`, which TOK-PQ
//! reaches through [`holder_key`]). Existing opcodes only; the parsers are shape matchers, never
//! an interpreter.
//!
//! - **The YED vault** (U-23, IT-1): the vault primitive's V with `tag = YED\0`, `setId =
//!   cancelSetId = attestorSetId`, `delay = CLAIM_DELAY`, `ownerHeight = appHeight = refHeight + 1`
//!   ([`yed_vault_params`], [`yed_vault_script`]).
//! - **Holders** (TOK-PQ, quantum spec §3.5, D-Q-19): [`holder_key`] / [`holder_allowed`].
//! - **The carrier** (v3 §3.4, BUNDLE-1): `OP_SWAP OP_SHA256 <bundleHash> OP_EQUALVERIFY <pk>
//!   OP_CHECKSIG`, spent by `<bundle> <sig> <carrierScript>`.
//! - **The attestor bond** (v3 §3.4): `<locktime> OP_CHECKLOCKTIMEVERIFY OP_DROP <pk> OP_CHECKSIG`.
//! - **The v2 vault** (plan §3.4): refused for new mints since the upgrade (MINT-3) and read by no
//!   rule on the upgrade line; kept because the C++ module keeps it (its tests, its fuzzer).
//!
//! "Compressed" is the C++ `IsCompressedKey` (`CPubKey::IsValid() && IsCompressed()`): 33 bytes
//! with a `0x02`/`0x03` header, no curve check. Only the TX_PQCHANNEL server key is checked on the
//! curve (`IsFullyValid`), as `MatchPQChannel` does.

use kogany_vault::script::{op::*, tokenize, Builder, Token};
use kogany_vault::template::{build_vault, is_known_pq_scheme, VaultParams};
use kogany_vault::{Hash32, PqOwner, PubKeyBytes, Tag};

use crate::params::{Params, LOCKTIME_THRESHOLD};

/// Opcodes the Yellowback templates use beyond [`kogany_vault::script::op`].
pub mod op {
    /// `OP_NOP`.
    pub const OP_NOP: u8 = 0x61;
    /// `OP_NOTIF`.
    pub const OP_NOTIF: u8 = 0x64;
    /// `OP_SWAP`.
    pub const OP_SWAP: u8 = 0x7c;
    /// `OP_SHA256`.
    pub const OP_SHA256: u8 = 0xa8;
    /// `OP_HASH256`.
    pub const OP_HASH256: u8 = 0xaa;
    /// `OP_CHECKSIGVERIFY`.
    pub const OP_CHECKSIGVERIFY: u8 = 0xad;
    /// `OP_CHECKMULTISIG`.
    pub const OP_CHECKMULTISIG: u8 = 0xae;
    /// `OP_TRUE` (= `OP_1`).
    pub const OP_TRUE: u8 = 0x51;
}
use op::*;

/// The YED module's application tag in the primitive (`YED_TAG`): `"YED\0"`.
pub const YED_TAG: Tag = Tag(*b"YED\0");

/// The 33-byte compressed-key shape (`IsCompressedKey`): a `0x02`/`0x03` header, no curve check.
pub fn is_compressed_key(key: &[u8]) -> bool {
    key.len() == 33 && matches!(key.first(), Some(0x02 | 0x03))
}

/// `CPubKey::IsFullyValid` for a 33-byte key: compressed and on the curve.
fn is_fully_valid_key(key: &[u8]) -> bool {
    is_compressed_key(key) && secp256k1::PublicKey::from_slice(key).is_ok()
}

// ---------------------------------------------------------------- shared readers

/// `GetPushes`: the pushes of a push-only script (every opcode `<= OP_16`, so `OP_RESERVED`
/// counts) and their opcodes; `None` on any other opcode or a truncated push.
fn get_pushes(script: &[u8]) -> Option<Vec<Token<'_>>> {
    let t = tokenize(script)?;
    t.iter().all(|t| t.op <= OP_16).then_some(t)
}

/// The minimal `CScriptNum` of at most 5 bytes (`CScriptNum(data, true, 5)`); `None` for a
/// non-minimal encoding or more than 5 bytes. Empty is zero.
pub(crate) fn script_num_minimal(data: &[u8]) -> Option<i64> {
    if data.len() > 5 {
        return None;
    }
    if let Some((&last, init)) = data.split_last() {
        if last & 0x7f == 0 && init.last().is_none_or(|&b| b & 0x80 == 0) {
            return None;
        }
    }
    let mut v: i64 = 0;
    for &b in data.iter().rev() {
        v = v.checked_shl(8)?.checked_add(i64::from(b))?;
    }
    match data.last() {
        Some(&last) if last & 0x80 != 0 => {
            let bits = u32::try_from(data.len())
                .ok()?
                .checked_mul(8)?
                .checked_sub(1)?;
            let mask = 1i64.checked_shl(bits)?;
            Some(v.checked_sub(mask)?.checked_neg()?)
        }
        _ => Some(v),
    }
}

/// `ReadHeightPush`: `OP_1..OP_16` or a data push of 1..5 bytes holding a minimal
/// `CScriptNum`, in `1..LOCKTIME_THRESHOLD`. The push itself need not be minimal (`0x01 0x05` is
/// height 5), as in the C++.
fn read_height(t: &Token<'_>) -> Option<i64> {
    let h = if let Some(n) = t.small_int() {
        i64::from(n)
    } else if t.op <= OP_PUSHDATA4 && !t.data.is_empty() {
        script_num_minimal(t.data)?
    } else {
        return None;
    };
    (h > 0 && h < i64::from(LOCKTIME_THRESHOLD)).then_some(h)
}

/// A token of exactly `n` pushed bytes (any push opcode).
fn data_of<const N: usize>(t: &Token<'_>) -> Option<[u8; N]> {
    <[u8; N]>::try_from(t.data).ok()
}

/// `P2SHScript`: `OP_HASH160 <hash160(redeem)> OP_EQUAL`.
pub fn p2sh_script(redeem: &[u8]) -> Vec<u8> {
    kogany_vault::template::p2sh_script_pubkey(redeem)
}

/// `ExtractRedeemScript`: the last push of a push-only, non-empty scriptSig.
pub fn extract_redeem_script(script_sig: &[u8]) -> Option<Vec<u8>> {
    get_pushes(script_sig)?.last().map(|t| t.data.to_vec())
}

// ---------------------------------------------------------------- the vault upgrade (U-23)

/// `YedVaultParamsAt`: the V of a YED vault record, whatever its heights (a pre-IT-1 vault has
/// `ownerHeight = lockHeight`, `appHeight = lockHeight + GRACE`).
pub fn yed_vault_params_at(
    p: &Params,
    owner: &PqOwner,
    owner_height: i64,
    app_height: i64,
) -> VaultParams {
    let set = Hash32(p.attestor_set_id);
    VaultParams {
        tag: YED_TAG,
        cancel_set_id: set,
        delay: i64::from(p.claim_delay),
        set_id: set,
        owner_height,
        owner: *owner,
        app_height,
    }
}

/// `YedVaultParams`: a new mint's V (IT-1): `ownerHeight = appHeight = refHeight + 1`, so the
/// owner's redeem (selector 2) and the claim (selector 4) both open the block after the mint.
pub fn yed_vault_params(p: &Params, owner: &PqOwner, ref_height: i64) -> VaultParams {
    let h = ref_height.saturating_add(1);
    yed_vault_params_at(p, owner, h, h)
}

/// `YedVaultScriptAt`: `BuildVault(YedVaultParamsAt(...))`; `None` when YED has no attestor set
/// or a field is out of range (the caller's MINT-2/3 then fails).
pub fn yed_vault_script_at(
    p: &Params,
    owner: &PqOwner,
    owner_height: i64,
    app_height: i64,
) -> Option<Vec<u8>> {
    if p.attestor_set_id == [0u8; 32] {
        return None;
    }
    build_vault(&yed_vault_params_at(p, owner, owner_height, app_height))
}

/// `YedVaultScript`: a new mint's V script.
pub fn yed_vault_script(p: &Params, owner: &PqOwner, ref_height: i64) -> Option<Vec<u8>> {
    let h = ref_height.saturating_add(1);
    yed_vault_script_at(p, owner, h, h)
}

/// `OwnerFromBytes`: 33 bytes read as `scheme || keyHash`; scheme 0 and a zero hash (no owner)
/// for any other length.
pub fn owner_from_bytes(bytes: &[u8]) -> PqOwner {
    match bytes.split_first() {
        Some((&scheme, hash)) if bytes.len() == 33 => PqOwner {
            scheme,
            hash: Hash32::from_slice(hash).unwrap_or_default(),
        },
        _ => PqOwner::default(),
    }
}

// ---------------------------------------------------------------- holders (TOK-PQ)

/// The destination of a YED holder script (the C++ `CTxDestination` [`holder_key`] returns).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Holder {
    /// A 25-byte P2PKH's key hash (`CKeyID`).
    KeyId([u8; 20]),
    /// A TX_PQPKH's key, or a TX_PQCHANNEL's client (`CPQKeyID`).
    Pq(PqOwner),
}

/// `GetScriptForDestination(CKeyID)`: `OP_DUP OP_HASH160 <keyId> OP_EQUALVERIFY OP_CHECKSIG`.
pub fn p2pkh_script(key_id: &[u8; 20]) -> Vec<u8> {
    Builder::new()
        .op(OP_DUP)
        .op(OP_HASH160)
        .push(key_id)
        .op(OP_EQUALVERIFY)
        .op(OP_CHECKSIG)
        .into_bytes()
}

/// `GetScriptForPQKey`: the TX_PQPKH `<hash:32> OP_<scheme> OP_CHECKPQSIG` (35 bytes); `None`
/// unless the scheme is registered.
pub fn pq_key_script(owner: &PqOwner) -> Option<Vec<u8>> {
    if !is_known_pq_scheme(owner.scheme) {
        return None;
    }
    Some(
        Builder::new()
            .push(&owner.hash.0)
            .num(i64::from(owner.scheme))
            .op(OP_CHECKPQSIG)
            .into_bytes(),
    )
}

/// The parameters of a TX_PQCHANNEL (`PQChannelParams`, quantum spec D-Q-19).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PqChannelParams {
    /// The client (the YED holder).
    pub client: PqOwner,
    /// The server's secp256k1 key.
    pub server: PubKeyBytes,
    /// The refund branch's height, `1..LOCKTIME_THRESHOLD`.
    pub refund_height: i64,
}

/// `GetScriptForPQChannel`:
///
/// ```text
/// OP_IF <clientHash:32> OP_1|OP_2 OP_CHECKPQSIG OP_VERIFY <serverKey:33> OP_CHECKSIG
/// OP_ELSE <refundHeight> OP_CHECKLOCKTIMEVERIFY OP_DROP <clientHash:32> OP_1|OP_2 OP_CHECKPQSIG OP_ENDIF
/// ```
///
/// `None` unless the client scheme is registered, the server key is compressed and on the curve
/// and `refund_height` is in `1..LOCKTIME_THRESHOLD`. Consensus-reachable through TOK-PQ.
pub fn pq_channel_script(c: &PqChannelParams) -> Option<Vec<u8>> {
    if !is_known_pq_scheme(c.client.scheme) || !is_fully_valid_key(&c.server.0) {
        return None;
    }
    if c.refund_height < 1 || c.refund_height >= i64::from(LOCKTIME_THRESHOLD) {
        return None;
    }
    let scheme = i64::from(c.client.scheme);
    Some(
        Builder::new()
            .op(OP_IF)
            .push(&c.client.hash.0)
            .num(scheme)
            .op(OP_CHECKPQSIG)
            .op(OP_VERIFY)
            .push(&c.server.0)
            .op(OP_CHECKSIG)
            .op(OP_ELSE)
            .num(c.refund_height)
            .op(OP_CHECKLOCKTIMEVERIFY)
            .op(OP_DROP)
            .push(&c.client.hash.0)
            .num(scheme)
            .op(OP_CHECKPQSIG)
            .op(OP_ENDIF)
            .into_bytes(),
    )
}

/// `MatchPQChannel`: the fields of an exact TX_PQCHANNEL (decode the four fields by token, then
/// require the rebuilt script byte for byte: minimal pushes, identical client slots, a server
/// key on the curve). Consensus-reachable through TOK-PQ.
pub fn match_pq_channel(script: &[u8]) -> Option<PqChannelParams> {
    // 111 bytes + the refundHeight push (1..6).
    if !(112..=117).contains(&script.len())
        || script.first() != Some(&OP_IF)
        || script.last() != Some(&OP_ENDIF)
    {
        return None;
    }
    let ops = tokenize(script)?;
    let [_, hash, scheme_op, _, _, server, _, _, refund, ..] = ops.as_slice() else {
        return None;
    };
    if ops.len() != 15 {
        return None;
    }
    let hash = data_of::<32>(hash)?;
    let server = PubKeyBytes(data_of::<33>(server)?);
    let scheme = match scheme_op.op {
        OP_1 | OP_2 => scheme_op.small_int()?,
        _ => return None,
    };
    let refund_height = if let Some(n) = refund.small_int() {
        i64::from(n)
    } else if refund.op <= OP_PUSHDATA4 && !refund.data.is_empty() {
        script_num_minimal(refund.data)?
    } else {
        return None;
    };
    let c = PqChannelParams {
        client: PqOwner {
            scheme,
            hash: Hash32(hash),
        },
        server,
        refund_height,
    };
    if !is_fully_valid_key(&server.0) {
        return None;
    }
    (pq_channel_script(&c)?.as_slice() == script).then_some(c)
}

/// `HolderKey` (quantum plan §4.4, spec §3.5): the 25-byte P2PKH's key hash, the 35-byte
/// TX_PQPKH `20 <keyHash:32> OP_1|OP_2 OP_CHECKPQSIG`'s key (matched byte for byte, as Solver),
/// or a TX_PQCHANNEL's client (D-Q-19); `None` for any other script.
pub fn holder_key(s: &[u8]) -> Option<Holder> {
    if let [OP_DUP, OP_HASH160, 20, key @ .., OP_EQUALVERIFY, OP_CHECKSIG] = s {
        if let Ok(k) = <[u8; 20]>::try_from(key) {
            return Some(Holder::KeyId(k));
        }
    }
    if let [32, hash @ .., n @ (OP_1 | OP_2), OP_CHECKPQSIG] = s {
        if let Ok(h) = <[u8; 32]>::try_from(hash) {
            return Some(Holder::Pq(PqOwner {
                scheme: n.wrapping_sub(OP_1 - 1),
                hash: Hash32(h),
            }));
        }
    }
    match_pq_channel(s).map(|c| Holder::Pq(c.client))
}

/// `HolderAllowed`, TOK-PQ (quantum spec F-7, D-Q-19): below the Falcon height
/// ([`Params::is_pq_falcon_active`]) any script may hold YED; from it, only a TX_PQPKH of scheme
/// 0x02 (FN-DSA-512) or a TX_PQCHANNEL whose client is scheme 0x02.
pub fn holder_allowed(p: &Params, height: i64, script: &[u8]) -> bool {
    if !p.is_pq_falcon_active(height) {
        return true;
    }
    matches!(
        holder_key(script),
        Some(Holder::Pq(PqOwner {
            scheme: kogany_vault::template::PQ_SCHEME_FN_DSA_512,
            ..
        }))
    )
}

// ---------------------------------------------------------------- v3 (§3.4): carrier and bond

/// The carrier redeem script's size: `1 + 1 + (1 + 32) + 1 + (1 + 33) + 1`.
pub const CARRIER_SCRIPT_SIZE: usize = 71;

/// `CarrierScript`: `OP_SWAP OP_SHA256 <bundleHash 32> OP_EQUALVERIFY <pk 33> OP_CHECKSIG`;
/// `None` if the key is not compressed.
pub fn carrier_script(pk: &PubKeyBytes, bundle_hash: &Hash32) -> Option<Vec<u8>> {
    if !pk.is_compressed() {
        return None;
    }
    Some(
        Builder::new()
            .op(OP_SWAP)
            .op(OP_SHA256)
            .push(&bundle_hash.0)
            .op(OP_EQUALVERIFY)
            .push(&pk.0)
            .op(OP_CHECKSIG)
            .into_bytes(),
    )
}

/// `IsCarrierScript`: the key and the bundle hash of the exact 71-byte carrier template.
pub fn is_carrier_script(script: &[u8]) -> Option<(PubKeyBytes, Hash32)> {
    match script {
        [OP_SWAP, OP_SHA256, 32, rest @ ..] if script.len() == CARRIER_SCRIPT_SIZE => {
            let (hash, rest) = rest.split_at_checked(32)?;
            let [OP_EQUALVERIFY, 33, rest @ ..] = rest else {
                return None;
            };
            let [key @ .., OP_CHECKSIG] = rest else {
                return None;
            };
            let key = PubKeyBytes::from_slice(key)?;
            key.is_compressed()
                .then_some((key, Hash32::from_slice(hash)?))
        }
        _ => None,
    }
}

/// `CarrierScriptSig`: `<bundle> <sig> <carrierScript>`.
pub fn carrier_script_sig(bundle: &[u8], sig: &[u8], carrier: &[u8]) -> Vec<u8> {
    Builder::new()
        .push(bundle)
        .push(sig)
        .push(carrier)
        .into_bytes()
}

/// A carrier input's parts (`CarrierSpend`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CarrierSpend {
    /// The first push: the bundle bytes (whether `SHA256(bundle) == bundle_hash` is BUNDLE-1's).
    pub bundle: Vec<u8>,
    /// The second push: a DER signature with its hashtype byte.
    pub sig: Vec<u8>,
    /// The key from the redeem script.
    pub pk: PubKeyBytes,
    /// The bundle hash from the redeem script.
    pub bundle_hash: Hash32,
    /// The third push: the carrier redeem script.
    pub carrier_script: Vec<u8>,
}

/// `ParseCarrierScriptSig`: carrier identification by shape — exactly three data pushes
/// (`OP_0` counts; `OP_1..OP_16` do not), the third a carrier script. Nothing else is looked at.
pub fn parse_carrier_script_sig(script_sig: &[u8]) -> Option<CarrierSpend> {
    let pushes = get_pushes(script_sig)?;
    let [bundle, sig, carrier] = pushes.as_slice() else {
        return None;
    };
    if [bundle, sig, carrier].iter().any(|t| t.op > OP_PUSHDATA4) {
        return None;
    }
    let (pk, bundle_hash) = is_carrier_script(carrier.data)?;
    Some(CarrierSpend {
        bundle: bundle.data.to_vec(),
        sig: sig.data.to_vec(),
        pk,
        bundle_hash,
        carrier_script: carrier.data.to_vec(),
    })
}

/// Why a transaction has no carrier input ([`find_carrier_input`]; BUNDLE-1's reasons).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CarrierError {
    /// No input is carrier-shaped.
    Shape,
    /// Two or more inputs are.
    TwoCarriers,
}

impl CarrierError {
    /// The C++ reason string: `"shape"` or `"two-carriers"`.
    pub const fn reason(self) -> &'static str {
        match self {
            CarrierError::Shape => "shape",
            CarrierError::TwoCarriers => "two-carriers",
        }
    }
}

/// `FindCarrierInput`: the index of the transaction's one carrier-shaped input, given its input
/// scriptSigs in order, skipping input 0 when asked (a REDEEM's vault input is never one).
pub fn find_carrier_input<S: AsRef<[u8]>>(
    script_sigs: &[S],
    skip_vin0: bool,
) -> Result<usize, CarrierError> {
    let mut found = None;
    for (i, s) in script_sigs.iter().enumerate().skip(usize::from(skip_vin0)) {
        if parse_carrier_script_sig(s.as_ref()).is_none() {
            continue;
        }
        if found.is_some() {
            return Err(CarrierError::TwoCarriers);
        }
        found = Some(i);
    }
    found.ok_or(CarrierError::Shape)
}

/// `BondScript`: `<locktime> OP_CHECKLOCKTIMEVERIFY OP_DROP <pk 33> OP_CHECKSIG`; `None` if the
/// locktime is not in `1..LOCKTIME_THRESHOLD` or the key is not compressed.
pub fn bond_script(pk: &PubKeyBytes, locktime: u32) -> Option<Vec<u8>> {
    if locktime == 0 || locktime >= LOCKTIME_THRESHOLD || !pk.is_compressed() {
        return None;
    }
    Some(
        Builder::new()
            .num(i64::from(locktime))
            .op(OP_CHECKLOCKTIMEVERIFY)
            .op(OP_DROP)
            .push(&pk.0)
            .op(OP_CHECKSIG)
            .into_bytes(),
    )
}

/// `ParseBondScript`: the key and locktime of the bond template (the height a minimal number,
/// the key any 33-byte compressed push).
pub fn parse_bond_script(script: &[u8]) -> Option<(PubKeyBytes, u32)> {
    let t = tokenize(script)?;
    let [lock, cltv, drop, key, checksig] = t.as_slice() else {
        return None;
    };
    let lock = read_height(lock)?;
    if cltv.op != OP_CHECKLOCKTIMEVERIFY || drop.op != OP_DROP {
        return None;
    }
    let key = PubKeyBytes(data_of::<33>(key)?);
    if !key.is_compressed() || checksig.op != OP_CHECKSIG {
        return None;
    }
    Some((key, u32::try_from(lock).ok()?))
}

// ---------------------------------------------------------------- v2 (§3.4)

/// The v2 vault redeem script (`VaultScript`):
///
/// ```text
/// OP_IF <lockHeight> OP_CHECKLOCKTIMEVERIFY OP_DROP <ownerPubKey> OP_CHECKSIG
/// OP_ELSE <claimHeight> OP_CHECKLOCKTIMEVERIFY OP_DROP OP_TRUE OP_ENDIF
/// ```
///
/// `None` if a height is not in `1..LOCKTIME_THRESHOLD`, `claim <= lock`, or the key is not
/// compressed. Refused for new mints since the vault upgrade (MINT-3).
pub fn v2_vault_script(
    lock_height: u32,
    owner: &PubKeyBytes,
    claim_height: u32,
) -> Option<Vec<u8>> {
    if lock_height == 0 || lock_height >= LOCKTIME_THRESHOLD {
        return None;
    }
    if claim_height <= lock_height || claim_height >= LOCKTIME_THRESHOLD || !owner.is_compressed() {
        return None;
    }
    Some(
        Builder::new()
            .op(OP_IF)
            .num(i64::from(lock_height))
            .op(OP_CHECKLOCKTIMEVERIFY)
            .op(OP_DROP)
            .push(&owner.0)
            .op(OP_CHECKSIG)
            .op(OP_ELSE)
            .num(i64::from(claim_height))
            .op(OP_CHECKLOCKTIMEVERIFY)
            .op(OP_DROP)
            .op(OP_TRUE)
            .op(OP_ENDIF)
            .into_bytes(),
    )
}

/// The parts of a v2 vault script.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct V2Vault {
    /// The owner branch's height.
    pub lock_height: u32,
    /// The owner's key.
    pub owner: PubKeyBytes,
    /// The claim branch's height.
    pub claim_height: u32,
}

/// `ParseVaultScript`: the parts of the exact v2 template (heights minimal numbers, claim above
/// lock, a compressed key).
pub fn parse_v2_vault_script(script: &[u8]) -> Option<V2Vault> {
    let t = tokenize(script)?;
    let [if_, lock, cltv1, drop1, key, checksig, else_, claim, cltv2, drop2, true_, endif] =
        t.as_slice()
    else {
        return None;
    };
    if if_.op != OP_IF {
        return None;
    }
    let lock = read_height(lock)?;
    if cltv1.op != OP_CHECKLOCKTIMEVERIFY || drop1.op != OP_DROP {
        return None;
    }
    let owner = PubKeyBytes(data_of::<33>(key)?);
    if !owner.is_compressed() || checksig.op != OP_CHECKSIG || else_.op != OP_ELSE {
        return None;
    }
    let claim = read_height(claim)?;
    if cltv2.op != OP_CHECKLOCKTIMEVERIFY
        || drop2.op != OP_DROP
        || true_.op != OP_TRUE
        || endif.op != OP_ENDIF
        || claim <= lock
    {
        return None;
    }
    Some(V2Vault {
        lock_height: u32::try_from(lock).ok()?,
        owner,
        claim_height: u32::try_from(claim).ok()?,
    })
}

/// `OwnerScriptSig`: `<ownerSig> OP_1 <vaultScript>`.
pub fn owner_script_sig(owner_sig: &[u8], vault_script: &[u8]) -> Vec<u8> {
    Builder::new()
        .push(owner_sig)
        .op(OP_1)
        .push(vault_script)
        .into_bytes()
}

/// `ClaimScriptSig`: `OP_0 <vaultScript>`.
pub fn claim_script_sig(vault_script: &[u8]) -> Vec<u8> {
    Builder::new().op(OP_0).push(vault_script).into_bytes()
}

/// The path a v2 vault spend takes, as `OP_IF` would evaluate its selector (`VaultSpendPath`, K4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VaultSpendPath {
    /// `CastToBool(selector)`: true = owner branch, false = claim branch.
    pub owner_path: bool,
    /// The stack element of the push before the redeem script (empty for `OP_0`; the number
    /// for `OP_1..OP_16`, `0x81` for `OP_1NEGATE`).
    pub selector: Vec<u8>,
    /// The last push.
    pub vault_script: Vec<u8>,
    /// The push before the selector as a stack element, if any (empty otherwise).
    pub owner_sig: Vec<u8>,
    /// The number of pushes.
    pub pushes: usize,
}

/// What `EvalScript` pushes for a push opcode: the data, or the small number for `OP_1NEGATE` /
/// `OP_1..OP_16`.
fn stack_element(t: &Token<'_>) -> Vec<u8> {
    if t.op == OP_1NEGATE {
        vec![0x81]
    } else if let Some(n) = t.small_int() {
        vec![n]
    } else {
        t.data.to_vec()
    }
}

/// The interpreter's truth test: any non-zero byte, except a negative zero.
fn cast_to_bool(v: &[u8]) -> bool {
    match v.iter().position(|&b| b != 0) {
        Some(i) => !(i.checked_add(1) == Some(v.len()) && v.get(i) == Some(&0x80)),
        None => false,
    }
}

/// `ParseVaultSpendPath`: path detection for RED-4. `None` iff the scriptSig is not push-only or
/// has fewer than two pushes. Whether the shape is the wallet's exact `<sig> OP_1 <script>` /
/// `OP_0 <script>` is strict-template policy (TPL-2), not decided here.
pub fn parse_vault_spend_path(script_sig: &[u8]) -> Option<VaultSpendPath> {
    let pushes = get_pushes(script_sig)?;
    let [.., sel, last] = pushes.as_slice() else {
        return None;
    };
    let selector = stack_element(sel);
    let owner_sig = match pushes.as_slice() {
        [.., sig, _, _] => stack_element(sig),
        _ => Vec::new(),
    };
    Some(VaultSpendPath {
        owner_path: cast_to_bool(&selector),
        selector,
        vault_script: last.data.to_vec(),
        owner_sig,
        pushes: pushes.len(),
    })
}
