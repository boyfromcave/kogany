//! The vault primitive's script templates (upgrade plan §15.3; ycash6 `src/vault/template.*`):
//! the vault V and the intent I (bare scriptPubKeys, U-12) and the member bond B (a P2SH
//! redeem script).
//!
//! Builders emit the exact byte shapes with minimal pushes; parsers accept only those shapes
//! (match the opcode skeleton, read the fields, range-check them, rebuild and compare bytes).

use ripemd::Ripemd160;
use sha2::{Digest, Sha256};

use crate::bytes::{Hash32, PqOwner, PubKeyBytes, SetId, Tag};
use crate::script::{is_push_only, op::*, tokenize, Builder, Token};

/// `OP_CHECKSETSIG` role: unlock (U-13).
pub const ROLE_UNLOCK: u8 = 1;
/// `OP_CHECKSETSIG` role: cancel (U-13).
pub const ROLE_CANCEL: u8 = 2;

/// Selector 1 (the scriptSig's last push): V set unlock, I RELEASE.
pub const SEL_UNLOCK: u8 = 1;
/// Selector 2: V owner at height, I CANCEL.
pub const SEL_OWNER: u8 = 2;
/// Selector 3: V and I owner when the set is released.
pub const SEL_RELEASED: u8 = 3;
/// Selector 4: V only, the APP branch.
pub const SEL_APP: u8 = 4;

/// Smallest `delay` (§15.3).
pub const MIN_DELAY: i64 = 1;
/// Largest `delay` (§15.3; the BIP68 16-bit height field).
pub const MAX_DELAY: i64 = 65535;
/// Largest `ownerHeight`, `appHeight` and bond locktime: a height, never a time.
pub const MAX_TEMPLATE_HEIGHT: i64 = 499_999_999;

/// Registered owner scheme: SLH-DSA-SHA2-128s.
pub const PQ_SCHEME_SLH_DSA_SHA2_128S: u8 = 1;
/// Registered owner scheme: FN-DSA-512 (Falcon). Its activation is the interpreter's flag
/// (quantum spec A-1); the template accepts it.
pub const PQ_SCHEME_FN_DSA_512: u8 = 2;

/// A registered post-quantum scheme (C++ `pq::IsKnownScheme`: schemes 1 and 2). The script
/// crate's `OP_CHECKPQSIG` registry (kogany-pq, W3) must agree with this list.
pub fn is_known_pq_scheme(scheme: u8) -> bool {
    matches!(scheme, PQ_SCHEME_SLH_DSA_SHA2_128S | PQ_SCHEME_FN_DSA_512)
}

/// The vault V's parameters.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct VaultParams {
    /// The application tag.
    pub tag: Tag,
    /// The set whose cancel signatures stop an intent.
    pub cancel_set_id: SetId,
    /// The intent's BIP68 relative height delay, `MIN_DELAY..=MAX_DELAY`.
    pub delay: i64,
    /// The set whose unlock signatures release the vault.
    pub set_id: SetId,
    /// The owner branch's absolute height, `1..=MAX_TEMPLATE_HEIGHT`.
    pub owner_height: i64,
    /// The post-quantum owner.
    pub owner: PqOwner,
    /// The APP branch's absolute height, `0..=MAX_TEMPLATE_HEIGHT` (0 = no APP branch).
    pub app_height: i64,
}

/// The intent I's parameters.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct IntentParams {
    /// The application tag.
    pub tag: Tag,
    /// SHA256 (single) of the recipient scriptPubKey.
    pub recipient_hash: Hash32,
    /// SHA256 (single) of the originating V scriptPubKey.
    pub vault_hash: Hash32,
    /// The BIP68 relative height delay, `MIN_DELAY..=MAX_DELAY`.
    pub delay: i64,
    /// The set whose cancel signatures stop the intent.
    pub cancel_set_id: SetId,
    /// The set whose dormancy releases the owner.
    pub set_id: SetId,
    /// The post-quantum owner.
    pub owner: PqOwner,
}

/// Result of matching a scriptPubKey against a template. `Malformed` means the opcode skeleton
/// matches but a push is non-minimal or a field is out of range (§15.3: "a V-shaped output
/// outside them is not a template, rule V-1 then rejects it").
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Shape<T> {
    /// The skeleton does not match: not this template.
    NotTemplate,
    /// The exact template shape with in-range fields.
    Match(T),
    /// The skeleton matches, but the bytes are not the canonical template.
    Malformed,
}

impl<T> Shape<T> {
    /// The parameters of a `Match`.
    pub fn into_match(self) -> Option<T> {
        match self {
            Shape::Match(p) => Some(p),
            _ => None,
        }
    }
}

/// The owner scheme is registered.
pub fn is_owner_valid(owner: &PqOwner) -> bool {
    is_known_pq_scheme(owner.scheme)
}

/// Range check of a V's fields (C++ `VaultParamsValid`).
pub fn vault_params_valid(p: &VaultParams) -> bool {
    (MIN_DELAY..=MAX_DELAY).contains(&p.delay)
        && (1..=MAX_TEMPLATE_HEIGHT).contains(&p.owner_height)
        && (0..=MAX_TEMPLATE_HEIGHT).contains(&p.app_height)
        && is_owner_valid(&p.owner)
}

/// Range check of an I's fields (C++ `IntentParamsValid`).
pub fn intent_params_valid(p: &IntentParams) -> bool {
    (MIN_DELAY..=MAX_DELAY).contains(&p.delay) && is_owner_valid(&p.owner)
}

/// Builds V:
///
/// ```text
/// <tag> <cancelSetId> <delay> OP_2DROP OP_DROP
/// OP_DUP OP_1 OP_EQUAL OP_IF
///   OP_DROP <setId> OP_1 OP_CHECKSETSIG
/// OP_ELSE OP_DUP OP_2 OP_EQUAL OP_IF
///   OP_DROP <ownerHeight> OP_CHECKLOCKTIMEVERIFY OP_DROP <ownerHash> <scheme> OP_CHECKPQSIG
/// OP_ELSE OP_DUP OP_3 OP_EQUAL OP_IF
///   OP_DROP <setId> OP_CHECKSETDORMANT OP_VERIFY <ownerHash> <scheme> OP_CHECKPQSIG
/// OP_ELSE
///   OP_4 OP_EQUALVERIFY <appHeight> OP_CHECKLOCKTIMEVERIFY
/// OP_ENDIF OP_ENDIF OP_ENDIF
/// ```
///
/// `None` when the parameters are out of range (the C++ returns an empty script).
pub fn build_vault(p: &VaultParams) -> Option<Vec<u8>> {
    if !vault_params_valid(p) {
        return None;
    }
    let scheme = i64::from(p.owner.scheme);
    let owner = &p.owner.hash.0;
    let s = Builder::new()
        .push(&p.tag.0)
        .push(&p.cancel_set_id.0)
        .num(p.delay)
        .op(OP_2DROP)
        .op(OP_DROP)
        .op(OP_DUP)
        .op(OP_1)
        .op(OP_EQUAL)
        .op(OP_IF)
        .op(OP_DROP)
        .push(&p.set_id.0)
        .op(OP_1)
        .op(OP_CHECKSETSIG)
        .op(OP_ELSE)
        .op(OP_DUP)
        .op(OP_2)
        .op(OP_EQUAL)
        .op(OP_IF)
        .op(OP_DROP)
        .num(p.owner_height)
        .op(OP_CHECKLOCKTIMEVERIFY)
        .op(OP_DROP)
        .push(owner)
        .num(scheme)
        .op(OP_CHECKPQSIG)
        .op(OP_ELSE)
        .op(OP_DUP)
        .op(OP_3)
        .op(OP_EQUAL)
        .op(OP_IF)
        .op(OP_DROP)
        .push(&p.set_id.0)
        .op(OP_CHECKSETDORMANT)
        .op(OP_VERIFY)
        .push(owner)
        .num(scheme)
        .op(OP_CHECKPQSIG)
        .op(OP_ELSE)
        .op(OP_4)
        .op(OP_EQUALVERIFY)
        .num(p.app_height)
        .op(OP_CHECKLOCKTIMEVERIFY)
        .op(OP_ENDIF)
        .op(OP_ENDIF)
        .op(OP_ENDIF);
    Some(s.into_bytes())
}

/// Builds I:
///
/// ```text
/// <tag> <recipientHash> <vaultHash> OP_2DROP OP_DROP
/// OP_DUP OP_1 OP_EQUAL OP_IF
///   OP_DROP <delay> OP_CHECKSEQUENCEVERIFY
/// OP_ELSE OP_DUP OP_2 OP_EQUAL OP_IF
///   OP_DROP <cancelSetId> OP_2 OP_CHECKSETSIG
/// OP_ELSE
///   OP_3 OP_EQUALVERIFY <setId> OP_CHECKSETDORMANT OP_VERIFY <ownerHash> <scheme> OP_CHECKPQSIG
/// OP_ENDIF OP_ENDIF
/// ```
///
/// `None` when the parameters are out of range.
pub fn build_intent(p: &IntentParams) -> Option<Vec<u8>> {
    if !intent_params_valid(p) {
        return None;
    }
    let s = Builder::new()
        .push(&p.tag.0)
        .push(&p.recipient_hash.0)
        .push(&p.vault_hash.0)
        .op(OP_2DROP)
        .op(OP_DROP)
        .op(OP_DUP)
        .op(OP_1)
        .op(OP_EQUAL)
        .op(OP_IF)
        .op(OP_DROP)
        .num(p.delay)
        .op(OP_CHECKSEQUENCEVERIFY)
        .op(OP_ELSE)
        .op(OP_DUP)
        .op(OP_2)
        .op(OP_EQUAL)
        .op(OP_IF)
        .op(OP_DROP)
        .push(&p.cancel_set_id.0)
        .op(OP_2)
        .op(OP_CHECKSETSIG)
        .op(OP_ELSE)
        .op(OP_3)
        .op(OP_EQUALVERIFY)
        .push(&p.set_id.0)
        .op(OP_CHECKSETDORMANT)
        .op(OP_VERIFY)
        .push(&p.owner.hash.0)
        .num(i64::from(p.owner.scheme))
        .op(OP_CHECKPQSIG)
        .op(OP_ENDIF)
        .op(OP_ENDIF);
    Some(s.into_bytes())
}

/// A skeleton slot: a field (any push-type token) or an exact opcode.
#[derive(Clone, Copy)]
enum Slot {
    F,
    Op(u8),
}

use Slot::{Op, F};

/// V's skeleton; field positions: tag 0, cancelSetId 1, delay 2, setId 10, ownerHeight 19,
/// ownerHash 22, scheme 23, setId 31, ownerHash 34, scheme 35, appHeight 40.
#[rustfmt::skip]
const VAULT_SKELETON: [Slot; 45] = [
    F, F, F, Op(OP_2DROP), Op(OP_DROP), // 0..4
    Op(OP_DUP), Op(OP_1), Op(OP_EQUAL), Op(OP_IF), // 5..8
    Op(OP_DROP), F, Op(OP_1), Op(OP_CHECKSETSIG), // 9..12
    Op(OP_ELSE), Op(OP_DUP), Op(OP_2), Op(OP_EQUAL), Op(OP_IF), // 13..17
    Op(OP_DROP), F, Op(OP_CHECKLOCKTIMEVERIFY), Op(OP_DROP), F, F, Op(OP_CHECKPQSIG), // 18..24
    Op(OP_ELSE), Op(OP_DUP), Op(OP_3), Op(OP_EQUAL), Op(OP_IF), // 25..29
    Op(OP_DROP), F, Op(OP_CHECKSETDORMANT), Op(OP_VERIFY), F, F, Op(OP_CHECKPQSIG), // 30..36
    Op(OP_ELSE), Op(OP_4), Op(OP_EQUALVERIFY), F, Op(OP_CHECKLOCKTIMEVERIFY), // 37..41
    Op(OP_ENDIF), Op(OP_ENDIF), Op(OP_ENDIF), // 42..44
];

/// I's skeleton; field positions: tag 0, recipientHash 1, vaultHash 2, delay 10,
/// cancelSetId 18, setId 24, ownerHash 27, scheme 28.
#[rustfmt::skip]
const INTENT_SKELETON: [Slot; 32] = [
    F, F, F, Op(OP_2DROP), Op(OP_DROP), // 0..4
    Op(OP_DUP), Op(OP_1), Op(OP_EQUAL), Op(OP_IF), // 5..8
    Op(OP_DROP), F, Op(OP_CHECKSEQUENCEVERIFY), // 9..11
    Op(OP_ELSE), Op(OP_DUP), Op(OP_2), Op(OP_EQUAL), Op(OP_IF), // 12..16
    Op(OP_DROP), F, Op(OP_2), Op(OP_CHECKSETSIG), // 17..20
    Op(OP_ELSE), Op(OP_3), Op(OP_EQUALVERIFY), F, Op(OP_CHECKSETDORMANT), Op(OP_VERIFY), // 21..26
    F, F, Op(OP_CHECKPQSIG), // 27..29
    Op(OP_ENDIF), Op(OP_ENDIF), // 30..31
];

/// Tokenizes `spk` and matches it slot by slot against `skel`.
fn match_skeleton<'a>(spk: &'a [u8], skel: &[Slot]) -> Option<Vec<Token<'a>>> {
    let toks = tokenize(spk)?;
    if toks.len() != skel.len() {
        return None;
    }
    let ok = toks.iter().zip(skel).all(|(t, s)| match s {
        F => t.is_push(),
        Op(o) => t.op == *o,
    });
    ok.then_some(toks)
}

/// A pushed script number (at most 5 bytes, any encoding: minimality is checked by the
/// rebuild-and-compare step; C++ `TokNum`).
fn tok_num(t: &Token<'_>) -> Option<i64> {
    match t.op {
        OP_0 => return Some(0),
        OP_1NEGATE => return Some(-1),
        o if (OP_1..=OP_16).contains(&o) => return t.small_int().map(i64::from),
        o if o > OP_PUSHDATA4 => return None,
        _ => {}
    }
    let len = t.data.len();
    if len > 5 {
        return None;
    }
    let mut b = [0u8; 8];
    b.get_mut(..len)?.copy_from_slice(t.data);
    let mut neg = false;
    if let Some(last) = len.checked_sub(1).and_then(|i| b.get_mut(i)) {
        if *last & 0x80 != 0 {
            *last &= 0x7f;
            neg = true;
        }
    }
    let v = i64::try_from(u64::from_le_bytes(b)).ok()?;
    if neg {
        v.checked_neg()
    } else {
        Some(v)
    }
}

/// Exactly `N` bytes from a data push.
fn tok_bytes<const N: usize>(t: &Token<'_>) -> Option<[u8; N]> {
    if !t.is_data_push() {
        return None;
    }
    <[u8; N]>::try_from(t.data).ok()
}

/// The owner slot `<ownerHash:32> <scheme>`: the hash exactly 32 bytes, the scheme a number
/// (OP_1/OP_2 after the rebuild compare) in the registry.
fn tok_owner(hash: &Token<'_>, scheme: &Token<'_>) -> Option<PqOwner> {
    let h = tok_bytes::<32>(hash)?;
    let s = u8::try_from(tok_num(scheme)?).ok()?;
    is_known_pq_scheme(s).then_some(PqOwner {
        scheme: s,
        hash: Hash32(h),
    })
}

/// Token `i` of a matched skeleton (always present: the skeleton fixed the length).
fn at<'t, 'a>(t: &'t [Token<'a>], i: usize) -> Option<&'t Token<'a>> {
    t.get(i)
}

/// Matches a scriptPubKey against V (C++ `MatchVault`).
pub fn match_vault(spk: &[u8]) -> Shape<VaultParams> {
    let Some(t) = match_skeleton(spk, &VAULT_SKELETON) else {
        return Shape::NotTemplate;
    };
    let read = || -> Option<VaultParams> {
        let p = VaultParams {
            tag: Tag(tok_bytes::<4>(at(&t, 0)?)?),
            cancel_set_id: Hash32(tok_bytes::<32>(at(&t, 1)?)?),
            delay: tok_num(at(&t, 2)?)?,
            set_id: Hash32(tok_bytes::<32>(at(&t, 10)?)?),
            owner_height: tok_num(at(&t, 19)?)?,
            owner: tok_owner(at(&t, 22)?, at(&t, 23)?)?,
            app_height: tok_num(at(&t, 40)?)?,
        };
        let set_id2 = Hash32(tok_bytes::<32>(at(&t, 31)?)?);
        let owner2 = tok_owner(at(&t, 34)?, at(&t, 35)?)?;
        (set_id2 == p.set_id && owner2 == p.owner).then_some(p)
    };
    let Some(p) = read() else {
        return Shape::Malformed;
    };
    // Range check, then a non-minimal push anywhere fails the byte compare.
    match build_vault(&p) {
        Some(b) if b == spk => Shape::Match(p),
        _ => Shape::Malformed,
    }
}

/// Matches a scriptPubKey against I (C++ `MatchIntent`).
pub fn match_intent(spk: &[u8]) -> Shape<IntentParams> {
    let Some(t) = match_skeleton(spk, &INTENT_SKELETON) else {
        return Shape::NotTemplate;
    };
    let read = || -> Option<IntentParams> {
        Some(IntentParams {
            tag: Tag(tok_bytes::<4>(at(&t, 0)?)?),
            recipient_hash: Hash32(tok_bytes::<32>(at(&t, 1)?)?),
            vault_hash: Hash32(tok_bytes::<32>(at(&t, 2)?)?),
            delay: tok_num(at(&t, 10)?)?,
            cancel_set_id: Hash32(tok_bytes::<32>(at(&t, 18)?)?),
            set_id: Hash32(tok_bytes::<32>(at(&t, 24)?)?),
            owner: tok_owner(at(&t, 27)?, at(&t, 28)?)?,
        })
    };
    let Some(p) = read() else {
        return Shape::Malformed;
    };
    match build_intent(&p) {
        Some(b) if b == spk => Shape::Match(p),
        _ => Shape::Malformed,
    }
}

/// V's parameters, only for the exact byte shape with in-range fields (C++ `ParseVault`).
pub fn parse_vault(spk: &[u8]) -> Option<VaultParams> {
    match_vault(spk).into_match()
}

/// I's parameters, only for the exact byte shape with in-range fields (C++ `ParseIntent`).
pub fn parse_intent(spk: &[u8]) -> Option<IntentParams> {
    match_intent(spk).into_match()
}

/// SHA256 (single) of a script's bytes: `recipientHash` / `vaultHash` (C++ `ScriptHash256`).
pub fn script_hash256(script: &[u8]) -> Hash32 {
    Hash32(Sha256::digest(script).into())
}

/// The intent a V's UNLOCK/APP spend may create paying `recipient_script` (S-2; C++
/// `IntentFor`).
pub fn intent_for(v: &VaultParams, vault_spk: &[u8], recipient_script: &[u8]) -> IntentParams {
    IntentParams {
        tag: v.tag,
        recipient_hash: script_hash256(recipient_script),
        vault_hash: script_hash256(vault_spk),
        delay: v.delay,
        cancel_set_id: v.cancel_set_id,
        set_id: v.set_id,
        owner: v.owner,
    }
}

/// Bond B redeem script: `<locktime> OP_CHECKLOCKTIMEVERIFY OP_DROP <memberKey:33>
/// OP_CHECKSIG`. `None` when `locktime` is not in `1..=MAX_TEMPLATE_HEIGHT` or the key is not
/// compressed.
pub fn build_bond_redeem(locktime: u32, member_key: &PubKeyBytes) -> Option<Vec<u8>> {
    if !(1..=MAX_TEMPLATE_HEIGHT).contains(&i64::from(locktime)) || !member_key.is_compressed() {
        return None;
    }
    let s = Builder::new()
        .num(i64::from(locktime))
        .op(OP_CHECKLOCKTIMEVERIFY)
        .op(OP_DROP)
        .push(&member_key.0)
        .op(OP_CHECKSIG);
    Some(s.into_bytes())
}

/// Parses B: the locktime and member key, only for the exact canonical bytes (C++
/// `ParseBondRedeem`).
pub fn parse_bond_redeem(redeem: &[u8]) -> Option<(u32, PubKeyBytes)> {
    let t = tokenize(redeem)?;
    let [lt, cltv, drop, key, checksig] = t.as_slice() else {
        return None;
    };
    if !lt.is_push() {
        return None;
    }
    let lt = tok_num(lt)?;
    if cltv.op != OP_CHECKLOCKTIMEVERIFY || drop.op != OP_DROP || checksig.op != OP_CHECKSIG {
        return None;
    }
    let key = PubKeyBytes(tok_bytes::<33>(key)?);
    if !(1..=MAX_TEMPLATE_HEIGHT).contains(&lt) {
        return None;
    }
    let lt = u32::try_from(lt).ok()?;
    (build_bond_redeem(lt, &key)? == redeem).then_some((lt, key))
}

/// HASH160 (RIPEMD160 of SHA256) of a script: the P2SH script id.
pub fn hash160(data: &[u8]) -> [u8; 20] {
    Ripemd160::digest(Sha256::digest(data)).into()
}

/// `OP_HASH160 <hash160(redeem)> OP_EQUAL`.
pub fn p2sh_script_pubkey(redeem: &[u8]) -> Vec<u8> {
    Builder::new()
        .op(OP_HASH160)
        .push(&hash160(redeem))
        .op(OP_EQUAL)
        .into_bytes()
}

/// P2SH(B(memberKey, locktime)); `None` if B is (C++ `BondScriptPubKey`).
pub fn bond_script_pubkey(locktime: u32, member_key: &PubKeyBytes) -> Option<Vec<u8>> {
    build_bond_redeem(locktime, member_key).map(|r| p2sh_script_pubkey(&r))
}

/// The selector of a template input (C++ `ParseSelector`): the scriptSig must be non-empty and
/// push-only, and its last push exactly `OP_1..OP_4`. Returns the selector and every push
/// before it, as the interpreter would see them on the stack (`OP_n` as the byte `n`,
/// `OP_1NEGATE` as `0x81`, `OP_0` and `OP_RESERVED` as empty).
pub fn parse_selector(script_sig: &[u8]) -> Option<(u8, Vec<Vec<u8>>)> {
    if script_sig.is_empty() || !is_push_only(script_sig) {
        return None;
    }
    let t = tokenize(script_sig)?;
    let (last, before) = t.split_last()?;
    if !(OP_1..=OP_4).contains(&last.op) {
        return None;
    }
    let pushes = before
        .iter()
        .map(|t| match (t.small_int(), t.op) {
            (Some(n), _) => vec![n],
            (None, OP_1NEGATE) => vec![0x81],
            (None, _) => t.data.to_vec(),
        })
        .collect();
    Some((last.small_int()?, pushes))
}

/// Which template a spent coin is, with its parameters.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TemplateParams {
    /// A vault V.
    Vault(VaultParams),
    /// An intent I.
    Intent(IntentParams),
}

/// A template input as parsed from the spent coin's scriptPubKey and the input's scriptSig.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TemplateSpend {
    /// The spent template and its parameters.
    pub params: TemplateParams,
    /// The selector, `SEL_UNLOCK..=SEL_APP` for V, `SEL_UNLOCK..=SEL_RELEASED` for I.
    pub selector: u8,
    /// Every scriptSig push before the selector (set or owner signatures).
    pub sigs: Vec<Vec<u8>>,
}

impl TemplateSpend {
    /// A spend of a vault V.
    pub fn is_vault(&self) -> bool {
        matches!(self.params, TemplateParams::Vault(_))
    }
}

/// Parses a template input (C++ `ParseTemplateSpend`). `None` when the coin is not a template
/// (an exact `Match`), the scriptSig has no selector, or an I is given `OP_4` (A-10).
pub fn parse_template_spend(spent_spk: &[u8], script_sig: &[u8]) -> Option<TemplateSpend> {
    let params = if let Some(v) = parse_vault(spent_spk) {
        TemplateParams::Vault(v)
    } else {
        TemplateParams::Intent(parse_intent(spent_spk)?)
    };
    let (selector, sigs) = parse_selector(script_sig)?;
    if matches!(params, TemplateParams::Intent(_)) && selector == SEL_APP {
        return None;
    }
    Some(TemplateSpend {
        params,
        selector,
        sigs,
    })
}
