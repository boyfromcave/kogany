//! The `YV` OP_RETURN act codec (upgrade plan §15.5; ycash6 `src/vault/act.*`) and the two
//! signed messages (`actMsg`, §15.5; `setSigMsg`, §15.2 step 4).
//!
//! ```text
//! OP_RETURN <P> [<S_1> ... <S_n>]
//! P   = "YV" || 0x01 || type u8 || body      (integers little-endian, fixed width)
//! S_i = 65-byte recoverable compact signature over actMsg
//! ```
//!
//! Decoding is bounds-checked and total; `encode(decode(x)) == x` is required, so pushes are
//! minimal.

use secp256k1::ecdsa::{RecoverableSignature, RecoveryId};
use secp256k1::{Message, PublicKey, SecretKey};
use sha2::{Digest, Sha256};

use crate::bytes::{Hash32, OutPoint, PubKeyBytes, RecoverableSig, SetId};
use crate::script::{get_op, op::OP_RETURN, Builder};

/// First magic byte, `'Y'`.
pub const ACT_MAGIC_0: u8 = 0x59;
/// Second magic byte, `'V'`.
pub const ACT_MAGIC_1: u8 = 0x56;
/// The act encoding version.
pub const ACT_VERSION: u8 = 0x01;

/// `SET_CREATE`.
pub const ACT_SET_CREATE: u8 = 0x01;
/// `SET_JOIN`.
pub const ACT_SET_JOIN: u8 = 0x02;
/// `SET_HEARTBEAT`.
pub const ACT_SET_HEARTBEAT: u8 = 0x03;
/// `SET_REMOVE`.
pub const ACT_SET_REMOVE: u8 = 0x04;
/// `SET_EQUIVOCATION`.
pub const ACT_SET_EQUIVOCATION: u8 = 0x05;
/// `SET_WINDDOWN`.
pub const ACT_SET_WINDDOWN: u8 = 0x06;

/// The `SET_CREATE` flag for an open set.
pub const SET_FLAG_OPEN: u8 = 0x01;
/// Most seats in a set.
pub const MAX_SET_SEATS: u8 = 15;
/// Most signatures after the payload: a closed `SET_JOIN`'s joiner plus `slashThreshold <=
/// seats` cosigners. More is `bad-vault-act-sigs` at decode, before any recovery.
pub const MAX_ACT_SIGS: usize = 1 + MAX_SET_SEATS as usize;
/// Largest `rateWindow` / `livenessWindow`.
pub const MAX_SET_WINDOW: u32 = 1_048_576;
/// Largest `rateLimitBps`.
pub const MAX_RATE_BPS: u16 = 10_000;
/// The size of a recoverable compact signature.
pub const RECOVERABLE_SIG_SIZE: usize = 65;
/// `MAX_MONEY` (21,000,000 YEC in zatoshis): the upper bound of `bondMin` (D-1).
pub const MAX_MONEY: i64 = 2_100_000_000_000_000;

/// The fixed body size of an act type (§15.5); `None` for an unknown type.
pub fn act_body_size(act_type: u8) -> Option<usize> {
    match act_type {
        ACT_SET_CREATE => Some(64),
        ACT_SET_JOIN => Some(70),
        ACT_SET_HEARTBEAT => Some(65),
        ACT_SET_REMOVE => Some(66),
        ACT_SET_EQUIVOCATION => Some(264),
        ACT_SET_WINDDOWN => Some(32),
        _ => None,
    }
}

/// `SET_CREATE` body (64 bytes): the set's parameters.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SetCreateBody {
    /// Seats, `1..=MAX_SET_SEATS`.
    pub seats: u8,
    /// Unlock signatures required, `1..=seats`.
    pub unlock_threshold: u8,
    /// Cancel signatures required, `1..=seats`.
    pub cancel_threshold: u8,
    /// Slash (remove, wind-down, admission) signatures required, `1..=seats`.
    pub slash_threshold: u8,
    /// Flags; only `SET_FLAG_OPEN` is defined.
    pub flags: u8,
    /// Unlock rate limit in basis points of locked value per window, `0..=MAX_RATE_BPS`.
    pub rate_limit_bps: u16,
    /// Rate window in blocks, `1..=MAX_SET_WINDOW`.
    pub rate_window: u32,
    /// Liveness window in blocks, `1..=MAX_SET_WINDOW`.
    pub liveness_window: u32,
    /// Minimum bond in zatoshis, `1..=MAX_MONEY`.
    pub bond_min: i64,
    /// Minimum bond lock in blocks.
    pub bond_lock_min: u32,
    /// Blocks before a joined member's seat counts.
    pub maturity: u32,
    /// The admission key.
    pub admit_key: PubKeyBytes,
}

impl SetCreateBody {
    /// An open set.
    pub fn is_open(&self) -> bool {
        self.flags & SET_FLAG_OPEN != 0
    }

    /// The `SET_CREATE` parameter rules (§15.5 row 0x01; C++ `SetCreateBody::Valid`).
    pub fn valid(&self) -> bool {
        let seats = 1..=self.seats;
        (1..=MAX_SET_SEATS).contains(&self.seats)
            && seats.contains(&self.unlock_threshold)
            && seats.contains(&self.cancel_threshold)
            && seats.contains(&self.slash_threshold)
            && self.rate_limit_bps <= MAX_RATE_BPS
            && (1..=MAX_SET_WINDOW).contains(&self.rate_window)
            && (1..=MAX_SET_WINDOW).contains(&self.liveness_window)
            && (1..=MAX_MONEY).contains(&self.bond_min)
            && self.admit_key.is_compressed()
            && self.flags & !SET_FLAG_OPEN == 0
    }
}

/// `SET_JOIN` body (70 bytes).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SetJoinBody {
    /// The set joined.
    pub set_id: SetId,
    /// The joining member's key.
    pub member_key: PubKeyBytes,
    /// The bond B's locktime, `1..500_000_000`.
    pub bond_locktime: u32,
    /// The output of this transaction that is the bond.
    pub bond_vout: u8,
}

/// `SET_HEARTBEAT` body (65 bytes).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SetHeartbeatBody {
    /// The set.
    pub set_id: SetId,
    /// The member proving liveness.
    pub member_key: PubKeyBytes,
}

/// `SET_REMOVE` body (66 bytes).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SetRemoveBody {
    /// The set.
    pub set_id: SetId,
    /// The member removed.
    pub member_key: PubKeyBytes,
    /// 1 burns the bond, 0 returns it.
    pub burn: u8,
}

/// `SET_EQUIVOCATION` body (264 bytes): two conflicting set signatures by one member over the
/// same prevout.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SetEquivocationBody {
    /// The set.
    pub set_id: SetId,
    /// The template input both signatures sign.
    pub prevout: OutPoint,
    /// The first signature's role (1 or 2).
    pub role_a: u8,
    /// The first signature's sighash.
    pub sighash_a: Hash32,
    /// The first signature.
    pub sig_a: RecoverableSig,
    /// The second signature's role (1 or 2).
    pub role_b: u8,
    /// The second signature's sighash.
    pub sighash_b: Hash32,
    /// The second signature.
    pub sig_b: RecoverableSig,
}

/// `SET_WINDDOWN` body (32 bytes).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SetWindDownBody {
    /// The set.
    pub set_id: SetId,
}

/// An act's typed body; the variant is the act type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ActBody {
    /// `SET_CREATE` (0x01).
    Create(SetCreateBody),
    /// `SET_JOIN` (0x02).
    Join(SetJoinBody),
    /// `SET_HEARTBEAT` (0x03).
    Heartbeat(SetHeartbeatBody),
    /// `SET_REMOVE` (0x04).
    Remove(SetRemoveBody),
    /// `SET_EQUIVOCATION` (0x05).
    Equivocation(SetEquivocationBody),
    /// `SET_WINDDOWN` (0x06).
    WindDown(SetWindDownBody),
}

impl ActBody {
    /// The act type byte.
    pub fn act_type(&self) -> u8 {
        match self {
            ActBody::Create(_) => ACT_SET_CREATE,
            ActBody::Join(_) => ACT_SET_JOIN,
            ActBody::Heartbeat(_) => ACT_SET_HEARTBEAT,
            ActBody::Remove(_) => ACT_SET_REMOVE,
            ActBody::Equivocation(_) => ACT_SET_EQUIVOCATION,
            ActBody::WindDown(_) => ACT_SET_WINDDOWN,
        }
    }

    /// The set the act names; `None` for `SET_CREATE`, whose set is its own txid (the C++
    /// returns a null id).
    pub fn target_set(&self) -> Option<SetId> {
        match self {
            ActBody::Create(_) => None,
            ActBody::Join(b) => Some(b.set_id),
            ActBody::Heartbeat(b) => Some(b.set_id),
            ActBody::Remove(b) => Some(b.set_id),
            ActBody::Equivocation(b) => Some(b.set_id),
            ActBody::WindDown(b) => Some(b.set_id),
        }
    }
}

/// A decoded act: its body and the signatures `S_1..S_n` that follow the payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Act {
    /// The typed body.
    pub body: ActBody,
    /// The signatures, at most `MAX_ACT_SIGS`.
    pub sigs: Vec<RecoverableSig>,
}

/// Why an act does not decode; each maps to the C++ reject string.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ActError {
    /// `bad-vault-act-malformed`: magic, size, carrier or push encoding.
    Malformed,
    /// `bad-vault-act-version`.
    Version,
    /// `bad-vault-act-type`.
    Type,
    /// `bad-vault-act-sigs`: more than `MAX_ACT_SIGS` signatures.
    Sigs,
}

impl ActError {
    /// The C++ reject reason.
    pub fn reject_reason(&self) -> &'static str {
        match self {
            ActError::Malformed => "bad-vault-act-malformed",
            ActError::Version => "bad-vault-act-version",
            ActError::Type => "bad-vault-act-type",
            ActError::Sigs => "bad-vault-act-sigs",
        }
    }
}

/// Little-endian fixed-width reader over a payload body; every read fails past the end.
struct Reader<'a> {
    rest: &'a [u8],
}

impl<'a> Reader<'a> {
    fn take<const N: usize>(&mut self) -> Option<[u8; N]> {
        let (head, rest) = self.rest.split_at_checked(N)?;
        self.rest = rest;
        head.try_into().ok()
    }
    fn u8(&mut self) -> Option<u8> {
        self.take::<1>().map(|[b]| b)
    }
    fn u16(&mut self) -> Option<u16> {
        self.take().map(u16::from_le_bytes)
    }
    fn u32(&mut self) -> Option<u32> {
        self.take().map(u32::from_le_bytes)
    }
    fn i64(&mut self) -> Option<i64> {
        self.take().map(i64::from_le_bytes)
    }
    fn hash(&mut self) -> Option<Hash32> {
        self.take().map(Hash32)
    }
    fn key(&mut self) -> Option<PubKeyBytes> {
        self.take().map(PubKeyBytes)
    }
    fn sig(&mut self) -> Option<RecoverableSig> {
        self.take().map(RecoverableSig)
    }
    fn outpoint(&mut self) -> Option<OutPoint> {
        Some(OutPoint {
            txid: self.hash()?,
            n: self.u32()?,
        })
    }
}

/// `P = "YV" || version || type || body` (C++ `EncodePayload`).
pub fn encode_payload(body: &ActBody) -> Vec<u8> {
    let mut w = vec![ACT_MAGIC_0, ACT_MAGIC_1, ACT_VERSION, body.act_type()];
    match body {
        ActBody::Create(c) => {
            w.extend_from_slice(&[
                c.seats,
                c.unlock_threshold,
                c.cancel_threshold,
                c.slash_threshold,
                c.flags,
            ]);
            w.extend_from_slice(&c.rate_limit_bps.to_le_bytes());
            w.extend_from_slice(&c.rate_window.to_le_bytes());
            w.extend_from_slice(&c.liveness_window.to_le_bytes());
            w.extend_from_slice(&c.bond_min.to_le_bytes());
            w.extend_from_slice(&c.bond_lock_min.to_le_bytes());
            w.extend_from_slice(&c.maturity.to_le_bytes());
            w.extend_from_slice(&c.admit_key.0);
        }
        ActBody::Join(j) => {
            w.extend_from_slice(&j.set_id.0);
            w.extend_from_slice(&j.member_key.0);
            w.extend_from_slice(&j.bond_locktime.to_le_bytes());
            w.push(j.bond_vout);
        }
        ActBody::Heartbeat(h) => {
            w.extend_from_slice(&h.set_id.0);
            w.extend_from_slice(&h.member_key.0);
        }
        ActBody::Remove(r) => {
            w.extend_from_slice(&r.set_id.0);
            w.extend_from_slice(&r.member_key.0);
            w.push(r.burn);
        }
        ActBody::Equivocation(e) => {
            w.extend_from_slice(&e.set_id.0);
            w.extend_from_slice(&e.prevout.to_bytes());
            w.push(e.role_a);
            w.extend_from_slice(&e.sighash_a.0);
            w.extend_from_slice(&e.sig_a.0);
            w.push(e.role_b);
            w.extend_from_slice(&e.sighash_b.0);
            w.extend_from_slice(&e.sig_b.0);
        }
        ActBody::WindDown(d) => w.extend_from_slice(&d.set_id.0),
    }
    w
}

/// The full OP_RETURN script: `OP_RETURN <P> <S_1>...<S_n>` (C++ `EncodeAct`).
pub fn encode_act(act: &Act) -> Vec<u8> {
    let mut b = Builder::new()
        .op(OP_RETURN)
        .push(&encode_payload(&act.body));
    for s in &act.sigs {
        b = b.push(&s.0);
    }
    b.into_bytes()
}

/// Decodes only the payload `P` (C++ `DecodePayload`).
pub fn decode_payload(p: &[u8]) -> Result<ActBody, ActError> {
    let [m0, m1, version, act_type, body @ ..] = p else {
        return Err(ActError::Malformed);
    };
    if *m0 != ACT_MAGIC_0 || *m1 != ACT_MAGIC_1 {
        return Err(ActError::Malformed);
    }
    if *version != ACT_VERSION {
        return Err(ActError::Version);
    }
    let size = act_body_size(*act_type).ok_or(ActError::Type)?;
    if body.len() != size {
        return Err(ActError::Malformed);
    }
    let mut r = Reader { rest: body };
    let read = |r: &mut Reader<'_>| -> Option<ActBody> {
        Some(match *act_type {
            ACT_SET_CREATE => ActBody::Create(SetCreateBody {
                seats: r.u8()?,
                unlock_threshold: r.u8()?,
                cancel_threshold: r.u8()?,
                slash_threshold: r.u8()?,
                flags: r.u8()?,
                rate_limit_bps: r.u16()?,
                rate_window: r.u32()?,
                liveness_window: r.u32()?,
                bond_min: r.i64()?,
                bond_lock_min: r.u32()?,
                maturity: r.u32()?,
                admit_key: r.key()?,
            }),
            ACT_SET_JOIN => ActBody::Join(SetJoinBody {
                set_id: r.hash()?,
                member_key: r.key()?,
                bond_locktime: r.u32()?,
                bond_vout: r.u8()?,
            }),
            ACT_SET_HEARTBEAT => ActBody::Heartbeat(SetHeartbeatBody {
                set_id: r.hash()?,
                member_key: r.key()?,
            }),
            ACT_SET_REMOVE => ActBody::Remove(SetRemoveBody {
                set_id: r.hash()?,
                member_key: r.key()?,
                burn: r.u8()?,
            }),
            ACT_SET_EQUIVOCATION => ActBody::Equivocation(SetEquivocationBody {
                set_id: r.hash()?,
                prevout: r.outpoint()?,
                role_a: r.u8()?,
                sighash_a: r.hash()?,
                sig_a: r.sig()?,
                role_b: r.u8()?,
                sighash_b: r.hash()?,
                sig_b: r.sig()?,
            }),
            ACT_SET_WINDDOWN => ActBody::WindDown(SetWindDownBody { set_id: r.hash()? }),
            _ => return None,
        })
    };
    let decoded = read(&mut r).ok_or(ActError::Malformed)?;
    if !r.rest.is_empty() {
        return Err(ActError::Malformed);
    }
    Ok(decoded)
}

/// The first push after `OP_RETURN` and the position after it, when it is a data push.
fn act_payload_push(spk: &[u8]) -> Option<(&[u8], usize)> {
    let (&first, _) = spk.split_first()?;
    if first != OP_RETURN {
        return None;
    }
    let (t, next) = get_op(spk, 1)?;
    t.is_data_push().then_some((t.data, next))
}

/// `OP_RETURN` followed by a data push that begins `"YV"` (C++ `IsActOutput`). Such an output
/// is an act and must decode.
pub fn is_act_output(spk: &[u8]) -> bool {
    matches!(
        act_payload_push(spk),
        Some(([ACT_MAGIC_0, ACT_MAGIC_1, ..], _))
    )
}

/// Decodes a `YV` output (C++ `DecodeAct`): the payload, then at most `MAX_ACT_SIGS`
/// 65-byte data pushes, and the canonical encoding must reproduce the script byte for byte.
pub fn decode_act(spk: &[u8]) -> Result<Act, ActError> {
    if !is_act_output(spk) {
        return Err(ActError::Malformed);
    }
    let (p, mut pos) = act_payload_push(spk).ok_or(ActError::Malformed)?;
    let body = decode_payload(p)?;
    let mut sigs = Vec::new();
    while pos < spk.len() {
        let (t, next) = get_op(spk, pos).ok_or(ActError::Malformed)?;
        if !t.is_data_push() {
            return Err(ActError::Malformed);
        }
        let sig = RecoverableSig::from_slice(t.data).ok_or(ActError::Malformed)?;
        // Before the push, so at most MAX_ACT_SIGS are stored and the rest of a huge output
        // is not walked (W3-V-2).
        if sigs.len() >= MAX_ACT_SIGS {
            return Err(ActError::Sigs);
        }
        sigs.push(sig);
        pos = next;
    }
    let act = Act { body, sigs };
    if encode_act(&act) != spk {
        return Err(ActError::Malformed);
    }
    Ok(act)
}

/// A signature header in 31..34 (recoverable, compressed).
fn sig_header_ok(sig: &RecoverableSig) -> bool {
    (31..=34).contains(&sig.header())
}

/// An `OP_CHECKSETSIG` role, 1 or 2.
fn role_ok(role: u8) -> bool {
    role == 1 || role == 2
}

/// The context-free field rules of §15.5 that the decoder does not apply (C++
/// `ActFieldsValid`): `SET_CREATE` ranges, compressed keys, `SET_JOIN` `bondLocktime` in
/// `1..500_000_000`, `SET_REMOVE` `burn` in {0, 1}, `SET_EQUIVOCATION` roles in {1, 2}, and every
/// signature header in 31..34. Rejected at rule time as `bad-vault-act-params`.
pub fn act_fields_valid(act: &Act) -> bool {
    if !act.sigs.iter().all(sig_header_ok) {
        return false;
    }
    body_fields_valid(&act.body)
}

/// The body half of [`act_fields_valid`].
pub fn body_fields_valid(body: &ActBody) -> bool {
    match body {
        ActBody::Create(c) => c.valid(),
        ActBody::Join(j) => {
            j.member_key.is_compressed() && (1..500_000_000).contains(&j.bond_locktime)
        }
        ActBody::Heartbeat(h) => h.member_key.is_compressed(),
        ActBody::Remove(r) => r.member_key.is_compressed() && r.burn <= 1,
        ActBody::Equivocation(e) => {
            role_ok(e.role_a)
                && role_ok(e.role_b)
                && sig_header_ok(&e.sig_a)
                && sig_header_ok(&e.sig_b)
        }
        ActBody::WindDown(_) => true,
    }
}

fn sha256d(parts: &[&[u8]]) -> Hash32 {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    Hash32(Sha256::digest(h.finalize()).into())
}

/// `actMsg = SHA256d("YcashSetAct" || P || prevout(36))`, where `prevout` is the act
/// transaction's `vin[0].prevout`.
pub fn act_msg(p: &[u8], prevout: &OutPoint) -> Hash32 {
    sha256d(&[b"YcashSetAct", p, &prevout.to_bytes()])
}

/// `setSigMsg = SHA256d("YcashSetSig" || setId(32) || role(1) || prevout(36) || sighash(32))`,
/// the message an `OP_CHECKSETSIG` signature signs.
pub fn set_sig_msg(set_id: &SetId, role: u8, prevout: &OutPoint, sighash: &Hash32) -> Hash32 {
    sha256d(&[
        b"YcashSetSig",
        &set_id.0,
        &[role],
        &prevout.to_bytes(),
        &sighash.0,
    ])
}

/// secp256k1 order / 2, big-endian.
const HALF_ORDER: [u8; 32] = [
    0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x5D, 0x57, 0x6E, 0x73, 0x57, 0xA4, 0x50, 0x1D, 0xDF, 0xE9, 0x2F, 0x46, 0x68, 0x1B, 0x20, 0xA0,
];

/// Strict recovery of a 65-byte recoverable signature (C++ `RecoverSig`): header 31..34
/// (compressed), low S (`s <= n/2`), `r` and `s` in range and non-zero; returns the recovered
/// compressed key.
pub fn recover_sig(msg: &Hash32, sig: &RecoverableSig) -> Option<PubKeyBytes> {
    let [header, rs @ ..] = &sig.0;
    if !(31..=34).contains(header) {
        return None;
    }
    let (_, s) = rs.split_at_checked(32)?;
    if s > HALF_ORDER.as_slice() {
        return None;
    }
    let recid = RecoveryId::from_u8_masked(header.wrapping_sub(31));
    let rsig = RecoverableSignature::from_compact(rs, recid).ok()?;
    let key = rsig.recover_ecdsa(Message::from_digest(msg.0)).ok()?;
    Some(PubKeyBytes(key.serialize()))
}

/// The compressed public key of a 32-byte secret; `None` for an invalid secret.
pub fn public_key(secret: &[u8; 32]) -> Option<PubKeyBytes> {
    let sk = SecretKey::from_secret_bytes(*secret).ok()?;
    Some(PubKeyBytes(PublicKey::from_secret_key(&sk).serialize()))
}

/// Signs `msg` with a compressed key (C++ `SignRecoverable`, `CKey::SignCompact`): libsecp256k1's
/// RFC 6979 nonce, low S, header `31 + recid`. `None` for an invalid secret.
pub fn sign_recoverable(secret: &[u8; 32], msg: &Hash32) -> Option<RecoverableSig> {
    let sk = SecretKey::from_secret_bytes(*secret).ok()?;
    let sig = RecoverableSignature::sign_ecdsa_recoverable(Message::from_digest(msg.0), &sk);
    let (recid, rs) = sig.serialize_compact();
    let mut out = [0u8; RECOVERABLE_SIG_SIZE];
    let (h, body) = out.split_at_mut(1);
    h.copy_from_slice(&[31u8.checked_add(recid.to_u8())?]);
    body.copy_from_slice(&rs);
    let out = RecoverableSig(out);
    sig_header_ok(&out).then_some(out)
}
