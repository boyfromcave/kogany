// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

//! The Yellowback payload codec (ycash6 `src/yellowback/payload.{h,cpp}`): version 3 for every
//! type but MINT (v3 plan §3.3, W14), the MINT at version 4 with a post-quantum owner (quantum
//! spec §3.1, header C-1).
//!
//! ```text
//! magic   2 bytes   0x59 0x42 ("YB")
//! version 1 byte    0x04 for MINT, 0x03 for every other type (another version => non-Yellowback)
//! type    1 byte    0x01 MINT | 0x02 TRANSFER | 0x03 REDEEM | 0x05 ATTESTOR_REGISTER |
//!                   0x06 CLAIM_NOTICE | 0x07 EQUIVOCATION | 0x08 ATTESTOR_REVIVE | 0x09 CANCEL_COSIGN
//! body    per type; total <= 80 bytes; trailing bytes => malformed
//!
//! MINT (v4)          termClass u8, cents u32, lockHeight u32, refHeight u32,
//!                    ownerScheme u8, ownerHash 32, feeVout u8, attestFeeVout u8              (52)
//! TRANSFER           count u8, count x (vout u8, cents u32)                                  (5 + 5n, n <= 15)
//! REDEEM             refHeight u32, feeVout u8, attestFeeVout u8, count u8,
//!                    count x (vout u8, cents u32)                                            (11 + 5n, n <= 13)
//! ATTESTOR_REGISTER  attestorPubKey 33, bondPubKey 33, bondLocktime u32, flags u8            (75)
//! CLAIM_NOTICE       vaultTxid 32, vaultVout u8, refHeight u32                               (41)
//! EQUIVOCATION       (empty; the carrier holds the two attestations)                         (4)
//! ATTESTOR_REVIVE    seq u16, priceMicroUsd u32, citedHeight u32, sig 64                     (78)
//! CANCEL_COSIGN      (empty; the carrier holds the co-signatures)                            (4)
//! ```
//!
//! Every other type (0x04, 0x0A-0xFF) and every other version is non-Yellowback (the
//! forward-compatibility rule, V23). Integers are fixed-width little-endian. `feeVout` /
//! `attestFeeVout` = [`FEE_VOUT_NONE`] mean "no such fee output"; the codec does not range-check
//! either (MINT-8 / RED-3 / AFEE-1 do, K11). The MINT owner and the ATTESTOR_REGISTER keys are any
//! 33 bytes: the codec fixes the shape, MINT-3 / REG-A1 judge them, and the records keep the
//! bytes verbatim.
//!
//! Rust shape: the C++ `Payload` is one struct with every type's fields and a `version` byte;
//! here it is an enum with one body per type and the version derived from the type
//! ([`PayloadType::version`]). A decoded C++ payload always has the derived version, and the C++
//! encoder refuses any other, so the two are the same set of encodable values; the C++
//! "wrong version is not encodable" case is unrepresentable here.

use kogany_vault::script::{get_op, op::OP_PUSHDATA4, op::OP_RETURN, Builder};
use kogany_vault::{Hash32, OutPoint, PqOwner, PubKeyBytes};

#[cfg(doc)]
use crate::params::FEE_VOUT_NONE;
use crate::params::{
    MAX_PAYLOAD, MINT_PAYLOAD_VERSION, MIN_PAYLOAD, PAYLOAD_MAGIC_0, PAYLOAD_MAGIC_1,
    PAYLOAD_VERSION,
};

/// TRANSFER: `5 + 5 * count <= 80`, so `count <= 15`.
pub const MAX_ASSIGNMENTS: usize = 15;
/// REDEEM: `11 + 5 * count <= 80`, so `count <= 13`.
pub const MAX_REDEEM_ASSIGNMENTS: usize = 13;
/// The ATTESTOR_REVIVE compact signature.
pub const COMPACT_SIG_SIZE: usize = 64;
/// The MINT owner field and the ATTESTOR_REGISTER keys.
pub const KEY_SIZE: usize = 33;

/// The header: magic, version, type.
const HEADER_SIZE: usize = 4;
/// The MINT body (48 bytes; total 52).
const MINT_BODY_SIZE: usize = 48;
/// The REDEEM head: refHeight, feeVout, attestFeeVout, count.
const REDEEM_HEAD_SIZE: usize = 7;
/// The ATTESTOR_REGISTER body (71; total 75).
const REGISTER_BODY_SIZE: usize = 71;
/// The CLAIM_NOTICE body (37; total 41).
const NOTICE_BODY_SIZE: usize = 37;
/// The ATTESTOR_REVIVE body (74; total 78).
const REVIVE_BODY_SIZE: usize = 74;
/// One assignment: vout u8, cents u32.
const ASSIGNMENT_SIZE: usize = 5;

/// A payload type (`PayloadType`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum PayloadType {
    /// 0x01: a mint (v4).
    Mint = 0x01,
    /// 0x02: a YED transfer.
    Transfer = 0x02,
    /// 0x03: a redeem.
    Redeem = 0x03,
    /// 0x05: an attestor registration (REG-A1).
    AttestorRegister = 0x05,
    /// 0x06: a claim notice (NOT-1).
    ClaimNotice = 0x06,
    /// 0x07: an equivocation proof marker (EQV-1).
    Equivocation = 0x07,
    /// 0x08: an attestor revival (REV-1).
    AttestorRevive = 0x08,
    /// 0x09: a cancel's co-signature marker (CAN-2, C4b).
    CancelCosign = 0x09,
}

impl PayloadType {
    /// The type of a type byte; `None` for 0x04 and 0x0A-0xFF (reserved: non-Yellowback).
    pub const fn from_byte(b: u8) -> Option<PayloadType> {
        match b {
            0x01 => Some(PayloadType::Mint),
            0x02 => Some(PayloadType::Transfer),
            0x03 => Some(PayloadType::Redeem),
            0x05 => Some(PayloadType::AttestorRegister),
            0x06 => Some(PayloadType::ClaimNotice),
            0x07 => Some(PayloadType::Equivocation),
            0x08 => Some(PayloadType::AttestorRevive),
            0x09 => Some(PayloadType::CancelCosign),
            _ => None,
        }
    }

    /// The type byte.
    pub const fn byte(self) -> u8 {
        self as u8
    }

    /// `VersionOf`: [`MINT_PAYLOAD_VERSION`] for a MINT, [`PAYLOAD_VERSION`] otherwise (C-1).
    pub const fn version(self) -> u8 {
        match self {
            PayloadType::Mint => MINT_PAYLOAD_VERSION,
            _ => PAYLOAD_VERSION,
        }
    }

    /// `PayloadTypeName`: the name in RPC output and logs.
    pub const fn name(self) -> &'static str {
        match self {
            PayloadType::Mint => "mint",
            PayloadType::Transfer => "transfer",
            PayloadType::Redeem => "redeem",
            PayloadType::AttestorRegister => "register",
            PayloadType::ClaimNotice => "notice",
            PayloadType::Equivocation => "equivocation",
            PayloadType::AttestorRevive => "revive",
            PayloadType::CancelCosign => "cancelcosign",
        }
    }
}

/// One `(vout, cents)` assignment of a TRANSFER or REDEEM (`Assignment`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Assignment {
    /// The output that receives the YED.
    pub vout: u8,
    /// The YED amount in cents; never 0 in a decodable payload.
    pub cents: u32,
}

impl Assignment {
    /// An assignment.
    pub const fn new(vout: u8, cents: u32) -> Assignment {
        Assignment { vout, cents }
    }
}

/// The MINT body (v4, quantum spec §3.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Mint {
    /// 0 = A, 1 = B, 2 = C (V19); any byte decodes, MINT-2 checks it.
    pub term_class: u8,
    /// The minted YED, cents.
    pub cents: u32,
    /// The term's end (record-keeping since IT-1: the class and the fee).
    pub lock_height: u32,
    /// MINT-2's reference height.
    pub ref_height: u32,
    /// The 33 owner bytes verbatim, `scheme || keyHash` (`ownerKeyBytes`); any scheme decodes.
    pub owner_bytes: [u8; KEY_SIZE],
    /// The protocol-fee output, or [`FEE_VOUT_NONE`].
    pub fee_vout: u8,
    /// The attestor-fee output, or [`FEE_VOUT_NONE`] (AFEE-0).
    pub attest_fee_vout: u8,
}

impl Mint {
    /// The owner as `scheme = byte 0, hash = bytes 1..33` (the C++ `owner`, `OwnerFromBytes`).
    pub fn owner(&self) -> PqOwner {
        let [scheme, hash @ ..] = self.owner_bytes;
        PqOwner {
            scheme,
            hash: Hash32(hash),
        }
    }
}

/// The REDEEM body.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Redeem {
    /// The reference height (V11).
    pub ref_height: u32,
    /// The protocol-fee output, or [`FEE_VOUT_NONE`].
    pub fee_vout: u8,
    /// The attestor-fee output, or [`FEE_VOUT_NONE`].
    pub attest_fee_vout: u8,
    /// At most [`MAX_REDEEM_ASSIGNMENTS`], distinct vouts, non-zero cents.
    pub assignments: Vec<Assignment>,
}

/// The ATTESTOR_REGISTER body (REG-A1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AttestorRegister {
    /// The attestor key, any 33 bytes (`attestorKeyBytes`).
    pub attestor_key: PubKeyBytes,
    /// The bond key, any 33 bytes (`bondKeyBytes`).
    pub bond_key: PubKeyBytes,
    /// The bond's locktime.
    pub bond_locktime: u32,
    /// The flags byte.
    pub flags: u8,
}

/// The CLAIM_NOTICE body (NOT-1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClaimNotice {
    /// The vault's txid, internal byte order (as written; not the displayed reversed hex, R13).
    pub vault_txid: Hash32,
    /// The vault's output index: a byte, any value (0xFF is a value here, not "none").
    pub vault_vout: u8,
    /// The reference height.
    pub ref_height: u32,
}

impl ClaimNotice {
    /// `VaultOutPoint`: the vault outpoint `(vault_txid, vault_vout)`.
    pub fn vault_outpoint(&self) -> OutPoint {
        OutPoint {
            txid: self.vault_txid,
            n: u32::from(self.vault_vout),
        }
    }

    /// `ClaimNotice(COutPoint, refHeight)`: the outpoint's index is truncated to the byte the
    /// payload carries (a YED vault output is always a low index in practice).
    pub fn from_outpoint(vault: &OutPoint, ref_height: u32) -> ClaimNotice {
        let [n, ..] = vault.n.to_le_bytes();
        ClaimNotice {
            vault_txid: vault.txid,
            vault_vout: n,
            ref_height,
        }
    }
}

/// The ATTESTOR_REVIVE body (REV-1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AttestorRevive {
    /// The attestor's sequence number.
    pub seq: u16,
    /// The quoted price, micro-USD per YEC.
    pub price_micro_usd: u32,
    /// The cited height.
    pub cited_height: u32,
    /// The 64-byte compact signature.
    pub sig: [u8; COMPACT_SIG_SIZE],
}

/// A Yellowback payload (`Payload`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Payload {
    /// MINT (v4).
    Mint(Mint),
    /// TRANSFER: at most [`MAX_ASSIGNMENTS`] assignments, distinct vouts, non-zero cents.
    Transfer(Vec<Assignment>),
    /// REDEEM.
    Redeem(Redeem),
    /// ATTESTOR_REGISTER.
    AttestorRegister(AttestorRegister),
    /// CLAIM_NOTICE.
    ClaimNotice(ClaimNotice),
    /// EQUIVOCATION (empty body).
    Equivocation,
    /// ATTESTOR_REVIVE.
    AttestorRevive(AttestorRevive),
    /// CANCEL_COSIGN (empty body, so the outputs do not depend on the co-signature count).
    CancelCosign,
}

impl Payload {
    /// `Payload::Mint`: a v4 MINT whose 33 owner bytes are `scheme || keyHash`.
    pub fn mint(
        term_class: u8,
        cents: u32,
        lock_height: u32,
        ref_height: u32,
        owner: &PqOwner,
        fee_vout: u8,
        attest_fee_vout: u8,
    ) -> Payload {
        let mut owner_bytes = [0u8; KEY_SIZE];
        let (scheme, hash) = owner_bytes.split_at_mut(1);
        scheme.copy_from_slice(&[owner.scheme]);
        hash.copy_from_slice(&owner.hash.0);
        Payload::Mint(Mint {
            term_class,
            cents,
            lock_height,
            ref_height,
            owner_bytes,
            fee_vout,
            attest_fee_vout,
        })
    }

    /// `Payload::Redeem`.
    pub fn redeem(
        ref_height: u32,
        fee_vout: u8,
        assignments: Vec<Assignment>,
        attest_fee_vout: u8,
    ) -> Payload {
        Payload::Redeem(Redeem {
            ref_height,
            fee_vout,
            attest_fee_vout,
            assignments,
        })
    }

    /// The payload's type.
    pub fn payload_type(&self) -> PayloadType {
        match self {
            Payload::Mint(_) => PayloadType::Mint,
            Payload::Transfer(_) => PayloadType::Transfer,
            Payload::Redeem(_) => PayloadType::Redeem,
            Payload::AttestorRegister(_) => PayloadType::AttestorRegister,
            Payload::ClaimNotice(_) => PayloadType::ClaimNotice,
            Payload::Equivocation => PayloadType::Equivocation,
            Payload::AttestorRevive(_) => PayloadType::AttestorRevive,
            Payload::CancelCosign => PayloadType::CancelCosign,
        }
    }

    /// The version byte it encodes with (`VersionOf(type)`).
    pub fn version(&self) -> u8 {
        self.payload_type().version()
    }

    /// The TRANSFER or REDEEM assignments; empty for every other type.
    pub fn assignments(&self) -> &[Assignment] {
        match self {
            Payload::Transfer(a) => a,
            Payload::Redeem(r) => &r.assignments,
            _ => &[],
        }
    }

    /// The reference height of a MINT, REDEEM or CLAIM_NOTICE.
    pub fn ref_height(&self) -> Option<u32> {
        match self {
            Payload::Mint(m) => Some(m.ref_height),
            Payload::Redeem(r) => Some(r.ref_height),
            Payload::ClaimNotice(n) => Some(n.ref_height),
            _ => None,
        }
    }

    /// `AssignedCents`: the sum of the assigned cents (TRANSFER / REDEEM); 0 otherwise. At most
    /// `15 * (2^32 - 1)`, so it always fits.
    pub fn assigned_cents(&self) -> i64 {
        self.assignments()
            .iter()
            .fold(0i64, |s, a| s.saturating_add(i64::from(a.cents)))
    }
}

/// `ValidAssignments`: at most `max` entries, no zero cents, no repeated vout.
fn valid_assignments(assignments: &[Assignment], max: usize) -> bool {
    if assignments.len() > max {
        return false;
    }
    let mut seen = [false; 256];
    for a in assignments {
        if a.cents == 0 {
            return false;
        }
        match seen.get_mut(usize::from(a.vout)) {
            Some(s) if !*s => *s = true,
            _ => return false,
        }
    }
    true
}

fn put_assignments(out: &mut Vec<u8>, assignments: &[Assignment]) {
    // valid_assignments bounds the count by 15.
    out.push(u8::try_from(assignments.len()).unwrap_or(u8::MAX));
    for a in assignments {
        out.push(a.vout);
        out.extend_from_slice(&a.cents.to_le_bytes());
    }
}

/// `EncodePayload`: the data push of the OP_RETURN output. `None` when the payload is not
/// encodable (an invalid assignment list).
pub fn encode_payload(payload: &Payload) -> Option<Vec<u8>> {
    let t = payload.payload_type();
    let mut out = vec![PAYLOAD_MAGIC_0, PAYLOAD_MAGIC_1, t.version(), t.byte()];
    match payload {
        Payload::Mint(m) => {
            out.push(m.term_class);
            out.extend_from_slice(&m.cents.to_le_bytes());
            out.extend_from_slice(&m.lock_height.to_le_bytes());
            out.extend_from_slice(&m.ref_height.to_le_bytes());
            out.extend_from_slice(&m.owner_bytes);
            out.push(m.fee_vout);
            out.push(m.attest_fee_vout);
        }
        Payload::Transfer(a) => {
            if !valid_assignments(a, MAX_ASSIGNMENTS) {
                return None;
            }
            put_assignments(&mut out, a);
        }
        Payload::Redeem(r) => {
            if !valid_assignments(&r.assignments, MAX_REDEEM_ASSIGNMENTS) {
                return None;
            }
            out.extend_from_slice(&r.ref_height.to_le_bytes());
            out.push(r.fee_vout);
            out.push(r.attest_fee_vout);
            put_assignments(&mut out, &r.assignments);
        }
        Payload::AttestorRegister(g) => {
            out.extend_from_slice(&g.attestor_key.0);
            out.extend_from_slice(&g.bond_key.0);
            out.extend_from_slice(&g.bond_locktime.to_le_bytes());
            out.push(g.flags);
        }
        Payload::ClaimNotice(n) => {
            out.extend_from_slice(&n.vault_txid.0);
            out.push(n.vault_vout);
            out.extend_from_slice(&n.ref_height.to_le_bytes());
        }
        Payload::Equivocation | Payload::CancelCosign => {}
        Payload::AttestorRevive(v) => {
            out.extend_from_slice(&v.seq.to_le_bytes());
            out.extend_from_slice(&v.price_micro_usd.to_le_bytes());
            out.extend_from_slice(&v.cited_height.to_le_bytes());
            out.extend_from_slice(&v.sig);
        }
    }
    (out.len() <= MAX_PAYLOAD).then_some(out)
}

/// A bounds-checked little-endian reader (the C++ `Reader`). Never panics.
struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn bytes<const N: usize>(&mut self) -> Option<[u8; N]> {
        let (head, rest) = self.0.split_at_checked(N)?;
        self.0 = rest;
        head.try_into().ok()
    }
    fn u8(&mut self) -> Option<u8> {
        let (&b, rest) = self.0.split_first()?;
        self.0 = rest;
        Some(b)
    }
    fn u16(&mut self) -> Option<u16> {
        self.bytes::<2>().map(u16::from_le_bytes)
    }
    fn u32(&mut self) -> Option<u32> {
        self.bytes::<4>().map(u32::from_le_bytes)
    }
    fn assignments(&mut self, count: u8) -> Option<Vec<Assignment>> {
        (0..count)
            .map(|_| {
                Some(Assignment {
                    vout: self.u8()?,
                    cents: self.u32()?,
                })
            })
            .collect()
    }
    fn at_end(&self) -> bool {
        self.0.is_empty()
    }
}

/// The exact total size of a body of `count` assignments after a head of `head` bytes.
fn sized(head: usize, count: u8) -> Option<usize> {
    ASSIGNMENT_SIZE
        .checked_mul(usize::from(count))?
        .checked_add(head)?
        .checked_add(HEADER_SIZE)
}

/// The body of `t` from `r`, whose whole payload is `size` bytes (`DecodeBodyV3`).
fn decode_body(r: &mut Reader<'_>, t: PayloadType, size: usize) -> Option<Payload> {
    let fixed = |body: usize| size == HEADER_SIZE.saturating_add(body);
    match t {
        PayloadType::Mint => {
            if !fixed(MINT_BODY_SIZE) {
                return None;
            }
            Some(Payload::Mint(Mint {
                term_class: r.u8()?,
                cents: r.u32()?,
                lock_height: r.u32()?,
                ref_height: r.u32()?,
                owner_bytes: r.bytes::<KEY_SIZE>()?,
                fee_vout: r.u8()?,
                attest_fee_vout: r.u8()?,
            }))
        }
        PayloadType::Transfer => {
            let count = r.u8()?;
            if usize::from(count) > MAX_ASSIGNMENTS || Some(size) != sized(1, count) {
                return None;
            }
            let a = r.assignments(count)?;
            valid_assignments(&a, MAX_ASSIGNMENTS).then_some(Payload::Transfer(a))
        }
        PayloadType::Redeem => {
            let ref_height = r.u32()?;
            let fee_vout = r.u8()?;
            let attest_fee_vout = r.u8()?;
            let count = r.u8()?;
            if usize::from(count) > MAX_REDEEM_ASSIGNMENTS
                || Some(size) != sized(REDEEM_HEAD_SIZE, count)
            {
                return None;
            }
            let assignments = r.assignments(count)?;
            valid_assignments(&assignments, MAX_REDEEM_ASSIGNMENTS).then_some(Payload::Redeem(
                Redeem {
                    ref_height,
                    fee_vout,
                    attest_fee_vout,
                    assignments,
                },
            ))
        }
        PayloadType::AttestorRegister => {
            if !fixed(REGISTER_BODY_SIZE) {
                return None;
            }
            Some(Payload::AttestorRegister(AttestorRegister {
                attestor_key: PubKeyBytes(r.bytes::<KEY_SIZE>()?),
                bond_key: PubKeyBytes(r.bytes::<KEY_SIZE>()?),
                bond_locktime: r.u32()?,
                flags: r.u8()?,
            }))
        }
        PayloadType::ClaimNotice => {
            if !fixed(NOTICE_BODY_SIZE) {
                return None;
            }
            Some(Payload::ClaimNotice(ClaimNotice {
                vault_txid: Hash32(r.bytes::<32>()?),
                vault_vout: r.u8()?,
                ref_height: r.u32()?,
            }))
        }
        PayloadType::Equivocation => fixed(0).then_some(Payload::Equivocation),
        PayloadType::CancelCosign => fixed(0).then_some(Payload::CancelCosign),
        PayloadType::AttestorRevive => {
            if !fixed(REVIVE_BODY_SIZE) {
                return None;
            }
            Some(Payload::AttestorRevive(AttestorRevive {
                seq: r.u16()?,
                price_micro_usd: r.u32()?,
                cited_height: r.u32()?,
                sig: r.bytes::<COMPACT_SIG_SIZE>()?,
            }))
        }
    }
}

/// `DecodePayload`: `None` for every malformed case of §3.3 — bad magic, version (4 for MINT, 3
/// for every other type) or type, short or long body, count over 15 (TRANSFER) / 13 (REDEEM),
/// duplicate vout, zero cents. Versions 1 and 2 are non-Yellowback (V23). The checks that need
/// the transaction (the vout exists, is not the OP_RETURN) are [`find_payload`]'s.
pub fn decode_payload(data: &[u8]) -> Option<Payload> {
    if !(MIN_PAYLOAD..=MAX_PAYLOAD).contains(&data.len()) {
        return None;
    }
    let mut r = Reader(data);
    let [m0, m1, version, type_byte] = r.bytes::<4>()?;
    if m0 != PAYLOAD_MAGIC_0 || m1 != PAYLOAD_MAGIC_1 {
        return None;
    }
    let t = PayloadType::from_byte(type_byte)?;
    if version != t.version() {
        return None;
    }
    let p = decode_body(&mut r, t, data.len())?;
    r.at_end().then_some(p)
}

/// `PayloadScript`: `OP_RETURN <data>`, with the `CScript <<` push encoding.
pub fn payload_script(data: &[u8]) -> Vec<u8> {
    Builder::new().op(OP_RETURN).push(data).into_bytes()
}

/// `ExtractOpReturnData`: the pushed bytes if `script` is exactly `OP_RETURN <one data push>` of
/// [`MIN_PAYLOAD`]..=[`MAX_PAYLOAD`] bytes. A non-minimal push (`OP_PUSHDATA1` for 10 bytes) is
/// still one push; no push, two pushes, an `OP_n`, an empty push or trailing bytes are `None`.
pub fn extract_op_return_data(script: &[u8]) -> Option<&[u8]> {
    if script.first() != Some(&OP_RETURN) {
        return None;
    }
    let (t, next) = get_op(script, 1)?;
    if t.op > OP_PUSHDATA4 || t.data.is_empty() || next != script.len() {
        return None;
    }
    (MIN_PAYLOAD..=MAX_PAYLOAD)
        .contains(&t.data.len())
        .then_some(t.data)
}

/// `FindOpReturn`: the index of the only output whose script starts with `OP_RETURN`; `None`
/// for none or more than one (§3.2).
pub fn find_op_return<S: AsRef<[u8]>>(outputs: &[S]) -> Option<usize> {
    let mut found = None;
    for (i, s) in outputs.iter().enumerate() {
        if s.as_ref().first() == Some(&OP_RETURN) {
            if found.is_some() {
                return None;
            }
            found = Some(i);
        }
    }
    found
}

/// A transaction's payload and the index of its OP_RETURN output (`FoundPayload`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FoundPayload {
    /// The decoded payload.
    pub payload: Payload,
    /// The OP_RETURN output's index.
    pub op_return_index: usize,
}

/// `FindPayload`: the payload of a transaction whose output scripts are `outputs`, in order —
/// exactly one OP_RETURN output, of the required shape, that decodes, whose assigned vouts all
/// exist and none of which is the OP_RETURN itself. Otherwise `None`: the transaction is
/// non-Yellowback for outputs (its inputs still follow IN-1..3).
pub fn find_payload<S: AsRef<[u8]>>(outputs: &[S]) -> Option<FoundPayload> {
    let op_return_index = find_op_return(outputs)?;
    let data = extract_op_return_data(outputs.get(op_return_index)?.as_ref())?;
    let payload = decode_payload(data)?;
    let ok = payload.assignments().iter().all(|a| {
        let v = usize::from(a.vout);
        v < outputs.len() && v != op_return_index
    });
    ok.then_some(FoundPayload {
        payload,
        op_return_index,
    })
}
