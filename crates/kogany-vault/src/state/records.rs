//! The four record kinds of the set state and their canonical byte encodings.
//!
//! The encodings are the C++ `SER_DISK` serialisations of ycash6 `src/vault/state.h`
//! (`SetRecord`, `MemberRecord`, `BondRecord`, `TemplateOutRecord`) and the keys are its
//! `KeySet` / `KeyMember` / `KeyBond` / `KeyTemplateOut`. They are what `statehash` digests
//! ([`super::hash`]); they are **not** a storage format: kogany's column families (W4-c) may
//! store the records however they like, as long as these encodings come out the same.
//!
//! Little-endian fixed-width integers; `bool` as one byte; a public key as CompactSize(33) and
//! its 33 bytes (the C++ `CPubKey` serialisation); a script as CompactSize(len) and its bytes;
//! an outpoint as txid ‖ n (u32 LE). The trailing `join_count` / `join_ordinal` / `exit_height`
//! fields are written only when non-zero, so a record without them keeps its earlier bytes.

use crate::act::SetCreateBody;
use crate::bytes::{Hash32, OutPoint, PubKeyBytes, SetId};

/// Key prefix of a set record: `'s' ‖ setId(32)`.
pub const KEY_SET: u8 = b's';
/// Key prefix of a member record: `'m' ‖ setId(32) ‖ memberKey(33)`.
pub const KEY_MEMBER: u8 = b'm';
/// Key prefix of a bond record: `'b' ‖ txid(32) ‖ n(u32 LE)`.
pub const KEY_BOND: u8 = b'b';
/// Key prefix of a template-output record: `'v' ‖ txid(32) ‖ n(u32 LE)`.
pub const KEY_TEMPLATE_OUT: u8 = b'v';

/// A member's status (C++ `MemberStatus`, serialised as its `u8`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub enum MemberStatus {
    /// `MEMBER_ACTIVE` (0): holds a seat.
    #[default]
    Active,
    /// `MEMBER_REMOVED` (1): left (removed, its own exit, or displaced).
    Removed,
    /// `MEMBER_EJECTED` (2): ejected for equivocation (or by a module's ejection hook).
    Ejected,
    /// `MEMBER_WITHDRAWN` (3): an ACTIVE member whose bond was spent.
    Withdrawn,
}

impl MemberStatus {
    /// The serialised byte.
    pub fn to_u8(self) -> u8 {
        match self {
            MemberStatus::Active => 0,
            MemberStatus::Removed => 1,
            MemberStatus::Ejected => 2,
            MemberStatus::Withdrawn => 3,
        }
    }

    /// The status of a serialised byte; `None` outside 0..=3.
    pub fn from_u8(b: u8) -> Option<MemberStatus> {
        match b {
            0 => Some(MemberStatus::Active),
            1 => Some(MemberStatus::Removed),
            2 => Some(MemberStatus::Ejected),
            3 => Some(MemberStatus::Withdrawn),
            _ => None,
        }
    }
}

/// A signer set (C++ `SetRecord`): its `SET_CREATE` parameters and running values.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SetRecord {
    /// The `SET_CREATE` body.
    pub params: SetCreateBody,
    /// The height of the `SET_CREATE`.
    pub create_height: i64,
    /// The height of the `SET_WINDDOWN`; 0 = none.
    pub wind_down_height: i64,
    /// The sum of the values of the set's unspent V outputs.
    pub locked_value: i64,
    /// The current rate epoch, `height / rateWindow` (U-20).
    pub epoch: i64,
    /// `locked_value` at the epoch's first touch.
    pub epoch_basis: i64,
    /// Value unlocked into intents in this epoch.
    pub epoch_used: i64,
    /// The number of `SET_JOIN`s admitted; written only when non-zero.
    pub join_count: u32,
}

impl SetRecord {
    /// A fresh record for a `SET_CREATE` at `height`.
    pub fn new(params: SetCreateBody, create_height: i64) -> SetRecord {
        SetRecord {
            params,
            create_height,
            wind_down_height: 0,
            locked_value: 0,
            epoch: create_height
                .checked_div(i64::from(params.rate_window))
                .unwrap_or(0),
            epoch_basis: 0,
            epoch_used: 0,
            join_count: 0,
        }
    }
}

/// A member of a set (C++ `MemberRecord`), keyed by (set, member key).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MemberRecord {
    /// The member's (latest) bond output.
    pub bond_outpoint: OutPoint,
    /// The bond's value.
    pub bond_value: i64,
    /// The bond's CLTV locktime.
    pub bond_locktime: u32,
    /// The height of its latest `SET_JOIN`.
    pub join_height: i64,
    /// Its last proven act; starts at `join_height + maturity`.
    pub last_act: i64,
    /// Its status.
    pub status: MemberStatus,
    /// Its bond is frozen.
    pub bond_frozen: bool,
    /// The set's `join_count` after this member's latest join (1 = the first join); 0 = unknown.
    /// Written only when non-zero.
    pub join_ordinal: u32,
}

/// An unspent member bond (C++ `BondRecord`), keyed by its outpoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BondRecord {
    /// The set the bond was posted to.
    pub set_id: SetId,
    /// Its member's key.
    pub member_key: PubKeyBytes,
    /// Frozen (burnt): never spendable.
    pub frozen: bool,
    /// The height its member left without a freeze (the bond exit delay); 0 = still a
    /// member's bond. Written only when non-zero.
    pub exit_height: i64,
}

/// What a template-output record indexes.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum TemplateOutKind {
    /// A vault V (serialised 0).
    #[default]
    Vault,
    /// An intent I (serialised 1).
    Intent,
}

impl TemplateOutKind {
    /// The serialised byte.
    pub fn to_u8(self) -> u8 {
        match self {
            TemplateOutKind::Vault => 0,
            TemplateOutKind::Intent => 1,
        }
    }
}

/// An unspent V or I output created from activation (C++ `TemplateOutRecord`), keyed by its
/// outpoint: the `vault_list` index and an intent's creation height.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TemplateOutRecord {
    /// V or I.
    pub kind: TemplateOutKind,
    /// The creating block's height.
    pub height: i64,
    /// The output's value.
    pub value: i64,
    /// The output's scriptPubKey.
    pub script_pubkey: Vec<u8>,
    /// For an intent, the scriptPubKey of the V it was unlocked from; empty for a V.
    pub origin: Vec<u8>,
}

// ---- keys -------------------------------------------------------------------------------

/// `'s' ‖ setId`.
pub fn key_set(set_id: &SetId) -> Vec<u8> {
    let mut k = Vec::with_capacity(33);
    k.push(KEY_SET);
    k.extend_from_slice(&set_id.0);
    k
}

/// `'m' ‖ setId ‖ memberKey`.
pub fn key_member(set_id: &SetId, key: &PubKeyBytes) -> Vec<u8> {
    let mut k = Vec::with_capacity(66);
    k.push(KEY_MEMBER);
    k.extend_from_slice(&set_id.0);
    k.extend_from_slice(&key.0);
    k
}

/// `'b' ‖ txid ‖ n (LE)`.
pub fn key_bond(op: &OutPoint) -> Vec<u8> {
    let mut k = Vec::with_capacity(37);
    k.push(KEY_BOND);
    k.extend_from_slice(&op.to_bytes());
    k
}

/// `'v' ‖ txid ‖ n (LE)`.
pub fn key_template_out(op: &OutPoint) -> Vec<u8> {
    let mut k = Vec::with_capacity(37);
    k.push(KEY_TEMPLATE_OUT);
    k.extend_from_slice(&op.to_bytes());
    k
}

// ---- encoding ---------------------------------------------------------------------------

/// Appends a Bitcoin CompactSize.
pub(crate) fn write_compact_size(w: &mut Vec<u8>, n: usize) {
    // usize -> u64 is lossless on every supported target.
    let n = n as u64;
    if n < 253 {
        w.push(n as u8);
    } else if n <= 0xffff {
        w.push(253);
        w.extend_from_slice(&(n as u16).to_le_bytes());
    } else if n <= 0xffff_ffff {
        w.push(254);
        w.extend_from_slice(&(n as u32).to_le_bytes());
    } else {
        w.push(255);
        w.extend_from_slice(&n.to_le_bytes());
    }
}

fn write_bytes(w: &mut Vec<u8>, b: &[u8]) {
    write_compact_size(w, b.len());
    w.extend_from_slice(b);
}

fn write_set_params(w: &mut Vec<u8>, c: &SetCreateBody) {
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
    write_bytes(w, &c.admit_key.0);
}

impl SetRecord {
    /// The canonical encoding (C++ `SetRecord::Serialize`).
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Vec::with_capacity(128);
        write_set_params(&mut w, &self.params);
        for v in [
            self.create_height,
            self.wind_down_height,
            self.locked_value,
            self.epoch,
            self.epoch_basis,
            self.epoch_used,
        ] {
            w.extend_from_slice(&v.to_le_bytes());
        }
        if self.join_count != 0 {
            w.extend_from_slice(&self.join_count.to_le_bytes());
        }
        w
    }

    /// Parses [`SetRecord::encode`]'s bytes; `None` unless every byte is consumed.
    pub fn decode(b: &[u8]) -> Option<SetRecord> {
        let mut r = Reader { rest: b };
        let params = SetCreateBody {
            seats: r.u8()?,
            unlock_threshold: r.u8()?,
            cancel_threshold: r.u8()?,
            slash_threshold: r.u8()?,
            flags: r.u8()?,
            rate_limit_bps: u16::from_le_bytes(r.take()?),
            rate_window: r.u32()?,
            liveness_window: r.u32()?,
            bond_min: r.i64()?,
            bond_lock_min: r.u32()?,
            maturity: r.u32()?,
            admit_key: r.pubkey()?,
        };
        let rec = SetRecord {
            params,
            create_height: r.i64()?,
            wind_down_height: r.i64()?,
            locked_value: r.i64()?,
            epoch: r.i64()?,
            epoch_basis: r.i64()?,
            epoch_used: r.i64()?,
            join_count: if r.rest.is_empty() { 0 } else { r.u32()? },
        };
        r.rest.is_empty().then_some(rec)
    }
}

impl MemberRecord {
    /// The canonical encoding (C++ `MemberRecord::Serialize`).
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Vec::with_capacity(72);
        w.extend_from_slice(&self.bond_outpoint.to_bytes());
        w.extend_from_slice(&self.bond_value.to_le_bytes());
        w.extend_from_slice(&self.bond_locktime.to_le_bytes());
        w.extend_from_slice(&self.join_height.to_le_bytes());
        w.extend_from_slice(&self.last_act.to_le_bytes());
        w.push(self.status.to_u8());
        w.push(u8::from(self.bond_frozen));
        if self.join_ordinal != 0 {
            w.extend_from_slice(&self.join_ordinal.to_le_bytes());
        }
        w
    }

    /// Parses [`MemberRecord::encode`]'s bytes; `None` unless every byte is consumed.
    pub fn decode(b: &[u8]) -> Option<MemberRecord> {
        let mut r = Reader { rest: b };
        let rec = MemberRecord {
            bond_outpoint: r.outpoint()?,
            bond_value: r.i64()?,
            bond_locktime: r.u32()?,
            join_height: r.i64()?,
            last_act: r.i64()?,
            status: MemberStatus::from_u8(r.u8()?)?,
            bond_frozen: r.bool()?,
            join_ordinal: if r.rest.is_empty() { 0 } else { r.u32()? },
        };
        r.rest.is_empty().then_some(rec)
    }
}

impl BondRecord {
    /// The canonical encoding (C++ `BondRecord::Serialize`): 67 bytes, 75 with an exit height.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Vec::with_capacity(75);
        w.extend_from_slice(&self.set_id.0);
        write_bytes(&mut w, &self.member_key.0);
        w.push(u8::from(self.frozen));
        if self.exit_height != 0 {
            w.extend_from_slice(&self.exit_height.to_le_bytes());
        }
        w
    }

    /// Parses [`BondRecord::encode`]'s bytes; `None` unless every byte is consumed.
    pub fn decode(b: &[u8]) -> Option<BondRecord> {
        let mut r = Reader { rest: b };
        let rec = BondRecord {
            set_id: Hash32(r.take()?),
            member_key: r.pubkey()?,
            frozen: r.bool()?,
            exit_height: if r.rest.is_empty() { 0 } else { r.i64()? },
        };
        r.rest.is_empty().then_some(rec)
    }
}

impl TemplateOutRecord {
    /// The canonical encoding (C++ `TemplateOutRecord` serialisation).
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Vec::with_capacity(
            self.script_pubkey
                .len()
                .saturating_add(self.origin.len())
                .saturating_add(32),
        );
        w.push(self.kind.to_u8());
        w.extend_from_slice(&self.height.to_le_bytes());
        w.extend_from_slice(&self.value.to_le_bytes());
        write_bytes(&mut w, &self.script_pubkey);
        write_bytes(&mut w, &self.origin);
        w
    }

    /// Parses [`TemplateOutRecord::encode`]'s bytes; `None` unless every byte is consumed.
    pub fn decode(b: &[u8]) -> Option<TemplateOutRecord> {
        let mut r = Reader { rest: b };
        let kind = match r.u8()? {
            0 => TemplateOutKind::Vault,
            1 => TemplateOutKind::Intent,
            _ => return None,
        };
        let rec = TemplateOutRecord {
            kind,
            height: r.i64()?,
            value: r.i64()?,
            script_pubkey: r.bytes()?,
            origin: r.bytes()?,
        };
        r.rest.is_empty().then_some(rec)
    }
}

/// Little-endian reader; every read fails past the end.
struct Reader<'a> {
    rest: &'a [u8],
}

impl Reader<'_> {
    fn take<const N: usize>(&mut self) -> Option<[u8; N]> {
        let (head, rest) = self.rest.split_at_checked(N)?;
        self.rest = rest;
        head.try_into().ok()
    }
    fn u8(&mut self) -> Option<u8> {
        self.take::<1>().map(|[b]| b)
    }
    fn bool(&mut self) -> Option<bool> {
        // The C++ reads any non-zero byte as true; a canonical encoding writes 0 or 1 only.
        match self.u8()? {
            0 => Some(false),
            1 => Some(true),
            _ => None,
        }
    }
    fn u32(&mut self) -> Option<u32> {
        self.take().map(u32::from_le_bytes)
    }
    fn i64(&mut self) -> Option<i64> {
        self.take().map(i64::from_le_bytes)
    }
    fn outpoint(&mut self) -> Option<OutPoint> {
        Some(OutPoint {
            txid: Hash32(self.take()?),
            n: self.u32()?,
        })
    }
    fn compact_size(&mut self) -> Option<usize> {
        let n: u64 = match self.u8()? {
            253 => u64::from(u16::from_le_bytes(self.take()?)),
            254 => u64::from(self.u32()?),
            255 => u64::from_le_bytes(self.take()?),
            b => u64::from(b),
        };
        usize::try_from(n).ok()
    }
    fn bytes(&mut self) -> Option<Vec<u8>> {
        let n = self.compact_size()?;
        let (head, rest) = self.rest.split_at_checked(n)?;
        self.rest = rest;
        Some(head.to_vec())
    }
    fn pubkey(&mut self) -> Option<PubKeyBytes> {
        if self.compact_size()? != 33 {
            return None;
        }
        Some(PubKeyBytes(self.take()?))
    }
}
