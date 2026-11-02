// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

//! The attest-side records of the YED state and their canonical encodings: the attestor registry
//! (`A<seq>` [`AttestorRecord`], `Z` [`AttestorSetRecord`], `N` next seq, `B<outpoint>` bond index),
//! the carried arming state (`M` [`AttestState`]) and the per-height bundle log (`W<height>`
//! [`BundleLogRecord`]) — ycash6 `src/yellowback/view.{h,cpp}` at `65cb4ae0f`.
//!
//! The encodings are the C++ `SER_DISK` serialisations the YED state hash digests (fixed-width
//! little-endian integers, `u8` booleans and enumerations, CompactSize-prefixed vectors, an
//! outpoint as txid ‖ n); the keys are `keys::*` of `view.cpp` (heights and seqs big-endian, an
//! outpoint as txid ‖ n big-endian). How the node stores them is the index's (W5-e).
//!
//! [`RegistryRead`] / [`RegistryWrite`] are what the mirror rules ([`super::mirror`]) need of
//! the YED state; the state machine (W5-d) implements them over its view, and [`Registry`] is an
//! in-memory implementation for tests and dry runs.

use std::collections::BTreeMap;

use kogany_vault::{OutPoint, PubKeyBytes};

use crate::params::{Amount, MicroUsd};

/// `AttestorStatus`, declaration order, serialised as its `u8`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub enum AttestorStatus {
    /// 0: joined, not yet mature or under the bond floor.
    #[default]
    Pending,
    /// 1: may be seated.
    Eligible,
    /// 2: not live (set dormancy, or S15).
    Dormant,
    /// 3: ejected for equivocation (or a `SET_REMOVE` with burn).
    Ejected,
    /// 4: left (own exit, eviction, or bond spent).
    Withdrawn,
}

impl AttestorStatus {
    /// The serialised byte.
    pub const fn to_u8(self) -> u8 {
        match self {
            AttestorStatus::Pending => 0,
            AttestorStatus::Eligible => 1,
            AttestorStatus::Dormant => 2,
            AttestorStatus::Ejected => 3,
            AttestorStatus::Withdrawn => 4,
        }
    }

    /// The status of a byte. The C++ stores the raw `u8` and compares it with the enumerators, so
    /// a byte outside `0..=4` is no status at all; `None` here.
    pub const fn from_u8(b: u8) -> Option<AttestorStatus> {
        match b {
            0 => Some(AttestorStatus::Pending),
            1 => Some(AttestorStatus::Eligible),
            2 => Some(AttestorStatus::Dormant),
            3 => Some(AttestorStatus::Ejected),
            4 => Some(AttestorStatus::Withdrawn),
            _ => None,
        }
    }
}

/// `AttestorRecord.flags`: evicted by a larger bond (WITHDRAWN without slashing).
pub const ATTESTOR_FLAG_EVICTED: u8 = 0x80;

/// `Attestors[seq]` (`AttestorRecord`): the module's mirror of one `SET_JOIN` of the attestor
/// set (P4-b).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AttestorRecord {
    /// The member key.
    pub attestor_pub_key: PubKeyBytes,
    /// The bond key (the member key since P4-b).
    pub bond_pub_key: PubKeyBytes,
    /// `txid:bondVout` of the `SET_JOIN`.
    pub bond_outpoint: OutPoint,
    /// The bond's value.
    pub bond_zat: Amount,
    /// The bond's CLTV locktime.
    pub bond_locktime: u32,
    /// [`ATTESTOR_FLAG_EVICTED`] or 0.
    pub flags: u8,
    /// The `SET_JOIN`'s height.
    pub register_height: i32,
    /// The status.
    pub status: AttestorStatus,
    /// The height of the last status change.
    pub status_height: i32,
    /// 0 = the bond is unspent.
    pub bond_spent_height: i32,
    /// The SNAP height at which it entered `seated[]`; 0 = not seated.
    pub seated_since: i32,
    /// The set's `lastAct` for this member.
    pub last_act: i32,
    /// The bond is frozen in the set.
    pub bond_frozen: bool,
}

impl AttestorRecord {
    /// A fresh PENDING record with every height 0 for `key` (the C++ default record with a key).
    pub fn new(key: PubKeyBytes) -> AttestorRecord {
        AttestorRecord {
            attestor_pub_key: key,
            bond_pub_key: key,
            bond_outpoint: OutPoint::default(),
            bond_zat: 0,
            bond_locktime: 0,
            flags: 0,
            register_height: 0,
            status: AttestorStatus::Pending,
            status_height: 0,
            bond_spent_height: 0,
            seated_since: 0,
            last_act: 0,
            bond_frozen: false,
        }
    }

    /// Neither EJECTED nor WITHDRAWN, bond unspent and unfrozen: a record that may still act for
    /// its key.
    pub fn is_standing(&self) -> bool {
        !matches!(
            self.status,
            AttestorStatus::Ejected | AttestorStatus::Withdrawn
        ) && self.bond_spent_height == 0
            && !self.bond_frozen
    }
}

/// `AttestorSet` (P4-b): the parameters of `attestorSetId`'s `SET_CREATE` the module reads.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AttestorSetRecord {
    /// The `SET_CREATE`'s height.
    pub create_height: i32,
    /// The set's seats (bounds `N_SLOTS`).
    pub seats: u8,
    /// The set's maturity (the bond exit delay).
    pub maturity: u32,
    /// The set's member dormancy window.
    pub liveness_window: u32,
}

/// `AttestStatus`, declaration order (ARM-1/2; never moves backward).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub enum AttestStatus {
    /// 0.
    #[default]
    Unarmed,
    /// 1.
    Triggered,
    /// 2.
    Armed,
}

impl AttestStatus {
    /// The serialised byte.
    pub const fn to_u8(self) -> u8 {
        match self {
            AttestStatus::Unarmed => 0,
            AttestStatus::Triggered => 1,
            AttestStatus::Armed => 2,
        }
    }

    /// The status of a byte; `None` outside `0..=2`.
    pub const fn from_u8(b: u8) -> Option<AttestStatus> {
        match b {
            0 => Some(AttestStatus::Unarmed),
            1 => Some(AttestStatus::Triggered),
            2 => Some(AttestStatus::Armed),
            _ => None,
        }
    }
}

/// `Attest` (`AttestState`): the carried ARM-1/2 state, copied into every snapshot.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AttestState {
    /// The status.
    pub status: AttestStatus,
    /// The SNAP height of ARM-1.
    pub trigger_height: i32,
    /// `trigger_height + ATTEST_ARM_DELAY`.
    pub arm_height: i32,
}

impl AttestState {
    /// The snapshot's own status (`IsArmed`); "ARMED" in a rule is [`crate::params::Params::is_armed`]
    /// of it (W15).
    pub fn is_armed(&self) -> bool {
        self.status == AttestStatus::Armed
    }
}

/// `BundleLog[height]` (R12): one row per height with at least one MINT, REDEEM or CLAIM_NOTICE
/// bundle for which BUNDLE-1 held and whose rule held. `a_mint` / `a_claim` are the lower medians
/// of those bundles' statistics (0 = undefined); `selected_seqs` the sorted union of their
/// selected sets; `(seqs[i], prices[i], cited_heights[i])` the sorted, deduplicated union of
/// their attestations' `(seq, price, citedHeight)`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BundleLogRecord {
    /// The lower median of the bundles' `aMint`; 0 = undefined.
    pub a_mint: i64,
    /// The lower median of the bundles' `aClaim`; 0 = undefined.
    pub a_claim: i64,
    /// The union of the selected sets, ascending.
    pub selected_seqs: Vec<u16>,
    /// Parallel to `prices` and `cited_heights`.
    pub seqs: Vec<u16>,
    /// Parallel to `seqs`.
    pub prices: Vec<i64>,
    /// Parallel to `seqs` (audit A-2).
    pub cited_heights: Vec<u32>,
}

impl BundleLogRecord {
    /// `AMint`: `a_mint` when positive.
    pub fn a_mint(&self) -> Option<MicroUsd> {
        (self.a_mint > 0).then_some(self.a_mint)
    }

    /// `AClaim`: `a_claim` when positive.
    pub fn a_claim(&self) -> Option<MicroUsd> {
        (self.a_claim > 0).then_some(self.a_claim)
    }
}

// ---------------------------------------------------------------- keys (view.cpp keys::*)

/// `keys::Attestor(seq)`: `'A' ‖ seq BE16`.
pub fn key_attestor(seq: u16) -> Vec<u8> {
    let [hi, lo] = seq.to_be_bytes();
    vec![b'A', hi, lo]
}

/// `keys::BondIndex(outpoint)`: `'B' ‖ txid ‖ n BE32` (derived, not hashed).
pub fn key_bond_index(op: &OutPoint) -> Vec<u8> {
    outpoint_key(b'B', op)
}

/// `keys::AttestorSeq()`: `"N"`.
pub fn key_attestor_seq() -> Vec<u8> {
    vec![b'N']
}

/// `keys::Attest()`: `"M"`.
pub fn key_attest() -> Vec<u8> {
    vec![b'M']
}

/// `keys::BundleLog(height)`: `'W' ‖ height BE32`.
pub fn key_bundle_log(height: u32) -> Vec<u8> {
    let mut k = vec![b'W'];
    k.extend_from_slice(&height.to_be_bytes());
    k
}

/// `keys::AttestorSet()`: `"Z"`.
pub fn key_attestor_set() -> Vec<u8> {
    vec![b'Z']
}

fn outpoint_key(prefix: u8, op: &OutPoint) -> Vec<u8> {
    let mut k = Vec::with_capacity(37);
    k.push(prefix);
    k.extend_from_slice(&op.txid.0);
    k.extend_from_slice(&op.n.to_be_bytes());
    k
}

// ---------------------------------------------------------------- encodings

fn put_compact_size(w: &mut Vec<u8>, n: usize) {
    match u64::try_from(n).unwrap_or(u64::MAX) {
        v @ 0..=252 => w.push(u8::try_from(v).unwrap_or(0)),
        v @ 253..=0xffff => {
            w.push(253);
            w.extend_from_slice(&u16::try_from(v).unwrap_or(0).to_le_bytes());
        }
        v @ 0x1_0000..=0xffff_ffff => {
            w.push(254);
            w.extend_from_slice(&u32::try_from(v).unwrap_or(0).to_le_bytes());
        }
        v => {
            w.push(255);
            w.extend_from_slice(&v.to_le_bytes());
        }
    }
}

fn put_key(w: &mut Vec<u8>, k: &PubKeyBytes) {
    put_compact_size(w, k.0.len());
    w.extend_from_slice(&k.0);
}

fn put_outpoint(w: &mut Vec<u8>, op: &OutPoint) {
    w.extend_from_slice(&op.to_bytes());
}

/// A cursor over a record's bytes; every read is `None` past the end.
struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take<const N: usize>(&mut self) -> Option<[u8; N]> {
        let (head, rest) = self.0.split_first_chunk::<N>()?;
        self.0 = rest;
        Some(*head)
    }

    fn bytes(&mut self, n: usize) -> Option<&'a [u8]> {
        let (head, rest) = self.0.split_at_checked(n)?;
        self.0 = rest;
        Some(head)
    }

    fn u8(&mut self) -> Option<u8> {
        self.take::<1>().map(|[b]| b)
    }

    fn compact_size(&mut self) -> Option<u64> {
        // The C++ ReadCompactSize: non-canonical encodings fail.
        match self.u8()? {
            253 => {
                let v = u64::from(u16::from_le_bytes(self.take()?));
                (v >= 253).then_some(v)
            }
            254 => {
                let v = u64::from(u32::from_le_bytes(self.take()?));
                (v >= 0x1_0000).then_some(v)
            }
            255 => {
                let v = u64::from_le_bytes(self.take()?);
                (v >= 0x1_0000_0000).then_some(v)
            }
            b => Some(u64::from(b)),
        }
    }

    fn key(&mut self) -> Option<PubKeyBytes> {
        let n = usize::try_from(self.compact_size()?).ok()?;
        PubKeyBytes::from_slice(self.bytes(n)?)
    }

    fn outpoint(&mut self) -> Option<OutPoint> {
        OutPoint::from_slice(&self.take::<36>()?)
    }

    fn i32(&mut self) -> Option<i32> {
        self.take().map(i32::from_le_bytes)
    }

    fn u32(&mut self) -> Option<u32> {
        self.take().map(u32::from_le_bytes)
    }

    fn i64(&mut self) -> Option<i64> {
        self.take().map(i64::from_le_bytes)
    }

    fn vec<T>(&mut self, mut item: impl FnMut(&mut Self) -> Option<T>) -> Option<Vec<T>> {
        let n = usize::try_from(self.compact_size()?).ok()?;
        // Each item is at least one byte: bound the allocation by what is left.
        let mut out = Vec::with_capacity(n.min(self.0.len()));
        for _ in 0..n {
            out.push(item(self)?);
        }
        Some(out)
    }

    fn done(&self) -> bool {
        self.0.is_empty()
    }
}

impl AttestorRecord {
    /// The canonical serialisation.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Vec::with_capacity(120);
        put_key(&mut w, &self.attestor_pub_key);
        put_key(&mut w, &self.bond_pub_key);
        put_outpoint(&mut w, &self.bond_outpoint);
        w.extend_from_slice(&self.bond_zat.to_le_bytes());
        w.extend_from_slice(&self.bond_locktime.to_le_bytes());
        w.push(self.flags);
        w.extend_from_slice(&self.register_height.to_le_bytes());
        w.push(self.status.to_u8());
        w.extend_from_slice(&self.status_height.to_le_bytes());
        w.extend_from_slice(&self.bond_spent_height.to_le_bytes());
        w.extend_from_slice(&self.seated_since.to_le_bytes());
        w.extend_from_slice(&self.last_act.to_le_bytes());
        w.push(u8::from(self.bond_frozen));
        w
    }

    /// Parses [`AttestorRecord::encode`]; `None` for trailing or missing bytes, a key that is
    /// not 33 bytes, or an unknown status byte.
    pub fn decode(b: &[u8]) -> Option<AttestorRecord> {
        let mut r = Reader(b);
        let rec = AttestorRecord {
            attestor_pub_key: r.key()?,
            bond_pub_key: r.key()?,
            bond_outpoint: r.outpoint()?,
            bond_zat: r.i64()?,
            bond_locktime: r.u32()?,
            flags: r.u8()?,
            register_height: r.i32()?,
            status: AttestorStatus::from_u8(r.u8()?)?,
            status_height: r.i32()?,
            bond_spent_height: r.i32()?,
            seated_since: r.i32()?,
            last_act: r.i32()?,
            bond_frozen: r.u8()? != 0,
        };
        r.done().then_some(rec)
    }
}

impl AttestorSetRecord {
    /// The canonical serialisation (13 bytes).
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Vec::with_capacity(13);
        w.extend_from_slice(&self.create_height.to_le_bytes());
        w.push(self.seats);
        w.extend_from_slice(&self.maturity.to_le_bytes());
        w.extend_from_slice(&self.liveness_window.to_le_bytes());
        w
    }

    /// Parses [`AttestorSetRecord::encode`].
    pub fn decode(b: &[u8]) -> Option<AttestorSetRecord> {
        let mut r = Reader(b);
        let rec = AttestorSetRecord {
            create_height: r.i32()?,
            seats: r.u8()?,
            maturity: r.u32()?,
            liveness_window: r.u32()?,
        };
        r.done().then_some(rec)
    }
}

impl AttestState {
    /// The canonical serialisation (9 bytes).
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Vec::with_capacity(9);
        w.push(self.status.to_u8());
        w.extend_from_slice(&self.trigger_height.to_le_bytes());
        w.extend_from_slice(&self.arm_height.to_le_bytes());
        w
    }

    /// Parses [`AttestState::encode`].
    pub fn decode(b: &[u8]) -> Option<AttestState> {
        let mut r = Reader(b);
        let rec = AttestState {
            status: AttestStatus::from_u8(r.u8()?)?,
            trigger_height: r.i32()?,
            arm_height: r.i32()?,
        };
        r.done().then_some(rec)
    }
}

impl BundleLogRecord {
    /// The canonical serialisation.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Vec::new();
        w.extend_from_slice(&self.a_mint.to_le_bytes());
        w.extend_from_slice(&self.a_claim.to_le_bytes());
        put_compact_size(&mut w, self.selected_seqs.len());
        for s in &self.selected_seqs {
            w.extend_from_slice(&s.to_le_bytes());
        }
        put_compact_size(&mut w, self.seqs.len());
        for s in &self.seqs {
            w.extend_from_slice(&s.to_le_bytes());
        }
        put_compact_size(&mut w, self.prices.len());
        for p in &self.prices {
            w.extend_from_slice(&p.to_le_bytes());
        }
        put_compact_size(&mut w, self.cited_heights.len());
        for h in &self.cited_heights {
            w.extend_from_slice(&h.to_le_bytes());
        }
        w
    }

    /// Parses [`BundleLogRecord::encode`].
    pub fn decode(b: &[u8]) -> Option<BundleLogRecord> {
        let mut r = Reader(b);
        let u16le = |r: &mut Reader<'_>| r.take().map(u16::from_le_bytes);
        let rec = BundleLogRecord {
            a_mint: r.i64()?,
            a_claim: r.i64()?,
            selected_seqs: r.vec(u16le)?,
            seqs: r.vec(u16le)?,
            prices: r.vec(|r| r.i64())?,
            cited_heights: r.vec(|r| r.u32())?,
        };
        r.done().then_some(rec)
    }
}

/// The 2-byte serialisation of a seq (`AttestorSeqRecord` and `BondIndexRecord`).
pub fn encode_seq(seq: u16) -> [u8; 2] {
    seq.to_le_bytes()
}

/// Parses [`encode_seq`].
pub fn decode_seq(b: &[u8]) -> Option<u16> {
    <[u8; 2]>::try_from(b).ok().map(u16::from_le_bytes)
}

// ---------------------------------------------------------------- the store interface

/// What the attestor rules read of the YED state.
pub trait RegistryRead {
    /// `Attestors[seq]`.
    fn attestor(&self, seq: u16) -> Option<AttestorRecord>;
    /// Every `Attestors` record, ascending seq (the C++ `State::Attestors()`).
    fn attestors(&self) -> Vec<(u16, AttestorRecord)>;
    /// `AttestorSet`, once the module adopted `attestorSetId`'s `SET_CREATE`.
    fn attestor_set(&self) -> Option<AttestorSetRecord>;
    /// `AttestorSeq.next`: the seq the next `SET_JOIN` gets (0 when unset).
    fn next_seq(&self) -> u16;
    /// `BondIndex[outpoint]`: the seq whose bond the outpoint is.
    fn bond_seq(&self, bond: &OutPoint) -> Option<u16>;
}

/// What the attestor rules write. Every write is a full record (the C++ `State::Put`); the
/// implementation records the undo.
pub trait RegistryWrite: RegistryRead {
    /// Writes `Attestors[seq]`.
    fn put_attestor(&mut self, seq: u16, rec: AttestorRecord);
    /// Writes `AttestorSet`.
    fn put_attestor_set(&mut self, rec: AttestorSetRecord);
    /// Writes `AttestorSeq.next`.
    fn put_next_seq(&mut self, next: u16);
    /// Writes `BondIndex[bond] = seq`.
    fn put_bond_seq(&mut self, bond: OutPoint, seq: u16);
}

/// An in-memory registry: the attest-side tables as ordered maps.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Registry {
    /// `Attestors`.
    pub attestors: BTreeMap<u16, AttestorRecord>,
    /// `AttestorSet`.
    pub attestor_set: Option<AttestorSetRecord>,
    /// `AttestorSeq.next`; `None` = never written (reads as 0).
    pub next_seq: Option<u16>,
    /// `BondIndex`.
    pub bond_index: BTreeMap<OutPoint, u16>,
}

impl Registry {
    /// An empty registry.
    pub fn new() -> Registry {
        Registry::default()
    }

    /// The key → canonical bytes of every record, as the C++ store holds them (the bond index
    /// included; the state hash excludes `B`).
    pub fn canonical_entries(&self) -> BTreeMap<Vec<u8>, Vec<u8>> {
        let mut out = BTreeMap::new();
        for (seq, rec) in &self.attestors {
            out.insert(key_attestor(*seq), rec.encode());
        }
        if let Some(z) = &self.attestor_set {
            out.insert(key_attestor_set(), z.encode());
        }
        if let Some(n) = self.next_seq {
            out.insert(key_attestor_seq(), encode_seq(n).to_vec());
        }
        for (op, seq) in &self.bond_index {
            out.insert(key_bond_index(op), encode_seq(*seq).to_vec());
        }
        out
    }
}

impl RegistryRead for Registry {
    fn attestor(&self, seq: u16) -> Option<AttestorRecord> {
        self.attestors.get(&seq).copied()
    }
    fn attestors(&self) -> Vec<(u16, AttestorRecord)> {
        self.attestors.iter().map(|(s, r)| (*s, *r)).collect()
    }
    fn attestor_set(&self) -> Option<AttestorSetRecord> {
        self.attestor_set
    }
    fn next_seq(&self) -> u16 {
        self.next_seq.unwrap_or(0)
    }
    fn bond_seq(&self, bond: &OutPoint) -> Option<u16> {
        self.bond_index.get(bond).copied()
    }
}

impl RegistryWrite for Registry {
    fn put_attestor(&mut self, seq: u16, rec: AttestorRecord) {
        self.attestors.insert(seq, rec);
    }
    fn put_attestor_set(&mut self, rec: AttestorSetRecord) {
        self.attestor_set = Some(rec);
    }
    fn put_next_seq(&mut self, next: u16) {
        self.next_seq = Some(next);
    }
    fn put_bond_seq(&mut self, bond: OutPoint, seq: u16) {
        self.bond_index.insert(bond, seq);
    }
}
