// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

//! The read interface of the YED state ([`YedRead`]), the in-memory state ([`YedState`]), the
//! write overlay ([`YedOverlay`], the C++ `OverlayStateView` + `State`), the per-block change
//! set with its own undo ([`YedDelta`]) and the state hash (`StateHash`, `view.cpp:458`).
//!
//! The model is the kogany-vault one (`kogany_vault::state`): a block is evaluated over a
//! read-only base into an overlay, each transaction on a child overlay merged only when it
//! passes; the block's [`YedDelta`] carries every written key's value before and after, so the
//! base moves forward by [`YedState::apply`] and back, byte for byte, by [`YedState::revert`]
//! (the C++ `UndoRecord`: "the first pre-image of each key wins"). A store that is not a
//! `YedState` (the index, W5-e) implements [`YedRead`] and writes the delta's
//! [`YedDelta::canonical_entries`] itself.

use std::collections::BTreeMap;

use kogany_vault::{Hash32, OutPoint};
use sha2::{Digest, Sha256};

use super::keys::{Table, YedKey, YedRecord};
use super::records::{
    IntentRecord, Judgement, NoticeRecord, ParamsRecord, Snapshot, TagRecord, TipRecord,
    TokenRecord, Totals, TxLogRecord, VaultRecord,
};
use crate::attest::registry::{
    AttestState, AttestorRecord, AttestorSetRecord, BundleLogRecord, RegistryRead, RegistryWrite,
};

/// Read access to a YED state (the C++ `StateView` with `State`'s typed reads). Implemented by
/// [`YedState`], [`YedOverlay`] and the node's store (W5-e). Object safe: the rules take
/// `&dyn YedRead`.
pub trait YedRead {
    /// The record at `key`, if any.
    fn get(&self, key: &YedKey) -> Option<YedRecord>;

    /// Every entry of `table`, ascending key order (the C++ `Iterate(prefix)`).
    fn scan(&self, table: Table) -> Vec<(YedKey, YedRecord)>;

    /// `GetTip`.
    fn tip(&self) -> Option<TipRecord> {
        match self.get(&YedKey::Tip)? {
            YedRecord::Tip(r) => Some(r),
            _ => None,
        }
    }
    /// `GetTag` (no START_HEIGHT gate; the rules use [`super::tag_at`]).
    fn tag(&self, height: u32) -> Option<TagRecord> {
        match self.get(&YedKey::Tag(height))? {
            YedRecord::Tag(r) => Some(r),
            _ => None,
        }
    }
    /// `GetJudgement`.
    fn judgement(&self, height: u32) -> Option<Judgement> {
        match self.get(&YedKey::Judgement(height))? {
            YedRecord::Judgement(r) => Some(r),
            _ => None,
        }
    }
    /// `GetVault`.
    fn vault(&self, out: &OutPoint) -> Option<VaultRecord> {
        match self.get(&YedKey::Vault(*out))? {
            YedRecord::Vault(r) => Some(*r),
            _ => None,
        }
    }
    /// `GetToken`.
    fn token(&self, out: &OutPoint) -> Option<TokenRecord> {
        match self.get(&YedKey::Token(*out))? {
            YedRecord::Token(r) => Some(r),
            _ => None,
        }
    }
    /// `GetTxLog`.
    fn txlog(&self, txid: &Hash32) -> Option<TxLogRecord> {
        match self.get(&YedKey::TxLog(*txid))? {
            YedRecord::TxLog(r) => Some(*r),
            _ => None,
        }
    }
    /// `GetSnapshot` (stored only; the rules use [`super::snapshot_at`]).
    fn snapshot(&self, height: u32) -> Option<Snapshot> {
        match self.get(&YedKey::Snapshot(height))? {
            YedRecord::Snapshot(r) => Some(*r),
            _ => None,
        }
    }
    /// `GetTotals`: the zero totals when absent.
    fn totals(&self) -> Totals {
        match self.get(&YedKey::Totals) {
            Some(YedRecord::Totals(t)) => t,
            _ => Totals::default(),
        }
    }
    /// `GetParamsRecord`.
    fn params_record(&self) -> Option<ParamsRecord> {
        match self.get(&YedKey::Params)? {
            YedRecord::Params(r) => Some(r),
            _ => None,
        }
    }
    /// `GetAttest`: UNARMED/0/0 when absent.
    fn attest(&self) -> AttestState {
        match self.get(&YedKey::Attest) {
            Some(YedRecord::Attest(a)) => a,
            _ => AttestState::default(),
        }
    }
    /// `GetBundleLog`.
    fn bundle_log(&self, height: u32) -> Option<BundleLogRecord> {
        match self.get(&YedKey::BundleLog(height))? {
            YedRecord::BundleLog(r) => Some(r),
            _ => None,
        }
    }
    /// `GetNotice`.
    fn notice(&self, out: &OutPoint) -> Option<NoticeRecord> {
        match self.get(&YedKey::Notice(*out))? {
            YedRecord::Notice(r) => Some(r),
            _ => None,
        }
    }
    /// `GetIntent`.
    fn intent(&self, out: &OutPoint) -> Option<IntentRecord> {
        match self.get(&YedKey::Intent(*out))? {
            YedRecord::Intent(r) => Some(r),
            _ => None,
        }
    }
    /// `Intents()`: every intent, ascending outpoint key order.
    fn intents(&self) -> Vec<(OutPoint, IntentRecord)> {
        self.scan(Table::Intent)
            .into_iter()
            .filter_map(|(k, v)| match (k, v) {
                (YedKey::Intent(o), YedRecord::Intent(r)) => Some((o, r)),
                _ => None,
            })
            .collect()
    }
    /// Every vault, ascending outpoint key order.
    fn vaults(&self) -> Vec<(OutPoint, VaultRecord)> {
        self.scan(Table::Vault)
            .into_iter()
            .filter_map(|(k, v)| match (k, v) {
                (YedKey::Vault(o), YedRecord::Vault(r)) => Some((o, *r)),
                _ => None,
            })
            .collect()
    }
    /// Every token, ascending outpoint key order.
    fn tokens(&self) -> Vec<(OutPoint, TokenRecord)> {
        self.scan(Table::Token)
            .into_iter()
            .filter_map(|(k, v)| match (k, v) {
                (YedKey::Token(o), YedRecord::Token(r)) => Some((o, r)),
                _ => None,
            })
            .collect()
    }
}

/// Every record of a state as canonical key → value bytes.
pub fn canonical_entries_of(read: &dyn YedRead) -> BTreeMap<Vec<u8>, Vec<u8>> {
    let mut out = BTreeMap::new();
    for t in ALL_TABLES {
        for (k, v) in read.scan(t) {
            out.insert(k.encode(), v.encode());
        }
    }
    out
}

const ALL_TABLES: [Table; 17] = [
    Table::Attestor,
    Table::BondIndex,
    Table::Notice,
    Table::Totals,
    Table::Intent,
    Table::Judgement,
    Table::Token,
    Table::TxLog,
    Table::Attest,
    Table::AttestorSeq,
    Table::Params,
    Table::Tag,
    Table::Snapshot,
    Table::Tip,
    Table::Vault,
    Table::BundleLog,
    Table::AttestorSet,
];

/// The `yed_getstatehash` preimage (`StateHash`, N18): `key ‖ value` of the tip (the zero tip
/// with `network` when none was written), then of every record of the tables
/// [`Table::HASHED`], each in ascending key order. TxLog and the bond index are excluded.
pub fn state_hash_preimage(read: &dyn YedRead, network: &str) -> Vec<u8> {
    let mut pre = YedKey::Tip.encode();
    match read.tip() {
        Some(t) => pre.extend(t.encode()),
        None => pre.extend(TipRecord::zero(network).encode()),
    }
    for t in Table::HASHED {
        for (k, v) in read.scan(t) {
            pre.extend(k.encode());
            pre.extend(v.encode());
        }
    }
    pre
}

/// The state hash: single SHA-256 of [`state_hash_preimage`], in natural digest order — the hex
/// of these bytes is what `yed_getstatehash` prints and the golden vectors pin (the C++ stores
/// the digest reversed so `uint256::GetHex` shows it in this order).
pub fn state_hash(read: &dyn YedRead, network: &str) -> [u8; 32] {
    Sha256::digest(state_hash_preimage(read, network)).into()
}

// ---------------------------------------------------------------- the in-memory state

/// The whole YED state in memory (the C++ `MemoryStateView`, typed). `BTreeMap` only.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct YedState {
    /// Every record by key.
    pub entries: BTreeMap<YedKey, YedRecord>,
}

fn table_range<V>(
    map: &BTreeMap<YedKey, V>,
    t: Table,
) -> std::collections::btree_map::Range<'_, YedKey, V> {
    let (lo, hi) = t.bounds();
    map.range(lo..=hi)
}

impl YedRead for YedState {
    fn get(&self, key: &YedKey) -> Option<YedRecord> {
        self.entries.get(key).cloned()
    }
    fn scan(&self, table: Table) -> Vec<(YedKey, YedRecord)> {
        table_range(&self.entries, table)
            .map(|(k, v)| (*k, v.clone()))
            .collect()
    }
}

impl YedState {
    /// An empty state.
    pub fn new() -> YedState {
        YedState::default()
    }

    /// Every record as canonical key → value bytes (what a byte store holds).
    pub fn canonical_entries(&self) -> BTreeMap<Vec<u8>, Vec<u8>> {
        self.entries
            .iter()
            .map(|(k, v)| (k.encode(), v.encode()))
            .collect()
    }

    /// Moves the state forward by a block's delta.
    pub fn apply(&mut self, delta: &YedDelta) {
        delta.write(self, false);
    }

    /// Moves the state back by a block's delta (the block's undo, byte for byte, when `self` is
    /// the base `delta` was computed against plus `delta`).
    pub fn revert(&mut self, delta: &YedDelta) {
        delta.write(self, true);
    }

    /// A copy with `delta` applied.
    pub fn with(&self, delta: &YedDelta) -> YedState {
        let mut s = self.clone();
        s.apply(delta);
        s
    }
}

// ---------------------------------------------------------------- the delta

/// One key's change: its value before the block and after it (`None` = absent).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Change<T> {
    /// The base's value (the undo).
    pub before: Option<T>,
    /// The value after the block.
    pub after: Option<T>,
}

/// A canonical entry's (before, after) bytes.
pub type CanonicalChange = (Option<Vec<u8>>, Option<Vec<u8>>);

/// The per-block change set of the YED state with its own undo: every key the block wrote, with
/// the base's prior value. A key written back to its prior value is kept (as the C++ undo keeps
/// it).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct YedDelta {
    /// The changed keys.
    pub changes: BTreeMap<YedKey, Change<YedRecord>>,
}

impl YedDelta {
    /// No key changed.
    pub fn is_empty(&self) -> bool {
        self.changes.is_empty()
    }

    /// The number of changed keys.
    pub fn len(&self) -> usize {
        self.changes.len()
    }

    /// The delta that undoes this one.
    pub fn inverse(&self) -> YedDelta {
        YedDelta {
            changes: self
                .changes
                .iter()
                .map(|(k, c)| {
                    (
                        *k,
                        Change {
                            before: c.after.clone(),
                            after: c.before.clone(),
                        },
                    )
                })
                .collect(),
        }
    }

    fn write(&self, s: &mut YedState, undo: bool) {
        for (k, c) in &self.changes {
            let v = if undo { &c.before } else { &c.after };
            match v {
                Some(r) => {
                    s.entries.insert(*k, r.clone());
                }
                None => {
                    s.entries.remove(k);
                }
            }
        }
    }

    /// The changed keys in canonical form, key → (before, after) bytes.
    pub fn canonical_entries(&self) -> BTreeMap<Vec<u8>, CanonicalChange> {
        self.changes
            .iter()
            .map(|(k, c)| {
                (
                    k.encode(),
                    (
                        c.before.as_ref().map(YedRecord::encode),
                        c.after.as_ref().map(YedRecord::encode),
                    ),
                )
            })
            .collect()
    }
}

// ---------------------------------------------------------------- the overlay

/// The writes of one overlay (`None` = erased).
pub type Writes = BTreeMap<YedKey, Option<YedRecord>>;

/// A copy-on-write overlay over a read-only base (`OverlayStateView` with `State` on top):
/// reads fall through to the base unless written here. Implements [`YedRead`] with the writes
/// visible, and the attest module's [`RegistryRead`] / [`RegistryWrite`] over the attestor
/// tables.
pub struct YedOverlay<'a> {
    base: &'a dyn YedRead,
    writes: Writes,
}

impl YedRead for YedOverlay<'_> {
    fn get(&self, key: &YedKey) -> Option<YedRecord> {
        match self.writes.get(key) {
            Some(v) => v.clone(),
            None => self.base.get(key),
        }
    }
    fn scan(&self, table: Table) -> Vec<(YedKey, YedRecord)> {
        let mut merged: BTreeMap<YedKey, YedRecord> = self.base.scan(table).into_iter().collect();
        for (k, v) in table_range(&self.writes, table) {
            match v {
                Some(r) => {
                    merged.insert(*k, r.clone());
                }
                None => {
                    merged.remove(k);
                }
            }
        }
        merged.into_iter().collect()
    }
}

impl<'a> YedOverlay<'a> {
    /// An empty overlay over `base`.
    pub fn new(base: &'a dyn YedRead) -> YedOverlay<'a> {
        YedOverlay {
            base,
            writes: BTreeMap::new(),
        }
    }

    /// No write yet.
    pub fn is_empty(&self) -> bool {
        self.writes.is_empty()
    }

    /// The pending writes (`OverlayStateView::Pending`).
    pub fn writes(&self) -> &Writes {
        &self.writes
    }

    /// Moves the writes out (a child overlay's, to merge into its parent).
    pub fn into_writes(self) -> Writes {
        self.writes
    }

    /// Takes a child's writes on top of this overlay's.
    pub fn merge(&mut self, w: Writes) {
        self.writes.extend(w);
    }

    /// Discards every write.
    pub fn discard(&mut self) {
        self.writes.clear();
    }

    /// The overlay's writes with the base's prior values: the block's [`YedDelta`].
    pub fn delta(&self) -> YedDelta {
        YedDelta {
            changes: self
                .writes
                .iter()
                .map(|(k, v)| {
                    (
                        *k,
                        Change {
                            before: self.base.get(k),
                            after: v.clone(),
                        },
                    )
                })
                .collect(),
        }
    }

    /// `State::Put`.
    pub fn put(&mut self, key: YedKey, rec: YedRecord) {
        self.writes.insert(key, Some(rec));
    }

    /// `State::EraseKey`.
    pub fn erase(&mut self, key: YedKey) {
        self.writes.insert(key, None);
    }

    /// `State::Has`.
    pub fn has(&self, key: &YedKey) -> bool {
        self.get(key).is_some()
    }

    /// Writes `Vaults[out]`.
    pub fn put_vault(&mut self, out: OutPoint, rec: VaultRecord) {
        self.put(YedKey::Vault(out), YedRecord::Vault(Box::new(rec)));
    }
    /// Writes `Tokens[out]`.
    pub fn put_token(&mut self, out: OutPoint, rec: TokenRecord) {
        self.put(YedKey::Token(out), YedRecord::Token(rec));
    }
    /// Writes `Intents[out]`.
    pub fn put_intent(&mut self, out: OutPoint, rec: IntentRecord) {
        self.put(YedKey::Intent(out), YedRecord::Intent(rec));
    }
    /// Writes `Notices[out]`.
    pub fn put_notice(&mut self, out: OutPoint, rec: NoticeRecord) {
        self.put(YedKey::Notice(out), YedRecord::Notice(rec));
    }
    /// Writes `Totals`.
    pub fn put_totals(&mut self, t: Totals) {
        self.put(YedKey::Totals, YedRecord::Totals(t));
    }
    /// Writes `TxLog[txid]`.
    pub fn put_txlog(&mut self, txid: Hash32, rec: TxLogRecord) {
        self.put(YedKey::TxLog(txid), YedRecord::TxLog(Box::new(rec)));
    }
    /// Writes `Snapshots[h]`.
    pub fn put_snapshot(&mut self, h: u32, s: Snapshot) {
        self.put(YedKey::Snapshot(h), YedRecord::Snapshot(Box::new(s)));
    }
    /// Writes `Tags[h]`.
    pub fn put_tag(&mut self, h: u32, t: TagRecord) {
        self.put(YedKey::Tag(h), YedRecord::Tag(t));
    }
    /// Writes `Judgements[h]`.
    pub fn put_judgement(&mut self, h: u32, j: Judgement) {
        self.put(YedKey::Judgement(h), YedRecord::Judgement(j));
    }
    /// Writes `Attest`.
    pub fn put_attest(&mut self, a: AttestState) {
        self.put(YedKey::Attest, YedRecord::Attest(a));
    }
    /// Writes `BundleLog[h]`.
    pub fn put_bundle_log(&mut self, h: u32, r: BundleLogRecord) {
        self.put(YedKey::BundleLog(h), YedRecord::BundleLog(r));
    }
}

impl RegistryRead for YedOverlay<'_> {
    fn attestor(&self, seq: u16) -> Option<AttestorRecord> {
        attestor_of(self, seq)
    }
    fn attestors(&self) -> Vec<(u16, AttestorRecord)> {
        attestors_of(self)
    }
    fn attestor_set(&self) -> Option<AttestorSetRecord> {
        attestor_set_of(self)
    }
    fn next_seq(&self) -> u16 {
        next_seq_of(self)
    }
    fn bond_seq(&self, bond: &OutPoint) -> Option<u16> {
        bond_seq_of(self, bond)
    }
}

impl RegistryWrite for YedOverlay<'_> {
    fn put_attestor(&mut self, seq: u16, rec: AttestorRecord) {
        self.put(YedKey::Attestor(seq), YedRecord::Attestor(rec));
    }
    fn put_attestor_set(&mut self, rec: AttestorSetRecord) {
        self.put(YedKey::AttestorSet, YedRecord::AttestorSet(rec));
    }
    fn put_next_seq(&mut self, next: u16) {
        self.put(YedKey::AttestorSeq, YedRecord::AttestorSeq(next));
    }
    fn put_bond_seq(&mut self, bond: OutPoint, seq: u16) {
        self.put(YedKey::BondIndex(bond), YedRecord::BondIndex(seq));
    }
}

impl RegistryRead for YedState {
    fn attestor(&self, seq: u16) -> Option<AttestorRecord> {
        attestor_of(self, seq)
    }
    fn attestors(&self) -> Vec<(u16, AttestorRecord)> {
        attestors_of(self)
    }
    fn attestor_set(&self) -> Option<AttestorSetRecord> {
        attestor_set_of(self)
    }
    fn next_seq(&self) -> u16 {
        next_seq_of(self)
    }
    fn bond_seq(&self, bond: &OutPoint) -> Option<u16> {
        bond_seq_of(self, bond)
    }
}

/// `GetAttestor` over any [`YedRead`].
pub fn attestor_of(r: &dyn YedRead, seq: u16) -> Option<AttestorRecord> {
    match r.get(&YedKey::Attestor(seq))? {
        YedRecord::Attestor(a) => Some(a),
        _ => None,
    }
}

/// `State::Attestors()` over any [`YedRead`]: ascending seq.
pub fn attestors_of(r: &dyn YedRead) -> Vec<(u16, AttestorRecord)> {
    r.scan(Table::Attestor)
        .into_iter()
        .filter_map(|(k, v)| match (k, v) {
            (YedKey::Attestor(s), YedRecord::Attestor(a)) => Some((s, a)),
            _ => None,
        })
        .collect()
}

/// `GetAttestorSet` over any [`YedRead`].
pub fn attestor_set_of(r: &dyn YedRead) -> Option<AttestorSetRecord> {
    match r.get(&YedKey::AttestorSet)? {
        YedRecord::AttestorSet(z) => Some(z),
        _ => None,
    }
}

/// `GetAttestorSeq().next` over any [`YedRead`]: 0 when absent.
pub fn next_seq_of(r: &dyn YedRead) -> u16 {
    match r.get(&YedKey::AttestorSeq) {
        Some(YedRecord::AttestorSeq(n)) => n,
        _ => 0,
    }
}

/// `GetBondIndex` over any [`YedRead`].
pub fn bond_seq_of(r: &dyn YedRead, bond: &OutPoint) -> Option<u16> {
    match r.get(&YedKey::BondIndex(*bond))? {
        YedRecord::BondIndex(s) => Some(s),
        _ => None,
    }
}
