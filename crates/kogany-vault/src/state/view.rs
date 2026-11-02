//! The read interface of the set state, the §15.4 predicates over it, the in-memory state
//! [`SetState`] and the per-block change set [`Delta`].

use std::collections::{BTreeMap, BTreeSet};

use super::hash::state_hash_of_entries;
use super::records::{
    key_bond, key_member, key_set, key_template_out, BondRecord, MemberRecord, MemberStatus,
    SetRecord, TemplateOutRecord,
};
use crate::act::{recover_sig, MAX_MONEY};
use crate::bytes::{Hash32, OutPoint, PubKeyBytes, RecoverableSig, SetId};
use crate::template::{ROLE_CANCEL, ROLE_UNLOCK};

/// A set's members in member-key byte order (the C++ `MemberList`).
pub type MemberList = Vec<(PubKeyBytes, MemberRecord)>;

/// Read access to a set state (the C++ `KVReader` with its typed reads). Implemented by the
/// in-memory [`SetState`], by the rules' write overlay ([`super::VaultOverlay`]), and by
/// whatever the node keeps (W4-c: column families plus the non-finalized deltas).
///
/// The provided methods are the snapshot queries script evaluation needs (C++ `SetSnapshot`):
/// the state after the parent block, asked at the spending height.
pub trait StateRead {
    /// The set record.
    fn set(&self, set_id: &SetId) -> Option<SetRecord>;
    /// One member's record.
    fn member(&self, set_id: &SetId, key: &PubKeyBytes) -> Option<MemberRecord>;
    /// Every member record of a set, in member-key byte order.
    fn members(&self, set_id: &SetId) -> MemberList;
    /// The bond index entry of an outpoint.
    fn bond(&self, outpoint: &OutPoint) -> Option<BondRecord>;
    /// The template-output index entry of an outpoint.
    fn template_out(&self, outpoint: &OutPoint) -> Option<TemplateOutRecord>;

    /// `key` is a current member of the set at `h` (C++ `SetSnapshot::IsCurrentMember`).
    fn is_current_member(&self, set_id: &SetId, key: &PubKeyBytes, h: i64) -> bool {
        match (self.set(set_id), self.member(set_id, key)) {
            (Some(s), Some(m)) => is_current(&s, &m, h),
            _ => false,
        }
    }

    /// Role 1 → unlock threshold, 2 → cancel threshold; `None` for an unknown set or role
    /// (C++ `SetSnapshot::Threshold`, the checker's `SetThreshold`).
    fn threshold(&self, set_id: &SetId, role: u8) -> Option<u8> {
        let s = self.set(set_id)?;
        match role {
            ROLE_UNLOCK => Some(s.params.unlock_threshold),
            ROLE_CANCEL => Some(s.params.cancel_threshold),
            _ => None,
        }
    }

    /// Dormant at `h`; false for an unknown set (C++ `SetSnapshot::IsDormant`).
    fn is_dormant(&self, set_id: &SetId, h: i64) -> bool {
        match self.set(set_id) {
            Some(s) => is_dormant(&s, &self.members(set_id), h),
            None => false,
        }
    }

    /// Dormant, or wound down for `livenessWindow` blocks, or unknown (§15.4; C++
    /// `SetSnapshot::IsReleased`, the checker's `IsSetReleased`).
    fn is_released(&self, set_id: &SetId, h: i64) -> bool {
        let s = self.set(set_id);
        let members = if s.is_some() {
            self.members(set_id)
        } else {
            Vec::new()
        };
        is_released(s.as_ref(), &members, h)
    }

    /// §15.2 steps 2, 3, 5 (C++ `SetSnapshot::CheckSetSigs`): exactly `threshold(role)`
    /// 65-byte low-S recoverable signatures over `msg`, recovering to distinct current members
    /// at `h`. The caller computes `msg = setSigMsg(setId, role, prevout, sighash)`.
    fn check_set_sigs(
        &self,
        set_id: &SetId,
        role: u8,
        msg: &Hash32,
        sigs: &[Vec<u8>],
        h: i64,
    ) -> bool {
        let Some(k) = self.threshold(set_id, role) else {
            return false;
        };
        if usize::from(k) != sigs.len() {
            return false;
        }
        let Some(s) = self.set(set_id) else {
            return false;
        };
        let members = self.members(set_id);
        let mut seen = BTreeSet::new();
        for sig in sigs {
            let Some(key) = RecoverableSig::from_slice(sig).and_then(|sig| recover_sig(msg, &sig))
            else {
                return false;
            };
            if !seen.insert(key) {
                return false;
            }
            let current = members
                .iter()
                .find(|(mk, _)| *mk == key)
                .is_some_and(|(_, m)| is_current(&s, m, h));
            if !current {
                return false;
            }
        }
        true
    }
}

// ---- §15.4 predicates -------------------------------------------------------------------

/// ACTIVE and matured at `h` (C++ `IsCurrent`).
pub fn is_current(s: &SetRecord, m: &MemberRecord, h: i64) -> bool {
    m.status == MemberStatus::Active
        && h >= m.join_height.wrapping_add(i64::from(s.params.maturity))
}

/// The number of current members at `h` (C++ `CountCurrent`).
pub fn count_current(s: &SetRecord, members: &[(PubKeyBytes, MemberRecord)], h: i64) -> usize {
    members.iter().filter(|(_, m)| is_current(s, m, h)).count()
}

/// The number of ACTIVE members, mature or not (C++ `CountActive`).
pub fn count_active(members: &[(PubKeyBytes, MemberRecord)]) -> usize {
    members
        .iter()
        .filter(|(_, m)| m.status == MemberStatus::Active)
        .count()
}

/// Fewer than `cancelThreshold` current members acted within the liveness window
/// (C++ `IsDormant`).
pub fn is_dormant(s: &SetRecord, members: &[(PubKeyBytes, MemberRecord)], h: i64) -> bool {
    let since = h.wrapping_sub(i64::from(s.params.liveness_window));
    let live = members
        .iter()
        .filter(|(_, m)| is_current(s, m, h) && m.last_act >= since)
        .count();
    live < usize::from(s.params.cancel_threshold)
}

/// Unknown, dormant, or wound down `livenessWindow` blocks ago (C++ `IsReleased`).
pub fn is_released(s: Option<&SetRecord>, members: &[(PubKeyBytes, MemberRecord)], h: i64) -> bool {
    let Some(s) = s else {
        return true;
    };
    if is_dormant(s, members, h) {
        return true;
    }
    s.wind_down_height != 0
        && h >= s
            .wind_down_height
            .wrapping_add(i64::from(s.params.liveness_window))
}

/// `floor(basis × bps / 10000)` without overflow (C++ `RateCap`); 0 for `basis <= 0`.
pub fn rate_cap(basis: i64, bps: u16) -> i64 {
    if basis <= 0 {
        return 0;
    }
    let bps = i64::from(bps);
    // basis / 10000 * bps <= basis for bps <= 10000; the remainder term is < bps.
    (basis / 10_000)
        .wrapping_mul(bps)
        .wrapping_add((basis % 10_000).wrapping_mul(bps) / 10_000)
}

/// `0 <= v <= MAX_MONEY` (C++ `MoneyRange`).
pub fn money_range(v: i64) -> bool {
    (0..=MAX_MONEY).contains(&v)
}

// ---- the in-memory state ----------------------------------------------------------------

/// The whole set state in memory (the C++ key space `'s'`/`'m'`/`'b'`/`'v'` as typed maps).
/// `BTreeMap` only: iteration order never depends on a hasher.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SetState {
    /// Set records by set id.
    pub sets: BTreeMap<SetId, SetRecord>,
    /// Member records by (set id, member key).
    pub members: BTreeMap<(SetId, PubKeyBytes), MemberRecord>,
    /// The bond index.
    pub bonds: BTreeMap<OutPoint, BondRecord>,
    /// The template-output index.
    pub template_outs: BTreeMap<OutPoint, TemplateOutRecord>,
}

/// The lowest and highest member keys, for a set's member range.
const KEY_MIN: PubKeyBytes = PubKeyBytes([0u8; 33]);
const KEY_MAX: PubKeyBytes = PubKeyBytes([0xffu8; 33]);

pub(crate) fn member_range(set_id: &SetId) -> core::ops::RangeInclusive<(SetId, PubKeyBytes)> {
    (*set_id, KEY_MIN)..=(*set_id, KEY_MAX)
}

impl StateRead for SetState {
    fn set(&self, set_id: &SetId) -> Option<SetRecord> {
        self.sets.get(set_id).copied()
    }
    fn member(&self, set_id: &SetId, key: &PubKeyBytes) -> Option<MemberRecord> {
        self.members.get(&(*set_id, *key)).copied()
    }
    fn members(&self, set_id: &SetId) -> MemberList {
        self.members
            .range(member_range(set_id))
            .map(|((_, k), m)| (*k, *m))
            .collect()
    }
    fn bond(&self, outpoint: &OutPoint) -> Option<BondRecord> {
        self.bonds.get(outpoint).copied()
    }
    fn template_out(&self, outpoint: &OutPoint) -> Option<TemplateOutRecord> {
        self.template_outs.get(outpoint).cloned()
    }
}

impl SetState {
    /// An empty state (before activation).
    pub fn new() -> SetState {
        SetState::default()
    }

    /// Every entry in its canonical encoding, keyed by its canonical key: the `statehash`
    /// preimage's entries ([`super::records`]).
    pub fn canonical_entries(&self) -> BTreeMap<Vec<u8>, Vec<u8>> {
        let mut out = BTreeMap::new();
        for (id, r) in &self.sets {
            out.insert(key_set(id), r.encode());
        }
        for ((id, k), r) in &self.members {
            out.insert(key_member(id, k), r.encode());
        }
        for (op, r) in &self.bonds {
            out.insert(key_bond(op), r.encode());
        }
        for (op, r) in &self.template_outs {
            out.insert(key_template_out(op), r.encode());
        }
        out
    }

    /// The canonical `statehash` (C++ `vault::StateHash`), internal byte order; RPC prints it
    /// with [`super::display_hex`].
    pub fn state_hash(&self) -> Hash32 {
        state_hash_of_entries(&self.canonical_entries())
    }

    /// Applies a block's delta (every changed entry to its `after` value).
    pub fn apply(&mut self, delta: &Delta) {
        delta.write(self, false);
    }

    /// Reverts a block's delta (every changed entry back to its `before` value): the block's
    /// undo, byte for byte, provided `self` is the state `delta` was computed against plus
    /// `delta`.
    pub fn revert(&mut self, delta: &Delta) {
        delta.write(self, true);
    }

    /// A copy with `delta` applied.
    pub fn with(&self, delta: &Delta) -> SetState {
        let mut s = self.clone();
        s.apply(delta);
        s
    }

    /// Every set id, in key order (C++ `ListSets`).
    pub fn set_ids(&self) -> Vec<SetId> {
        self.sets.keys().copied().collect()
    }
}

// ---- the delta --------------------------------------------------------------------------

/// A canonical entry's (before, after) bytes; `None` = absent.
pub type CanonicalChange = (Option<Vec<u8>>, Option<Vec<u8>>);

/// One entry's change: its value before the block and after it (`None` = absent).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Change<T> {
    /// The value in the base state (the block's undo).
    pub before: Option<T>,
    /// The value after the block.
    pub after: Option<T>,
}

/// The per-block change set of the set state, with its own undo: every entry the block
/// wrote, with the base's prior value (C++ `VaultState::Changes()` plus `MakeUndo()`).
///
/// Computed by [`super::apply_block`] against a parent state; applied forward with
/// [`SetState::apply`] and reverted on a reorg with [`SetState::revert`]. An entry that was
/// written with its own prior value is kept (as in the C++, whose undo then rewrites it).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Delta {
    /// Changed set records.
    pub sets: BTreeMap<SetId, Change<SetRecord>>,
    /// Changed member records.
    pub members: BTreeMap<(SetId, PubKeyBytes), Change<MemberRecord>>,
    /// Changed bond-index entries.
    pub bonds: BTreeMap<OutPoint, Change<BondRecord>>,
    /// Changed template-output index entries.
    pub template_outs: BTreeMap<OutPoint, Change<TemplateOutRecord>>,
}

fn put<K: Ord + Clone, T: Clone>(map: &mut BTreeMap<K, T>, k: &K, v: &Option<T>) {
    match v {
        Some(v) => {
            map.insert(k.clone(), v.clone());
        }
        None => {
            map.remove(k);
        }
    }
}

impl Delta {
    /// No entry changed.
    pub fn is_empty(&self) -> bool {
        self.sets.is_empty()
            && self.members.is_empty()
            && self.bonds.is_empty()
            && self.template_outs.is_empty()
    }

    /// The number of changed entries.
    pub fn len(&self) -> usize {
        self.sets
            .len()
            .saturating_add(self.members.len())
            .saturating_add(self.bonds.len())
            .saturating_add(self.template_outs.len())
    }

    /// The delta that undoes this one (before and after swapped).
    pub fn inverse(&self) -> Delta {
        fn inv<K: Ord + Clone, T: Clone>(m: &BTreeMap<K, Change<T>>) -> BTreeMap<K, Change<T>> {
            m.iter()
                .map(|(k, c)| {
                    (
                        k.clone(),
                        Change {
                            before: c.after.clone(),
                            after: c.before.clone(),
                        },
                    )
                })
                .collect()
        }
        Delta {
            sets: inv(&self.sets),
            members: inv(&self.members),
            bonds: inv(&self.bonds),
            template_outs: inv(&self.template_outs),
        }
    }

    fn write(&self, s: &mut SetState, undo: bool) {
        fn side<T>(c: &Change<T>, undo: bool) -> &Option<T> {
            if undo {
                &c.before
            } else {
                &c.after
            }
        }
        for (k, c) in &self.sets {
            put(&mut s.sets, k, side(c, undo));
        }
        for (k, c) in &self.members {
            put(&mut s.members, k, side(c, undo));
        }
        for (k, c) in &self.bonds {
            put(&mut s.bonds, k, side(c, undo));
        }
        for (k, c) in &self.template_outs {
            put(&mut s.template_outs, k, side(c, undo));
        }
    }

    /// The changed entries in canonical form, key → (before, after), for storage layers and
    /// for comparing two deltas byte for byte.
    pub fn canonical_entries(&self) -> BTreeMap<Vec<u8>, CanonicalChange> {
        let mut out = BTreeMap::new();
        for (id, c) in &self.sets {
            out.insert(
                key_set(id),
                (c.before.map(|r| r.encode()), c.after.map(|r| r.encode())),
            );
        }
        for ((id, k), c) in &self.members {
            out.insert(
                key_member(id, k),
                (c.before.map(|r| r.encode()), c.after.map(|r| r.encode())),
            );
        }
        for (op, c) in &self.bonds {
            out.insert(
                key_bond(op),
                (c.before.map(|r| r.encode()), c.after.map(|r| r.encode())),
            );
        }
        for (op, c) in &self.template_outs {
            out.insert(
                key_template_out(op),
                (
                    c.before.as_ref().map(TemplateOutRecord::encode),
                    c.after.as_ref().map(TemplateOutRecord::encode),
                ),
            );
        }
        out
    }
}
