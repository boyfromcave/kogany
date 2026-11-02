//! The Vault upgrade's set state in a non-finalized [`Chain`] (kogany plan W4-c, M24-15, M24-16).
//!
//! ycash6 undoes a block's vault changes from a per-block undo record. A Zakura fork is an
//! in-memory [`Chain`] above the finalized tip, reverted block by block through
//! [`UpdateWith`]. So each [`ContextuallyVerifiedBlock`](crate::ContextuallyVerifiedBlock)
//! carries its block's [`VaultDelta`] (every changed entry with its value before and after), and
//! the chain keeps one [`ChainVaultOverlay`]: for every canonical key some block of this chain
//! wrote, the value after the newest such block, and how many of the chain's blocks wrote it.
//!
//! - push: the entry takes the delta's `after` value;
//! - pop the tip (a reorg): it goes back to the delta's `before` value, or leaves the overlay when
//!   no other block of the chain wrote it (the finalized value applies again);
//! - pop the root (finalization): the finalized database now holds the root's value, so an entry
//!   no remaining block wrote leaves the overlay.
//!
//! The overlay never holds more entries than the chain's blocks wrote, so its memory is bounded
//! by the non-finalized window (K-13: 1,000 blocks; see [`ChainVaultOverlay::approx_bytes`]).

use std::{collections::BTreeMap, sync::Arc};

use kogany_vault::{
    state::{
        BondRecord, Delta, MemberList, MemberRecord, SetRecord, SetState, StateRead,
        TemplateOutRecord,
    },
    OutPoint, PubKeyBytes, SetId,
};

use crate::{
    service::finalized_state::{
        vault::{member_key_of, member_key_range, set_state_from_entries},
        ZakuraDb,
    },
    ValidateContextError,
};

use super::{Chain, RevertPosition, UpdateWith};

/// A block's vault change set: [`kogany_vault::state::Delta`], computed against the state after
/// the block's parent.
pub type VaultDelta = Delta;

/// One overlay entry: the value after the newest block of the chain that wrote the key (`None` =
/// erased), and how many of the chain's blocks wrote it.
#[derive(Clone, Debug, PartialEq, Eq)]
struct OverlayEntry {
    value: Option<Vec<u8>>,
    writers: u32,
}

/// The chain's vault writes over the finalized state, keyed by canonical key.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ChainVaultOverlay {
    entries: Arc<BTreeMap<Vec<u8>, OverlayEntry>>,
}

impl ChainVaultOverlay {
    /// `Some(value)` when the chain decides the key (`Some(None)` = erased by the chain), `None`
    /// when the finalized state does.
    pub fn get(&self, canonical_key: &[u8]) -> Option<Option<&Vec<u8>>> {
        self.entries.get(canonical_key).map(|e| e.value.as_ref())
    }

    /// The chain's entries in `[from, to]`, canonical key → value (`None` = erased).
    pub fn range(
        &self,
        from: &[u8],
        to: &[u8],
    ) -> impl Iterator<Item = (&Vec<u8>, Option<&Vec<u8>>)> {
        self.entries
            .range::<[u8], _>((
                std::ops::Bound::Included(from),
                std::ops::Bound::Included(to),
            ))
            .map(|(k, e)| (k, e.value.as_ref()))
    }

    /// The number of keys the chain's blocks wrote.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// No block of the chain wrote a vault entry.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The overlay's approximate heap size in bytes: keys and values plus a per-entry map
    /// overhead (K-13 measurement).
    pub fn approx_bytes(&self) -> usize {
        const PER_ENTRY: usize = 64;
        self.entries
            .iter()
            .map(|(k, e)| k.len() + e.value.as_ref().map_or(0, Vec::len) + PER_ENTRY)
            .sum()
    }

    fn push(&mut self, delta: &VaultDelta) {
        if delta.is_empty() {
            return;
        }
        let entries = Arc::make_mut(&mut self.entries);
        for (key, (_before, after)) in delta.canonical_entries() {
            let entry = entries.entry(key).or_insert(OverlayEntry {
                value: None,
                writers: 0,
            });
            entry.value = after;
            entry.writers = entry.writers.saturating_add(1);
        }
    }

    fn pop(&mut self, delta: &VaultDelta, position: RevertPosition) {
        if delta.is_empty() {
            return;
        }
        let entries = Arc::make_mut(&mut self.entries);
        for (key, (before, _after)) in delta.canonical_entries() {
            let entry = entries
                .get_mut(&key)
                .expect("every key of a pushed block's delta is in the overlay until it is popped");
            entry.writers = entry
                .writers
                .checked_sub(1)
                .expect("a key is popped at most as often as it was pushed");
            if entry.writers == 0 {
                // No other block of the chain wrote the key: the finalized value applies (after
                // a root pop, the finalized state is committing the root's value).
                entries.remove(&key);
            } else if position == RevertPosition::Tip {
                // The tip was the newest writer, so the previous writer's value is its `before`.
                entry.value = before;
            }
        }
    }
}

impl UpdateWith<VaultDelta> for Chain {
    fn update_chain_tip_with(&mut self, delta: &VaultDelta) -> Result<(), ValidateContextError> {
        self.vault_overlay.push(delta);
        Ok(())
    }

    fn revert_chain_with(&mut self, delta: &VaultDelta, position: RevertPosition) {
        self.vault_overlay.pop(delta, position);
    }
}

/// The set state at a non-finalized chain's tip: the chain's overlay over the finalized state.
/// The base for the next block's vault transition and for scripts that spend at the next height.
#[derive(Clone, Copy)]
pub struct ChainVaultView<'a> {
    /// The chain's writes, or `None` for the finalized tip itself.
    pub overlay: Option<&'a ChainVaultOverlay>,
    /// The finalized state below the chain.
    pub db: &'a ZakuraDb,
}

impl ChainVaultView<'_> {
    fn raw(&self, key: &[u8]) -> Option<Vec<u8>> {
        match self.overlay.and_then(|o| o.get(key)) {
            Some(value) => value.cloned(),
            None => self.db.vault_raw_get(key),
        }
    }

    /// Every entry at the chain's tip, canonical key → value: the `statehash` preimage.
    pub fn canonical_entries(&self) -> BTreeMap<Vec<u8>, Vec<u8>> {
        let mut entries = self.db.vault_canonical_entries();
        if let Some(overlay) = self.overlay {
            for (k, e) in overlay.entries.iter() {
                match &e.value {
                    Some(v) => entries.insert(k.clone(), v.clone()),
                    None => entries.remove(k),
                };
            }
        }
        entries
    }

    /// The whole set state at the chain's tip, in memory.
    pub fn set_state(&self) -> SetState {
        set_state_from_entries(&self.canonical_entries())
    }
}

fn decoded<T>(value: Option<T>, what: &str) -> T {
    value.unwrap_or_else(|| panic!("a vault {what} record written by this node decodes"))
}

impl StateRead for ChainVaultView<'_> {
    fn set(&self, set_id: &SetId) -> Option<SetRecord> {
        self.raw(&kogany_vault::state::records::key_set(set_id))
            .map(|b| decoded(SetRecord::decode(&b), "set"))
    }
    fn member(&self, set_id: &SetId, key: &PubKeyBytes) -> Option<MemberRecord> {
        self.raw(&kogany_vault::state::records::key_member(set_id, key))
            .map(|b| decoded(MemberRecord::decode(&b), "member"))
    }
    fn members(&self, set_id: &SetId) -> MemberList {
        let mut members: BTreeMap<PubKeyBytes, MemberRecord> =
            self.db.vault_members(set_id).into_iter().collect();
        if let Some(overlay) = self.overlay {
            let (from, to) = member_key_range(set_id);
            for (k, v) in overlay.range(&from, &to) {
                let key = member_key_of(k);
                match v {
                    Some(v) => members.insert(key, decoded(MemberRecord::decode(v), "member")),
                    None => members.remove(&key),
                };
            }
        }
        members.into_iter().collect()
    }
    fn bond(&self, outpoint: &OutPoint) -> Option<BondRecord> {
        self.raw(&kogany_vault::state::records::key_bond(outpoint))
            .map(|b| decoded(BondRecord::decode(&b), "bond"))
    }
    fn template_out(&self, outpoint: &OutPoint) -> Option<TemplateOutRecord> {
        self.raw(&kogany_vault::state::records::key_template_out(outpoint))
            .map(|b| decoded(TemplateOutRecord::decode(&b), "template-output"))
    }
}

impl Chain {
    /// The chain's vault overlay over the finalized state.
    pub fn vault_overlay(&self) -> &ChainVaultOverlay {
        &self.vault_overlay
    }

    /// The set state at this chain's tip, over `db` (the finalized state the chain grows from).
    pub fn vault_view<'a>(&'a self, db: &'a ZakuraDb) -> ChainVaultView<'a> {
        ChainVaultView {
            overlay: Some(&self.vault_overlay),
            db,
        }
    }
}
