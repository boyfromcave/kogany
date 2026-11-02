//! The Ycash Yellowback (YED) index in a non-finalized [`Chain`] (kogany plan W5-e, M24-15,
//! M24-16).
//!
//! ycash6 disconnects a block's YED changes from its `U` undo record (`UndoDisconnect`). A
//! Zakura fork is an in-memory [`Chain`] above the finalized tip, reverted block by block through
//! [`UpdateWith`]. So each [`ContextuallyVerifiedBlock`](crate::ContextuallyVerifiedBlock) carries
//! its block's [`YedBlockEffect`](crate::service::yed::YedBlockEffect), whose
//! [`YedDelta`] holds every written key with its value before and after, and the chain keeps
//! one [`ChainYedOverlay`]: for every key some block of this chain wrote, the value after the
//! newest such block and how many of the chain's blocks wrote it — the same model as the vault
//! state's `ChainVaultOverlay` (`chain/vault.rs`):
//!
//! - push: the entry takes the delta's `after` value;
//! - pop the tip (a reorg): it goes back to the delta's `before` value, or leaves the overlay when
//!   no other block of the chain wrote it (the finalized value applies again);
//! - pop the root (finalization): the finalized database now holds the root's value, so an entry
//!   no remaining block wrote leaves the overlay.
//!
//! Memory is bounded by the non-finalized window (K-13: 1,000 blocks). Every Vault-epoch block
//! writes at least its `Snapshots`, `Tip` and `Totals` records, so the overlay holds about two
//! keys per block plus what its transactions wrote.

use std::{collections::BTreeMap, sync::Arc};

use kogany_yellowback::state::{Table, YedDelta, YedKey, YedRead, YedRecord};

use crate::{
    service::finalized_state::{yed::FinalizedYedState, ZakuraDb},
    ValidateContextError,
};

use super::{Chain, RevertPosition, UpdateWith};

/// One overlay entry: the value after the newest block of the chain that wrote the key (`None` =
/// erased), and how many of the chain's blocks wrote it.
#[derive(Clone, Debug, PartialEq, Eq)]
struct OverlayEntry {
    value: Option<YedRecord>,
    writers: u32,
}

/// The chain's YED writes over the finalized state.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ChainYedOverlay {
    entries: Arc<BTreeMap<YedKey, OverlayEntry>>,
}

impl ChainYedOverlay {
    /// `Some(value)` when the chain decides the key (`Some(None)` = erased by the chain), `None`
    /// when the finalized state does.
    pub fn get(&self, key: &YedKey) -> Option<Option<&YedRecord>> {
        self.entries.get(key).map(|e| e.value.as_ref())
    }

    /// The chain's entries of `table`, key → value (`None` = erased), ascending key order.
    pub fn table(&self, table: Table) -> impl Iterator<Item = (&YedKey, Option<&YedRecord>)> {
        let (lo, hi) = table.bounds();
        self.entries
            .range(lo..=hi)
            .map(|(k, e)| (k, e.value.as_ref()))
    }

    /// Every entry, key → value (`None` = erased).
    pub fn entries(&self) -> impl Iterator<Item = (&YedKey, Option<&YedRecord>)> {
        self.entries.iter().map(|(k, e)| (k, e.value.as_ref()))
    }

    /// The number of keys the chain's blocks wrote.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// No block of the chain wrote a YED record.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The overlay's approximate heap size in bytes: canonical keys and values plus a per-entry
    /// map overhead (K-13 measurement).
    pub fn approx_bytes(&self) -> usize {
        const PER_ENTRY: usize = 96;
        self.entries
            .iter()
            .map(|(k, e)| {
                k.encode().len() + e.value.as_ref().map_or(0, |v| v.encode().len()) + PER_ENTRY
            })
            .sum()
    }

    /// Pushes a block's delta (the newest block's values win).
    pub(crate) fn push(&mut self, delta: &YedDelta) {
        if delta.is_empty() {
            return;
        }
        let entries = Arc::make_mut(&mut self.entries);
        for (key, change) in &delta.changes {
            let entry = entries.entry(*key).or_insert(OverlayEntry {
                value: None,
                writers: 0,
            });
            entry.value = change.after.clone();
            entry.writers = entry.writers.saturating_add(1);
        }
    }

    /// Pops a block's delta from the tip (back to `before`) or the root (finalized).
    pub(crate) fn pop(&mut self, delta: &YedDelta, position: RevertPosition) {
        if delta.is_empty() {
            return;
        }
        let entries = Arc::make_mut(&mut self.entries);
        for (key, change) in &delta.changes {
            let entry = entries
                .get_mut(key)
                .expect("every key of a pushed block's delta is in the overlay until it is popped");
            entry.writers = entry
                .writers
                .checked_sub(1)
                .expect("a key is popped at most as often as it was pushed");
            if entry.writers == 0 {
                // No other block of the chain wrote the key: the finalized value applies (after
                // a root pop, the finalized state is committing the root's value).
                entries.remove(key);
            } else if position == RevertPosition::Tip {
                // The tip was the newest writer, so the previous writer's value is its `before`.
                entry.value = change.before.clone();
            }
        }
    }
}

impl UpdateWith<YedDelta> for Chain {
    fn update_chain_tip_with(&mut self, delta: &YedDelta) -> Result<(), ValidateContextError> {
        self.yed_overlay.push(delta);
        Ok(())
    }

    fn revert_chain_with(&mut self, delta: &YedDelta, position: RevertPosition) {
        self.yed_overlay.pop(delta, position);
    }
}

/// The YED state at a non-finalized chain's tip: the chain's overlay over the finalized state.
/// The base for the next block's evaluation.
#[derive(Clone, Copy)]
pub struct ChainYedView<'a> {
    /// The chain's writes, or `None` for the finalized tip itself.
    pub overlay: Option<&'a ChainYedOverlay>,
    /// The finalized state below the chain.
    pub db: &'a ZakuraDb,
}

impl YedRead for ChainYedView<'_> {
    fn get(&self, key: &YedKey) -> Option<YedRecord> {
        match self.overlay.and_then(|o| o.get(key)) {
            Some(value) => value.cloned(),
            None => FinalizedYedState(self.db).get(key),
        }
    }

    fn scan(&self, table: Table) -> Vec<(YedKey, YedRecord)> {
        let base = FinalizedYedState(self.db).scan(table);
        let Some(overlay) = self.overlay.filter(|o| !o.is_empty()) else {
            return base;
        };
        let mut merged: BTreeMap<YedKey, YedRecord> = base.into_iter().collect();
        for (k, v) in overlay.table(table) {
            match v {
                Some(v) => merged.insert(*k, v.clone()),
                None => merged.remove(k),
            };
        }
        merged.into_iter().collect()
    }
}

impl Chain {
    /// The chain's YED overlay over the finalized state.
    pub fn yed_overlay(&self) -> &ChainYedOverlay {
        &self.yed_overlay
    }

    /// The YED state at this chain's tip, over `db` (the finalized state the chain grows from).
    pub fn yed_view<'a>(&'a self, db: &'a ZakuraDb) -> ChainYedView<'a> {
        ChainYedView {
            overlay: Some(&self.yed_overlay),
            db,
        }
    }
}
