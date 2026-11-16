// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE-MIT or https://www.opensource.org/licenses/mit-license.php .

//! Ycash (beta3 item 2): the column family of the transparent value pools by address type, and
//! the finalized half of the chain transaction count.
//!
//! This is a node-side index ([`crate::transparent_pools`]), never a validity rule. The write
//! path here is total: it returns nothing, takes no validation state and uses no `?`. A block
//! whose record cannot be computed gets no record, the reason is logged once, and the entries of
//! that block and its descendants say `monitored: false`.
//!
//! # Rows
//!
//! `ycash_transparent_pools` holds one row per finalized height: the totals after that block
//! ([`TransparentPools::to_bytes`]). The rows form one contiguous range, or the column family
//! is empty. The range usually ends at the finalized tip, but not always: a pruned database
//! that upgraded from an older format has no rows (its blocks are gone), a fill that was stopped
//! part-way ends where it stopped until it resumes, and a block whose record could not be
//! computed ends the range for itself and its descendants. Heights above the range read as
//! `monitored: false`. Every block write either inserts its row or
//! deletes whatever is stored at its height, so a row left above the tip by a rollback can never
//! be read as the row of a later block.

use std::{
    collections::HashMap,
    sync::atomic::{AtomicBool, Ordering},
};

use zakura_chain::{block::Height, block_info::BlockInfo, transparent};

use crate::{
    request::FinalizedBlock,
    service::finalized_state::{
        disk_db::DiskWriteBatch,
        disk_format::{
            block::MAX_ON_DISK_HEIGHT, chain::ycash_chain_tx_count_from_row, RawBytes,
            TransactionLocation,
        },
        zakura_db::ZakuraDb,
        TypedColumnFamily,
    },
    transparent_pools::{compiled_seed, BlockIndexInfo, TransparentPools, TransparentPoolsSeed},
    HashOrHeight,
};

/// The name of the transparent pools column family.
pub const YCASH_TRANSPARENT_POOLS: &str = "ycash_transparent_pools";

/// The type for reading the transparent pools: the totals after the block at a height.
///
/// The value is raw so that a row this code cannot read is "no record", never a panic.
pub type TransparentPoolsCf<'cf> = TypedColumnFamily<'cf, Height, RawBytes>;

/// Set once a block was written without a record, so the reason is logged once per run.
static REPORTED_UNMONITORED: AtomicBool = AtomicBool::new(false);

impl ZakuraDb {
    /// Returns a typed handle to the transparent pools column family, or `None` when this
    /// database was opened without it.
    ///
    /// Every state database is opened with it (`STATE_COLUMN_FAMILIES_IN_CODE`). The index
    /// still treats a missing column family as "no index" rather than as an invariant: nothing
    /// on the block write path may panic because of this index.
    pub(crate) fn transparent_pools_cf(&self) -> Option<TransparentPoolsCf<'_>> {
        TransparentPoolsCf::new(&self.db, YCASH_TRANSPARENT_POOLS)
    }

    /// Returns the transparent pools after the finalized block at `height`, if the index holds
    /// a readable row for it.
    ///
    /// The caller checks that `height` is at or below the finalized tip.
    pub(crate) fn transparent_pools_at(&self, height: Height) -> Option<TransparentPools> {
        let row = self.transparent_pools_cf()?.zs_get(&height)?;
        TransparentPools::from_bytes(row.raw_bytes())
    }

    /// Returns the transparent pools after the parent of the block at `height`: all zero for
    /// the genesis block.
    fn parent_transparent_pools(&self, height: Height) -> Option<TransparentPools> {
        match height.previous() {
            Ok(parent) => self.transparent_pools_at(parent),
            Err(_) => Some(TransparentPools::default()),
        }
    }

    /// Returns the index rows of a finalized block, or `None` if the block is not in the
    /// finalized state.
    pub fn finalized_block_index_info(
        &self,
        hash_or_height: HashOrHeight,
    ) -> Option<BlockIndexInfo> {
        let height = hash_or_height.height_or_else(|hash| self.height(hash))?;
        // A row above the tip is not the row of any block.
        if height > self.finalized_tip_height()? {
            return None;
        }
        Some(BlockIndexInfo {
            chain_tx_count: self.chain_tx_count_at(height),
            pools: self.transparent_pools_at(height),
            parent_pools: self.parent_transparent_pools(height),
        })
    }

    /// Returns the chain transaction count stored with the `block_info` row at `height`, if the
    /// row holds one.
    ///
    /// The row is read raw: the block write path must not depend on decoding a parent's row.
    pub(crate) fn chain_tx_count_at(&self, height: Height) -> Option<u64> {
        let row = self.raw_block_info_cf().zs_get(&height)?;
        ycash_chain_tx_count_from_row(row.raw_bytes())
    }

    /// Returns `block_info` with the chain transaction count after `finalized`: the parent's
    /// count plus the block's transactions, or no count when the parent's is not known.
    ///
    /// A count is never computed from an unknown parent count as if it were 0.
    pub(crate) fn with_chain_tx_count(
        &self,
        finalized: &FinalizedBlock,
        block_info: BlockInfo,
    ) -> BlockInfo {
        let parent_count = match finalized.height.previous() {
            Ok(parent) => self.chain_tx_count_at(parent),
            Err(_) => Some(0),
        };
        let transactions = u64::try_from(finalized.block.transactions.len()).ok();
        let count = parent_count
            .zip(transactions)
            .and_then(|(parent, transactions)| parent.checked_add(transactions));
        block_info.with_chain_tx_count(count)
    }
}

// ---- the format upgrade's reads and writes --------------------------------------------------

impl ZakuraDb {
    /// Returns the lowest height at or below `tip` whose `block_info` row holds no chain
    /// transaction count (or is missing), or `None` when every row holds one.
    ///
    /// Rows are counted from genesis without a gap by the upgrade and by every block write of
    /// this build, so the rows below the returned height were all written by code that also
    /// keeps the transparent pools rows.
    pub(crate) fn first_height_without_chain_tx_count(&self, tip: Height) -> Option<Height> {
        let mut expected = Height::MIN;
        for (height, row) in self.raw_block_info_cf().zs_forward_range_iter(..=tip) {
            if height != expected || ycash_chain_tx_count_from_row(row.raw_bytes()).is_none() {
                return Some(expected);
            }
            match expected.next() {
                Ok(next) => expected = next,
                Err(_) => return None,
            }
        }
        (expected <= tip).then_some(expected)
    }

    /// Returns the number of transactions of each finalized block from `from` to `to`, in
    /// height order, read from the keys of the transaction location index (which pruning keeps).
    pub(crate) fn transaction_counts_by_height(
        &self,
        from: Height,
        to: Height,
    ) -> impl Iterator<Item = (Height, u64)> + '_ {
        use itertools::Itertools;

        let hash_by_tx_loc = self
            .db
            .cf_handle("hash_by_tx_loc")
            .expect("column family was created when database was created");
        let range =
            TransactionLocation::min_for_height(from)..=TransactionLocation::max_for_height(to);
        self.db
            .zs_forward_range_iter::<_, TransactionLocation, RawBytes, _>(&hash_by_tx_loc, range)
            .map(|(location, _hash)| location.height)
            .dedup_with_count()
            // A block holds far fewer than 2^64 transactions.
            .map(|(count, height)| (height, count as u64))
    }

    /// Returns the highest row of the transparent pools column family.
    pub(crate) fn last_transparent_pools_row(&self) -> Option<(Height, Option<TransparentPools>)> {
        let (height, row) = self.transparent_pools_cf()?.zs_last_key_value()?;
        Some((height, TransparentPools::from_bytes(row.raw_bytes())))
    }
}

impl DiskWriteBatch {
    /// Deletes the transparent pools rows at and above `from`.
    pub(crate) fn delete_transparent_pools_from(&mut self, zakura_db: &ZakuraDb, from: Height) {
        let Some(cf) = zakura_db.transparent_pools_cf() else {
            return;
        };
        let _ = cf
            .with_batch_for_writing(self)
            .zs_delete_range(&from, &MAX_ON_DISK_HEIGHT)
            .zs_delete(&MAX_ON_DISK_HEIGHT);
    }

    /// Inserts the transparent pools row of the block at `height`.
    pub(crate) fn insert_transparent_pools(
        &mut self,
        zakura_db: &ZakuraDb,
        height: Height,
        record: &TransparentPools,
    ) {
        let Some(cf) = zakura_db.transparent_pools_cf() else {
            return;
        };
        let _ = cf
            .with_batch_for_writing(self)
            .zs_insert(&height, &RawBytes::new_raw_bytes(record.to_bytes()));
    }
}

impl DiskWriteBatch {
    /// Adds the transparent pools row of `finalized` to this batch, or deletes the row at its
    /// height when the record cannot be computed. Total: it never fails and never panics on a
    /// block or a stored row, whatever they hold.
    ///
    /// `spent_utxos_by_outpoint` is the write path's map of every coin the block spends,
    /// including outputs created earlier in the block.
    pub fn prepare_transparent_pools_batch(
        &mut self,
        zakura_db: &ZakuraDb,
        finalized: &FinalizedBlock,
        spent_utxos_by_outpoint: &HashMap<transparent::OutPoint, transparent::Utxo>,
    ) {
        let Some(cf) = zakura_db.transparent_pools_cf() else {
            return;
        };
        let height = finalized.height;
        let record = match zakura_db.parent_transparent_pools(height) {
            None => Err("the index does not cover its parent".to_string()),
            Some(parent) => parent
                .apply_block(&finalized.block, |outpoint| {
                    spent_utxos_by_outpoint
                        .get(outpoint)
                        .map(|utxo| &utxo.output)
                })
                .map_err(|error| error.to_string()),
        };
        let record =
            record.and_then(|record| check_seed(compiled_seed(), height, finalized.hash, record));

        let cf = cf.with_batch_for_writing(self);
        let _ = match record {
            Ok(record) => cf.zs_insert(&height, &RawBytes::new_raw_bytes(record.to_bytes())),
            Err(reason) => {
                if !REPORTED_UNMONITORED.swap(true, Ordering::Relaxed) {
                    tracing::warn!(
                        ?height,
                        hash = ?finalized.hash,
                        %reason,
                        "the transparent pools by type are not monitored from this block: \
                         delete the state database and sync again to enable them"
                    );
                }
                cf.zs_delete(&height)
            }
        };
    }
}

/// Checks a record computed at the compiled seed's block against the seed.
///
/// A sync from genesis reaches the seed block with totals it computed itself; they must be the
/// seed's. A mismatch leaves the blocks from the seed block on unmonitored (ycash6
/// `StepResult::SEED_MISMATCH` in `BlockConnected`).
pub(crate) fn check_seed(
    seed: Option<TransparentPoolsSeed>,
    height: Height,
    hash: zakura_chain::block::Hash,
    record: TransparentPools,
) -> Result<TransparentPools, String> {
    match seed {
        Some(seed) if seed.height == height && seed.hash == hash => {
            if record != seed.record {
                return Err(format!(
                    "the totals computed at the seed block ({record:?}) differ from the compiled \
                     seed (transparent {})",
                    seed.record.transparent
                ));
            }
            tracing::info!(
                ?height,
                "the compiled transparent pools seed matches the totals computed from genesis"
            );
            Ok(record)
        }
        _ => Ok(record),
    }
}

#[cfg(test)]
mod tests;
