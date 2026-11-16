// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE-MIT or https://www.opensource.org/licenses/mit-license.php .

//! Ycash (beta3 items 2 and 11): fill the transparent value pools by address type and the chain
//! transaction count for the blocks an older database already holds.
//!
//! Both are node-side indexes ([`crate::transparent_pools`]); the fill reads blocks and writes
//! only the `ycash_transparent_pools` rows and the count appended to each `block_info` row.
//!
//! # When it runs
//!
//! Startup format changes complete before the database is exposed
//! (`ZakuraDb::run_startup_format_change`), so no block is committed while this runs and the
//! fill cannot race a block write. Block writes do not depend on that: a block whose parent has
//! no count or no pools row is written without one, never with a value computed from an unknown
//! parent as if it were zero.
//!
//! # The two fills
//!
//! 1. **The chain transaction count**, from the first height whose `block_info` row has none.
//!    The count of each block is the number of keys it has in `hash_by_tx_loc`, which pruning
//!    keeps, so no transaction is read.
//! 2. **The transparent pools**, from the highest row the index holds, or else from the
//!    compiled seed when the chain contains the seed block, or else from genesis. Each block is
//!    read with the outputs its inputs spend. A pruned database that no longer has them stops
//!    here: its entries say `monitored: false` until it is synced again.
//!
//! # Restart and re-run
//!
//! A run that stops part-way leaves a prefix of counted `block_info` rows and one contiguous
//! range of pools rows; the next run continues after both. A database that an older binary
//! extended in the meantime (the format version then goes back, and this upgrade runs again) is
//! handled by the first step: the older binary writes `block_info` rows without a count, so every
//! pools row at or above the first such height is deleted and filled again from the blocks.

use std::{collections::HashMap, sync::mpsc::TryRecvError, sync::Arc};

use itertools::Itertools;
use rayon::iter::{IntoParallelIterator, ParallelIterator as _};
use semver::Version;
use zakura_chain::{
    block::{Block, Height},
    transparent,
};

use crate::{
    service::finalized_state::{
        disk_format::{chain::ycash_block_info_row_with_count, RawBytes},
        zakura_db::transparent_pools::check_seed,
        DiskWriteBatch, ZakuraDb,
    },
    transparent_pools::{compiled_seed, TransparentPools, TransparentPoolsSeed},
    HashOrHeight,
};

use super::{CancelFormatChange, CancelReceiver, DiskFormatUpgrade, FormatChangeError};

/// The number of heights whose rows are written in one batch.
const BATCH_HEIGHTS: u32 = 1_000;

/// Progress is logged every this many heights.
const LOG_INTERVAL: u32 = 100_000;

/// Implements [`DiskFormatUpgrade`] for the transparent pools by type and the chain transaction
/// count.
pub struct Upgrade;

impl DiskFormatUpgrade for Upgrade {
    fn version(&self) -> Version {
        Version::new(30, 3, 0)
    }

    fn description(&self) -> &'static str {
        "add the transparent pools by type and the chain transaction count"
    }

    fn run(
        &self,
        initial_finalized_tip_height: Option<Height>,
        db: &ZakuraDb,
        cancel_receiver: &CancelReceiver,
    ) -> Result<(), FormatChangeError> {
        run_with_seed(
            initial_finalized_tip_height,
            db,
            compiled_seed(),
            cancel_receiver,
        )
    }
}

/// [`Upgrade::run`] with the seed to start an empty index from.
pub(crate) fn run_with_seed(
    initial_finalized_tip_height: Option<Height>,
    db: &ZakuraDb,
    seed: Option<TransparentPoolsSeed>,
    cancel_receiver: &CancelReceiver,
) -> Result<(), FormatChangeError> {
    // An empty database has nothing to fill: the genesis block write starts both indexes.
    let Some(tip) = initial_finalized_tip_height else {
        return Ok(());
    };

    // Rows at or above the first block an older binary wrote, and rows above the tip, are
    // not this chain's rows.
    let first_uncounted = db.first_height_without_chain_tx_count(tip);
    let stale_from = first_uncounted.or_else(|| tip.next().ok());
    if let Some(stale_from) = stale_from {
        let mut batch = DiskWriteBatch::new();
        batch.delete_transparent_pools_from(db, stale_from);
        write(db, batch)?;
    }

    if let Some(from) = first_uncounted {
        fill_chain_tx_counts(db, from, tip, cancel_receiver)?;
    }
    fill_transparent_pools(db, tip, seed, cancel_receiver)
}

/// Appends the chain transaction count to the `block_info` rows from `from` to `tip`.
///
/// Stops, leaving the remaining rows without a count, at a height whose transactions or
/// `block_info` row are not as expected; the reason is logged.
fn fill_chain_tx_counts(
    db: &ZakuraDb,
    from: Height,
    tip: Height,
    cancel_receiver: &CancelReceiver,
) -> Result<(), FormatChangeError> {
    let parent_count = match from.previous() {
        Ok(parent) => db.chain_tx_count_at(parent),
        Err(_) => Some(0),
    };
    let Some(mut count) = parent_count else {
        // Unreachable after `first_height_without_chain_tx_count`; never guess a count.
        warn!(?from, "no chain transaction count below this height");
        return Ok(());
    };

    info!(?from, ?tip, "adding the chain transaction count");
    let mut expected = from;
    let mut batch = DiskWriteBatch::new();
    let mut complete = false;
    for (height, transactions) in db.transaction_counts_by_height(from, tip) {
        // The row is rewritten from its raw bytes: nothing but the count changes.
        let row = count.checked_add(transactions).and_then(|new_count| {
            let row = db.raw_block_info_cf().zs_get(&height)?;
            Some((
                ycash_block_info_row_with_count(row.raw_bytes(), new_count)?,
                new_count,
            ))
        });
        let (Some((row, new_count)), true) = (row, height == expected) else {
            warn!(
                ?height,
                ?expected,
                "the chain transaction count stops here: this block's rows are not as expected"
            );
            break;
        };
        count = new_count;
        let _ = db
            .raw_block_info_cf()
            .with_batch_for_writing(&mut batch)
            .zs_insert(&height, &RawBytes::new_raw_bytes(row));

        if height.0 % BATCH_HEIGHTS == 0 {
            check_cancelled(cancel_receiver)?;
            write(db, std::mem::take(&mut batch))?;
        }
        if height.0 % LOG_INTERVAL == 0 {
            info!(?height, ?tip, "adding the chain transaction count");
        }
        if height == tip {
            complete = true;
            break;
        }
        expected = height.next().map_err(|_| {
            FormatChangeError::InvalidPostcondition("a height above the maximum".to_string())
        })?;
    }
    write(db, batch)?;
    if complete {
        info!(
            ?tip,
            transactions = count,
            "added the chain transaction count"
        );
    } else {
        warn!(
            ?expected,
            ?tip,
            "the chain transaction count is not known from this height"
        );
    }
    Ok(())
}

/// A block and the outputs its inputs spend, or `None` when the database no longer has them.
type LoadedBlock = Option<(
    Arc<Block>,
    HashMap<transparent::OutPoint, transparent::Output>,
)>;

/// Loads the block at `height` and the outputs its inputs spend from the transaction store.
fn load_block(db: &ZakuraDb, height: Height) -> LoadedBlock {
    let block = db.block(HashOrHeight::Height(height))?;
    let mut spent = HashMap::new();
    for outpoint in block
        .transactions
        .iter()
        .flat_map(|transaction| transaction.inputs())
        .filter_map(|input| input.outpoint())
    {
        let (transaction, _height, _time) = db.transaction(outpoint.hash)?;
        // Outpoint indexes are 32 bits wide, and `usize` is at least that wide here.
        let output = transaction.outputs().get(outpoint.index as usize)?;
        spent.insert(outpoint, output.clone());
    }
    Some((block, spent))
}

/// Writes the transparent pools rows up to `tip`, starting after the highest row the index
/// holds, or at the compiled seed, or at genesis.
///
/// Stops, leaving the remaining blocks unmonitored, at a block that cannot be read (a pruned
/// database) or whose totals leave their range; the reason is logged.
fn fill_transparent_pools(
    db: &ZakuraDb,
    tip: Height,
    seed: Option<TransparentPoolsSeed>,
    cancel_receiver: &CancelReceiver,
) -> Result<(), FormatChangeError> {
    let (mut parent, from) = match db.last_transparent_pools_row() {
        Some((last, Some(record))) => match last.next() {
            Ok(next) => (record, next),
            Err(_) => return Ok(()),
        },
        Some((_, None)) => {
            // A row this code cannot read: rebuild the index rather than extend it.
            let mut batch = DiskWriteBatch::new();
            batch.delete_transparent_pools_from(db, Height::MIN);
            write(db, batch)?;
            start_of_empty_index(db, tip, seed)?
        }
        None => start_of_empty_index(db, tip, seed)?,
    };
    if from > tip {
        info!(
            ?tip,
            "the transparent pools by type cover the finalized tip"
        );
        return Ok(());
    }

    info!(?from, ?tip, "adding the transparent pools by type");
    let chunk_size = rayon::current_num_threads().max(1);
    let mut batch = DiskWriteBatch::new();
    for heights in &(from.0..=tip.0).chunks(chunk_size) {
        check_cancelled(cancel_receiver)?;
        // Reading and parsing blocks is the slow part, so it is done in parallel; rayon keeps
        // the results in height order.
        let loaded: Vec<(Height, LoadedBlock)> = heights
            .collect_vec()
            .into_par_iter()
            .map(|height| (Height(height), load_block(db, Height(height))))
            .collect();

        for (height, loaded) in loaded {
            let Some((block, spent)) = loaded else {
                write(db, batch)?;
                warn!(
                    ?height,
                    "the block or an output it spends is no longer stored (a pruned database): \
                     the transparent pools by type are not monitored from this height; delete \
                     the state database and sync again to enable them"
                );
                return Ok(());
            };
            let record = parent
                .apply_block(&block, |outpoint| spent.get(outpoint))
                .map_err(|error| error.to_string())
                .and_then(|record| check_seed(seed, height, block.hash(), record));
            let record = match record {
                Ok(record) => record,
                Err(reason) => {
                    write(db, batch)?;
                    warn!(
                        ?height,
                        %reason,
                        "the transparent pools by type are not monitored from this height"
                    );
                    return Ok(());
                }
            };
            batch.insert_transparent_pools(db, height, &record);
            parent = record;

            if height.0 % BATCH_HEIGHTS == 0 {
                write(db, std::mem::take(&mut batch))?;
            }
            if height.0 % LOG_INTERVAL == 0 {
                info!(?height, ?tip, "adding the transparent pools by type");
            }
        }
    }
    write(db, batch)?;
    info!(?tip, "added the transparent pools by type");
    Ok(())
}

/// The record to start an empty index from and the first height to fill: the compiled seed when
/// the finalized chain contains the seed block (its row is written here), else genesis.
fn start_of_empty_index(
    db: &ZakuraDb,
    tip: Height,
    seed: Option<TransparentPoolsSeed>,
) -> Result<(TransparentPools, Height), FormatChangeError> {
    let seed = seed.filter(|seed| seed.height <= tip && db.hash(seed.height) == Some(seed.hash));
    let Some((seed, next)) = seed.and_then(|seed| Some((seed, seed.height.next().ok()?))) else {
        return Ok((TransparentPools::default(), Height::MIN));
    };
    info!(height = ?seed.height, "starting the transparent pools by type from the compiled seed");
    let mut batch = DiskWriteBatch::new();
    batch.insert_transparent_pools(db, seed.height, &seed.record);
    write(db, batch)?;
    Ok((seed.record, next))
}

fn write(db: &ZakuraDb, batch: DiskWriteBatch) -> Result<(), FormatChangeError> {
    db.write_batch(batch)
        .map_err(|error| FormatChangeError::MigrationStorage(error.to_string()))
}

fn check_cancelled(cancel_receiver: &CancelReceiver) -> Result<(), CancelFormatChange> {
    match cancel_receiver.try_recv() {
        Err(TryRecvError::Empty) => Ok(()),
        _ => Err(CancelFormatChange),
    }
}
