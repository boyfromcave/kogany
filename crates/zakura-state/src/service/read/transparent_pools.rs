// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE-MIT or https://www.opensource.org/licenses/mit-license.php .

//! Ycash (beta3 items 2 and 11): reading the transparent value pools by address type and the
//! chain transaction count of a block.
//!
//! A finalized block's rows are read from the database. A non-finalized block has no rows: its
//! figures are derived here, on each read, from the rows of the last finalized block below its
//! chain and the blocks of that chain up to it. Nothing is stored in the non-finalized state,
//! so the non-finalized commit path does not know this index exists, and a fork needs no
//! bookkeeping: each chain is read from its own blocks.

use zakura_chain::block::Height;

use crate::{
    service::{
        finalized_state::ZakuraDb,
        non_finalized_state::{Chain, NonFinalizedState},
    },
    transparent_pools::{BlockIndexInfo, TransparentPools},
    HashOrHeight,
};

/// Returns the index figures of the block with `hash_or_height`, if it exists in any of the
/// non-finalized `chains` or in the finalized `db`.
///
/// Heights resolve on the first chain in `chains` that has them, so use
/// [`block_index_info_by_hash_or_best_chain_height`] to look up heights in the best chain.
pub fn block_index_info<'a, C: AsRef<Chain> + 'a>(
    mut chains: impl Iterator<Item = &'a C>,
    db: &ZakuraDb,
    hash_or_height: HashOrHeight,
) -> Option<BlockIndexInfo> {
    chains
        .find_map(|chain| chain_block_index_info(chain.as_ref(), db, hash_or_height))
        .or_else(|| db.finalized_block_index_info(hash_or_height))
}

/// Returns the index figures of a block: a hash resolves on any non-finalized chain, a height
/// only on the best chain (as [`super::block_info_by_hash_or_best_chain_height`] does).
pub fn block_index_info_by_hash_or_best_chain_height(
    non_finalized_state: &NonFinalizedState,
    db: &ZakuraDb,
    hash_or_height: HashOrHeight,
) -> Option<BlockIndexInfo> {
    match hash_or_height {
        HashOrHeight::Hash(_) => {
            block_index_info(non_finalized_state.chain_iter(), db, hash_or_height)
        }
        HashOrHeight::Height(_) => block_index_info(
            non_finalized_state.best_chain().into_iter(),
            db,
            hash_or_height,
        ),
    }
}

/// Returns the index figures of a block of the non-finalized `chain`, or `None` if the block is
/// not in it.
///
/// The figures start from the rows of the finalized block below the chain's root (the empty
/// chain when the root is the genesis block) and add each block of the chain up to the
/// requested one. A figure the finalized rows do not hold, or that a block cannot extend, is
/// `None`: it is never derived from an unknown value as if it were zero.
fn chain_block_index_info(
    chain: &Chain,
    db: &ZakuraDb,
    hash_or_height: HashOrHeight,
) -> Option<BlockIndexInfo> {
    let height = hash_or_height.height_or_else(|hash| chain.height_by_hash(hash))?;
    if !chain.blocks.contains_key(&height) {
        return None;
    }

    let root = chain.non_finalized_root_height();
    let below_root = match root.previous() {
        Ok(parent) => db
            .finalized_block_index_info(parent.into())
            .unwrap_or_default(),
        Err(_) => BlockIndexInfo {
            chain_tx_count: Some(0),
            pools: Some(TransparentPools::default()),
            parent_pools: None,
        },
    };

    let mut chain_tx_count = below_root.chain_tx_count;
    let mut pools = below_root.pools;
    let mut parent_pools = None;
    for block in chain
        .blocks
        .range(Height::MIN..=height)
        .map(|(_, block)| block)
    {
        chain_tx_count = chain_tx_count
            .zip(u64::try_from(block.block.transactions.len()).ok())
            .and_then(|(count, transactions)| count.checked_add(transactions));
        parent_pools = pools;
        pools = pools.and_then(|pools| {
            pools
                .apply_block(&block.block, |outpoint| {
                    block
                        .spent_outputs
                        .get(outpoint)
                        .map(|utxo| &utxo.utxo.output)
                })
                .ok()
        });
    }

    Some(BlockIndexInfo {
        chain_tx_count,
        pools,
        parent_pools,
    })
}
