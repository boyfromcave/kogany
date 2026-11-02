// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

//! The Ycash mempool's return of a disconnected block's transactions (kogany finding F-S5-7).
//!
//! ycashd's `DisconnectTip` hands every transaction of the block it disconnects back to
//! `AcceptToMemoryPool` (`ycash6` at `65cb4ae0f`, `src/main.cpp:4723,4750-4760`: "resurrected
//! transactions", coinbases excepted, validation errors ignored), so a reorg or an
//! `invalidateblock` puts the undone transactions back in the mempool, where the next template
//! mines them again. Zakura's mempool, on a `TipAction::Reset`, re-verifies only the transactions
//! it already held (`retry_after_tip_reset`): the transactions of the blocks that left the best
//! chain are lost until a wallet rebroadcasts them.
//!
//! This module keeps the transactions of the recent best-chain blocks the mempool has seen (the
//! blocks of a `Grow`, and on a `Reset` the best chain's blocks read from the state), at most
//! [`KEPT_BLOCKS`] of them, which is the non-finalized depth: a deeper block can no longer be
//! disconnected. On a `Reset` a background task asks the state which of the kept blocks are no
//! longer in the best chain (`ReadRequest::Depth`), and hands their non-coinbase transactions,
//! in chain order, back to `poll_ready`, which queues them for verification at the new tip like
//! any retried transaction. A transaction the new chain also mined, or whose inputs it spent, is
//! refused there as on ycashd; a child queued before its parent waits as an orphan
//! (`state_retry`).

use std::{collections::VecDeque, sync::Arc};

use futures::FutureExt;
use tokio::{sync::Notify, task::JoinHandle};
use tower::{Service, ServiceExt};

use crate::BoxError;
use zakura_chain::{
    block::{self, Height},
    transaction::Transaction,
};
use zakura_state as zs;

/// How many recent best-chain blocks are kept: the non-finalized state's depth
/// (`MAX_BLOCK_REORG_HEIGHT` + 1). A block below it is finalized and cannot be disconnected.
pub(super) const KEPT_BLOCKS: usize = zs::MAX_BLOCK_REORG_HEIGHT as usize + 1;

/// One kept best-chain block.
#[derive(Clone, Debug)]
struct KeptBlock {
    height: Height,
    hash: block::Hash,
    transactions: Vec<Arc<Transaction>>,
}

/// What a reset's background task found.
#[derive(Debug, Default)]
pub(super) struct Found {
    /// The kept blocks that left the best chain.
    disconnected: Vec<block::Hash>,
    /// Their non-coinbase transactions, oldest block first, in block order.
    transactions: Vec<Arc<Transaction>>,
    /// The best chain's blocks above the highest kept block still in it, read from the state.
    filled: Vec<KeptBlock>,
}

/// The kept blocks and the running reset task, if any.
#[derive(Default)]
pub(super) struct ReorgResurrect {
    kept: VecDeque<KeptBlock>,
    pending: Option<JoinHandle<Found>>,
}

impl Drop for ReorgResurrect {
    fn drop(&mut self) {
        if let Some(task) = self.pending.take() {
            task.abort();
        }
    }
}

impl ReorgResurrect {
    /// Keeps the block of a `TipAction::Grow`.
    pub(super) fn grew(
        &mut self,
        height: Height,
        hash: block::Hash,
        transactions: &[Arc<Transaction>],
    ) {
        self.insert(KeptBlock {
            height,
            hash,
            transactions: transactions.to_vec(),
        });
    }

    fn insert(&mut self, block: KeptBlock) {
        if self.kept.iter().any(|kept| kept.hash == block.hash) {
            return;
        }
        // Keep the blocks in height order (a fill can arrive after a later `Grow`).
        let position = self
            .kept
            .iter()
            .rposition(|kept| kept.height <= block.height)
            .map_or(0, |index| index + 1);
        self.kept.insert(position, block);
        while self.kept.len() > KEPT_BLOCKS {
            self.kept.pop_front();
        }
    }

    /// Starts the reset task for the new best tip `tip` (replacing a running one). `finished` is
    /// notified when it is done, so the queue checker polls the mempool.
    pub(super) fn reset<ZS>(
        &mut self,
        tip: (Height, block::Hash),
        read_state: ZS,
        finished: Arc<Notify>,
    ) where
        ZS: Service<zs::ReadRequest, Response = zs::ReadResponse, Error = BoxError>
            + Send
            + Clone
            + 'static,
        ZS::Future: Send,
    {
        if let Some(task) = self.pending.take() {
            task.abort();
        }
        let kept: Vec<KeptBlock> = self.kept.iter().cloned().collect();
        self.pending = Some(tokio::spawn(async move {
            let found = find(tip, kept, read_state).await;
            finished.notify_one();
            found
        }));
    }

    /// The disconnected transactions of a finished reset task, to queue for verification; `None`
    /// while it runs or when none runs. Forgets the disconnected blocks and keeps the filled ones.
    pub(super) fn poll_disconnected(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> Option<Vec<Arc<Transaction>>> {
        let task = self.pending.as_mut()?;
        let std::task::Poll::Ready(result) = task.poll_unpin(cx) else {
            return None;
        };
        self.pending = None;
        let found = result.ok()?;
        self.kept
            .retain(|kept| !found.disconnected.contains(&kept.hash));
        for block in found.filled {
            self.insert(block);
        }
        Some(found.transactions)
    }
}

/// The reset task (see the module documentation).
async fn find<ZS>(tip: (Height, block::Hash), kept: Vec<KeptBlock>, read_state: ZS) -> Found
where
    ZS: Service<zs::ReadRequest, Response = zs::ReadResponse, Error = BoxError>
        + Send
        + Clone
        + 'static,
    ZS::Future: Send,
{
    let mut found = Found::default();
    let mut highest_connected: Option<Height> = None;
    for block in kept {
        let depth = read_state
            .clone()
            .oneshot(zs::ReadRequest::Depth(block.hash))
            .await;
        match depth {
            Ok(zs::ReadResponse::Depth(Some(_))) => {
                highest_connected = highest_connected.max(Some(block.height));
            }
            Ok(zs::ReadResponse::Depth(None)) => {
                found.disconnected.push(block.hash);
                found.transactions.extend(
                    block
                        .transactions
                        .iter()
                        .filter(|transaction| !transaction.is_coinbase())
                        .cloned(),
                );
            }
            // A state that cannot answer: leave the block kept, the next reset asks again.
            _ => {}
        }
    }

    // Keep the best chain's blocks the mempool did not see grow (a reset that skipped blocks),
    // so a later reorg finds their transactions too.
    let lowest = tip
        .0
         .0
        .saturating_sub(u32::try_from(KEPT_BLOCKS).unwrap_or(u32::MAX) - 1);
    let start = highest_connected.map_or(lowest, |height| (height.0 + 1).max(lowest));
    for height in start..=tip.0 .0 {
        let Ok(zs::ReadResponse::Block(Some(block))) = read_state
            .clone()
            .oneshot(zs::ReadRequest::Block(Height(height).into()))
            .await
        else {
            continue;
        };
        found.filled.push(KeptBlock {
            height: Height(height),
            hash: block.hash(),
            transactions: block.transactions.clone(),
        });
    }

    found
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use tower::service_fn;
    use zakura_chain::{block::Block, parameters::Network, serialization::ZcashDeserializeInto};

    use super::*;

    fn hash(byte: u8) -> block::Hash {
        block::Hash([byte; 32])
    }

    /// A reset hands back the non-coinbase transactions of the kept blocks the state no longer
    /// has in its best chain, oldest first, and forgets those blocks; the connected ones stay.
    #[tokio::test]
    async fn ycash_reset_returns_the_disconnected_blocks_transactions() {
        let _init_guard = zakura_test::init();
        let coinbase: Arc<Block> = zakura_test::vectors::BLOCK_MAINNET_1_BYTES
            .zcash_deserialize_into()
            .expect("the test block deserializes");
        let coinbase = coinbase.transactions[0].clone();
        let spends: Vec<Arc<Transaction>> = Network::Mainnet
            .unmined_transactions_in_blocks(..)
            .map(|tx| tx.transaction.transaction().clone())
            .filter(|tx| !tx.is_coinbase())
            .take(3)
            .collect();
        assert_eq!(spends.len(), 3, "the test vectors hold three transactions");

        let mut resurrect = ReorgResurrect::default();
        resurrect.grew(Height(10), hash(10), &[coinbase.clone(), spends[0].clone()]);
        resurrect.grew(Height(11), hash(11), &[coinbase.clone(), spends[1].clone()]);
        resurrect.grew(Height(12), hash(12), &[coinbase, spends[2].clone()]);

        // Blocks 11 and 12 left the best chain; the new tip is block 10.
        let connected: HashSet<block::Hash> = [hash(10)].into();
        let read_state = service_fn(move |request: zs::ReadRequest| {
            let connected = connected.clone();
            async move {
                Ok::<_, BoxError>(match request {
                    zs::ReadRequest::Depth(hash) => {
                        zs::ReadResponse::Depth(connected.contains(&hash).then_some(0))
                    }
                    zs::ReadRequest::Block(_) => zs::ReadResponse::Block(None),
                    other => panic!("unexpected request {other:?}"),
                })
            }
        });
        let finished = Arc::new(Notify::new());
        resurrect.reset((Height(10), hash(10)), read_state, finished.clone());
        finished.notified().await;

        let returned =
            std::future::poll_fn(|cx| std::task::Poll::Ready(resurrect.poll_disconnected(cx)))
                .await;
        let returned = match returned {
            Some(returned) => returned,
            None => {
                // The task notified just before it returned: poll until it has.
                let mut found = None;
                for _ in 0..100 {
                    tokio::task::yield_now().await;
                    found = std::future::poll_fn(|cx| {
                        std::task::Poll::Ready(resurrect.poll_disconnected(cx))
                    })
                    .await;
                    if found.is_some() {
                        break;
                    }
                }
                found.expect("the reset task finishes")
            }
        };
        let returned: Vec<_> = returned.iter().map(|tx| tx.hash()).collect();
        assert_eq!(returned, vec![spends[1].hash(), spends[2].hash()]);
        let kept: Vec<_> = resurrect.kept.iter().map(|block| block.hash).collect();
        assert_eq!(
            kept,
            vec![hash(10)],
            "the disconnected blocks are forgotten"
        );
    }

    /// At most [`KEPT_BLOCKS`] blocks are kept, in height order, each once.
    #[test]
    fn ycash_kept_blocks_are_bounded_ordered_and_unique() {
        let mut resurrect = ReorgResurrect::default();
        for height in (0..u32::try_from(KEPT_BLOCKS).expect("fits") + 10).rev() {
            let byte = u8::try_from(height % 251).expect("fits");
            let mut bytes = [byte; 32];
            bytes[..4].copy_from_slice(&height.to_le_bytes());
            resurrect.grew(Height(height), block::Hash(bytes), &[]);
            resurrect.grew(Height(height), block::Hash(bytes), &[]);
        }
        assert_eq!(resurrect.kept.len(), KEPT_BLOCKS);
        assert!(resurrect
            .kept
            .iter()
            .zip(resurrect.kept.iter().skip(1))
            .all(|(a, b)| a.height < b.height));
    }
}
