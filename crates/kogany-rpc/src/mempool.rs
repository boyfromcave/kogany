//! The node's mempool as the extension reads it (S5 parity, F-S5-5 and `getaddressmempool`).
//!
//! Copyright (c) 2026 The Ycash developers. Distributed under the MIT software license.
//!
//! ycashd's RPCs read `mempool` under `mempool.cs` beside the chain state: `yed_getvault`'s
//! `spendPending`/`spendTxid` (`MempoolSpenderOf`, ycash6 `src/yellowback/policy.cpp`, the
//! mempool's `mapNextTx`) and `getaddressmempool` (`src/rpc/misc.cpp`, the mempool's address
//! index). kogany's extension is given the node's mempool service once at start by `zakurad`
//! ([`set_mempool`], as the payout key and the network are); without one (tests, a node whose RPC
//! server starts before its mempool) every read here answers an empty mempool. The reads are
//! scans of the mempool's verified set (`mempool::Request::FullTransactions`): no index is added.

use std::sync::OnceLock;

use tower::{util::BoxCloneSyncService, Service, ServiceExt};
use zakura_chain::{
    transaction::{self, VerifiedUnminedTx},
    transparent,
};
use zakura_node_services::mempool::{Request, Response};
use zakura_state::BoxError;

/// The mempool service type the extension keeps.
pub type MempoolService = BoxCloneSyncService<Request, Response, BoxError>;

static MEMPOOL: OnceLock<MempoolService> = OnceLock::new();

/// Gives the extension the node's mempool service. The first call wins.
pub fn set_mempool<S>(mempool: S)
where
    S: Service<Request, Response = Response, Error = BoxError> + Clone + Send + Sync + 'static,
    S::Future: Send + 'static,
{
    let _ = MEMPOOL.set(BoxCloneSyncService::new(mempool));
}

/// Every verified transaction in the mempool (the expired-at-the-next-block ones aside, as the
/// template sees it); empty without a mempool or while the mempool is disabled (ycashd's mempool
/// is never disabled, and an empty one answers the same).
pub async fn transactions() -> Vec<VerifiedUnminedTx> {
    let Some(mempool) = MEMPOOL.get().cloned() else {
        return Vec::new();
    };
    match mempool.oneshot(Request::FullTransactions).await {
        Ok(Response::FullTransactions { transactions, .. }) => transactions,
        _ => Vec::new(),
    }
}

/// `MempoolSpenderOf(out)`: the mempool transaction that spends `outpoint`, if any.
pub async fn spender_of(outpoint: &transparent::OutPoint) -> Option<transaction::Hash> {
    spender_in(&transactions().await, outpoint)
}

/// The transaction of `transactions` that spends `outpoint`.
pub fn spender_in(
    transactions: &[VerifiedUnminedTx],
    outpoint: &transparent::OutPoint,
) -> Option<transaction::Hash> {
    transactions
        .iter()
        .find(|tx| {
            tx.transaction
                .transaction()
                .spent_outpoints()
                .any(|spent| &spent == outpoint)
        })
        .map(|tx| tx.transaction.id().mined_id())
}
