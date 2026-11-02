// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

//! The Ycash mempool re-check after the chain tip grows (kogany plan W6-c `tip-recheck`).
//!
//! ycashd's `ConnectTip` re-checks its mempool against the new tip before the next template
//! (`ycash6` at `65cb4ae0f`, `src/main.cpp:4846,4866`):
//!
//! - `RemoveInvalidVaultSpends` (`src/yellowback/index.cpp:720`): the YED module's
//!   `MempoolCheck` of every mempool transaction over the new tip's YED state; a refusal is
//!   evicted with its descendants;
//! - `vault::RecheckMempool(pool, tip + 1)` (`src/vault/node.cpp:258`): for every transaction that
//!   touches the primitive (`IsVaultRelevant`), `vault::CheckTx` at the next height over the new
//!   set state and the scripts of its template inputs against it (`RecheckTemplateScripts`);
//!   a failure is evicted with its descendants.
//!
//! Zakura re-checks nothing on a `Grow` (`mempool.rs`, the `TipAction::Grow` arm), and a `Reset`
//! (a reorg, an activation) already clears the mempool and re-verifies every transaction at the
//! new tip (`retry_after_tip_reset`), which runs the same rules, BIP68 at the new height
//! included. So this module adds the `Grow` half: a background task that re-runs the
//! transaction verifier (which carries the vault and YED mempool checks since W6-c) on each
//! vault-relevant stored transaction, and the YED module's check on every stored transaction,
//! then hands the failures back to `poll_ready`, which evicts them if the tip has not moved.
//!
//! Only the rules a tip move can change evict here (see [`evicts`]); any other verifier failure
//! leaves the transaction where it is, as ycashd's re-check does.

use std::{collections::HashSet, sync::Arc};

use futures::{future::join_all, FutureExt};
use tokio::{sync::Notify, task::JoinHandle};
use tower::{timeout::Timeout, Service, ServiceExt};

use crate::BoxError;
use zakura_chain::{
    block::{self, Height},
    parameters::Network,
    transaction::{self, VerifiedUnminedTx},
};
use zakura_consensus::{
    error::TransactionError,
    transaction::{self as tx, vault_mempool},
};
use zakura_state as zs;

use super::{ReadState, TxVerifier, TRANSACTION_VERIFY_TIMEOUT};

/// One stored transaction the re-check refuses at the new tip.
#[derive(Clone, Debug)]
pub(super) struct Eviction {
    /// Its mined id (the storage key).
    pub(super) mined_id: transaction::Hash,
    /// The verifier's refusal.
    pub(super) error: TransactionError,
}

/// The outcome of one re-check: the tip it was run for and what to evict.
#[derive(Debug, Default)]
pub(super) struct Outcome {
    tip_hash: Option<block::Hash>,
    evictions: Vec<Eviction>,
}

/// Does a re-check failure evict? The rules a tip move changes (the set state, the YED state,
/// BIP68 lock heights after a reorg), as ycashd's re-check evicts; not a lookup failure, a
/// timeout, or a tip that moved during the check.
pub(super) fn evicts(error: &TransactionError) -> bool {
    use zs::ValidateContextError as Ctx;
    match error {
        TransactionError::VaultRejected { .. }
        | TransactionError::VaultTemplateSetState { .. }
        | TransactionError::NonMandatoryScriptFlag { .. }
        | TransactionError::YellowbackRejected { .. }
        | TransactionError::Script(_) => true,
        TransactionError::ValidateContextError(error) => matches!(
            **error,
            Ctx::VaultTimeLock { .. }
                | Ctx::UnsatisfiedSequenceLock { .. }
                | Ctx::VaultRejected { .. }
        ),
        _ => false,
    }
}

/// The misbehaviour score the relaying peer gets for `error` beyond Zakura's ban/cooldown
/// actions: ycashd's 10 for a byte-level act failure (`IsByteLevelActFailure`), else none.
pub(super) fn extra_misbehavior_score(error: &TransactionError) -> Option<u32> {
    matches!(
        error,
        TransactionError::VaultRejected {
            byte_level: true,
            ..
        }
    )
    .then(|| error.mempool_misbehavior_score())
}

/// Is `tx` expired for a block at `next_height` (ycashd `IsExpiredTx`: `nExpiryHeight != 0 &&
/// height > nExpiryHeight`)? Such a transaction stays in ycashd's mempool until the tip passes
/// its expiry height, but no template may include it.
pub(super) fn is_expired_at(tx: &VerifiedUnminedTx, next_height: Height) -> bool {
    tx.transaction
        .transaction()
        .expiry_height()
        .is_some_and(|expiry| next_height > expiry)
}

/// The running re-check, if any.
#[derive(Default)]
pub(super) struct TipRecheck {
    pending: Option<JoinHandle<Outcome>>,
}

impl Drop for TipRecheck {
    fn drop(&mut self) {
        self.clear();
    }
}

impl TipRecheck {
    /// Drops the running re-check (a tip reset re-verifies everything anyway).
    pub(super) fn clear(&mut self) {
        if let Some(task) = self.pending.take() {
            task.abort();
        }
    }

    /// Starts a re-check of `candidates` for the block after `tip` (replacing a running one),
    /// where the Vault upgrade is active at that block. `finished` is notified when it is done,
    /// so the queue checker polls the mempool.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn schedule(
        &mut self,
        network: Network,
        tip: (Height, block::Hash),
        candidates: Vec<VerifiedUnminedTx>,
        verifier: TxVerifier,
        read_state: ReadState,
        finished: Arc<Notify>,
    ) {
        self.clear();
        let Ok(next_height) = tip.0.next() else {
            return;
        };
        if candidates.is_empty() || !network.is_vault_active(next_height) {
            return;
        }
        self.pending = Some(tokio::spawn(async move {
            let verifier = Timeout::new(verifier, TRANSACTION_VERIFY_TIMEOUT);
            let outcome = recheck(tip, next_height, candidates, verifier, read_state).await;
            finished.notify_one();
            outcome
        }));
    }

    /// The evictions of a finished re-check run for the tip `tip_hash`; `None` while it runs,
    /// when none runs, or when it was run for another tip (its result is dropped).
    pub(super) fn poll_evictions(
        &mut self,
        cx: &mut std::task::Context<'_>,
        tip_hash: block::Hash,
    ) -> Option<Vec<Eviction>> {
        let task = self.pending.as_mut()?;
        let std::task::Poll::Ready(result) = task.poll_unpin(cx) else {
            return None;
        };
        self.pending = None;
        let outcome = result.ok()?;
        (outcome.tip_hash == Some(tip_hash)).then_some(outcome.evictions)
    }
}

/// The re-check itself (see the module documentation).
async fn recheck<ZV, ZS>(
    tip: (Height, block::Hash),
    next_height: Height,
    candidates: Vec<VerifiedUnminedTx>,
    verifier: ZV,
    read_state: ZS,
) -> Outcome
where
    ZV: Service<tx::Request, Response = tx::Response, Error = BoxError> + Send + Clone + 'static,
    ZV::Future: Send,
    ZS: Service<zs::ReadRequest, Response = zs::ReadResponse, Error = BoxError>
        + Send
        + Clone
        + 'static,
    ZS::Future: Send,
{
    let stale = Outcome::default();

    // The set state at the new tip, for the relevance filter (`IsVaultRelevant` reads bonds).
    let Ok(zs::ReadResponse::VaultSnapshot(Some(snapshot))) = read_state
        .clone()
        .oneshot(zs::ReadRequest::BestChainVaultSnapshot)
        .await
    else {
        return stale;
    };
    if snapshot.tip != Some(tip) {
        return stale;
    }
    let state: zakura_script::VaultStateSnapshot = snapshot.state.clone();

    // 1. `RecheckMempool`: the vault-relevant transactions through the whole verifier, at the
    //    next height (CheckTx, the template input and every script over the new set state).
    let requests: Vec<(transaction::Hash, tx::Request)> = candidates
        .iter()
        .filter(|candidate| {
            vault_mempool::is_vault_relevant(
                candidate.transaction.transaction(),
                &candidate.spent_outputs,
                &state,
            )
        })
        .map(|candidate| {
            (
                candidate.transaction.id().mined_id(),
                tx::Request::Mempool {
                    transaction: candidate.transaction.clone(),
                    height: next_height,
                },
            )
        })
        .collect();
    let checks: Vec<_> = requests
        .into_iter()
        .map(|(mined_id, request)| {
            let verifier = verifier.clone();
            let verify = verifier.oneshot(request);
            async move {
                let error = match verify.await {
                    Ok(_) => return None,
                    Err(error) => TransactionError::from(error),
                };
                evicts(&error).then_some(Eviction { mined_id, error })
            }
            .boxed()
        })
        .collect();
    let mut evictions: Vec<Eviction> = join_all(checks).await.into_iter().flatten().collect();

    // 2. `RemoveInvalidVaultSpends`: the YED module's check of every other transaction.
    let evicted: HashSet<_> = evictions.iter().map(|e| e.mined_id).collect();
    let (rest_ids, rest): (Vec<_>, Vec<_>) = candidates
        .iter()
        .map(|candidate| (candidate.transaction.id().mined_id(), candidate))
        .filter(|(mined_id, _)| !evicted.contains(mined_id))
        .map(|(mined_id, candidate)| {
            let transaction = candidate.transaction.transaction();
            (
                mined_id,
                (
                    zs::vault::vault_tx(transaction, &mined_id),
                    transaction.expiry_height().map_or(0, |h| h.0),
                ),
            )
        })
        .unzip();
    let response = read_state
        .oneshot(zs::ReadRequest::BestChainYedMempoolCheck(rest))
        .await;
    match response {
        Ok(zs::ReadResponse::YedMempoolCheck {
            tip: yed_tip,
            reasons,
        }) if yed_tip == Some(tip) => {
            evictions.extend(
                rest_ids
                    .into_iter()
                    .zip(reasons)
                    .filter_map(|(mined_id, reason)| {
                        Some(Eviction {
                            mined_id,
                            error: TransactionError::YellowbackRejected { reason: reason? },
                        })
                    }),
            );
        }
        _ => return stale,
    }

    Outcome {
        tip_hash: Some(tip.1),
        evictions,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use zakura_chain::{
        amount::Amount,
        transaction::{LockTime, Transaction, UnminedTx},
        transparent,
    };
    use zakura_test::mock_service::MockService;

    const TIP: Height = Height(200);

    fn tip_hash() -> block::Hash {
        block::Hash([7; 32])
    }

    /// A v4 transaction spending `prevout` into one output with `lock_script`, expiring at
    /// `expiry` (0 = none).
    fn verified_tx(prevout: u8, lock_script: Vec<u8>, expiry: u32) -> VerifiedUnminedTx {
        verified_spend(transaction::Hash([prevout; 32]), lock_script, expiry)
    }

    /// [`verified_tx`] spending output 0 of `parent`.
    fn verified_spend(
        parent: transaction::Hash,
        lock_script: Vec<u8>,
        expiry: u32,
    ) -> VerifiedUnminedTx {
        let transaction = Transaction::V4 {
            inputs: vec![transparent::Input::PrevOut {
                outpoint: transparent::OutPoint {
                    hash: parent,
                    index: 0,
                },
                unlock_script: transparent::Script::new(&[0x51]),
                sequence: u32::MAX,
            }],
            outputs: vec![transparent::Output {
                value: Amount::try_from(1_000).expect("a valid amount"),
                lock_script: transparent::Script::new(&lock_script),
            }],
            lock_time: LockTime::unlocked(),
            expiry_height: Height(expiry),
            joinsplit_data: None,
            sapling_shielded_data: None,
        };
        let spent = transparent::Output {
            value: Amount::try_from(200_000).expect("a valid amount"),
            lock_script: transparent::Script::new(&[0x75, 0x51]),
        };
        VerifiedUnminedTx::new(
            UnminedTx::from(transaction),
            Amount::try_from(199_000).expect("a valid amount"),
            0,
            0,
            Arc::new(vec![spent]),
        )
        .expect("the test transaction pays a high fee")
    }

    /// An act-shaped output script (`OP_RETURN OP_PUSHDATA1 <n> "YV" ...`): vault-relevant.
    fn act_script() -> Vec<u8> {
        let mut spk = vec![0x6a, 0x4c, 20, b'Y', b'V'];
        spk.resize(23, 0);
        spk
    }

    fn snapshot_at(tip: (Height, block::Hash)) -> zs::ReadResponse {
        zs::ReadResponse::VaultSnapshot(Some(zs::vault::VaultSnapshot {
            tip: Some(tip),
            state: Arc::new(Default::default()),
        }))
    }

    #[tokio::test]
    async fn the_recheck_evicts_vault_failures_and_yed_refusals() {
        let _init_guard = zakura_test::init();
        let mut verifier =
            MockService::build().for_unit_tests::<tx::Request, tx::Response, BoxError>();
        let mut read_state =
            MockService::build().for_unit_tests::<zs::ReadRequest, zs::ReadResponse, BoxError>();
        let act = verified_tx(1, act_script(), 0);
        let plain = verified_tx(2, vec![0x51], 0);
        let kept = verified_tx(3, vec![0x52], 0);
        let tip = (TIP, tip_hash());

        let run = tokio::spawn(recheck(
            tip,
            Height(TIP.0 + 1),
            vec![act.clone(), plain.clone(), kept.clone()],
            verifier.clone(),
            read_state.clone(),
        ));

        read_state
            .expect_request(zs::ReadRequest::BestChainVaultSnapshot)
            .await
            .respond(snapshot_at(tip));
        // Only the vault-relevant transaction goes back through the verifier, at tip + 1.
        let act_id = act.transaction.id();
        verifier
            .expect_request_that(|request| {
                request.tx_id() == act_id && request.height() == Height(TIP.0 + 1)
            })
            .await
            .respond(Err::<tx::Response, BoxError>(
                TransactionError::VaultRejected {
                    reason: "bad-txns-vault-release".into(),
                    height: Height(201),
                    byte_level: false,
                }
                .into(),
            ));
        // The YED module's sweep covers the rest.
        read_state
            .expect_request_that(|request| {
                matches!(request, zs::ReadRequest::BestChainYedMempoolCheck(txs) if txs.len() == 2)
            })
            .await
            .respond(zs::ReadResponse::YedMempoolCheck {
                tip: Some(tip),
                reasons: vec![Some("mempool-expiry".into()), None],
            });
        verifier.expect_no_requests().await;

        let outcome = run.await.expect("the re-check does not panic");
        assert_eq!(outcome.tip_hash, Some(tip_hash()));
        let evicted: Vec<_> = outcome
            .evictions
            .iter()
            .map(|e| (e.mined_id, e.error.clone()))
            .collect();
        assert_eq!(
            evicted,
            vec![
                (
                    act_id.mined_id(),
                    TransactionError::VaultRejected {
                        reason: "bad-txns-vault-release".into(),
                        height: Height(201),
                        byte_level: false
                    }
                ),
                (
                    plain.transaction.id().mined_id(),
                    TransactionError::YellowbackRejected {
                        reason: "mempool-expiry".into()
                    }
                ),
            ]
        );
    }

    #[tokio::test]
    async fn a_retryable_failure_keeps_the_transaction() {
        let _init_guard = zakura_test::init();
        let mut verifier =
            MockService::build().for_unit_tests::<tx::Request, tx::Response, BoxError>();
        let mut read_state =
            MockService::build().for_unit_tests::<zs::ReadRequest, zs::ReadResponse, BoxError>();
        let act = verified_tx(1, act_script(), 0);
        let tip = (TIP, tip_hash());
        let run = tokio::spawn(recheck(
            tip,
            Height(TIP.0 + 1),
            vec![act],
            verifier.clone(),
            read_state.clone(),
        ));
        read_state
            .expect_request(zs::ReadRequest::BestChainVaultSnapshot)
            .await
            .respond(snapshot_at(tip));
        verifier
            .expect_request_that(|_| true)
            .await
            .respond(Err::<tx::Response, BoxError>(
                TransactionError::Other("the chain tip moved, retry".into()).into(),
            ));
        read_state
            .expect_request_that(|_| true)
            .await
            .respond(zs::ReadResponse::YedMempoolCheck {
                tip: Some(tip),
                reasons: vec![None],
            });
        let outcome = run.await.expect("the re-check does not panic");
        assert_eq!(outcome.tip_hash, Some(tip_hash()));
        assert!(outcome.evictions.is_empty());
    }

    #[tokio::test]
    async fn a_moved_tip_drops_the_recheck() {
        let _init_guard = zakura_test::init();
        let mut verifier =
            MockService::build().for_unit_tests::<tx::Request, tx::Response, BoxError>();
        let mut read_state =
            MockService::build().for_unit_tests::<zs::ReadRequest, zs::ReadResponse, BoxError>();
        let run = tokio::spawn(recheck(
            (TIP, tip_hash()),
            Height(TIP.0 + 1),
            vec![verified_tx(1, act_script(), 0)],
            verifier.clone(),
            read_state.clone(),
        ));
        read_state
            .expect_request(zs::ReadRequest::BestChainVaultSnapshot)
            .await
            .respond(snapshot_at((Height(TIP.0 + 1), block::Hash([8; 32]))));
        verifier.expect_no_requests().await;
        let outcome = run.await.expect("the re-check does not panic");
        assert_eq!(outcome.tip_hash, None);
        assert!(outcome.evictions.is_empty());
    }

    fn regtest_storage() -> super::super::Storage {
        super::super::Storage::new_for_network(
            &super::super::Config::default(),
            &Network::new_regtest(Default::default()),
        )
    }

    #[test]
    fn eviction_takes_the_descendants_and_rejects_until_the_next_tip() {
        let _init_guard = zakura_test::init();
        let mut storage = regtest_storage();
        let parent = verified_tx(1, vec![0x75, 0x51], 0);
        let parent_id = parent.transaction.id();
        let child = verified_spend(parent_id.mined_id(), vec![0x75, 0x51], 0);
        let child_id = child.transaction.id();
        let other = verified_tx(9, vec![0x75, 0x51], 0);
        let tip = Some(Height(50));
        storage
            .insert_with_evicted_ids(parent, Vec::new(), tip)
            .0
            .expect("the parent is stored");
        storage
            .insert_with_evicted_ids(
                child,
                vec![transparent::OutPoint {
                    hash: parent_id.mined_id(),
                    index: 0,
                }],
                tip,
            )
            .0
            .expect("the child is stored");
        storage
            .insert_with_evicted_ids(other, Vec::new(), tip)
            .0
            .expect("the other transaction is stored");

        let error = TransactionError::VaultTemplateSetState {
            input_index: 0,
            script_error: "OP_CHECKSETSIG or OP_CHECKSETDORMANT failed".into(),
        };
        let removed = storage.evict_after_tip_recheck(vec![Eviction {
            mined_id: parent_id.mined_id(),
            error,
        }]);
        assert_eq!(removed, [parent_id, child_id].into_iter().collect());
        assert_eq!(storage.transaction_count(), 1);
        assert!(storage.contains_rejected(&parent_id));
        storage.clear_tip_rejections();
        assert!(!storage.contains_rejected(&parent_id));
    }

    #[test]
    fn a_transaction_expiring_at_the_tip_stays_one_more_block() {
        let _init_guard = zakura_test::init();
        let mut storage = regtest_storage();
        let tx = verified_tx(1, vec![0x75, 0x51], 100);
        let id = tx.transaction.id();
        storage
            .insert_with_evicted_ids(tx, Vec::new(), Some(Height(90)))
            .0
            .expect("the transaction is stored");
        // ycashd `removeExpired(100)` keeps it (100 > 100 is false); Zakura's rule dropped it.
        assert!(storage.remove_expired_transactions(Height(100)).is_empty());
        assert_eq!(storage.transaction_count(), 1);
        assert_eq!(
            storage.remove_expired_transactions(Height(101)),
            [id].into_iter().collect()
        );
    }

    #[test]
    fn expiry_at_the_next_height_is_ycashd_s() {
        // ycashd `IsExpiredTx(tx, h)`: expired when h > nExpiryHeight; 0 never expires.
        let tx = verified_tx(1, vec![0x51], 100);
        assert!(!is_expired_at(&tx, Height(100)));
        assert!(is_expired_at(&tx, Height(101)));
        assert!(!is_expired_at(
            &verified_tx(1, vec![0x51], 0),
            Height(5_000_000)
        ));
    }

    #[test]
    fn only_tip_dependent_failures_evict() {
        for error in [
            TransactionError::VaultRejected {
                reason: "bad-txns-vault-release".into(),
                height: Height(201),
                byte_level: false,
            },
            TransactionError::VaultTemplateSetState {
                input_index: 0,
                script_error: "OP_CHECKSETSIG or OP_CHECKSETDORMANT failed".into(),
            },
            TransactionError::YellowbackRejected {
                reason: "mempool-expiry".into(),
            },
            TransactionError::Script(zakura_script::Error::ScriptInvalid),
        ] {
            assert!(evicts(&error), "{error:?}");
        }
        for error in [
            TransactionError::TransparentInputNotFound,
            TransactionError::Other("the chain tip moved, retry".into()),
            TransactionError::InternalDowncastError("timeout".into()),
            TransactionError::BadBalance,
        ] {
            assert!(!evicts(&error), "{error:?}");
        }
    }

    #[test]
    fn byte_level_act_failures_score_ten() {
        let byte_level = TransactionError::VaultRejected {
            reason: "bad-vault-act-malformed".into(),
            height: Height(201),
            byte_level: true,
        };
        assert_eq!(extra_misbehavior_score(&byte_level), Some(10));
        let state = TransactionError::VaultRejected {
            reason: "bad-vault-act-noset".into(),
            height: Height(201),
            byte_level: false,
        };
        assert_eq!(extra_misbehavior_score(&state), None);
        assert_eq!(
            extra_misbehavior_score(&TransactionError::YellowbackRejected { reason: "x".into() }),
            None
        );
    }
}
