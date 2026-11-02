//! The Ycash `getblocktemplate` hooks over the node's Yellowback state (plan W8-b; zakura-rpc's
//! [`YcashMining`]), compiled under the `ycash` feature.
//!
//! Copyright (c) 2026 The Ycash developers. Distributed under the MIT software license.
//!
//! The template reads the same [`YedReadState`] the `yed_*` RPCs serve, so the quote
//! `yed_setquote` stores is the quote the next template's coinbase tag carries, as ycashd's
//! `getblocktemplate` and `yed_setquote` share `g_yellowback` (`src/rpc/mining.cpp:690`,
//! `src/yellowback/index.cpp:751-787`).

use std::sync::Arc;

use async_trait::async_trait;
use kogany_vault::state::SetState;
use kogany_yellowback::{
    params::Params,
    state::{process_tx, Table, Writes, YedKey, YedRead, YedRecord},
};
use tower::{Service, ServiceExt};
use zakura_chain::{block, transaction::VerifiedUnminedTx};
use zakura_rpc::ycash_mining::{VaultModules, YcashMining, YedTemplateFilter, YellowbackMiner};
use zakura_state::{BoxError, ReadRequest, ReadResponse};

use crate::yed::YedReadState;

/// The template hooks of a node whose Yellowback state is `yed` and whose read state service is
/// `read_state`.
///
/// The vault half of the template filter reads the set state after the template's parent
/// (`ReadRequest::VaultSnapshot`, plan W4-d); the YED half needs the registered index, which
/// plan W5-f serves ([`YcashMining::yed_template_filter`]).
#[derive(Clone)]
pub struct YedMining<R> {
    yed: Arc<dyn YedReadState>,
    read_state: R,
}

impl<R> YedMining<R> {
    /// The hooks over `yed` and `read_state`.
    pub fn new(yed: Arc<dyn YedReadState>, read_state: R) -> Self {
        Self { yed, read_state }
    }
}

#[async_trait]
impl<R> YcashMining for YedMining<R>
where
    R: Service<ReadRequest, Response = ReadResponse, Error = BoxError>
        + Clone
        + Send
        + Sync
        + 'static,
    R::Future: Send,
{
    /// ycashd's `g_yellowback` checks in `getblocktemplate`: no state is "not live", an
    /// unhealthy index refuses, and otherwise the miner status with `BuildTagScript`'s tag.
    async fn yellowback_miner(&self) -> Result<Option<YellowbackMiner>, String> {
        let Some(snapshot) = self.yed.snapshot().await? else {
            return Ok(None);
        };
        let health = snapshot.index.health();
        if !health.healthy {
            return Err(health.unhealthy_reason);
        }
        let miner = snapshot.node.miner;
        let tag = miner.quote.and_then(|quote| {
            YellowbackMiner::build_tag(
                miner.quote_kind == "quote",
                miner.payout_key,
                quote.price_micro_usd,
                quote.source_mask,
            )
        });
        Ok(Some(YellowbackMiner {
            tag,
            payout_key: miner.payout_key,
            quote_age_seconds: miner.quote_age_seconds,
            registered: miner.registered,
            eligible: miner.eligible,
        }))
    }

    /// ycash6 `TemplateRun`'s base: the set state after `parent`, `None` when the state
    /// service does not know it (the template then leaves out every vault transaction).
    async fn vault_state(&self, parent: block::Hash) -> Option<Arc<SetState>> {
        match self
            .read_state
            .clone()
            .oneshot(ReadRequest::VaultSnapshot {
                parent_hash: parent,
            })
            .await
        {
            Ok(ReadResponse::VaultSnapshot(Some(snapshot))) => Some(snapshot.state),
            Ok(_) => None,
            Err(error) => {
                tracing::warn!(%error, "the template's vault state could not be read");
                None
            }
        }
    }

    /// ycash6 `FilterTemplate` over a `TemplateView` of the index after `parent` (plan W5-f):
    /// `None` (keep every candidate) where Yellowback is off or `height` is below the start
    /// height; a filter that keeps nothing when the index state after `parent` is unknown.
    async fn yed_template_filter(
        &self,
        height: block::Height,
        parent: block::Hash,
    ) -> Option<Box<dyn YedTemplateFilter>> {
        let Some(snapshot) = self
            .yed_snapshot(ReadRequest::YedSnapshot { hash: parent })
            .await
        else {
            // The index state after the parent is unknown: where the node runs Yellowback and
            // the template is in the YED epoch, keep nothing (fail closed).
            let params = self
                .yed_snapshot(ReadRequest::BestChainYedSnapshot)
                .await
                .and_then(|s| s.params)?;
            return (i64::from(height.0) >= i64::from(params.start_height))
                .then(|| Box::new(KeepNothing) as Box<dyn YedTemplateFilter>);
        };
        let params = snapshot.params?;
        if i64::from(height.0) < i64::from(params.start_height) {
            return None;
        }
        Some(Box::new(YedTemplateRun {
            base: snapshot,
            writes: Writes::new(),
            params,
            height: i64::from(height.0),
        }))
    }

    /// The registered module table and the ancestor hashes after `parent` (ycash6
    /// `TemplateRun`'s modules and `SetBlockHashes(AncestorHashes(tip))`).
    async fn vault_modules(&self, parent: block::Hash) -> Option<VaultModules> {
        let snapshot = self
            .yed_snapshot(ReadRequest::YedSnapshot { hash: parent })
            .await?;
        let table = snapshot.module_table();
        Some(VaultModules {
            table,
            block_hash_at: Arc::new(move |h| snapshot.block_hash_at(h)),
        })
    }
}

impl<R> YedMining<R>
where
    R: Service<ReadRequest, Response = ReadResponse, Error = BoxError>
        + Clone
        + Send
        + Sync
        + 'static,
    R::Future: Send,
{
    /// The YED index state `request` reads (`ReadRequest::YedSnapshot` or
    /// `BestChainYedSnapshot`), `None` when the state service does not know it.
    async fn yed_snapshot(&self, request: ReadRequest) -> Option<zakura_state::yed::YedSnapshot> {
        match self.read_state.clone().oneshot(request).await {
            Ok(ReadResponse::YedSnapshot(snapshot)) => snapshot,
            Ok(_) => None,
            Err(error) => {
                tracing::warn!(%error, "the template's YED state could not be read");
                None
            }
        }
    }
}

/// The template's YED filter when the index state after its parent is unknown: it cannot tell
/// which candidates touch the module, so it keeps none (fail closed; the template still mines).
struct KeepNothing;

impl YedTemplateFilter for KeepNothing {
    fn keep(&mut self, _tx: &VerifiedUnminedTx) -> bool {
        false
    }
}

/// ycash6 `TemplateView` + `FilterTemplate`: the index after the template's parent, the
/// template's own overlay of the candidates it kept, and the parameters in force.
struct YedTemplateRun {
    base: zakura_state::yed::YedSnapshot,
    writes: Writes,
    params: Params,
    height: i64,
}

/// The template overlay over the index (the C++ `TemplateView::Overlay()`).
struct TemplateOverlay<'a> {
    base: &'a dyn YedRead,
    writes: &'a Writes,
}

impl YedRead for TemplateOverlay<'_> {
    fn get(&self, key: &YedKey) -> Option<YedRecord> {
        match self.writes.get(key) {
            Some(v) => v.clone(),
            None => self.base.get(key),
        }
    }

    fn scan(&self, table: Table) -> Vec<(YedKey, YedRecord)> {
        let base = self.base.scan(table);
        let (lo, hi) = table.bounds();
        let mut merged: std::collections::BTreeMap<YedKey, YedRecord> = base.into_iter().collect();
        for (k, v) in self.writes.range(lo..=hi) {
            match v {
                Some(v) => merged.insert(*k, v.clone()),
                None => merged.remove(k),
            };
        }
        merged.into_iter().collect()
    }
}

impl YedTemplateFilter for YedTemplateRun {
    fn keep(&mut self, tx: &VerifiedUnminedTx) -> bool {
        // The module cannot be evaluated: skip every candidate (the next block stops the node).
        if zakura_state::yed::yed_unhealthy_reason().is_some() {
            return false;
        }
        let transaction = tx.transaction.transaction();
        if transaction.is_coinbase() {
            return true;
        }
        let vtx = zakura_state::vault::vault_tx(transaction, &tx.transaction.id().mined_id());
        let overlay = TemplateOverlay {
            base: &self.base,
            writes: &self.writes,
        };
        // The storage boundary (audit A-3): a storage failure skips the candidate and marks the
        // index unhealthy instead of unwinding the template.
        let effect = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            process_tx(
                &overlay,
                &self.params,
                &vtx,
                self.height,
                Some(zakura_state::yed::module::node_yed_sig_cache()),
            )
        }));
        let effect = match effect {
            Ok(effect) => effect,
            Err(_) => {
                zakura_state::yed::mark_yed_unhealthy(
                    "storage failure in FilterTemplate".to_owned(),
                );
                return false;
            }
        };
        if effect.outcome.invalid {
            tracing::debug!(
                txid = ?tx.transaction.id().mined_id(),
                height = self.height,
                verdict = %effect.outcome.log.verdict,
                "FilterTemplate: skipping a candidate the YED module refuses"
            );
            return false;
        }
        self.writes.extend(effect.writes);
        true
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use kogany_vault::state::SetState;
    use zakura_chain::{block, chain_tip::NoChainTip};
    use zakura_state::{BoxError, ReadRequest, ReadResponse};

    use super::*;
    use crate::yed::mock::{MockYedState, UnavailableYedState};

    fn no_state(
    ) -> impl Service<ReadRequest, Response = ReadResponse, Error = BoxError, Future = impl Send>
           + Clone
           + Send
           + Sync
           + 'static {
        tower::service_fn(|_: ReadRequest| async {
            Ok::<_, BoxError>(ReadResponse::VaultSnapshot(None))
        })
    }

    /// `yed_setquote` and the template read one quote: no quote, no tag; a quote, a quote tag
    /// with no signal bit and the node's payout key; `0` clears it.
    #[tokio::test]
    async fn the_template_tag_follows_yed_setquote() {
        let yed: Arc<dyn YedReadState> = Arc::new(MockYedState::new(NoChainTip));
        let hooks = YedMining::new(yed.clone(), no_state());
        let miner = hooks.yellowback_miner().await.unwrap().expect("live");
        assert_eq!(miner.tag, None);
        assert!(miner.flags().is_empty());

        yed.set_quote(2_000_000, 5).await.expect("the quote is set");
        let miner = hooks.yellowback_miner().await.unwrap().expect("live");
        let tag = miner.tag.expect("a quote tag");
        assert_eq!(tag.flags, 0);
        assert_eq!(tag.price_micro_usd, 2_000_000);
        assert_eq!(tag.source_mask, 5);
        assert_eq!(Some(tag.payout_key), miner.payout_key);
        assert_eq!(miner.flags().len(), 37);

        yed.set_quote(0, 0).await.expect("the quote is cleared");
        let miner = hooks.yellowback_miner().await.unwrap().expect("live");
        assert_eq!(miner.tag, None);
    }

    /// Not live: no Yellowback fields; unhealthy: the template is refused with the reason.
    #[tokio::test]
    async fn not_live_and_unhealthy() {
        let off = YedMining::new(Arc::new(UnavailableYedState), no_state());
        assert_eq!(off.yellowback_miner().await, Ok(None));
        let sick = YedMining::new(Arc::new(MockYedState::unhealthy(NoChainTip)), no_state());
        assert!(sick.yellowback_miner().await.is_err());
    }

    /// The vault state comes from the read state's snapshot after the parent.
    #[tokio::test]
    async fn the_vault_state_is_the_snapshot_after_the_parent() {
        let parent = block::Hash([7; 32]);
        let state = Arc::new(SetState::new());
        let served = state.clone();
        let read_state = tower::service_fn(move |request: ReadRequest| {
            let served = served.clone();
            async move {
                let ReadRequest::VaultSnapshot { parent_hash } = request else {
                    return Ok::<_, BoxError>(ReadResponse::VaultSnapshot(None));
                };
                Ok(ReadResponse::VaultSnapshot((parent_hash == parent).then(
                    || zakura_state::vault::VaultSnapshot {
                        tip: None,
                        state: served,
                        yed_params: None,
                    },
                )))
            }
        });
        let hooks = YedMining::new(Arc::new(UnavailableYedState), read_state);
        assert!(hooks
            .vault_state(parent)
            .await
            .is_some_and(|s| Arc::ptr_eq(&s, &state)));
        assert!(hooks.vault_state(block::Hash([8; 32])).await.is_none());
    }
}
