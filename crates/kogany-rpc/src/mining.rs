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
use tower::{Service, ServiceExt};
use zakura_chain::block;
use zakura_rpc::ycash_mining::{YcashMining, YedTemplateFilter, YellowbackMiner};
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

    fn yed_template_filter(
        &self,
        height: zakura_chain::block::Height,
    ) -> Option<Box<dyn YedTemplateFilter>> {
        // Plan W5-f: the registered index's `TemplateView` (ycash6 `FilterTemplate`), built
        // here at `height` once the index exists.
        let _ = height;
        None
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
