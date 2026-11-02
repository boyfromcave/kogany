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
