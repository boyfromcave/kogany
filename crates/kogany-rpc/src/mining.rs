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
use zakura_rpc::ycash_mining::{YcashMining, YedTemplateFilter, YellowbackMiner};

use crate::yed::YedReadState;

/// The template hooks of a node whose Yellowback state is `yed`.
///
/// The vault half of the template filter needs the set state at the tip, which plan W4-d
/// serves ([`YcashMining::vault_state`] keeps its default until then); the YED half needs the
/// registered index, which plan W5-f serves ([`YcashMining::yed_template_filter`]).
#[derive(Clone)]
pub struct YedMining {
    yed: Arc<dyn YedReadState>,
}

impl YedMining {
    /// The hooks over `yed`.
    pub fn new(yed: Arc<dyn YedReadState>) -> Self {
        Self { yed }
    }
}

#[async_trait]
impl YcashMining for YedMining {
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
