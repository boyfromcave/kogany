//! The Vault upgrade's set state across the finalized and non-finalized states (kogany plan
//! W4-c): the per-block transition for a fork, and the read API (a snapshot by block hash) that
//! contextual validation and script verification (W4-d) and the vault read RPCs (W7) consume.
//!
//! One data model throughout: `kogany_vault::state` records, [`SetState`], [`StateRead`] and
//! [`VaultDelta`]. The finalized state stores the records in four column families
//! ([`crate::service::finalized_state::vault`]); each non-finalized [`Chain`] holds an
//! overlay of what its blocks wrote ([`ChainVaultOverlay`]).

use std::{ops::Bound, sync::Arc};

use kogany_vault::{state::SetState, Hash32};
use zakura_chain::{
    block::{self, Height},
    parameters::Network,
};

use crate::{
    service::{
        finalized_state::{
            vault::{block_vault_delta_total, report_skipped, vault_txs, OrderedUtxoCoins},
            ZakuraDb,
        },
        non_finalized_state::Chain,
    },
    ContextuallyVerifiedBlock,
};

#[cfg(any(test, feature = "proptest-impl"))]
pub use crate::service::finalized_state::vault::register_vault_params_for_test;
pub use crate::service::{
    finalized_state::vault::{vault_network_params, FinalizedVaultState, VaultNetworkParams},
    non_finalized_state::{ChainVaultOverlay, ChainVaultView, VaultDelta},
};

/// The vault delta of `block` pushed onto `parent_chain` (the parent fork, or an empty chain at
/// the finalized tip), computed over the state at the parent's tip with the block's own spent
/// outputs. Total (see `block_vault_delta_total`): a reject is logged and skipped.
pub fn block_vault_delta_for_chain(
    network: &Network,
    parent_chain: &Chain,
    db: &ZakuraDb,
    block: &ContextuallyVerifiedBlock,
) -> VaultDelta {
    if vault_network_params(network).is_none_or(|p| !p.is_active(block.height)) {
        return VaultDelta::default();
    }
    let txs = vault_txs(&block.block, &block.transaction_hashes);
    let (delta, skipped) = block_vault_delta_total(
        network,
        &parent_chain.vault_view(db),
        &txs,
        block.height,
        &OrderedUtxoCoins(&block.spent_outputs),
    );
    report_skipped("non-finalized push", block.height, block.hash, &skipped);
    delta
}

/// The set state after one block: what scripts spending in its child, the child's vault
/// transition, and the vault read RPCs read (ycash6 `SetSnapshot`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VaultSnapshot {
    /// The block the state is after: `None` for an empty finalized state.
    pub tip: Option<(Height, block::Hash)>,
    /// The whole set state after `tip`, in memory.
    pub state: Arc<SetState>,
}

impl VaultSnapshot {
    /// The canonical `statehash` (`vault_getinfo.statehash`), internal byte order.
    pub fn state_hash(&self) -> Hash32 {
        self.state.state_hash()
    }
}

/// The set state at the finalized tip.
pub fn finalized_vault_snapshot(db: &ZakuraDb) -> VaultSnapshot {
    VaultSnapshot {
        tip: db.tip(),
        state: Arc::new(db.vault_set_state()),
    }
}

/// The set state at `chain`'s tip.
pub fn chain_tip_vault_snapshot(chain: &Chain, db: &ZakuraDb) -> VaultSnapshot {
    let tip = chain
        .tip_block()
        .map(|b| (b.height, b.hash))
        .or_else(|| db.tip());
    VaultSnapshot {
        tip,
        state: Arc::new(chain.vault_view(db).set_state()),
    }
}

/// The set state after the block `hash` (fork-aware): the finalized tip, or a block of any of
/// `chains`. `None` when `hash` is neither the finalized tip nor in a non-finalized chain (a
/// finalized block below the tip has no stored state: there is no finalized undo, K-14).
///
/// Reads the finalized state and the chains as given; the caller passes the chains and database
/// of one non-finalized-state version, as every other zakura-state read does.
pub fn vault_snapshot_by_hash<'a>(
    chains: impl IntoIterator<Item = &'a Arc<Chain>>,
    db: &ZakuraDb,
    hash: block::Hash,
) -> Option<VaultSnapshot> {
    for chain in chains {
        let Some(height) = chain.height_by_hash(hash) else {
            continue;
        };
        let mut state = chain.vault_view(db).set_state();
        // Undo the blocks above `hash`, newest first.
        let above = (Bound::Excluded(height), Bound::Unbounded);
        for (_, block) in chain.blocks.range(above).rev() {
            state.revert(&block.vault_delta);
        }
        return Some(VaultSnapshot {
            tip: Some((height, hash)),
            state: Arc::new(state),
        });
    }
    let tip = db.tip()?;
    (tip.1 == hash).then(|| finalized_vault_snapshot(db))
}
