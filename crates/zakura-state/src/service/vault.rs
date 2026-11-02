//! The Vault upgrade's set state across the finalized and non-finalized states (kogany plan
//! W4-c): the per-block transition for a fork, and the read API (a snapshot by block hash) that
//! contextual validation and script verification (W4-d) and the vault read RPCs (W7) consume.
//!
//! One data model throughout: `kogany_vault::state` records, [`SetState`], [`StateRead`] and
//! [`VaultDelta`]. The finalized state stores the records in four column families
//! ([`crate::service::finalized_state::vault`]); each non-finalized [`Chain`] holds an
//! overlay of what its blocks wrote ([`ChainVaultOverlay`]).

use std::{collections::HashMap, ops::Bound, sync::Arc};

use kogany_vault::{
    state::{check_tx, Rules, SetState, StateRead},
    Hash32,
};
use zakura_chain::{
    block::{self, Height},
    parameters::Network,
    transaction::{self, Transaction},
    transparent,
};

use crate::{
    service::{
        finalized_state::{
            vault::{
                block_vault_delta_total, report_skipped, vault_txs, OrderedUtxoCoins, UtxoCoins,
            },
            ZakuraDb,
        },
        non_finalized_state::Chain,
        yed::{
            module::{chain_block_hash_at, static_module_table},
            yed_params_for_db,
        },
    },
    ContextuallyVerifiedBlock,
};

#[cfg(any(test, feature = "proptest-impl"))]
pub use crate::service::finalized_state::vault::register_vault_params_for_test;
pub use crate::service::{
    finalized_state::vault::{
        vault_network_params, vault_outpoint, vault_tx, FinalizedVaultState, VaultNetworkParams,
    },
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
    let block_hash_at = |h: i64| chain_block_hash_at(parent_chain, db, h);
    let (delta, skipped) = block_vault_delta_total(
        network,
        &db.config().yellowback,
        &parent_chain.vault_view(db),
        &txs,
        block.height,
        &OrderedUtxoCoins(&block.spent_outputs),
        Some(&block_hash_at),
    );
    report_skipped("non-finalized push", block.height, block.hash, &skipped);
    delta
}

/// The YED parameters a [`VaultSnapshot`] carries (W5-f).
pub type YedModuleParams = kogany_yellowback::params::Params;

/// The set state after one block: what scripts spending in its child, the child's vault
/// transition, and the vault read RPCs read (ycash6 `SetSnapshot`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VaultSnapshot {
    /// The block the state is after: `None` for an empty finalized state.
    pub tip: Option<(Height, block::Hash)>,
    /// The whole set state after `tip`, in memory.
    pub state: Arc<SetState>,
    /// kogany (W5-f): the node's YED parameters (`None` where Yellowback is off): the module
    /// table a transaction checked over this state is judged with ([`mempool_vault_check`]).
    pub yed_params: Option<kogany_yellowback::params::Params>,
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
        yed_params: yed_params_for_db(db).ok().flatten(),
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
        yed_params: yed_params_for_db(db).ok().flatten(),
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
            yed_params: yed_params_for_db(db).ok().flatten(),
        });
    }
    let tip = db.tip()?;
    (tip.1 == hash).then(|| finalized_vault_snapshot(db))
}

/// The mempool's vault check (ycash6 `AcceptToMemoryPool`'s `vault::CheckTx`, `src/main.cpp:2198-2202`):
/// would `tx` apply at `height`, the next block's, over `tip_state`, the set state at the best
/// chain tip? `spent_utxos` are the coins it spends, a mempool parent's at `height`.
///
/// `Ok` where the Vault upgrade is not active at `height`. `Err` is the C++ reject reason; the
/// mempool does not score it (ycash6 DoS 0: it depends on the tip).
///
/// The module table is the node's: `YED\0` registered with `yed_params` (the snapshot's
/// [`VaultSnapshot::yed_params`]) where Yellowback is configured (W5-f). The mempool passes no
/// ancestor hashes: the hooks that read them (ejection, liveness) never reject.
pub fn mempool_vault_check(
    network: &Network,
    tip_state: &dyn StateRead,
    yed_params: Option<kogany_yellowback::params::Params>,
    tx: &Transaction,
    txid: &transaction::Hash,
    height: Height,
    spent_utxos: &HashMap<transparent::OutPoint, transparent::Utxo>,
) -> Result<(), String> {
    let Some(params) = vault_network_params(network).filter(|p| p.is_active(height)) else {
        return Ok(());
    };
    check_tx(
        tip_state,
        &vault_tx(tx, txid),
        i64::from(height.0),
        &UtxoCoins(spent_utxos),
        &Rules {
            modules: static_module_table(yed_params),
            ..params.rules()
        },
    )
    .map(|_| ())
    .map_err(|reject| reject.reason().to_owned())
}
