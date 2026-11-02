//! The YED rule module registered with the vault primitive (kogany plan W5-f, U-21, U-25).
//!
//! ycash6 registers `yellowback::Module` in the primitive's compile-time table
//! (`src/vault/module.cpp`), configures it once at init with the network's YED parameters
//! (`yellowback::SetModuleParams`, `src/init.cpp`) and hands the primitive the index's signature
//! cache (`vault::SetModuleCache`, `src/init.cpp:2380`) and, per block, the ancestor hashes
//! (`SetBlockHashes(AncestorHashes(pindex->pprev))`, `src/main.cpp:4348`). Zakura has no init-time
//! global for consensus parameters: the vault transition builds its [`Rules`] per block from the
//! network. So here the transition builds its module table from the node's YED parameters (the
//! same [`yed_network_params`] the index uses) — `YED\0` → [`YedModule`] where Yellowback is
//! configured, the primitive's inert entry otherwise ([`registered_modules`]) — with the node's
//! one [`LruSigCache`] and a block-hash provider over the chain being validated.

use std::sync::OnceLock;

use kogany_vault::{
    state::{registered_modules, BlockHashFn, ModuleEntry, Rules},
    Hash32,
};
use kogany_yellowback::module::{LruSigCache, YedModule};
use zakura_chain::{block::Height, parameters::Network};

use crate::service::{
    finalized_state::{
        vault::VaultNetworkParams, yed::yed_network_params, ZakuraDb,
    },
    non_finalized_state::Chain,
};

use super::YellowbackConfig;

/// The node's signature cache (ycash6 `YellowbackIndex::sigCache`, an `LruSigCache` of
/// `SIG_CACHE_ENTRIES`): shared by the index's evaluations (block and mempool) and the module's
/// liveness hook. Node-local, never state.
pub fn node_yed_sig_cache() -> &'static LruSigCache {
    static CACHE: OnceLock<LruSigCache> = OnceLock::new();
    CACHE.get_or_init(LruSigCache::default)
}

/// The YED module of `network` under `config` (`SetModuleParams`), `None` where Yellowback is off
/// (no Vault height or no attestor set, U-22). A configuration the index cannot resolve is also
/// `None` here: the index's evaluation of the first Vault-epoch block then stops the node.
pub fn yed_module(network: &Network, config: &YellowbackConfig) -> Option<YedModule<'static>> {
    let p = yed_network_params(network, config).ok().flatten()?;
    YedModule::new(p, Some(node_yed_sig_cache()))
}

/// Runs `f` with the vault transition's [`Rules`] for `network`: `vault`'s activation height and
/// set maturity, the module table with `YED\0` registered where Yellowback is configured
/// ([`yed_module`]; the inert table otherwise), and `block_hashes` for the module hooks.
pub fn with_vault_rules<R>(
    vault: &VaultNetworkParams,
    network: &Network,
    config: &YellowbackConfig,
    block_hashes: Option<BlockHashFn<'_>>,
    f: impl FnOnce(&Rules<'_>) -> R,
) -> R {
    let module = yed_module(network, config);
    let table = module.as_ref().map(YedModule::table);
    let modules: &[ModuleEntry<'_>] = match &table {
        Some(table) => table,
        None => registered_modules(),
    };
    let base = vault.rules();
    f(&Rules {
        activation_height: base.activation_height,
        min_set_maturity: base.min_set_maturity,
        modules,
        block_hashes,
    })
}

fn height_of(h: i64) -> Option<Height> {
    u32::try_from(h).ok().map(Height)
}

/// The finalized chain's block hashes (`AncestorHashes` when the block's parent is the finalized
/// tip: the finalized write path).
pub fn finalized_block_hash_at(db: &ZakuraDb, h: i64) -> Option<Hash32> {
    db.hash(height_of(h)?).map(|hash| Hash32(hash.0))
}

/// The block hashes of `chain` (a non-finalized fork), then of the finalized chain below its
/// root (`AncestorHashes(pindex->pprev)` when `chain` is the block's parent fork).
pub fn chain_block_hash_at(chain: &Chain, db: &ZakuraDb, h: i64) -> Option<Hash32> {
    let height = height_of(h)?;
    chain
        .hash_by_height(height)
        .or_else(|| db.hash(height))
        .map(|hash| Hash32(hash.0))
}
