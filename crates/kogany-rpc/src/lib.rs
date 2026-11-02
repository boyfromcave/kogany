//! kogany's JSON-RPC methods, served beside Zakura's `RpcServer` (plan W7).
//!
//! Copyright (c) 2026 The Ycash developers. Distributed under the MIT software license.
//!
//! - [`kogany_rpc_trait!`]: zakura-rpc's `rpc_trait!` for a trait outside zakura-rpc, with an
//!   access class per method (`macros.rs` says why Zakura's macro cannot be reused).
//! - [`vault`]: the vault primitive's read RPCs (`vault_getinfo`, `set_list`, `set_getinfo`,
//!   `vault_list`, `vault_decodescript`; `ycash6/doc/vault-rpc.md`), over a
//!   [`state::VaultReadState`].
//! - [`yed`]: Ycash Yellowback (YED)'s node-context RPCs (`yed_*`, `ycash6/doc/yellowback-rpc.md`,
//!   rpcversion 8) over a [`yed::YedReadState`] (plan W5-e/W5-f), and the wallet-context ones
//!   refused (`-32601`; yewd serves them, K-3).
//! - [`state`]: the read boundary plan W4-d implements; [`mock`]: the prototype's states.
//! - [`node_extension`]: what `zakurad` passes to
//!   `zakura_rpc::server::kogany_extension::start_node_server`.
//!
//! The extension's methods are dispatched by
//! `zakura_rpc::server::kogany_extension::ExtendedMethods`: a name the extension registers goes
//! to it, any other name to `RpcServer`, and a name neither registers is `-32601`.

use std::sync::Arc;

use zakura_chain::{chain_tip::ChainTip, parameters::Network};
use zakura_rpc::server::kogany_extension::RpcExtension;

mod macros;

pub mod json;
pub mod mock;
pub mod regtest;
pub mod state;
pub mod types;
pub mod vault;
pub mod yed;

#[doc(hidden)]
pub mod __private {
    pub use async_trait::async_trait;
    pub use serde;
    pub use zakura_rpc::server::{
        jsonrpc,
        kogany_extension::{ExtensionAccess, RpcExtension},
        rpc_service::RpcMethods,
    };
}

pub use state::VaultReadState;
pub use vault::{VaultRpc, VaultRpcDispatch, VaultRpcImpl};

/// The extension `zakurad` serves on `network` at the chain tip `tip`.
///
/// Until plan W4-d wires the vault state, the vault reads answer from
/// [`mock::UnavailableVaultState`], or from [`mock::MockVaultState`] when the environment
/// variable [`mock::MOCK_ENV`] is `1`. Until plan W5-f registers the YED module, the `yed_*`
/// methods answer from [`yed::mock::UnavailableYedState`] (`-32601`, Yellowback not live), or
/// from [`yed::mock::MockYedState`] when [`yed::mock::MOCK_ENV`] is `1`.
pub fn node_extension<T>(network: &Network, tip: T) -> RpcExtension
where
    T: ChainTip + Clone + Send + Sync + 'static,
{
    let yed = yed_state(tip.clone());
    let state: Arc<dyn VaultReadState> =
        if std::env::var(mock::MOCK_ENV).is_ok_and(|value| value == "1") {
            tracing::warn!(
                "{}=1: the vault RPCs answer from a fixed fixture, not the chain",
                mock::MOCK_ENV
            );
            Arc::new(mock::MockVaultState::new(tip))
        } else {
            Arc::new(mock::UnavailableVaultState::new(tip))
        };
    VaultRpcImpl::new(state, network.clone())
        .into_extension()
        .and(yed::extension(yed, network))
        .and(regtest::RegtestRpcImpl::new(network.clone()).into_extension())
}

/// The YED state `zakurad` serves until plan W5-f registers the module.
fn yed_state<T>(tip: T) -> Arc<dyn yed::YedReadState>
where
    T: ChainTip + Clone + Send + Sync + 'static,
{
    if std::env::var(yed::mock::MOCK_ENV).is_ok_and(|value| value == "1") {
        tracing::warn!(
            "{}=1: the yed_* RPCs answer from a fixed fixture, not the chain",
            yed::mock::MOCK_ENV
        );
        Arc::new(yed::mock::MockYedState::new(tip))
    } else {
        Arc::new(yed::mock::UnavailableYedState)
    }
}
