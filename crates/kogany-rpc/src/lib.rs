//! kogany's JSON-RPC methods, served beside Zakura's `RpcServer` (plan W7).
//!
//! Copyright (c) 2026 The Ycash developers. Distributed under the MIT software license.
//!
//! - [`kogany_rpc_trait!`]: zakura-rpc's `rpc_trait!` for a trait outside zakura-rpc, with an
//!   access class per method (`macros.rs` says why Zakura's macro cannot be reused).
//! - [`vault`]: the vault primitive's read RPCs (`vault_getinfo`, `set_list`, `set_getinfo`,
//!   `vault_list`, `vault_decodescript`; `ycash6/doc/vault-rpc.md`), over a
//!   [`state::VaultReadState`].
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
pub mod state;
pub mod types;
pub mod vault;

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
/// variable [`mock::MOCK_ENV`] is `1`.
pub fn node_extension<T>(network: &Network, tip: T) -> RpcExtension
where
    T: ChainTip + Clone + Send + Sync + 'static,
{
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
    VaultRpcImpl::new(state, network.clone()).into_extension()
}
