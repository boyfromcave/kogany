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
//! - [`state`]: the read boundary; [`live`]: its implementation over the node's set state
//!   (plan W4-d); [`mock`]: the prototype's states.
//! - [`node_extension`]: what `zakurad` passes to
//!   `zakura_rpc::server::kogany_extension::start_node_server`.
//!
//! The extension's methods are dispatched by
//! `zakura_rpc::server::kogany_extension::ExtendedMethods`: a name the extension registers goes
//! to it, any other name to `RpcServer`, and a name neither registers is `-32601`.

use std::sync::Arc;

use zakura_chain::{chain_tip::ChainTip, parameters::Network};
use zakura_rpc::server::kogany_extension::RpcExtension;
use zakura_state::{BoxError, ReadRequest, ReadResponse};

mod macros;

#[cfg(feature = "ycash")]
pub mod insight;
pub mod json;
pub mod live;
pub mod mempool;
#[cfg(feature = "ycash")]
pub mod mining;
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

/// The extension `zakurad` serves on `network` at the chain tip `tip`, over the read state
/// service `read_state`.
///
/// The vault reads answer from the node's set state ([`live::LiveVaultState`]), or from
/// [`mock::MockVaultState`] when the environment variable [`mock::MOCK_ENV`] is `1`. The `yed_*`
/// methods answer from the registered index ([`yed::live::LiveYedState`], plan W5-f; `-32601`
/// where Yellowback is off), or from [`yed::mock::MockYedState`] when [`yed::mock::MOCK_ENV`]
/// is `1`.
pub fn node_extension<T, R>(network: &Network, tip: T, read_state: R) -> RpcExtension
where
    T: ChainTip + Clone + Send + Sync + 'static,
    R: tower::Service<ReadRequest, Response = ReadResponse, Error = BoxError>
        + Clone
        + Send
        + Sync
        + 'static,
    R::Future: Send + 'static,
{
    yed::live::set_network(network);
    let yed = yed_state(tip.clone(), read_state.clone());
    let insight_read_state = read_state.clone();
    let state: Arc<dyn VaultReadState> =
        if std::env::var(mock::MOCK_ENV).is_ok_and(|value| value == "1") {
            tracing::warn!(
                "{}=1: the vault RPCs answer from a fixed fixture, not the chain",
                mock::MOCK_ENV
            );
            Arc::new(mock::MockVaultState::new(tip))
        } else {
            Arc::new(live::LiveVaultState::new(network.clone(), read_state))
        };
    let extension = VaultRpcImpl::new(state, network.clone())
        .into_extension()
        .and(yed::extension(yed, network))
        .and(regtest::RegtestRpcImpl::new(network.clone()).into_extension());
    // S5 parity: ycashd's insight reads Zakura does not serve (getaddressmempool,
    // getaddressdeltas).
    #[cfg(feature = "ycash")]
    let extension = extension.and(
        insight::InsightRpcImpl::new(
            network.clone(),
            Some(tower::util::BoxCloneSyncService::new(insight_read_state)),
        )
        .into_extension(),
    );
    #[cfg(not(feature = "ycash"))]
    drop(insight_read_state);
    extension
}

/// The `getblocktemplate` hooks `zakurad` installs on a Ycash node (plan W8-b): over the same
/// YED state as the `yed_*` methods of [`node_extension`], so `yed_setquote` sets the quote the
/// next template's coinbase tag carries. The vault half of the template filter reads the set
/// state from `read_state`.
#[cfg(feature = "ycash")]
pub fn mining_hooks<T, R>(tip: T, read_state: R) -> Arc<dyn zakura_rpc::ycash_mining::YcashMining>
where
    T: ChainTip + Clone + Send + Sync + 'static,
    R: tower::Service<ReadRequest, Response = ReadResponse, Error = BoxError>
        + Clone
        + Send
        + Sync
        + 'static,
    R::Future: Send,
{
    Arc::new(mining::YedMining::new(
        yed_state(tip, read_state.clone()),
        read_state,
    ))
}

/// The YED state `zakurad` serves: one per process, so every listener and the template read one
/// quote (ycash6's `g_yellowback`). The registered index ([`yed::live::LiveYedState`], plan
/// W5-f), which answers "not live" (`-32601`) where Yellowback is off; or
/// [`yed::mock::MockYedState`] when [`yed::mock::MOCK_ENV`] is `1`.
fn yed_state<T, R>(tip: T, read_state: R) -> Arc<dyn yed::YedReadState>
where
    T: ChainTip + Clone + Send + Sync + 'static,
    R: tower::Service<ReadRequest, Response = ReadResponse, Error = BoxError>
        + Clone
        + Send
        + Sync
        + 'static,
    R::Future: Send,
{
    static YED_STATE: std::sync::OnceLock<Arc<dyn yed::YedReadState>> = std::sync::OnceLock::new();
    YED_STATE
        .get_or_init(|| new_yed_state(tip, read_state))
        .clone()
}

fn new_yed_state<T, R>(tip: T, read_state: R) -> Arc<dyn yed::YedReadState>
where
    T: ChainTip + Clone + Send + Sync + 'static,
    R: tower::Service<ReadRequest, Response = ReadResponse, Error = BoxError>
        + Clone
        + Send
        + Sync
        + 'static,
    R::Future: Send,
{
    if std::env::var(yed::mock::MOCK_ENV).is_ok_and(|value| value == "1") {
        tracing::warn!(
            "{}=1: the yed_* RPCs answer from a fixed fixture, not the chain",
            yed::mock::MOCK_ENV
        );
        Arc::new(yed::mock::MockYedState::new(tip))
    } else {
        Arc::new(yed::live::LiveYedState::new(tip, read_state))
    }
}
