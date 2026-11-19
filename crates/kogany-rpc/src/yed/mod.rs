//! Ycash Yellowback (YED)'s node-context RPCs (`yed_*`), served beside Zakura's `RpcServer`
//! (plan W7-b; ycash6 `src/rpc/yellowback.cpp`, `doc/yellowback-rpc.md`, rpcversion 10).
//!
//! - [`rpc`]: the 25 read methods and the 2 node-state ones (`yed_setquote`, the miner's quote;
//!   `yed_addattestation`, the attestation pool; both `Admin`, ycashd's "RPC auth like every
//!   command"), over a [`state::YedReadState`].
//! - [`wallet`]: the 25 wallet-context `yed_*` methods, each answered `-32601` (kogany has no
//!   wallet, plan K-3; yewd serves them, K-20).
//! - [`state`]: the read boundary plan W5-e/W5-f implement; [`mock`]: the prototype's states.
//! - [`fees`]: the node's network-fee policy behind `params.fees.network` (W6-b).
//! - [`extension`]: both method sets as one server extension.
//!
//! Without Yellowback live (the default until W5-f registers the module) every `yed_*` method
//! answers `-32601 "Method not found (Yellowback is not active: …)"`, which is what ycashd answers
//! and what the lightwalletd-dd probe (`common/yellowback.go` `ProbeYellowback`) reads as "no
//! Yellowback". With it, `yed_getinfo.rpcversion` is [`YED_RPC_VERSION`].

use std::sync::Arc;

use zakura_chain::parameters::Network;
use zakura_rpc::server::kogany_extension::RpcExtension;

mod format;
mod params;

pub mod fees;
pub mod live;
pub mod live_index;
pub mod mock;
pub mod pool;
pub mod rpc;
pub mod state;
pub mod types;
pub mod wallet;

pub use rpc::{YedRpc, YedRpcDispatch, YedRpcImpl};
pub use state::{YedIndexView, YedReadState};
pub use wallet::{
    YedWalletRefusal, YedWalletRefusalDispatch, YedWalletRefusalImpl, WALLET_METHODS,
};

/// `YELLOWBACK_RPC_VERSION` (`ycash6/src/rpc/yellowback.cpp`): `11`, tag v2 (beta4 D-T2/D-T3):
/// `yed_gettag.version` (1 or 2) and `payoutScheme`, and every payee / `payoutAddress` may be a
/// plain-YEC post-quantum address (D-9 form). `10` was the beta3 additions in one
/// step (decision B3-D5): `getcoinbasetemplatefor`; `getblockchaininfo.transparentPools` and
/// `.transactions` (and `getblock`'s `transparentPools`); `getaddressbalance.txcount`,
/// `getaddressfirstlastheight` and the Sprout `commitments` of `z_gettreestate`; the opt-in insight
/// input fields of `getrawtransaction` / `getblock` and `getblock`'s `blockfee`; and the miner's
/// development-fund share (`-ydf`, kogany's `mining.ydf`). `9` was the scheme-visible
/// post-quantum address prefixes (D-9), `8` the fee structure.
pub const YED_RPC_VERSION: i64 = 11;

/// The `yed_*` read and node-state methods over `state`, and the wallet refusals, for `network`.
pub fn extension(state: Arc<dyn YedReadState>, network: &Network) -> RpcExtension {
    YedRpcImpl::new(state, network.clone())
        .into_extension()
        .and(YedWalletRefusalImpl.into_extension())
}
