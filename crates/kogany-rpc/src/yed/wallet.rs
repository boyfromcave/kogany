//! The wallet-context `yed_*` methods (`ycash6/src/rpc/yellowbackwallet.cpp`), which kogany does
//! not serve: kogany has no wallet (plan K-3), and the Yellowback wallet in front of it is yewd
//! (K-20, plan §3b), which serves these methods itself and forwards every other one to kogany.
//!
//! kogany answers each of them `-32601`, the code ycashd gives on a node without a wallet (the
//! wallet table is not registered under `-disablewallet`), with a message that names the method
//! and where it is served. They are registered, rather than left to the server's generic
//! "Method not found", so that the refusal says why and so that plan W7-d's OpenRPC check can
//! list them as sidecar-served from [`YedWalletRefusalDispatch::METHOD_DOCS`].

// The refusals take no parameters, so the dispatch kogany_rpc_trait! generates never reads them.
#![allow(unused_variables)]

use serde_json::Value;
use zakura_rpc::server::jsonrpc::{ErrorCode, ErrorObject, RpcResult};

/// The refusal of the wallet method `method`.
pub fn wallet_refusal(method: &str) -> ErrorObject {
    ErrorObject::new(
        ErrorCode::MethodNotFound,
        format!(
            "Method not found ({method} is a Yellowback wallet RPC; kogany has no wallet: call it on the wallet, yewd)"
        ),
    )
}

macro_rules! wallet_methods {
    ($($name:literal => $method:ident),* $(,)?) => {
        crate::kogany_rpc_trait! {
            /// The Yellowback wallet methods, each answered `-32601` (see the module docs).
            pub trait YedWalletRefusal {
                $(
                    /// A Yellowback wallet RPC, served by yewd (plan K-3, K-20); kogany answers -32601.
                    #[method(name = $name, access = Unauthenticated)]
                    async fn $method(&self) -> RpcResult<Value>;
                )*
            }
            dispatch = YedWalletRefusalDispatch;
        }

        /// The wallet-context method names, in ycashd's table order.
        pub const WALLET_METHODS: &[&str] = &[$($name),*];

        /// [`YedWalletRefusal`]: every method refuses.
        #[derive(Clone, Copy, Debug, Default)]
        pub struct YedWalletRefusalImpl;

        #[async_trait::async_trait]
        impl YedWalletRefusal for YedWalletRefusalImpl {
            $(
                async fn $method(&self) -> RpcResult<Value> {
                    Err(wallet_refusal($name))
                }
            )*
        }
    };
}

wallet_methods! {
    "yed_getnewaddress" => yed_getnewaddress,
    "yed_validateaddress" => yed_validateaddress,
    "yed_getbalance" => yed_getbalance,
    "yed_listunspent" => yed_listunspent,
    "yed_mint" => yed_mint,
    "yed_send" => yed_send,
    "yed_sendmany" => yed_sendmany,
    "yed_redeem" => yed_redeem,
    "yed_claim" => yed_claim,
    "yed_listpositions" => yed_listpositions,
    "yed_listtransactions" => yed_listtransactions,
    "yed_listaddresses" => yed_listaddresses,
    "yed_lockcoins" => yed_lockcoins,
    "yed_estimatesend" => yed_estimatesend,
    "yed_estimateredeem" => yed_estimateredeem,
    "yed_unlockcoin" => yed_unlockcoin,
    "yed_buildcancel" => yed_buildcancel,
    "yed_signcancelcosign" => yed_signcancelcosign,
    "yed_claimnotice" => yed_claimnotice,
    "yed_sweepcarriers" => yed_sweepcarriers,
    "yed_registerattestor" => yed_registerattestor,
    "yed_withdrawbond" => yed_withdrawbond,
    "yed_revive" => yed_revive,
    "yed_reportequivocation" => yed_reportequivocation,
    "yed_signattestation" => yed_signattestation,
}

impl YedWalletRefusalImpl {
    /// These refusals as a server extension.
    pub fn into_extension(self) -> zakura_rpc::server::kogany_extension::RpcExtension {
        YedWalletRefusalDispatch(self).into_extension()
    }
}
