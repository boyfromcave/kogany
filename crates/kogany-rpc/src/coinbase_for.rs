//! `getcoinbasetemplatefor`: a coinbase for a payout address and a block template the caller
//! names (beta3 item 3), served beside Zakura's `getblocktemplate` on a Ycash node.
//!
//! Copyright (c) 2026 The Ycash developers. Distributed under the MIT software license.
//!
//! ycashd's call (`ycash6 src/rpc/mining.cpp` `getcoinbasetemplatefor`) reads the tip and the
//! mempool under `cs_main` and `mempool.cs`, builds the coinbase with the node's own builder and
//! keeps nothing. kogany's reads the tip from the read state service and the fees from the
//! mempool service ([`crate::mempool`]), and builds the coinbase in zakura-rpc
//! (`zakura_rpc::ycash_coinbase_for`), where the node's own coinbase is built. The request, the
//! response and the errors are the contract's (`docs/plans/beta3/getcoinbasetemplatefor.md` of the
//! Yellowback workspace), the same on the three node lines.
//!
//! `zakurad` gives the method the node's `mining.ydf` once at start ([`set_ydf_percentage`]), so
//! the call's fund output is the one the node's own coinbase carries, and installs the Sapling
//! output prover (`zakura_rpc::ycash_sapling_coinbase`).

use std::{
    future::Future,
    pin::Pin,
    sync::{Arc, OnceLock},
};

use serde_json::Value;
use tower::util::BoxCloneSyncService;
use zakura_chain::{chain_tip::ChainTip, parameters::Network};
use zakura_node_services::mempool::{Request, Response};
use zakura_rpc::{
    server::{
        jsonrpc::{ErrorObject, Id, MethodResponse, Params, RpcResult},
        rpc_service::RpcMethods,
    },
    ycash_coinbase_for::{get_coinbase_template_for, CoinbaseForNode, CoinbaseTemplateFor},
    ycash_mining::YcashMining,
    ycash_sapling_coinbase::installed_output_prover,
};
use zakura_state::{BoxError, ReadRequest, ReadResponse};

/// The read state service the call reads the tip from.
pub type ReadStateService = BoxCloneSyncService<ReadRequest, ReadResponse, BoxError>;

/// The call's usage line, the first line of ycashd's help text for it.
pub const USAGE: &str =
    "getcoinbasetemplatefor \"address\" {\"previousblockhash\":\"hex\",\"txids\":[\"hex\",...]}";

static YDF_PERCENTAGE: OnceLock<u64> = OnceLock::new();

/// Gives the call the node's `mining.ydf` (0..=100), as the node's own coinbase reads it. The
/// first call wins; without one the share is the default, 0.
pub fn set_ydf_percentage(ydf_percentage: u64) {
    let _ = YDF_PERCENTAGE.set(ydf_percentage.min(100));
}

crate::kogany_rpc_trait! {
    /// The coinbase a pool pairs with a stock block template.
    pub trait CoinbaseForRpc {
        /// A coinbase paying `address` for the template `{"previousblockhash", "txids"}`: the
        /// node derives the amount (subsidy, less its development-fund output, plus the mempool
        /// fee of every named transaction). There is no amount argument: a third parameter is
        /// refused with the usage line, as ycashd refuses it.
        #[method(name = "getcoinbasetemplatefor", access = Unauthenticated)]
        async fn getcoinbasetemplatefor(
            &self,
            address: Value,
            template: Value,
            unexpected: Option<Value>,
        ) -> RpcResult<CoinbaseTemplateFor>;
    }
    dispatch = CoinbaseForRpcDispatch;
}

/// [`CoinbaseForRpc`] on a node.
#[derive(Clone)]
pub struct CoinbaseForRpcImpl<Tip> {
    network: Network,
    latest_chain_tip: Tip,
    read_state: ReadStateService,
    mining: Arc<dyn YcashMining>,
}

impl<Tip> CoinbaseForRpcImpl<Tip>
where
    Tip: ChainTip + Clone + Send + Sync + 'static,
{
    /// The call on `network`, over the chain tip, the read state service and the node's
    /// Yellowback mining state (`crate::mining_hooks`, the one `getblocktemplate` reads).
    pub fn new(
        network: Network,
        latest_chain_tip: Tip,
        read_state: ReadStateService,
        mining: Arc<dyn YcashMining>,
    ) -> Self {
        Self {
            network,
            latest_chain_tip,
            read_state,
            mining,
        }
    }

    /// This method as a server extension, refusing more than two positional parameters.
    pub fn into_extension(self) -> zakura_rpc::server::kogany_extension::RpcExtension {
        zakura_rpc::server::kogany_extension::RpcExtension::new(
            TwoParameters(CoinbaseForRpcDispatch(self)),
            CoinbaseForRpcDispatch::<Self>::METHOD_ACCESS,
        )
    }
}

/// [`CoinbaseForRpcDispatch`] that refuses a call with more than two positional parameters, as
/// ycashd refuses `params.size() != 2`. The decoder reads a trailing JSON `null` as an omitted
/// optional parameter, so `[address, template, null]` would otherwise pass: this counts the
/// parameters as they were sent.
#[derive(Clone)]
struct TwoParameters<T>(CoinbaseForRpcDispatch<T>);

/// Whether `params` are positional and more than two.
fn more_than_two_positional(params: &Params<'_>) -> bool {
    !params.is_object()
        && params
            .parse::<Vec<serde::de::IgnoredAny>>()
            .is_ok_and(|params| params.len() > 2)
}

impl<T> RpcMethods for TwoParameters<T>
where
    T: CoinbaseForRpc + Clone + Send + Sync + 'static,
{
    const METHOD_NAMES: &'static [&'static str] =
        <CoinbaseForRpcDispatch<T> as RpcMethods>::METHOD_NAMES;

    fn call<'a>(
        &'a self,
        method: &str,
        params: Params<'a>,
        id: Id<'a>,
        max_response_size: usize,
    ) -> Option<Pin<Box<dyn Future<Output = MethodResponse> + Send + 'a>>> {
        if Self::METHOD_NAMES.contains(&method) && more_than_two_positional(&params) {
            // ycashd answers a wrong number of parameters with its help text (`RPC_MISC_ERROR`).
            let refused: RpcResult<()> = Err(ErrorObject::new(-1, USAGE));
            return Some(Box::pin(async move {
                MethodResponse::response(id, &refused, max_response_size)
            }));
        }
        self.0.call(method, params, id, max_response_size)
    }
}

/// The node's mempool, or one that answers nothing while the node has none (then a request that
/// names a transaction is refused as stale).
fn mempool() -> crate::mempool::MempoolService {
    crate::mempool::service().unwrap_or_else(|| {
        BoxCloneSyncService::new(tower::service_fn(|_: Request| async {
            Err::<Response, BoxError>("the node has no mempool yet".into())
        }))
    })
}

#[async_trait::async_trait]
impl<Tip> CoinbaseForRpc for CoinbaseForRpcImpl<Tip>
where
    Tip: ChainTip + Clone + Send + Sync + 'static,
{
    async fn getcoinbasetemplatefor(
        &self,
        address: Value,
        template: Value,
        unexpected: Option<Value>,
    ) -> RpcResult<CoinbaseTemplateFor> {
        // ycashd answers a wrong number of parameters with its help text (`RPC_MISC_ERROR`).
        if unexpected.is_some() {
            return Err(ErrorObject::new(-1, USAGE));
        }
        get_coinbase_template_for(
            CoinbaseForNode {
                network: self.network.clone(),
                mempool: mempool(),
                read_state: self.read_state.clone(),
                latest_chain_tip: self.latest_chain_tip.clone(),
                mining: self.mining.clone(),
                ydf_percentage: YDF_PERCENTAGE.get().copied().unwrap_or(0),
                sapling_output_prover: installed_output_prover(),
            },
            &address,
            &template,
        )
        .await
    }
}
