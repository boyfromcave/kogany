//! `getcoinbasetemplatefor` as the extension serves it (beta3 item 3): the method reads the
//! node's `mining.ydf` and its mempool through the extension's process-wide hooks, refuses a
//! third parameter with the usage line, and without a mempool can state no fee. Its own test
//! binary, since the share is one value per process. The coinbase itself is tested in
//! zakura-rpc, and against ycashd by `qa/coinbase_for_parity.py`.

#![cfg(feature = "ycash")]

use std::{future::Future, pin::Pin, sync::Arc};

use kogany_rpc::coinbase_for::{set_ydf_percentage, CoinbaseForRpc, CoinbaseForRpcImpl, USAGE};
use serde_json::{json, Value};
use tower::util::BoxCloneSyncService;
use zakura_chain::{
    block::{self, Height},
    chain_tip::NoChainTip,
    parameters::Network,
};
use zakura_rpc::{
    server::{
        jsonrpc::{Id, MethodResponse, Params},
        kogany_extension::{ExtendedMethods, ExtensionAccess},
        rpc_service::{handle_rpc_call, RpcMethods, RpcService},
    },
    ycash_mining::NotLive,
};
use zakura_state::{BoxError, ReadRequest, ReadResponse};

const P2PKH: &str = "smKfGwyRJhcNVEQL3ZC2Kitx3WhmHHGLxFR";
const SUBSIDY: i64 = 625_000_000;

#[tokio::test]
async fn the_method_reads_the_nodes_share_and_takes_no_third_parameter() {
    let tip = block::Hash([7; 32]);
    let read_state = tower::service_fn(move |request: ReadRequest| async move {
        assert!(matches!(request, ReadRequest::Tip));
        Ok::<_, BoxError>(ReadResponse::Tip(Some((Height(119), tip))))
    });
    set_ydf_percentage(5);
    let rpc = CoinbaseForRpcImpl::new(
        Network::new_regtest(Default::default()),
        NoChainTip,
        BoxCloneSyncService::new(read_state),
        Arc::new(NotLive),
    );
    let reference = |txids: &[&str]| json!({"previousblockhash": tip.to_string(), "txids": txids});

    // An empty template: the subsidy, less the node's 5 %.
    let answer = rpc
        .getcoinbasetemplatefor(json!(P2PKH), reference(&[]), None)
        .await
        .expect("the call answers");
    let fund = SUBSIDY * 5 / 100;
    assert_eq!(
        (
            answer.height,
            answer.subsidy,
            answer.fund,
            answer.fundrule.as_str(),
            answer.fees,
            answer.amount,
            answer.txcount
        ),
        (120, SUBSIDY, fund, "optional", 0, SUBSIDY - fund, 0)
    );

    // No mempool was given to the extension: no fee can be stated, so the named transaction is
    // not in the mempool (the contract's row 11), never the mempool service's own error.
    let txid = "ab".repeat(32);
    let error = rpc
        .getcoinbasetemplatefor(json!(P2PKH), reference(&[&txid]), None)
        .await
        .expect_err("no mempool");
    assert_eq!(
        (error.code(), error.message()),
        (
            -1,
            format!("template-stale: transaction is not in the mempool: {txid}").as_str()
        )
    );

    // A third parameter cannot carry an amount: the usage line, as ycashd.
    let error = rpc
        .getcoinbasetemplatefor(json!(P2PKH), reference(&[]), Some(json!(1)))
        .await
        .expect_err("a third parameter is refused");
    assert_eq!((error.code(), error.message()), (-1, USAGE));
    assert!(USAGE.starts_with("getcoinbasetemplatefor \"address\""));

    // As the server dispatches it: any third positional parameter, `null` included, is refused
    // with the usage line, as ycashd refuses `params.size() != 2`; two are answered.
    let extension = rpc.into_extension();
    // The access class of `getblocktemplate` and `submitblock` (zakura-rpc `methods.rs`,
    // `RPC_METHOD_ACCESS`): the mining calls are served where those are.
    assert_eq!(
        extension.access("getcoinbasetemplatefor"),
        Some(ExtensionAccess::Unauthenticated)
    );
    let service = RpcService::new(
        ExtendedMethods::new(NoMethods, extension),
        vec!["getcoinbasetemplatefor"],
        usize::MAX,
    );
    let call = |params: Value| {
        let service = service.clone();
        async move {
            let body = json!({"jsonrpc": "2.0", "id": 1, "method": "getcoinbasetemplatefor", "params": params})
                .to_string();
            let response = handle_rpc_call(body.as_bytes(), true, &service, 100, usize::MAX).await;
            serde_json::from_str::<Value>(response.as_json().get()).expect("responses are JSON")
        }
    };
    for params in [
        json!([P2PKH, reference(&[]), null]),
        json!([P2PKH, reference(&[]), 1]),
        json!([P2PKH, reference(&[]), null, null]),
    ] {
        let response = call(params.clone()).await;
        assert_eq!(
            (&response["error"]["code"], &response["error"]["message"]),
            (&json!(-1), &json!(USAGE)),
            "{params}: {response}"
        );
    }
    let response = call(json!([P2PKH, reference(&[])])).await;
    assert_eq!(
        response["result"]["amount"],
        json!(SUBSIDY - fund),
        "{response}"
    );
}

/// No method of its own: the server's primary set beside the extension.
#[derive(Clone)]
struct NoMethods;

impl RpcMethods for NoMethods {
    const METHOD_NAMES: &'static [&'static str] = &[];

    fn call<'a>(
        &'a self,
        _method: &str,
        _params: Params<'a>,
        _id: Id<'a>,
        _max_response_size: usize,
    ) -> Option<Pin<Box<dyn Future<Output = MethodResponse> + Send + 'a>>> {
        None
    }
}
