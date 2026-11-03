//! The vault reads dispatched beside another method set, through zakura-rpc's `RpcService`, with
//! the mock and the unavailable states.

mod common;

use std::{future::Future, pin::Pin, sync::Arc};

use kogany_rpc::{
    mock::{Fixture, MockVaultState, UnavailableVaultState},
    VaultReadState, VaultRpcDispatch, VaultRpcImpl,
};
use serde_json::{json, Value};
use zakura_chain::{chain_tip::NoChainTip, parameters::Network};
use zakura_rpc::server::{
    jsonrpc::{Id, MethodResponse, Params},
    kogany_extension::{ExtendedMethods, ExtensionAccess, RpcExtension},
    rpc_service::{handle_rpc_call, RpcMethods, RpcService},
};

/// A stand-in for `RpcServer`'s methods: `getinfo` answers `"primary"`.
#[derive(Clone)]
struct Primary;

impl RpcMethods for Primary {
    const METHOD_NAMES: &'static [&'static str] = &["getinfo"];

    fn call<'a>(
        &'a self,
        method: &str,
        _params: Params<'a>,
        id: Id<'a>,
        max_response_size: usize,
    ) -> Option<Pin<Box<dyn Future<Output = MethodResponse> + Send + 'a>>> {
        (method == "getinfo").then(|| {
            Box::pin(async move {
                MethodResponse::response(
                    id,
                    &Ok::<_, zakura_rpc::server::jsonrpc::ErrorObject>("primary"),
                    max_response_size,
                )
            }) as Pin<Box<dyn Future<Output = MethodResponse> + Send + 'a>>
        })
    }
}

fn service(state: Arc<dyn VaultReadState>) -> RpcService<ExtendedMethods<Primary>> {
    let extension =
        VaultRpcImpl::new(state, Network::new_regtest(Default::default())).into_extension();
    let enabled: Vec<&'static str> = Primary::METHOD_NAMES
        .iter()
        .copied()
        .chain(extension.method_names().collect::<Vec<_>>())
        .collect();
    RpcService::new(
        ExtendedMethods::new(Primary, extension),
        enabled,
        usize::MAX,
    )
}

async fn call_text(
    service: &RpcService<ExtendedMethods<Primary>>,
    method: &str,
    params: Value,
) -> String {
    let body = json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).to_string();
    let response = handle_rpc_call(body.as_bytes(), true, service, 100, usize::MAX).await;
    response.as_json().get().to_owned()
}

async fn call(
    service: &RpcService<ExtendedMethods<Primary>>,
    method: &str,
    params: Value,
) -> Value {
    serde_json::from_str(&call_text(service, method, params).await).expect("responses are JSON")
}

fn mock() -> RpcService<ExtendedMethods<Primary>> {
    service(Arc::new(MockVaultState::new(NoChainTip)))
}

fn hex_display(id: &kogany_vault::SetId) -> String {
    kogany_rpc::json::display_hex(id)
}

#[tokio::test]
async fn both_method_sets_answer_and_unknown_is_method_not_found() {
    let s = mock();
    assert_eq!(call(&s, "getinfo", json!([])).await["result"], "primary");
    assert_eq!(
        call(&s, "vault_getinfo", json!([])).await["result"]["branchid"],
        "6d5b7a31"
    );
    let unknown = call(&s, "vault_nosuchmethod", json!([])).await;
    assert_eq!(unknown["error"]["code"], -32601);
    // A wallet RPC of ycashd that kogany does not serve (K-3).
    assert_eq!(
        call(&s, "vault_lock", json!([{}])).await["error"]["code"],
        -32601
    );
}

#[tokio::test]
async fn vault_getinfo_mock_and_unavailable() {
    let text = call_text(&mock(), "vault_getinfo", json!([])).await;
    let r: Value = serde_json::from_str(&text).unwrap();
    let info = &r["result"];
    assert_eq!(info["activationheight"], -1);
    assert_eq!(info["active"], false);
    assert_eq!(info["height"], -1);
    assert_eq!(info["attestorsetid"], Value::Null);
    assert_eq!(info["moduleactive"], false);
    assert_eq!(
        (
            info["sets"].clone(),
            info["vaults"].clone(),
            info["intents"].clone()
        ),
        (json!(2), json!(1), json!(1))
    );
    assert!(text.contains("\"lockedvalue\":5.00000000"), "{text}");
    assert_eq!(info["statehash"], "5e".repeat(32));

    let none = service(Arc::new(UnavailableVaultState::new(NoChainTip)));
    let r = call(&none, "vault_getinfo", json!([])).await;
    let keys: Vec<_> = r["result"].as_object().unwrap().keys().cloned().collect();
    let mut expected = vec![
        "active",
        "activationheight",
        "attestorsetid",
        "branchid",
        "dbtip",
        "height",
        "moduleactive",
    ];
    expected.sort();
    let mut keys = keys;
    keys.sort();
    assert_eq!(keys, expected);
    assert_eq!(r["result"]["dbtip"], Value::Null);
    for (method, params) in [
        ("set_list", json!([])),
        ("vault_list", json!([])),
        ("set_getinfo", json!(["00".repeat(32)])),
    ] {
        let e = call(&none, method, params).await;
        assert_eq!(e["error"]["code"], -32603, "{method}");
        assert_eq!(
            e["error"]["message"], "the vault database is not available",
            "{method}"
        );
    }
}

#[tokio::test]
async fn set_reads() {
    let s = mock();
    let text = call_text(&s, "set_list", json!([])).await;
    let r: Value = serde_json::from_str(&text).unwrap();
    let sets = r["result"].as_array().unwrap();
    assert_eq!(sets.len(), 2);
    assert!(sets.iter().all(|s| s.get("memberlist").is_none()));
    assert!(sets[0].get("unlockavailable").is_none());
    assert!(text.contains("\"bondmin\":0.50000000"), "{text}");
    assert!(text.contains("\"unlockavailable\":0.00000000"), "{text}");
    // ycashd's field order.
    let first = serde_json::to_string(&sets[0]).unwrap();
    assert!(first.starts_with("{\""), "{first}");

    let a = hex_display(&Fixture::SET_A);
    // Positional and named parameters, as for RpcServer's methods.
    for params in [
        json!([a]),
        json!({"setid": a}),
        json!([a, null]),
        json!([a, 300]),
    ] {
        let r = call(&s, "set_getinfo", params.clone()).await;
        let info = &r["result"];
        assert_eq!(info["setid"], a, "{params}");
        let members = info["memberlist"].as_array().unwrap();
        assert_eq!(members.len(), 2);
        assert!(members[0].get("exitheight").is_none());
        assert_eq!(members[1]["exitheight"], 212);
        assert_eq!(members[1]["unlockheight"], 214);
        assert!(members.iter().all(|m| m.get("wallet").is_none()));
    }
    assert_eq!(
        call(&s, "set_getinfo", json!([a, 300])).await["result"]["height"],
        300
    );
    assert_eq!(
        call(&s, "set_getinfo", json!([a])).await["result"]["height"],
        0
    );

    let unknown = call(&s, "set_getinfo", json!(["00".repeat(32)])).await;
    assert_eq!(unknown["error"]["code"], -5);
    assert!(unknown["error"]["message"]
        .as_str()
        .unwrap()
        .contains("unknown set"));
    assert_eq!(
        call(&s, "set_getinfo", json!(["zz"])).await["error"]["code"],
        -8
    );
    assert_eq!(
        call(&s, "set_getinfo", json!([a, -1])).await["error"]["code"],
        -8
    );
    // A missing required parameter is invalid params (the server's middleware makes it -1).
    assert_eq!(
        call(&s, "set_getinfo", json!([])).await["error"]["code"],
        -32602
    );
    assert_eq!(
        call(&s, "set_getinfo", json!({})).await["error"]["code"],
        -32602
    );
    assert_eq!(
        call(&s, "set_getinfo", json!([1])).await["error"]["code"],
        -32602
    );
}

#[tokio::test]
async fn vault_list_filters() {
    let s = mock();
    let all = call(&s, "vault_list", json!([])).await;
    let all = all["result"].as_array().unwrap();
    assert_eq!(all.len(), 2);
    assert_eq!(all[0]["kind"], "vault");
    assert_eq!(all[1]["kind"], "intent");
    assert_eq!(all[1]["matureheight"], 214);
    assert_eq!(all[1]["origin"], all[0]["script"]);
    assert!(all.iter().all(|o| o.get("wallet").is_none()));

    let count = |r: Value| r["result"].as_array().map(Vec::len);
    assert_eq!(
        count(call(&s, "vault_list", json!([{"kind": "vault"}])).await),
        Some(1)
    );
    assert_eq!(
        count(call(&s, "vault_list", json!([{"kind": "intent"}])).await),
        Some(1)
    );
    assert_eq!(
        count(call(&s, "vault_list", json!([{"tag": "TEST"}])).await),
        Some(2)
    );
    assert_eq!(
        count(call(&s, "vault_list", json!([{"tag": "54455354"}])).await),
        Some(2)
    );
    assert_eq!(
        count(call(&s, "vault_list", json!([{"tag": "WYEC"}])).await),
        Some(0)
    );
    assert_eq!(
        count(
            call(
                &s,
                "vault_list",
                json!([{"setid": hex_display(&Fixture::SET_A)}])
            )
            .await
        ),
        Some(2)
    );
    assert_eq!(
        count(
            call(
                &s,
                "vault_list",
                json!([{"setid": hex_display(&Fixture::SET_B)}])
            )
            .await
        ),
        Some(0)
    );
    let owner = format!("01{}", "0c".repeat(32));
    assert_eq!(
        count(call(&s, "vault_list", json!([{"owner": owner}])).await),
        Some(2)
    );
    assert_eq!(
        count(call(&s, "vault_list", json!([{"mine": false}])).await),
        Some(2)
    );
    assert_eq!(
        count(call(&s, "vault_list", json!({"filter": {"kind": "vault"}})).await),
        Some(1)
    );

    let e = call(&s, "vault_list", json!([{"kind": "coin"}])).await;
    assert_eq!(
        (e["error"]["code"].clone(), e["error"]["message"].clone()),
        (json!(-8), json!("kind must be vault or intent"))
    );
    let e = call(
        &s,
        "vault_list",
        json!([{"owner": format!("03{}", "11".repeat(32))}]),
    )
    .await;
    assert_eq!(e["error"]["code"], -8);
    assert!(e["error"]["message"]
        .as_str()
        .unwrap()
        .contains("unregistered post-quantum scheme"));
    assert_eq!(
        call(&s, "vault_list", json!([{"mine": true}])).await["error"]["code"],
        -8
    );
}

#[tokio::test]
async fn vault_decodescript_over_rpc() {
    let s = mock();
    let list = call(&s, "vault_list", json!([])).await;
    let script = list["result"][0]["script"].as_str().unwrap().to_owned();
    let d = call(&s, "vault_decodescript", json!([script])).await;
    assert_eq!(d["result"]["type"], "vault");
    assert_eq!(d["result"]["setid"], hex_display(&Fixture::SET_A));
    assert_eq!(
        call(&s, "vault_decodescript", json!(["51"])).await["result"],
        json!({"type": "none"})
    );
    let e = call(&s, "vault_decodescript", json!(["5"])).await;
    assert_eq!(e["error"]["code"], -8);
    assert_eq!(
        e["error"]["message"],
        "hex must be hexadecimal string (not '5')"
    );
}

#[test]
fn every_method_is_classified_and_documented() {
    type D = VaultRpcDispatch<VaultRpcImpl>;
    let names: Vec<_> = D::METHOD_ACCESS.iter().map(|(n, _)| *n).collect();
    assert_eq!(names, <D as RpcMethods>::METHOD_NAMES);
    assert_eq!(
        names,
        [
            "vault_getinfo",
            "set_list",
            "set_getinfo",
            "vault_list",
            "vault_decodescript"
        ]
    );
    assert!(D::METHOD_ACCESS
        .iter()
        .all(|(_, a)| *a == ExtensionAccess::Unauthenticated));
    assert!(D::METHOD_DOCS.iter().all(|(_, doc)| !doc.trim().is_empty()));
    let _ = RpcExtension::none();
    let _ = common::top_keys("{}");
}
