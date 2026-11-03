//! The `yed_*` RPCs through zakura-rpc's `RpcService`: not live (`-32601`, the lightwalletd-dd
//! probe), the mock fixture's shapes and errors, the M8 health allow-list, the wallet refusals
//! and the access classes.

use std::{future::Future, pin::Pin, sync::Arc};

use kogany_rpc::yed::{
    self,
    mock::{MockYedState, UnavailableYedState, GOLDEN_STATE_HASH, GOLDEN_TIP_HASH, VAULTS},
    rpc::NOT_LIVE_MESSAGE,
    YedReadState, YedRpcDispatch, YedWalletRefusalDispatch, WALLET_METHODS, YED_RPC_VERSION,
};
use serde_json::{json, Value};
use zakura_chain::{chain_tip::NoChainTip, parameters::Network};
use zakura_rpc::server::{
    jsonrpc::{Id, MethodResponse, Params},
    kogany_extension::{ExtendedMethods, ExtensionAccess},
    rpc_service::{handle_rpc_call, RpcMethods, RpcService},
};

/// A stand-in for `RpcServer`'s methods.
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

type Service = RpcService<ExtendedMethods<Primary>>;

fn service(state: Arc<dyn YedReadState>) -> Service {
    let extension = yed::extension(state, &Network::new_regtest(Default::default()));
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

async fn call_text(s: &Service, method: &str, params: Value) -> String {
    let body = json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).to_string();
    let response = handle_rpc_call(body.as_bytes(), true, s, 100, usize::MAX).await;
    response.as_json().get().to_owned()
}

async fn call(s: &Service, method: &str, params: Value) -> Value {
    serde_json::from_str(&call_text(s, method, params).await).expect("responses are JSON")
}

fn mock() -> Service {
    service(Arc::new(MockYedState::new(NoChainTip)))
}

fn display(h: &kogany_vault::Hash32) -> String {
    kogany_rpc::json::display_hex(h)
}

/// Every read and node-state method with arguments the mock answers.
fn reads() -> Vec<(&'static str, Value)> {
    let v0 = display(&VAULTS[0]);
    let v1 = display(&VAULTS[1]);
    let v2 = display(&VAULTS[2]);
    vec![
        ("yed_getinfo", json!([])),
        ("yed_getstatehash", json!([])),
        ("yed_verifyindex", json!([])),
        ("yed_getstats", json!([])),
        ("yed_getprice", json!([])),
        ("yed_getactivation", json!([])),
        ("yed_listminers", json!([])),
        ("yed_gettag", json!(["440"])),
        ("yed_getfeepayee", json!([438])),
        ("yed_getvault", json!([v2])),
        ("yed_listvaults", json!([])),
        ("yed_listtokens", json!([["yrExample"]])),
        ("yed_listclaimable", json!([])),
        ("yed_gettxinfo", json!([v0])),
        ("yed_decodepayload", json!(["00"])),
        ("yed_validaterawtransaction", json!(["00"])),
        ("yed_getblockverdict", json!([GOLDEN_TIP_HASH])),
        ("yed_estimatecollateral", json!([100000, 48])),
        ("yed_estimatefee", json!([100000])),
        ("yed_gethistory", json!([430, 440])),
        ("yed_listattestors", json!([])),
        ("yed_getattestations", json!([])),
        ("yed_buildbundle", json!([438, ""])),
        ("yed_getselection", json!([438, ""])),
        ("yed_getnotice", json!([v1])),
        ("yed_setquote", json!([2000000, 3])),
        ("yed_addattestation", json!(["00"])),
    ]
}

#[test]
fn twenty_seven_node_methods_verifychain_and_twenty_five_wallet_refusals() {
    let names = <YedRpcDispatch<yed::YedRpcImpl> as RpcMethods>::METHOD_NAMES;
    assert_eq!(names.len(), 28);
    assert!(names.contains(&"verifychain"));
    assert_eq!(reads().len(), 27);
    for (name, _) in reads() {
        assert!(names.contains(&name), "{name}");
    }
    assert_eq!(WALLET_METHODS.len(), 25);
    for (name, access) in YedRpcDispatch::<yed::YedRpcImpl>::METHOD_ACCESS {
        let admin = matches!(*name, "yed_setquote" | "yed_addattestation");
        assert_eq!(
            *access,
            if admin {
                ExtensionAccess::Admin
            } else {
                ExtensionAccess::Unauthenticated
            },
            "{name}"
        );
    }
    let docs = YedWalletRefusalDispatch::<yed::YedWalletRefusalImpl>::METHOD_DOCS;
    assert!(docs.iter().all(|(_, d)| d.contains("served by yewd")));
}

#[tokio::test]
async fn not_live_is_method_not_found_for_every_yed_method() {
    let s = service(Arc::new(UnavailableYedState));
    assert_eq!(call(&s, "getinfo", json!([])).await["result"], "primary");
    // ycashd's verifychain has nothing YED to re-check when Yellowback is not live.
    assert_eq!(
        call(&s, "verifychain", json!([4, 20])).await["result"],
        true
    );
    for (method, params) in reads() {
        let r = call(&s, method, params).await;
        assert_eq!(r["error"]["code"], -32601, "{method}: {r}");
        assert_eq!(r["error"]["message"], NOT_LIVE_MESSAGE, "{method}");
    }
    // lightwalletd-dd's ProbeYellowback splits the rendered error at the first ':' and compares
    // the code with "-32601" (common/yellowback.go).
    let r = call(&s, "yed_getinfo", json!([])).await;
    let rendered = format!("{}: {}", r["error"]["code"], r["error"]["message"]);
    assert_eq!(rendered.split(':').next().map(str::trim), Some("-32601"));
}

#[tokio::test]
async fn wallet_methods_are_refused_with_method_not_found() {
    for state in [
        Arc::new(UnavailableYedState) as Arc<dyn YedReadState>,
        Arc::new(MockYedState::new(NoChainTip)),
    ] {
        let s = service(state);
        for method in WALLET_METHODS {
            for params in [json!([]), json!([1, "x", {"a": 1}])] {
                let r = call(&s, method, params).await;
                assert_eq!(r["error"]["code"], -32601, "{method}");
                let m = r["error"]["message"].as_str().unwrap();
                assert!(
                    m.starts_with("Method not found (") && m.contains(method),
                    "{m}"
                );
            }
        }
    }
}

#[tokio::test]
async fn every_method_answers_from_the_mock() {
    let s = mock();
    for (method, params) in reads() {
        let r = call(&s, method, params.clone()).await;
        if method == "yed_addattestation" {
            // Not 74 bytes.
            assert_eq!(r["error"]["code"], -8, "{r}");
            assert!(r["error"]["message"]
                .as_str()
                .unwrap()
                .starts_with("attest-malformed"));
            continue;
        }
        if method == "yed_validaterawtransaction" {
            assert_eq!(r["error"]["code"], -22, "{r}");
            assert_eq!(r["error"]["message"], "TX decode failed");
            continue;
        }
        if method == "yed_listtokens" {
            assert_eq!(r["error"]["code"], -5, "{r}");
            assert!(r["error"]["message"]
                .as_str()
                .unwrap()
                .starts_with("invalid-address: "));
            continue;
        }
        assert!(r.get("error").is_none(), "{method} {params}: {r}");
    }
}

#[tokio::test]
async fn getinfo_is_rpcversion_8_at_the_golden_tip() {
    let s = mock();
    let info = call(&s, "yed_getinfo", json!([])).await["result"].clone();
    assert_eq!(info["rpcversion"], YED_RPC_VERSION);
    assert_eq!(info["rpcversion"], 8);
    assert_eq!(info["enabled"], true);
    assert_eq!(info["network"], "regtest");
    assert_eq!(info["height"], 440);
    assert_eq!(info["blockhash"], GOLDEN_TIP_HASH);
    assert_eq!(info["upgrade"]["branchId"], "6d5b7a31");
    assert_eq!(info["upgrade"]["status"], "active");
    assert_eq!(info["lockedOutputs"], 0);
    assert_eq!(info["protectedByIndex"], false);
    let p = &info["params"];
    assert_eq!(p["addressVersion"], "2002");
    assert_eq!(p["pqAddressVersion"], "5710");
    assert_eq!(p["pq"]["plainAddressVersion"], "4c51");
    assert_eq!(p["pq"]["falconHeight"], 400);
    assert_eq!(p["pq"]["schemes"], json!([1, 2]));
    assert_eq!(p["fees"]["protocol"]["bands"][2]["uptoCents"], Value::Null);
    assert_eq!(p["attest"]["mintPayloadVersion"], 4);
    assert_eq!(p["classes"].as_array().map(Vec::len), Some(3));
    // ycashd's field order: rpcversion first, params last.
    let keys: Vec<&String> = info.as_object().unwrap().keys().collect();
    assert_eq!(keys.first().map(|k| k.as_str()), Some("rpcversion"));
    assert_eq!(keys.last().map(|k| k.as_str()), Some("params"));

    let h = call(&s, "yed_getstatehash", json!([])).await["result"].clone();
    assert_eq!(h["statehash"], GOLDEN_STATE_HASH);
    let wrong = call(&s, "yed_getstatehash", json!([7])).await;
    assert_eq!(wrong["error"]["message"], "index is at height 440, not 7");
}

#[tokio::test]
async fn unhealthy_index_refuses_all_but_the_allow_list() {
    let s = service(Arc::new(MockYedState::unhealthy(NoChainTip)));
    let allowed = [
        "yed_getinfo",
        "yed_verifyindex",
        "yed_getactivation",
        "yed_gettag",
        "yed_setquote",
        "yed_decodepayload",
        "yed_getblockverdict",
    ];
    for (method, params) in reads() {
        let r = call(&s, method, params).await;
        let refused = r["error"]["message"]
            .as_str()
            .is_some_and(|m| m.starts_with("yellowback-unhealthy: "));
        if allowed.contains(&method) {
            assert!(!refused, "{method}: {r}");
        } else if !matches!(
            method,
            "yed_addattestation" | "yed_validaterawtransaction" | "yed_listtokens"
        ) {
            // (Those three refuse their malformed argument before the health check, as ycashd.)
            assert!(refused, "{method}: {r}");
            assert_eq!(r["error"]["code"], -26, "{method}");
        }
    }
    let info = call(&s, "yed_getinfo", json!([])).await["result"].clone();
    assert_eq!(info["healthy"], false);
    assert!(!info["unhealthyReason"].as_str().unwrap().is_empty());
}

#[tokio::test]
async fn documented_errors_from_the_mock() {
    let s = mock();
    let unknown = "00".repeat(32);
    let cases = [
        ("yed_getvault", json!([unknown]), -8, "vault-not-found: "),
        ("yed_getnotice", json!([unknown]), -8, "vault-not-found: "),
        ("yed_gettxinfo", json!([unknown]), -8, "tx-not-found: "),
        ("yed_listtokens", json!([[]]), -8, "too-many-addresses: "),
        (
            "yed_listtokens",
            json!([["nonsense"]]),
            -5,
            "invalid-address: ",
        ),
        (
            "yed_estimatecollateral",
            json!([100000, 1]),
            -8,
            "mint-bad-lock: ",
        ),
        ("yed_setquote", json!([1, 0]), -8, "quote-out-of-range: "),
        (
            "yed_addattestation",
            json!(["00"]),
            -8,
            "attest-malformed: ",
        ),
        ("yed_listvaults", json!(["OPEN"]), -8, "status must be"),
        (
            "yed_listminers",
            json!([440, 5000]),
            -8,
            "window must be at most 4032",
        ),
        ("yed_gethistory", json!([0, 441]), -8, "range must satisfy"),
        (
            "yed_buildbundle",
            json!([438, "00"]),
            -8,
            "selectorHex must be empty",
        ),
        ("yed_gettag", json!(["99999"]), -8, "height out of range"),
        (
            "yed_gettag",
            json!(["ab".repeat(32)]),
            -8,
            "block not found",
        ),
        (
            "yed_getblockverdict",
            json!(["11".repeat(32)]),
            -8,
            "block not found",
        ),
        (
            "yed_estimatefee",
            json!([1, 1]),
            -8,
            "priceMicroUsd must be between",
        ),
    ];
    for (method, params, code, prefix) in cases {
        let r = call(&s, method, params.clone()).await;
        assert_eq!(r["error"]["code"], code, "{method} {params}: {r}");
        let m = r["error"]["message"].as_str().unwrap();
        assert!(m.starts_with(prefix), "{method}: {m}");
    }
}

#[tokio::test]
async fn attestation_pool_round_trip() {
    let s = mock();
    let pool = call(&s, "yed_getattestations", json!([])).await["result"].clone();
    let rows = pool.as_array().unwrap();
    assert_eq!(rows.len(), 3);
    let hex = rows[0]["hex"].as_str().unwrap().to_owned();
    assert_eq!(hex.len(), 148);
    let again = call(&s, "yed_addattestation", json!([hex])).await["result"].clone();
    assert_eq!(
        (again["accepted"].clone(), again["replaced"].clone()),
        (json!(true), json!(false))
    );
    assert_eq!(again["poolSize"], 3);

    let mut bytes = hex::decode(&hex).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    let bad = call(&s, "yed_addattestation", json!([hex::encode(&bytes)])).await;
    assert!(bad["error"]["message"]
        .as_str()
        .unwrap()
        .starts_with("attest-bad-sig: "));
    assert_eq!(bad["error"]["code"], -26);

    for (seq, id) in [
        (999u16, "attest-unknown-seq: "),
        (4, "attest-not-eligible: "),
    ] {
        let a = yed::state::Attestation {
            seq,
            price_micro_usd: 1_985_000,
            cited_height: 437,
            sig: MockYedState::<NoChainTip>::mock_signature(seq, 437),
        };
        let r = call(&s, "yed_addattestation", json!([hex::encode(a.encode())])).await;
        assert!(
            r["error"]["message"].as_str().unwrap().starts_with(id),
            "{r}"
        );
    }
    let stale = yed::state::Attestation {
        seq: 1,
        price_micro_usd: 1_985_000,
        cited_height: 420,
        sig: MockYedState::<NoChainTip>::mock_signature(1, 420),
    };
    let r = call(
        &s,
        "yed_addattestation",
        json!([hex::encode(stale.encode())]),
    )
    .await;
    assert!(
        r["error"]["message"]
            .as_str()
            .unwrap()
            .starts_with("attest-stale: "),
        "{r}"
    );

    let fresh = yed::state::Attestation {
        seq: 2,
        price_micro_usd: 1_990_000,
        cited_height: 437,
        sig: MockYedState::<NoChainTip>::mock_signature(2, 437),
    };
    let r = call(
        &s,
        "yed_addattestation",
        json!([hex::encode(fresh.encode())]),
    )
    .await["result"]
        .clone();
    assert_eq!(r["replaced"], true, "{r}");

    let bundle = call(&s, "yed_buildbundle", json!([438, ""])).await["result"].clone();
    assert_eq!(bundle["count"], 2);
    assert!(bundle["hex"].as_str().unwrap().starts_with("59410102"));
    let decoded = call(&s, "yed_decodepayload", json!(["6a"])).await["result"].clone();
    assert_eq!(decoded["valid"], false);
}

#[tokio::test]
async fn setquote_then_getinfo_reports_the_quote() {
    let s = mock();
    let r = call(&s, "yed_setquote", json!([2000000, 3])).await["result"].clone();
    assert_eq!(r["nextTag"]["kind"], "quote");
    assert!(r["receivedAt"].as_i64().unwrap() > 1_700_000_000);
    let info = call(&s, "yed_getinfo", json!([])).await["result"].clone();
    assert_eq!(info["miner"]["quoteKind"], "quote");
    let cleared = call(&s, "yed_setquote", json!([0, 0])).await["result"].clone();
    assert_eq!(cleared["nextTag"]["kind"], "none");
}

#[tokio::test]
async fn vault_rows_carry_their_optional_fields_only_in_their_state() {
    let s = mock();
    let all = call(&s, "yed_listvaults", json!([])).await["result"].clone();
    let rows = all.as_array().unwrap();
    assert_eq!(rows.len(), 3);
    assert!(rows.iter().all(|r| r.get("spendPending").is_none()));
    assert!(rows[0].get("intents").is_none() && rows[0].get("refundHolder").is_none());
    assert_eq!(rows[1]["noticed"], true);
    assert_eq!(rows[2]["status"], "CLAIMING");
    assert_eq!(rows[2]["intents"][0]["role"], "claimant");
    assert!(rows[2]["refundHolder"].is_string());
    assert!(rows[0]["ownerAddress"].as_str().unwrap().len() == 53);
    let text = call_text(&s, "yed_listvaults", json!([])).await;
    assert!(text.contains("\"collateral\":2518.89169000"), "{text}");
    let claiming = call(&s, "yed_listvaults", json!(["CLAIMING", 10, 0])).await["result"].clone();
    assert_eq!(claiming.as_array().map(Vec::len), Some(1));
    let v = call(&s, "yed_getvault", json!([display(&VAULTS[0])])).await["result"].clone();
    assert_eq!(v["spendPending"], false);
    assert!(v.get("spendTxid").is_none());
    let notice = call(&s, "yed_getnotice", json!([display(&VAULTS[0])])).await["result"].clone();
    assert_eq!(notice, json!({"found": false}));
}

#[tokio::test]
async fn listtokens_takes_every_address_form() {
    let s = mock();
    let info = call(&s, "yed_getinfo", json!([])).await["result"].clone();
    assert_eq!(info["network"], "regtest");
    // The fixture's P2PKH holder, in its YED form; then its transparent twin.
    let params = kogany_rpc::yed::mock::golden_params();
    let yed_addr = kogany_yellowback::codecs::address::encode_address(&[0x33; 20], &params);
    let r = call(&s, "yed_listtokens", json!([[yed_addr]])).await["result"].clone();
    let rows = r.as_array().unwrap();
    assert_eq!(rows.len(), 1, "{r}");
    let twin = rows[0]["transparentAddress"].as_str().unwrap().to_owned();
    assert_eq!(rows[0]["address"], yed_addr);
    let r2 = call(&s, "yed_listtokens", json!([[twin]])).await["result"].clone();
    assert_eq!(r2, r);
    // The post-quantum holder, by its YED form and its plain-YEC (rq…) form.
    let owner = kogany_vault::PqOwner {
        scheme: 2,
        hash: kogany_vault::Hash32([0x44; 32]),
    };
    let pq = kogany_yellowback::codecs::address::encode_pq_address(&owner, &params).unwrap();
    let r3 = call(&s, "yed_listtokens", json!([[pq]])).await["result"].clone();
    let rows3 = r3.as_array().unwrap();
    assert_eq!(rows3.len(), 1, "{r3}");
    let plain = rows3[0]["transparentAddress"].as_str().unwrap().to_owned();
    assert!(plain.starts_with("rq"), "{plain}");
    assert_eq!(
        call(&s, "yed_listtokens", json!([[plain]])).await["result"],
        r3
    );
    // minHeight and paging.
    let both = json!([[yed_addr, pq], 0, 1, 1]);
    assert_eq!(call(&s, "yed_listtokens", both).await["result"], r3);
}
