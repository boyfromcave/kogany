//! `vault_decodescript` over the pinned cross-line vectors (`testdata/yellowback/vault_vectors.json`,
//! byte-identical to ycash6's; never modified here).

use kogany_rpc::vault::decode_script;
mod common;

use serde_json::Value;
use zakura_chain::parameters::Network;

fn vectors() -> Value {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../testdata/yellowback/vault_vectors.json"
    );
    serde_json::from_str(&std::fs::read_to_string(path).expect("the pinned vectors are present"))
        .expect("the pinned vectors are JSON")
}

fn decode(script_hex: &str) -> Value {
    let script = hex::decode(script_hex).expect("vector scripts are hex");
    serde_json::to_value(decode_script(
        &script,
        &Network::new_regtest(Default::default()),
    ))
    .expect("decoded scripts serialize")
}

/// A display-order id from a vector's internal-order hex.
fn display(internal: &Value) -> String {
    let mut b = hex::decode(internal.as_str().expect("ids are strings")).expect("ids are hex");
    b.reverse();
    hex::encode(b)
}

fn pqkeyid(owner: &Value) -> String {
    format!(
        "{:02x}{}",
        owner["scheme"].as_u64().expect("schemes are numbers"),
        owner["hash"].as_str().expect("hashes are strings")
    )
}

fn list<'a>(v: &'a Value, key: &str) -> &'a Vec<Value> {
    v[key].as_array().expect("vector lists are arrays")
}

#[test]
fn vaults_decode_with_their_fields() {
    let v = vectors();
    for case in list(&v, "vaults") {
        let d = decode(case["script"].as_str().unwrap());
        let p = &case["params"];
        let script = hex::decode(case["script"].as_str().unwrap()).unwrap();
        let text = serde_json::to_string(&decode_script(
            &script,
            &Network::new_regtest(Default::default()),
        ))
        .unwrap();
        let keys = common::top_keys(&text);
        assert_eq!(
            keys,
            [
                "type",
                "tag",
                "tagtext",
                "setid",
                "cancelsetid",
                "delay",
                "ownerheight",
                "appheight",
                "owner",
                "ownerscheme"
            ],
            "{}",
            case["name"]
        );
        assert_eq!(d["type"], "vault", "{}", case["name"]);
        assert_eq!(d["tag"], p["tag"]);
        assert_eq!(d["setid"], display(&p["setId"]));
        assert_eq!(d["cancelsetid"], display(&p["cancelSetId"]));
        assert_eq!(d["delay"], p["delay"]);
        assert_eq!(d["ownerheight"], p["ownerHeight"]);
        assert_eq!(d["appheight"], p["appHeight"]);
        assert_eq!(d["owner"], pqkeyid(&p["owner"]));
        assert_eq!(d["ownerscheme"], p["owner"]["scheme"]);
    }
}

#[test]
fn intents_decode_with_their_fields() {
    let v = vectors();
    for case in list(&v, "intents") {
        let d = decode(case["script"].as_str().unwrap());
        let p = &case["params"];
        assert_eq!(d["type"], "intent", "{}", case["name"]);
        assert_eq!(d["tag"], p["tag"]);
        assert_eq!(d["setid"], display(&p["setId"]));
        assert_eq!(d["cancelsetid"], display(&p["cancelSetId"]));
        assert_eq!(d["delay"], p["delay"]);
        assert_eq!(d["owner"], pqkeyid(&p["owner"]));
        assert_eq!(d["recipienthash"], p["recipientHash"]);
        assert_eq!(d["vaulthash"], p["vaultHash"]);
    }
}

#[test]
fn invalid_templates_do_not_decode_as_their_template() {
    let v = vectors();
    for (key, template) in [("vaultsInvalid", "vault"), ("intentsInvalid", "intent")] {
        for case in list(&v, key) {
            let d = decode(case["script"].as_str().unwrap());
            let ty = d["type"].as_str().unwrap();
            assert_ne!(ty, template, "{}", case["name"]);
            assert!(
                ["malformed", "none", "vault", "intent"].contains(&ty),
                "{}: {ty}",
                case["name"]
            );
        }
    }
}

#[test]
fn bonds_decode_with_their_p2sh() {
    let v = vectors();
    for case in list(&v, "bonds") {
        let d = decode(case["redeem"].as_str().unwrap());
        assert_eq!(d["type"], "bond");
        assert_eq!(d["locktime"], case["locktime"]);
        assert_eq!(d["memberkey"], case["memberKey"]);
        assert_eq!(d["scriptpubkey"], case["spk"]);
        // Regtest P2SH addresses: Zcash regtest's `t2…`, or with the `ycash` feature Ycash
        // regtest's `s2…`.
        let prefix = if cfg!(feature = "ycash") { "s2" } else { "t2" };
        assert!(d["address"].as_str().unwrap().starts_with(prefix), "{d}");
    }
}

#[test]
fn acts_decode_with_their_payload_and_signatures() {
    let v = vectors();
    let names = [
        "",
        "create",
        "join",
        "heartbeat",
        "remove",
        "equivocation",
        "winddown",
    ];
    for case in list(&v, "acts") {
        let d = decode(case["script"].as_str().unwrap());
        assert_eq!(d["type"], "act", "{}", case["name"]);
        let ty = usize::try_from(case["type"].as_u64().unwrap()).unwrap();
        assert_eq!(d["acttype"], names[ty], "{}", case["name"]);
        assert_eq!(d["payload"], case["payload"], "{}", case["name"]);
        let sigs: Vec<_> = list(case, "sigs")
            .iter()
            .map(|s| s.as_str().unwrap())
            .collect();
        let decoded: Vec<_> = d["signatures"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| s["sig"].as_str().unwrap())
            .collect();
        assert_eq!(decoded, sigs, "{}", case["name"]);
        assert!(d.get("error").is_none());
    }
}

#[test]
fn undecodable_acts_report_the_reject_reason() {
    let v = vectors();
    for case in list(&v, "actScriptsInvalid") {
        let d = decode(case["script"].as_str().unwrap());
        assert_eq!(d["type"], "act", "{}", case["name"]);
        let error = d["error"].as_str().unwrap();
        assert!(
            error.starts_with("bad-vault-act-"),
            "{}: {error}",
            case["name"]
        );
        assert_eq!(d.as_object().unwrap().len(), 2);
    }
}

#[test]
fn other_scripts_are_none() {
    assert_eq!(decode("51")["type"], "none");
    assert_eq!(
        decode("76a914000000000000000000000000000000000000000088ac"),
        serde_json::json!({"type": "none"})
    );
}
