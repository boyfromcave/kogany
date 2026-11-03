//! kogany's Vault heights, in the shape of ycash6's `qa/yellowback-vault-params.py extract`
//! (audit leg (d), kogany plan W2-d).
//!
//! ```sh
//! cargo run -p zakura-chain --features ycash --example kogany_vault_params > kogany.json
//! python3 qa/kogany_vault_params.py compare kogany.json ycash6.json
//! ```
//!
//! Prints the keys kogany defines: `main`, `regtest`, `test.fast` and `test.slow`, each with
//! `vault_activation_height` (a height, or `"NO_ACTIVATION_HEIGHT"` as ycashd spells
//! `Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT`). ycash6's `test.legacy` profile has no kogany
//! counterpart (decision K-10), and the protocol version, Falcon height, set maturity and YED
//! columns are other chunks' (W1-Y5, W3, W4, W5). Only a `ycash` build has Ycash networks, so a
//! Zcash build exits 2.

// An extractor's output is its purpose.
#![allow(clippy::print_stdout, clippy::print_stderr)]

#[cfg(feature = "ycash")]
fn main() {
    use serde_json::{json, Map, Value};
    use zakura_chain::parameters::Network;

    fn height(network: &Network) -> Value {
        network
            .vault_activation_height()
            .map_or_else(|| json!("NO_ACTIVATION_HEIGHT"), |height| json!(height.0))
    }
    fn entry(network: &Network) -> Value {
        let mut fields = Map::new();
        fields.insert("vault_activation_height".to_owned(), height(network));
        Value::Object(fields)
    }

    // Keys in sorted order, as `json.dumps(sort_keys=True)` prints them, whatever map type
    // serde_json is built with.
    let mut test = Map::new();
    test.insert("fast".to_owned(), entry(&Network::new_default_testnet()));
    test.insert("slow".to_owned(), entry(&Network::new_ycash_testnet_slow()));
    let mut doc = Map::new();
    doc.insert("main".to_owned(), entry(&Network::Mainnet));
    doc.insert(
        "regtest".to_owned(),
        entry(&Network::new_regtest(Default::default())),
    );
    doc.insert("test".to_owned(), Value::Object(test));

    println!(
        "{}",
        serde_json::to_string_pretty(&Value::Object(doc)).expect("a JSON value serializes")
    );
}

#[cfg(not(feature = "ycash"))]
fn main() {
    eprintln!(
        "kogany_vault_params: build with `--features ycash`: a Zcash build has no Ycash networks"
    );
    std::process::exit(2);
}
