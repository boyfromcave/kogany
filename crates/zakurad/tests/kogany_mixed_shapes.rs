//! Beta2 address-interop plan W4.1, W4.3: a running `koganyd` relays and mines the C++-built
//! transactions that mix Sapling spends and outputs with TX_PQPKH inputs and outputs and a
//! vault-lock output (`testdata/mixed-shapes/chain.json`, recorded by `record.py` there on a
//! ycash-dd node with a ycash6 node following).
//!
//! The node takes the recorded chain up to the first shape through `submitblock`; then, in the
//! recorded order, each shape goes to its mempool through `sendrawtransaction` (with
//! standardness on), and `generate` mines a block of kogany's own template that must carry it.
//! Each shape was mined alone in the recording, so kogany's blocks grow the same Sapling tree and
//! the later shapes' anchors stay valid on kogany's chain.
//!
//! For each TX_PQPKH output it also reads what the node's RPCs say about its address (plan W4.3)
//! and asserts the answers that do not depend on the address encoding: `getrawtransaction`'s
//! verbose `scriptPubKey` is the recorded script, of type `pqpubkeyhash`, with one address, and
//! `getaddressutxos` on that address finds the coin (txid, output index, value, kogany's height).
//! The address text itself, next to ycash-dd's recorded one, and `decoderawtransaction` (which
//! koganyd does not have) are printed, not asserted: the D-9 prefixes change every recorded
//! address.
//!
//! Copyright (c) 2026 The Ycash developers. Distributed under the MIT software license.

#![cfg(feature = "ycash")]
#![allow(clippy::print_stderr, clippy::unwrap_in_result)]

use std::{path::Path, time::Duration};

use eyre::{bail, eyre, Result};
use serde_json::Value;

use zakura_chain::{
    parameters::{
        testnet::{ConfiguredActivationHeights, RegtestParameters},
        Network, NetworkKind,
    },
    transparent::Address,
};
use zakura_node_services::rpc_client::RpcRequestClient;
use zakura_rpc::server::OPENED_RPC_ENDPOINT_MSG;
use zakura_test::{args, command::TestChild};
use zakurad::config::ZakuradConfig;

mod common;

use common::{
    config::{read_listen_addr_from_logs, testdir},
    launch::{ZakuradTestDirExt, EXTENDED_LAUNCH_DELAY},
};

fn fixture() -> Result<Value> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/mixed-shapes/chain.json");
    Ok(serde_json::from_slice(&std::fs::read(path)?)?)
}

fn u32_of(v: &Value) -> Result<u32> {
    Ok(u32::try_from(
        v.as_u64().ok_or_else(|| eyre!("an integer: {v}"))?,
    )?)
}

fn str_of(v: &Value) -> Result<String> {
    v.as_str()
        .map(str::to_owned)
        .ok_or_else(|| eyre!("a string: {v}"))
}

/// The recording's regtest: every upgrade through Canopy at 1, Vault and Falcon as recorded.
fn network(doc: &Value) -> Result<Network> {
    Ok(Network::new_regtest(RegtestParameters::from(
        ConfiguredActivationHeights {
            overwinter: Some(1),
            sapling: Some(1),
            ycash: Some(1),
            blossom: Some(1),
            heartwood: Some(1),
            canopy: Some(1),
            vault: Some(u32_of(&doc["vaultActivation"])?),
            pq_falcon: Some(u32_of(&doc["pqFalconHeight"])?),
            ..Default::default()
        },
    )))
}

struct Node {
    child: TestChild<tempfile::TempDir>,
    client: RpcRequestClient,
}

impl Node {
    /// `kogany_regtest.rs`'s node: OS-assigned ports, the legacy P2P stack, cookie auth off, a
    /// P2SH miner address, the mempool on from height 0, standardness on.
    async fn start(net: &Network) -> Result<Node> {
        let mut config = ZakuradConfig {
            network: zakura_network::Config {
                network: net.clone(),
                listen_addr: "127.0.0.1:0".parse()?,
                p2p_stack: zakura_network::P2pStack::Legacy,
                ..zakura_network::Config::default()
            },
            ..ZakuradConfig::default()
        };
        config.rpc.listen_addr = Some("127.0.0.1:0".parse()?);
        config.rpc.parallel_cpu_threads = 1;
        config.rpc.enable_cookie_auth = false;
        config.mempool.debug_enable_at_height = Some(0);
        config.mempool.accept_non_standard = Some(false);
        config.mining.miner_address = Some(
            Address::from_script_hash(NetworkKind::Regtest, [0x42; 20])
                .to_string()
                .parse()?,
        );
        config.consensus.checkpoint_sync = false;
        let mut child = testdir()?
            .with_config(&mut config)?
            .spawn_child(args!["start"])?
            .with_timeout(EXTENDED_LAUNCH_DELAY);
        let rpc = read_listen_addr_from_logs(&mut child, OPENED_RPC_ENDPOINT_MSG)?;
        child.expect_stdout_line_matches("activating mempool")?;
        let client = RpcRequestClient::new_with_timeout(rpc, Duration::from_secs(120));
        Ok(Node { child, client })
    }

    async fn call(&self, method: &str, params: &str) -> Result<std::result::Result<Value, Value>> {
        let text = self
            .client
            .text_from_call(method, params)
            .await
            .map_err(|e| eyre!("{method}: {e}"))?;
        let response: Value =
            serde_json::from_str(&text).map_err(|e| eyre!("{method}: not JSON ({e}): {text}"))?;
        match response.get("error") {
            Some(error) if !error.is_null() => Ok(Err(error.clone())),
            _ => Ok(Ok(response.get("result").cloned().unwrap_or(Value::Null))),
        }
    }

    async fn ok(&self, method: &str, params: &str) -> Result<Value> {
        self.call(method, params)
            .await?
            .map_err(|e| eyre!("{method} failed: {e}"))
    }

    async fn height(&self) -> Result<u32> {
        u32_of(&self.ok("getblockcount", "[]").await?)
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn kogany_relays_and_mines_the_mixed_shapes() -> Result<()> {
    let _init_guard = zakura_test::init();
    let doc = fixture()?;
    let net = network(&doc)?;
    let node = Node::start(&net).await?;

    let setup_tip = u32_of(&doc["setupTip"])?;
    let blocks = doc["blocks"]
        .as_array()
        .ok_or_else(|| eyre!("blocks"))?
        .iter()
        .map(str_of)
        .collect::<Result<Vec<_>>>()?;
    for (i, block) in blocks.iter().take(setup_tip as usize).enumerate() {
        let answer = node.ok("submitblock", &format!(r#"["{block}"]"#)).await?;
        if !answer.is_null() {
            bail!("submitblock of block {} answered {answer}", i + 1);
        }
    }
    for _ in 0..600 {
        if node.height().await? == setup_tip {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(node.height().await?, setup_tip, "the recorded setup chain");

    let mut shapes: Vec<(String, Value)> = doc["shapes"]
        .as_object()
        .ok_or_else(|| eyre!("shapes"))?
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    shapes.sort_by_key(|(_, s)| s["height"].as_u64());
    assert_eq!(shapes.len(), 6, "six mixed shapes");

    for (name, shape) in &shapes {
        let txid = str_of(&shape["txid"])?;
        // kogany mines its own blocks from here, so the bytes come from the recording.
        let raw = raw_from_recording(&doc, &txid)?;

        match node
            .call("sendrawtransaction", &format!(r#"["{raw}"]"#))
            .await?
        {
            Ok(answer) => assert_eq!(str_of(&answer)?, txid, "{name}"),
            Err(e) => {
                return Err(eyre!(
                    "{name}: kogany's mempool refused the C++-built transaction: {e}"
                ))
            }
        }
        let mempool = node.ok("getrawmempool", "[]").await?;
        assert!(
            mempool
                .as_array()
                .is_some_and(|m| m.iter().any(|t| t.as_str() == Some(&txid))),
            "{name} is in kogany's mempool"
        );
        let template = node.ok("getblocktemplate", "[]").await?;
        assert!(
            template["transactions"]
                .as_array()
                .is_some_and(|t| t.iter().any(|t| t["hash"].as_str() == Some(&txid))),
            "{name} is in kogany's block template"
        );
        let mined = node.ok("generate", "[1]").await?;
        let hash = str_of(&mined[0])?;
        let block = node.ok("getblock", &format!(r#"["{hash}", 1]"#)).await?;
        assert!(
            block["tx"]
                .as_array()
                .is_some_and(|t| t.iter().any(|t| t.as_str() == Some(&txid))),
            "{name}: kogany's block {hash} carries it"
        );
        eprintln!("{name}: accepted, templated and mined by kogany in {hash}");

        for out in shape["pqOutputs"].as_array().into_iter().flatten() {
            let n = out["n"].as_u64().ok_or_else(|| eyre!("n"))? as usize;
            let verbose = node
                .call("getrawtransaction", &format!(r#"["{txid}", 1]"#))
                .await?;
            let decoded = node
                .call("decoderawtransaction", &format!(r#"["{raw}"]"#))
                .await?;
            let address = out["address"].as_str().unwrap_or_default();
            let utxos = node
                .call(
                    "getaddressutxos",
                    &format!(r#"[{{"addresses": ["{address}"]}}]"#),
                )
                .await?;
            let addresses = |v: &std::result::Result<Value, Value>| match v {
                Ok(v) => v["vout"][n]["scriptPubKey"].clone(),
                Err(e) => e.clone(),
            };

            // W4.3, asserted: the verbose script, its type and its one address, and the index.
            let recorded = &out["addressUtxos"][0];
            let spk = addresses(&verbose);
            assert_eq!(spk["type"], "pqpubkeyhash", "{name} vout {n}: {spk}");
            assert_eq!(spk["hex"], recorded["script"], "{name} vout {n}: {spk}");
            let kogany_address = match spk["addresses"].as_array().map(Vec::as_slice) {
                Some([one]) => str_of(one)?,
                _ => return Err(eyre!("{name} vout {n}: one address expected in {spk}")),
            };
            let height = block["height"].clone();
            let found = node
                .ok(
                    "getaddressutxos",
                    &format!(r#"[{{"addresses": ["{kogany_address}"]}}]"#),
                )
                .await?;
            assert!(
                found.as_array().is_some_and(|rows| rows.iter().any(|row| {
                    row["txid"].as_str() == Some(&txid)
                        && row["outputIndex"] == out["n"]
                        && row["satoshis"] == recorded["satoshis"]
                        && row["height"] == height
                        && row["script"] == recorded["script"]
                })),
                "{name} vout {n}: getaddressutxos {kogany_address} finds the coin: {found}"
            );
            eprintln!(
                "W4.3 {name} vout {n}: ycash-dd type {} address {address}\n  \
                 kogany getrawtransaction: {}\n  kogany decoderawtransaction: {}\n  \
                 kogany getaddressutxos: {}",
                out["type"],
                addresses(&verbose),
                addresses(&decoded),
                utxos.unwrap_or_else(|e| e),
            );
        }
    }
    let mut child = node.child;
    child.kill(true)?;
    Ok(())
}

/// The recorded transaction `txid`'s bytes (hex), from the block the recording mined it in.
fn raw_from_recording(doc: &Value, txid: &str) -> Result<String> {
    use zakura_chain::{block::Block, serialization::ZcashDeserializeInto};
    let height = doc["shapes"]
        .as_object()
        .and_then(|s| s.values().find(|s| s["txid"] == txid))
        .ok_or_else(|| eyre!("{txid} is a shape"))?["height"]
        .as_u64()
        .ok_or_else(|| eyre!("a height"))? as usize;
    let block: Block =
        hex::decode(str_of(&doc["blocks"][height - 1])?)?.zcash_deserialize_into()?;
    let tx = block
        .transactions
        .iter()
        .find(|t| t.hash().to_string() == txid)
        .ok_or_else(|| eyre!("{txid} is in block {height}"))?;
    use zakura_chain::serialization::ZcashSerialize;
    Ok(hex::encode(tx.zcash_serialize_to_vec()?))
}
