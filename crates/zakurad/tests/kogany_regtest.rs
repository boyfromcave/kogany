//! kogany's own regtest tests (plan docs/plans/kogany/kogany-yellowback-plan.md W4-e; the
//! `kogany-regtest` nextest profile in `.config/nextest.toml`, the `kogany-regtest` leg of
//! `.github/workflows/kogany-tests.yml`).
//!
//! Copyright (c) 2026 The Ycash developers. Distributed under the MIT software license.
//!
//! Each test starts a `koganyd` (the `--features ycash` build) on a Ycash regtest (every Ycash
//! upgrade through Canopy at height 1, Vault at [`VAULT_HEIGHT`]) the way Zakura's acceptance
//! tests do (`common::launch`, `common::config`), mines through `generate` (kogany's regtest checks
//! the Equihash solution shape only, K-16), and drives it over JSON-RPC only:
//!
//! - [`kogany_regtest_vault_activation`]: the upgrade schedule across the activation height
//!   (`getblockchaininfo` `upgrades` / `consensus`, `vault_getinfo.branchid`).
//! - [`kogany_regtest_vault_spend_reorg_restart`]: a set, two members and a vault built from the
//!   pinned `testdata/yellowback/vault_vectors.json` keys, each transaction submitted with
//!   `sendrawtransaction` and mined; the vault's set-signed UNLOCK; `invalidateblock` /
//!   `reconsiderblock` of the block that carries the vault transaction; a restart with the tip,
//!   the blocks and the vault read state unchanged.
//!
//! The set state reaches scripts and the read RPCs with W4-d (the snapshot hook): until
//! `vault_getinfo` answers a `statehash`, `OP_CHECKSETSIG` has no set state and fails closed, so
//! the UNLOCK must be refused, and the state-hash checks are skipped with a message. Once it does,
//! the UNLOCK must be accepted and mined, and `statehash` must follow every block, undo and
//! restart. Each transparent input spends a P2SH(`OP_TRUE`) coinbase output, so no wallet and no
//! transparent signature is involved; the set and act signatures are secp256k1 recoverable
//! signatures by the vector keys (`kogany_vault::act::sign_recoverable`).

#![cfg(feature = "ycash")]
#![allow(clippy::print_stderr, clippy::unwrap_in_result)]

use std::{sync::Arc, time::Duration};

use eyre::{bail, eyre, Result};
use serde_json::Value;
use sha2::{Digest, Sha256};

use kogany_vault::{
    act::{
        act_msg, encode_act, encode_payload, public_key, set_sig_msg, sign_recoverable, Act,
        ActBody, SetCreateBody, SetJoinBody,
    },
    script::Builder,
    template::{
        bond_script_pubkey, build_intent, build_vault, hash160, intent_for, VaultParams,
        ROLE_UNLOCK, SEL_UNLOCK,
    },
    Hash32, OutPoint as VaultOutPoint, PqOwner, PubKeyBytes, Tag,
};
use zakura_chain::{
    amount::{Amount, NonNegative},
    block::{Block, Height},
    parameters::{testnet::ConfiguredActivationHeights, Network, NetworkKind, NetworkUpgrade},
    serialization::{ZcashDeserializeInto, ZcashSerialize},
    transaction::{self, LockTime, Transaction},
    transparent::{Address, Input, OutPoint, Output, Script},
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

/// The Vault activation height of both tests: above coinbase maturity, so the first coinbases
/// are spendable when the upgrade activates.
const VAULT_HEIGHT: u32 = 105;

/// The Vault branch ID, `vault_getinfo.branchid` (ycash6 `NetworkUpgradeInfo[UPGRADE_VAULT]`).
const VAULT_BRANCH_ID_HEX: &str = "6d5b7a31";

/// The fee every test transaction pays (ycash6's relay floor is 1,000 zatoshis at most).
const FEE: i64 = 10_000;

/// One YEC.
const COIN: i64 = 100_000_000;

/// The set's maturity: blocks between a JOIN and the member signing.
const MATURITY: u32 = 3;

/// `OP_TRUE`, the redeem script of every funding coin.
const OP_TRUE: u8 = 0x51;

// ---------------------------------------------------------------------------------------------
// The node

/// A running `koganyd` and its RPC client.
struct Node {
    child: TestChild<tempfile::TempDir>,
    client: RpcRequestClient,
}

/// The Ycash regtest with Vault at [`VAULT_HEIGHT`].
fn ycash_regtest() -> Network {
    Network::new_regtest(
        ConfiguredActivationHeights {
            overwinter: Some(1),
            sapling: Some(1),
            ycash: Some(1),
            blossom: Some(1),
            heartwood: Some(1),
            canopy: Some(1),
            vault: Some(VAULT_HEIGHT),
            ..Default::default()
        }
        .into(),
    )
}

/// P2SH(`OP_TRUE`), the miner address.
fn miner() -> Address {
    Address::from_script_hash(NetworkKind::Regtest, hash160(&[OP_TRUE]))
}

/// `common::config::os_assigned_rpc_port_config` without its Zcash miner address (which does not
/// parse as a Ycash address): the P2P and RPC listeners on OS-assigned localhost ports, the legacy
/// P2P stack, cookie auth off.
fn node_config(net: &Network) -> Result<ZakuradConfig> {
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
    config.mining.miner_address = Some(miner().to_string().parse()?);
    config.state.ephemeral = false;
    // Write the non-finalized state at every block, so a restart restores all of it.
    config.state.debug_skip_non_finalized_state_backup_task = true;
    config.consensus.checkpoint_sync = false;
    Ok(config)
}

async fn spawn(dir: tempfile::TempDir) -> Result<Node> {
    let mut child = dir
        .spawn_child(args!["start"])?
        .with_timeout(EXTENDED_LAUNCH_DELAY);
    let rpc = read_listen_addr_from_logs(&mut child, OPENED_RPC_ENDPOINT_MSG)?;
    child.expect_stdout_line_matches("activating mempool")?;
    let client = RpcRequestClient::new_with_timeout(rpc, Duration::from_secs(120));
    Ok(Node { child, client })
}

impl Node {
    async fn start(net: &Network) -> Result<Node> {
        let mut config = node_config(net)?;
        spawn(testdir()?.with_config(&mut config)?).await
    }

    /// Stops the node through the `stop` RPC, then starts it again on the same state.
    async fn restart(self) -> Result<Node> {
        let _ = self.client.text_from_call("stop", "[]").await;
        let output = self
            .child
            .wait_with_output_or_timeout(Duration::from_secs(120))?;
        let mut output = output;
        let dir = output
            .dir
            .take()
            .ok_or_else(|| eyre!("the state directory is kept"))?;
        tokio::time::sleep(Duration::from_secs(2)).await;
        spawn(dir).await
    }

    fn kill(mut self) -> Result<()> {
        self.child.kill(true)?;
        Ok(())
    }

    /// `method(params)`: the result, or the JSON-RPC error object as `Err`.
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
            .map_err(|e| eyre!("{method}({params}) failed: {e}"))
    }

    async fn height(&self) -> Result<u32> {
        let h = self.ok("getblockcount", "[]").await?;
        Ok(u32::try_from(h.as_u64().ok_or_else(|| eyre!("a height"))?)?)
    }

    async fn best_hash(&self) -> Result<String> {
        str_of(&self.ok("getbestblockhash", "[]").await?)
    }

    async fn generate(&self, n: u32) -> Result<Vec<String>> {
        let hashes = self.ok("generate", &format!("[{n}]")).await?;
        hashes
            .as_array()
            .ok_or_else(|| eyre!("generate answers hashes"))?
            .iter()
            .map(str_of)
            .collect()
    }

    async fn block(&self, hash_or_height: &str) -> Result<Block> {
        let hex_block = self
            .ok("getblock", &format!(r#"["{hash_or_height}", 0]"#))
            .await?;
        Ok(hex::decode(str_of(&hex_block)?)?.zcash_deserialize_into()?)
    }

    /// `sendrawtransaction`: the txid, or the error message.
    async fn send(&self, tx: &Transaction) -> Result<std::result::Result<String, String>> {
        let data = hex::encode(tx.zcash_serialize_to_vec()?);
        Ok(
            match self
                .call("sendrawtransaction", &format!(r#"["{data}"]"#))
                .await?
            {
                Ok(txid) => Ok(str_of(&txid)?),
                Err(e) => Err(e
                    .get("message")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned()),
            },
        )
    }

    /// Sends `txs`, mines one block, and checks it carries every one of them.
    async fn mine_txs(&self, label: &str, txs: &[&Transaction]) -> Result<String> {
        for tx in txs {
            if let Err(message) = self.send(tx).await? {
                bail!(
                    "{label}: sendrawtransaction refused {}: {message}",
                    tx.hash()
                );
            }
        }
        let hash = self
            .generate(1)
            .await?
            .pop()
            .ok_or_else(|| eyre!("one hash"))?;
        let block = self.block(&hash).await?;
        for tx in txs {
            if !block.transactions.iter().any(|t| t.hash() == tx.hash()) {
                bail!("{label}: block {hash} does not carry {}", tx.hash());
            }
        }
        Ok(hash)
    }

    async fn vault_info(&self) -> Result<Value> {
        self.ok("vault_getinfo", "[]").await
    }
}

fn str_of(v: &Value) -> Result<String> {
    v.as_str()
        .map(str::to_owned)
        .ok_or_else(|| eyre!("a string: {v}"))
}

/// `vault_getinfo.statehash`, when kogany serves the set state (W4-d).
fn state_hash(info: &Value) -> Option<String> {
    info.get("statehash")
        .and_then(Value::as_str)
        .map(str::to_owned)
}

// ---------------------------------------------------------------------------------------------
// The pinned vectors

fn vault_vectors() -> Result<Value> {
    let dir =
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata/yellowback");
    let bytes = std::fs::read(dir.join("vault_vectors.json"))?;
    let pin = std::fs::read_to_string(dir.join("PIN"))?;
    let want = pin
        .lines()
        .filter(|line| !line.starts_with('#'))
        .find_map(|line| {
            let mut fields = line.split_whitespace();
            let sha = fields.next()?;
            (fields.next()? == "testdata/yellowback/vault_vectors.json").then(|| sha.to_owned())
        })
        .ok_or_else(|| eyre!("vault_vectors.json is pinned in PIN"))?;
    if hex::encode(Sha256::digest(&bytes)) != want {
        bail!("vault_vectors.json differs from its PIN");
    }
    Ok(serde_json::from_slice(&bytes)?)
}

/// The secret of the vector key labelled `label`.
fn vector_secret(vectors: &Value, label: &str) -> Result<[u8; 32]> {
    let key = vectors["keys"]
        .as_array()
        .ok_or_else(|| eyre!("keys"))?
        .iter()
        .find(|k| k["label"] == label)
        .ok_or_else(|| eyre!("no vector key {label}"))?;
    let secret: [u8; 32] = hex::decode(str_of(&key["secret"])?)?
        .try_into()
        .map_err(|_| eyre!("a 32-byte secret"))?;
    // The vector's pubkey is the secret's: the keys are the C++ lines' keys.
    let pubkey = public_key(&secret).ok_or_else(|| eyre!("a valid secret"))?;
    if hex::encode(pubkey.0) != str_of(&key["pubkey"])? {
        bail!("vector key {label}: the public key does not match the secret");
    }
    Ok(secret)
}

/// The vectors' SLH-DSA owner (scheme byte, then the 32-byte key hash).
fn vector_owner(vectors: &Value) -> Result<PqOwner> {
    let owner = &vectors["pqOwner"]["owner"];
    let hash = hex::decode(str_of(&owner["hash"])?)?;
    Ok(PqOwner {
        scheme: u8::try_from(owner["scheme"].as_u64().ok_or_else(|| eyre!("a scheme"))?)?,
        hash: Hash32::from_slice(&hash).ok_or_else(|| eyre!("a 32-byte owner hash"))?,
    })
}

// ---------------------------------------------------------------------------------------------
// Transactions

/// The funding coins: the miner's coinbase outputs at `heights`.
async fn coinbase_coin(node: &Node, height: u32) -> Result<(OutPoint, i64)> {
    let block = node.block(&height.to_string()).await?;
    let coinbase = block
        .transactions
        .first()
        .ok_or_else(|| eyre!("a coinbase"))?;
    let script = miner().script();
    let (index, output) = coinbase
        .outputs()
        .iter()
        .enumerate()
        .find(|(_, o)| o.lock_script == script)
        .ok_or_else(|| eyre!("the coinbase at {height} pays the miner"))?;
    Ok((
        OutPoint {
            hash: coinbase.hash(),
            index: u32::try_from(index)?,
        },
        i64::from(output.value()),
    ))
}

fn amount(zat: i64) -> Result<Amount<NonNegative>> {
    Ok(Amount::try_from(zat)?)
}

fn output(zat: i64, script: &[u8]) -> Result<Output> {
    Ok(Output::new(amount(zat)?, Script::new(script)))
}

/// An input spending a P2SH(`OP_TRUE`) coin.
fn op_true_input(outpoint: OutPoint) -> Input {
    Input::PrevOut {
        outpoint,
        unlock_script: Script::new(&[0x01, OP_TRUE]),
        sequence: u32::MAX,
    }
}

fn v4(inputs: Vec<Input>, outputs: Vec<Output>) -> Transaction {
    Transaction::V4 {
        inputs,
        outputs,
        lock_time: LockTime::unlocked(),
        expiry_height: Height(0),
        joinsplit_data: None,
        sapling_shielded_data: None,
    }
}

fn vault_outpoint(outpoint: &OutPoint) -> VaultOutPoint {
    VaultOutPoint {
        txid: Hash32(outpoint.hash.0),
        n: outpoint.index,
    }
}

/// An act transaction: `vin[0]` the coin, `outputs_before` (a JOIN's bond), the YV output with
/// one signature per secret over `actMsg(P, vin[0].prevout)`, then the change.
fn act_tx(
    coin: (OutPoint, i64),
    body: ActBody,
    signers: &[[u8; 32]],
    outputs_before: Vec<Output>,
) -> Result<Transaction> {
    let payload = encode_payload(&body);
    let msg = act_msg(&payload, &vault_outpoint(&coin.0));
    let sigs = signers
        .iter()
        .map(|s| sign_recoverable(s, &msg).ok_or_else(|| eyre!("a signature")))
        .collect::<Result<Vec<_>>>()?;
    let spent: i64 = outputs_before.iter().map(|o| i64::from(o.value())).sum();
    let mut outputs = outputs_before;
    outputs.push(output(0, &encode_act(&Act { body, sigs }))?);
    outputs.push(output(
        coin.1 - spent - FEE,
        miner().script().as_raw_bytes(),
    )?);
    Ok(v4(vec![op_true_input(coin.0)], outputs))
}

/// The UNLOCK of the vault at `vault` (value `value`, script `v_spk`): one intent paying the
/// whole value to `recipient`, the fee from `fee_coin`, `vin[0]` signed by `signers` for role 1.
fn unlock_tx(
    vault: OutPoint,
    value: i64,
    v_spk: &[u8],
    vp: &VaultParams,
    recipient: &[u8],
    fee_coin: (OutPoint, i64),
    signers: &[[u8; 32]],
) -> Result<Transaction> {
    let intent =
        build_intent(&intent_for(vp, v_spk, recipient)).ok_or_else(|| eyre!("a valid intent"))?;
    let inputs = vec![
        Input::PrevOut {
            outpoint: vault,
            unlock_script: Script::new(&[]),
            sequence: u32::MAX,
        },
        op_true_input(fee_coin.0),
    ];
    let outputs = vec![
        output(value, &intent)?,
        output(fee_coin.1 - FEE, miner().script().as_raw_bytes())?,
    ];
    let unsigned = v4(inputs, outputs);
    // The set signature signs SIGHASH_ALL | ANYONECANPAY over the V's script and value under the
    // Vault branch ID (ycash6 SetSigChecker::CheckSetSigs; vault_sighash.rs replays the vectors).
    let previous = vec![
        Output::new(amount(value)?, Script::new(v_spk)),
        Output::new(amount(fee_coin.1)?, miner().script()),
    ];
    let sighash: [u8; 32] = unsigned
        .sighasher(NetworkUpgrade::Vault, Arc::new(previous))?
        .sighash_v4_raw(0x81, Some((0, v_spk.to_vec())))
        .into();
    let msg = set_sig_msg(
        &vp.set_id,
        ROLE_UNLOCK,
        &vault_outpoint(&vault),
        &Hash32(sighash),
    );
    let mut script_sig = Builder::new();
    for secret in signers {
        let sig = sign_recoverable(secret, &msg).ok_or_else(|| eyre!("a set signature"))?;
        script_sig = script_sig.push(&sig.0);
    }
    let script_sig = script_sig.num(i64::from(SEL_UNLOCK)).into_bytes();
    let Transaction::V4 {
        mut inputs,
        outputs,
        lock_time,
        expiry_height,
        ..
    } = unsigned
    else {
        bail!("a v4 transaction");
    };
    if let Some(Input::PrevOut { unlock_script, .. }) = inputs.first_mut() {
        *unlock_script = Script::new(&script_sig);
    }
    Ok(Transaction::V4 {
        inputs,
        outputs,
        lock_time,
        expiry_height,
        joinsplit_data: None,
        sapling_shielded_data: None,
    })
}

fn txid_of(tx: &Transaction) -> transaction::Hash {
    tx.hash()
}

// ---------------------------------------------------------------------------------------------
// The tests

/// The `upgrades` entry of `branch` in `getblockchaininfo`.
fn upgrade_status(info: &Value, branch: &str) -> Result<(u64, String)> {
    let u = &info["upgrades"][branch];
    Ok((
        u["activationheight"]
            .as_u64()
            .ok_or_else(|| eyre!("{branch}: an activation height: {info}"))?,
        str_of(&u["status"])?,
    ))
}

/// Vault activates at its configured height on a running koganyd.
#[tokio::test(flavor = "multi_thread")]
async fn kogany_regtest_vault_activation() -> Result<()> {
    let _init_guard = zakura_test::init();
    let net = ycash_regtest();
    let node = Node::start(&net).await?;

    node.generate(VAULT_HEIGHT - 2).await?;
    assert_eq!(node.height().await?, VAULT_HEIGHT - 2);
    let info = node.ok("getblockchaininfo", "[]").await?;
    assert_eq!(
        upgrade_status(&info, VAULT_BRANCH_ID_HEX)?,
        (u64::from(VAULT_HEIGHT), "pending".to_owned()),
        "Vault is scheduled, not active, two blocks below it"
    );
    assert_eq!(
        info["consensus"]["chaintip"], "19bd2d2f",
        "Ycash Canopy rules the tip"
    );
    assert_eq!(info["consensus"]["nextblock"], "19bd2d2f");

    node.generate(1).await?;
    let info = node.ok("getblockchaininfo", "[]").await?;
    assert_eq!(info["consensus"]["chaintip"], "19bd2d2f");
    assert_eq!(
        info["consensus"]["nextblock"], VAULT_BRANCH_ID_HEX,
        "the next block is the activation block"
    );

    node.generate(1).await?;
    assert_eq!(node.height().await?, VAULT_HEIGHT);
    let info = node.ok("getblockchaininfo", "[]").await?;
    assert_eq!(
        upgrade_status(&info, VAULT_BRANCH_ID_HEX)?,
        (u64::from(VAULT_HEIGHT), "active".to_owned())
    );
    assert_eq!(info["consensus"]["chaintip"], VAULT_BRANCH_ID_HEX);
    assert_eq!(info["consensus"]["nextblock"], VAULT_BRANCH_ID_HEX);
    for branch in [
        "5ba81b19", "76b809bb", "374d694f", "8e471bd6", "66314da3", "19bd2d2f",
    ] {
        assert_eq!(
            upgrade_status(&info, branch)?,
            (1, "active".to_owned()),
            "{branch} at 1"
        );
    }

    let vault = node.vault_info().await?;
    assert_eq!(vault["branchid"], VAULT_BRANCH_ID_HEX);
    assert_eq!(vault["height"], u64::from(VAULT_HEIGHT));
    if vault["activationheight"] != u64::from(VAULT_HEIGHT) {
        // W7-a's prototype answers the upgrade fields from a fixed table; the live parameters
        // arrive with the read RPCs' state (recorded for the coordinator).
        eprintln!(
            "PENDING (W7): vault_getinfo upgrade fields are not the live parameters: {vault}"
        );
    }

    // The activation block and every block after it are mined under the Vault rules: a block
    // past activation is accepted and the tip keeps advancing.
    node.generate(2).await?;
    assert_eq!(node.height().await?, VAULT_HEIGHT + 2);

    node.kill()
}

/// The vault lifecycle on a running koganyd: set, members, lock, set-signed UNLOCK, undo by
/// `invalidateblock`, redo by `reconsiderblock`, restart.
#[tokio::test(flavor = "multi_thread")]
async fn kogany_regtest_vault_spend_reorg_restart() -> Result<()> {
    let _init_guard = zakura_test::init();
    let net = ycash_regtest();
    let vectors = vault_vectors()?;
    let admit = vector_secret(&vectors, "admit")?;
    let members = [
        vector_secret(&vectors, "member-0")?,
        vector_secret(&vectors, "member-1")?,
    ];
    let owner = vector_owner(&vectors)?;

    let mut node = Node::start(&net).await?;
    node.generate(VAULT_HEIGHT).await?;
    assert_eq!(node.height().await?, VAULT_HEIGHT);
    let info0 = node.vault_info().await?;
    let served = state_hash(&info0).is_some();
    if !served {
        eprintln!(
            "PENDING (W4-d): vault_getinfo serves no statehash; the set state is not live, so the \
             UNLOCK must fail closed and the state-hash checks are skipped: {info0}"
        );
    }
    let mut hashes = vec![state_hash(&info0)];

    // SET_CREATE: no signatures; the set id is the act transaction's txid (internal order).
    let create = act_tx(
        coinbase_coin(&node, 1).await?,
        ActBody::Create(SetCreateBody {
            seats: 3,
            unlock_threshold: 2,
            cancel_threshold: 1,
            slash_threshold: 2,
            flags: 0,
            rate_limit_bps: 0,
            rate_window: 1000,
            liveness_window: 1000,
            bond_min: COIN,
            bond_lock_min: 20,
            maturity: MATURITY,
            admit_key: public_key(&admit).ok_or_else(|| eyre!("admit key"))?,
        }),
        &[],
        Vec::new(),
    )?;
    node.mine_txs("SET_CREATE", &[&create]).await?;
    let set_id = Hash32(txid_of(&create).0);
    hashes.push(state_hash(&node.vault_info().await?));

    // SET_JOIN of two members: the bond at vout 0, signed by the joiner and the admit key.
    let bond_locktime = node.height().await? + 1 + 20 + 30;
    let mut joins = Vec::new();
    for (i, member) in members.iter().enumerate() {
        let member_key: PubKeyBytes = public_key(member).ok_or_else(|| eyre!("member key"))?;
        let bond =
            bond_script_pubkey(bond_locktime, &member_key).ok_or_else(|| eyre!("a bond script"))?;
        joins.push(act_tx(
            coinbase_coin(&node, 2 + u32::try_from(i)?).await?,
            ActBody::Join(SetJoinBody {
                set_id,
                member_key,
                bond_locktime,
                bond_vout: 0,
            }),
            &[*member, admit],
            vec![output(COIN, &bond)?],
        )?);
    }
    node.mine_txs("SET_JOIN", &joins.iter().collect::<Vec<_>>())
        .await?;
    node.generate(MATURITY).await?;
    hashes.push(state_hash(&node.vault_info().await?));

    // The lock: the whole coin less the fee in one V.
    let (lock_coin, lock_coin_value) = coinbase_coin(&node, 4).await?;
    let vp = VaultParams {
        tag: Tag(*b"TEST"),
        set_id,
        cancel_set_id: set_id,
        delay: 5,
        owner_height: i64::from(node.height().await? + 500),
        app_height: 0,
        owner,
    };
    let v_spk = build_vault(&vp).ok_or_else(|| eyre!("a valid vault"))?;
    let vault_value = lock_coin_value - FEE;
    let lock = v4(
        vec![op_true_input(lock_coin)],
        vec![output(vault_value, &v_spk)?],
    );
    let lock_block = node.mine_txs("lock", &[&lock]).await?;
    let lock_height = node.height().await?;
    let after_lock = node.vault_info().await?;
    if served {
        assert_eq!(
            after_lock["vaults"], 1,
            "one vault after the lock: {after_lock}"
        );
        assert_ne!(Some(state_hash(&after_lock)), hashes.last().cloned());
    }
    hashes.push(state_hash(&after_lock));

    // The set-signed UNLOCK of the vault into one intent.
    let vault = OutPoint {
        hash: txid_of(&lock),
        index: 0,
    };
    let recipient = miner().script().as_raw_bytes().to_vec();
    let unlock = unlock_tx(
        vault,
        vault_value,
        &v_spk,
        &vp,
        &recipient,
        coinbase_coin(&node, 5).await?,
        &members,
    )?;
    let spend_block = match node.send(&unlock).await? {
        Ok(_) if served => {
            let hash = node
                .generate(1)
                .await?
                .pop()
                .ok_or_else(|| eyre!("a hash"))?;
            let block = node.block(&hash).await?;
            assert!(
                block.transactions.iter().any(|t| t.hash() == unlock.hash()),
                "the UNLOCK is mined"
            );
            let after = node.vault_info().await?;
            assert_eq!(after["vaults"], 0, "the vault is spent: {after}");
            assert_eq!(after["intents"], 1, "into one intent: {after}");
            hashes.push(state_hash(&after));
            Some(hash)
        }
        Ok(txid) => {
            return Err(eyre!(
                "the UNLOCK {txid} was accepted while kogany serves no set state: OP_CHECKSETSIG \
                 must fail closed before W4-d"
            ))
        }
        Err(message) if served => {
            return Err(eyre!(
                "the UNLOCK was refused with the set state live: {message}"
            ))
        }
        Err(message) => {
            assert!(
                message.contains("script"),
                "before W4-d the UNLOCK fails in script verification: {message}"
            );
            eprintln!("PENDING (W4-d): the UNLOCK fails closed without the set state: {message}");
            None
        }
    };

    // Undo: invalidate the block with the vault transaction (the UNLOCK's when it was mined,
    // else the lock's), and check the tip and the set state return to its parent's.
    let (undo_block, undo_height, before_undo) = match &spend_block {
        Some(hash) => (
            hash.clone(),
            lock_height + 1,
            hashes[hashes.len() - 2].clone(),
        ),
        None => (
            lock_block.clone(),
            lock_height,
            hashes[hashes.len() - 2].clone(),
        ),
    };
    let tip_before = node.best_hash().await?;
    let state_before = state_hash(&node.vault_info().await?);
    let parent = node.block(&undo_block).await?.header.previous_block_hash;
    node.ok("invalidateblock", &format!(r#"["{undo_block}"]"#))
        .await?;
    wait_for(&node, |h| h == parent.to_string()).await?;
    assert_eq!(node.height().await?, undo_height - 1);
    if served {
        assert_eq!(
            state_hash(&node.vault_info().await?),
            before_undo,
            "invalidateblock restores the parent's set state"
        );
    }
    // Redo.
    node.ok("reconsiderblock", &format!(r#"["{undo_block}"]"#))
        .await?;
    wait_for(&node, |h| h == tip_before).await?;
    assert_eq!(state_hash(&node.vault_info().await?), state_before);

    // Two more blocks, then the restart: the same tip, blocks and set state.
    node.generate(2).await?;
    let tip = node.best_hash().await?;
    let height = node.height().await?;
    let info_before = node.vault_info().await?;
    let lock_block_data = node.block(&lock_block).await?;
    node = node.restart().await?;
    assert_eq!(node.best_hash().await?, tip, "the restart keeps the tip");
    assert_eq!(node.height().await?, height);
    assert_eq!(
        node.block(&lock_block).await?.hash(),
        lock_block_data.hash(),
        "the lock block is kept"
    );
    let info_after = node.vault_info().await?;
    assert_eq!(state_hash(&info_after), state_hash(&info_before));
    for key in [
        "dbtip",
        "sets",
        "vaults",
        "intents",
        "lockedvalue",
        "branchid",
    ] {
        assert_eq!(
            info_after.get(key),
            info_before.get(key),
            "vault_getinfo.{key}"
        );
    }
    // The node mines on after the restart.
    node.generate(1).await?;
    assert_eq!(node.height().await?, height + 1);

    node.kill()
}

/// Waits until `getbestblockhash` satisfies `done`.
async fn wait_for(node: &Node, done: impl Fn(&str) -> bool) -> Result<()> {
    for _ in 0..300 {
        if done(&node.best_hash().await?) {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    Err(eyre!(
        "the tip did not reach the expected block: {}",
        node.best_hash().await?
    ))
}
