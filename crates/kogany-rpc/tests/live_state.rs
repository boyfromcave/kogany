//! kogany plan W4-d: the vault read RPCs over the node's real set state (`LiveVaultState`): a
//! state service that committed the ycash6 regtest chain `kogany-vault` recorded answers
//! `vault_getinfo.statehash` equal to ycashd's after the tip, and its counts, `dbtip` and set
//! list agree with the state. A Ycash build only (`--features ycash`): the blocks are Ycash's.
#![cfg(feature = "ycash")]

use std::{path::Path, sync::Arc};

use kogany_rpc::{live::LiveVaultState, vault::VaultRpc, VaultReadState, VaultRpcImpl};
use tower::{Service, ServiceExt};
use zakura_chain::{
    block::{genesis::regtest_genesis_block, Block},
    parameters::{testnet::ConfiguredActivationHeights, Network},
    serialization::ZcashDeserializeInto,
};
use zakura_state as zs;

#[tokio::test(flavor = "multi_thread")]
async fn vault_getinfo_reads_the_live_state() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../kogany-vault/tests/data/ycash6_statehash_vault_rpc.json");
    let doc: serde_json::Value =
        serde_json::from_slice(&std::fs::read(path).expect("the fixture is committed"))
            .expect("the fixture is JSON");
    let activation = doc["vaultActivation"].as_u64().expect("activation") as u32;
    let network = Network::new_regtest(
        ConfiguredActivationHeights {
            overwinter: Some(1),
            sapling: Some(1),
            ycash: Some(1),
            blossom: Some(1),
            heartwood: Some(1),
            canopy: Some(1),
            vault: Some(activation),
            ..Default::default()
        }
        .into(),
    );
    let (mut state, read, _, _) = zs::init_test_services(&network).await;

    let rpc = VaultRpcImpl::new(
        Arc::new(LiveVaultState::new(network.clone(), read.clone())),
        network.clone(),
    );
    let before = rpc.vault_getinfo().await.expect("vault_getinfo answers");
    assert_eq!(before.height, -1, "no block yet");
    assert_eq!(before.activationheight, i64::from(activation));
    assert!(before.dbtip.is_none());

    let blocks = doc["blocks"].as_array().expect("blocks");
    let genesis = regtest_genesis_block();
    let mut all: Vec<Arc<Block>> = vec![genesis];
    for b in blocks {
        let bytes = hex::decode(b["hex"].as_str().expect("hex")).expect("hex decodes");
        all.push(Arc::new(
            bytes.zcash_deserialize_into().expect("block parses"),
        ));
    }
    // The checkpoint write path (the total transition in `prepare_block_batch`).
    for block in &all {
        state
            .ready()
            .await
            .expect("the state is ready")
            .call(zs::Request::CommitCheckpointVerifiedBlock(
                zs::CheckpointVerifiedBlock::from(block.clone()),
            ))
            .await
            .expect("the recorded block commits");
    }
    let tip = blocks.len() as i64;
    let want = blocks.last().expect("a tip")["statehash"]
        .as_str()
        .expect("the tip's statehash");

    let info = rpc.vault_getinfo().await.expect("vault_getinfo answers");
    assert_eq!(info.height, tip);
    assert!(info.active, "Vault is active at the next block");
    assert_eq!(info.statehash.as_deref(), Some(want), "ycashd's statehash");
    let dbtip = info.dbtip.as_ref().expect("the state is at the tip");
    assert_eq!(dbtip.height, tip);
    assert_eq!(dbtip.hash, all.last().expect("tip").hash().to_string());

    let snapshot = LiveVaultState::new(network.clone(), read.clone())
        .snapshot()
        .await
        .expect("a snapshot");
    let db = snapshot.db.expect("the database is open");
    assert_eq!(info.sets, Some(db.set_ids().len() as u64));
    assert!(
        info.sets.expect("sets") > 0,
        "the recorded chain creates sets"
    );
    let sets = rpc.set_list().await.expect("set_list answers");
    assert_eq!(sets.len() as u64, info.sets.expect("sets"));
    let outputs = rpc.vault_list(None).await.expect("vault_list answers");
    assert_eq!(
        outputs.len() as u64,
        info.vaults.expect("vaults") + info.intents.expect("intents")
    );
}
