//! Beta2 address-interop plan W4.1: the recorded C++ chains of transactions that mix Sapling
//! spends and outputs with the Vault upgrade's transparent scripts (`testdata/mixed-shapes/`:
//! `chain.json`, recorded by `record.py` on a ycash-dd node with a ycash6 node following, and
//! `chain2.json`, recorded by `record2.py` on a ycash6 wallet node with a ycash-dd node
//! following) go through kogany's full block pipeline: every block, each mixed shape mined alone
//! in its own block, commits; the tip is the C++ tip.
//!
//! The shapes of `chain.json`: Sapling to a TX_PQPKH output (SLH-DSA and FN-DSA-512), a TX_PQPKH
//! input to Sapling (each scheme), Sapling to a vault-lock output, and a Sapling spend and a PQ
//! input together paying a vault lock, a PQ output and Sapling change. `chain2.json` adds the
//! ycash6 wallet's shapes (Sapling to PQ, PQ to Sapling with PQ change, a Sapling-funded
//! `vault_lock`), an FN-DSA-512 input beside a Sapling spend, a Sapling spend and an SLH-DSA
//! input paying a PQ output and PQ change, and a vault unlock whose fee a Sapling spend pays.
//!
//! A Ycash build only (`--features ycash`): the recorded blocks are Ycash regtest blocks.
//!
//! Copyright (c) 2026 The Ycash developers. Distributed under the MIT software license.
#![cfg(feature = "ycash")]

use std::{path::Path, sync::Arc, time::Duration};

use tower::{Service, ServiceExt};
use zakura_chain::{
    block::{self, genesis::regtest_genesis_block, Block},
    parameters::{
        testnet::{ConfiguredActivationHeights, RegtestParameters},
        Network,
    },
    serialization::ZcashDeserializeInto,
};
use zakura_consensus::{router, Config, Request as BlockRequest};
use zakura_node_services::mempool;
use zakura_state as zs;

type BoxError = Box<dyn std::error::Error + Send + Sync + 'static>;
type Mempool = tower::util::BoxCloneService<mempool::Request, mempool::Response, BoxError>;

fn fixture(file: &str) -> serde_json::Value {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata/mixed-shapes")
        .join(file);
    serde_json::from_slice(&std::fs::read(path).expect("the fixture is committed"))
        .expect("the fixture is JSON")
}

/// The recording's regtest: every upgrade through Canopy at 1, Vault and Falcon as recorded.
fn network(doc: &serde_json::Value) -> Network {
    let height = |key: &str| Some(doc[key].as_u64().expect("a height") as u32);
    Network::new_regtest(RegtestParameters::from(ConfiguredActivationHeights {
        overwinter: Some(1),
        sapling: Some(1),
        ycash: Some(1),
        blossom: Some(1),
        heartwood: Some(1),
        canopy: Some(1),
        vault: height("vaultActivation"),
        pq_falcon: height("pqFalconHeight"),
        ..Default::default()
    }))
}

#[tokio::test(flavor = "multi_thread")]
async fn mixed_shape_chain_commits_through_the_pipeline() {
    let _init_guard = zakura_test::init();
    commits_through_the_pipeline("chain.json", 6).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn mixed_shape_chain2_commits_through_the_pipeline() {
    let _init_guard = zakura_test::init();
    commits_through_the_pipeline("chain2.json", 8).await;
}

async fn commits_through_the_pipeline(file: &str, expected_shapes: usize) {
    let doc = fixture(file);
    let network = network(&doc);
    let blocks: Vec<Arc<Block>> = doc["blocks"]
        .as_array()
        .expect("blocks")
        .iter()
        .map(|b| {
            let bytes = hex::decode(b.as_str().expect("block hex")).expect("hex decodes");
            Arc::new(bytes.zcash_deserialize_into().expect("the block parses"))
        })
        .collect();

    // Every shape is in the block the recording says, alone beside the coinbase.
    let shapes = doc["shapes"].as_object().expect("shapes");
    assert_eq!(shapes.len(), expected_shapes, "{file}: the mixed shapes");
    for (name, shape) in shapes {
        let height = shape["height"].as_u64().expect("a height") as usize;
        let block = &blocks[height - 1];
        assert_eq!(block.transactions.len(), 2, "{name} is mined alone");
        assert_eq!(
            block.transactions[1].hash().to_string(),
            shape["txid"].as_str().expect("a txid"),
            "{name}"
        );
        assert!(
            block.transactions[1].has_sapling_shielded_data(),
            "{name} carries Sapling parts"
        );
    }

    let max_checkpoint_height = network.checkpoint_list().max_height();
    let (state, _read, _tip, _change) =
        zs::init(zs::Config::ephemeral(), &network, max_checkpoint_height, 10)
            .await
            .expect("the state opens");
    let state = tower::buffer::Buffer::new(state, 10);
    let (router, _tx, _handles, _) = router::init(
        Config::default(),
        &network,
        state.clone(),
        tokio::sync::oneshot::channel::<Mempool>().1,
    )
    .await;
    let mut router = router;

    for (i, block) in std::iter::once(regtest_genesis_block())
        .chain(blocks.iter().cloned())
        .enumerate()
    {
        let hash = block.hash();
        let committed: block::Hash = tokio::time::timeout(
            Duration::from_secs(120),
            router
                .ready()
                .await
                .expect("the router is ready")
                .call(BlockRequest::Commit(block)),
        )
        .await
        .expect("the block commits in time")
        .unwrap_or_else(|e| panic!("block {i} ({hash}) is accepted: {e:?}"));
        assert_eq!(committed, hash);
    }
}
