//! kogany plan W4-d: chains of vault acts through the full pipeline (block verifier, script
//! checks reading the parent's set state, contextual `check::vault`, the non-finalized overlay,
//! the finalized write path), a reorg across the acts, and a restart, replayed over the two
//! ycash6 regtest chains `kogany-vault` recorded (`crates/kogany-vault/tests/data/`): the
//! `statehash` after every block must be ycashd's `vault_getinfo.statehash`.
//!
//! A Ycash build only (`--features ycash`): the recorded blocks are Ycash regtest blocks.
#![cfg(feature = "ycash")]

use std::{path::Path, sync::Arc, time::Duration};

use tempfile::TempDir;
use tower::{
    util::{BoxCloneService, BoxService},
    Service, ServiceExt,
};
use zakura_chain::{
    block::{self, genesis::regtest_genesis_block, Block, Height},
    parameters::{
        testnet::{ConfiguredActivationHeights, ConfiguredCheckpoints, RegtestParameters},
        Network,
    },
    serialization::ZcashDeserializeInto,
};
use zakura_consensus::{router, Config, Request as BlockRequest};
use zakura_node_services::mempool;
use zakura_state as zs;

type BoxError = Box<dyn std::error::Error + Send + Sync + 'static>;
type Mempool = BoxCloneService<mempool::Request, mempool::Response, BoxError>;

/// One recorded block and ycashd's `vault_getinfo.statehash` after it (display order), recorded
/// from just below the Vault activation.
struct Recorded {
    block: Arc<Block>,
    statehash: Option<String>,
}

struct Fixture {
    vault_activation: u32,
    blocks: Vec<Recorded>,
}

impl Fixture {
    fn load(name: &str) -> Fixture {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../kogany-vault/tests/data")
            .join(name);
        let doc: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).expect("the fixture is committed"))
                .expect("the fixture is JSON");
        assert_eq!(doc["minSetMaturity"], 2, "regtest's set maturity");
        let blocks = doc["blocks"]
            .as_array()
            .expect("blocks")
            .iter()
            .enumerate()
            .map(|(i, b)| {
                assert_eq!(
                    b["height"].as_u64(),
                    Some(i as u64 + 1),
                    "blocks from height 1"
                );
                let bytes = hex::decode(b["hex"].as_str().expect("hex")).expect("hex decodes");
                Recorded {
                    block: Arc::new(bytes.zcash_deserialize_into().expect("block parses")),
                    statehash: b["statehash"].as_str().map(str::to_owned),
                }
            })
            .collect();
        Fixture {
            vault_activation: doc["vaultActivation"].as_u64().expect("activation") as u32,
            blocks,
        }
    }

    /// The recorded state hash after `height`; below the Vault activation, where ycashd's set
    /// state is empty and the recording has none, the empty state's.
    fn statehash_at(&self, height: u32) -> String {
        let recorded = height
            .checked_sub(1)
            .and_then(|i| self.blocks[i as usize].statehash.clone());
        match recorded {
            Some(hash) => hash,
            None => {
                assert!(
                    height < self.vault_activation,
                    "recorded from the activation"
                );
                self.empty_statehash()
            }
        }
    }

    /// The state hash of the empty set state: the first recorded one, from below the
    /// activation, where no set exists yet.
    fn empty_statehash(&self) -> String {
        let below = self
            .blocks
            .iter()
            .take(self.vault_activation as usize - 1)
            .find_map(|b| b.statehash.clone())
            .expect("the recording starts below the Vault activation");
        below
    }

    fn hash_at(&self, height: u32) -> block::Hash {
        if height == 0 {
            regtest_genesis_block().hash()
        } else {
            self.blocks[height as usize - 1].block.hash()
        }
    }

    fn tip(&self) -> u32 {
        self.blocks.len() as u32
    }

    /// The harness's regtest (`ycash6 qa`: every upgrade through Canopy at 1, Vault at its
    /// height), with `checkpoints` up to some height when given.
    fn network(&self, checkpoint_to: Option<u32>) -> Network {
        let activation_heights = ConfiguredActivationHeights {
            overwinter: Some(1),
            sapling: Some(1),
            ycash: Some(1),
            blossom: Some(1),
            heartwood: Some(1),
            canopy: Some(1),
            vault: Some(self.vault_activation),
            ..Default::default()
        };
        let checkpoints = checkpoint_to.map(|to| {
            ConfiguredCheckpoints::HeightsAndHashes(
                (0..=to).map(|h| (Height(h), self.hash_at(h))).collect(),
            )
        });
        Network::new_regtest(RegtestParameters {
            activation_heights,
            checkpoints,
            ..Default::default()
        })
    }
}

const FIXTURES: [&str; 2] = [
    "ycash6_statehash_vault_rpc.json",
    "ycash6_statehash_vault_slashing.json",
];

struct Node {
    state: BoxService<zs::Request, zs::Response, BoxError>,
    read: zs::ReadStateService,
    router: tower::buffer::Buffer<
        BlockRequest,
        futures::future::BoxFuture<'static, Result<block::Hash, router::RouterError>>,
    >,
}

async fn start(network: &Network, state_config: zs::Config) -> Node {
    let max_checkpoint_height = network.checkpoint_list().max_height();
    let (state, read, _tip, _change) = zs::init(state_config, network, max_checkpoint_height, 10)
        .await
        .expect("the state opens");
    let state = tower::buffer::Buffer::new(state, 10);
    let (router, _tx, _handles, _) = router::init(
        Config::default(),
        network,
        state.clone(),
        tokio::sync::oneshot::channel::<Mempool>().1,
    )
    .await;
    Node {
        state: BoxService::new(state),
        read,
        router,
    }
}

impl Node {
    async fn statehash(&self) -> (Option<Height>, String) {
        let zs::ReadResponse::VaultSnapshot(Some(snapshot)) = self
            .read
            .clone()
            .oneshot(zs::ReadRequest::BestChainVaultSnapshot)
            .await
            .expect("the read succeeds")
        else {
            panic!("a best-chain vault snapshot always answers Some");
        };
        (
            snapshot.tip.map(|(h, _)| h),
            // display order: the reversed internal bytes, as ycashd's `uint256::GetHex`
            hex::encode(
                snapshot
                    .state_hash()
                    .0
                    .iter()
                    .rev()
                    .copied()
                    .collect::<Vec<u8>>(),
            ),
        )
    }

    async fn commit(&mut self, block: Arc<Block>) {
        let hash = block.hash();
        let committed = tokio::time::timeout(
            Duration::from_secs(120),
            self.router
                .ready()
                .await
                .expect("the router is ready")
                .call(BlockRequest::Commit(block)),
        )
        .await
        .expect("the block commits in time")
        .unwrap_or_else(|e| panic!("block {hash} is accepted: {e:?}"));
        assert_eq!(committed, hash);
    }

    async fn state_call(&mut self, request: zs::Request) -> zs::Response {
        self.state
            .ready()
            .await
            .expect("the state is ready")
            .call(request)
            .await
            .expect("the state request succeeds")
    }

    /// Waits until the best tip is `height` and returns its state hash.
    async fn statehash_when_at(&self, height: u32) -> String {
        for _ in 0..600 {
            let (tip, hash) = self.statehash().await;
            if tip == Some(Height(height)) {
                return hash;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("the best tip never reached {height}");
    }
}

/// Every block through the router; the state hash after each equals ycashd's; then the chain is
/// invalidated block by block down below the Vault activation (a reorg across every act, each
/// step reverting one block's delta) and reconsidered back to the tip.
#[tokio::test(flavor = "multi_thread")]
async fn vault_acts_commit_reorg_and_reconsider_through_the_pipeline() {
    let _init_guard = zakura_test::init();
    for name in FIXTURES {
        let fixture = Fixture::load(name);
        let network = fixture.network(None);
        let mut node = start(&network, zs::Config::ephemeral()).await;

        node.commit(regtest_genesis_block()).await;
        assert_eq!(node.statehash_when_at(0).await, fixture.statehash_at(0));
        for (i, b) in fixture.blocks.iter().enumerate() {
            node.commit(b.block.clone()).await;
            let height = i as u32 + 1;
            assert_eq!(
                node.statehash_when_at(height).await,
                fixture.statehash_at(height),
                "{name}: statehash after block {height}"
            );
        }

        let low = fixture.vault_activation - 2;
        for height in (low + 1..=fixture.tip()).rev() {
            node.state_call(zs::Request::InvalidateBlock(fixture.hash_at(height)))
                .await;
            assert_eq!(
                node.statehash_when_at(height - 1).await,
                fixture.statehash_at(height - 1),
                "{name}: statehash after disconnecting block {height}"
            );
        }
        // Reconsider them back, lowest first: each re-pushes its block.
        for height in low + 1..=fixture.tip() {
            node.state_call(zs::Request::ReconsiderBlock(fixture.hash_at(height)))
                .await;
            assert_eq!(
                node.statehash_when_at(height).await,
                fixture.statehash_at(height),
                "{name}: statehash after reconsidering block {height}"
            );
        }
    }
}

/// A checkpointed prefix reaching into the Vault epoch (finalized through the total transition
/// in the write path), then semantically verified blocks; a restart reopens the finalized vault
/// state and restores the non-finalized blocks from their backup (re-validating them, vault
/// rules included); the state hash at the tip is ycashd's, and the chain grows on after it.
#[test]
fn vault_state_survives_a_restart() {
    let _init_guard = zakura_test::init();
    // Each node run has its own runtime: shutting it down drops the state's background tasks,
    // which hold database handles, so the next run can take the database lock, as after a
    // process exit.
    let node_run = || {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("the node runtime starts")
    };
    for name in FIXTURES {
        let fixture = Fixture::load(name);
        let checkpoint_to = fixture.vault_activation + 20;
        let network = fixture.network(Some(checkpoint_to));
        let dir = TempDir::new().expect("a temporary directory");
        let config = zs::Config {
            cache_dir: dir.path().to_path_buf(),
            ephemeral: false,
            debug_skip_non_finalized_state_backup_task: true,
            ..zs::Config::default()
        };
        let stop_at = fixture.tip() - 10;

        node_run().block_on(async {
            let mut node = start(&network, config.clone()).await;
            node.commit(regtest_genesis_block()).await;
            for b in &fixture.blocks[..stop_at as usize] {
                node.commit(b.block.clone()).await;
            }
            assert_eq!(
                node.statehash_when_at(stop_at).await,
                fixture.statehash_at(stop_at),
                "{name}: statehash before the restart"
            );
        });

        node_run().block_on(async {
            let mut node = start(&network, config).await;
            assert_eq!(
                node.statehash_when_at(stop_at).await,
                fixture.statehash_at(stop_at),
                "{name}: statehash after the restart"
            );
            for (i, _) in fixture.blocks.iter().enumerate().skip(stop_at as usize) {
                let height = i as u32 + 1;
                node.commit(fixture.blocks[i].block.clone()).await;
                assert_eq!(
                    node.statehash_when_at(height).await,
                    fixture.statehash_at(height),
                    "{name}: statehash after block {height}, after the restart"
                );
            }
        });
    }
}
