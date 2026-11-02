//! W4-c exit-gate tests: the vault column families, the total transition in the finalized write
//! path, the non-finalized `Chain` overlay, restart, reorg and finalization, replayed over the
//! two ycash6 regtest chains `kogany-vault` recorded (`crates/kogany-vault/tests/data/`), whose
//! `statehash` after every Vault-epoch block is ycashd's `vault_getinfo.statehash`.
//!
//! The raw ycash6 blocks cannot yet go through `commit_finalized_direct` end to end: until the
//! Vault network upgrade is in `zakura-chain` (plan W2-b) the history tree does not reset at the
//! Vault activation, so the block-commitment check of a Vault-epoch block fails. These tests
//! therefore drive the vault halves of the two write paths (`prepare_vault_batch_for_block`, the
//! function `prepare_block_batch` calls, and `Chain::push` / `pop_tip` / `pop_root` with the
//! delta `validate_and_commit` computes) over a real RocksDB database.

use std::{collections::HashMap, path::Path, sync::Arc};

use kogany_vault::{
    state::{display_hex, Delta, MemberRecord, MemberStatus, StateRead},
    Hash32, OutPoint, PubKeyBytes,
};
use proptest::prelude::*;
use tempfile::TempDir;
use zakura_chain::{
    amount::NonNegative,
    block::{Block, Height},
    parameters::{testnet::ConfiguredActivationHeights, Network},
    serialization::ZcashDeserializeInto,
    transaction, transparent,
    value_balance::ValueBalance,
};

use crate::{
    config::Config,
    constants::{state_database_format_version_in_code, STATE_DATABASE_KIND},
    preview_rollback_finalized_state,
    service::{
        arbitrary::PreparedChain,
        finalized_state::{
            vault::{register_vault_params_for_test, VaultNetworkParams},
            CheckpointVerifiedBlock, FinalizedState, ZakuraDb, STATE_COLUMN_FAMILIES_IN_CODE,
        },
        non_finalized_state::{Chain, ChainVaultOverlay},
        vault::{
            block_vault_delta_for_chain, chain_tip_vault_snapshot, finalized_vault_snapshot,
            vault_snapshot_by_hash,
        },
    },
    ContextuallyVerifiedBlock, DiskWriteBatch, RollbackFinalizedStateError,
    RollbackFinalizedStateOptions, SemanticallyVerifiedBlock,
};

/// One recorded block.
struct FixtureBlock {
    height: Height,
    block: Arc<Block>,
    tx_hashes: Arc<[transaction::Hash]>,
    /// ycashd's `vault_getinfo.statehash` after the block (display order), if recorded.
    statehash: Option<String>,
}

struct Fixture {
    name: &'static str,
    params: VaultNetworkParams,
    blocks: Vec<FixtureBlock>,
}

const FIXTURES: [&str; 2] = [
    "ycash6_statehash_vault_rpc.json",
    "ycash6_statehash_vault_slashing.json",
];

fn fixture(name: &'static str) -> Fixture {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../kogany-vault/tests/data")
        .join(name);
    let doc: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).expect("the recorded fixture is committed"))
            .expect("the fixture is JSON");
    let params = VaultNetworkParams {
        activation_height: Height(doc["vaultActivation"].as_u64().unwrap() as u32),
        min_set_maturity: doc["minSetMaturity"].as_u64().unwrap() as u32,
    };
    let blocks = doc["blocks"]
        .as_array()
        .unwrap()
        .iter()
        .map(|b| {
            let bytes = hex::decode(b["hex"].as_str().unwrap()).unwrap();
            let block: Arc<Block> = Arc::new(bytes.zcash_deserialize_into().unwrap());
            assert_eq!(
                block.hash().to_string(),
                b["hash"].as_str().unwrap(),
                "{name}: zakura parses ycash6's block bytes to the same header hash"
            );
            let tx_hashes: Arc<[transaction::Hash]> =
                block.transactions.iter().map(|tx| tx.hash()).collect();
            FixtureBlock {
                height: Height(b["height"].as_u64().unwrap() as u32),
                block,
                tx_hashes,
                statehash: b["statehash"].as_str().map(str::to_owned),
            }
        })
        .collect();
    Fixture {
        name,
        params,
        blocks,
    }
}

/// A fresh regtest network (all upgrades through Canopy at height 1, as ycash6's
/// `YCASH_UPGRADE_ARGS`) with the fixture's Vault parameters registered on it alone.
fn network(params: VaultNetworkParams) -> Network {
    let network = Network::new_regtest(ConfiguredActivationHeights::default().into());
    register_vault_params_for_test(&network, params);
    network
}

fn config_at(dir: &Path) -> Config {
    Config {
        cache_dir: dir.to_path_buf(),
        ephemeral: false,
        ..Config::default()
    }
}

/// Opens (or reopens) the database at `config` with every column family, skipping format
/// upgrades: only the vault column families are written by these tests.
fn open_db(config: &Config, network: &Network) -> ZakuraDb {
    ZakuraDb::new(
        config,
        STATE_DATABASE_KIND,
        &state_database_format_version_in_code(),
        network,
        true,
        STATE_COLUMN_FAMILIES_IN_CODE
            .iter()
            .map(ToString::to_string),
        false,
    )
    .expect("opening the state database succeeds")
}

/// The running UTXO set of a replay: every output created so far (spent ones too: the vault
/// rules only read the coins the block spends, and a block never spends a coin twice).
#[derive(Default)]
struct Coins(HashMap<transparent::OutPoint, transparent::OrderedUtxo>);

impl Coins {
    /// Adds `b`'s outputs and returns the coins its inputs spend (same-block outputs included).
    fn spend(
        &mut self,
        b: &FixtureBlock,
    ) -> HashMap<transparent::OutPoint, transparent::OrderedUtxo> {
        self.0.extend(transparent::new_ordered_outputs_with_height(
            &b.block,
            b.height,
            &b.tx_hashes,
        ));
        b.block
            .transactions
            .iter()
            .flat_map(|tx| tx.inputs().iter().filter_map(|i| i.outpoint()))
            .map(|op| {
                let utxo = self
                    .0
                    .get(&op)
                    .cloned()
                    .expect("the fixture spends known coins");
                (op, utxo)
            })
            .collect()
    }
}

fn unordered(
    spent: &HashMap<transparent::OutPoint, transparent::OrderedUtxo>,
) -> HashMap<transparent::OutPoint, transparent::Utxo> {
    spent.iter().map(|(op, u)| (*op, u.utxo.clone())).collect()
}

/// The finalized write path's vault half for one block, committed on its own.
fn commit_vault_half(
    db: &ZakuraDb,
    network: &Network,
    b: &FixtureBlock,
    spent: &HashMap<transparent::OutPoint, transparent::OrderedUtxo>,
) {
    let mut batch = DiskWriteBatch::new();
    batch.prepare_vault_batch_for_block(
        db,
        network,
        &b.block,
        b.height,
        b.block.hash(),
        &b.tx_hashes,
        &unordered(spent),
    );
    db.write_batch(batch).expect("the vault batch writes");
}

fn hex(h: &Hash32) -> String {
    display_hex(h)
}

/// The checkpoint / finalized path: every block's transition computed in the finalized write
/// path and committed to RocksDB equals ycashd's `statehash` after it; the state survives a
/// restart byte for byte.
#[test]
fn finalized_path_statehash_equals_ycash6_and_survives_restart() {
    let _init_guard = zakura_test::init();
    for name in FIXTURES {
        let fx = fixture(name);
        let network = network(fx.params);
        let dir = TempDir::new().unwrap();
        let config = config_at(dir.path());

        let db = open_db(&config, &network);
        let mut coins = Coins::default();
        let mut checked = 0;
        for b in &fx.blocks {
            let spent = coins.spend(b);
            commit_vault_half(&db, &network, b, &spent);
            if b.height < fx.params.activation_height {
                assert!(!db.has_vault_state(), "{name}: nothing before activation");
            }
            if let Some(want) = &b.statehash {
                assert_eq!(
                    &hex(&db.vault_state_hash()),
                    want,
                    "{name} at {:?}",
                    b.height
                );
                checked += 1;
            }
        }
        assert!(checked >= 50, "{name}: {checked} heights checked");

        let entries = db.vault_canonical_entries();
        let hash = db.vault_state_hash();
        let state = db.vault_set_state();
        assert_eq!(
            state.state_hash(),
            hash,
            "the decoded state hashes the same"
        );
        assert!(!state.sets.is_empty() && !state.members.is_empty());
        // The typed reads agree with the decoded state.
        let reader = db.vault_state();
        for id in state.set_ids() {
            assert_eq!(reader.set(&id), state.set(&id));
            assert_eq!(reader.members(&id), state.members(&id));
        }
        drop(db);

        let reopened = open_db(&config, &network);
        assert_eq!(
            reopened.vault_canonical_entries(),
            entries,
            "{name}: restart"
        );
        assert_eq!(reopened.vault_state_hash(), hash);
        assert_eq!(
            hex(&hash),
            *fx.blocks.last().unwrap().statehash.as_ref().unwrap()
        );
    }
}

/// A network without Vault parameters computes and stores nothing (the seam's default).
#[test]
fn no_vault_state_without_activation() {
    let _init_guard = zakura_test::init();
    let fx = fixture(FIXTURES[0]);
    let network = Network::new_regtest(ConfiguredActivationHeights::default().into());
    let dir = TempDir::new().unwrap();
    let db = open_db(&config_at(dir.path()), &network);
    let mut coins = Coins::default();
    for b in &fx.blocks {
        let spent = coins.spend(b);
        commit_vault_half(&db, &network, b, &spent);
    }
    assert!(!db.has_vault_state());
}

/// Builds the non-finalized chain of every fixture block on an empty finalized state, through
/// `Chain::push` with the delta `validate_and_commit` computes.
fn push_all(
    fx: &Fixture,
    network: &Network,
    db: &ZakuraDb,
) -> (Chain, Vec<ContextuallyVerifiedBlock>) {
    let mut chain = Chain::new(
        network,
        Height(0),
        Default::default(),
        Default::default(),
        Default::default(),
        Default::default(),
        Default::default(),
        ValueBalance::<NonNegative>::zero(),
    );
    let mut coins = Coins::default();
    let mut pushed = Vec::new();
    for b in &fx.blocks {
        let spent = coins.spend(b);
        let semantic =
            SemanticallyVerifiedBlock::from(CheckpointVerifiedBlock::from(b.block.clone()));
        let mut cv =
            ContextuallyVerifiedBlock::with_block_and_spent_utxos(network, semantic, spent)
                .expect("the fixture's value balances are valid");
        cv.vault_delta = Arc::new(block_vault_delta_for_chain(network, &chain, db, &cv));
        pushed.push(cv.clone());
        chain = chain
            .push(cv)
            .expect("the fixture block pushes onto the chain");
        if let Some(want) = &b.statehash {
            assert_eq!(
                &hex(&chain_tip_vault_snapshot(&chain, db).state_hash()),
                want,
                "{}: chain tip at {:?}",
                fx.name,
                b.height
            );
        }
    }
    (chain, pushed)
}

/// The semantic path: pushed through `Chain`, every tip's state equals ycashd's; a snapshot by
/// any block hash (fork-aware) equals ycashd's state after that block; forking back (a reorg)
/// reverts the overlay exactly and re-pushing restores it; finalizing every block (pop the root,
/// then the finalized write path recomputes the root's transition over RocksDB) keeps the tip's
/// state equal and leaves the database at ycashd's state; a checkpoint-committed copy of the
/// same range ends in identical entries.
#[test]
fn chain_reorg_and_finalization_equal_ycash6_and_the_checkpoint_path() {
    let _init_guard = zakura_test::init();
    for name in FIXTURES {
        let fx = fixture(name);
        let network = network(fx.params);
        let dir = TempDir::new().unwrap();
        let config = config_at(dir.path());
        let db = open_db(&config, &network);

        let (chain, pushed) = push_all(&fx, &network, &db);
        let chain = Arc::new(chain);
        assert!(!chain.vault_overlay().is_empty());

        // Fork-aware snapshots by hash.
        for b in &fx.blocks {
            let snapshot = vault_snapshot_by_hash([&chain], &db, b.block.hash())
                .expect("every pushed block has a snapshot");
            assert_eq!(snapshot.tip, Some((b.height, b.block.hash())));
            if let Some(want) = &b.statehash {
                assert_eq!(
                    &hex(&snapshot.state_hash()),
                    want,
                    "{name}: snapshot {:?}",
                    b.height
                );
            }
        }

        // Reorgs: fork at a few heights, compare with the chain pushed only that far, then
        // re-push the popped blocks.
        let tip = fx.blocks.len();
        for depth in [1usize, 2, 7, 30] {
            let at = &fx.blocks[tip - 1 - depth];
            let mut forked = chain
                .fork(at.block.hash())
                .expect("the chain holds the block");
            let mut short = Chain::new(
                &network,
                Height(0),
                Default::default(),
                Default::default(),
                Default::default(),
                Default::default(),
                Default::default(),
                ValueBalance::<NonNegative>::zero(),
            );
            for cv in &pushed[..tip - depth] {
                short = short.push(cv.clone()).unwrap();
            }
            assert_eq!(
                forked.vault_overlay(),
                short.vault_overlay(),
                "{name}: the overlay after popping {depth} tips"
            );
            if let Some(want) = &at.statehash {
                assert_eq!(
                    &hex(&chain_tip_vault_snapshot(&forked, &db).state_hash()),
                    want
                );
            }
            for cv in &pushed[tip - depth..] {
                forked = forked.push(cv.clone()).unwrap();
            }
            assert_eq!(
                forked.vault_overlay(),
                chain.vault_overlay(),
                "{name}: re-pushed"
            );
        }

        // Finalization: pop every root and commit it through the finalized write path, which
        // recomputes its transition over the database.
        let tip_hash = chain_tip_vault_snapshot(&chain, &db).state_hash();
        let mut chain = Arc::unwrap_or_clone(chain);
        let mut coins = Coins::default();
        for b in &fx.blocks {
            let (root, _treestate) = chain.pop_root();
            assert_eq!(root.hash, b.block.hash());
            let spent = coins.spend(b);
            commit_vault_half(&db, &network, b, &spent);
            if let Some(want) = &b.statehash {
                assert_eq!(
                    &hex(&db.vault_state_hash()),
                    want,
                    "{name}: finalized {:?}",
                    b.height
                );
            }
            if !chain.is_empty() {
                assert_eq!(
                    chain_tip_vault_snapshot(&chain, &db).state_hash(),
                    tip_hash,
                    "{name}: the tip's state is unchanged by finalizing {:?}",
                    b.height
                );
            }
        }
        assert!(
            chain.vault_overlay().is_empty(),
            "an empty chain holds no overlay"
        );
        assert_eq!(finalized_vault_snapshot(&db).state_hash(), tip_hash);

        // The checkpoint path over the same range ends in identical entries.
        let dir2 = TempDir::new().unwrap();
        let checkpoint_db = open_db(&config_at(dir2.path()), &network);
        let mut coins = Coins::default();
        for b in &fx.blocks {
            let spent = coins.spend(b);
            commit_vault_half(&checkpoint_db, &network, b, &spent);
        }
        assert_eq!(
            checkpoint_db.vault_canonical_entries(),
            db.vault_canonical_entries(),
            "{name}: checkpoint-committed == semantically verified then finalized"
        );
    }
}

/// K-13: the overlay's memory at the 1,000-block window. Measured on the fixtures (the largest
/// per-block delta they hold), then a synthetic 1,000-block window of member churn that writes a
/// distinct member record in every block.
#[test]
fn overlay_memory_at_the_reorg_window() {
    let _init_guard = zakura_test::init();
    let mut max_delta_bytes = 0usize;
    for name in FIXTURES {
        let fx = fixture(name);
        let network = network(fx.params);
        let dir = TempDir::new().unwrap();
        let db = open_db(&config_at(dir.path()), &network);
        let (chain, pushed) = push_all(&fx, &network, &db);
        for cv in &pushed {
            let bytes: usize = cv
                .vault_delta
                .canonical_entries()
                .iter()
                .map(|(k, (b, a))| {
                    k.len() + b.as_ref().map_or(0, Vec::len) + a.as_ref().map_or(0, Vec::len)
                })
                .sum();
            max_delta_bytes = max_delta_bytes.max(bytes);
        }
        eprintln!(
            "K-13 {name}: {} blocks, overlay {} entries / {} bytes",
            pushed.len(),
            chain.vault_overlay().len(),
            chain.vault_overlay().approx_bytes()
        );
    }

    // A synthetic window: 1,000 blocks, each writing one new member record.
    let mut overlay = ChainVaultOverlay::default();
    let set = Hash32([7u8; 32]);
    for i in 0u32..1_000 {
        let mut key = [2u8; 33];
        key[1..5].copy_from_slice(&i.to_be_bytes());
        let mut delta = Delta::default();
        delta.members.insert(
            (set, PubKeyBytes(key)),
            kogany_vault::state::Change {
                before: None,
                after: Some(MemberRecord {
                    bond_outpoint: OutPoint {
                        txid: Hash32([1u8; 32]),
                        n: i,
                    },
                    bond_value: 1,
                    bond_locktime: 0,
                    join_height: i64::from(i),
                    last_act: i64::from(i),
                    status: MemberStatus::Active,
                    bond_frozen: false,
                    join_ordinal: i,
                }),
            },
        );
        overlay.push(&delta);
    }
    let bytes = overlay.approx_bytes();
    eprintln!(
        "K-13 synthetic: 1,000 blocks x 1 member record: overlay {} entries / {bytes} bytes; \
         fixture max per-block delta {max_delta_bytes} bytes (x1,000 = {} bytes)",
        overlay.len(),
        max_delta_bytes * 1_000
    );
    assert_eq!(overlay.len(), 1_000);
    assert!(
        bytes < 1 << 20,
        "a 1,000-block window of member churn stays under 1 MiB"
    );
}

/// K-14: the offline rollback refuses a database that holds vault state (and, on a network with
/// a Vault height, any rollback once the tip reached it); without either it proceeds as before.
#[test]
fn rollback_refuses_past_vault() {
    let _init_guard = zakura_test::init();
    let result = proptest::test_runner::TestRunner::new(ProptestConfig::with_cases(1)).run(
        &PreparedChain::default().no_shrink(),
        |(chain, count, network, _history_tree)| {
            let synced: Vec<SemanticallyVerifiedBlock> =
                chain.iter().take(count.min(8)).cloned().collect();
            prop_assume!(synced.len() >= 3);
            let tip = synced.len() - 1;

            let dir = TempDir::new().unwrap();
            let config = config_at(dir.path());
            {
                let mut state = FinalizedState::new(&config, &network).unwrap();
                for block in &synced {
                    state
                        .commit_finalized_direct(
                            CheckpointVerifiedBlock::from(block.block.clone()).into(),
                            None,
                            None,
                            "vault rollback test",
                        )
                        .unwrap();
                }
            }
            let preview = || {
                preview_rollback_finalized_state(
                    config.clone(),
                    &network,
                    RollbackFinalizedStateOptions {
                        target_height: Height(u32::try_from(tip - 1).unwrap()),
                        keep_rolled_back_blocks: false,
                        max_checkpoint_height: None,
                    },
                )
            };
            prop_assert!(preview().is_ok(), "no vault state: the rollback is allowed");

            // Store one vault entry: the database now holds state with no finalized undo.
            {
                let db = open_db(&config, &network);
                let mut delta = Delta::default();
                delta.bonds.insert(
                    OutPoint {
                        txid: Hash32([9u8; 32]),
                        n: 0,
                    },
                    kogany_vault::state::Change {
                        before: None,
                        after: Some(kogany_vault::state::BondRecord {
                            set_id: Hash32([3u8; 32]),
                            member_key: PubKeyBytes([2u8; 33]),
                            frozen: false,
                            exit_height: 0,
                        }),
                    },
                );
                let mut batch = DiskWriteBatch::new();
                batch.prepare_vault_delta_batch(&db, &delta);
                db.write_batch(batch).unwrap();
            }
            prop_assert!(
                matches!(
                    preview(),
                    Err(RollbackFinalizedStateError::PastVaultActivation { .. })
                ),
                "stored vault state: the rollback is refused"
            );
            Ok(())
        },
    );
    result.expect("the rollback refusal holds");
}

/// The format upgrade's postcondition: an older database below the activation height opens
/// with empty vault column families.
#[test]
fn format_upgrade_accepts_a_database_below_activation() {
    let _init_guard = zakura_test::init();
    let fx = fixture(FIXTURES[0]);
    let network = network(fx.params);
    let dir = TempDir::new().unwrap();
    let state = FinalizedState::new(&config_at(dir.path()), &network).unwrap();
    assert!(!state.db.has_vault_state());
    assert_eq!(
        state.db.vault_state_hash(),
        kogany_vault::state::SetState::new().state_hash()
    );
}
