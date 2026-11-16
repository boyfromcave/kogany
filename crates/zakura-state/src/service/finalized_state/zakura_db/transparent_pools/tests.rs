//! State tests of the transparent pools by type and the chain transaction count, over the two
//! ycash6 regtest chains `kogany-vault` recorded (`crates/kogany-vault/tests/data/`): blocks that
//! ycashd mined, with vaults, intents, bonds and post-quantum outputs created and spent.
//!
//! The oracle is independent of the index's arithmetic: it replays the chain into an unspent
//! output set and sums that set by class after every block, where the index adds and subtracts
//! per block from its parent's record.

use std::{collections::HashMap, path::Path, sync::Arc};

use semver::Version;
use tempfile::TempDir;
use zakura_chain::{
    block::{genesis::regtest_genesis_block, Block, Height},
    parameters::{testnet::ConfiguredActivationHeights, Network},
    serialization::ZcashDeserializeInto,
    transparent,
};

use crate::{
    arbitrary::Prepare,
    config::Config,
    constants::state_database_format_version_in_code,
    service::{
        finalized_state::{
            disk_format::{
                upgrade::{add_transparent_pools::run_with_seed, cancel_channel},
                RawBytes,
            },
            vault::{register_vault_params_for_test, VaultNetworkParams},
            DiskWriteBatch, FinalizedState, ZakuraDb,
        },
        non_finalized_state::{Chain, NonFinalizedState},
        read::transparent_pools::{
            block_index_info, block_index_info_by_hash_or_best_chain_height,
        },
    },
    transparent_pools::{
        classify_transparent_script, BlockIndexInfo, PoolClass, TransparentPools,
        TransparentPoolsSeed,
    },
    HashOrHeight, PruningConfig, StorageMode,
};

const FIXTURES: [&str; 2] = [
    "ycash6_statehash_vault_rpc.json",
    "ycash6_statehash_vault_slashing.json",
];

/// A recorded chain, genesis first, and what the index must say after each block.
struct Fixture {
    name: &'static str,
    network: Network,
    blocks: Vec<Arc<Block>>,
    expected: Vec<BlockIndexInfo>,
}

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
    let network = Network::new_regtest(
        ConfiguredActivationHeights {
            overwinter: Some(1),
            sapling: Some(1),
            ycash: Some(1),
            blossom: Some(1),
            heartwood: Some(1),
            canopy: Some(1),
            vault: Some(params.activation_height.0),
            ..Default::default()
        }
        .into(),
    );
    register_vault_params_for_test(&network, params);

    let mut blocks = vec![regtest_genesis_block()];
    for (i, b) in doc["blocks"].as_array().unwrap().iter().enumerate() {
        assert_eq!(b["height"].as_u64().unwrap() as usize, i + 1, "{name}");
        let bytes = hex::decode(b["hex"].as_str().unwrap()).unwrap();
        blocks.push(Arc::new(bytes.zcash_deserialize_into().unwrap()));
    }
    let expected = oracle(&blocks);
    Fixture {
        name,
        network,
        blocks,
        expected,
    }
}

/// The record of an unspent output set, summed from scratch.
fn sum_by_class(unspent: &HashMap<transparent::OutPoint, transparent::Output>) -> TransparentPools {
    let mut r = TransparentPools::default();
    for output in unspent.values() {
        let value = i64::from(output.value());
        let class = classify_transparent_script(&output.lock_script);
        r.transparent += value;
        match class.class {
            PoolClass::TransparentPq if class.pq_scheme == 1 => r.pq1 += value,
            PoolClass::TransparentPq => r.pq2 += value,
            PoolClass::PqChannel => r.channel += value,
            PoolClass::Vault => {
                r.vault += value;
                r.vault_yed += if class.yed { value } else { 0 };
            }
            PoolClass::VaultIntent => {
                r.intent += value;
                r.intent_yed += if class.yed { value } else { 0 };
            }
            PoolClass::TransparentEcc => {}
        }
    }
    r
}

fn oracle(blocks: &[Arc<Block>]) -> Vec<BlockIndexInfo> {
    let mut unspent = HashMap::new();
    let mut chain_tx_count = 0u64;
    let mut parent_pools = TransparentPools::default();
    blocks
        .iter()
        .map(|block| {
            for transaction in &block.transactions {
                for outpoint in transaction.inputs().iter().filter_map(|i| i.outpoint()) {
                    unspent.remove(&outpoint).expect("a known coin");
                }
                let hash = transaction.hash();
                for (index, output) in transaction.outputs().iter().enumerate() {
                    let outpoint = transparent::OutPoint::from_usize(hash, index);
                    unspent.insert(outpoint, output.clone());
                }
            }
            chain_tx_count += block.transactions.len() as u64;
            let pools = sum_by_class(&unspent);
            let info = BlockIndexInfo {
                chain_tx_count: Some(chain_tx_count),
                pools: Some(pools),
                parent_pools: Some(parent_pools),
            };
            parent_pools = pools;
            info
        })
        .collect()
}

fn height(i: usize) -> Height {
    Height(i as u32)
}

fn config_at(dir: &Path) -> Config {
    Config {
        cache_dir: dir.to_path_buf(),
        ephemeral: false,
        ..Config::default()
    }
}

/// A state with `blocks` committed through the finalized write path.
fn finalized(config: &Config, network: &Network, blocks: &[Arc<Block>]) -> FinalizedState {
    let mut state =
        FinalizedState::new_with_debug_without_storage_validation(config, network, false, false)
            .expect("the state opens");
    for block in blocks {
        state
            .commit_finalized_direct(block.clone().into(), None, None, "transparent pools test")
            .expect("a recorded block commits");
    }
    state
}

fn assert_rows(db: &ZakuraDb, fx: &Fixture, range: std::ops::Range<usize>, context: &str) {
    for i in range {
        assert_eq!(
            db.finalized_block_index_info(height(i).into()),
            Some(fx.expected[i]),
            "{} {context}: height {i}",
            fx.name
        );
    }
}

/// Makes the database look as an older binary left it from the given heights on: `block_info`
/// rows without a count from `count_from`, and no pools rows from `pools_from`.
fn strip(db: &ZakuraDb, count_from: usize, pools_from: usize) {
    let tip = db.finalized_tip_height().expect("a tip").0 as usize;
    let mut batch = DiskWriteBatch::new();
    for i in count_from..=tip {
        let row = db.raw_block_info_cf().zs_get(&height(i)).expect("a row");
        let _ = db
            .raw_block_info_cf()
            .with_batch_for_writing(&mut batch)
            .zs_insert(
                &height(i),
                &RawBytes::new_raw_bytes(row.raw_bytes()[..60].to_vec()),
            );
    }
    batch.delete_transparent_pools_from(db, height(pools_from));
    db.write_batch(batch).expect("the batch writes");
}

fn upgrade(db: &ZakuraDb, seed: Option<TransparentPoolsSeed>) {
    let (_cancel_handle, cancel_receiver) = cancel_channel();
    run_with_seed(db.finalized_tip_height(), db, seed, &cancel_receiver).expect("the upgrade runs");
}

/// The fixtures exercise the classes: the tests below would pass trivially on coinbase-only
/// chains. Between them they hold vault and intent outputs; they hold no post-quantum or channel
/// output (the recorded chains predate those wallets), and this test pins that, so that a
/// re-recorded fixture extends the assertions. Those classes are covered by the classifier vectors
/// and by `qa/value_pools_parity.py`, whose chain has every class.
#[test]
fn the_recorded_chains_create_and_spend_template_outputs() {
    let mut seen = [0i64; 3];
    for name in FIXTURES {
        let fx = fixture(name);
        let max = |f: fn(&TransparentPools) -> i64| {
            fx.expected
                .iter()
                .map(|info| f(&info.pools.unwrap()))
                .max()
                .unwrap()
        };
        seen[0] = seen[0].max(max(|r| r.pq1 + r.pq2));
        seen[1] = seen[1].max(max(|r| r.channel));
        seen[2] = seen[2].max(max(|r| r.intent));
        assert!(max(|r| r.vault) > 0, "{name}: vaults");
        assert!(max(|r| r.transparent_ecc()) > 0, "{name}: ECC outputs");
        assert!(
            fx.expected
                .windows(2)
                .any(|w| w[1].pools.unwrap().vault < w[0].pools.unwrap().vault),
            "{name}: a vault is spent"
        );
        assert!(fx.expected.iter().all(|info| info.pools.unwrap().is_sane()));
        let last = fx.expected.last().unwrap();
        assert!(last.chain_tx_count.unwrap() > fx.blocks.len() as u64);
    }
    assert_eq!(
        seen[..2],
        [0, 0],
        "post-quantum and channel outputs: assert them now"
    );
    assert!(seen[2] > 0, "intent outputs: {seen:?}");
}

/// A fresh database: the finalized write path stores the row and the count of every block,
/// equal to the oracle, and they survive a restart.
#[test]
fn finalized_rows_equal_the_oracle_and_survive_restart() {
    let _init_guard = zakura_test::init();
    for name in FIXTURES {
        let fx = fixture(name);
        let dir = TempDir::new().unwrap();
        let config = config_at(dir.path());

        let state = finalized(&config, &fx.network, &fx.blocks);
        assert_eq!(
            state.db.format_version_on_disk().unwrap(),
            Some(state_database_format_version_in_code()),
            "{name}: a new database is created in the current format"
        );
        assert_eq!(state_database_format_version_in_code().minor, 3);
        assert_rows(&state.db, &fx, 0..fx.blocks.len(), "fresh");
        // By hash too, and nothing above the tip.
        let tip = fx.blocks.len() - 1;
        assert_eq!(
            state
                .db
                .finalized_block_index_info(fx.blocks[tip].hash().into()),
            Some(fx.expected[tip])
        );
        assert_eq!(
            state.db.finalized_block_index_info(height(tip + 1).into()),
            None
        );
        drop(state);

        let state = finalized(&config, &fx.network, &[]);
        assert_rows(&state.db, &fx, 0..fx.blocks.len(), "restart");
    }
}

/// Non-finalized blocks have no rows: their figures are read from the finalized rows below the
/// chain and the chain's own blocks, on every fork, through reorgs and into finalization.
#[test]
fn non_finalized_reads_follow_forks_and_reorgs() {
    const NON_FINALIZED: usize = 12;
    let _init_guard = zakura_test::init();
    for name in FIXTURES {
        let fx = fixture(name);
        let split = fx.blocks.len() - NON_FINALIZED;
        let mut state = finalized(&Config::ephemeral(), &fx.network, &fx.blocks[..split]);

        let read = |nfs: &NonFinalizedState, db: &ZakuraDb, at: HashOrHeight| {
            block_index_info_by_hash_or_best_chain_height(nfs, db, at)
        };
        let assert_chain = |nfs: &NonFinalizedState, db: &ZakuraDb, tip: usize, context: &str| {
            for i in 0..=tip {
                for at in [height(i).into(), fx.blocks[i].hash().into()] {
                    assert_eq!(
                        read(nfs, db, at),
                        Some(fx.expected[i]),
                        "{name} {context}: {at:?}"
                    );
                }
            }
            assert_eq!(read(nfs, db, height(tip + 1).into()), None);
        };

        let mut nfs = NonFinalizedState::new(&fx.network);
        for (k, block) in fx.blocks[split..].iter().enumerate() {
            let prepared = block.clone().prepare();
            if k == 0 {
                nfs.commit_new_chain(prepared, &state.db)
            } else {
                nfs.commit_block(prepared, &state.db)
            }
            .expect("a recorded block validates");
        }
        let tip = fx.blocks.len() - 1;
        assert_chain(&nfs, &state.db, tip, "pushed");

        // A competing fork that ends earlier: each chain answers from its own blocks, and a
        // hash resolves on whichever chain has it.
        let mid = split + NON_FINALIZED / 2;
        let best = nfs.best_chain().expect("a chain").clone();
        let fork: Arc<Chain> = Arc::new(
            best.fork(fx.blocks[mid].hash())
                .expect("the fork point is in the chain"),
        );
        for chains in [vec![fork.clone(), best.clone()], vec![best, fork.clone()]] {
            for i in [split, mid, tip] {
                assert_eq!(
                    block_index_info(chains.iter(), &state.db, fx.blocks[i].hash().into()),
                    Some(fx.expected[i]),
                    "{name}: two chains, height {i}"
                );
            }
        }
        // The fork alone does not know the blocks above its tip.
        assert_eq!(
            block_index_info([fork].iter(), &state.db, fx.blocks[tip].hash().into()),
            None
        );

        // Reorgs: back to the finalized tip and forward, then from the middle.
        nfs.invalidate_block(fx.blocks[split].hash())
            .expect("the block is non-finalized");
        assert_chain(
            &nfs,
            &state.db,
            split - 1,
            "invalidated to the finalized tip",
        );
        assert_eq!(read(&nfs, &state.db, fx.blocks[tip].hash().into()), None);
        nfs.reconsider_block(fx.blocks[split].hash(), &state.db)
            .expect("the block is reconsidered");
        assert_chain(&nfs, &state.db, tip, "reconsidered");
        nfs.invalidate_block(fx.blocks[mid].hash())
            .expect("the block is non-finalized");
        assert_chain(&nfs, &state.db, mid - 1, "invalidated in the middle");
        nfs.reconsider_block(fx.blocks[mid].hash(), &state.db)
            .expect("the block is reconsidered");
        assert_chain(&nfs, &state.db, tip, "reconsidered in the middle");

        // Finalizing moves each block's figures into rows; every read stays the same.
        while nfs.best_chain_len().unwrap_or(0) > 0 {
            let block = nfs.finalize();
            state
                .commit_finalized_direct(block, None, None, "transparent pools test")
                .expect("a finalized block commits");
            assert_chain(&nfs, &state.db, tip, "finalizing");
        }
        assert_rows(&state.db, &fx, 0..fx.blocks.len(), "finalized");
    }
}

/// A block whose parent has no row or no count is written without one, a stale row at its
/// height is deleted, and nothing is derived from the unknown parent: not by the write path and
/// not by the read path.
#[test]
fn a_block_above_an_unknown_parent_stays_unknown() {
    let _init_guard = zakura_test::init();
    let fx = fixture(FIXTURES[0]);
    let split = fx.blocks.len() - 10;
    let mut state = finalized(&Config::ephemeral(), &fx.network, &fx.blocks[..split]);

    // The tip loses its count and its pools row; a stale row sits at the next height.
    strip(&state.db, split - 1, split - 1);
    let mut batch = DiskWriteBatch::new();
    batch.insert_transparent_pools(&state.db, height(split), &fx.expected[3].pools.unwrap());
    state.db.write_batch(batch).unwrap();

    // The non-finalized read above the unknown tip is unknown.
    let mut nfs = NonFinalizedState::new(&fx.network);
    nfs.commit_new_chain(fx.blocks[split].clone().prepare(), &state.db)
        .expect("the block validates whatever the index holds");
    let unknown = BlockIndexInfo {
        chain_tx_count: None,
        pools: None,
        parent_pools: None,
    };
    assert_eq!(
        block_index_info_by_hash_or_best_chain_height(&nfs, &state.db, height(split).into()),
        Some(unknown)
    );

    // The finalized write commits the block, without a row and without a count.
    for block in &fx.blocks[split..split + 3] {
        state
            .commit_finalized_direct(block.clone().into(), None, None, "transparent pools test")
            .expect("the block commits whatever the index holds");
    }
    for i in split..split + 3 {
        assert_eq!(
            state.db.finalized_block_index_info(height(i).into()),
            Some(unknown),
            "height {i}"
        );
        assert_eq!(
            state.db.transparent_pools_cf().unwrap().zs_get(&height(i)),
            None
        );
    }
    // The value pools and the block size are stored as ever.
    let info = state.db.block_info(height(split).into()).expect("a row");
    assert_eq!(info.chain_tx_count(), None);
    assert!(info.size() > 0);

    // The next run of the upgrade fills the gap.
    upgrade(&state.db, None);
    assert_rows(&state.db, &fx, 0..split + 3, "after the upgrade");
}

/// The upgrade from the previous format, a restart at each stage of it, and a database an older
/// binary extended: each run leaves exactly the rows a fresh sync writes.
#[test]
fn upgrade_fills_resumes_and_replaces_stale_rows() {
    let _init_guard = zakura_test::init();
    for name in FIXTURES {
        let fx = fixture(name);
        let state = finalized(&Config::ephemeral(), &fx.network, &fx.blocks);
        let db = &state.db;
        let len = fx.blocks.len();

        // The previous format: no counts, no pools rows.
        strip(db, 0, 0);
        assert_eq!(
            db.first_height_without_chain_tx_count(height(len - 1)),
            Some(Height(0))
        );
        assert_eq!(db.last_transparent_pools_row(), None);
        assert_eq!(
            db.finalized_block_index_info(height(len - 1).into())
                .unwrap()
                .pools,
            None
        );
        upgrade(db, None);
        assert_rows(db, &fx, 0..len, "from the previous format");
        assert_eq!(
            db.first_height_without_chain_tx_count(height(len - 1)),
            None
        );

        // A second run changes nothing.
        upgrade(db, None);
        assert_rows(db, &fx, 0..len, "run twice");

        // Stopped while adding the counts (the pools fill had not started).
        strip(db, 100, 0);
        upgrade(db, None);
        assert_rows(db, &fx, 0..len, "restart in the count fill");

        // Stopped while adding the pools rows (the counts were complete).
        strip(db, len, 40);
        upgrade(db, None);
        assert_rows(db, &fx, 0..len, "restart in the pools fill");

        // An older binary replaced the chain from height 100 (a rollback and a sync): its
        // `block_info` rows have no count, and the pools rows from there are another chain's.
        strip(db, 100, len);
        let mut batch = DiskWriteBatch::new();
        for i in 100..len + 5 {
            batch.insert_transparent_pools(db, height(i), &fx.expected[1].pools.unwrap());
        }
        db.write_batch(batch).unwrap();
        upgrade(db, None);
        assert_rows(db, &fx, 0..len, "after an older binary");
        assert_eq!(
            db.last_transparent_pools_row().map(|(h, _)| h),
            Some(height(len - 1)),
            "{name}: no row is left above the tip"
        );

        // A row this code cannot read: the index is rebuilt.
        let _ = db
            .transparent_pools_cf()
            .unwrap()
            .new_batch_for_writing()
            .zs_insert(&height(len - 1), &RawBytes::new_raw_bytes(vec![9; 65]))
            .write_batch();
        assert_eq!(
            db.finalized_block_index_info(height(len - 1).into())
                .unwrap()
                .pools,
            None
        );
        upgrade(db, None);
        assert_rows(db, &fx, 0..len, "after a corrupt row");
    }
}

/// An empty index starts from the seed when the chain contains the seed block, and a fill from
/// genesis checks the seed as it passes the seed block.
#[test]
fn upgrade_starts_from_the_seed_and_checks_it() {
    let _init_guard = zakura_test::init();
    let fx = fixture(FIXTURES[0]);
    let state = finalized(&Config::ephemeral(), &fx.network, &fx.blocks);
    let db = &state.db;
    let len = fx.blocks.len();
    const SEED: usize = 60;
    let seed = TransparentPoolsSeed {
        height: height(SEED),
        hash: fx.blocks[SEED].hash(),
        record: fx.expected[SEED].pools.unwrap(),
    };
    let pools_at = |i: usize| {
        db.finalized_block_index_info(height(i).into())
            .unwrap()
            .pools
    };

    // From the seed: no block below it is read, every row from it on is the oracle's.
    strip(db, 0, 0);
    upgrade(db, Some(seed));
    for (i, expected) in fx.expected.iter().enumerate() {
        let expected = (i >= SEED).then(|| expected.pools.unwrap());
        assert_eq!(pools_at(i), expected, "from the seed: height {i}");
    }
    // The counts never start from a seed.
    assert_eq!(
        db.first_height_without_chain_tx_count(height(len - 1)),
        None
    );
    assert_eq!(
        db.finalized_block_index_info(height(len - 1).into())
            .unwrap()
            .chain_tx_count,
        fx.expected[len - 1].chain_tx_count
    );

    // A seed that names another block (another network), or a block above the tip, is not
    // used: the fill starts at genesis.
    for other in [
        TransparentPoolsSeed {
            hash: fx.blocks[SEED + 1].hash(),
            ..seed
        },
        TransparentPoolsSeed {
            height: height(len + 10),
            ..seed
        },
    ] {
        strip(db, len, 0);
        upgrade(db, Some(other));
        assert_rows(db, &fx, 0..len, "a seed for another chain");
    }

    // A fill from genesis that reaches the seed block with other totals stops there.
    let wrong = TransparentPoolsSeed {
        record: TransparentPools {
            transparent: seed.record.transparent + 1,
            ..seed.record
        },
        ..seed
    };
    strip(db, len, 0);
    // Rows below the seed exist, so the fill resumes from them rather than from the seed.
    let mut batch = DiskWriteBatch::new();
    batch.insert_transparent_pools(db, Height(0), &fx.expected[0].pools.unwrap());
    db.write_batch(batch).unwrap();
    upgrade(db, Some(wrong));
    for (i, expected) in fx.expected.iter().enumerate() {
        let expected = (i < SEED).then(|| expected.pools.unwrap());
        assert_eq!(pools_at(i), expected, "a seed mismatch: height {i}");
    }
}

/// A pruned database no longer has the blocks: the pools stay unmonitored, the counts (which
/// need no transaction) are complete, and nothing fails.
#[test]
fn upgrade_on_a_pruned_database_counts_but_does_not_monitor() {
    let _init_guard = zakura_test::init();
    let fx = fixture(FIXTURES[0]);
    let config = Config {
        storage_mode: StorageMode::Pruned(PruningConfig { tx_retention: 8 }),
        ..Config::ephemeral()
    };
    let state = finalized(&config, &fx.network, &fx.blocks);
    let db = &state.db;
    let len = fx.blocks.len();
    assert!(
        db.block(height(len / 2).into()).is_none(),
        "bodies are pruned"
    );
    // A pruned node that synced on this format has every row: it wrote them as it committed.
    assert_rows(db, &fx, 0..len, "pruned sync");

    strip(db, 0, 0);
    upgrade(db, None);
    for (i, expected) in fx.expected.iter().enumerate() {
        let info = db.finalized_block_index_info(height(i).into()).unwrap();
        assert_eq!(info.chain_tx_count, expected.chain_tx_count, "height {i}");
        // The genesis block's body is never pruned; the fill stops at the first pruned block.
        assert_eq!(info.pools.is_some(), i == 0, "height {i}");
    }
}

/// The upgrade is registered: a database marked with the previous format version is filled when
/// the state opens, before anything can read or commit.
#[test]
fn a_database_in_the_previous_format_is_upgraded_at_startup() {
    let _init_guard = zakura_test::init();
    let fx = fixture(FIXTURES[1]);
    let dir = TempDir::new().unwrap();
    let config = config_at(dir.path());

    let state = finalized(&config, &fx.network, &fx.blocks);
    strip(&state.db, 0, 0);
    let previous = Version::new(30, 2, 0);
    state
        .db
        .update_format_version_on_disk(&previous)
        .expect("the version file is written");
    drop(state);

    let state = finalized(&config, &fx.network, &[]);
    assert_eq!(
        state.db.format_version_on_disk().unwrap(),
        Some(state_database_format_version_in_code())
    );
    assert_rows(&state.db, &fx, 0..fx.blocks.len(), "upgraded at startup");
}

/// The `block_info` row: the count is appended to the full 60-byte row only, a row without one
/// reads as "not known", and a shorter (older-layout) row never gets or shows a count.
#[test]
fn the_chain_transaction_count_is_appended_to_a_full_length_row_only() {
    use crate::service::finalized_state::disk_format::{
        chain::{ycash_block_info_row_with_count, ycash_chain_tx_count_from_row},
        FromDisk, IntoDisk,
    };
    use zakura_chain::{block_info::BlockInfo, value_balance::ValueBalance};

    let plain = BlockInfo::new(ValueBalance::zero(), 1_234);
    let plain_row = plain.as_bytes();
    assert_eq!(plain_row.len(), 60, "upstream's row is unchanged");
    assert_eq!(BlockInfo::from_bytes(&plain_row), plain);
    assert_eq!(BlockInfo::from_bytes(&plain_row).chain_tx_count(), None);

    let counted = plain.clone().with_chain_tx_count(Some(718_557));
    let counted_row = counted.as_bytes();
    assert_eq!(counted_row.len(), 68);
    assert_eq!(counted_row[..60], plain_row[..]);
    assert_eq!(counted_row[60..], 718_557u64.to_le_bytes());
    let read = BlockInfo::from_bytes(&counted_row);
    assert_eq!(read, counted);
    assert_eq!(read.chain_tx_count(), Some(718_557));
    assert_eq!(
        (read.size(), read.value_pools()),
        (1_234, plain.value_pools())
    );
    // Zero is a count, not "unknown".
    let zero = plain.clone().with_chain_tx_count(Some(0)).as_bytes();
    assert_eq!(BlockInfo::from_bytes(&zero).chain_tx_count(), Some(0));

    // The upgrade's rewrite: a full row, with or without a count, and nothing else.
    assert_eq!(
        ycash_block_info_row_with_count(&plain_row, 718_557),
        Some(counted_row.clone())
    );
    assert_eq!(
        ycash_block_info_row_with_count(&zero, 718_557),
        Some(counted_row.clone())
    );
    // The older layouts (44 and 52 bytes) and their lengths plus eight are never a counted row:
    // 52 bytes is a layout of its own, not 44 bytes and a count.
    for len in [0, 43, 44, 51, 52, 59, 61, 67, 69, 76] {
        let row = vec![0u8; len];
        assert_eq!(ycash_chain_tx_count_from_row(&row), None, "{len} bytes");
        assert_eq!(
            ycash_block_info_row_with_count(&row, 7),
            None,
            "{len} bytes"
        );
    }
    for len in [44, 52] {
        assert_eq!(BlockInfo::from_bytes(vec![0u8; len]).chain_tx_count(), None);
    }
}
