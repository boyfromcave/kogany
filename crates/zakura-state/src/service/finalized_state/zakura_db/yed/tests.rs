//! W5-e exit-gate tests: the YED index column families, its evaluation in the finalized write
//! path, the non-finalized `Chain` overlay, reorgs, finalization, restart, the undo records, and
//! "cannot evaluate ⇒ stop the node".
//!
//! - **The golden chain** (`testdata/yellowback/yellowback_golden.json`, 462 entries of 440
//!   heights, pinned byte for byte to ycash6) is synthetic: no block headers (its hashes are the
//!   model's), and 79 of its 136 prevouts are coins outside the chain, so it cannot be committed
//!   as Zakura blocks. Its blocks go through the YED halves of both write paths — the functions
//!   `prepare_block_batch` and `validate_and_commit` call (`finalized_yed_effect` +
//!   `prepare_yed_effect_batch` over a real RocksDB database; `chain_yed_effect` +
//!   `Chain::push` / `fork` / `pop_root` with carrier blocks) — as W4-c's vault tests do. The
//!   state hash equals the pinned `stateHash` at the tip, and the in-memory replay
//!   (`kogany_yellowback`'s own golden test, itself pinned) at every height.
//! - **The real write paths** run on the zakura-test testnet vectors: `commit_finalized_direct`
//!   and `NonFinalizedState::commit_block` evaluate the index through the two hooks.
//! - **The C++ undo cases** of `yellowback_state_tests.cpp` (`apply_undo_identity_over_sequences`,
//!   `p_mint_persists_through_undo_and_reapply`, `overlay_view_equivalence`, `undo_identity_v3`,
//!   `overlay_equivalence_v3`) run on the W5-d fixture (`kogany-yellowback/tests/state_common`),
//!   mirrored into the store: every block's delta into RocksDB and onto a `Chain`, the undo
//!   through the chain's reverts and the stored undo records.

use std::{
    collections::BTreeMap,
    panic::{catch_unwind, AssertUnwindSafe},
    path::Path,
    sync::Arc,
};

use kogany_vault::Hash32;
use kogany_yellowback::{
    params::{regtest_params_with, BundleCarrier, Params},
    state::{
        evaluate_block, state_hash, ParamsRecord, TipRecord, VaultStatus, YedKey, YedOverlay,
        YedRead, YedRecord, YedState,
    },
};
use tempfile::TempDir;
use zakura_chain::{
    amount::NonNegative,
    block::{self, Block, Height},
    parameters::{testnet::ConfiguredActivationHeights, Network},
    serialization::ZcashDeserializeInto,
    value_balance::ValueBalance,
};

use super::*;
use crate::{
    arbitrary::Prepare,
    config::Config,
    constants::{state_database_format_version_in_code, STATE_DATABASE_KIND},
    service::{
        finalized_state::{
            disk_format::upgrade::add_yed_state::missing_yed_epoch, FinalizedState,
            STATE_COLUMN_FAMILIES_IN_CODE,
        },
        non_finalized_state::{Chain, ChainYedOverlay, NonFinalizedState},
        yed::{
            chain_tip_yed_snapshot, chain_yed_effect, finalized_yed_snapshot,
            finalized_yed_snapshot_below, tip_yed_snapshot, yed_snapshot_by_hash,
        },
    },
    tests::FakeChainHelper,
    ContextuallyVerifiedBlock,
};

#[path = "../../../../../../kogany-yellowback/tests/state_common/rawtx.rs"]
mod rawtx;

#[path = "../../../../../../kogany-yellowback/tests/state_common/fixture.rs"]
mod fixture;

// ---- shared helpers -----------------------------------------------------------------------

fn testdata(name: &str) -> serde_json::Value {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata/yellowback")
        .join(name);
    serde_json::from_slice(&std::fs::read(&path).expect("the pinned vectors are committed"))
        .expect("the vector is JSON")
}

/// A display-order hex `uint256` in memory order.
fn display_hash(s: &str) -> Hash32 {
    let mut b: [u8; 32] = hex::decode(s).unwrap().try_into().unwrap();
    b.reverse();
    Hash32(b)
}

fn config_at(dir: &Path) -> Config {
    Config {
        cache_dir: dir.to_path_buf(),
        ephemeral: false,
        ..Config::default()
    }
}

/// Opens (or reopens) the database at `config` with every column family, skipping format
/// upgrades: only the YED column families are written by the half-path tests.
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

/// A fresh regtest network with `p` registered on it alone.
fn network_with(p: Params) -> Network {
    let network = Network::new_regtest(ConfiguredActivationHeights::default().into());
    register_yed_params_for_test(&network, p);
    network
}

/// Commits an evaluated block's YED writes on their own (the finalized write path's YED half).
fn commit(db: &ZakuraDb, height: Height, hash: block::Hash, effect: &YedBlockEffect) {
    let mut batch = DiskWriteBatch::new();
    batch.prepare_yed_effect_batch(db, height, hash, effect);
    db.write_batch(batch).expect("the YED batch writes");
}

fn hex32(h: [u8; 32]) -> String {
    hex::encode(h)
}

/// Carrier blocks for `Chain` pushes: fake children of a mainnet block (their own transactions
/// are not what the index evaluates; the YED effect is computed from the input and attached).
fn carriers(n: usize) -> Vec<Arc<Block>> {
    let mut block: Arc<Block> = zakura_test::vectors::BLOCK_MAINNET_434873_BYTES
        .zcash_deserialize_into()
        .unwrap();
    (0..n)
        .map(|_| {
            let current = block.clone();
            block = block.make_fake_child();
            current
        })
        .collect()
}

fn empty_chain() -> Chain {
    Chain::new(
        &Network::Mainnet,
        Height(434_872),
        Default::default(),
        Default::default(),
        Default::default(),
        Default::default(),
        Default::default(),
        ValueBalance::<NonNegative>::fake_populated_pool(),
    )
}

fn carrier_cv(carrier: &Arc<Block>, effect: YedBlockEffect) -> ContextuallyVerifiedBlock {
    let mut cv = carrier.clone().prepare().test_with_zero_spent_utxos();
    cv.yed_effect = Arc::new(effect);
    cv
}

// ---- the golden chain -----------------------------------------------------------------------

struct GoldenBlock {
    input: YedBlockInput,
    invalid: bool,
}

struct Golden {
    p: Params,
    blocks: Vec<GoldenBlock>,
    doc: serde_json::Value,
}

/// The rejected entries of the golden chain, in order (`yellowback_state_golden.rs`).
const GOLDEN_INVALID: [(u32, &str); 22] = [
    (137, "bad-mint-amount"),
    (141, "bad-mint-collateral"),
    (146, "yed-template-output"),
    (150, "bad-redeem-early-fee"),
    (185, "vault-spend-short-burn"),
    (217, "vault-spend-malformed"),
    (231, "attestor-register-retired"),
    (251, "mint9-no-bundle"),
    (252, "mint9-bundle-sig"),
    (253, "mint9-bundle-member"),
    (292, "liveness-unheld"),
    (299, "red5-residual"),
    (299, "red5-residual"),
    (299, "red5-claimant-short"),
    (300, "intent-cancel-no-vault"),
    (300, "intent-cancel-no-refund"),
    (300, "intent-cancel-cosign"),
    (308, "intent-cancel-residual"),
    (310, "intent-residual-held"),
    (340, "intent-residual-held"),
    (402, "bad-yed-holder"),
    (403, "bad-yed-holder"),
];

fn golden() -> Golden {
    let doc = testdata("yellowback_golden.json");
    let v = &doc["params"];
    let int = |k: &str| i32::try_from(v[k].as_i64().unwrap()).unwrap();
    let carrier = match v["bundleCarrier"].as_i64().unwrap() {
        0 => BundleCarrier::ScriptSig,
        1 => BundleCarrier::OpReturn,
        _ => BundleCarrier::Either,
    };
    let mut p = regtest_params_with(
        int("startHeight"),
        int("sigmaRefBps"),
        int("supplyCapBps"),
        display_hash(v["attestorSetId"].as_str().unwrap()).0,
        int("attestArmMin"),
        carrier,
        v["mintRequiresArmed"].as_bool().unwrap(),
    );
    p.pq_falcon_height = int("pqFalconHeight");
    let mut parent = block::Hash([0u8; 32]);
    let blocks = doc["blocks"]
        .as_array()
        .unwrap()
        .iter()
        .map(|b| {
            let hash = block::Hash(display_hash(b["hash"].as_str().unwrap()).0);
            let invalid = b.get("invalid").and_then(|x| x.as_bool()).unwrap_or(false);
            let input = YedBlockInput {
                height: Height(u32::try_from(b["height"].as_i64().unwrap()).unwrap()),
                hash,
                parent,
                txs: b["txs"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|t| rawtx::parse_v4(&hex::decode(t.as_str().unwrap()).unwrap()))
                    .collect(),
                subsidy_zat: b["subsidyZat"].as_i64().unwrap(),
            };
            if !invalid {
                parent = hash;
            }
            GoldenBlock { input, invalid }
        })
        .collect();
    Golden { p, blocks, doc }
}

/// The in-memory replay (`kogany_yellowback`'s pinned golden test): the state hash after every
/// valid block, and the whole state at every `sample`-th one and the tip.
struct Reference {
    hashes: Vec<[u8; 32]>,
    samples: BTreeMap<usize, BTreeMap<Vec<u8>, Vec<u8>>>,
}

fn reference(g: &Golden, sample: usize) -> Reference {
    let mut state = YedState::new();
    let mut hashes = Vec::new();
    let mut samples = BTreeMap::new();
    let valid = g.blocks.iter().filter(|b| !b.invalid).count();
    for b in g.blocks.iter().filter(|b| !b.invalid) {
        let ev = evaluate_block(
            &state,
            &g.p,
            &b.input.txs,
            i64::from(b.input.height.0),
            &Hash32(b.input.hash.0),
            b.input.subsidy_zat,
            None,
        );
        assert!(!ev.block_invalid, "{:?}", b.input.height);
        state.apply(&ev.delta);
        let i = hashes.len();
        hashes.push(state_hash(&state, "regtest"));
        if i % sample == 0 || i + 1 == valid {
            samples.insert(i, state.canonical_entries());
        }
    }
    assert_eq!(
        hex32(*hashes.last().unwrap()),
        g.doc["stateHash"].as_str().unwrap()
    );
    Reference { hashes, samples }
}

/// The finalized path over the golden chain: every block evaluated over the RocksDB state and
/// committed in its own batch; a restart in the middle; the state hash equal to the in-memory
/// replay at every height and to the pinned `stateHash`, tip and totals at the end; the 22
/// invalid entries judged with their verdicts and not committed; the state unchanged by a
/// restart; the undo records restoring every recent height.
#[test]
fn golden_finalized_path_equals_pinned_across_restart() {
    let _init_guard = zakura_test::init();
    let g = golden();
    let r = reference(&g, 37);
    let network = network_with(g.p);
    let dir = TempDir::new().unwrap();
    let config = config_at(dir.path());
    let mut db = open_db(&config, &network);

    let mut valid = 0usize;
    let mut invalid = Vec::new();
    let mut by_height = BTreeMap::new();
    for (n, b) in g.blocks.iter().enumerate() {
        if n == 200 {
            let entries = db.yed_canonical_entries();
            drop(db);
            db = open_db(&config, &network);
            assert_eq!(db.yed_canonical_entries(), entries, "restart at entry {n}");
        }
        let effect = finalized_yed_effect(&db, Some(&g.p), &b.input).expect("evaluates");
        assert!(effect.evaluated);
        if b.invalid {
            let verdict = effect.invalid.expect("a flagged entry is invalid");
            assert!(effect.delta.is_empty());
            assert!(verdict.reason.starts_with(&format!("{}:", verdict.verdict)));
            invalid.push((b.input.height.0, verdict.verdict));
            continue;
        }
        assert_eq!(effect.invalid, None, "{:?}", b.input.height);
        commit(&db, b.input.height, b.input.hash, &effect);
        assert_eq!(
            db.yed_state_hash("regtest"),
            r.hashes[valid],
            "state hash at {:?}",
            b.input.height
        );
        if let Some(entries) = r.samples.get(&valid) {
            assert_eq!(&db.yed_canonical_entries(), entries, "{:?}", b.input.height);
        }
        by_height.insert(b.input.height, (b.input.hash, r.hashes[valid]));
        valid += 1;
    }
    let got: Vec<(u32, &str)> = invalid.iter().map(|(h, v)| (*h, v.as_str())).collect();
    assert_eq!(got, GOLDEN_INVALID.to_vec());

    // The pinned tip, totals and state hash.
    assert_eq!(
        hex32(db.yed_state_hash("regtest")),
        g.doc["stateHash"].as_str().unwrap()
    );
    let tip = db.yed_tip().unwrap();
    assert_eq!(
        i64::from(tip.height),
        g.doc["tip"]["height"].as_i64().unwrap()
    );
    assert_eq!(
        tip.block_hash,
        display_hash(g.doc["tip"]["hash"].as_str().unwrap())
    );
    let t = db.yed_state().totals();
    let tj = &g.doc["totals"];
    assert_eq!(t.supply_cents, tj["supplyCents"].as_i64().unwrap());
    assert_eq!(t.collateral_zat, tj["collateralZat"].as_i64().unwrap());
    assert_eq!(t.open_debt_cents, tj["openDebtCents"].as_i64().unwrap());
    assert_eq!(
        i64::from(t.active_vaults),
        tj["activeVaults"].as_i64().unwrap()
    );
    assert_eq!(
        i64::from(t.claimed_vaults),
        tj["claimedVaults"].as_i64().unwrap()
    );
    assert_eq!(db.yed_rules_version(), Some(RULES_VERSION));

    // A snapshot of the tip and of every height below it through the undo records.
    let snapshot = finalized_yed_snapshot(&db);
    assert_eq!(
        hex32(snapshot.state_hash()),
        g.doc["stateHash"].as_str().unwrap()
    );
    let top = Height(u32::try_from(tip.height).unwrap());
    for (h, (hash, want)) in &by_height {
        let s = finalized_yed_snapshot_below(&db, top, *h, *hash).expect("within UNDO_KEEP");
        assert_eq!(s.state_hash(), *want, "undo-record snapshot at {h:?}");
    }
    assert!(
        finalized_yed_snapshot_below(&db, top, Height(top.0 + 1), block::Hash([0; 32])).is_none()
    );

    // Restart at the tip (a snapshot holds a database handle).
    drop(snapshot);
    let entries = db.yed_canonical_entries();
    drop(db);
    let db = open_db(&config, &network);
    assert_eq!(db.yed_canonical_entries(), entries);
    assert_eq!(
        hex32(db.yed_state_hash("regtest")),
        g.doc["stateHash"].as_str().unwrap()
    );
}

/// The non-finalized path over the golden chain: every block evaluated over the parent chain's
/// overlay and pushed; the tip state and a fork-aware snapshot by every block hash equal the
/// replay; forks at several depths revert the overlay exactly and re-pushing restores it; an
/// invalid entry is judged and not pushed, and a child of a block the module rejects cannot be
/// evaluated; finalizing every root through the finalized path keeps the tip state and ends at
/// the pinned state; a checkpoint-committed copy ends in identical entries.
#[test]
fn golden_chain_reorg_finalization_and_checkpoint_path() {
    let _init_guard = zakura_test::init();
    let g = golden();
    let r = reference(&g, 1_000);
    let network = network_with(g.p);
    let dir = TempDir::new().unwrap();
    let db = open_db(&config_at(dir.path()), &network);
    let valid: Vec<&GoldenBlock> = g.blocks.iter().filter(|b| !b.invalid).collect();
    let carriers = carriers(valid.len() + 1);

    let mut chain = empty_chain();
    let mut pushed = Vec::new();
    let mut checked_child_of_invalid = false;
    for b in &g.blocks {
        let effect = chain_yed_effect(&g.p, &chain, &db, &b.input).expect("evaluates");
        if b.invalid {
            let verdict = effect.invalid.clone().expect("a flagged entry is invalid");
            // Until W5-f rejects it, a chain holding the block cannot be followed: the index did
            // not advance, so the block's child fails the tip check (U-21: stop, never skip).
            if !checked_child_of_invalid {
                checked_child_of_invalid = true;
                let side = chain
                    .clone()
                    .push(carrier_cv(&carriers[valid.len()], effect))
                    .unwrap();
                let child = YedBlockInput {
                    height: Height(b.input.height.0 + 1),
                    hash: block::Hash([0xee; 32]),
                    parent: b.input.hash,
                    txs: vec![b.input.txs[0].clone()],
                    subsidy_zat: b.input.subsidy_zat,
                };
                assert!(matches!(
                    chain_yed_effect(&g.p, &side, &db, &child),
                    Err(YedEvaluationFailed::TipMismatch { .. })
                ));
                assert!(verdict.reject_reason().starts_with("bad-yellowback-"));
            }
            continue;
        }
        let i = pushed.len();
        let cv = carrier_cv(&carriers[i], effect);
        pushed.push(cv.clone());
        chain = chain.push(cv).expect("the carrier block pushes");
        assert_eq!(
            chain_tip_yed_snapshot(&chain, &db).state_hash(),
            r.hashes[i],
            "chain tip at {:?}",
            b.input.height
        );
    }
    assert!(checked_child_of_invalid);
    let chain = Arc::new(chain);
    assert_eq!(
        hex32(chain_tip_yed_snapshot(&chain, &db).state_hash()),
        g.doc["stateHash"].as_str().unwrap()
    );
    assert_eq!(
        hex32(tip_yed_snapshot(Some(&chain), &db).state_hash()),
        g.doc["stateHash"].as_str().unwrap()
    );

    // Fork-aware snapshots by hash.
    for (i, cv) in pushed.iter().enumerate() {
        let s = yed_snapshot_by_hash([&chain], &db, cv.hash).expect("a pushed block");
        assert_eq!(s.tip, Some((cv.height, cv.hash)));
        assert_eq!(s.state_hash(), r.hashes[i], "snapshot of {i}");
        assert_eq!(
            s.index_tip().map(|t| t.block_hash),
            Some(Hash32(valid[i].input.hash.0))
        );
    }

    // Reorgs: fork at several depths, compare with the chain pushed only that far, re-push.
    let n = pushed.len();
    for depth in [1usize, 2, 7, 30, 120, n - 1] {
        let at = &pushed[n - 1 - depth];
        let mut forked = chain.fork(at.hash).expect("the chain holds the block");
        let mut short = empty_chain();
        for cv in &pushed[..n - depth] {
            short = short.push(cv.clone()).unwrap();
        }
        assert_eq!(forked.yed_overlay(), short.yed_overlay(), "depth {depth}");
        assert_eq!(
            chain_tip_yed_snapshot(&forked, &db).state_hash(),
            r.hashes[n - 1 - depth]
        );
        for cv in &pushed[n - depth..] {
            forked = forked.push(cv.clone()).unwrap();
        }
        assert_eq!(
            forked.yed_overlay(),
            chain.yed_overlay(),
            "re-pushed {depth}"
        );
    }

    // Finalization: pop every root and commit it through the finalized path, which evaluates
    // it again over the database and must reach the same delta.
    let tip_hash = chain_tip_yed_snapshot(&chain, &db).state_hash();
    let mut chain = Arc::unwrap_or_clone(chain);
    for (i, b) in valid.iter().enumerate() {
        let (root, _) = chain.pop_root();
        assert_eq!(root.hash, pushed[i].hash);
        let effect = finalized_yed_effect(&db, Some(&g.p), &b.input).expect("evaluates");
        assert_eq!(effect, *root.yed_effect, "finalized == contextual at {i}");
        commit(&db, b.input.height, b.input.hash, &effect);
        assert_eq!(db.yed_state_hash("regtest"), r.hashes[i]);
        if !chain.is_empty() {
            assert_eq!(
                chain_tip_yed_snapshot(&chain, &db).state_hash(),
                tip_hash,
                "finalizing {i} leaves the tip state"
            );
        }
    }
    assert!(chain.yed_overlay().is_empty());
    assert_eq!(finalized_yed_snapshot(&db).state_hash(), tip_hash);

    // The checkpoint path over the same range ends in identical entries.
    let dir2 = TempDir::new().unwrap();
    let checkpoint_db = open_db(&config_at(dir2.path()), &network);
    for b in &valid {
        let effect = finalized_yed_effect(&checkpoint_db, Some(&g.p), &b.input).unwrap();
        commit(&checkpoint_db, b.input.height, b.input.hash, &effect);
    }
    assert_eq!(
        checkpoint_db.yed_canonical_entries(),
        db.yed_canonical_entries()
    );
}

/// K-13: the overlay's memory at the 1,000-block window, measured on the golden chain (the
/// largest per-block delta) and on a synthetic window where every block writes its snapshot,
/// tag, tip and totals.
#[test]
fn overlay_memory_at_the_reorg_window() {
    let _init_guard = zakura_test::init();
    let g = golden();
    let network = network_with(g.p);
    let dir = TempDir::new().unwrap();
    let db = open_db(&config_at(dir.path()), &network);
    let mut overlay = ChainYedOverlay::default();
    let mut state = YedState::new();
    let mut max_delta = 0usize;
    for b in g.blocks.iter().filter(|b| !b.invalid) {
        let effect = evaluate_yed_block(&g.p, &state, &b.input).unwrap();
        let bytes: usize = effect
            .delta
            .canonical_entries()
            .iter()
            .map(|(k, (b, a))| {
                k.len() + b.as_ref().map_or(0, Vec::len) + a.as_ref().map_or(0, Vec::len)
            })
            .sum();
        max_delta = max_delta.max(bytes);
        state.apply(&effect.delta);
        overlay.push(&effect.delta);
    }
    let golden_bytes = overlay.approx_bytes();
    tracing::info!(
        "K-13 golden: {} keys / {golden_bytes} bytes over 440 blocks; max per-block delta {max_delta} bytes",
        overlay.len()
    );
    drop(db);
    // A synthetic 1,000-block window continuing the golden state's per-block records.
    let mut window = ChainYedOverlay::default();
    let base = state.clone();
    let tip = base.tip().unwrap();
    let snap = base.snapshot(u32::try_from(tip.height).unwrap()).unwrap();
    for i in 1u32..=1_000 {
        let h = u32::try_from(tip.height).unwrap() + i;
        let mut overlay = YedOverlay::new(&base);
        overlay.put_snapshot(h, snap.clone());
        overlay.put(
            YedKey::Tip,
            YedRecord::Tip(TipRecord {
                height: i32::try_from(h).unwrap(),
                ..tip.clone()
            }),
        );
        overlay.put_totals(base.totals());
        window.push(&overlay.delta());
    }
    let bytes = window.approx_bytes();
    tracing::info!(
        "K-13 synthetic: 1,000 blocks x (snapshot, tip, totals): {} keys / {bytes} bytes; golden max delta x 1,000 = {} bytes",
        window.len(),
        max_delta * 1_000
    );
    assert_eq!(window.len(), 1_002);
    assert!(bytes < 1 << 20, "a 1,000-block window stays under 1 MiB");
}

// ---- cannot evaluate ⇒ stop the node --------------------------------------------------------

/// Every failure class of `TipMatches` and `SyncToChain` is a [`YedEvaluationFailed`], never a
/// skipped block: an empty index above the start height, a parent that is not the tip, a foreign
/// schema or network, another rules stamp, other hashed parameters, unresolvable parameters.
#[test]
fn cannot_evaluate_is_a_failure_not_a_skip() {
    let _init_guard = zakura_test::init();
    let g = golden();
    let network = network_with(g.p);
    let dir = TempDir::new().unwrap();
    let db = open_db(&config_at(dir.path()), &network);

    // An empty index at a height above the start height.
    assert!(matches!(
        finalized_yed_effect(&db, Some(&g.p), &g.blocks[1].input),
        Err(YedEvaluationFailed::TipMismatch { .. })
    ));
    // Below the start height (or with Yellowback off) nothing is evaluated.
    let mut later = g.p;
    later.start_height = 10;
    assert_eq!(
        finalized_yed_effect(&db, Some(&later), &g.blocks[1].input),
        Ok(YedBlockEffect::default())
    );
    assert_eq!(
        finalized_yed_effect(&db, None, &g.blocks[0].input),
        Ok(YedBlockEffect::default())
    );

    for b in g.blocks.iter().take(5) {
        let e = finalized_yed_effect(&db, Some(&g.p), &b.input).unwrap();
        commit(&db, b.input.height, b.input.hash, &e);
    }
    let next = &g.blocks[5].input;
    assert!(finalized_yed_effect(&db, Some(&g.p), next).is_ok());

    // A parent that is not the index tip (a gap, or a sibling's child).
    let mut gap = next.clone();
    gap.height = Height(next.height.0 + 1);
    assert!(matches!(
        finalized_yed_effect(&db, Some(&g.p), &gap),
        Err(YedEvaluationFailed::TipMismatch { .. })
    ));
    let mut sibling = next.clone();
    sibling.parent = block::Hash([1; 32]);
    assert!(matches!(
        finalized_yed_effect(&db, Some(&g.p), &sibling),
        Err(YedEvaluationFailed::TipMismatch { .. })
    ));

    // Other hashed parameters (a regtest flag changed between restarts).
    let mut other = g.p;
    other.sigma_ref_bps = 1;
    assert_eq!(
        finalized_yed_effect(&db, Some(&other), next),
        Err(YedEvaluationFailed::ParamsChanged)
    );
    assert_ne!(
        ParamsRecord::of(&other).encode(),
        ParamsRecord::of(&g.p).encode()
    );

    // Another rules stamp.
    let write_raw = |cf: &str, key: Vec<u8>, value: Vec<u8>| {
        let mut batch = DiskWriteBatch::new();
        let _ = db.yed_cf(cf).with_batch_for_writing(&mut batch).zs_insert(
            &RawBytes::new_raw_bytes(key),
            &RawBytes::new_raw_bytes(value),
        );
        db.write_batch(batch).unwrap();
    };
    write_raw(YED_RULES, RULES_KEY.to_vec(), 2u32.to_le_bytes().to_vec());
    assert_eq!(
        finalized_yed_effect(&db, Some(&g.p), next),
        Err(YedEvaluationFailed::RulesVersion { stored: 2, code: 1 })
    );
    write_raw(
        YED_RULES,
        RULES_KEY.to_vec(),
        RULES_VERSION.to_le_bytes().to_vec(),
    );

    // A tip written under another schema or network.
    let tip = db.yed_tip().unwrap();
    for bad in [
        TipRecord {
            schema_version: SCHEMA_VERSION - 1,
            ..tip.clone()
        },
        TipRecord {
            network: "test".to_owned(),
            ..tip.clone()
        },
    ] {
        write_raw(
            cf_for_table(Table::Tip),
            YedKey::Tip.encode(),
            YedRecord::Tip(bad).encode(),
        );
        assert!(matches!(
            finalized_yed_effect(&db, Some(&g.p), next),
            Err(YedEvaluationFailed::Schema { .. })
        ));
    }

    // Unresolvable parameters (ycashd refuses the flags): mainnet with a regtest-only key.
    let config = YellowbackConfig {
        sigma_ref: 5,
        ..Default::default()
    };
    assert_eq!(
        yed_network_params(&Network::Mainnet, &config),
        Err("yellowback.sigma_ref is regtest-only".to_owned())
    );

    // The node-level hook stops the node: the panic carries the failure.
    let failure = finalized_yed_effect(&db, Some(&g.p), next).unwrap_err();
    let panic = catch_unwind(|| failure.stop_the_node("test")).unwrap_err();
    let message = panic.downcast_ref::<String>().unwrap();
    assert!(
        message.starts_with("Yellowback index failure (test): "),
        "{message}"
    );
}

/// The real finalized write path: `commit_finalized_direct` of the testnet vector blocks with
/// YED registered from height 1 evaluates every block in `prepare_block_batch`; the index tip
/// follows the block tip; a snapshot by every block hash reaches it through the undo records; a
/// restart keeps it; and a block the index cannot evaluate stops the writer (the panic
/// `zakurad` supervision turns into a node exit) without committing anything.
#[test]
fn real_finalized_path_evaluates_and_stops_on_failure() {
    let _init_guard = zakura_test::init();
    let network = Network::new_default_testnet();
    let p = regtest_params_with(1, 0, 0, [7u8; 32], 3, BundleCarrier::ScriptSig, false);
    register_yed_params_for_test(&network, p);
    let dir = TempDir::new().unwrap();
    let config = config_at(dir.path());
    let blocks: Vec<Arc<Block>> = network
        .blockchain_map()
        .range(0..=10)
        .map(|(_, bytes)| bytes.zcash_deserialize_into().unwrap())
        .collect();
    assert_eq!(blocks.len(), 11);

    let mut hashes = Vec::new();
    {
        let mut state = FinalizedState::new(&config, &network).unwrap();
        for (h, block) in blocks.iter().take(10).enumerate() {
            state
                .commit_finalized_direct(block.clone().into(), None, None, "yed test")
                .unwrap();
            let tip = state.db.yed_tip();
            if h == 0 {
                assert_eq!(tip, None, "genesis is below the start height");
            } else {
                let tip = tip.unwrap();
                assert_eq!(i64::from(tip.height), h as i64);
                assert_eq!(tip.block_hash, Hash32(block.hash().0));
                assert!(state.db.yed_undo(Height(h as u32)).is_some());
            }
            hashes.push(state.db.yed_state_hash("regtest"));
        }
        for (h, block) in blocks.iter().take(10).enumerate() {
            let s = yed_snapshot_by_hash([], &state.db, block.hash()).unwrap();
            assert_eq!(s.state_hash(), hashes[h], "snapshot of {h}");
            assert!(s.is_live());
        }
    }
    let entries = {
        let state = FinalizedState::new(&config, &network).unwrap();
        assert_eq!(state.db.yed_state_hash("regtest"), hashes[9], "restart");
        state.db.yed_canonical_entries()
    };

    // Tamper with the stored tip: the next block cannot be evaluated, so the writer stops.
    let mut state = FinalizedState::new(&config, &network).unwrap();
    let tip = state.db.yed_tip().unwrap();
    {
        let mut batch = DiskWriteBatch::new();
        let _ = state
            .db
            .yed_cf(cf_for_table(Table::Tip))
            .with_batch_for_writing(&mut batch)
            .zs_insert(
                &RawBytes::new_raw_bytes(YedKey::Tip.encode()),
                &RawBytes::new_raw_bytes(
                    YedRecord::Tip(TipRecord {
                        block_hash: Hash32([9; 32]),
                        ..tip.clone()
                    })
                    .encode(),
                ),
            );
        state.db.write_batch(batch).unwrap();
    }
    let block10 = blocks[10].clone();
    let panic = catch_unwind(AssertUnwindSafe(|| {
        state.commit_finalized_direct(block10.into(), None, None, "yed test")
    }))
    .expect_err("an index that cannot evaluate the block stops the writer");
    let message = panic.downcast_ref::<String>().unwrap();
    assert!(message.contains("tip-mismatch"), "{message}");
    assert_eq!(state.db.finalized_tip_height(), Some(Height(9)));
    assert_ne!(state.db.yed_canonical_entries(), entries);
}

/// The real non-finalized path: `NonFinalizedState::commit_new_chain` / `commit_block` evaluate
/// every block in `validate_and_commit` over its parent fork; a fork-aware snapshot by each hash
/// sees that block's index tip; and an index that cannot evaluate a block stops the node.
#[test]
fn real_non_finalized_path_evaluates_forks_and_stops_on_failure() {
    let _init_guard = zakura_test::init();
    let fake_pool = ValueBalance::<NonNegative>::fake_populated_pool();
    let start = 583_999;
    let network = Network::new_default_testnet();
    register_yed_params_for_test(
        &network,
        regtest_params_with(start, 0, 0, [7u8; 32], 3, BundleCarrier::ScriptSig, false),
    );
    let block1: Arc<Block> = Arc::new(network.test_block(653_599, 583_999).unwrap());
    let block2 = block1.make_fake_child().set_work(10);
    let child = block1.make_fake_child().set_work(1);

    let mut state = NonFinalizedState::new(&network);
    let finalized_state = FinalizedState::new(&Config::ephemeral(), &network).unwrap();
    finalized_state.set_finalized_value_pool(fake_pool);
    state
        .commit_new_chain(block1.clone().prepare(), &finalized_state)
        .unwrap();
    state
        .commit_block(block2.clone().prepare(), &finalized_state)
        .unwrap();
    state
        .commit_block(child.clone().prepare(), &finalized_state)
        .unwrap();

    let best = state.best_chain().unwrap();
    assert_eq!(best.tip_block().unwrap().hash, block2.hash());
    for (block, height) in [(&block1, start), (&block2, start + 1), (&child, start + 1)] {
        let s = yed_snapshot_by_hash(state.chain_iter(), &finalized_state.db, block.hash())
            .expect("a non-finalized block");
        let tip = s.index_tip().unwrap();
        assert_eq!(tip.height, height);
        assert_eq!(tip.block_hash, Hash32(block.hash().0));
    }
    let chain_block = best.blocks.values().next().unwrap();
    assert!(chain_block.yed_effect.evaluated);
    assert!(chain_block.yed_effect.invalid.is_none());
    assert!(
        best.yed_overlay().len() >= 4,
        "params, totals, seq, snapshot, tip"
    );

    // Yellowback starting one block earlier: the empty index cannot evaluate block1.
    let network = Network::new_default_testnet();
    register_yed_params_for_test(
        &network,
        regtest_params_with(
            start - 1,
            0,
            0,
            [7u8; 32],
            3,
            BundleCarrier::ScriptSig,
            false,
        ),
    );
    let mut state = NonFinalizedState::new(&network);
    let finalized_state = FinalizedState::new(&Config::ephemeral(), &network).unwrap();
    finalized_state.set_finalized_value_pool(fake_pool);
    let panic = catch_unwind(AssertUnwindSafe(|| {
        state.commit_new_chain(block1.clone().prepare(), &finalized_state)
    }))
    .expect_err("the node stops");
    let message = panic.downcast_ref::<String>().unwrap();
    assert!(message.contains("tip-mismatch"), "{message}");
}

// ---- configuration and the format upgrade -----------------------------------------------------

/// `ParamsFromArgs`: regtest takes the six keys and the Vault height; without an attestor set or
/// a Vault height Yellowback is off; mainnet and testnet refuse regtest-only keys and are off
/// (no attestor set); invalid values are refused; the TOML section parses.
#[test]
fn config_maps_to_params_as_params_from_args() {
    let _init_guard = zakura_test::init();
    let set_hex = "0eeebe67c4bc64cf5deb624972629c92b09e3362e126a3702443b192dca80f4a";
    let config: YellowbackConfig = toml::from_str(&format!(
        "attestor_set = \"{set_hex}\"\nsigma_ref = 250\nsupply_cap_bps = 100\n\
         attest_arm_min = 2\nbundle_carrier = \"either\"\nmint_requires_armed = true\n"
    ))
    .unwrap();
    let vault = 205;
    let network = Network::new_regtest(
        ConfiguredActivationHeights {
            vault: Some(vault),
            ..Default::default()
        }
        .into(),
    );
    let p = yed_network_params(&network, &config).unwrap().unwrap();
    let mut want = regtest_params_with(
        205,
        250,
        100,
        display_hash(set_hex).0,
        2,
        BundleCarrier::Either,
        true,
    );
    want.pq_falcon_height = -1; // kogany's regtest has no Falcon height (W3-c/F-1)
    want.issued_before_start = i64::from(
        zakura_chain::parameters::subsidy::expected_issued_supply(Height(vault - 1), &network)
            .unwrap(),
    );
    assert!(want.issued_before_start > 0);
    assert_eq!(p, want);

    // Off: no attestor set, or no Vault height.
    assert_eq!(
        yed_network_params(&network, &YellowbackConfig::default()),
        Ok(None)
    );
    let no_vault = Network::new_regtest(ConfiguredActivationHeights::default().into());
    assert_eq!(yed_network_params(&no_vault, &config), Ok(None));

    // Mainnet and testnet: regtest-only keys refused, and off without a released attestor set.
    assert_eq!(
        yed_network_params(&Network::Mainnet, &config),
        Err("yellowback.attestor_set is regtest-only".to_owned())
    );
    assert_eq!(
        yed_network_params(&Network::Mainnet, &YellowbackConfig::default()),
        Ok(None)
    );
    assert_eq!(
        yed_network_params(
            &Network::new_default_testnet(),
            &YellowbackConfig::default()
        ),
        Ok(None)
    );

    // ycashd's refusals.
    for (bad, message) in [
        (
            YellowbackConfig {
                attestor_set: Some("00".to_owned()),
                ..Default::default()
            },
            "yellowback.attestor_set must be a set id (64 hex characters)",
        ),
        (
            YellowbackConfig {
                attestor_set: Some("0".repeat(64)),
                ..Default::default()
            },
            "yellowback.attestor_set must not be zero",
        ),
        (
            YellowbackConfig {
                supply_cap_bps: 10_001,
                ..Default::default()
            },
            "yellowback.supply_cap_bps must be between 0 and 10000",
        ),
        (
            YellowbackConfig {
                sigma_ref: -1,
                ..Default::default()
            },
            "yellowback.sigma_ref must be >= 0",
        ),
        (
            YellowbackConfig {
                bundle_carrier: "witness".to_owned(),
                ..Default::default()
            },
            "yellowback.bundle_carrier must be scriptsig, opreturn or either",
        ),
    ] {
        assert_eq!(yed_network_params(&network, &bad), Err(message.to_owned()));
    }
    assert!(YellowbackConfig::default().is_default());
    assert!(toml::from_str::<YellowbackConfig>("unknown = 1").is_err());
}

/// The format upgrade refuses a database that holds YED-epoch blocks without their index (a
/// resync), and accepts one below the start height.
#[test]
fn format_upgrade_refuses_a_yed_epoch_without_its_index() {
    let _init_guard = zakura_test::init();
    let network = Network::new_default_testnet();
    let mut state = FinalizedState::new(&Config::ephemeral(), &network).unwrap();
    for (_, bytes) in network.blockchain_map().range(0..=3) {
        let block: Arc<Block> = bytes.zcash_deserialize_into().unwrap();
        state
            .commit_finalized_direct(block.into(), None, None, "yed test")
            .unwrap();
    }
    let tip = state.db.finalized_tip_height();
    assert_eq!(missing_yed_epoch(tip, &state.db), None, "Yellowback off");
    assert!(!state.db.has_yed_state());
    register_yed_params_for_test(
        &network,
        regtest_params_with(5, 0, 0, [7u8; 32], 3, BundleCarrier::ScriptSig, false),
    );
    assert_eq!(missing_yed_epoch(tip, &state.db), None, "below the start");
    register_yed_params_for_test(
        &network,
        regtest_params_with(2, 0, 0, [7u8; 32], 3, BundleCarrier::ScriptSig, false),
    );
    assert!(
        missing_yed_epoch(tip, &state.db).is_some(),
        "a YED epoch without its index"
    );
}

/// The undo record's serialisation round-trips, and an undo record restores the state before
/// its block byte for byte.
#[test]
fn undo_record_round_trips() {
    let g = golden();
    let mut state = YedState::new();
    for b in g.blocks.iter().filter(|b| !b.invalid).take(160) {
        let e = evaluate_yed_block(&g.p, &state, &b.input).unwrap();
        let undo = YedUndoRecord::of(b.input.height, b.input.hash, &e.delta);
        assert_eq!(YedUndoRecord::decode(&undo.encode()), Some(undo.clone()));
        let before = state.canonical_entries();
        state.apply(&e.delta);
        let mut restored = state.canonical_entries();
        for (k, v) in undo.before {
            match v {
                Some(v) => restored.insert(k, v),
                None => restored.remove(&k),
            };
        }
        assert_eq!(restored, before, "{:?}", b.input.height);
    }
    assert_eq!(YedUndoRecord::decode(&[0u8; 35]), None);
}

// ---- the C++ undo cases over the store ------------------------------------------------------

use fixture::{
    fake_hash, mv, none_skip, op, spend, EmergencyFixture, Fixture, MintOpts, SpendOpts,
};
use kogany_yellowback::{attest::registry::AttestorStatus, codecs::payload::Assignment};

/// The fixture's chain mirrored into the store: every applied block's delta committed to a
/// RocksDB finalized state (with its undo record) and pushed onto a `Chain` over an empty one.
struct Mirror {
    _dirs: (TempDir, TempDir),
    fin: ZakuraDb,
    nf_db: ZakuraDb,
    chain: Chain,
    carriers: Vec<Arc<Block>>,
    /// (fixture height, the pushed block).
    pushed: Vec<(i64, ContextuallyVerifiedBlock)>,
    /// The finalized state's highest committed height.
    fin_tip: i64,
}

impl Mirror {
    fn new(p: Params) -> Mirror {
        let network = network_with(p);
        let (d1, d2) = (TempDir::new().unwrap(), TempDir::new().unwrap());
        let fin = open_db(&config_at(d1.path()), &network);
        let nf_db = open_db(&config_at(d2.path()), &network);
        Mirror {
            _dirs: (d1, d2),
            fin,
            nf_db,
            chain: empty_chain(),
            carriers: carriers(1_200),
            pushed: Vec::new(),
            fin_tip: 0,
        }
    }

    /// Mirrors every block the fixture applied above the chain's tip.
    fn sync(&mut self, f: &Fixture) {
        let from = self.pushed.last().map_or(0, |(h, _)| *h);
        for (h, delta) in f.deltas.range(from + 1..) {
            let effect = YedBlockEffect {
                evaluated: true,
                delta: delta.clone(),
                invalid: None,
            };
            let height = Height(u32::try_from(*h).unwrap());
            if *h > self.fin_tip {
                commit(&self.fin, height, block::Hash(fake_hash(*h).0), &effect);
                self.fin_tip = *h;
            }
            let cv = carrier_cv(&self.carriers[self.pushed.len()], effect);
            self.chain = self.chain.clone().push(cv.clone()).unwrap();
            self.pushed.push((*h, cv));
        }
    }

    /// Pops the chain's tip (a reorg).
    fn pop(&mut self) {
        self.pushed.pop().unwrap();
        self.chain = match self.pushed.last() {
            Some((_, cv)) => self.chain.fork(cv.hash).unwrap(),
            None => empty_chain(),
        };
    }

    /// The chain's view and the finalized undo-record snapshot at the fixture's tip both hold
    /// exactly the fixture's state.
    fn assert_matches(&self, f: &Fixture) {
        let want = f.state.canonical_entries();
        let view =
            kogany_yellowback::state::canonical_entries_of(&self.chain.yed_view(&self.nf_db));
        assert_eq!(view, want, "chain view at {}", f.tip);
        let below = finalized_yed_snapshot_below(
            &self.fin,
            Height(u32::try_from(self.fin_tip).unwrap()),
            Height(u32::try_from(f.tip.max(0)).unwrap()),
            block::Hash(fake_hash(f.tip).0),
        )
        .unwrap();
        assert_eq!(
            below.canonical_entries(),
            want,
            "undo-record snapshot at {}",
            f.tip
        );
    }
}

fn hash_of(r: &dyn YedRead) -> String {
    hex32(state_hash(r, "regtest"))
}

/// `apply_undo_identity_over_sequences`: checkpoints along a full lifecycle; undoing every block
/// through the store returns to each checkpoint and to the empty state; re-applying the same
/// blocks reproduces the chain; a fresh replay of the prefix reproduces its deltas.
#[test]
fn apply_undo_identity_over_sequences() {
    let _init_guard = zakura_test::init();
    let mut f = Fixture::new();
    let mut hashes = vec![hash_of(&f.state)];
    f.mine_quotes_to(131, 50000);
    let v = f.mint_active10k();
    hashes.push(hash_of(&f.state));
    let t = f.transfer_tx(
        &[op(v, 1)],
        &[Assignment::new(0, 6000), Assignment::new(1, 4000)],
        false,
        0,
    );
    f.mine(Some(Fixture::quote(50000, 1)), vec![t.clone()]);
    hashes.push(hash_of(&f.state));
    let w = f.mint_active10k();
    hashes.push(hash_of(&f.state));
    let bad = f.mint_tx(5000, 48, f.tip - 1, MintOpts::default());
    f.mine(Some(Fixture::quote(50000, 2)), vec![bad]);
    hashes.push(hash_of(&f.state));
    let s = f.spend_tx(
        &w,
        &[op(t.txid(), 0), op(w, 1)],
        f.tip,
        SpendOpts::default(),
    );
    let r = spend(&mut f, &w, &s);
    assert_eq!(r.verdict, kogany_yellowback::state::verdict::OK);
    hashes.push(hash_of(&f.state));
    for i in 0..40 {
        let tag = Fixture::quote_with(50000, (f.tip + 1) % 3, i % 2 == 0, 7);
        f.mine(Some(tag), Vec::new());
    }
    let top = f.tip;

    let mut m = Mirror::new(f.p);
    m.sync(&f);
    m.assert_matches(&f);
    let full_overlay = m.chain.yed_overlay().clone();
    let all = m.pushed.clone();
    while f.tip >= 1 {
        f.undo();
        m.pop();
        m.assert_matches(&f);
        if f.tip == top - 40 - 1 {
            assert_eq!(hash_of(&m.chain.yed_view(&m.nf_db)), hashes[4]);
        }
    }
    assert!(f.state.entries.is_empty());
    assert!(m.chain.yed_overlay().is_empty());
    assert_eq!(hash_of(&m.chain.yed_view(&m.nf_db)), hashes[0]);

    // Re-apply the same blocks: the same overlay.
    for (_, cv) in &all {
        m.chain = m.chain.clone().push(cv.clone()).unwrap();
    }
    assert_eq!(m.chain.yed_overlay(), &full_overlay);
    // Every block again from scratch gives the same deltas (SNAP is a pure function of the chain).
    let mut g2 = Fixture::new();
    g2.mine_quotes_to(131, 50000);
    let v2 = g2.mint_active10k();
    assert_eq!(v2, v);
    for (h, d) in &g2.deltas {
        assert_eq!(
            Some(d),
            all.iter()
                .find(|(x, _)| x == h)
                .map(|(_, cv)| &cv.yed_effect.delta)
        );
    }
}

/// `p_mint_persists_through_undo_and_reapply` (FEE-1′): a mint evaluated over the store records
/// its mint price; the undo (a chain revert, and the stored undo record) removes it byte for
/// byte; re-applying gives the same record and the same undo bytes.
#[test]
fn p_mint_persists_through_undo_and_reapply() {
    let _init_guard = zakura_test::init();
    let mut f = Fixture::new();
    f.activate(50000);
    let mut m = Mirror::new(f.p);
    m.sync(&f);
    let h = f.tip + 1;
    let mint = f.mint_tx(10000, 48, f.tip - 1, MintOpts::default());
    let txid = mint.txid();
    let mut txs = vec![Fixture::coinbase(h, Some(&Fixture::quote(50000, 0))).tx()];
    txs.push(mint.tx());
    let input = YedBlockInput {
        height: Height(u32::try_from(h).unwrap()),
        hash: block::Hash(fake_hash(h).0),
        parent: block::Hash(fake_hash(f.tip).0),
        txs,
        subsidy_zat: fixture::SUBSIDY,
    };
    let before = kogany_yellowback::state::canonical_entries_of(&m.chain.yed_view(&m.nf_db));
    let e1 = chain_yed_effect(&f.p, &m.chain, &m.nf_db, &input).unwrap();
    assert!(e1.invalid.is_none());
    let cv = carrier_cv(&m.carriers[m.pushed.len()], e1.clone());
    let pushed = m.chain.clone().push(cv).unwrap();
    let vault = pushed.yed_view(&m.nf_db).vault(&op(txid, 0)).unwrap();
    assert_eq!(vault.p_mint, 50000);
    assert_eq!(vault.p_mint, f.pmint_at(f.tip - 1));
    // undo: the chain without the block
    assert!(m.chain.yed_view(&m.nf_db).vault(&op(txid, 0)).is_none());
    assert_eq!(
        kogany_yellowback::state::canonical_entries_of(&m.chain.yed_view(&m.nf_db)),
        before
    );
    // the finalized store: commit, then the undo record restores the state before it
    commit(&m.fin, input.height, input.hash, &e1);
    let undo = m.fin.yed_undo(input.height).unwrap();
    assert_eq!(
        undo.encode(),
        YedUndoRecord::of(input.height, input.hash, &e1.delta).encode()
    );
    let restored = finalized_yed_snapshot_below(
        &m.fin,
        input.height,
        Height(input.height.0 - 1),
        input.parent,
    )
    .unwrap();
    assert_eq!(restored.canonical_entries(), before);
    // re-apply: the same record and the same undo bytes
    let e2 = chain_yed_effect(&f.p, &m.chain, &m.nf_db, &input).unwrap();
    assert_eq!(
        YedUndoRecord::of(input.height, input.hash, &e2.delta).encode(),
        undo.encode()
    );
    assert_eq!(e2, e1);
}

/// `overlay_view_equivalence` (SNAP): a valid redeem evaluated over two nested overlays over the
/// store gives the same delta and snapshot as over the fixture's state; committed, the vault is
/// CLOSED.
#[test]
fn overlay_view_equivalence() {
    let _init_guard = zakura_test::init();
    let mut f = Fixture::new();
    f.activate(50000);
    let v = f.mint_active10k();
    let mut m = Mirror::new(f.p);
    m.sync(&f);
    let h = f.tip + 1;
    let redeem = f.spend_tx(&v, &[op(v, 1)], f.tip, SpendOpts::default());
    let mut txs = vec![Fixture::coinbase(h, Some(&Fixture::quote(50000, 0))).tx()];
    txs.push(redeem.tx());
    let view = m.chain.yed_view(&m.nf_db);
    let outer = YedOverlay::new(&view);
    let inner = YedOverlay::new(&outer);
    let a = evaluate_block(&inner, &f.p, &txs, h, &fake_hash(h), fixture::SUBSIDY, None);
    let b = evaluate_block(
        &f.state,
        &f.p,
        &txs,
        h,
        &fake_hash(h),
        fixture::SUBSIDY,
        None,
    );
    assert!(!a.block_invalid);
    assert_eq!(a.delta, b.delta);
    assert_eq!(a.snapshot, b.snapshot);
    let cv = carrier_cv(
        &m.carriers[m.pushed.len()],
        YedBlockEffect {
            evaluated: true,
            delta: a.delta.clone(),
            invalid: None,
        },
    );
    let chain = m.chain.clone().push(cv).unwrap();
    let after = chain.yed_view(&m.nf_db);
    assert_eq!(after.vault(&op(v, 0)).unwrap().status, VaultStatus::Closed);
    assert_eq!(
        after.snapshot(u32::try_from(h).unwrap()).unwrap().encode(),
        a.snapshot.encode()
    );
    assert_eq!(
        kogany_yellowback::state::canonical_entries_of(&after),
        f.state.with(&b.delta).canonical_entries()
    );
}

/// `undo_identity_v3`: a sequence touching every v3 table (a notice, an emergency claim, an
/// equivocation, S15 dormancy, a refused revival and a heartbeat revival, two bond spends),
/// mirrored into the store and undone block by block back to the empty state through the store.
#[test]
fn undo_identity_v3() {
    let _init_guard = zakura_test::init();
    let mut g = EmergencyFixture::new(64);
    let mut hashes = Vec::new();
    assert!(g.post_notice(None));
    hashes.push(hash_of(&g.f.state));
    for _ in 0..=g.f.p.emergency_persist {
        g.tick();
    }
    {
        let residual = g.residual(g.f.tip - 1);
        let c = g.claim(
            SpendOpts {
                residual_value: Some(residual),
                ..SpendOpts::default()
            },
            None,
        );
        assert_eq!(g.mine(&c).verdict, kogany_yellowback::state::verdict::OK);
    }
    hashes.push(hash_of(&g.f.state));
    {
        let cited = g.f.tip;
        g.tick();
        let (a, b) = (
            g.f.att(0, 11500, cited, None),
            g.f.att(0, 11600, cited, None),
        );
        let e = g.f.equivocation_tx(&a, &b);
        assert_eq!(
            fixture::verdict_of(&mut g.f, &e),
            kogany_yellowback::state::verdict::OK
        );
    }
    for _ in 0..g.f.p.dormancy_blocks {
        g.tick();
    }
    let f = &mut g.f;
    let pool = g.pool_price;
    let quote = |f: &Fixture| Some(Fixture::quote(pool, (f.tip + 1) % 3));
    let mut l: Option<u16> = None;
    let mut rows = 0;
    while rows < f.p.dormancy_min_bundles {
        let r = f.tip - 1;
        let sel = f.selected(r, &[]);
        if sel.len() < 3 {
            let t = quote(f);
            f.mine(t, Vec::new());
            continue;
        }
        let ll = *l.get_or_insert(sel[0]);
        if sel.contains(&ll) {
            let skip: std::collections::BTreeSet<u16> = [ll].into_iter().collect();
            let o = MintOpts {
                attest_payee: -1,
                term_class: 2,
                ..MintOpts::default()
            };
            let m = f.mint_v3(10000, pool, o, &skip, 145);
            let v = mv(f, &m);
            assert!(
                v.is_empty() || v == "mint-halted-global-ratio" || v == "mint-halted-divergence",
                "{v}"
            );
            if f.bundle_row(f.tip).is_some() {
                rows += 1;
            }
        } else {
            let t = quote(f);
            f.mine(t, Vec::new());
        }
    }
    let l = l.unwrap();
    while f.tip % i64::from(f.p.dormancy_check) != 0
        || f.tip - i64::from(f.p.dormancy_blocks) < i64::from(f.attestor(l).unwrap().seated_since)
    {
        let t = quote(f);
        f.mine(t, Vec::new());
    }
    assert_eq!(f.attestor(l).unwrap().status, AttestorStatus::Dormant);
    let a = f.att(usize::from(l), pool, f.tip, None);
    let rv = f.revive_tx(&a);
    assert_eq!(
        fixture::verdict_of(f, &rv),
        kogany_yellowback::state::verdict::ATTESTOR_REVIVE_RETIRED
    );
    let hb = f.heartbeat_tx(usize::from(l));
    assert_eq!(
        fixture::verdict_of(f, &hb),
        kogany_yellowback::state::verdict::OK
    );
    assert_eq!(f.attestor(l).unwrap().status, AttestorStatus::Eligible);
    hashes.push(hash_of(&f.state));
    while f.tip < i64::from(f.attestor(2).unwrap().bond_locktime) {
        let t = quote(f);
        f.mine(t, Vec::new());
    }
    let s2 = f.bond_spend_tx(2);
    assert_eq!(
        fixture::verdict_of(f, &s2),
        kogany_yellowback::state::verdict::OK
    );
    let s0 = f.bond_spend_tx(0);
    assert_eq!(
        fixture::verdict_of(f, &s0),
        kogany_yellowback::state::verdict::OK
    );
    hashes.push(hash_of(&f.state));
    assert_eq!(hashes.len(), 4);

    let mut m = Mirror::new(f.p);
    m.sync(f);
    m.assert_matches(f);
    while f.tip >= 1 {
        f.undo();
        m.pop();
        m.assert_matches(f);
    }
    assert!(f.state.entries.is_empty());
    assert!(m.chain.yed_overlay().is_empty());
}

/// `overlay_equivalence_v3` (SNAP, BUNDLE-1): one block with a registration, an emergency claim
/// with a bundle, an equivocation and a bundled mint, evaluated over nested overlays over the
/// store, equals the evaluation over the fixture's state; the store's revert restores the state
/// before it byte for byte.
#[test]
fn overlay_equivalence_v3() {
    let _init_guard = zakura_test::init();
    let mut g = EmergencyFixture::new(64);
    assert!(g.post_notice(None));
    for _ in 0..=g.f.p.emergency_persist {
        g.tick();
    }
    let residual = g.residual(g.f.tip - 1);
    let cited = g.f.tip - 1;
    let h = g.f.tip + 1;
    let reg =
        g.f.register_tx(5, 10 * kogany_yellowback::params::COIN, -1, None);
    let claim = g.claim(
        SpendOpts {
            residual_value: Some(residual),
            ..SpendOpts::default()
        },
        None,
    );
    let (a1, a2) = (
        g.f.att(1, 11500, cited, None),
        g.f.att(1, 11600, cited, None),
    );
    let eqv = g.f.equivocation_tx(&a1, &a2);
    let mint = g.f.mint_v3(
        10000,
        g.pool_price,
        MintOpts {
            term_class: 2,
            ..MintOpts::default()
        },
        &none_skip(),
        145,
    );
    let mut txs = vec![Fixture::coinbase(h, Some(&Fixture::quote(g.pool_price, 0))).tx()];
    txs.extend([reg.tx(), claim.tx(), eqv.tx(), mint.tx()]);

    let mut m = Mirror::new(g.f.p);
    m.sync(&g.f);
    let view = m.chain.yed_view(&m.nf_db);
    let outer = YedOverlay::new(&view);
    let inner = YedOverlay::new(&outer);
    let a = evaluate_block(
        &inner,
        &g.f.p,
        &txs,
        h,
        &fake_hash(h),
        fixture::SUBSIDY,
        None,
    );
    let b = evaluate_block(
        &g.f.state,
        &g.f.p,
        &txs,
        h,
        &fake_hash(h),
        fixture::SUBSIDY,
        None,
    );
    assert!(!a.block_invalid, "{}", a.reason);
    assert_eq!(a.txlogs.len(), 4);
    assert_eq!(a.txlogs[1].1.verdict, kogany_yellowback::state::verdict::OK);
    assert_eq!(a.txlogs[1].1.claim_path, "b");
    assert_eq!(a.delta, b.delta);
    assert_eq!(a.snapshot, b.snapshot);

    let before = kogany_yellowback::state::canonical_entries_of(&view);
    let cv = carrier_cv(
        &m.carriers[m.pushed.len()],
        YedBlockEffect {
            evaluated: true,
            delta: a.delta.clone(),
            invalid: None,
        },
    );
    let parent_hash = m.pushed.last().unwrap().1.hash;
    let chain = m.chain.clone().push(cv).unwrap();
    let after = chain.yed_view(&m.nf_db);
    assert!(
        after.get(&YedKey::Attestor(4)).is_some(),
        "the fifth registration takes seq 4"
    );
    assert_eq!(kogany_yellowback::state::view::next_seq_of(&after), 5);
    assert!(matches!(
        after.get(&YedKey::Attestor(1)),
        Some(YedRecord::Attestor(r)) if r.status == AttestorStatus::Ejected
    ));
    assert!(after.bundle_log(u32::try_from(h).unwrap()).is_some());
    // undo restores the pre-block view byte for byte
    let reverted = chain.fork(parent_hash).unwrap();
    assert_eq!(
        kogany_yellowback::state::canonical_entries_of(&reverted.yed_view(&m.nf_db)),
        before
    );
    assert_eq!(before, g.f.state.canonical_entries());
}

/// `MempoolCheckLocked` over a snapshot: a transaction the module makes invalid at the next
/// height is refused with its verdict, a valid one is admitted, and with Yellowback off nothing
/// is checked.
#[test]
fn mempool_check_over_the_tip_snapshot() {
    let _init_guard = zakura_test::init();
    let g = golden();
    let network = network_with(g.p);
    let dir = TempDir::new().unwrap();
    let db = open_db(&config_at(dir.path()), &network);
    let first_invalid = g.blocks.iter().position(|b| b.invalid).unwrap();
    for b in g.blocks[..first_invalid].iter() {
        let e = finalized_yed_effect(&db, Some(&g.p), &b.input).unwrap();
        commit(&db, b.input.height, b.input.hash, &e);
    }
    let bad = &g.blocks[first_invalid];
    let good = &g.blocks[first_invalid + 1];
    assert_eq!(bad.input.height, good.input.height);
    let snapshot = finalized_yed_snapshot(&db);
    assert!(snapshot.is_live());
    let refused: Vec<String> = bad.input.txs[1..]
        .iter()
        .filter_map(|tx| snapshot.mempool_check(tx, 0))
        .collect();
    assert_eq!(refused, vec!["bad-mint-amount".to_owned()]);
    for tx in &good.input.txs {
        assert_eq!(snapshot.mempool_check(tx, 0), None);
    }
    assert_eq!(snapshot.attested_fee_price(), {
        let s = snapshot
            .snapshot_at(i64::from(snapshot.index_tip().unwrap().height))
            .unwrap();
        kogany_yellowback::attest::price::attested_fee_price(
            s.pfast(),
            s.pmid(),
            s.pslow(),
            s.halt_mask,
        )
    });
    let off = Network::new_regtest(ConfiguredActivationHeights::default().into());
    let off_dir = TempDir::new().unwrap();
    let off_db = open_db(&config_at(off_dir.path()), &off);
    let off_snapshot = finalized_yed_snapshot(&off_db);
    assert!(!off_snapshot.is_live());
    assert_eq!(off_snapshot.mempool_check(&bad.input.txs[1], 0), None);
    assert_eq!(off_snapshot.attested_fee_price(), None);
}

/// W5-f exit gate (1): the golden chain through the registered module. Every one of the 462
/// entries is evaluated over the parent chain's index state as contextual validation evaluates
/// it, and judged by `check::yed::yed_verdict`, the rejection `validate_and_commit` applies: the
/// 22 flagged entries are refused with `ValidateContextError::YedRejected`
/// (`bad-yellowback-<verdict>`, the C++ verdicts in order, misbehaviour score 100) and never
/// pushed; the 440 others are accepted and pushed. The tip's state hash and `Totals` equal the
/// pinned `stateHash` and `totals`, and the state hash equals the in-memory replay at every
/// height.
#[test]
fn golden_chain_through_the_registered_module_rejects_at_dos_100() {
    use crate::{service::check::yed::yed_verdict, CommitBlockError, ValidateContextError};

    let _init_guard = zakura_test::init();
    let g = golden();
    let r = reference(&g, 1_000);
    let network = network_with(g.p);
    let dir = TempDir::new().unwrap();
    let db = open_db(&config_at(dir.path()), &network);
    let valid = g.blocks.iter().filter(|b| !b.invalid).count();
    let carriers = carriers(valid);

    let mut chain = empty_chain();
    let mut accepted = 0usize;
    let mut rejected = Vec::new();
    for b in &g.blocks {
        let effect = chain_yed_effect(&g.p, &chain, &db, &b.input).expect("evaluates");
        let cv = carrier_cv(&carriers[accepted.min(valid - 1)], effect.clone());
        match yed_verdict(effect, &cv) {
            Err(error) => {
                assert!(b.invalid, "{:?} rejected: {error}", b.input.height);
                let ValidateContextError::YedRejected { reason, .. } = &error else {
                    panic!("a YED verdict is YedRejected: {error}");
                };
                rejected.push((b.input.height.0, reason.clone()));
                let commit_error = CommitBlockError::from(Box::new(error));
                assert_eq!(commit_error.misbehavior_score(), 100, "DoS 100");
            }
            Ok(effect) => {
                assert!(!b.invalid, "{:?} accepted", b.input.height);
                chain = chain
                    .push(carrier_cv(&carriers[accepted], effect))
                    .expect("the carrier block pushes");
                assert_eq!(
                    chain_tip_yed_snapshot(&chain, &db).state_hash(),
                    r.hashes[accepted],
                    "chain tip at {:?}",
                    b.input.height
                );
                accepted += 1;
            }
        }
    }
    assert_eq!(accepted, 440);
    let want: Vec<(u32, String)> = GOLDEN_INVALID
        .iter()
        .map(|(h, v)| (*h, format!("bad-yellowback-{v}")))
        .collect();
    assert_eq!(rejected, want);
    let snapshot = chain_tip_yed_snapshot(&chain, &db);
    assert_eq!(
        hex32(snapshot.state_hash()),
        g.doc["stateHash"].as_str().unwrap()
    );
    let t = snapshot.totals();
    let want = &g.doc["totals"];
    assert_eq!(t.supply_cents, want["supplyCents"].as_i64().unwrap());
    assert_eq!(t.collateral_zat, want["collateralZat"].as_i64().unwrap());
    assert_eq!(i64::from(t.active_vaults), want["activeVaults"].as_i64().unwrap());
    assert_eq!(i64::from(t.void_vaults), want["voidVaults"].as_i64().unwrap());
    assert_eq!(i64::from(t.closed_vaults), want["closedVaults"].as_i64().unwrap());
    assert_eq!(i64::from(t.claimed_vaults), want["claimedVaults"].as_i64().unwrap());
    assert_eq!(t.unbacked_cents, want["unbackedCents"].as_i64().unwrap());
    assert_eq!(t.open_debt_cents, want["openDebtCents"].as_i64().unwrap());
}
