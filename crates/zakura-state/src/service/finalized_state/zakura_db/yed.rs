//! The Ycash Yellowback (YED) index in the finalized database (kogany plan W5-e, U-21, M24-13,
//! M24-16).
//!
//! ycash6 keeps the module's state in its own LevelDB (`src/yellowback/index.*`): the §3.6
//! tables, an undo record per block kept `UNDO_KEEP` (4,096) deep under `U`, and the node-local
//! rules stamp `R`; `SyncToChain` wipes and rebuilds it from the chain when the schema, the rules
//! version, the network or the hashed parameters differ, and walks it back by undo after a crash.
//! Since U-21 that state is consensus: `ConnectBlock` rejects a block the module judges invalid
//! (`DoS(100)`) and **aborts the node** when the index cannot evaluate the block
//! (`ycash6/src/main.cpp:4358`, `AbortNode(state, "Yellowback index failure: …")`).
//!
//! Zakura has one RocksDB write path for checkpointed and finalized blocks
//! (`prepare_block_batch`) and keeps reorgs in memory. So here:
//!
//! - every table lives in its own column family, `yed_<table>` ([`YED_TABLE_COLUMN_FAMILIES`]),
//!   keyed by the **canonical key** ([`YedKey::encode`], prefix byte included) and holding the
//!   **canonical value** ([`YedRecord::encode`], the C++ SER_DISK bytes), so a plain scan in
//!   [`Table::HASHED`] order is the `yed_getstatehash` preimage; the undo `U` ([`YED_UNDO`]) and
//!   the rules stamp `R` ([`YED_RULES`]) are node-local and never hashed;
//! - the block's evaluation is **computed** inside `prepare_block_batch`
//!   ([`DiskWriteBatch::prepare_yed_batch`]) for checkpoint and finalized commits alike, in the
//!   same atomic batch as the block (so the index can never drift from the chain, and nothing
//!   like `SyncToChain`'s walk-back is needed);
//! - **cannot evaluate ⇒ stop the node** ([`YedEvaluationFailed`]): an index whose tip is not
//!   the block's parent, whose schema, rules stamp, network or parameters differ from this
//!   binary's, or whose parameters cannot be resolved, stops the block writer (a panic in the
//!   block write task, which `zakurad` supervises and turns into a node exit). ycash6 rebuilds
//!   such an index from its block files; kogany has no in-place rebuild, so the message asks for
//!   a resync (as the vault state's K-14 refusal does).
//!
//! **The asymmetry with the vault transition** (`zakura_db/vault.rs`): the vault transition is
//! total — a rejected act at this layer is logged and skipped — because ycash6 decides vault
//! validity per transaction against the parent's set state (`ConnectBlock` → `ApplyBlock`, a
//! `DoS(100)` verdict that kogany's contextual validation reproduces before a block reaches the
//! write path, and checkpoints never cover the Vault epoch, K-9). The YED index has a second
//! failure class with no vault counterpart: the index itself can be unable to judge the block
//! (out of step, foreign schema or rules, unreadable). ycash6 does not reject the block then — it
//! cannot know whether the block is valid — and does not skip it either (a skipped YED block
//! leaves every later state hash wrong); it stops the node (U-21: "an index that cannot evaluate
//! the block stops the node"). kogany does the same. A *verdict* (the block is invalid under the
//! module) is not a failure to evaluate: it is exposed in [`YedBlockEffect::invalid`] for W5-f,
//! which registers the module and turns it into a `DoS(100)` rejection in contextual
//! validation. Until then the index does not follow a chain that holds such a block: the
//! finalized path refuses to commit it, and the block's children fail the tip check.

use std::collections::BTreeMap;

use kogany_vault::{state::VaultTx, Hash32};
use kogany_yellowback::{
    params::Params,
    state::{
        evaluate_block, state_hash, ParamsRecord, Table, TipRecord, YedDelta, YedKey, YedRead,
        YedRecord, SCHEMA_VERSION,
    },
};
use zakura_chain::{
    block::{self, Block, Height},
    parameters::{subsidy::halving_block_subsidy, Network},
    transaction,
};

use crate::{
    request::FinalizedBlock,
    service::finalized_state::{
        disk_db::DiskWriteBatch, disk_format::RawBytes, vault::vault_txs, zakura_db::ZakuraDb,
        TypedColumnFamily,
    },
};

pub use crate::service::yed::YellowbackConfig;

// ---- column families --------------------------------------------------------------------

/// The table column families, one per [`Table`], in [`Table`] (key-prefix) order.
pub const YED_TABLE_COLUMN_FAMILIES: [(Table, &str); 17] = [
    (Table::Attestor, "yed_attestor"),
    (Table::BondIndex, "yed_bond_index"),
    (Table::Notice, "yed_notice"),
    (Table::Totals, "yed_totals"),
    (Table::Intent, "yed_intent"),
    (Table::Judgement, "yed_judgement"),
    (Table::Token, "yed_token"),
    (Table::TxLog, "yed_txlog"),
    (Table::Attest, "yed_attest"),
    (Table::AttestorSeq, "yed_attestor_seq"),
    (Table::Params, "yed_params"),
    (Table::Tag, "yed_tag"),
    (Table::Snapshot, "yed_snapshot"),
    (Table::Tip, "yed_tip"),
    (Table::Vault, "yed_vault"),
    (Table::BundleLog, "yed_bundle_log"),
    (Table::AttestorSet, "yed_attestor_set"),
];

/// The undo table `U` (node-local, not hashed): `u32 height` (big-endian) → the block's hash and
/// its undo record (every key it wrote with the value before it), kept [`UNDO_KEEP`] deep.
pub const YED_UNDO: &str = "yed_undo";

/// The rules stamp `R` (node-local, not hashed): the [`RULES_VERSION`] the stored heights were
/// judged under.
pub const YED_RULES: &str = "yed_rules";

/// Every YED column family: the 17 tables, then `U` and `R`.
pub const YED_COLUMN_FAMILIES: [&str; 19] = [
    "yed_attestor",
    "yed_bond_index",
    "yed_notice",
    "yed_totals",
    "yed_intent",
    "yed_judgement",
    "yed_token",
    "yed_txlog",
    "yed_attest",
    "yed_attestor_seq",
    "yed_params",
    "yed_tag",
    "yed_snapshot",
    "yed_tip",
    "yed_vault",
    "yed_bundle_log",
    "yed_attestor_set",
    YED_UNDO,
    YED_RULES,
];

/// ycash6 `RULES_VERSION` (`src/yellowback/view.h:99`): bumped by a release that changes how
/// stored heights are judged without changing any record's bytes.
pub const RULES_VERSION: u32 = 1;

/// ycash6 `UNDO_KEEP` (`src/yellowback/index.h:71`): how many blocks below the finalized tip keep
/// their undo record (and so a [`crate::service::yed::YedSnapshot`] by hash).
pub const UNDO_KEEP: u32 = 4_096;

/// The key of the rules stamp in [`YED_RULES`].
const RULES_KEY: [u8; 1] = *b"R";

/// The column family of a table.
pub fn cf_for_table(table: Table) -> &'static str {
    YED_TABLE_COLUMN_FAMILIES
        .iter()
        .find(|(t, _)| *t == table)
        .map(|(_, name)| *name)
        .expect("every table has a column family")
}

/// A YED column family handle: raw canonical keys to raw canonical values.
type YedCf<'cf> = TypedColumnFamily<'cf, RawBytes, RawBytes>;

// ---- the parameters ---------------------------------------------------------------------

/// The YED parameters of `network` under `config` (ycash6 `ParamsFromArgs`,
/// `src/yellowback/index.cpp:1134`), `Ok(None)` when Yellowback is off there: no `UPGRADE_VAULT`
/// height, or no YED attestor set (U-22; mainnet and testnet have none until the gate-passing
/// release, P8). `Err` for a configuration ycashd refuses to start with.
///
/// - `start_height` is the Vault activation height ([`Network::vault_activation_height`]);
/// - mainnet and testnet use `MainParams`/`TestParams` and refuse every regtest-only key; regtest
///   uses `RegtestParams` with [`YellowbackConfig`]'s six keys;
/// - `pq_falcon_height` is ycash6 `PQFalconHeightOf`: the later of the Vault height and the Falcon
///   height, `-1` when either never activates, with kogany's Falcon height
///   (`zakura_script::ycash::pq_falcon_height`: 0 off regtest, none on regtest);
/// - `issued_before_start` is `CirculatingSupplyAt(start - 1)` (D-Q-25), Zakura's
///   [`expected_issued_supply`](zakura_chain::parameters::subsidy::expected_issued_supply).
///
/// Tests may register exact parameters per network instance
/// ([`register_yed_params_for_test`]); they take precedence.
pub fn yed_network_params(
    network: &Network,
    config: &YellowbackConfig,
) -> Result<Option<Params>, String> {
    #[cfg(any(test, feature = "proptest-impl"))]
    if let Some(params) = test_params::lookup(network) {
        return Ok(Some(params));
    }
    let start = network.vault_activation_height();
    let mut p = if network.is_regtest() {
        let set_id = config.attestor_set_id()?;
        kogany_yellowback::params::regtest_params_with(
            0,
            config.sigma_ref_i32(),
            config.supply_cap_bps_i32(),
            set_id.unwrap_or([0u8; 32]),
            config.attest_arm_min_i32(),
            config.bundle_carrier()?,
            config.mint_requires_armed,
        )
    } else {
        if let Some(key) = config.regtest_only_key_set() {
            return Err(format!("yellowback.{key} is regtest-only"));
        }
        match network {
            Network::Mainnet => kogany_yellowback::params::main_params(),
            // kogany has no testnet-yb-fast profile selector yet: the testnet column (mainnet's
            // values), as ycash6's testnet-yb-slow and testnet-legacy.
            Network::Testnet(_) => kogany_yellowback::params::test_params(),
        }
    };
    config.validate()?;
    let Some(start) = start else {
        return Ok(None);
    };
    if p.attestor_set_id == [0u8; 32] {
        return Ok(None);
    }
    p.start_height = i32::try_from(start.0).map_err(|_| "the Vault height is out of range")?;
    // PQFalconHeightOf: max(vault, falcon), or -1 when Falcon never activates.
    p.pq_falcon_height = if network.is_regtest() {
        -1
    } else {
        p.start_height
    };
    p.issued_before_start = match start.previous() {
        Ok(before) if start.0 > 0 => {
            zakura_chain::parameters::subsidy::expected_issued_supply(before, network)
                .map(i64::from)
                .map_err(|e| format!("the circulating supply before the Vault height: {e}"))?
        }
        _ => 0,
    };
    Ok(p.is_configured().then_some(p))
}

/// Registers exact YED parameters for one test network instance (matched by identity of its
/// parameters, so other tests' networks are unaffected).
#[cfg(any(test, feature = "proptest-impl"))]
pub fn register_yed_params_for_test(network: &Network, params: Params) {
    test_params::register(network, params)
}

#[cfg(any(test, feature = "proptest-impl"))]
mod test_params {
    use std::sync::{Arc, Mutex};

    use kogany_yellowback::params::Params;
    use zakura_chain::parameters::Network;

    /// Registered (network, params); the network clone keeps its `Arc` alive, so a pointer is
    /// never reused by another network while it is registered.
    static REGISTERED: Mutex<Vec<(Network, Params)>> = Mutex::new(Vec::new());

    fn same(a: &Network, b: &Network) -> bool {
        match (a, b) {
            (Network::Testnet(a), Network::Testnet(b)) => Arc::ptr_eq(a, b),
            _ => false,
        }
    }

    pub(super) fn register(network: &Network, params: Params) {
        assert!(
            matches!(network, Network::Testnet(_)),
            "only a test network instance can be given YED parameters"
        );
        let mut reg = REGISTERED.lock().expect("registry lock is not poisoned");
        reg.retain(|(n, _)| !same(n, network));
        reg.push((network.clone(), params));
    }

    pub(super) fn lookup(network: &Network) -> Option<Params> {
        let reg = REGISTERED.lock().expect("registry lock is not poisoned");
        reg.iter().find(|(n, _)| same(n, network)).map(|(_, p)| *p)
    }
}

/// The YED parameters of the database's network under its configuration.
pub fn yed_params_for_db(db: &ZakuraDb) -> Result<Option<Params>, String> {
    yed_network_params(&db.network(), &db.config().yellowback)
}

// ---- the evaluation ---------------------------------------------------------------------

/// The index cannot evaluate a block (U-21): the node must stop.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum YedEvaluationFailed {
    /// The configuration cannot be turned into parameters (ycashd refuses to start).
    #[error("the Yellowback parameters cannot be resolved: {0}")]
    Params(String),

    /// The index tip is not the block's parent (`TipMatches`).
    #[error(
        "tip-mismatch: block {height} {hash} whose parent {parent} is not the index tip \
         ({index_tip}); start height {start_height}"
    )]
    TipMismatch {
        /// The block's height.
        height: u32,
        /// The block's hash.
        hash: block::Hash,
        /// The block's parent.
        parent: block::Hash,
        /// The stored tip, `"empty"` when none.
        index_tip: String,
        /// `startHeight`.
        start_height: i32,
    },

    /// The stored tip was written under another `SCHEMA_VERSION` or network.
    #[error("the index was written under schema {stored_schema} on {stored_network:?}; this binary has schema {schema} on {network:?}")]
    Schema {
        /// The stored tip's schema.
        stored_schema: u32,
        /// The stored tip's network.
        stored_network: String,
        /// [`SCHEMA_VERSION`].
        schema: u32,
        /// The parameters' network.
        network: String,
    },

    /// The stored heights were judged under another [`RULES_VERSION`].
    #[error("the index was judged under rules version {stored}; this binary has {code}")]
    RulesVersion {
        /// The stamp.
        stored: u32,
        /// [`RULES_VERSION`].
        code: u32,
    },

    /// The stored `Params` record is not this configuration's (a hashed regtest value changed).
    #[error("the index was built under other Yellowback parameters than this configuration's")]
    ParamsChanged,

    /// A read-path storage failure marked the index unhealthy (`SetUnhealthy`).
    #[error("the Yellowback index is unhealthy ({0})")]
    Unhealthy(String),

    /// A block the module judges invalid reached the finalized write path.
    #[error(
        "block {height} {hash} is invalid under the YED module ({reason}) but is being \
         committed: the module is not registered yet (plan W5-f), or a checkpoint covers the \
         Vault epoch (K-9)"
    )]
    InvalidBlockCommitted {
        /// The block's height.
        height: u32,
        /// The block's hash.
        hash: block::Hash,
        /// `"<verdict>:<txid>"`.
        reason: String,
    },
}

impl YedEvaluationFailed {
    /// Stops the node (U-21): logs the failure and panics. In the block write task the panic
    /// becomes a writer failure, which `zakurad` supervision turns into a node exit.
    pub fn stop_the_node(&self, source: &str) -> ! {
        metrics::counter!("zakura.state.yed.evaluation_failed").increment(1);
        tracing::error!(
            source,
            failure = %self,
            "Yellowback index failure: the index cannot evaluate the block, so the node stops \
             (U-21). Delete the state and resync."
        );
        panic!("Yellowback index failure ({source}): {self}; delete the state and resync")
    }
}

/// One block as the module reads it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct YedBlockInput {
    /// Its height.
    pub height: Height,
    /// Its hash.
    pub hash: block::Hash,
    /// Its parent's hash.
    pub parent: block::Hash,
    /// Every transaction, block order (`txs[0]` the coinbase).
    pub txs: Vec<VaultTx>,
    /// `GetBlockSubsidy(height)` (issuance, D-Q-25).
    pub subsidy_zat: i64,
}

impl YedBlockInput {
    /// The module's view of a Zakura block: its transparent transactions, and the halving-schedule
    /// subsidy at its height (Ycash has no ZIP 234).
    pub fn from_block(
        network: &Network,
        block: &Block,
        height: Height,
        hash: block::Hash,
        transaction_hashes: &[transaction::Hash],
    ) -> YedBlockInput {
        YedBlockInput {
            height,
            hash,
            parent: block.header.previous_block_hash,
            txs: vault_txs(block, transaction_hashes),
            subsidy_zat: halving_block_subsidy(height, network)
                .map(i64::from)
                .unwrap_or(0),
        }
    }
}

/// The block's verdict when the module judges it invalid (`bad-yellowback-<verdict>`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct YedInvalidBlock {
    /// The first invalid transaction's verdict.
    pub verdict: String,
    /// `"<verdict>:<txid display hex>"`.
    pub reason: String,
}

impl YedInvalidBlock {
    /// The reject reason W5-f uses (`bad-yellowback-<verdict>`, DoS 100).
    pub fn reject_reason(&self) -> String {
        format!("bad-yellowback-{}", self.verdict)
    }
}

/// One block's effect on the index: its delta (empty below the start height, with Yellowback
/// off, or when the block is invalid), and the module's verdict.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct YedBlockEffect {
    /// The block was evaluated (at or above the start height, Yellowback on).
    pub evaluated: bool,
    /// The block's change set with its undo (the C++ `UndoRecord`).
    pub delta: YedDelta,
    /// `Some` when the module judges the block invalid (BLK-1): W5-f rejects it at DoS 100.
    pub invalid: Option<YedInvalidBlock>,
}

/// `TipMatches` plus `SyncToChain`'s schema, network and parameter checks, over the state after
/// the block's parent.
fn check_base(
    p: &Params,
    base: &dyn YedRead,
    input: &YedBlockInput,
) -> Result<(), YedEvaluationFailed> {
    let h = i64::from(input.height.0);
    let mismatch = |index_tip: String| YedEvaluationFailed::TipMismatch {
        height: input.height.0,
        hash: input.hash,
        parent: input.parent,
        index_tip,
        start_height: p.start_height,
    };
    match base.tip() {
        None if h == i64::from(p.start_height) => {}
        None => return Err(mismatch("empty".to_owned())),
        Some(tip) => {
            if tip.schema_version != SCHEMA_VERSION || tip.network != p.network {
                return Err(YedEvaluationFailed::Schema {
                    stored_schema: tip.schema_version,
                    stored_network: tip.network,
                    schema: SCHEMA_VERSION,
                    network: p.network.to_owned(),
                });
            }
            if i64::from(tip.height) != h.saturating_sub(1)
                || tip.block_hash != Hash32(input.parent.0)
            {
                return Err(mismatch(format!(
                    "{} {}",
                    tip.height,
                    block::Hash(tip.block_hash.0)
                )));
            }
        }
    }
    if let Some(stored) = base.params_record() {
        if stored.encode() != ParamsRecord::of(p).encode() {
            return Err(YedEvaluationFailed::ParamsChanged);
        }
    }
    Ok(())
}

/// Evaluates `input` over `base`, the state after its parent (ycash6 `CheckConnect` →
/// `Evaluate` → `EvaluateBlock`). Below the start height nothing is evaluated. A base that is not
/// the parent's state is a [`YedEvaluationFailed`]; an invalid block is an `Ok` effect with
/// [`YedBlockEffect::invalid`] set and an empty delta.
pub fn evaluate_yed_block(
    p: &Params,
    base: &dyn YedRead,
    input: &YedBlockInput,
) -> Result<YedBlockEffect, YedEvaluationFailed> {
    if i64::from(input.height.0) < i64::from(p.start_height) {
        return Ok(YedBlockEffect::default());
    }
    check_base(p, base, input)?;
    let ev = evaluate_block(
        base,
        p,
        &input.txs,
        i64::from(input.height.0),
        &Hash32(input.hash.0),
        input.subsidy_zat,
        // kogany (W5-f): the node's signature cache (BUNDLE-1; a hit and a cold check agree).
        Some(crate::service::yed::module::node_yed_sig_cache()),
    );
    Ok(if ev.block_invalid {
        YedBlockEffect {
            evaluated: true,
            delta: YedDelta::default(),
            invalid: Some(YedInvalidBlock {
                verdict: ev.verdict,
                reason: ev.reason,
            }),
        }
    } else {
        YedBlockEffect {
            evaluated: true,
            delta: ev.delta,
            invalid: None,
        }
    })
}

/// The rules stamp check (`SyncToChain`): an index with a tip stamped with another
/// [`RULES_VERSION`] cannot evaluate. An index without the stamp reads as version 1, as in C++.
pub fn check_rules_stamp(db: &ZakuraDb) -> Result<(), YedEvaluationFailed> {
    if let Some(reason) = crate::service::yed::yed_unhealthy_reason() {
        return Err(YedEvaluationFailed::Unhealthy(reason));
    }
    if FinalizedYedState(db).tip().is_none() {
        return Ok(());
    }
    let stored = db.yed_rules_version().unwrap_or(1);
    if stored != RULES_VERSION {
        return Err(YedEvaluationFailed::RulesVersion {
            stored,
            code: RULES_VERSION,
        });
    }
    Ok(())
}

/// The finalized write path's evaluation of a block over the finalized state (its parent's).
/// `Ok(default)` with Yellowback off or below the start height.
pub fn finalized_yed_effect(
    db: &ZakuraDb,
    p: Option<&Params>,
    input: &YedBlockInput,
) -> Result<YedBlockEffect, YedEvaluationFailed> {
    let Some(p) = p else {
        return Ok(YedBlockEffect::default());
    };
    if i64::from(input.height.0) < i64::from(p.start_height) {
        return Ok(YedBlockEffect::default());
    }
    check_rules_stamp(db)?;
    evaluate_yed_block(p, &FinalizedYedState(db), input)
}

// ---- the undo record --------------------------------------------------------------------

/// One stored undo record (`U`): the block, and every key it wrote with its value before
/// (`None` = absent), in canonical key order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct YedUndoRecord {
    /// The block's height.
    pub height: u32,
    /// The block's hash.
    pub hash: block::Hash,
    /// Canonical key → the value before the block.
    pub before: Vec<(Vec<u8>, Option<Vec<u8>>)>,
}

fn put_compact_size(out: &mut Vec<u8>, n: usize) {
    match u64::try_from(n).unwrap_or(u64::MAX) {
        n @ 0..=0xfc => out.push(n as u8),
        n @ 0xfd..=0xffff => {
            out.push(0xfd);
            out.extend((n as u16).to_le_bytes());
        }
        n @ 0x1_0000..=0xffff_ffff => {
            out.push(0xfe);
            out.extend((n as u32).to_le_bytes());
        }
        n => {
            out.push(0xff);
            out.extend(n.to_le_bytes());
        }
    }
}

fn get_compact_size(b: &[u8], i: &mut usize) -> Option<usize> {
    let first = *b.get(*i)?;
    *i += 1;
    let width = match first {
        0xfd => 2,
        0xfe => 4,
        0xff => 8,
        x => return Some(usize::from(x)),
    };
    let mut v = [0u8; 8];
    v.get_mut(..width)?.copy_from_slice(b.get(*i..*i + width)?);
    *i += width;
    usize::try_from(u64::from_le_bytes(v)).ok()
}

fn get_bytes(b: &[u8], i: &mut usize) -> Option<Vec<u8>> {
    let n = get_compact_size(b, i)?;
    let v = b.get(*i..i.checked_add(n)?)?.to_vec();
    *i += n;
    Some(v)
}

impl YedUndoRecord {
    /// The record of a block's delta.
    pub fn of(height: Height, hash: block::Hash, delta: &YedDelta) -> YedUndoRecord {
        YedUndoRecord {
            height: height.0,
            hash,
            before: delta
                .canonical_entries()
                .into_iter()
                .map(|(k, (before, _after))| (k, before))
                .collect(),
        }
    }

    /// `hash ‖` the C++ `UndoRecord` serialisation (`i32 height`, then `UndoEntry`s: key,
    /// `hadValue`, value, CompactSize-prefixed strings).
    pub fn encode(&self) -> Vec<u8> {
        let mut out = self.hash.0.to_vec();
        out.extend(i32::try_from(self.height).unwrap_or(i32::MAX).to_le_bytes());
        put_compact_size(&mut out, self.before.len());
        for (k, v) in &self.before {
            put_compact_size(&mut out, k.len());
            out.extend(k);
            out.push(u8::from(v.is_some()));
            let v = v.as_deref().unwrap_or_default();
            put_compact_size(&mut out, v.len());
            out.extend(v);
        }
        out
    }

    /// Parses [`Self::encode`]'s bytes.
    pub fn decode(b: &[u8]) -> Option<YedUndoRecord> {
        let hash = block::Hash(b.get(..32)?.try_into().ok()?);
        let height = u32::try_from(i32::from_le_bytes(b.get(32..36)?.try_into().ok()?)).ok()?;
        let mut i = 36;
        let n = get_compact_size(b, &mut i)?;
        let mut before = Vec::with_capacity(n.min(1 << 16));
        for _ in 0..n {
            let k = get_bytes(b, &mut i)?;
            let had = *b.get(i)? != 0;
            i += 1;
            let v = get_bytes(b, &mut i)?;
            before.push((k, had.then_some(v)));
        }
        (i == b.len()).then_some(YedUndoRecord {
            height,
            hash,
            before,
        })
    }
}

// ---- reads ------------------------------------------------------------------------------

fn decoded<T>(value: Option<T>, what: &str) -> T {
    value.unwrap_or_else(|| {
        panic!("a stored YED {what} does not decode: the database is corrupt; resync")
    })
}

/// The finalized YED state as the module's [`YedRead`] (the C++ `State` over the index DB).
#[derive(Clone, Copy)]
pub struct FinalizedYedState<'a>(pub &'a ZakuraDb);

impl YedRead for FinalizedYedState<'_> {
    fn get(&self, key: &YedKey) -> Option<YedRecord> {
        let table = key.table();
        self.0
            .yed_raw_get(cf_for_table(table), &key.encode())
            .map(|v| decoded(YedRecord::decode(table, &v), "record"))
    }

    fn scan(&self, table: Table) -> Vec<(YedKey, YedRecord)> {
        self.0
            .yed_raw_scan(cf_for_table(table))
            .into_iter()
            .map(|(k, v)| {
                (
                    decoded(YedKey::decode(&k), "key"),
                    decoded(YedRecord::decode(table, &v), "record"),
                )
            })
            .collect()
    }
}

impl ZakuraDb {
    fn yed_cf(&self, name: &str) -> YedCf<'_> {
        YedCf::new(&self.db, name).expect("YED column families are created with the database")
    }

    /// The raw value under `key` in the YED column family `cf`.
    pub fn yed_raw_get(&self, cf: &str, key: &[u8]) -> Option<Vec<u8>> {
        self.yed_cf(cf)
            .zs_get(&RawBytes::new_raw_bytes(key.to_vec()))
            .map(|v| v.raw_bytes().clone())
    }

    /// Every raw entry of the YED column family `cf`, in key order.
    pub fn yed_raw_scan(&self, cf: &str) -> Vec<(Vec<u8>, Vec<u8>)> {
        self.yed_cf(cf)
            .zs_forward_range_iter::<std::ops::RangeFull>(..)
            .map(|(k, v)| (k.raw_bytes().clone(), v.raw_bytes().clone()))
            .collect()
    }

    /// The finalized YED state as a [`YedRead`].
    pub fn yed_state(&self) -> FinalizedYedState<'_> {
        FinalizedYedState(self)
    }

    /// Is any YED record, undo record or stamp stored?
    pub fn has_yed_state(&self) -> bool {
        YED_COLUMN_FAMILIES
            .iter()
            .any(|name| !self.yed_cf(name).zs_is_empty())
    }

    /// Every stored YED record, canonical key → canonical value (the tables only).
    pub fn yed_canonical_entries(&self) -> BTreeMap<Vec<u8>, Vec<u8>> {
        YED_TABLE_COLUMN_FAMILIES
            .iter()
            .flat_map(|(_, cf)| self.yed_raw_scan(cf))
            .collect()
    }

    /// The finalized state's `yed_getstatehash` (natural digest order: its hex is what the RPC
    /// prints and the golden vectors pin).
    pub fn yed_state_hash(&self, network: &str) -> [u8; 32] {
        state_hash(&FinalizedYedState(self), network)
    }

    /// The finalized YED tip (`GetTip`).
    pub fn yed_tip(&self) -> Option<TipRecord> {
        FinalizedYedState(self).tip()
    }

    /// The rules stamp `R`, `None` when never written.
    pub fn yed_rules_version(&self) -> Option<u32> {
        self.yed_raw_get(YED_RULES, &RULES_KEY)
            .map(|v| u32::from_le_bytes(decoded(v.as_slice().try_into().ok(), "rules stamp")))
    }

    /// The undo record of the finalized block at `height`, if still kept.
    pub fn yed_undo(&self, height: Height) -> Option<YedUndoRecord> {
        self.yed_raw_get(YED_UNDO, &height.0.to_be_bytes())
            .map(|v| decoded(YedUndoRecord::decode(&v), "undo record"))
    }
}

// ---- writes -----------------------------------------------------------------------------

impl DiskWriteBatch {
    /// Evaluates `finalized` over the finalized state (its parent's) and adds the index's writes
    /// to this batch: the YED half of `prepare_block_batch`, for checkpoint and finalized commits
    /// alike. **Stops the node** when the index cannot evaluate the block, or when the module
    /// judges a committed block invalid (U-21; see the module documentation).
    pub fn prepare_yed_batch(
        &mut self,
        zakura_db: &ZakuraDb,
        network: &Network,
        finalized: &FinalizedBlock,
    ) {
        let params = yed_params_for_db(zakura_db)
            .map_err(YedEvaluationFailed::Params)
            .unwrap_or_else(|e| e.stop_the_node("finalized write"));
        let Some(p) = params else {
            return;
        };
        if i64::from(finalized.height.0) < i64::from(p.start_height) {
            return;
        }
        let input = YedBlockInput::from_block(
            network,
            &finalized.block,
            finalized.height,
            finalized.hash,
            &finalized.transaction_hashes,
        );
        let effect = finalized_yed_effect(zakura_db, Some(&p), &input)
            .unwrap_or_else(|e| e.stop_the_node("finalized write"));
        if let Some(invalid) = &effect.invalid {
            YedEvaluationFailed::InvalidBlockCommitted {
                height: input.height.0,
                hash: input.hash,
                reason: invalid.reason.clone(),
            }
            .stop_the_node("finalized write")
        }
        self.prepare_yed_effect_batch(zakura_db, input.height, input.hash, &effect);
    }

    /// Adds an evaluated block's writes to this batch: every changed record to its `after` value
    /// (`None` deletes), the block's undo record under `U`, the undo record [`UNDO_KEEP`] blocks
    /// below it deleted, and the rules stamp `R`. Nothing for an unevaluated or invalid block.
    pub fn prepare_yed_effect_batch(
        &mut self,
        zakura_db: &ZakuraDb,
        height: Height,
        hash: block::Hash,
        effect: &YedBlockEffect,
    ) {
        if !effect.evaluated || effect.invalid.is_some() {
            return;
        }
        for (key, change) in &effect.delta.changes {
            let cf = zakura_db.yed_cf(cf_for_table(key.table()));
            let raw_key = RawBytes::new_raw_bytes(key.encode());
            let _ = match &change.after {
                Some(record) => cf
                    .with_batch_for_writing(self)
                    .zs_insert(&raw_key, &RawBytes::new_raw_bytes(record.encode())),
                None => cf.with_batch_for_writing(self).zs_delete(&raw_key),
            };
        }
        let _ = zakura_db
            .yed_cf(YED_UNDO)
            .with_batch_for_writing(self)
            .zs_insert(
                &RawBytes::new_raw_bytes(height.0.to_be_bytes().to_vec()),
                &RawBytes::new_raw_bytes(YedUndoRecord::of(height, hash, &effect.delta).encode()),
            );
        if let Some(old) = height.0.checked_sub(UNDO_KEEP) {
            let _ = zakura_db
                .yed_cf(YED_UNDO)
                .with_batch_for_writing(self)
                .zs_delete(&RawBytes::new_raw_bytes(old.to_be_bytes().to_vec()));
        }
        let _ = zakura_db
            .yed_cf(YED_RULES)
            .with_batch_for_writing(self)
            .zs_insert(
                &RawBytes::new_raw_bytes(RULES_KEY.to_vec()),
                &RawBytes::new_raw_bytes(RULES_VERSION.to_le_bytes().to_vec()),
            );
    }
}

#[cfg(test)]
mod tests;
