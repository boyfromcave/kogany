//! The Ycash Yellowback (YED) index across the finalized and non-finalized states (kogany plan
//! W5-e): its configuration, the per-block evaluation for a fork, and the read API — a snapshot
//! by block hash — that the `yed_*` RPCs (W5-f, over `kogany_rpc::yed::state::YedIndexView`) and
//! the fee policy (W6-b) consume.
//!
//! One data model throughout: `kogany_yellowback::state` keys and records, [`YedRead`] and
//! [`YedDelta`]. The finalized state stores the records in one column family per table
//! ([`crate::service::finalized_state::yed`]), computed in `prepare_block_batch`; each
//! non-finalized [`Chain`] holds an overlay of what its blocks wrote ([`ChainYedOverlay`]),
//! computed in contextual validation and carried by the block as its [`YedBlockEffect`].
//!
//! The module is **not registered** in this chunk: a block the module judges invalid is not
//! rejected; its verdict is exposed in [`YedBlockEffect::invalid`] for W5-f, which registers
//! `YED\0` with the primitive and rejects at DoS 100.

use std::{collections::BTreeMap, sync::Arc};

use kogany_vault::Hash32;
use kogany_yellowback::{
    attest::price::attested_fee_price,
    params::{BundleCarrier, MicroUsd, Params},
    state::{state_hash, Snapshot, Table, TipRecord, Totals, YedKey, YedRead, YedRecord},
};
use serde::{Deserialize, Serialize};
use zakura_chain::{
    block::{self, Height},
    parameters::Network,
};

use crate::{
    service::{
        finalized_state::{
            yed::{
                check_rules_stamp, evaluate_yed_block, yed_network_params, FinalizedYedState,
                YedBlockInput,
            },
            ZakuraDb,
        },
        non_finalized_state::Chain,
    },
    ContextuallyVerifiedBlock,
};

#[cfg(any(test, feature = "proptest-impl"))]
pub use crate::service::finalized_state::yed::register_yed_params_for_test;
pub use crate::service::{
    finalized_state::yed::{
        yed_params_for_db, YedBlockEffect, YedEvaluationFailed, YedInvalidBlock, YedUndoRecord,
        RULES_VERSION, UNDO_KEEP, YED_COLUMN_FAMILIES,
    },
    non_finalized_state::{ChainYedOverlay, ChainYedView},
};

// ---- configuration ----------------------------------------------------------------------

/// The node's Yellowback configuration (`zakurad.toml` `[yellowback]`): ycashd's regtest-only
/// `-yellowback*` flags (`ycash6/src/yellowback/index.cpp` `ParamsFromArgs`). Every value is
/// hashed into the YED state (the `Params` record, M13), so mismatched test nodes fail loudly.
///
/// On mainnet and testnet every key must keep its default (ycashd: "… is regtest-only"); there
/// the parameters are the network's and Yellowback is off until a release sets the attestor set.
/// The start height is always the Vault activation height (`-yellowbackstartheight` is retired).
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct YellowbackConfig {
    /// `-yellowbackattestorset`: the YED attestor set id, 64 hex characters in display order
    /// (the `SET_CREATE` txid as ycashd prints it). Without it Yellowback is off on regtest.
    pub attestor_set: Option<String>,

    /// `-yellowbacksigmaref`: SIGMA-1's reference volatility, basis points, `>= 0`.
    pub sigma_ref: i64,

    /// `-yellowbacksupplycapbps`: MINT-6's supply cap, basis points of issuance, `0..=10000`
    /// (0 = no cap).
    pub supply_cap_bps: i64,

    /// `-yellowbackattestarmmin`: ARM-1's minimum eligible attestors, `>= 0` (default 3).
    pub attest_arm_min: i64,

    /// `-yellowbackbundlecarrier`: where a bundle may travel: `scriptsig`, `opreturn` or `either`
    /// (default `scriptsig`).
    pub bundle_carrier: String,

    /// `-yellowbackmintrequiresarmed`: MINT requires an ARMED snapshot (H-1).
    pub mint_requires_armed: bool,
}

impl Default for YellowbackConfig {
    fn default() -> Self {
        YellowbackConfig {
            attestor_set: None,
            sigma_ref: 0,
            supply_cap_bps: 0,
            attest_arm_min: i64::from(kogany_yellowback::params::REGTEST_DEFAULT_ATTEST_ARM_MIN),
            bundle_carrier: kogany_yellowback::params::REGTEST_DEFAULT_BUNDLE_CARRIER
                .name()
                .to_owned(),
            mint_requires_armed: kogany_yellowback::params::REGTEST_DEFAULT_MINT_REQUIRES_ARMED,
        }
    }
}

impl YellowbackConfig {
    /// Every key at its default (the section can be omitted).
    pub fn is_default(&self) -> bool {
        *self == YellowbackConfig::default()
    }

    /// The first key set away from its default (ycashd refuses those off regtest).
    pub fn regtest_only_key_set(&self) -> Option<&'static str> {
        let d = YellowbackConfig::default();
        [
            ("attestor_set", self.attestor_set != d.attestor_set),
            ("sigma_ref", self.sigma_ref != d.sigma_ref),
            ("supply_cap_bps", self.supply_cap_bps != d.supply_cap_bps),
            ("attest_arm_min", self.attest_arm_min != d.attest_arm_min),
            ("bundle_carrier", self.bundle_carrier != d.bundle_carrier),
            (
                "mint_requires_armed",
                self.mint_requires_armed != d.mint_requires_armed,
            ),
        ]
        .into_iter()
        .find(|(_, set)| *set)
        .map(|(key, _)| key)
    }

    /// The attestor set id in memory order (the reverse of its hex), `None` when unset.
    pub fn attestor_set_id(&self) -> Result<Option<[u8; 32]>, String> {
        let Some(hex_str) = &self.attestor_set else {
            return Ok(None);
        };
        let mut id: [u8; 32] = hex::decode(hex_str)
            .ok()
            .and_then(|b| b.try_into().ok())
            .ok_or("yellowback.attestor_set must be a set id (64 hex characters)")?;
        if id == [0u8; 32] {
            return Err("yellowback.attestor_set must not be zero".to_owned());
        }
        id.reverse();
        Ok(Some(id))
    }

    /// The bundle carrier.
    pub fn bundle_carrier(&self) -> Result<BundleCarrier, String> {
        BundleCarrier::parse(&self.bundle_carrier).ok_or_else(|| {
            "yellowback.bundle_carrier must be scriptsig, opreturn or either".to_owned()
        })
    }

    /// ycashd's range checks; also validates the attestor set and the carrier.
    pub fn validate(&self) -> Result<(), String> {
        self.attestor_set_id()?;
        self.bundle_carrier()?;
        if !(0..=0x7FFF_FFFF).contains(&self.sigma_ref) {
            return Err("yellowback.sigma_ref must be >= 0".to_owned());
        }
        if !(0..=10_000).contains(&self.supply_cap_bps) {
            return Err("yellowback.supply_cap_bps must be between 0 and 10000".to_owned());
        }
        if !(0..=0x7FFF_FFFF).contains(&self.attest_arm_min) {
            return Err("yellowback.attest_arm_min must be >= 0".to_owned());
        }
        Ok(())
    }

    /// `sigma_ref` as the parameter type (validated by [`Self::validate`]).
    pub(crate) fn sigma_ref_i32(&self) -> i32 {
        i32::try_from(self.sigma_ref).unwrap_or(i32::MAX)
    }

    /// `supply_cap_bps` as the parameter type (validated by [`Self::validate`]).
    pub(crate) fn supply_cap_bps_i32(&self) -> i32 {
        i32::try_from(self.supply_cap_bps).unwrap_or(i32::MAX)
    }

    /// `attest_arm_min` as the parameter type (validated by [`Self::validate`]).
    pub(crate) fn attest_arm_min_i32(&self) -> i32 {
        i32::try_from(self.attest_arm_min).unwrap_or(i32::MAX)
    }
}

/// `CChainParams::NetworkIDString` of `network`, the `network` the YED records and the state
/// hash carry.
pub fn yed_network_name(network: &Network) -> &'static str {
    if network.is_regtest() {
        "regtest"
    } else {
        match network {
            Network::Mainnet => "main",
            Network::Testnet(_) => "test",
        }
    }
}

// ---- the evaluation on a fork -----------------------------------------------------------

/// The YED effect of `block` pushed onto `parent_chain` (the parent fork, or an empty chain at
/// the finalized tip), evaluated over the state at the parent's tip: the hook contextual
/// validation calls. **Stops the node** when the index cannot evaluate the block (U-21); an
/// invalid block's verdict is in the effect (not rejected until W5-f).
pub fn block_yed_effect_for_chain(
    network: &Network,
    parent_chain: &Chain,
    db: &ZakuraDb,
    block: &ContextuallyVerifiedBlock,
) -> YedBlockEffect {
    try_block_yed_effect_for_chain(network, parent_chain, db, block)
        .unwrap_or_else(|e| e.stop_the_node("contextual validation"))
}

/// [`block_yed_effect_for_chain`] returning the failure instead of stopping the node.
pub fn try_block_yed_effect_for_chain(
    network: &Network,
    parent_chain: &Chain,
    db: &ZakuraDb,
    block: &ContextuallyVerifiedBlock,
) -> Result<YedBlockEffect, YedEvaluationFailed> {
    let Some(p) = yed_network_params(network, &db.config().yellowback)
        .map_err(YedEvaluationFailed::Params)?
    else {
        return Ok(YedBlockEffect::default());
    };
    if i64::from(block.height.0) < i64::from(p.start_height) {
        return Ok(YedBlockEffect::default());
    }
    let input = YedBlockInput::from_block(
        network,
        &block.block,
        block.height,
        block.hash,
        &block.transaction_hashes,
    );
    chain_yed_effect(&p, parent_chain, db, &input)
}

/// Evaluates `input` over the state at `parent_chain`'s tip (`parent_chain` empty: the finalized
/// tip). The rules stamp is checked as in the finalized path.
pub fn chain_yed_effect(
    p: &Params,
    parent_chain: &Chain,
    db: &ZakuraDb,
    input: &YedBlockInput,
) -> Result<YedBlockEffect, YedEvaluationFailed> {
    check_rules_stamp(db)?;
    evaluate_yed_block(p, &parent_chain.yed_view(db), input)
}

// ---- health -------------------------------------------------------------------------------

/// The node's index health (ycash6 `SetUnhealthy`): kogany's index has no unhealthy state on the
/// block path — a block it cannot evaluate stops the node — so only a read-path storage failure
/// (the mempool check) sets it, and the next block's evaluation then stops the node.
static YED_UNHEALTHY: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None);

/// Marks the index unhealthy (the first reason is kept).
pub fn mark_yed_unhealthy(reason: String) {
    tracing::error!(%reason, "Yellowback index unhealthy: the next block stops the node");
    let mut unhealthy = YED_UNHEALTHY
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    unhealthy.get_or_insert(reason);
}

/// `UnhealthyReason()`: `None` while healthy (`yed_getinfo.health`, W5-f).
pub fn yed_unhealthy_reason() -> Option<String> {
    YED_UNHEALTHY
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone()
}

// ---- snapshots ----------------------------------------------------------------------------

/// The YED state after one block (ycash6 reads one `State` under `cs_yellowback`): what the
/// `yed_*` RPCs and the fee policy read. A cheap view, not a copy: the finalized database with
/// the patch the chosen block's chain makes over it.
///
/// The view reads the live database. It stays exact while the database moves forward along the
/// snapshot's own chain (a finalized block's writes are already in the patch); a snapshot of a
/// chain that loses a reorg to a finalized fork goes stale, as Zakura's other non-finalized reads
/// do. Take a fresh one per answer.
#[derive(Clone, Debug)]
pub struct YedSnapshot {
    /// The block the state is after: `None` for an empty finalized state.
    pub tip: Option<(Height, block::Hash)>,
    /// The YED parameters in force, `None` when Yellowback is off (or misconfigured: the write
    /// path stops the node on the first Vault-epoch block then).
    pub params: Option<Params>,
    network: &'static str,
    patch: Arc<BTreeMap<YedKey, Option<YedRecord>>>,
    db: ZakuraDb,
}

impl YedRead for YedSnapshot {
    fn get(&self, key: &YedKey) -> Option<YedRecord> {
        match self.patch.get(key) {
            Some(value) => value.clone(),
            None => FinalizedYedState(&self.db).get(key),
        }
    }

    fn scan(&self, table: Table) -> Vec<(YedKey, YedRecord)> {
        let base = FinalizedYedState(&self.db).scan(table);
        if self.patch.is_empty() {
            return base;
        }
        let (lo, hi) = table.bounds();
        let mut merged: BTreeMap<YedKey, YedRecord> = base.into_iter().collect();
        for (k, v) in self.patch.range(lo..=hi) {
            match v {
                Some(v) => merged.insert(*k, v.clone()),
                None => merged.remove(k),
            };
        }
        merged.into_iter().collect()
    }
}

impl YedSnapshot {
    fn new(
        db: &ZakuraDb,
        tip: Option<(Height, block::Hash)>,
        patch: BTreeMap<YedKey, Option<YedRecord>>,
    ) -> YedSnapshot {
        let network = db.network();
        let params = yed_network_params(&network, &db.config().yellowback)
            .ok()
            .flatten();
        YedSnapshot {
            tip,
            params,
            // The records carry `Params::network` (the C++ `params.network`).
            network: params.map_or(yed_network_name(&network), |p| p.network),
            patch: Arc::new(patch),
            db: db.clone(),
        }
    }

    /// Yellowback is live on this node (the Vault height and the attestor set are known):
    /// otherwise every `yed_*` method answers `-32601`.
    pub fn is_live(&self) -> bool {
        self.params.is_some()
    }

    /// `CChainParams::NetworkIDString`.
    pub fn network(&self) -> &'static str {
        self.network
    }

    /// The index tip record (`GetTip`), `None` before the first Vault-epoch block.
    pub fn index_tip(&self) -> Option<TipRecord> {
        YedRead::tip(self)
    }

    /// `yed_getstatehash`: SHA-256 of the canonical preimage, natural digest order (its hex is
    /// what ycashd prints and `yellowback_golden.json` pins).
    pub fn state_hash(&self) -> [u8; 32] {
        state_hash(self, self.network)
    }

    /// [`Self::state_hash`] as lower-case hex (the `yed_getstatehash` value).
    pub fn state_hash_hex(&self) -> String {
        hex::encode(self.state_hash())
    }

    /// [`Self::state_hash`] in the C++ `uint256` memory order (the reverse), the internal order
    /// `kogany_rpc::yed::state::YedIndexView::state_hash` returns and the RPC layer reverses.
    pub fn state_hash_internal(&self) -> Hash32 {
        let mut h = self.state_hash();
        h.reverse();
        Hash32(h)
    }

    /// `Totals` (zero before the first Vault-epoch block).
    pub fn totals(&self) -> Totals {
        YedRead::totals(self)
    }

    /// The stored `Snapshots[height]`, `None` outside `[startHeight, tip]`.
    pub fn snapshot_at(&self, height: i64) -> Option<Snapshot> {
        u32::try_from(height)
            .ok()
            .and_then(|h| YedRead::snapshot(self, h))
    }

    /// The network-fee price (D-Q-23 (b), review M-1; ycash6 `PublishFeePrice`): the highest of
    /// the index tip snapshot's window medians when the price is trusted (no halt bit but
    /// HALT-2), else `None` (the `-pqfeerate` fallback). Node policy only (W6-b): nothing in block
    /// validity reads it.
    pub fn attested_fee_price(&self) -> Option<MicroUsd> {
        let p = self.params.as_ref()?;
        let tip = self.index_tip()?;
        if tip.height < p.start_height {
            return None;
        }
        let s = self.snapshot_at(i64::from(tip.height))?;
        attested_fee_price(s.pfast(), s.pmid(), s.pslow(), s.halt_mask)
    }

    /// `MempoolCheckLocked` (ycash6 `src/yellowback/index.cpp`): the module's check of a
    /// transaction for the next block over this snapshot (the tip's), `None` = admitted, else
    /// the reason (a verdict, [`MEMPOOL_EXPIRY`](kogany_yellowback::state::MEMPOOL_EXPIRY), or
    /// [`UNHEALTHY`](kogany_yellowback::state::UNHEALTHY)). The C++ guards:
    ///
    /// - Yellowback not live on this node (ycashd's stopped or absent index): `None`;
    /// - the index unhealthy: `UNHEALTHY`, admitting nothing that might touch the module;
    /// - a storage failure while reading (a record that does not decode): the index is marked
    ///   unhealthy ([`mark_yed_unhealthy`]) and the transaction refused with `UNHEALTHY`; the
    ///   next block's evaluation then stops the node, as ycashd's next `ConnectBlock` aborts.
    ///
    /// `expiry_height` is the transaction's `nExpiryHeight` (0 = none). For W6-b.
    pub fn mempool_check(
        &self,
        tx: &kogany_vault::state::VaultTx,
        expiry_height: u32,
    ) -> Option<String> {
        let p = self.params.as_ref()?;
        if tx.coinbase {
            return None;
        }
        if yed_unhealthy_reason().is_some() {
            return Some(kogany_yellowback::state::UNHEALTHY.to_owned());
        }
        // The index is in step with the chain, so its tip is the chain's.
        let next_height = self
            .index_tip()
            .map(|t| i64::from(t.height))
            .or(self.tip.map(|(h, _)| i64::from(h.0)))
            .map_or(0, |h| h.saturating_add(1));
        let checked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            kogany_yellowback::state::mempool_check_reason(
                self,
                p,
                next_height,
                tx,
                expiry_height,
                None,
            )
        }));
        match checked {
            Ok(reason) => reason,
            Err(panic) => {
                let what = panic
                    .downcast_ref::<String>()
                    .cloned()
                    .or_else(|| panic.downcast_ref::<&str>().map(|s| (*s).to_owned()))
                    .unwrap_or_default();
                mark_yed_unhealthy(format!("storage failure in MempoolCheck: {what}"));
                Some(kogany_yellowback::state::UNHEALTHY.to_owned())
            }
        }
    }

    /// Every record, canonical key → canonical value (the tables of the state hash and the rest).
    pub fn canonical_entries(&self) -> BTreeMap<Vec<u8>, Vec<u8>> {
        kogany_yellowback::state::canonical_entries_of(self)
    }
}

/// The YED state at the finalized tip.
pub fn finalized_yed_snapshot(db: &ZakuraDb) -> YedSnapshot {
    YedSnapshot::new(db, db.tip(), BTreeMap::new())
}

/// The YED state at `chain`'s tip.
pub fn chain_tip_yed_snapshot(chain: &Chain, db: &ZakuraDb) -> YedSnapshot {
    let tip = chain
        .tip_block()
        .map(|b| (b.height, b.hash))
        .or_else(|| db.tip());
    let patch = chain
        .yed_overlay()
        .entries()
        .map(|(k, v)| (*k, v.cloned()))
        .collect();
    YedSnapshot::new(db, tip, patch)
}

/// The YED state at the best chain's tip, or the finalized tip without one (the fee policy's
/// read, W6-b: `tip_yed_snapshot(non_finalized.best_chain(), db).attested_fee_price()`).
pub fn tip_yed_snapshot(best_chain: Option<&Arc<Chain>>, db: &ZakuraDb) -> YedSnapshot {
    match best_chain {
        Some(chain) => chain_tip_yed_snapshot(chain, db),
        None => finalized_yed_snapshot(db),
    }
}

/// `MempoolCheckReason(tx)` (ycash6 `src/main.cpp` `AcceptToMemoryPool`, after the scripts) over
/// `snapshot`, the YED state at the best chain tip (kogany W6-b): `None` = admitted, else the
/// module's reason (ycashd refuses `bad-yellowback-<reason>` at DoS 0: the module's state moves
/// with the tip, which the relaying peer need not share).
pub fn yed_mempool_check(
    snapshot: &YedSnapshot,
    transaction: &zakura_chain::transaction::Transaction,
) -> Option<String> {
    let vault_tx =
        crate::service::finalized_state::vault::vault_tx(transaction, &transaction.hash());
    let expiry = transaction.expiry_height().map_or(0, |h| h.0);
    snapshot.mempool_check(&vault_tx, expiry)
}

/// The YED state after the block `hash` (fork-aware): a block of any of `chains`, the finalized
/// tip, or a finalized block up to [`UNDO_KEEP`] below it (through the stored undo records).
/// `None` when `hash` is none of these.
///
/// Reads the finalized state and the chains as given; the caller passes the chains and database
/// of one non-finalized-state version, as every other zakura-state read does.
pub fn yed_snapshot_by_hash<'a>(
    chains: impl IntoIterator<Item = &'a Arc<Chain>>,
    db: &ZakuraDb,
    hash: block::Hash,
) -> Option<YedSnapshot> {
    for chain in chains {
        let Some(height) = chain.height_by_hash(hash) else {
            continue;
        };
        let mut patch: BTreeMap<YedKey, Option<YedRecord>> = chain
            .yed_overlay()
            .entries()
            .map(|(k, v)| (*k, v.cloned()))
            .collect();
        // Undo the blocks above `hash`, newest first: the last value written is the `before` of
        // the lowest such block, the value after `hash`.
        let above = (
            std::ops::Bound::Excluded(height),
            std::ops::Bound::Unbounded,
        );
        for (_, block) in chain.blocks.range(above).rev() {
            for (k, change) in &block.yed_effect.delta.changes {
                patch.insert(*k, change.before.clone());
            }
        }
        return Some(YedSnapshot::new(db, Some((height, hash)), patch));
    }
    let tip = db.tip()?;
    if tip.1 == hash {
        return Some(finalized_yed_snapshot(db));
    }
    finalized_yed_snapshot_below(db, tip.0, db.height(hash)?, hash)
}

/// The YED state after the finalized block `target` (`target_hash`), `from` being the finalized
/// tip: the finalized state with the stored undo records of the blocks `from` down to
/// `target + 1` applied, newest first. `None` when `target` is more than [`UNDO_KEEP`] below
/// `from`, or above it.
pub fn finalized_yed_snapshot_below(
    db: &ZakuraDb,
    from: Height,
    target: Height,
    target_hash: block::Hash,
) -> Option<YedSnapshot> {
    if target > from || from.0.saturating_sub(target.0) > UNDO_KEEP {
        return None;
    }
    let mut patch: BTreeMap<YedKey, Option<YedRecord>> = BTreeMap::new();
    let mut h = from;
    while h > target {
        // No record: a block below the start height (or with Yellowback off) wrote nothing.
        for (k, before) in db.yed_undo(h).map(|u| u.before).unwrap_or_default() {
            let key = YedKey::decode(&k)?;
            let value = match before {
                Some(v) => Some(YedRecord::decode(key.table(), &v)?),
                None => None,
            };
            patch.insert(key, value);
        }
        h = h.previous().ok()?;
    }
    Some(YedSnapshot::new(db, Some((target, target_hash)), patch))
}
