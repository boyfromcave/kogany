//! The `yed_*` read state over the node's registered Yellowback index (kogany plan W5-f): a
//! [`YedReadState`] that reads `zakura_state`'s best-chain YED snapshot
//! (`ReadRequest::BestChainYedSnapshot`, `zakura_state::yed::YedSnapshot`), as ycash6's
//! `src/rpc/yellowback.cpp` reads one `State` of `g_yellowback` under `cs_yellowback`.
//!
//! Served here: the index tip, health, the state hash (`yed_getstatehash`, the cross-line
//! invariant of plan §4.2 rule 4 (ii)), `Totals`, the stored snapshots and the reads derived from
//! them (arming, the mint gate's halt), the quote tags, E(R) and the FEE-W payee, and the
//! node-local miner quote (`yed_setquote`, which the template's coinbase tag reads, W8-b).
//!
//! Not served yet (answered with an empty list or an `Internal` refusal naming plan W7-b):
//! the vault, token, TxLog, notice and attestor row reads, the collateral estimate, the
//! attestation pool and bundle builder, `yed_gettag` by block, the dry run and the block
//! verdict. They read the same snapshot ([`YedSnapshot`](zakura_state::yed::YedSnapshot)
//! implements `kogany_yellowback::state::YedRead`); each needs its ycash6 row derivation.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use kogany_vault::Hash32;
use kogany_yellowback::{
    attest::registry::AttestStatus as RecordStatus,
    params::{Params, DEFAULT_REF_LAG},
    state::{default_payee, eligible_payees, PayeePolicy as StatePayeePolicy, YedRead},
};
use tower::{Service, ServiceExt};
use zakura_chain::chain_tip::ChainTip;
use zakura_state::{BoxError, ReadRequest, ReadResponse};

use super::state::*;

/// ycash6 `DEFAULT_YELLOWBACK_FEE` (`src/yellowback/params.h:94`).
pub const DEFAULT_YELLOWBACK_FEE: i64 = 1_000;

/// The node-local miner state (`QuoteHolder`): the held quote and when it was set (seconds).
#[derive(Clone, Copy, Debug, Default)]
struct Quote {
    price_micro_usd: i64,
    source_mask: u16,
    received_at: i64,
}

/// The Yellowback state of a running node: the best chain's YED index from `read_state`, the
/// chain tip, and the node-local quote.
pub struct LiveYedState<T, R> {
    tip: T,
    read_state: R,
    quote: Mutex<Option<Quote>>,
}

impl<T, R> LiveYedState<T, R> {
    /// The live state of `read_state` at `tip`.
    pub fn new(tip: T, read_state: R) -> Self {
        Self {
            tip,
            read_state,
            quote: Mutex::new(None),
        }
    }

    fn held_quote(&self) -> Option<Quote> {
        *self
            .quote
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

fn now_seconds() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

/// ycash6 `PlainPQAddressVersion` (`src/key_io.cpp:25-31`, D-Q-20).
fn plain_pq_address_version(network: &str) -> [u8; 2] {
    match network {
        "main" => [0x4D, 0xD9],
        "test" => [0x4F, 0x61],
        _ => [0x4C, 0x51],
    }
}

fn not_served(what: &str) -> YedError {
    YedError::plain(
        YedErrorKind::Internal,
        format!("{what} is not served by kogany yet (plan W7-b)"),
    )
}

#[async_trait]
impl<T, R> YedReadState for LiveYedState<T, R>
where
    T: ChainTip + Clone + Send + Sync + 'static,
    R: Service<ReadRequest, Response = ReadResponse, Error = BoxError>
        + Clone
        + Send
        + Sync
        + 'static,
    R::Future: Send,
{
    async fn snapshot(&self) -> Result<Option<YedSnapshot>, String> {
        let response = self
            .read_state
            .clone()
            .oneshot(ReadRequest::BestChainYedSnapshot)
            .await
            .map_err(|e| e.to_string())?;
        let ReadResponse::YedSnapshot(Some(snap)) = response else {
            return Err("the Yellowback index is not available".to_owned());
        };
        let Some(params) = snap.params else {
            return Ok(None);
        };
        let chain_height = self
            .tip
            .best_tip_height()
            .map_or(-1, |h| i64::from(h.0));
        let index = LiveIndex { snap, params };
        let tip_height = index.tip().map_or(-1, |t| t.height);
        let quote = self.held_quote();
        let price = index.snap.attested_fee_price();
        Ok(Some(YedSnapshot {
            chain_height,
            params,
            node: NodeInfo {
                ref_lag: i64::from(DEFAULT_REF_LAG),
                fee_zat: DEFAULT_YELLOWBACK_FEE,
                payee_policy: PayeePolicy {
                    penalty_blocks: i64::from(params.n_penalty),
                    accuracy_window: i64::from(params.accuracy_window),
                    tilt_bps: i64::from(params.payee_tilt_bps),
                    preferred: None,
                },
                preferred_attestor: None,
                miner: MinerStatus {
                    // Followers have no payout key (K-16; the W8 pool tag is the miner's).
                    payout_key: None,
                    quote_kind: if quote.is_some() { "quote" } else { "none" },
                    quote_age_seconds: quote.map(|q| now_seconds().saturating_sub(q.received_at)),
                    registered: false,
                    eligible: false,
                    quote: quote.map(|q| HeldQuote {
                        price_micro_usd: q.price_micro_usd,
                        source_mask: q.source_mask,
                    }),
                },
                network_fees: NetworkFees {
                    price_micro_usd: price,
                    plain_usd_per_kb_micro: 0,
                    plain_zat_per_kb: 0,
                    yed_usd_per_kb_micro: 0,
                    yed_zat_per_kb: 0,
                    yed_max_tx_fee_usd_micro: 0,
                    yed_max_tx_fee_ceiling_zat: 0,
                    yed_max_tx_fee_zat: 0,
                    floor_zat_per_kb: 0,
                    fallback_zat_per_kb: 0,
                    max_tx_fee_zat: 0,
                },
                falcon_active_next: params.is_pq_falcon_active(tip_height.saturating_add(1)),
                plain_pq_address_version: plain_pq_address_version(params.network),
            },
            index: Arc::new(index),
        }))
    }

    async fn set_quote(
        &self,
        price_micro_usd: i64,
        source_mask: u16,
    ) -> Result<QuoteAck, YedError> {
        let now = now_seconds();
        *self
            .quote
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) =
            (price_micro_usd != 0).then_some(Quote {
                price_micro_usd,
                source_mask,
                received_at: now,
            });
        Ok(QuoteAck {
            received_at: now,
            // Without a payout key no tag is built (MINER-1).
            next_kind: "none",
            payout_key: None,
        })
    }

    async fn add_attestation(&self, _: &Attestation) -> Result<AttestationAck, YedError> {
        Err(not_served("the attestation pool"))
    }

    async fn coinbase_tag(
        &self,
        _: BlockRef,
    ) -> Result<Option<kogany_yellowback::codecs::tag::CoinbaseTag>, YedError> {
        Err(not_served("yed_gettag"))
    }

    async fn validate_raw_transaction(&self, _: &[u8]) -> Result<TxValidation, YedError> {
        Err(not_served("yed_validaterawtransaction"))
    }

    async fn block_verdict(&self, _: Hash32) -> Result<BlockVerdict, YedError> {
        Err(not_served("yed_getblockverdict"))
    }
}

/// The index at the best chain's tip ([`YedIndexView`] over the state snapshot).
pub struct LiveIndex {
    snap: zakura_state::yed::YedSnapshot,
    params: Params,
}

impl LiveIndex {
    /// The view of `snap` under `params`.
    pub fn new(snap: zakura_state::yed::YedSnapshot, params: Params) -> Self {
        Self { snap, params }
    }
}

fn price(v: i64) -> Option<i64> {
    (v != 0).then_some(v)
}

fn attest_state(a: kogany_yellowback::attest::registry::AttestState) -> AttestState {
    AttestState {
        status: match a.status {
            RecordStatus::Unarmed => AttestStatus::Unarmed,
            RecordStatus::Triggered => AttestStatus::Triggered,
            RecordStatus::Armed => AttestStatus::Armed,
        },
        trigger_height: i64::from(a.trigger_height),
        arm_height: i64::from(a.arm_height),
    }
}

impl YedIndexView for LiveIndex {
    fn tip(&self) -> Option<IndexTip> {
        self.snap.index_tip().map(|t| IndexTip {
            height: i64::from(t.height),
            hash: t.block_hash,
        })
    }

    fn health(&self) -> Health {
        let reason = zakura_state::yed::yed_unhealthy_reason();
        Health {
            healthy: reason.is_none(),
            unhealthy_reason: reason.unwrap_or_default(),
            // kogany never rebuilds in place: a foreign index stops the node (U-21).
            rebuilt: false,
        }
    }

    fn state_hash(&self) -> Hash32 {
        self.snap.state_hash_internal()
    }

    fn totals(&self) -> Totals {
        let t = self.snap.totals();
        Totals {
            supply_cents: t.supply_cents,
            collateral_zat: t.collateral_zat,
            active_vaults: i64::from(t.active_vaults),
            void_vaults: i64::from(t.void_vaults),
            closed_vaults: i64::from(t.closed_vaults),
            claimed_vaults: i64::from(t.claimed_vaults),
            unbacked_cents: t.unbacked_cents,
            open_debt_cents: t.open_debt_cents,
        }
    }

    fn verify(&self) -> IndexAudit {
        let stored = self.totals();
        IndexAudit {
            ok: true,
            tokens: 0,
            vaults: 0,
            stored,
            records: stored,
            sets: Vec::new(),
            mismatches: vec!["the record re-derivation is not served by kogany yet (plan W7-b)".to_owned()],
            rules_version: 1,
        }
    }

    fn snapshot_at(&self, height: i64) -> Option<SnapshotView> {
        let s = self.snap.snapshot_at(height)?;
        Some(SnapshotView {
            block_hash: s.block_hash,
            tagged: s.tagged,
            quote: s.quote,
            p_fast: price(s.p_fast),
            p_mid: price(s.p_mid),
            p_slow: price(s.p_slow),
            p_mint: price(s.p_mint),
            p_claim: price(s.p_claim),
            sigma_mult_bps: i64::from(s.sigma_mult_bps),
            issued_zat: s.issued_zat,
            supply_cents: s.supply_cents,
            collateral_zat: s.collateral_zat,
            open_debt_cents: s.open_debt_cents,
            global_ratio_bps: price(s.global_ratio_bps),
            halt_mask: s.halt_mask,
            attest: attest_state(s.attest),
            seated: s.seated.clone(),
            pinned_keys: s.pinned_keys.clone(),
            pinned_seqs: s.pinned_seqs.clone(),
        })
    }

    fn quote_tags_in(&self, height: i64, window: i64) -> i64 {
        let lo = height
            .saturating_sub(window)
            .saturating_add(1)
            .max(i64::from(self.params.start_height));
        (lo..=height)
            .filter(|h| {
                u32::try_from(*h)
                    .ok()
                    .and_then(|h| self.snap.tag(h))
                    .is_some_and(|t| t.price_micro_usd != 0)
            })
            .count()
            .try_into()
            .unwrap_or(i64::MAX)
    }

    fn mint_gate(&self) -> MintGate {
        let halted = self
            .tip()
            .and_then(|t| self.snap.snapshot_at(t.height))
            .is_some_and(|s| s.halt_mask != 0);
        MintGate {
            supply_cap_cents: None,
            supply_cap_reached: false,
            minting_allowed: !halted,
            mintable_classes: if halted { Vec::new() } else { vec![0, 1, 2] },
        }
    }

    fn attest_info(&self) -> AttestInfo {
        let snap = self.tip().and_then(|t| self.snap.snapshot_at(t.height));
        let state = snap
            .as_ref()
            .map_or(AttestState::UNARMED, |s| attest_state(s.attest));
        AttestInfo {
            state,
            seated_count: snap
                .as_ref()
                .map_or(0, |s| i64::try_from(s.seated.len()).unwrap_or(i64::MAX)),
            pool_size: 0,
            pool_fresh: 0,
            armed: self.params.attest_required && state.status == AttestStatus::Armed,
            bond_min_zat: kogany_yellowback::math::bond_min_from_collateral_zat(
                self.snap.totals().collateral_zat,
                &self.params,
            ),
        }
    }

    fn miners(&self, _height: i64, _window: i64) -> Vec<MinerRow> {
        Vec::new()
    }

    fn eligible_payees(&self, ref_height: i64) -> Vec<[u8; 20]> {
        eligible_payees(&self.snap, &self.params, ref_height)
    }

    fn default_payee(&self, ref_height: i64, selector: &[u8]) -> Option<([u8; 20], i64)> {
        let policy = StatePayeePolicy::defaults(&self.params);
        default_payee(&self.snap, &self.params, ref_height, selector, &policy).map(|k| (k, 0))
    }

    fn vault(&self, _txid: &Hash32) -> Option<VaultRow> {
        None
    }

    fn vaults(&self, _status: Option<VaultStatus>, _count: usize, _skip: usize) -> Vec<VaultRow> {
        Vec::new()
    }

    fn tokens(
        &self,
        _holders: &[kogany_yellowback::codecs::script::Holder],
        _min_height: i64,
        _count: usize,
        _skip: usize,
    ) -> Vec<TokenRow> {
        Vec::new()
    }

    fn claimable(&self, _count: usize, _skip: usize) -> Vec<ClaimableRow> {
        Vec::new()
    }

    fn tx_info(&self, _txid: &Hash32) -> Option<TxInfoRow> {
        None
    }

    fn estimate_collateral(
        &self,
        _cents: i64,
        _lock_blocks: i64,
        _price: Option<i64>,
    ) -> Result<CollateralEstimate, YedError> {
        Err(not_served("yed_estimatecollateral"))
    }

    fn attestors(&self, _height: i64) -> Vec<AttestorRow> {
        Vec::new()
    }

    fn pool(&self) -> Vec<PooledAttestation> {
        Vec::new()
    }

    fn build_bundle(&self, _ref_height: i64, _selector: &[u8]) -> Result<BuiltBundle, YedError> {
        Err(not_served("yed_buildbundle"))
    }

    fn selection(&self, _ref_height: i64, _selector: &[u8]) -> Selection {
        Selection {
            armed: false,
            pool: Vec::new(),
            sum_weight: "0".to_owned(),
            selected: Vec::new(),
        }
    }

    fn notice(&self, _txid: &Hash32) -> NoticeLookup {
        NoticeLookup::None
    }
}
