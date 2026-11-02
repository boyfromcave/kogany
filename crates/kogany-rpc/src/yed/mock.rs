//! Prototype [`YedReadState`]s, until plan W5-e/W5-f read the real Yellowback index.
//!
//! - [`UnavailableYedState`]: Yellowback is not live (no YED module registered in kogany yet):
//!   every `yed_*` method answers `-32601 "Method not found (Yellowback is not active: …)"`,
//!   ycashd's answer without the vault upgrade or the YED attestor set, which the lightwalletd-dd
//!   probe reads as "no Yellowback". `zakurad` serves this by default.
//! - [`MockYedState`]: a fixed regtest index. Its tip, state hash, `Totals` and the seven
//!   hashed regtest parameters are those of the pinned golden chain
//!   (`testdata/yellowback/yellowback_golden.json`; the crate's tests check it against the file),
//!   and its rows (three vaults, tokens, three attestors, a pool, a notice, a TxLog record) are a
//!   synthetic fixture shaped like ycash6's contract examples, since the rows need the module's
//!   state machine (W5-d). `zakurad` serves it when [`MOCK_ENV`] is `1`, so the RPC shapes can be
//!   checked against `ycash6/doc/yellowback-rpc-contract.json` before W5-e.
//!
//! The mock's attestation "signature" check is a placeholder (the 64 signature bytes must all
//! equal `seq ^ citedHeight` truncated to a byte, [`MockYedState::mock_signature`]), so the pool
//! refusals can be provoked without a key; the real check is W5-c's.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use kogany_vault::{Hash32, OutPoint, PqOwner, PubKeyBytes};
use kogany_yellowback::{
    codecs::{
        script::{yed_vault_script, Holder},
        tag::CoinbaseTag,
    },
    math::{
        attest_fee_zat, min_ratio_bps, protocol_fee_cents, protocol_fee_zat,
        required_collateral_rounded,
    },
    params::{
        regtest_params_with, BundleCarrier, Params, LOCKTIME_THRESHOLD, PRICE_MAX, PRICE_MIN,
    },
};
use zakura_chain::chain_tip::ChainTip;

use super::state::*;

/// The environment variable that makes `zakurad` serve [`MockYedState`].
pub const MOCK_ENV: &str = "KOGANY_YED_RPC_MOCK";

/// The golden chain's tip height (`yellowback_golden.json` `tip.height`).
pub const GOLDEN_TIP_HEIGHT: i64 = 440;
/// Its tip hash, display order.
pub const GOLDEN_TIP_HASH: &str =
    "ca6c02a81b1fd42c9bf7775ace41f9b5224b700ad25acf0ccf48e86a979d1831";
/// Its state hash, display order.
pub const GOLDEN_STATE_HASH: &str =
    "ee6a9f157175b6e084df52f96dc5039e4d411189352542f329971e6dd7bb0c0b";
/// Its YED attestor set, display order.
pub const GOLDEN_ATTESTOR_SET: &str =
    "0eeebe67c4bc64cf5deb624972629c92b09e3362e126a3702443b192dca80f4a";
/// Its `Totals`.
pub const GOLDEN_TOTALS: Totals = Totals {
    supply_cents: 10_000,
    collateral_zat: 8_775_196_019_613,
    active_vaults: 2,
    void_vaults: 0,
    closed_vaults: 2,
    claimed_vaults: 1,
    unbacked_cents: 0,
    open_debt_cents: 20_000,
};

/// A display-order hex id as internal bytes (a compile-time constant of this module).
fn hash_of(display: &str) -> Hash32 {
    let mut b = [0u8; 32];
    if let Ok(v) = hex::decode(display) {
        if v.len() == 32 {
            b.copy_from_slice(&v);
        }
    }
    b.reverse();
    Hash32(b)
}

/// The golden chain's regtest parameters (`params` of the golden file: startHeight 1, sigmaRef 0,
/// supplyCap 0, the attestor set, armMin 3, scriptsig carrier, mintRequiresArmed false, Falcon
/// from 400).
pub fn golden_params() -> Params {
    let mut p = regtest_params_with(
        1,
        0,
        0,
        hash_of(GOLDEN_ATTESTOR_SET).0,
        3,
        BundleCarrier::ScriptSig,
        false,
    );
    p.pq_falcon_height = 400;
    p
}

fn filled(b: u8) -> Hash32 {
    Hash32([b; 32])
}

fn key(b: u8) -> PubKeyBytes {
    let mut k = [b; 33];
    k[0] = 0x02;
    PubKeyBytes(k)
}

fn chain_height<T: ChainTip>(tip: &T) -> i64 {
    tip.best_tip_height().map_or(-1, |h| i64::from(h.0))
}

/// Yellowback not live (see the module documentation).
#[derive(Clone)]
pub struct UnavailableYedState;

fn not_live() -> YedError {
    YedError::plain(
        YedErrorKind::Internal,
        "Yellowback is not live on this node",
    )
}

#[async_trait]
impl YedReadState for UnavailableYedState {
    async fn snapshot(&self) -> Result<Option<YedSnapshot>, String> {
        Ok(None)
    }
    async fn set_quote(&self, _: i64, _: u16) -> Result<QuoteAck, YedError> {
        Err(not_live())
    }
    async fn add_attestation(&self, _: &Attestation) -> Result<AttestationAck, YedError> {
        Err(not_live())
    }
    async fn coinbase_tag(&self, _: BlockRef) -> Result<Option<CoinbaseTag>, YedError> {
        Err(not_live())
    }
    async fn validate_raw_transaction(&self, _: &[u8]) -> Result<TxValidation, YedError> {
        Err(not_live())
    }
    async fn block_verdict(&self, _: Hash32) -> Result<BlockVerdict, YedError> {
        Err(not_live())
    }
}

/// The node-state the mock keeps across calls: the miner's quote and the pool.
#[derive(Debug)]
struct NodeState {
    quote: Option<(i64, u16, i64)>,
    pool: Vec<PooledAttestation>,
}

/// The fixture index at the chain tip `tip` (see the module documentation).
#[derive(Clone)]
pub struct MockYedState<T> {
    tip: T,
    node: Arc<Mutex<NodeState>>,
    healthy: bool,
}

/// The fixture's payout key.
pub const PAYOUT_KEY: [u8; 20] = [0x51; 20];
/// The fixture's vault txids (internal order): ACTIVE, ACTIVE with a standing notice, CLAIMING.
pub const VAULTS: [Hash32; 3] = [Hash32([0x6a; 32]), Hash32([0x6b; 32]), Hash32([0x6c; 32])];
/// The pool's `seq`s (1..=3 eligible; 4 is EJECTED, 5 has no record).
pub const SEATED: [u16; 3] = [1, 2, 3];

impl<T> MockYedState<T> {
    /// The fixture at `tip`, healthy.
    pub fn new(tip: T) -> Self {
        let pool = SEATED
            .iter()
            .map(|seq| {
                let cited = 437;
                PooledAttestation {
                    attestation: Attestation {
                        seq: *seq,
                        price_micro_usd: 1_985_000,
                        cited_height: cited,
                        sig: Self::mock_signature(*seq, cited),
                    },
                    received_height: GOLDEN_TIP_HEIGHT,
                    seated: true,
                    fresh: true,
                }
            })
            .collect();
        Self {
            tip,
            node: Arc::new(Mutex::new(NodeState { quote: None, pool })),
            healthy: true,
        }
    }

    /// The same fixture with an unhealthy index (`-yellowbacktestfault=storage:commit`), for the
    /// M8 allow-list.
    pub fn unhealthy(tip: T) -> Self {
        Self {
            healthy: false,
            ..Self::new(tip)
        }
    }

    /// The placeholder signature the mock accepts for `(seq, citedHeight)`.
    pub fn mock_signature(seq: u16, cited_height: u32) -> [u8; 64] {
        let [b, ..] = (u32::from(seq) ^ cited_height).to_le_bytes();
        [b; 64]
    }
}

#[async_trait]
impl<T: ChainTip + Send + Sync + 'static> YedReadState for MockYedState<T> {
    async fn snapshot(&self) -> Result<Option<YedSnapshot>, String> {
        let pool = self
            .node
            .lock()
            .map_err(|_| "the mock's node state is poisoned".to_owned())?
            .pool
            .clone();
        let quote = self.node.lock().ok().and_then(|n| n.quote);
        let params = golden_params();
        Ok(Some(YedSnapshot {
            chain_height: chain_height(&self.tip),
            params,
            node: NodeInfo {
                ref_lag: 2,
                fee_zat: 1000,
                payee_policy: PayeePolicy {
                    penalty_blocks: i64::from(params.n_penalty),
                    accuracy_window: i64::from(params.accuracy_window),
                    tilt_bps: i64::from(params.payee_tilt_bps),
                    preferred: None,
                },
                preferred_attestor: None,
                miner: MinerStatus {
                    payout_key: Some(PAYOUT_KEY),
                    quote_kind: if quote.is_some_and(|q| q.0 != 0) {
                        "quote"
                    } else {
                        "none"
                    },
                    quote_age_seconds: quote.map(|_| 0),
                    registered: true,
                    eligible: true,
                },
                network_fees: NetworkFees {
                    price_micro_usd: Some(400_000),
                    plain_usd_per_kb_micro: 20_000,
                    plain_zat_per_kb: 5_000_000,
                    yed_usd_per_kb_micro: 50_000,
                    yed_zat_per_kb: 12_500_000,
                    yed_max_tx_fee_usd_micro: 2_000_000,
                    yed_max_tx_fee_ceiling_zat: 1_000_000_000,
                    yed_max_tx_fee_zat: 500_000_000,
                    floor_zat_per_kb: 5000,
                    fallback_zat_per_kb: 100,
                    max_tx_fee_zat: 10_000_000,
                },
                falcon_active_next: params.is_pq_falcon_active(GOLDEN_TIP_HEIGHT + 1),
                plain_pq_address_version: [0x4c, 0x51],
            },
            index: Arc::new(Fixture {
                params,
                pool,
                healthy: self.healthy,
            }),
        }))
    }

    async fn set_quote(&self, price: i64, mask: u16) -> Result<QuoteAck, YedError> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX));
        let mut n = self
            .node
            .lock()
            .map_err(|_| YedError::plain(YedErrorKind::Internal, "poisoned"))?;
        n.quote = (price != 0).then_some((price, mask, now));
        Ok(QuoteAck {
            received_at: now,
            next_kind: if price != 0 { "quote" } else { "none" },
            payout_key: Some(PAYOUT_KEY),
        })
    }

    async fn add_attestation(&self, a: &Attestation) -> Result<AttestationAck, YedError> {
        let p = golden_params();
        let rejected = |id, text: String| Err(YedError::new(YedErrorKind::Rejected, id, text));
        match a.seq {
            1..=3 => {}
            4 => return rejected("attest-not-eligible", format!("seq {} is EJECTED", a.seq)),
            _ => {
                return rejected(
                    "attest-unknown-seq",
                    format!("no attestor with seq {}", a.seq),
                )
            }
        }
        let cited = i64::from(a.cited_height);
        let floor = GOLDEN_TIP_HEIGHT - 2 - i64::from(p.attest_max_age);
        if cited <= floor || cited > GOLDEN_TIP_HEIGHT || cited < i64::from(p.start_height) {
            return rejected(
                "attest-stale",
                format!("citedHeight {cited} is outside ({floor}, {GOLDEN_TIP_HEIGHT}]"),
            );
        }
        let price = i64::from(a.price_micro_usd);
        if !(PRICE_MIN..=PRICE_MAX).contains(&price) {
            return rejected(
                "attest-range",
                format!("priceMicroUsd {price} is out of range"),
            );
        }
        if a.sig != Self::mock_signature(a.seq, a.cited_height) {
            return rejected("attest-bad-sig", "the signature does not verify".to_owned());
        }
        let mut n = self
            .node
            .lock()
            .map_err(|_| YedError::plain(YedErrorKind::Internal, "poisoned"))?;
        let before = n.pool.len();
        let identical = n.pool.iter().any(|x| x.attestation == *a);
        let same_height = n.pool.iter().any(|x| {
            x.attestation.seq == a.seq
                && x.attestation.cited_height == a.cited_height
                && x.attestation != *a
        });
        if !identical {
            n.pool.retain(|x| {
                !(x.attestation.seq == a.seq && x.attestation.cited_height == a.cited_height)
            });
            n.pool.push(PooledAttestation {
                attestation: *a,
                received_height: GOLDEN_TIP_HEIGHT,
                seated: true,
                fresh: true,
            });
            n.pool
                .sort_by_key(|x| (x.attestation.seq, x.attestation.cited_height));
        }
        Ok(AttestationAck {
            replaced: same_height || (!identical && n.pool.len() <= before),
            // The pool is a handful of rows.
            pool_size: n.pool.len() as i64,
        })
    }

    async fn coinbase_tag(&self, block: BlockRef) -> Result<Option<CoinbaseTag>, YedError> {
        let h = match block {
            BlockRef::Height(h) => h,
            BlockRef::Hash(hash) if hash == hash_of(GOLDEN_TIP_HASH) => GOLDEN_TIP_HEIGHT,
            BlockRef::Hash(_) => {
                return Err(YedError::plain(
                    YedErrorKind::InvalidParameter,
                    "block not found",
                ))
            }
        };
        if !(0..=GOLDEN_TIP_HEIGHT).contains(&h) {
            return Err(YedError::plain(
                YedErrorKind::InvalidParameter,
                "height out of range",
            ));
        }
        Ok((h >= 1).then_some(CoinbaseTag {
            flags: 0,
            price_micro_usd: 2_000_000,
            source_mask: 3,
            payout_key: PAYOUT_KEY,
        }))
    }

    async fn validate_raw_transaction(&self, _tx: &[u8]) -> Result<TxValidation, YedError> {
        Ok(TxValidation {
            valid: false,
            invalid_reason: Some("input 0 is unknown or spent".to_owned()),
            verdict: "ok".to_owned(),
            kind: "none".to_owned(),
            path: String::new(),
            yed_in: 0,
            yed_out: 0,
            burned: 0,
            fee_zat: 0,
            payee: None,
            block_valid: true,
            would_be_rejected: false,
            mempool_expiry_ok: true,
            unconfirmed_inputs: vec![OutPoint {
                txid: filled(0x3c),
                n: 1,
            }],
        })
    }

    async fn block_verdict(&self, block_hash: Hash32) -> Result<BlockVerdict, YedError> {
        if block_hash != hash_of(GOLDEN_TIP_HASH) {
            return Err(YedError::plain(
                YedErrorKind::InvalidParameter,
                "block not found",
            ));
        }
        Ok(BlockVerdict {
            block_invalid: false,
            reason: String::new(),
            verdict: "ok".to_owned(),
            transactions: vec![BlockVerdictTx {
                txid: VAULTS[0],
                kind: "mint".to_owned(),
                path: String::new(),
                verdict: "ok".to_owned(),
                yed_in: 0,
                yed_out: 100_000,
                fee_zat: 503_778_338,
                payee: Some(PAYOUT_KEY),
                closed_vaults: vec![],
            }],
        })
    }
}

/// The fixture index.
struct Fixture {
    params: Params,
    pool: Vec<PooledAttestation>,
    healthy: bool,
}

const OWNER: PqOwner = PqOwner {
    scheme: 1,
    hash: Hash32([0xa1; 32]),
};

impl Fixture {
    fn vault_row(&self, i: usize) -> Option<VaultRow> {
        let txid = *VAULTS.get(i)?;
        let ref_height = 329 + i as i64; // i < 3
        let status = if i == 2 {
            VaultStatus::Claiming
        } else {
            VaultStatus::Active
        };
        Some(VaultRow {
            txid,
            status,
            owner: OWNER,
            term_class: 0,
            lock_height: ref_height + 48,
            claim_height: ref_height + 72,
            collateral_zat: 251_889_169_000,
            minted_cents: 100_000,
            mint_height: ref_height + 3,
            ref_height,
            fee_paid_zat: 503_778_338,
            p_mint: 1_985_000,
            closed: None,
            burned_cents: if i == 2 { 100_000 } else { 0 },
            unbacked: false,
            cancel_count: 0,
            cancels_required: 1,
            cancel_quiet_until: None,
            claimable: false,
            underwater_at: Some(496_250),
            void_reason: String::new(),
            script_pubkey: yed_vault_script(&self.params, &OWNER, ref_height).unwrap_or_default(),
            intents: (i == 2).then(|| {
                vec![VaultIntent {
                    outpoint: OutPoint {
                        txid: filled(0x7c),
                        n: 0,
                    },
                    claimant: true,
                    height: 435,
                    release_height: 435 + i64::from(self.params.claim_delay),
                }]
            }),
            refund_holder: (i == 2)
                .then(|| kogany_yellowback::codecs::script::p2pkh_script(&[0x33; 20])),
            held_residuals: (i == 2).then(|| {
                vec![OutPoint {
                    txid: filled(0x7d),
                    n: 1,
                }]
            }),
            notice: (i == 1).then_some((436, 434 + i64::from(self.params.emergency_persist))),
            spend_txid: None,
        })
    }

    fn snapshot(&self, h: i64) -> SnapshotView {
        let armed = h >= 308;
        SnapshotView {
            block_hash: if h == GOLDEN_TIP_HEIGHT {
                hash_of(GOLDEN_TIP_HASH)
            } else {
                // A synthetic hash per height (the golden file holds the real ones).
                let mut b = [0u8; 32];
                b[..8].copy_from_slice(&h.to_le_bytes());
                Hash32(b)
            },
            tagged: true,
            quote: true,
            p_fast: Some(2_000_000),
            p_mid: Some(2_000_000),
            p_slow: Some(1_990_000),
            p_mint: Some(1_990_000),
            p_claim: Some(2_000_000),
            sigma_mult_bps: 10_000,
            issued_zat: 625_000_000 * h,
            supply_cents: GOLDEN_TOTALS.supply_cents,
            collateral_zat: GOLDEN_TOTALS.collateral_zat,
            open_debt_cents: GOLDEN_TOTALS.open_debt_cents,
            global_ratio_bps: kogany_yellowback::math::global_ratio_bps(
                GOLDEN_TOTALS.collateral_zat,
                Some(1_990_000),
                GOLDEN_TOTALS.open_debt_cents,
            ),
            halt_mask: 0,
            attest: if armed {
                AttestState {
                    status: AttestStatus::Armed,
                    trigger_height: 300,
                    arm_height: 308,
                }
            } else {
                AttestState::UNARMED
            },
            seated: if armed { SEATED.to_vec() } else { vec![] },
            pinned_keys: vec![],
            pinned_seqs: vec![],
        }
    }

    fn fresh_seqs(&self) -> Vec<u16> {
        let mut s: Vec<u16> = self
            .pool
            .iter()
            .filter(|a| a.fresh)
            .map(|a| a.attestation.seq)
            .collect();
        s.dedup();
        s
    }
}

impl YedIndexView for Fixture {
    fn tip(&self) -> Option<IndexTip> {
        Some(IndexTip {
            height: GOLDEN_TIP_HEIGHT,
            hash: hash_of(GOLDEN_TIP_HASH),
        })
    }

    fn health(&self) -> Health {
        Health {
            healthy: self.healthy,
            unhealthy_reason: if self.healthy {
                String::new()
            } else {
                "storage failure in Commit: test fault (storage:commit)".to_owned()
            },
            rebuilt: false,
        }
    }

    fn state_hash(&self) -> Hash32 {
        hash_of(GOLDEN_STATE_HASH)
    }

    fn totals(&self) -> Totals {
        GOLDEN_TOTALS
    }

    fn verify(&self) -> IndexAudit {
        IndexAudit {
            ok: true,
            tokens: 4,
            vaults: 5,
            stored: GOLDEN_TOTALS,
            records: GOLDEN_TOTALS,
            sets: vec![SetAudit {
                set_id: hash_of(GOLDEN_ATTESTOR_SET),
                locked_value_zat: GOLDEN_TOTALS.collateral_zat,
                records_zat: GOLDEN_TOTALS.collateral_zat,
            }],
            mismatches: vec![],
            rules_version: 1,
        }
    }

    fn snapshot_at(&self, height: i64) -> Option<SnapshotView> {
        (i64::from(self.params.start_height)..=GOLDEN_TIP_HEIGHT)
            .contains(&height)
            .then(|| self.snapshot(height))
    }

    fn quote_tags_in(&self, height: i64, window: i64) -> i64 {
        let lo = (height - window + 1).max(i64::from(self.params.start_height));
        (height - lo + 1).max(0)
    }

    fn mint_gate(&self) -> MintGate {
        MintGate {
            supply_cap_cents: None,
            supply_cap_reached: false,
            minting_allowed: true,
            mintable_classes: vec![0, 1, 2],
        }
    }

    fn attest_info(&self) -> AttestInfo {
        AttestInfo {
            state: self.snapshot(GOLDEN_TIP_HEIGHT).attest,
            seated_count: SEATED.len() as i64,
            pool_size: self.pool.len() as i64,
            pool_fresh: self.fresh_seqs().len() as i64,
            armed: self.params.attest_required,
            bond_min_zat: kogany_yellowback::math::bond_min_from_collateral_zat(
                GOLDEN_TOTALS.collateral_zat,
                &self.params,
            ),
        }
    }

    fn miners(&self, height: i64, window: i64) -> Vec<MinerRow> {
        let tags = self.quote_tags_in(height, window);
        vec![MinerRow {
            payout_key: PAYOUT_KEY,
            last_tag_height: height,
            last_quote: 2_000_000,
            quote_tags: tags,
            share: 10_000,
            registered: true,
            eligible: true,
            penalized_until: 0,
            accuracy_bps: Some(10_000),
            quoted: tags.min(i64::from(self.params.accuracy_window)),
            in_band: tags.min(i64::from(self.params.accuracy_window)),
        }]
    }

    fn eligible_payees(&self, _ref_height: i64) -> Vec<[u8; 20]> {
        vec![PAYOUT_KEY]
    }

    fn default_payee(&self, _ref_height: i64, _selector: &[u8]) -> Option<([u8; 20], i64)> {
        Some((PAYOUT_KEY, 10_000 + i64::from(self.params.payee_tilt_bps)))
    }

    fn vault(&self, txid: &Hash32) -> Option<VaultRow> {
        let i = VAULTS.iter().position(|v| v == txid)?;
        self.vault_row(i)
    }

    fn vaults(&self, status: Option<VaultStatus>, count: usize, skip: usize) -> Vec<VaultRow> {
        (0..VAULTS.len())
            .filter_map(|i| self.vault_row(i))
            .filter(|v| status.is_none_or(|s| s == v.status))
            .skip(skip)
            .take(count)
            .collect()
    }

    fn tokens(
        &self,
        holders: &[Holder],
        min_height: i64,
        count: usize,
        skip: usize,
    ) -> Vec<TokenRow> {
        let all = [
            TokenRow {
                outpoint: OutPoint {
                    txid: VAULTS[0],
                    n: 1,
                },
                cents: 100_000,
                value_zat: 10_000,
                height: 332,
                holder: Holder::KeyId([0x33; 20]),
            },
            TokenRow {
                outpoint: OutPoint {
                    txid: VAULTS[1],
                    n: 1,
                },
                cents: 50_000,
                value_zat: 10_000,
                height: 405,
                holder: Holder::Pq(PqOwner {
                    scheme: 2,
                    hash: filled(0x44),
                }),
            },
        ];
        all.into_iter()
            .filter(|t| holders.contains(&t.holder) && t.height >= min_height)
            .skip(skip)
            .take(count)
            .collect()
    }

    fn claimable(&self, count: usize, skip: usize) -> Vec<ClaimableRow> {
        let fee = protocol_fee_zat(100_000, 1_985_000, &self.params).unwrap_or(0);
        (0..2)
            .map(|i| ClaimableRow {
                vault: OutPoint {
                    txid: VAULTS[i],
                    n: 0,
                },
                owner: OWNER,
                collateral_zat: 251_889_169_000,
                minted_cents: 100_000,
                p_mint: 1_985_000,
                fee_zat: fee,
                claim_height: 401,
                lock_height: 377,
                claimable: i == 1,
                underwater_at: Some(496_250),
                p_claim: Some(if i == 1 { 400_000 } else { 2_000_000 }),
                claim_path: if i == 1 { "b" } else { "" },
                cancel_count: 0,
                cancels_required: 1,
                cancel_quiet_until: None,
                notice: (i == 1).then_some((436, 434 + i64::from(self.params.emergency_persist))),
                residual_zat: 0,
                attest_fee_zat: attest_fee_zat(fee, self.params.attest_fee_bps),
            })
            .skip(skip)
            .take(count)
            .collect()
    }

    fn tx_info(&self, txid: &Hash32) -> Option<TxInfoRow> {
        (*txid == VAULTS[0]).then(|| TxInfoRow {
            height: 332,
            kind: "mint".to_owned(),
            path: String::new(),
            verdict: "ok".to_owned(),
            yed_in: 0,
            yed_out: 100_000,
            burned: 0,
            fee_zat: 503_778_338,
            payee: Some(PAYOUT_KEY),
            assigned: vec![(1, 100_000)],
            spent_tokens: vec![],
            closed_vaults: vec![],
            reopened_vaults: vec![],
            expired: false,
            x_mint: Some(1_990_000),
            x_claim: Some(2_000_000),
            a_mint: Some(1_985_000),
            a_claim: Some(1_995_000),
            p_mint: Some(1_985_000),
            p_claim: Some(2_000_000),
            bundle_seqs: vec![1, 2],
            attest_fee_zat: 125_944_584,
            attest_payee: Some([0x62; 20]),
            residual_zat: 0,
            claim_path: String::new(),
            notice: false,
            carrier_vin: 1,
            bundle_source: "scriptsig".to_owned(),
            seq: None,
        })
    }

    fn estimate_collateral(
        &self,
        cents: i64,
        lock_blocks: i64,
        price: Option<i64>,
    ) -> Result<CollateralEstimate, YedError> {
        let p = &self.params;
        let class = (0..3u8).find(|c| {
            let c = usize::from(*c);
            p.is_class_enabled(c as i64)
                && p.class_min
                    .get(c)
                    .is_some_and(|m| i64::from(*m) <= lock_blocks)
                && p.class_max
                    .get(c)
                    .is_some_and(|m| lock_blocks <= i64::from(*m))
        });
        let Some(class) = class else {
            return Err(YedError::new(
                YedErrorKind::InvalidParameter,
                "mint-bad-lock",
                format!("lockBlocks {lock_blocks} is in no term class"),
            ));
        };
        if cents < p.min_mint || cents > p.max_mint {
            return Err(YedError::plain(
                YedErrorKind::InvalidParameter,
                format!("cents must be between {} and {}", p.min_mint, p.max_mint),
            ));
        }
        let r = GOLDEN_TIP_HEIGHT - 2;
        let lock_height = r + lock_blocks;
        if lock_height + i64::from(p.grace) >= i64::from(LOCKTIME_THRESHOLD) {
            return Err(YedError::new(
                YedErrorKind::InvalidParameter,
                "mint-bad-lock",
                "lockHeight + GRACE exceeds LOCKTIME_THRESHOLD",
            ));
        }
        let base = p
            .base_ratio_bps
            .get(usize::from(class))
            .copied()
            .unwrap_or(0);
        let min_ratio = min_ratio_bps(base, 10_000);
        let (x_mint, a_mint) = (Some(1_990_000), Some(1_985_000));
        let p_mint = price.or(Some(1_985_000));
        let required =
            p_mint.and_then(|pm| required_collateral_rounded(cents, min_ratio, pm, 1000));
        if p_mint.is_some() && required.is_none() {
            return Err(YedError::new(
                YedErrorKind::Rejected,
                "mint-unsatisfiable",
                "the required collateral exceeds MAX_MONEY (more YEC than can exist; lower the amount or the term class)",
            ));
        }
        let fee = p_mint
            .and_then(|pm| protocol_fee_zat(cents, pm, p))
            .unwrap_or(0);
        let armed = price.is_none();
        Ok(CollateralEstimate {
            required_zat: required,
            required_zat_floored: required,
            protocol_fee_cents: protocol_fee_cents(cents, p),
            protocol_fee_zat: fee,
            term_class: class,
            lock_height,
            claim_height: lock_height + i64::from(p.grace),
            min_ratio_bps: i64::from(min_ratio),
            base_ratio_bps: i64::from(base),
            sigma_mult_bps: 10_000,
            p_mint,
            ref_height: r,
            x_mint,
            a_mint,
            source: if armed { "a" } else { "" },
            armed,
            bundle_seqs: if armed { vec![1, 2] } else { vec![] },
            attest_fee_zat: if armed {
                attest_fee_zat(fee, p.attest_fee_bps)
            } else {
                0
            },
            divergence_bps: Some(75),
            mint_blocked: None,
        })
    }

    fn attestors(&self, height: i64) -> Vec<AttestorRow> {
        (1..=4u16)
            .map(|seq| {
                let b = u8::try_from(seq).unwrap_or(0);
                AttestorRow {
                    seq,
                    attestor_pub_key: key(0xb0 | b),
                    bond_pub_key: key(0xb0 | b),
                    bond_outpoint: OutPoint {
                        txid: filled(0x70 | b),
                        n: 0,
                    },
                    bond_zat: 1_000_000_000,
                    bond_locktime: 500,
                    flags: 0,
                    register_height: 280,
                    status: if seq == 4 {
                        AttestorStatus::Ejected
                    } else {
                        AttestorStatus::Eligible
                    },
                    status_height: 288,
                    bond_spent_height: None,
                    seated_since: (seq != 4).then_some(300),
                    last_act: 281,
                    bond_frozen: seq == 4,
                    founding: true,
                    weight: (1_000_000_000i64 * 64).to_string(),
                    seat_weight: (65_536i64 * 1_000_000_000 + i64::from(seq)).to_string(),
                    evicted: false,
                    seated: seq != 4 && height >= 308,
                    pinned: false,
                    last_bundle_height: (seq != 4).then_some(330),
                    pool_fresh: self.fresh_seqs().contains(&seq),
                }
            })
            .collect()
    }

    fn pool(&self) -> Vec<PooledAttestation> {
        self.pool.clone()
    }

    fn build_bundle(&self, _ref_height: i64, _selector: &[u8]) -> Result<BuiltBundle, YedError> {
        let atts: Vec<&PooledAttestation> = self.pool.iter().filter(|a| a.fresh).take(2).collect();
        if atts.len() < 2 {
            return Err(YedError::new(
                YedErrorKind::Rejected,
                "bundle-insufficient",
                format!(
                    "{} of 3 selected attestors have a fresh attestation; missing seq 3",
                    atts.len()
                ),
            ));
        }
        let mut bundle = vec![b'Y', b'A', 0x01, 2];
        for a in &atts {
            bundle.extend_from_slice(&a.attestation.encode());
        }
        Ok(BuiltBundle {
            armed: true,
            selected: vec![2, 1, 3],
            seqs: atts.iter().map(|a| a.attestation.seq).collect(),
            missing: vec![],
            bundle,
            a_mint: Some(1_985_000),
            a_claim: Some(1_985_000),
        })
    }

    fn selection(&self, _ref_height: i64, _selector: &[u8]) -> Selection {
        let fresh = self.fresh_seqs();
        Selection {
            armed: true,
            pool: SEATED.to_vec(),
            sum_weight: (3 * 64_000_000_000i64).to_string(),
            selected: [2u16, 1, 3]
                .iter()
                .map(|seq| SelectedAttestor {
                    seq: *seq,
                    weight: 64_000_000_000i64.to_string(),
                    bond_key: Some([0x62; 20]),
                    status: Some(AttestorStatus::Eligible),
                    pool_fresh: fresh.contains(seq),
                })
                .collect(),
        }
    }

    fn notice(&self, txid: &Hash32) -> NoticeLookup {
        match VAULTS.iter().position(|v| v == txid) {
            None => NoticeLookup::VaultNotFound,
            Some(1) => NoticeLookup::Standing(NoticeRow {
                txid: filled(0x8c),
                height: 436,
                ref_height: 434,
                p_emerg: 1_800_000,
            }),
            Some(_) => NoticeLookup::None,
        }
    }
}
