//! The read boundary between the `yed_*` RPCs and the node's Yellowback state.
//!
//! As for the vault reads ([`crate::state`]), the RPC layer parses arguments, gates, formats and
//! names errors; it decides nothing a block could change. Everything the module's index and state
//! machine decide (prices, halts, arming, claimability, verdicts, payees, the attestation pool)
//! comes from a [`YedReadState`], which plan W5-e (the index) and W5-f (its registration in the
//! node) implement over `kogany-yellowback`'s `state` (W5-d1/d2). This crate ships
//! [`super::mock::UnavailableYedState`] (Yellowback not live: every method is `-32601`, ycashd's
//! answer without the vault upgrade or the YED attestor set) and [`super::mock::MockYedState`]
//! (a fixture built on `testdata/yellowback/yellowback_golden.json`).
//!
//! One call reads one [`YedSnapshot`], so every field of one answer is taken at one index tip,
//! as ycash6 reads one `State` under `cs_yellowback` (`src/rpc/yellowback.cpp`).
//!
//! Conventions: heights are `i64` (`-1` = none); prices are micro-USD per YEC, `None` where
//! ycash6 stores `0` for "undefined" and renders `null`; amounts are zatoshi, YED amounts cents.
//! Txids, block hashes and set ids are [`Hash32`] in internal byte order (the RPC layer reverses
//! them for display); key hashes are the 20 bytes of a `CKeyID`; a vault owner is a [`PqOwner`].
//! Strings that are ycash6 rule names (verdicts, `path`, `claimPath`, TxLog types, the
//! unhealthy reason) are passed through verbatim.

use std::sync::Arc;

use async_trait::async_trait;
use kogany_vault::{Hash32, OutPoint, PqOwner, PubKeyBytes};
use kogany_yellowback::{
    codecs::{script::Holder, tag::CoinbaseTag},
    params::Params,
};

/// The Yellowback state of the node, as the `yed_*` RPCs see it.
///
/// The read methods take a [`YedSnapshot`]; the two node-state methods (`yed_setquote`,
/// `yed_addattestation`) and the three that need the chain or the mempool beyond the index
/// (`yed_gettag` by hash, `yed_validaterawtransaction`, `yed_getblockverdict`) are methods here.
#[async_trait]
pub trait YedReadState: Send + Sync + 'static {
    /// The Yellowback state at the current index tip, `Ok(None)` when Yellowback is not live on
    /// this node (the Vault upgrade not scheduled or no YED attestor set: every `yed_*` method
    /// then answers `-32601`, the lightwalletd-dd probe's "no Yellowback").
    ///
    /// An `Err` is answered as `-32603` with its text.
    async fn snapshot(&self) -> Result<Option<YedSnapshot>, String>;

    /// `yed_setquote` (MINER-1): store the miner's quote (`0` clears it) with `receivedAt` = now
    /// on the node's clock, and say what the next template's tag would be. The arguments are
    /// already range-checked; the implementation refuses `no-payout-address` when the node has
    /// no payout key.
    async fn set_quote(&self, price_micro_usd: i64, source_mask: u16)
        -> Result<QuoteAck, YedError>;

    /// `yed_addattestation`: verify one attestation against the tip and pool it (S4). Refusals,
    /// in order: `attest-unknown-seq`, `attest-not-eligible`, `attest-stale`, `attest-range`,
    /// `attest-bad-sig` (all [`YedErrorKind::Rejected`]).
    async fn add_attestation(&self, attestation: &Attestation) -> Result<AttestationAck, YedError>;

    /// The coinbase tag of a stored block (`yed_gettag`, `yed_getprice`'s `tag`): `Ok(None)`
    /// when the block carries no valid tag or is below `startHeight`. Errors:
    /// `"height out of range"`, `"block not found"`, `"block not on disk"`
    /// ([`YedErrorKind::InvalidParameter`], no identifier).
    async fn coinbase_tag(&self, block: BlockRef) -> Result<Option<CoinbaseTag>, YedError>;

    /// `yed_validaterawtransaction`: the dry run of §3.8 at `tip + 1` and script verification
    /// of a decoded transaction (`tx` is its serialisation). A transaction that does not decode
    /// is answered by the RPC layer (`-22 "TX decode failed"`) before this is called.
    async fn validate_raw_transaction(&self, tx: &[u8]) -> Result<TxValidation, YedError>;

    /// `yed_getblockverdict`: `EvaluateBlock` on a stored block whose parent is the index tip.
    /// Errors: `"block not found"`, `"block not on disk"`, `verdict-parent-not-tip`.
    async fn block_verdict(&self, block_hash: Hash32) -> Result<BlockVerdict, YedError>;
}

#[async_trait]
impl<S: YedReadState + ?Sized> YedReadState for Arc<S> {
    async fn snapshot(&self) -> Result<Option<YedSnapshot>, String> {
        (**self).snapshot().await
    }
    async fn set_quote(
        &self,
        price_micro_usd: i64,
        source_mask: u16,
    ) -> Result<QuoteAck, YedError> {
        (**self).set_quote(price_micro_usd, source_mask).await
    }
    async fn add_attestation(&self, attestation: &Attestation) -> Result<AttestationAck, YedError> {
        (**self).add_attestation(attestation).await
    }
    async fn coinbase_tag(&self, block: BlockRef) -> Result<Option<CoinbaseTag>, YedError> {
        (**self).coinbase_tag(block).await
    }
    async fn validate_raw_transaction(&self, tx: &[u8]) -> Result<TxValidation, YedError> {
        (**self).validate_raw_transaction(tx).await
    }
    async fn block_verdict(&self, block_hash: Hash32) -> Result<BlockVerdict, YedError> {
        (**self).block_verdict(block_hash).await
    }
}

/// A refusal with one of ycashd's error classes. The RPC message is `"<id>: <text>"` when `id`
/// is set (the M8 identifier the clients match), else `text`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct YedError {
    /// The JSON-RPC error class.
    pub kind: YedErrorKind,
    /// The stable identifier (`doc/yellowback-rpc.md`, "Error identifiers (M8)"), if any.
    pub id: Option<&'static str>,
    /// The free text after the identifier.
    pub text: String,
}

impl YedError {
    /// A refusal with an identifier.
    pub fn new(kind: YedErrorKind, id: &'static str, text: impl Into<String>) -> Self {
        Self {
            kind,
            id: Some(id),
            text: text.into(),
        }
    }

    /// A refusal without an identifier (a bad argument such as `"block not found"`).
    pub fn plain(kind: YedErrorKind, text: impl Into<String>) -> Self {
        Self {
            kind,
            id: None,
            text: text.into(),
        }
    }

    /// The message ycashd writes.
    pub fn message(&self) -> String {
        match self.id {
            Some(id) if self.text.is_empty() => id.to_owned(),
            Some(id) => format!("{id}: {}", self.text),
            None => self.text.clone(),
        }
    }
}

/// ycashd's error classes for a Yellowback refusal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum YedErrorKind {
    /// `RPC_INVALID_PARAMETER` (-8): a bad argument.
    InvalidParameter,
    /// `RPC_INVALID_ADDRESS_OR_KEY` (-5).
    InvalidAddressOrKey,
    /// `RPC_VERIFY_REJECTED` (-26): a rule refused it.
    Rejected,
    /// `RPC_DESERIALIZATION_ERROR` (-22).
    Deserialization,
    /// `RPC_INTERNAL_ERROR` (-32603).
    Internal,
}

/// A block named by height on the active chain or by hash (`yed_gettag`'s argument).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockRef {
    /// A height on the active chain.
    Height(i64),
    /// A block hash, internal order.
    Hash(Hash32),
}

/// One 74-byte attestation (`seq u16 ‖ priceMicroUsd u32 ‖ citedHeight u32 ‖ sig 64`,
/// little-endian; ycash6 `src/yellowback/attest.h`), decoded only.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Attestation {
    /// The attestor's sequence number.
    pub seq: u16,
    /// The attested price, micro-USD per YEC.
    pub price_micro_usd: u32,
    /// The height whose block hash the signature binds.
    pub cited_height: u32,
    /// The compact signature.
    pub sig: [u8; 64],
}

impl Attestation {
    /// The attestation size.
    pub const SIZE: usize = 74;

    /// `DecodeAttestation`: exactly [`Self::SIZE`] bytes.
    pub fn decode(b: &[u8]) -> Option<Self> {
        let b: &[u8; Self::SIZE] = b.try_into().ok()?;
        let (seq, rest) = b.split_at(2);
        let (price, rest) = rest.split_at(4);
        let (cited, sig) = rest.split_at(4);
        Some(Self {
            seq: u16::from_le_bytes(seq.try_into().ok()?),
            price_micro_usd: u32::from_le_bytes(price.try_into().ok()?),
            cited_height: u32::from_le_bytes(cited.try_into().ok()?),
            sig: sig.try_into().ok()?,
        })
    }

    /// `EncodeAttestation`.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::SIZE);
        out.extend_from_slice(&self.seq.to_le_bytes());
        out.extend_from_slice(&self.price_micro_usd.to_le_bytes());
        out.extend_from_slice(&self.cited_height.to_le_bytes());
        out.extend_from_slice(&self.sig);
        out
    }
}

/// What `yed_setquote` stored.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QuoteAck {
    /// `receivedAt`: Unix seconds on the node's clock.
    pub received_at: i64,
    /// The next template's tag kind (`"quote"` or `"none"`).
    pub next_kind: &'static str,
    /// The payout key the next tag carries.
    pub payout_key: Option<[u8; 20]>,
}

/// What `yed_addattestation` pooled.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AttestationAck {
    /// An older attestation of this `seq` was dropped, or a different one for the same height.
    pub replaced: bool,
    /// The pool's size after the call.
    pub pool_size: i64,
}

/// The Yellowback state at one index tip, with the node facts the answers need.
#[derive(Clone)]
pub struct YedSnapshot {
    /// The active chain's height (`yed_getinfo.chainHeight`), which the index may trail.
    pub chain_height: i64,
    /// The parameter set in force (ycash6 `index.GetParams()`; `ParamsAt(h)` where an answer
    /// names a height is the view's business).
    pub params: Params,
    /// The node's configuration and miner state.
    pub node: NodeInfo,
    /// The index at its tip.
    pub index: Arc<dyn YedIndexView>,
}

/// The node's own Yellowback configuration and state (not consensus).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeInfo {
    /// `REF_LAG` as this node uses it (`-yellowbackmintlag`, `g_yellowbackMintLag`).
    pub ref_lag: i64,
    /// `YELLOWBACK_FEE` (`-yellowbackfee`): the flat network-fee floor, zatoshi.
    pub fee_zat: i64,
    /// The L6 payee policy.
    pub payee_policy: PayeePolicy,
    /// `-yellowbackpreferredattestor`.
    pub preferred_attestor: Option<u16>,
    /// The miner's status now (`MinerStatus`).
    pub miner: MinerStatus,
    /// The network-fee policy at the tip (`params.fees.network`).
    pub network_fees: NetworkFees,
    /// Whether Falcon (scheme 2) is active at the next block (`params.pq.falconActive`).
    pub falcon_active_next: bool,
    /// The plain-YEC post-quantum address version of this network (`sq`/`tq`/`rq`, D-Q-20).
    pub plain_pq_address_version: [u8; 2],
}

/// The L6 payee policy (`PayeePolicy`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PayeePolicy {
    /// `penaltyBlocks`.
    pub penalty_blocks: i64,
    /// `accuracyWindow`.
    pub accuracy_window: i64,
    /// `tiltBps`.
    pub tilt_bps: i64,
    /// `-yellowbackpreferredpayee`.
    pub preferred: Option<[u8; 20]>,
}

/// The miner's status (`MinerStatus`): what the next template's tag would be.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MinerStatus {
    /// The payout key, `None` without one.
    pub payout_key: Option<[u8; 20]>,
    /// `"quote"` or `"none"`.
    pub quote_kind: &'static str,
    /// Seconds since the held quote was set, `None` without one.
    pub quote_age_seconds: Option<i64>,
    /// REG-1 of the payout key at the tip.
    pub registered: bool,
    /// Membership in `E(tip)` (FEE-2).
    pub eligible: bool,
    /// The held quote (`GetQuote()`), `None` without one (or after `yed_setquote 0`): the price
    /// and source mask the next template's tag carries when `quote_kind` is `"quote"` (plan
    /// W8-b, `BuildTagScript`).
    pub quote: Option<HeldQuote>,
}

/// The miner's held quote (ycash6 `QuoteHolder`, set by `yed_setquote`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HeldQuote {
    /// The YEC/USD quote, micro-USD (non-zero).
    pub price_micro_usd: i64,
    /// The informational source bitfield.
    pub source_mask: u16,
}

/// The dollar-per-KB network-fee policy (fees spec §3.4; ycash6 `AttestedFeePolicy`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NetworkFees {
    /// The attested tip price fees convert at, `None` while untrusted (`priceSource` fallback).
    pub price_micro_usd: Option<i64>,
    /// Plain PQ target, micro-USD per KB.
    pub plain_usd_per_kb_micro: i64,
    /// Plain PQ rate, zat per KB.
    pub plain_zat_per_kb: i64,
    /// Vault/Yellowback target, micro-USD per KB.
    pub yed_usd_per_kb_micro: i64,
    /// Vault/Yellowback rate, zat per KB.
    pub yed_zat_per_kb: i64,
    /// The Yellowback cap's dollar term, micro-USD.
    pub yed_max_tx_fee_usd_micro: i64,
    /// `-yellowbackmaxtxfee`, the cap's ceiling.
    pub yed_max_tx_fee_ceiling_zat: i64,
    /// The effective Yellowback cap.
    pub yed_max_tx_fee_zat: i64,
    /// The relay floor, zat per KB.
    pub floor_zat_per_kb: i64,
    /// `-pqfeerate`, the fallback without a price.
    pub fallback_zat_per_kb: i64,
    /// `-maxtxfee`.
    pub max_tx_fee_zat: i64,
}

/// The module's index at its tip (ycash6 `YellowbackIndex` and `State`).
///
/// Every method answers from the same state. Lists come in the orders the RPC contract names.
pub trait YedIndexView: Send + Sync {
    /// The tip the index holds, `None` while it is empty.
    fn tip(&self) -> Option<IndexTip>;

    /// The index's health (M8).
    fn health(&self) -> Health;

    /// The canonical state hash (ycash6 `GetStateHash`, SHA-256 over the §3.6 preimage),
    /// internal order.
    fn state_hash(&self) -> Hash32;

    /// The `Totals` record.
    fn totals(&self) -> Totals;

    /// The invariant audit (`yed_verifyindex`); read only.
    fn verify(&self) -> IndexAudit;

    /// The `Snapshots` record at `height`, `None` when there is none (below `startHeight`, above
    /// the tip, or an empty index); the RPC layer renders `None` as ycash6's virtual snapshot.
    fn snapshot_at(&self, height: i64) -> Option<SnapshotView>;

    /// The quote tags in `(height - window, height]`, bounded below by `startHeight`.
    fn quote_tags_in(&self, height: i64, window: i64) -> i64;

    /// The mint gate at the tip (`yed_getstats`, `yed_getinfo.supplyCapReached`).
    fn mint_gate(&self) -> MintGate;

    /// The arming state at the tip and this node's pool (`yed_getinfo.attest`), and the bond
    /// minimum a `SET_JOIN` in the next block must meet.
    fn attest_info(&self) -> AttestInfo;

    /// `yed_listminers`: one row per payout key with a quote tag in `(height - window, height]`,
    /// in descending `lastTagHeight` order (ties by key).
    fn miners(&self, height: i64, window: i64) -> Vec<MinerRow>;

    /// `E(ref_height)` (FEE-2), height order, deduplicated.
    fn eligible_payees(&self, ref_height: i64) -> Vec<[u8; 20]>;

    /// The FEE-W choice for `selector` (ignoring the preferred payee) with its weight, `None`
    /// when `E(ref_height)` is empty.
    fn default_payee(&self, ref_height: i64, selector: &[u8]) -> Option<([u8; 20], i64)>;

    /// The vault at `txid:0`, with its derived fields at the tip.
    fn vault(&self, txid: &Hash32) -> Option<VaultRow>;

    /// A page of the vaults in ascending outpoint order, filtered by status.
    fn vaults(&self, status: Option<VaultStatus>, count: usize, skip: usize) -> Vec<VaultRow>;

    /// A page of the live `Tokens` held by any of `holders` (a P2PKH key hash, a TX_PQPKH key
    /// or a TX_PQCHANNEL client), created at or above `min_height`, sorted by
    /// `(height, txid, vout)`.
    fn tokens(
        &self,
        holders: &[Holder],
        min_height: i64,
        count: usize,
        skip: usize,
    ) -> Vec<TokenRow>;

    /// A page of the ACTIVE vaults whose claim branch is open, in outpoint order (IT-7).
    fn claimable(&self, count: usize, skip: usize) -> Vec<ClaimableRow>;

    /// The `TxLog` record of `txid` (or an expired wallet transaction), `None` when unknown.
    fn tx_info(&self, txid: &Hash32) -> Option<TxInfoRow>;

    /// `yed_estimatecollateral` at `R = tip - REF_LAG` (`price` overrides the snapshot's
    /// `pMint` and both bundle refusals). The RPC layer has checked the argument types and the
    /// price range; the view refuses `mint-bad-lock`, the cents range, `bundle-insufficient`,
    /// `mint10-diverged` and `mint-unsatisfiable`.
    fn estimate_collateral(
        &self,
        cents: i64,
        lock_blocks: i64,
        price: Option<i64>,
    ) -> Result<CollateralEstimate, YedError>;

    /// `yed_listattestors`: every `Attestors` record, ascending `seq`, with `seated`, `pinned`
    /// and the weights at `height`'s snapshot.
    fn attestors(&self, height: i64) -> Vec<AttestorRow>;

    /// This node's attestation pool, ascending `seq` then `citedHeight`.
    fn pool(&self) -> Vec<PooledAttestation>;

    /// The bundle this node would build for `(ref_height, selector)` (refuses
    /// `bundle-insufficient`).
    fn build_bundle(&self, ref_height: i64, selector: &[u8]) -> Result<BuiltBundle, YedError>;

    /// `selected(ref_height, selector)` with what `yed_getselection` reports.
    fn selection(&self, ref_height: i64, selector: &[u8]) -> Selection;

    /// The `Notices` record of the vault `txid:0`.
    fn notice(&self, txid: &Hash32) -> NoticeLookup;
}

/// The index tip.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IndexTip {
    /// Its height.
    pub height: i64,
    /// Its block hash, internal order.
    pub hash: Hash32,
}

/// The index's health.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Health {
    /// `IsHealthy()`.
    pub healthy: bool,
    /// `UnhealthyReason()`, `""` when healthy.
    pub unhealthy_reason: String,
    /// This start rebuilt the index (`SCHEMA_VERSION` or `RULES_VERSION` mismatch).
    pub rebuilt: bool,
}

/// The `Totals` record (§3.6).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Totals {
    /// `supplyCents`.
    pub supply_cents: i64,
    /// `collateralZat` (ACTIVE and CLAIMING vaults).
    pub collateral_zat: i64,
    /// `activeVaults`.
    pub active_vaults: i64,
    /// `voidVaults`.
    pub void_vaults: i64,
    /// `closedVaults`.
    pub closed_vaults: i64,
    /// `claimedVaults`.
    pub claimed_vaults: i64,
    /// `unbackedCents`.
    pub unbacked_cents: i64,
    /// `openDebtCents` (HALT-2's denominator).
    pub open_debt_cents: i64,
}

/// `yed_verifyindex`'s audit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IndexAudit {
    /// Whether the totals and every set's locked value re-derive (`ok`).
    pub ok: bool,
    /// The live `Tokens` records read.
    pub tokens: i64,
    /// The `Vaults` records read.
    pub vaults: i64,
    /// The `Totals` record.
    pub stored: Totals,
    /// The re-derived totals.
    pub records: Totals,
    /// Every signer set's stored and re-derived locked value.
    pub sets: Vec<SetAudit>,
    /// One line per disagreement.
    pub mismatches: Vec<String>,
    /// The index's `RULES_VERSION` stamp.
    pub rules_version: i64,
}

/// One set of `yed_verifyindex.sets`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SetAudit {
    /// The set id, internal order.
    pub set_id: Hash32,
    /// The stored `lockedValue`.
    pub locked_value_zat: i64,
    /// The sum of its unspent V outputs.
    pub records_zat: i64,
}

/// The arming status (`AttestStatus`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AttestStatus {
    /// `UNARMED`
    Unarmed,
    /// `TRIGGERED`
    Triggered,
    /// `ARMED`
    Armed,
}

impl AttestStatus {
    /// The RPC name.
    pub fn name(self) -> &'static str {
        match self {
            AttestStatus::Unarmed => "UNARMED",
            AttestStatus::Triggered => "TRIGGERED",
            AttestStatus::Armed => "ARMED",
        }
    }
}

/// The `Attest` record of a snapshot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AttestState {
    /// The arming status.
    pub status: AttestStatus,
    /// `triggerHeight` (0 while UNARMED).
    pub trigger_height: i64,
    /// `armHeight` (0 while UNARMED).
    pub arm_height: i64,
}

impl AttestState {
    /// `AttestState()`: unarmed.
    pub const UNARMED: AttestState = AttestState {
        status: AttestStatus::Unarmed,
        trigger_height: 0,
        arm_height: 0,
    };
}

/// One `Snapshots` record (§3.6), undefined prices `None`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SnapshotView {
    /// The block's hash, internal order.
    pub block_hash: Hash32,
    /// The block carried a valid tag.
    pub tagged: bool,
    /// That tag carried a quote.
    pub quote: bool,
    /// `P_fast`.
    pub p_fast: Option<i64>,
    /// `P_mid`.
    pub p_mid: Option<i64>,
    /// `P_slow`.
    pub p_slow: Option<i64>,
    /// The cross-section `pMint` (`xMint`).
    pub p_mint: Option<i64>,
    /// The cross-section `pClaim` (`xClaim`).
    pub p_claim: Option<i64>,
    /// SIGMA-1's multiplier.
    pub sigma_mult_bps: i64,
    /// The circulating YEC (MINT-6's base).
    pub issued_zat: i64,
    /// `supplyCents` copied from `Totals`.
    pub supply_cents: i64,
    /// `collateralZat` copied from `Totals`.
    pub collateral_zat: i64,
    /// `openDebtCents` copied from `Totals`.
    pub open_debt_cents: i64,
    /// HALT-2's ratio, `None` without open debt or `pMint`.
    pub global_ratio_bps: Option<i64>,
    /// The halt mask (`HALT_*` bits, [`halt_mask_names`]).
    pub halt_mask: u32,
    /// The arming state.
    pub attest: AttestState,
    /// `seated[]`, ascending.
    pub seated: Vec<u16>,
    /// PIN-1's excluded pool keys.
    pub pinned_keys: Vec<[u8; 20]>,
    /// PIN-2's excluded `seq`s.
    pub pinned_seqs: Vec<u16>,
}

/// The halt-mask names in bit order (ycash6 `HaltMaskNames`).
pub fn halt_mask_names(mask: u32) -> Vec<&'static str> {
    const NAMES: [(u32, &str); 6] = [
        (1 << 0, "NOT_ACTIVE"),
        (1 << 1, "NO_PRICE"),
        (1 << 2, "PARTICIPATION"),
        (1 << 3, "GLOBAL_RATIO"),
        (1 << 4, "DIVERGENCE"),
        (1 << 5, "ENFORCEMENT"),
    ];
    NAMES
        .iter()
        .filter(|(bit, _)| mask & bit != 0)
        .map(|(_, name)| *name)
        .collect()
}

/// The mint gate at the tip.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MintGate {
    /// MINT-6's cap at the tip, `None` without a cap.
    pub supply_cap_cents: Option<i64>,
    /// The next mint of any class would exceed the cap (W20).
    pub supply_cap_reached: bool,
    /// `mintingAllowed`.
    pub minting_allowed: bool,
    /// The term classes a mint can use now (0 = A), class order.
    pub mintable_classes: Vec<u8>,
}

/// The arming state at the tip and this node's pool.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AttestInfo {
    /// The tip's `Attest` record.
    pub state: AttestState,
    /// `|Snapshots[tip].seated|`.
    pub seated_count: i64,
    /// Attestations in this node's pool.
    pub pool_size: i64,
    /// Seated `seq`s with a citable pooled attestation for a mint built now.
    pub pool_fresh: i64,
    /// `ATTEST_REQUIRED && status == ARMED`, of the set in force.
    pub armed: bool,
    /// D-Q-30: the bond floor of a `SET_JOIN` in the next block.
    pub bond_min_zat: i64,
}

/// A `yed_listminers` row.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MinerRow {
    /// The payout key.
    pub payout_key: [u8; 20],
    /// The latest quote tag's height.
    pub last_tag_height: i64,
    /// Its quote.
    pub last_quote: i64,
    /// Quote tags of this key in the window.
    pub quote_tags: i64,
    /// Its share of the window's quote tags, bps.
    pub share: i64,
    /// REG-1.
    pub registered: bool,
    /// FEE-2.
    pub eligible: bool,
    /// REG-2's penalty end, 0 when not penalised.
    pub penalized_until: i64,
    /// REG-3, `None` when no tag of this key was judged.
    pub accuracy_bps: Option<i64>,
    /// The judged quote tags.
    pub quoted: i64,
    /// How many were in the band.
    pub in_band: i64,
}

/// A vault status (`VaultStatus`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VaultStatus {
    /// `ACTIVE`
    Active,
    /// `VOID`
    Void,
    /// `CLOSED`
    Closed,
    /// `CLAIMED`
    Claimed,
    /// `CLAIMING`
    Claiming,
}

impl VaultStatus {
    /// The RPC name.
    pub fn name(self) -> &'static str {
        match self {
            VaultStatus::Active => "ACTIVE",
            VaultStatus::Void => "VOID",
            VaultStatus::Closed => "CLOSED",
            VaultStatus::Claimed => "CLAIMED",
            VaultStatus::Claiming => "CLAIMING",
        }
    }

    /// The status of an RPC name.
    pub fn parse(name: &str) -> Option<Self> {
        Some(match name {
            "ACTIVE" => VaultStatus::Active,
            "VOID" => VaultStatus::Void,
            "CLOSED" => VaultStatus::Closed,
            "CLAIMED" => VaultStatus::Claimed,
            "CLAIMING" => VaultStatus::Claiming,
            _ => return None,
        })
    }
}

/// A vault and its derived fields (`yed_getvault`, `yed_listvaults`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VaultRow {
    /// The vault's mint (or re-creating cancel) txid; the outpoint is `txid:0`.
    pub txid: Hash32,
    /// The status.
    pub status: VaultStatus,
    /// The post-quantum owner.
    pub owner: PqOwner,
    /// The term class (0 = A).
    pub term_class: u8,
    /// `lockHeight`.
    pub lock_height: i64,
    /// `claimHeight`.
    pub claim_height: i64,
    /// The locked collateral.
    pub collateral_zat: i64,
    /// The debt.
    pub minted_cents: i64,
    /// `mintHeight`.
    pub mint_height: i64,
    /// `refHeight`.
    pub ref_height: i64,
    /// The protocol fee the mint paid.
    pub fee_paid_zat: i64,
    /// The stored mint price.
    pub p_mint: i64,
    /// While not open: the closing height and txid.
    pub closed: Option<(i64, Hash32)>,
    /// `burnedCents`.
    pub burned_cents: i64,
    /// IN-2.
    pub unbacked: bool,
    /// CAN-2's count.
    pub cancel_count: i64,
    /// Co-signers a cancel in the next block needs.
    pub cancels_required: i64,
    /// `lastCancelHeight + CANCEL_QUIET`, `None` when never cancelled.
    pub cancel_quiet_until: Option<i64>,
    /// RED-4 would pass at the tip (either clause).
    pub claimable: bool,
    /// The claim price below which it is claimable, `None` for a VOID vault.
    pub underwater_at: Option<i64>,
    /// The failing MINT rule, `""`.
    pub void_reason: String,
    /// The V template's scriptPubKey.
    pub script_pubkey: Vec<u8>,
    /// While CLAIMING: its intents.
    pub intents: Option<Vec<VaultIntent>>,
    /// While CLAIMING: the scriptPubKey the claim's burned YED came from.
    pub refund_holder: Option<Vec<u8>>,
    /// CAN-3's held residual intents (absent when none).
    pub held_residuals: Option<Vec<OutPoint>>,
    /// The standing notice: `(height, refHeight + EMERGENCY_PERSIST)`.
    pub notice: Option<(i64, i64)>,
    /// A mempool transaction spending the vault (`yed_getvault` only).
    pub spend_txid: Option<Hash32>,
}

/// A claim intent of a CLAIMING vault.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VaultIntent {
    /// The intent output.
    pub outpoint: OutPoint,
    /// `true` for the claimant intent, `false` for the owner residual.
    pub claimant: bool,
    /// The height it confirmed at.
    pub height: i64,
    /// `height + CLAIM_DELAY`.
    pub release_height: i64,
}

/// A live token (`yed_listtokens`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TokenRow {
    /// The token output.
    pub outpoint: OutPoint,
    /// Its YED.
    pub cents: i64,
    /// Its YEC value.
    pub value_zat: i64,
    /// The height it was created at.
    pub height: i64,
    /// Its holder.
    pub holder: Holder,
}

/// A `yed_listclaimable` row.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClaimableRow {
    /// The vault outpoint.
    pub vault: OutPoint,
    /// Its owner.
    pub owner: PqOwner,
    /// Its collateral.
    pub collateral_zat: i64,
    /// Its debt.
    pub minted_cents: i64,
    /// Its stored mint price.
    pub p_mint: i64,
    /// RED-3′'s protocol fee.
    pub fee_zat: i64,
    /// `claimHeight`.
    pub claim_height: i64,
    /// `lockHeight`.
    pub lock_height: i64,
    /// RED-4 would pass.
    pub claimable: bool,
    /// The claim price below which it is claimable.
    pub underwater_at: Option<i64>,
    /// The claim price at the tip.
    pub p_claim: Option<i64>,
    /// `"a"`, `"b"` or `""`.
    pub claim_path: &'static str,
    /// CAN-2's count.
    pub cancel_count: i64,
    /// Co-signers a cancel in the next block needs.
    pub cancels_required: i64,
    /// `lastCancelHeight + CANCEL_QUIET`.
    pub cancel_quiet_until: Option<i64>,
    /// The standing notice: `(height, emergencyOpenAt)`.
    pub notice: Option<(i64, i64)>,
    /// RED-5's residual.
    pub residual_zat: i64,
    /// AFEE-1′.
    pub attest_fee_zat: i64,
}

/// A `TxLog` record (`yed_gettxinfo`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxInfoRow {
    /// The height (`-1` for an expired wallet transaction).
    pub height: i64,
    /// The TxLog type name (`"mint"`, `"transfer"`, `"redeem"`, …).
    pub kind: String,
    /// `"owner"`, `"claim"` or `""`.
    pub path: String,
    /// The verdict (`"ok"`, `"expired"`).
    pub verdict: String,
    /// `yedIn`.
    pub yed_in: i64,
    /// `yedOut`.
    pub yed_out: i64,
    /// `burned`.
    pub burned: i64,
    /// The protocol fee paid.
    pub fee_zat: i64,
    /// The fee output's key.
    pub payee: Option<[u8; 20]>,
    /// The cents assigned per output `(vout, cents)`.
    pub assigned: Vec<(u32, i64)>,
    /// The tokens consumed.
    pub spent_tokens: Vec<OutPoint>,
    /// The vaults closed.
    pub closed_vaults: Vec<OutPoint>,
    /// The vaults a cancel re-created.
    pub reopened_vaults: Vec<OutPoint>,
    /// An expired wallet transaction.
    pub expired: bool,
    /// The cross-section at its `refHeight`.
    pub x_mint: Option<i64>,
    /// The cross-section at its `refHeight`.
    pub x_claim: Option<i64>,
    /// The bundle statistic.
    pub a_mint: Option<i64>,
    /// The bundle statistic.
    pub a_claim: Option<i64>,
    /// The combined PRICE-2 price.
    pub p_mint: Option<i64>,
    /// The combined PRICE-2 price.
    pub p_claim: Option<i64>,
    /// The contributing `seq`s, ascending.
    pub bundle_seqs: Vec<u16>,
    /// AFEE-1′.
    pub attest_fee_zat: i64,
    /// The attestor-fee payee key.
    pub attest_payee: Option<[u8; 20]>,
    /// RED-5's amount.
    pub residual_zat: i64,
    /// `"a"`, `"b"` or `""`.
    pub claim_path: String,
    /// It wrote a `Notices` record.
    pub notice: bool,
    /// The carrier's input index, `-1` for none.
    pub carrier_vin: i64,
    /// `"scriptsig"`, `"opreturn"` or `""`.
    pub bundle_source: String,
    /// The attestor `seq` of a `"register"` or `"set_act"` row.
    pub seq: Option<u16>,
}

/// `yed_validaterawtransaction`'s answer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxValidation {
    /// Every input verifies at `tip + 1`.
    pub valid: bool,
    /// Why not, when `valid` is false.
    pub invalid_reason: Option<String>,
    /// The verdict (`"ok"` for a transaction the module does not judge).
    pub verdict: String,
    /// The TxLog type name, `"none"` when not relevant.
    pub kind: String,
    /// `"owner"`, `"claim"` or `""`.
    pub path: String,
    /// `yedIn`.
    pub yed_in: i64,
    /// `yedOut`.
    pub yed_out: i64,
    /// `burned`.
    pub burned: i64,
    /// The protocol fee.
    pub fee_zat: i64,
    /// The fee output's key.
    pub payee: Option<[u8; 20]>,
    /// RED-1..5 (a block carrying it would be valid).
    pub block_valid: bool,
    /// The mempool refuses it.
    pub would_be_rejected: bool,
    /// MP-1's expiry bound holds.
    pub mempool_expiry_ok: bool,
    /// Inputs the index does not know.
    pub unconfirmed_inputs: Vec<OutPoint>,
}

/// `yed_getblockverdict`'s answer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockVerdict {
    /// A transaction in it is invalid under the Yellowback rules.
    pub block_invalid: bool,
    /// `"<verdict>:<txid>"` of the first invalid one, `""`.
    pub reason: String,
    /// Its verdict, `"ok"` when none.
    pub verdict: String,
    /// Every Yellowback-relevant transaction, block order.
    pub transactions: Vec<BlockVerdictTx>,
}

/// One transaction of a [`BlockVerdict`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockVerdictTx {
    /// The txid.
    pub txid: Hash32,
    /// The TxLog type name.
    pub kind: String,
    /// `"owner"`, `"claim"` or `""`.
    pub path: String,
    /// The verdict.
    pub verdict: String,
    /// `yedIn`.
    pub yed_in: i64,
    /// `yedOut`.
    pub yed_out: i64,
    /// The protocol fee.
    pub fee_zat: i64,
    /// The fee output's key.
    pub payee: Option<[u8; 20]>,
    /// The vaults it closes.
    pub closed_vaults: Vec<OutPoint>,
}

/// `yed_estimatecollateral`'s answer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CollateralEstimate {
    /// MINT-5's ratio clause rounded up to 1,000 zat; `None` without a price.
    pub required_zat: Option<i64>,
    /// What a mint locks (equal since rpcversion 8).
    pub required_zat_floored: Option<i64>,
    /// FEE-1′ of `cents`, cents (`0` without a price, as ycashd).
    pub protocol_fee_cents: i64,
    /// FEE-1′ of `cents` at `pMint`, zat (`0` without a price).
    pub protocol_fee_zat: i64,
    /// The class (0 = A).
    pub term_class: u8,
    /// `R + lockBlocks`.
    pub lock_height: i64,
    /// `lockHeight + GRACE`.
    pub claim_height: i64,
    /// `MinRatioBps(base, sigma)`.
    pub min_ratio_bps: i64,
    /// The class's base ratio.
    pub base_ratio_bps: i64,
    /// SIGMA-1.
    pub sigma_mult_bps: i64,
    /// The price used.
    pub p_mint: Option<i64>,
    /// `R`.
    pub ref_height: i64,
    /// The cross-section.
    pub x_mint: Option<i64>,
    /// The bundle statistic.
    pub a_mint: Option<i64>,
    /// `"x"`, `"a"` or `""`.
    pub source: &'static str,
    /// The snapshot's arming state.
    pub armed: bool,
    /// The `seq`s used.
    pub bundle_seqs: Vec<u16>,
    /// AFEE-1′.
    pub attest_fee_zat: i64,
    /// `|pFast - aMint| · 10⁴ / min(xMint, aMint)`.
    pub divergence_bps: Option<i64>,
    /// MINTPOL-1's refusal identifier, `None` when the mint gate is open.
    pub mint_blocked: Option<&'static str>,
}

/// An attestor status (`AttestorStatus`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AttestorStatus {
    /// `PENDING`
    Pending,
    /// `ELIGIBLE`
    Eligible,
    /// `DORMANT`
    Dormant,
    /// `EJECTED`
    Ejected,
    /// `WITHDRAWN`
    Withdrawn,
}

impl AttestorStatus {
    /// The RPC name.
    pub fn name(self) -> &'static str {
        match self {
            AttestorStatus::Pending => "PENDING",
            AttestorStatus::Eligible => "ELIGIBLE",
            AttestorStatus::Dormant => "DORMANT",
            AttestorStatus::Ejected => "EJECTED",
            AttestorStatus::Withdrawn => "WITHDRAWN",
        }
    }
}

/// A `yed_listattestors` row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttestorRow {
    /// The `seq`.
    pub seq: u16,
    /// The hot key (= the bond key since P4-b).
    pub attestor_pub_key: PubKeyBytes,
    /// The bond key.
    pub bond_pub_key: PubKeyBytes,
    /// The bond output.
    pub bond_outpoint: OutPoint,
    /// The bond.
    pub bond_zat: i64,
    /// The bond's CLTV height.
    pub bond_locktime: u32,
    /// The registration flags byte.
    pub flags: u8,
    /// `registerHeight`.
    pub register_height: i64,
    /// The status.
    pub status: AttestorStatus,
    /// The height it was last set.
    pub status_height: i64,
    /// The bond's spend height.
    pub bond_spent_height: Option<i64>,
    /// The height it entered `seated[]`.
    pub seated_since: Option<i64>,
    /// The set's lastAct for the member.
    pub last_act: i64,
    /// The set froze the bond.
    pub bond_frozen: bool,
    /// The founding cohort.
    pub founding: bool,
    /// The bond weight at `height` (a 256-bit value, as its decimal string).
    pub weight: String,
    /// The seat-ranking weight at `height` (Q16), decimal string.
    pub seat_weight: String,
    /// Evicted from the full set.
    pub evicted: bool,
    /// In `Snapshots[height].seated[]`.
    pub seated: bool,
    /// In `Snapshots[height].pinnedSeqs[]`.
    pub pinned: bool,
    /// The newest `BundleLog` row holding this `seq`.
    pub last_bundle_height: Option<i64>,
    /// The pool holds a citable attestation for `R = height - REF_LAG`.
    pub pool_fresh: bool,
}

/// One pooled attestation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PooledAttestation {
    /// The attestation.
    pub attestation: Attestation,
    /// The index tip when it was pooled.
    pub received_height: i64,
    /// Its `seq` is in the tip snapshot's `seated[]`.
    pub seated: bool,
    /// `citedHeight > tip - REF_LAG - ATTEST_MAX_AGE`.
    pub fresh: bool,
}

/// `yed_buildbundle`'s answer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BuiltBundle {
    /// The snapshot's arming state.
    pub armed: bool,
    /// `selected(R, selector)`, draw order.
    pub selected: Vec<u16>,
    /// The contributing `seq`s, ascending.
    pub seqs: Vec<u16>,
    /// Selected `seq`s without a usable attestation.
    pub missing: Vec<u16>,
    /// The bundle bytes.
    pub bundle: Vec<u8>,
    /// The bundle statistic.
    pub a_mint: Option<i64>,
    /// The bundle statistic.
    pub a_claim: Option<i64>,
}

/// `yed_getselection`'s answer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Selection {
    /// The snapshot's arming state.
    pub armed: bool,
    /// `Snapshots[R].seated[] \ pinnedSeqs[]`.
    pub pool: Vec<u16>,
    /// The pool's total weight, decimal string.
    pub sum_weight: String,
    /// The drawn `seq`s in draw order.
    pub selected: Vec<SelectedAttestor>,
}

/// One drawn attestor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SelectedAttestor {
    /// The `seq`.
    pub seq: u16,
    /// Its weight at `R`, decimal string.
    pub weight: String,
    /// Its bond key, `None` without a record.
    pub bond_key: Option<[u8; 20]>,
    /// Its status, `None` without a record.
    pub status: Option<AttestorStatus>,
    /// This node's pool holds a usable attestation for it at `R`.
    pub pool_fresh: bool,
}

/// `yed_getnotice`'s lookup.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NoticeLookup {
    /// No vault at `txid:0`.
    VaultNotFound,
    /// No record stands.
    None,
    /// The standing record.
    Standing(NoticeRow),
}

/// A `Notices` record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NoticeRow {
    /// The notice transaction.
    pub txid: Hash32,
    /// The block it confirmed in.
    pub height: i64,
    /// Its `R₁`.
    pub ref_height: i64,
    /// The emergency price it was judged under.
    pub p_emerg: i64,
}
