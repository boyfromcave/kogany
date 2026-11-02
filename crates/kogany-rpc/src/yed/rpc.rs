//! The 25 `yed_*` read RPCs and the 2 node-state ones (`yed_setquote`, `yed_addattestation`),
//! as ycash6 serves them from `src/rpc/yellowback.cpp` (`doc/yellowback-rpc.md`, rpcversion 8).
//!
//! Every method first asks the [`YedReadState`] for its snapshot: none means Yellowback is not
//! live on this node, answered `-32601 "Method not found (Yellowback is not active: …)"` exactly
//! as ycashd answers it (the lightwalletd-dd probe reads `-32601` as "no Yellowback"). Then the
//! arguments are checked with ycashd's messages, then health (M8: every method but
//! `yed_getinfo`, `yed_verifyindex`, `yed_getactivation`, `yed_gettag`, `yed_setquote`,
//! `yed_decodepayload` and `yed_getblockverdict` refuses `yellowback-unhealthy` on an
//! unhealthy index), then the answer is formatted from the view.

use std::sync::Arc;

use kogany_vault::{Hash32, OutPoint};
use kogany_yellowback::{
    codecs::{
        payload::{decode_payload, extract_op_return_data, find_payload, PayloadType},
        script::{find_carrier_input, parse_carrier_script_sig},
    },
    math::{attest_fee_zat, protocol_fee_cents, protocol_fee_zat},
    params::{PRICE_MAX, PRICE_MIN},
};
use serde_json::{json, Map, Value};
use zakura_chain::{
    parameters::Network, serialization::ZcashDeserializeInto, transaction::Transaction, transparent,
};
use zakura_rpc::server::{
    error::LegacyCode,
    jsonrpc::{ErrorCode, ErrorObject, RpcResult},
};

use crate::json::{display_hex, parse_display_hash, raw_hex, Yec};

use super::{
    format::{attestation_json, class_letter, decode_bundle, outpoint_json, payload_json, Fmt},
    params::{attestor_set_hex, params_json},
    state::{
        halt_mask_names, AttestStatus, Attestation, BlockRef, NoticeLookup, SnapshotView, VaultRow,
        VaultStatus, YedError, YedErrorKind, YedReadState, YedSnapshot,
    },
    types::*,
    YED_RPC_VERSION,
};

/// The Vault upgrade's branch ID as `yed_getactivation` writes it.
const BRANCH_ID_HEX: &str = "6d5b7a31";
/// ycashd's paging default (C-6).
const DEFAULT_LIST_COUNT: i64 = 1000;
/// `yed_listvaults`'s paging default.
const DEFAULT_VAULT_COUNT: i64 = 100;
/// `yed_listminers`'s window bound (C-6).
const MAX_LISTMINERS_WINDOW: i64 = 4032;
/// `yed_gethistory`'s row bound.
const MAX_HISTORY_ROWS: i64 = 2016;
/// ycashd's answer when Yellowback is not live (`EnsureIndex`).
pub const NOT_LIVE_MESSAGE: &str = "Method not found (Yellowback is not active: the vault upgrade or the YED attestor set is not configured on this network)";

crate::kogany_rpc_trait! {
    /// Ycash Yellowback (YED)'s node-context RPCs, as kogany serves them.
    ///
    /// They answer from a [`YedReadState`] and need no wallet; the wallet-context `yed_*`
    /// methods are yewd's (plan K-3, K-20) and kogany answers them `-32601`
    /// ([`super::wallet`]).
    pub trait YedRpc {
        /// Index status, the vault upgrade, miner state and parameters. Never refuses while
        /// unhealthy.
        #[method(name = "yed_getinfo", access = Unauthenticated)]
        async fn yed_getinfo(&self) -> RpcResult<InfoJson>;

        /// The state hash at the index tip (`height`, if given, must be the index height).
        #[method(name = "yed_getstatehash", access = Unauthenticated)]
        async fn yed_getstatehash(&self, height: Option<Value>) -> RpcResult<StateHashJson>;

        /// The invariant audit (read only). Answers on an unhealthy index too.
        #[method(name = "yed_verifyindex", access = Unauthenticated)]
        async fn yed_verifyindex(&self) -> RpcResult<VerifyIndexJson>;

        /// `Totals` plus the tip snapshot.
        #[method(name = "yed_getstats", access = Unauthenticated)]
        async fn yed_getstats(&self) -> RpcResult<StatsJson>;

        /// The snapshot prices at `height` (default the index tip) with their window fills and
        /// that block's tag.
        #[method(name = "yed_getprice", access = Unauthenticated)]
        async fn yed_getprice(&self, height: Option<Value>) -> RpcResult<PriceJson>;

        /// The vault upgrade's status.
        #[method(name = "yed_getactivation", access = Unauthenticated)]
        async fn yed_getactivation(&self) -> RpcResult<UpgradeJson>;

        /// One row per payout key with a quote tag in `(height - window, height]`.
        #[method(name = "yed_listminers", access = Unauthenticated)]
        async fn yed_listminers(&self, height: Option<Value>, window: Option<Value>) -> RpcResult<Vec<MinerRowJson>>;

        /// The coinbase tag of a block (all digits: a height on the active chain; else a block
        /// hash). Allowed while unhealthy.
        #[method(name = "yed_gettag", access = Unauthenticated)]
        async fn yed_gettag(&self, block: Value) -> RpcResult<TagJson>;

        /// Store the miner's quote (`0` clears it), MINER-1. Allowed while unhealthy.
        #[method(name = "yed_setquote", access = Admin)]
        async fn yed_setquote(&self, price_micro_usd: Value, source_mask: Value) -> RpcResult<SetQuoteJson>;

        /// `E(refHeight)` and the FEE-W choice for a selector.
        #[method(name = "yed_getfeepayee", access = Unauthenticated)]
        async fn yed_getfeepayee(&self, ref_height: Value, selector_hex: Option<Value>) -> RpcResult<FeePayeeJson>;

        /// The vault `txid:0` and its derived fields.
        #[method(name = "yed_getvault", access = Unauthenticated)]
        async fn yed_getvault(&self, txid: String) -> RpcResult<VaultJson>;

        /// A page of every vault, ascending outpoint order, optionally of one status.
        #[method(name = "yed_listvaults", access = Unauthenticated)]
        async fn yed_listvaults(&self, status: Option<Value>, count: Option<Value>, skip: Option<Value>) -> RpcResult<Vec<VaultJson>>;

        /// A page of the live YED tokens of 1..100 addresses, whoever holds the keys.
        #[method(name = "yed_listtokens", access = Unauthenticated)]
        async fn yed_listtokens(&self, addresses: Value, min_height: Option<Value>, count: Option<Value>, skip: Option<Value>) -> RpcResult<Vec<TokenJson>>;

        /// A page of the ACTIVE vaults whose claim branch is open, each with `claimable`.
        #[method(name = "yed_listclaimable", access = Unauthenticated)]
        async fn yed_listclaimable(&self, count: Option<Value>, skip: Option<Value>) -> RpcResult<Vec<ClaimableJson>>;

        /// The `TxLog` record of a confirmed transaction.
        #[method(name = "yed_gettxinfo", access = Unauthenticated)]
        async fn yed_gettxinfo(&self, txid: String) -> RpcResult<TxInfoJson>;

        /// Decode a Yellowback payload (the data push, an OP_RETURN script or a raw
        /// transaction) without touching state. Allowed while unhealthy.
        #[method(name = "yed_decodepayload", access = Unauthenticated)]
        async fn yed_decodepayload(&self, hex: String) -> RpcResult<Value>;

        /// Dry run of §3.8 at `tip + 1` plus script verification.
        #[method(name = "yed_validaterawtransaction", access = Unauthenticated)]
        async fn yed_validaterawtransaction(&self, hex: String) -> RpcResult<ValidateJson>;

        /// `EvaluateBlock` on a stored block whose parent is the index tip. Allowed while
        /// unhealthy.
        #[method(name = "yed_getblockverdict", access = Unauthenticated)]
        async fn yed_getblockverdict(&self, blockhash: String) -> RpcResult<BlockVerdictJson>;

        /// MINT-5's collateral for `cents` over `lockBlocks` at `R = tip - REF_LAG`.
        #[method(name = "yed_estimatecollateral", access = Unauthenticated)]
        async fn yed_estimatecollateral(&self, cents: Value, lock_blocks: Value, price_micro_usd: Option<Value>) -> RpcResult<CollateralJson>;

        /// FEE-1′, the protocol fee of a debt.
        #[method(name = "yed_estimatefee", access = Unauthenticated)]
        async fn yed_estimatefee(&self, minted_cents: Value, price_micro_usd: Option<Value>) -> RpcResult<FeeJson>;

        /// The `Snapshots` records for `from <= h <= to`.
        #[method(name = "yed_gethistory", access = Unauthenticated)]
        async fn yed_gethistory(&self, from: Value, to: Value) -> RpcResult<Vec<HistoryJson>>;

        /// Every `Attestors` record, ascending `seq`, evaluated at `height`.
        #[method(name = "yed_listattestors", access = Unauthenticated)]
        async fn yed_listattestors(&self, height: Option<Value>) -> RpcResult<Vec<AttestorJson>>;

        /// This node's attestation pool.
        #[method(name = "yed_getattestations", access = Unauthenticated)]
        async fn yed_getattestations(&self) -> RpcResult<Vec<PooledJson>>;

        /// Verify one 74-byte attestation against the tip and pool it.
        #[method(name = "yed_addattestation", access = Admin)]
        async fn yed_addattestation(&self, hex: Value) -> RpcResult<AddAttestationJson>;

        /// The bundle this node would build for `(refHeight, selector)`.
        #[method(name = "yed_buildbundle", access = Unauthenticated)]
        async fn yed_buildbundle(&self, ref_height: Value, selector_hex: Value) -> RpcResult<BundleJson>;

        /// `selected(refHeight, selector)` and its reachability.
        #[method(name = "yed_getselection", access = Unauthenticated)]
        async fn yed_getselection(&self, ref_height: Value, selector_hex: Value) -> RpcResult<SelectionJson>;

        /// The `Notices` record of the vault `vaultTxid:0`.
        #[method(name = "yed_getnotice", access = Unauthenticated)]
        async fn yed_getnotice(&self, vault_txid: String) -> RpcResult<NoticeJson>;
    }
    dispatch = YedRpcDispatch;
}

/// [`YedRpc`] over a [`YedReadState`].
#[derive(Clone)]
pub struct YedRpcImpl {
    state: Arc<dyn YedReadState>,
    network: Network,
}

impl YedRpcImpl {
    /// The `yed_*` RPCs over `state`, for `network` (its address encoding).
    pub fn new(state: Arc<dyn YedReadState>, network: Network) -> Self {
        Self { state, network }
    }

    /// These methods as a server extension.
    pub fn into_extension(self) -> zakura_rpc::server::kogany_extension::RpcExtension {
        YedRpcDispatch(self).into_extension()
    }

    /// The snapshot, or ycashd's `-32601` when Yellowback is not live.
    async fn live(&self) -> RpcResult<YedSnapshot> {
        match self.state.snapshot().await {
            Ok(Some(s)) => Ok(s),
            Ok(None) => Err(ErrorObject::new(
                ErrorCode::MethodNotFound,
                NOT_LIVE_MESSAGE,
            )),
            Err(message) => Err(ErrorObject::new(ErrorCode::InternalError, message)),
        }
    }

    fn fmt<'a>(&'a self, s: &'a YedSnapshot) -> Fmt<'a> {
        Fmt {
            network: &self.network,
            params: &s.params,
            plain_pq_version: s.node.plain_pq_address_version,
        }
    }
}

/// `EnsureHealthy`.
fn healthy(s: &YedSnapshot) -> RpcResult<()> {
    let h = s.index.health();
    if h.healthy {
        Ok(())
    } else {
        Err(rpc_error(
            LegacyCode::VerifyRejected,
            format!(
                "yellowback-unhealthy: {}; restart with -reindex-yellowback",
                h.unhealthy_reason
            ),
        ))
    }
}

fn rpc_error(code: LegacyCode, message: impl Into<String>) -> ErrorObject {
    ErrorObject::new(code, message)
}

fn invalid(message: impl Into<String>) -> ErrorObject {
    rpc_error(LegacyCode::InvalidParameter, message)
}

impl From<YedError> for ErrorObject {
    fn from(e: YedError) -> Self {
        let message = e.message();
        match e.kind {
            YedErrorKind::InvalidParameter => rpc_error(LegacyCode::InvalidParameter, message),
            YedErrorKind::InvalidAddressOrKey => {
                rpc_error(LegacyCode::InvalidAddressOrKey, message)
            }
            YedErrorKind::Rejected => rpc_error(LegacyCode::VerifyRejected, message),
            YedErrorKind::Deserialization => rpc_error(LegacyCode::Deserialization, message),
            YedErrorKind::Internal => ErrorObject::new(ErrorCode::InternalError, message),
        }
    }
}

/// A required number (`"<name> must be a number"`).
fn number(v: &Value, name: &str) -> RpcResult<i64> {
    v.as_i64()
        .ok_or_else(|| invalid(format!("{name} must be a number")))
}

/// An optional number with a default (`HeightArg`: `null` or absent is the default).
fn number_or(v: Option<&Value>, default: i64, name: &str) -> RpcResult<i64> {
    match v {
        None | Some(Value::Null) => Ok(default),
        Some(v) => number(v, name),
    }
}

/// `count`/`skip` (`"count and skip must be >= 0"`).
fn page(count: Option<&Value>, skip: Option<&Value>, default: i64) -> RpcResult<(usize, usize)> {
    let c = number_or(count, default, "count")?;
    let s = number_or(skip, 0, "skip")?;
    match (usize::try_from(c), usize::try_from(s)) {
        (Ok(c), Ok(s)) => Ok((c, s)),
        _ => Err(invalid("count and skip must be >= 0")),
    }
}

/// A price argument in `[PRICE_MIN, PRICE_MAX]`.
fn price_arg(v: Option<&Value>) -> RpcResult<Option<i64>> {
    match v {
        None | Some(Value::Null) => Ok(None),
        Some(v) => {
            let p = number(v, "priceMicroUsd")?;
            if !(PRICE_MIN..=PRICE_MAX).contains(&p) {
                return Err(invalid(format!(
                    "priceMicroUsd must be between {PRICE_MIN} and {PRICE_MAX} (PRICE_MIN, PRICE_MAX)"
                )));
            }
            Ok(Some(p))
        }
    }
}

/// `SelectorArg`: `""` or the 36-byte serialised vault outpoint.
fn selector_arg(v: &Value) -> RpcResult<Vec<u8>> {
    let s = v
        .as_str()
        .ok_or_else(|| invalid("selectorHex must be a string"))?;
    let bytes = hex::decode(s).map_err(|_| invalid("selectorHex must be hex"))?;
    if !bytes.is_empty() && bytes.len() != 36 {
        return Err(invalid("selectorHex must be empty (a MINT) or the 36-byte serialised vault outpoint (72 hex characters)"));
    }
    Ok(bytes)
}

/// ycashd's `ParseHashV` for a txid or block hash.
fn hash_arg(text: &str, name: &str) -> RpcResult<Hash32> {
    parse_display_hash(text, name)
}

/// The prices of a snapshot, ycashd's virtual snapshot for `None`.
struct Prices {
    p_fast: Option<i64>,
    p_mid: Option<i64>,
    p_slow: Option<i64>,
    p_mint: Option<i64>,
    p_claim: Option<i64>,
}

impl Prices {
    fn of(s: Option<&SnapshotView>) -> Self {
        Self {
            p_fast: s.and_then(|s| s.p_fast),
            p_mid: s.and_then(|s| s.p_mid),
            p_slow: s.and_then(|s| s.p_slow),
            p_mint: s.and_then(|s| s.p_mint),
            p_claim: s.and_then(|s| s.p_claim),
        }
    }
}

fn tag_json(tag: Option<kogany_yellowback::codecs::tag::CoinbaseTag>, fmt: &Fmt<'_>) -> TagJson {
    match tag {
        None => TagJson {
            found: false,
            kind: "none",
            version: None,
            price_micro_usd: None,
            source_mask: None,
            payout_address: None,
        },
        Some(t) => TagJson {
            found: true,
            kind: if t.is_quote() { "quote" } else { "signal" },
            version: Some(i64::from(kogany_yellowback::params::TAG_VERSION)),
            price_micro_usd: Some(t.price_micro_usd),
            source_mask: Some(t.source_mask),
            payout_address: Some(fmt.p2pkh(&t.payout_key)),
        },
    }
}

fn upgrade_json(s: &YedSnapshot, tip_height: i64) -> UpgradeJson {
    let p = &s.params;
    UpgradeJson {
        name: "Vault",
        branch_id: BRANCH_ID_HEX,
        status: if tip_height >= i64::from(p.start_height) {
            "active"
        } else {
            "pending"
        },
        activation_height: i64::from(p.start_height),
        attestor_set_id: attestor_set_hex(&p.attestor_set_id),
        claim_delay: i64::from(p.claim_delay),
        height: tip_height,
    }
}

fn vault_json(v: &VaultRow, fmt: &Fmt<'_>, with_spend: bool) -> VaultJson {
    VaultJson {
        txid: display_hex(&v.txid),
        vout: 0,
        status: v.status.name(),
        owner_scheme: v.owner.scheme,
        owner_hash: raw_hex(&v.owner.hash.0),
        owner_address: fmt.yed_pq_address(&v.owner),
        term_class: class_letter(v.term_class),
        lock_height: v.lock_height,
        claim_height: v.claim_height,
        collateral_zat: v.collateral_zat,
        collateral: Yec(v.collateral_zat),
        minted_cents: v.minted_cents,
        mint_height: v.mint_height,
        ref_height: v.ref_height,
        fee_paid_zat: v.fee_paid_zat,
        p_mint: v.p_mint,
        close_height: v.closed.map(|(h, _)| h),
        closing_txid: v.closed.map(|(_, t)| display_hex(&t)).unwrap_or_default(),
        burned_cents: v.burned_cents,
        unbacked: v.unbacked,
        cancel_count: v.cancel_count,
        cancels_required: v.cancels_required,
        cancel_quiet_until: v.cancel_quiet_until,
        claimable: v.claimable,
        underwater_at: v.underwater_at,
        void_reason: v.void_reason.clone(),
        script_pub_key: raw_hex(&v.script_pubkey),
        intents: v.intents.as_ref().map(|is| {
            is.iter()
                .map(|i| VaultIntentJson {
                    txid: display_hex(&i.outpoint.txid),
                    vout: i.outpoint.n,
                    role: if i.claimant { "claimant" } else { "residual" },
                    height: i.height,
                    release_height: i.release_height,
                })
                .collect()
        }),
        refund_holder: v.refund_holder.as_deref().map(raw_hex),
        held_residuals: v
            .held_residuals
            .as_ref()
            .filter(|h| !h.is_empty())
            .map(|h| h.iter().map(outpoint_json).collect()),
        noticed: v.notice.is_some(),
        notice_height: v.notice.map(|(h, _)| h),
        emergency_open_at: v.notice.map(|(_, e)| e),
        spend_pending: with_spend.then_some(v.spend_txid.is_some()),
        spend_txid: if with_spend {
            v.spend_txid.as_ref().map(display_hex)
        } else {
            None
        },
    }
}

fn outpoint_text(o: &OutPoint) -> String {
    format!("{}:{}", display_hex(&o.txid), o.n)
}

fn seqs(v: &[u16]) -> Vec<u16> {
    v.to_vec()
}

#[async_trait::async_trait]
impl YedRpc for YedRpcImpl {
    async fn yed_getinfo(&self) -> RpcResult<InfoJson> {
        let s = self.live().await?;
        let fmt = self.fmt(&s);
        let ix = &s.index;
        let tip = ix.tip();
        let h = tip.map_or(-1, |t| t.height);
        let snap = if h >= 0 { ix.snapshot_at(h) } else { None };
        let health = ix.health();
        let gate = ix.mint_gate();
        let attest = ix.attest_info();
        let m = &s.node.miner;
        let p = &s.params;
        Ok(InfoJson {
            rpcversion: YED_RPC_VERSION,
            enabled: true,
            network: p.network,
            height: h,
            blockhash: tip.map(|t| display_hex(&t.hash)).unwrap_or_default(),
            chain_height: s.chain_height,
            start_height: i64::from(p.start_height),
            healthy: health.healthy,
            unhealthy_reason: health.unhealthy_reason,
            supply_cap_reached: gate.supply_cap_reached,
            mint_requires_armed: p.mint_requires_armed,
            locked_outputs: 0,
            protected_by_index: false,
            rebuilt: health.rebuilt,
            upgrade: upgrade_json(&s, h),
            attest: InfoAttestJson {
                status: attest.state.status.name(),
                trigger_height: attest.state.trigger_height,
                arm_height: attest.state.arm_height,
                seated_count: attest.seated_count,
                pool_size: attest.pool_size,
                pool_fresh: attest.pool_fresh,
                carrier_mode: p.bundle_carrier.name(),
                required: p.attest_required,
                armed: attest.armed,
            },
            miner: MinerJson {
                payout_address: m.payout_key.as_ref().map(|k| fmt.p2pkh(k)),
                quote_kind: m.quote_kind,
                quote_age_seconds: m.quote_age_seconds,
                registered: m.registered,
                eligible: m.eligible,
            },
            params: params_json(&s, snap.as_ref(), &attest, |k| fmt.p2pkh(k)),
        })
    }

    async fn yed_getstatehash(&self, height: Option<Value>) -> RpcResult<StateHashJson> {
        let s = self.live().await?;
        healthy(&s)?;
        let tip = s.index.tip();
        let h = tip.map_or(-1, |t| t.height);
        if let Some(v) = height.as_ref().filter(|v| !v.is_null()) {
            let want = number(v, "height")?;
            if want != h {
                return Err(invalid(format!("index is at height {h}, not {want}")));
            }
        }
        Ok(StateHashJson {
            height: h,
            blockhash: tip.map(|t| display_hex(&t.hash)).unwrap_or_default(),
            statehash: display_hex(&s.index.state_hash()),
        })
    }

    async fn yed_verifyindex(&self) -> RpcResult<VerifyIndexJson> {
        let s = self.live().await?;
        let a = s.index.verify();
        let totals = |t: &super::state::Totals| TotalsJson {
            supply_cents: t.supply_cents,
            collateral_zat: t.collateral_zat,
            active_vaults: t.active_vaults,
            void_vaults: t.void_vaults,
            closed_vaults: t.closed_vaults,
            claimed_vaults: t.claimed_vaults,
            unbacked_cents: t.unbacked_cents,
            open_debt_cents: t.open_debt_cents,
        };
        Ok(VerifyIndexJson {
            height: s.index.tip().map_or(-1, |t| t.height),
            ok: a.ok && a.mismatches.is_empty(),
            tokens: a.tokens,
            vaults: a.vaults,
            stored: totals(&a.stored),
            records: totals(&a.records),
            sets: a
                .sets
                .iter()
                .map(|x| SetAuditJson {
                    setid: display_hex(&x.set_id),
                    locked_value_zat: x.locked_value_zat,
                    records_zat: x.records_zat,
                })
                .collect(),
            mismatches: a.mismatches.clone(),
            healthy: s.index.health().healthy,
            rules_version: a.rules_version,
        })
    }

    async fn yed_getstats(&self) -> RpcResult<StatsJson> {
        let s = self.live().await?;
        healthy(&s)?;
        let h = s.index.tip().map_or(-1, |t| t.height);
        let snap = if h >= 0 { s.index.snapshot_at(h) } else { None };
        let t = s.index.totals();
        let gate = s.index.mint_gate();
        let pr = Prices::of(snap.as_ref());
        Ok(StatsJson {
            height: h,
            supply_cents: t.supply_cents,
            collateral_zat: t.collateral_zat,
            active_vaults: t.active_vaults,
            void_vaults: t.void_vaults,
            closed_vaults: t.closed_vaults,
            claimed_vaults: t.claimed_vaults,
            unbacked_cents: t.unbacked_cents,
            open_debt_cents: t.open_debt_cents,
            issued_zat: snap.as_ref().map_or(0, |x| x.issued_zat),
            p_fast: pr.p_fast,
            p_mid: pr.p_mid,
            p_slow: pr.p_slow,
            p_mint: pr.p_mint,
            p_claim: pr.p_claim,
            sigma_mult_bps: snap.as_ref().map_or(10_000, |x| x.sigma_mult_bps),
            global_ratio_bps: snap.as_ref().and_then(|x| x.global_ratio_bps),
            global_ratio_denominator: "openDebt",
            supply_cap_cents: gate.supply_cap_cents,
            halt_mask: halt_mask_names(snap.as_ref().map_or(0, |x| x.halt_mask)),
            minting_allowed: gate.minting_allowed,
            mintable_classes: gate
                .mintable_classes
                .iter()
                .map(|c| class_letter(*c))
                .collect(),
        })
    }

    async fn yed_getprice(&self, height: Option<Value>) -> RpcResult<PriceJson> {
        let s = self.live().await?;
        healthy(&s)?;
        let p = &s.params;
        let tip = s.index.tip().map_or(-1, |t| t.height);
        let h = number_or(height.as_ref(), tip, "height")?;
        if h < 0 || h > tip {
            return Err(invalid(format!("height must be between 0 and {tip}")));
        }
        let start = i64::from(p.start_height);
        let snap = if h >= start {
            s.index.snapshot_at(h)
        } else {
            None
        };
        let pr = Prices::of(snap.as_ref());
        let attest = snap
            .as_ref()
            .map_or(super::state::AttestState::UNARMED, |x| x.attest);
        let fmt = self.fmt(&s);
        let fill = |window: i32| FillJson {
            quote_tags: if h >= start {
                s.index.quote_tags_in(h, i64::from(window))
            } else {
                0
            },
            window: i64::from(window),
            min_fill: i64::from(p.min_fill(window)),
        };
        let tag = self.state.coinbase_tag(BlockRef::Height(h)).await?;
        Ok(PriceJson {
            height: h,
            p_fast: pr.p_fast,
            p_mid: pr.p_mid,
            p_slow: pr.p_slow,
            p_mint: pr.p_mint,
            p_claim: pr.p_claim,
            x_mint: pr.p_mint,
            x_claim: pr.p_claim,
            armed: p.is_armed(attest.status == AttestStatus::Armed),
            attest_status: attest.status.name(),
            seated: snap.as_ref().map(|x| seqs(&x.seated)).unwrap_or_default(),
            pinned_keys: snap
                .as_ref()
                .map(|x| x.pinned_keys.iter().map(|k| fmt.p2pkh(k)).collect())
                .unwrap_or_default(),
            pinned_seqs: snap
                .as_ref()
                .map(|x| seqs(&x.pinned_seqs))
                .unwrap_or_default(),
            fill: FillsJson {
                fast: fill(p.p_fast_window),
                mid: fill(p.p_mid_window),
                slow: fill(p.p_slow_window),
            },
            tag: tag_json(tag, &fmt),
        })
    }

    async fn yed_getactivation(&self) -> RpcResult<UpgradeJson> {
        let s = self.live().await?;
        let h = s.index.tip().map_or(-1, |t| t.height);
        Ok(upgrade_json(&s, h))
    }

    async fn yed_listminers(
        &self,
        height: Option<Value>,
        window: Option<Value>,
    ) -> RpcResult<Vec<MinerRowJson>> {
        let s = self.live().await?;
        healthy(&s)?;
        let p = &s.params;
        let tip = s.index.tip().map_or(-1, |t| t.height);
        let h = number_or(height.as_ref(), tip, "height")?;
        let w = number_or(window.as_ref(), i64::from(p.payee_window), "window")?;
        let start = i64::from(p.start_height);
        if h < start || h > tip {
            return Err(invalid(format!("height must be between {start} and {tip}")));
        }
        if w <= 0 {
            return Err(invalid("window must be positive"));
        }
        if w > MAX_LISTMINERS_WINDOW {
            return Err(invalid(format!(
                "window must be at most {MAX_LISTMINERS_WINDOW}"
            )));
        }
        let fmt = self.fmt(&s);
        Ok(s.index
            .miners(h, w)
            .iter()
            .map(|r| MinerRowJson {
                payout_address: fmt.p2pkh(&r.payout_key),
                last_tag_height: r.last_tag_height,
                last_quote: r.last_quote,
                quote_tags: r.quote_tags,
                share: r.share,
                registered: r.registered,
                eligible: r.eligible,
                penalized_until: r.penalized_until,
                accuracy_bps: r.accuracy_bps,
                quoted: r.quoted,
                in_band: r.in_band,
            })
            .collect())
    }

    async fn yed_gettag(&self, block: Value) -> RpcResult<TagJson> {
        let s = self.live().await?;
        let arg = block
            .as_str()
            .ok_or_else(|| rpc_error(LegacyCode::Type, "Expected type string"))?;
        let r = if !arg.is_empty() && arg.bytes().all(|b| b.is_ascii_digit()) {
            BlockRef::Height(
                arg.parse::<i64>()
                    .map_err(|_| invalid("height out of range"))?,
            )
        } else {
            BlockRef::Hash(hash_arg(arg, "blockhash")?)
        };
        let tag = self.state.coinbase_tag(r).await?;
        Ok(tag_json(tag, &self.fmt(&s)))
    }

    async fn yed_setquote(
        &self,
        price_micro_usd: Value,
        source_mask: Value,
    ) -> RpcResult<SetQuoteJson> {
        let s = self.live().await?;
        let (Some(price), Some(mask)) = (price_micro_usd.as_i64(), source_mask.as_i64()) else {
            return Err(invalid("priceMicroUsd and sourceMask must be numbers"));
        };
        if price != 0 && !(PRICE_MIN..=PRICE_MAX).contains(&price) {
            return Err(invalid(format!(
                "quote-out-of-range: priceMicroUsd must be 0 or between {PRICE_MIN} and {PRICE_MAX}"
            )));
        }
        let mask16 =
            u16::try_from(mask).map_err(|_| invalid("sourceMask must be a 16-bit value"))?;
        let ack = self.state.set_quote(price, mask16).await?;
        let fmt = self.fmt(&s);
        Ok(SetQuoteJson {
            price_micro_usd: price,
            source_mask: mask,
            received_at: ack.received_at,
            next_tag: NextTagJson {
                kind: ack.next_kind,
                payout_address: ack.payout_key.as_ref().map(|k| fmt.p2pkh(k)),
            },
        })
    }

    async fn yed_getfeepayee(
        &self,
        ref_height: Value,
        selector_hex: Option<Value>,
    ) -> RpcResult<FeePayeeJson> {
        let s = self.live().await?;
        let r = number(&ref_height, "refHeight")?;
        let selector = match selector_hex.as_ref().filter(|v| !v.is_null()) {
            None => Vec::new(),
            Some(v) => v
                .as_str()
                .and_then(|t| hex::decode(t).ok())
                .ok_or_else(|| invalid("selectorHex must be hex"))?,
        };
        healthy(&s)?;
        let tip = s.index.tip().map_or(-1, |t| t.height);
        if r < i64::from(s.params.start_height) || r > tip {
            return Err(invalid("refHeight out of range"));
        }
        let eligible = s.index.eligible_payees(r);
        if eligible.is_empty() {
            return Err(rpc_error(
                LegacyCode::VerifyRejected,
                "fee-no-eligible-payee: no pool quoted in the payee window (FEE-0)",
            ));
        }
        let fmt = self.fmt(&s);
        let pp = &s.node.payee_policy;
        let default = match s.index.default_payee(r, &selector) {
            Some((k, weight)) => json!({"payoutAddress": fmt.p2pkh(&k), "weight": weight}),
            None => Value::Object(Map::new()),
        };
        Ok(FeePayeeJson {
            eligible: eligible.iter().map(|k| fmt.p2pkh(k)).collect(),
            default,
            preferred: pp
                .preferred
                .filter(|k| eligible.contains(k))
                .map(|k| fmt.p2pkh(&k)),
            policy: PolicyJson {
                penalty_blocks: pp.penalty_blocks,
                accuracy_window: pp.accuracy_window,
                tilt_bps: pp.tilt_bps,
            },
        })
    }

    async fn yed_getvault(&self, txid: String) -> RpcResult<VaultJson> {
        let s = self.live().await?;
        let id = hash_arg(&txid, "txid")?;
        healthy(&s)?;
        let v = s.index.vault(&id).ok_or_else(|| {
            invalid(format!(
                "vault-not-found: no vault at {}:0",
                display_hex(&id)
            ))
        })?;
        Ok(vault_json(&v, &self.fmt(&s), true))
    }

    async fn yed_listvaults(
        &self,
        status: Option<Value>,
        count: Option<Value>,
        skip: Option<Value>,
    ) -> RpcResult<Vec<VaultJson>> {
        let s = self.live().await?;
        let status = match status.as_ref().filter(|v| !v.is_null()) {
            None => None,
            Some(v) => {
                let text = v
                    .as_str()
                    .ok_or_else(|| rpc_error(LegacyCode::Type, "Expected type string"))?;
                if text.is_empty() {
                    None
                } else {
                    Some(VaultStatus::parse(text).ok_or_else(|| {
                        invalid("status must be ACTIVE, CLAIMING, VOID, CLOSED or CLAIMED")
                    })?)
                }
            }
        };
        let (count, skip) = page(count.as_ref(), skip.as_ref(), DEFAULT_VAULT_COUNT)?;
        healthy(&s)?;
        let fmt = self.fmt(&s);
        Ok(s.index
            .vaults(status, count, skip)
            .iter()
            .map(|v| vault_json(v, &fmt, false))
            .collect())
    }

    async fn yed_listtokens(
        &self,
        addresses: Value,
        min_height: Option<Value>,
        count: Option<Value>,
        skip: Option<Value>,
    ) -> RpcResult<Vec<TokenJson>> {
        let s = self.live().await?;
        let list = addresses
            .as_array()
            .ok_or_else(|| invalid("addresses must be an array"))?;
        if list.is_empty() || list.len() > 100 {
            return Err(invalid("too-many-addresses: 1..100 addresses"));
        }
        let min_height = number_or(min_height.as_ref(), 0, "minHeight")?;
        if min_height < 0 {
            return Err(invalid("minHeight must be >= 0"));
        }
        let (count, skip) = page(count.as_ref(), skip.as_ref(), DEFAULT_LIST_COUNT)?;
        let fmt = self.fmt(&s);
        let mut holders = Vec::with_capacity(list.len());
        for a in list {
            let text = a
                .as_str()
                .ok_or_else(|| invalid("invalid-address: addresses must be strings"))?;
            let holder = fmt.parse_holder(text).ok_or_else(|| {
                rpc_error(
                    LegacyCode::InvalidAddressOrKey,
                    format!("invalid-address: {text} is not a YED, transparent P2PKH or post-quantum address of this network"),
                )
            })?;
            if !holders.contains(&holder) {
                holders.push(holder);
            }
        }
        healthy(&s)?;
        Ok(s.index
            .tokens(&holders, min_height, count, skip)
            .iter()
            .map(|t| {
                let (address, transparent_address) = fmt.holder_addresses(&t.holder);
                TokenJson {
                    txid: display_hex(&t.outpoint.txid),
                    vout: t.outpoint.n,
                    cents: t.cents,
                    value_zat: t.value_zat,
                    height: t.height,
                    address,
                    transparent_address,
                }
            })
            .collect())
    }

    async fn yed_listclaimable(
        &self,
        count: Option<Value>,
        skip: Option<Value>,
    ) -> RpcResult<Vec<ClaimableJson>> {
        let s = self.live().await?;
        let (count, skip) = page(count.as_ref(), skip.as_ref(), DEFAULT_LIST_COUNT)?;
        healthy(&s)?;
        let fmt = self.fmt(&s);
        Ok(s.index
            .claimable(count, skip)
            .iter()
            .map(|c| ClaimableJson {
                vault: outpoint_text(&c.vault),
                owner_address: fmt.yed_pq_address(&c.owner),
                collateral_zat: c.collateral_zat,
                minted_cents: c.minted_cents,
                p_mint: c.p_mint,
                fee_zat: c.fee_zat,
                claim_height: c.claim_height,
                lock_height: c.lock_height,
                claimable: c.claimable,
                underwater_at: c.underwater_at,
                p_claim: c.p_claim,
                claim_path: if c.claimable { c.claim_path } else { "" },
                cancel_count: c.cancel_count,
                cancels_required: c.cancels_required,
                cancel_quiet_until: c.cancel_quiet_until,
                noticed: c.notice.is_some(),
                notice_height: c.notice.map(|(h, _)| h),
                emergency_open_at: c.notice.map(|(_, e)| e),
                residual_zat: c.residual_zat,
                attest_fee_zat: c.attest_fee_zat,
            })
            .collect())
    }

    async fn yed_gettxinfo(&self, txid: String) -> RpcResult<TxInfoJson> {
        let s = self.live().await?;
        let id = hash_arg(&txid, "txid")?;
        healthy(&s)?;
        let l = s.index.tx_info(&id).ok_or_else(|| {
            invalid(format!(
                "tx-not-found: {} is not in the Yellowback index",
                display_hex(&id)
            ))
        })?;
        let fmt = self.fmt(&s);
        let ops = |v: &[OutPoint]| v.iter().map(outpoint_json).collect::<Vec<_>>();
        Ok(TxInfoJson {
            txid: display_hex(&id),
            height: l.height,
            kind: l.kind.clone(),
            path: l.path.clone(),
            verdict: l.verdict.clone(),
            yed_in: l.yed_in,
            yed_out: l.yed_out,
            burned: l.burned,
            fee_zat: l.fee_zat,
            payee: l.payee.as_ref().map(|k| fmt.p2pkh(k)),
            assigned: l
                .assigned
                .iter()
                .map(|(vout, cents)| AssignedJson {
                    vout: *vout,
                    cents: *cents,
                })
                .collect(),
            spent_tokens: ops(&l.spent_tokens),
            closed_vaults: ops(&l.closed_vaults),
            reopened_vaults: ops(&l.reopened_vaults),
            expired: l.expired,
            x_mint: l.x_mint,
            x_claim: l.x_claim,
            a_mint: l.a_mint,
            a_claim: l.a_claim,
            p_mint: l.p_mint,
            p_claim: l.p_claim,
            bundle_seqs: l.bundle_seqs.clone(),
            attest_fee_zat: l.attest_fee_zat,
            attest_payee: l.attest_payee.as_ref().map(|k| fmt.p2pkh(k)),
            residual_zat: l.residual_zat,
            claim_path: l.claim_path.clone(),
            notice: l.notice,
            carrier_vin: l.carrier_vin,
            bundle_source: l.bundle_source.clone(),
            seq: l.seq,
        })
    }

    async fn yed_decodepayload(&self, hex: String) -> RpcResult<Value> {
        let s = self.live().await?;
        let bytes = hex::decode(&hex).map_err(|_| invalid("not hex"))?;
        let fmt = self.fmt(&s);
        if let Some(p) = decode_payload(&bytes) {
            return Ok(Value::Object(payload_json(&p, &fmt)));
        }
        if let Some(p) = extract_op_return_data(&bytes).and_then(decode_payload) {
            return Ok(Value::Object(payload_json(&p, &fmt)));
        }
        if let Some(o) = decode_tx_payload(&bytes, &fmt) {
            return Ok(Value::Object(o));
        }
        Ok(json!({
            "valid": false,
            "version": 0,
            "type": "none",
            "reason": "malformed: not a version-3 Yellowback payload, OP_RETURN script or transaction carrying one",
        }))
    }

    async fn yed_validaterawtransaction(&self, hex: String) -> RpcResult<ValidateJson> {
        let s = self.live().await?;
        let bytes = hex::decode(&hex)
            .ok()
            .filter(|b| b.zcash_deserialize_into::<Transaction>().is_ok())
            .ok_or_else(|| rpc_error(LegacyCode::Deserialization, "TX decode failed"))?;
        healthy(&s)?;
        let v = self.state.validate_raw_transaction(&bytes).await?;
        let fmt = self.fmt(&s);
        Ok(ValidateJson {
            valid: v.valid,
            invalid_reason: if v.valid { None } else { v.invalid_reason },
            verdict: v.verdict,
            kind: v.kind,
            path: v.path,
            yed_in: v.yed_in,
            yed_out: v.yed_out,
            burned: v.burned,
            fee_zat: v.fee_zat,
            payee: v.payee.as_ref().map(|k| fmt.p2pkh(k)),
            block_valid: v.block_valid,
            would_be_rejected: v.would_be_rejected,
            mempool_expiry_ok: v.mempool_expiry_ok,
            unconfirmed_inputs: v.unconfirmed_inputs.iter().map(outpoint_json).collect(),
        })
    }

    async fn yed_getblockverdict(&self, blockhash: String) -> RpcResult<BlockVerdictJson> {
        let s = self.live().await?;
        let hash = hash_arg(&blockhash, "blockhash")?;
        let v = self.state.block_verdict(hash).await?;
        let fmt = self.fmt(&s);
        Ok(BlockVerdictJson {
            block_invalid: v.block_invalid,
            reason: v.reason,
            verdict: v.verdict,
            transactions: v
                .transactions
                .iter()
                .map(|t| BlockVerdictTxJson {
                    txid: display_hex(&t.txid),
                    kind: t.kind.clone(),
                    path: t.path.clone(),
                    verdict: t.verdict.clone(),
                    yed_in: t.yed_in,
                    yed_out: t.yed_out,
                    fee_zat: t.fee_zat,
                    payee: t.payee.as_ref().map(|k| fmt.p2pkh(k)),
                    closed_vaults: t.closed_vaults.iter().map(outpoint_json).collect(),
                })
                .collect(),
        })
    }

    async fn yed_estimatecollateral(
        &self,
        cents: Value,
        lock_blocks: Value,
        price_micro_usd: Option<Value>,
    ) -> RpcResult<CollateralJson> {
        let s = self.live().await?;
        let (Some(cents), Some(lock_blocks)) = (cents.as_i64(), lock_blocks.as_i64()) else {
            return Err(invalid("cents and lockBlocks must be numbers"));
        };
        let price = price_arg(price_micro_usd.as_ref())?;
        healthy(&s)?;
        let e = s.index.estimate_collateral(cents, lock_blocks, price)?;
        Ok(CollateralJson {
            required_zat: e.required_zat,
            required_zat_floored: e.required_zat_floored,
            protocol_fee_cents: e.protocol_fee_cents,
            protocol_fee_zat: e.protocol_fee_zat,
            term_class: class_letter(e.term_class),
            lock_height: e.lock_height,
            claim_height: e.claim_height,
            min_ratio_bps: e.min_ratio_bps,
            base_ratio_bps: e.base_ratio_bps,
            sigma_mult_bps: e.sigma_mult_bps,
            p_mint: e.p_mint,
            ref_height: e.ref_height,
            x_mint: e.x_mint,
            a_mint: e.a_mint,
            source: e.source,
            armed: e.armed,
            bundle_seqs: e.bundle_seqs.clone(),
            attest_fee_zat: e.attest_fee_zat,
            divergence_bps: e.divergence_bps,
            mint_blocked: e.mint_blocked.is_some(),
            mint_blocked_reason: e.mint_blocked.unwrap_or(""),
        })
    }

    async fn yed_estimatefee(
        &self,
        minted_cents: Value,
        price_micro_usd: Option<Value>,
    ) -> RpcResult<FeeJson> {
        let s = self.live().await?;
        let cents = number(&minted_cents, "mintedCents")?;
        if !(0..=i64::from(u32::MAX)).contains(&cents) {
            return Err(invalid("mintedCents out of range"));
        }
        healthy(&s)?;
        let p = &s.params;
        let p_mint = match price_arg(price_micro_usd.as_ref())? {
            Some(price) => Some(price),
            None => {
                let tip = s.index.tip().map_or(-1, |t| t.height);
                let r = tip.saturating_sub(s.node.ref_lag);
                if r >= i64::from(p.start_height) {
                    s.index.snapshot_at(r).and_then(|x| x.p_mint)
                } else {
                    None
                }
            }
        };
        let fee_zat = p_mint.and_then(|price| protocol_fee_zat(cents, price, p));
        Ok(FeeJson {
            fee_cents: protocol_fee_cents(cents, p),
            p_mint,
            fee_zat,
            attest_fee_zat: fee_zat.map(|f| attest_fee_zat(f, p.attest_fee_bps)),
        })
    }

    async fn yed_gethistory(&self, from: Value, to: Value) -> RpcResult<Vec<HistoryJson>> {
        let s = self.live().await?;
        let (Some(from), Some(to)) = (from.as_i64(), to.as_i64()) else {
            return Err(invalid("from and to must be numbers"));
        };
        healthy(&s)?;
        let start = i64::from(s.params.start_height);
        let tip = s.index.tip().map_or(-1, |t| t.height);
        let from = from.max(start);
        if from < 0 || to < from || to > tip || to.saturating_sub(from) >= MAX_HISTORY_ROWS {
            return Err(invalid(format!(
                "range must satisfy {start} <= from <= to <= {tip} with at most 2016 rows"
            )));
        }
        Ok((from..=to)
            .filter_map(|h| s.index.snapshot_at(h).map(|x| (h, x)))
            .map(|(h, x)| HistoryJson {
                height: h,
                block_hash: display_hex(&x.block_hash),
                tagged: x.tagged,
                quote: x.quote,
                p_fast: x.p_fast,
                p_mid: x.p_mid,
                p_slow: x.p_slow,
                p_mint: x.p_mint,
                p_claim: x.p_claim,
                sigma_mult_bps: x.sigma_mult_bps,
                issued_zat: x.issued_zat,
                supply_cents: x.supply_cents,
                collateral_zat: x.collateral_zat,
                open_debt_cents: x.open_debt_cents,
                global_ratio_bps: x.global_ratio_bps,
                global_ratio_denominator: "openDebt",
                halt_mask: halt_mask_names(x.halt_mask),
            })
            .collect())
    }

    async fn yed_listattestors(&self, height: Option<Value>) -> RpcResult<Vec<AttestorJson>> {
        let s = self.live().await?;
        healthy(&s)?;
        let tip = s.index.tip().map_or(-1, |t| t.height);
        let h = number_or(height.as_ref(), tip, "height")?;
        if h < 0 || h > tip {
            return Err(invalid(format!("height must be between 0 and {tip}")));
        }
        let fmt = self.fmt(&s);
        Ok(s.index
            .attestors(h)
            .iter()
            .map(|r| AttestorJson {
                seq: r.seq,
                attestor_pub_key: raw_hex(&r.attestor_pub_key.0),
                bond_address: fmt
                    .bond_address(&r.bond_pub_key, r.bond_locktime)
                    .unwrap_or_default(),
                bond_key_address: fmt.key_address(&r.bond_pub_key),
                bond_outpoint: outpoint_json(&r.bond_outpoint),
                bond_zat: r.bond_zat,
                bond_locktime: r.bond_locktime,
                flags: FlagsJson::new(r.flags),
                register_height: r.register_height,
                status: r.status.name(),
                status_height: r.status_height,
                bond_spent_height: r.bond_spent_height,
                seated_since: r.seated_since,
                last_act: r.last_act,
                bond_frozen: r.bond_frozen,
                founding: r.founding,
                weight: r.weight.clone(),
                seat_weight: r.seat_weight.clone(),
                evicted: r.evicted,
                seated: r.seated,
                pinned: r.pinned,
                last_bundle_height: r.last_bundle_height,
                pool_fresh: r.pool_fresh,
            })
            .collect())
    }

    async fn yed_getattestations(&self) -> RpcResult<Vec<PooledJson>> {
        let s = self.live().await?;
        healthy(&s)?;
        Ok(s.index
            .pool()
            .iter()
            .map(|a| PooledJson {
                seq: a.attestation.seq,
                price_micro_usd: a.attestation.price_micro_usd,
                cited_height: a.attestation.cited_height,
                received_height: a.received_height,
                seated: a.seated,
                fresh: a.fresh,
                hex: raw_hex(&a.attestation.encode()),
            })
            .collect())
    }

    async fn yed_addattestation(&self, hex: Value) -> RpcResult<AddAttestationJson> {
        let s = self.live().await?;
        let bytes = hex
            .as_str()
            .and_then(|t| hex::decode(t).ok())
            .ok_or_else(|| invalid("attest-malformed: hex expected"))?;
        let att = Attestation::decode(&bytes).ok_or_else(|| {
            invalid(format!(
                "attest-malformed: an attestation is exactly {} bytes",
                Attestation::SIZE
            ))
        })?;
        healthy(&s)?;
        let ack = self.state.add_attestation(&att).await?;
        Ok(AddAttestationJson {
            accepted: true,
            seq: att.seq,
            price_micro_usd: att.price_micro_usd,
            cited_height: att.cited_height,
            replaced: ack.replaced,
            pool_size: ack.pool_size,
        })
    }

    async fn yed_buildbundle(
        &self,
        ref_height: Value,
        selector_hex: Value,
    ) -> RpcResult<BundleJson> {
        let s = self.live().await?;
        let selector = selector_arg(&selector_hex)?;
        healthy(&s)?;
        let r = ref_height_arg(&s, &ref_height)?;
        let b = s.index.build_bundle(r, &selector)?;
        Ok(BundleJson {
            ref_height: r,
            selector: raw_hex(&selector),
            armed: b.armed,
            selected: b.selected.clone(),
            seqs: b.seqs.clone(),
            missing: b.missing.clone(),
            // A bundle holds at most 255 attestations, so the count fits.
            count: b.seqs.len() as i64,
            hex: raw_hex(&b.bundle),
            a_mint: b.a_mint,
            a_claim: b.a_claim,
        })
    }

    async fn yed_getselection(
        &self,
        ref_height: Value,
        selector_hex: Value,
    ) -> RpcResult<SelectionJson> {
        let s = self.live().await?;
        let selector = selector_arg(&selector_hex)?;
        healthy(&s)?;
        let r = ref_height_arg(&s, &ref_height)?;
        let sel = s.index.selection(r, &selector);
        let fmt = self.fmt(&s);
        let reachable = sel.selected.iter().filter(|x| x.pool_fresh).count();
        Ok(SelectionJson {
            ref_height: r,
            selector: raw_hex(&selector),
            armed: sel.armed,
            fallback: sel.sum_weight == "0" && !sel.pool.is_empty(),
            pool: sel.pool.clone(),
            sum_weight: sel.sum_weight.clone(),
            m_select: i64::from(s.params.m_select),
            k_slack: i64::from(s.params.k_slack),
            selected: sel
                .selected
                .iter()
                .map(|x| SelectedJson {
                    seq: x.seq,
                    weight: x.weight.clone(),
                    bond_key_address: x.bond_key.as_ref().map(|k| fmt.p2pkh(k)),
                    status: x.status.map_or("", |st| st.name()),
                    pool_fresh: x.pool_fresh,
                })
                .collect(),
            // A selection is at most N_SLOTS long, so the count fits.
            reachable: reachable as i64,
        })
    }

    async fn yed_getnotice(&self, vault_txid: String) -> RpcResult<NoticeJson> {
        let s = self.live().await?;
        let id = hash_arg(&vault_txid, "vaultTxid")?;
        healthy(&s)?;
        let p = &s.params;
        match s.index.notice(&id) {
            NoticeLookup::VaultNotFound => Err(invalid(format!(
                "vault-not-found: no vault at {}:0",
                display_hex(&id)
            ))),
            NoticeLookup::None => Ok(NoticeJson {
                found: false,
                vault: None,
                txid: None,
                height: None,
                ref_height: None,
                p_emerg: None,
                emergency_open_at: None,
                expires_at: None,
            }),
            NoticeLookup::Standing(n) => Ok(NoticeJson {
                found: true,
                vault: Some(format!("{}:0", display_hex(&id))),
                txid: Some(display_hex(&n.txid)),
                height: Some(n.height),
                ref_height: Some(n.ref_height),
                p_emerg: Some(n.p_emerg),
                emergency_open_at: Some(
                    n.ref_height.saturating_add(i64::from(p.emergency_persist)),
                ),
                expires_at: Some(
                    n.ref_height
                        .saturating_add(i64::from(p.emergency_notice_ttl)),
                ),
            }),
        }
    }
}

/// `RefHeightArg`: `startHeight <= R <= tip`.
fn ref_height_arg(s: &YedSnapshot, v: &Value) -> RpcResult<i64> {
    let r = number(v, "refHeight")?;
    let start = i64::from(s.params.start_height);
    let tip = s.index.tip().map_or(-1, |t| t.height);
    if r < start || r > tip {
        return Err(invalid(format!(
            "refHeight must be between {start} and {tip}"
        )));
    }
    Ok(r)
}

/// `yed_decodepayload` of a raw transaction: its payload, `opReturnIndex` and, when it has a
/// carrier-shaped input, the bundle that input carries (decoded, never verified).
fn decode_tx_payload(bytes: &[u8], fmt: &Fmt<'_>) -> Option<Map<String, Value>> {
    let tx: Transaction = bytes.zcash_deserialize_into().ok()?;
    let outputs: Vec<Vec<u8>> = tx
        .outputs()
        .iter()
        .map(|o| o.lock_script.as_raw_bytes().to_vec())
        .collect();
    let found = find_payload(&outputs)?;
    let mut o = payload_json(&found.payload, fmt);
    o.insert("opReturnIndex".into(), json!(found.op_return_index));
    let script_sigs: Vec<Vec<u8>> = tx
        .inputs()
        .iter()
        .map(|i| match i {
            transparent::Input::PrevOut { unlock_script, .. } => {
                unlock_script.as_raw_bytes().to_vec()
            }
            transparent::Input::Coinbase { .. } => Vec::new(),
        })
        .collect();
    let redeem = found.payload.payload_type() == PayloadType::Redeem;
    if let Ok(vin) = find_carrier_input(&script_sigs, redeem) {
        if let Some(spend) = script_sigs
            .get(vin)
            .and_then(|s| parse_carrier_script_sig(s))
        {
            let bundle = decode_bundle(&spend.bundle);
            o.insert(
                "bundle".into(),
                json!({
                    "vin": vin,
                    "hash": display_hex(&spend.bundle_hash),
                    "version": bundle.as_ref().map_or(0, |(v, _)| *v),
                    "count": bundle.as_ref().map_or(0, |(_, a)| a.len()),
                    "attestations": bundle
                        .as_ref()
                        .map(|(_, a)| a.iter().map(attestation_json).collect::<Vec<_>>())
                        .unwrap_or_default(),
                }),
            );
        }
    }
    Some(o)
}
