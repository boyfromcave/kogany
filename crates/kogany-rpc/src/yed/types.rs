//! The result shapes of the `yed_*` read RPCs (`ycash6/doc/yellowback-rpc.md`, rpcversion 8;
//! `doc/yellowback-rpc-contract.json`), field for field and in ycashd's field order
//! (`src/rpc/yellowback.cpp`). Every value is already formatted: hex strings, addresses,
//! decimal strings for 256-bit weights; an `Option` serialises as `null` unless the field is
//! marked as absent-when-`None` (the contract's **optional** fields).

use serde::Serialize;

use crate::json::Yec;

/// `{"txid", "vout"}`.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct OutPointJson {
    /// The txid, display order.
    pub txid: String,
    /// The output index.
    pub vout: u32,
}

/// The `upgrade` object and `yed_getactivation`'s result.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UpgradeJson {
    /// `"Vault"`.
    pub name: &'static str,
    /// `"6d5b7a31"`.
    pub branch_id: &'static str,
    /// `"active"` or `"pending"`.
    pub status: &'static str,
    /// The `UPGRADE_VAULT` height (= `startHeight`).
    pub activation_height: i64,
    /// The YED attestor set, display order.
    pub attestor_set_id: String,
    /// `CLAIM_DELAY`.
    pub claim_delay: i64,
    /// The index tip.
    pub height: i64,
}

/// `yed_getinfo`'s result.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InfoJson {
    /// `8`.
    pub rpcversion: i64,
    /// Always `true` (the command does not exist otherwise).
    pub enabled: bool,
    /// `"main"`, `"test"` or `"regtest"`.
    pub network: &'static str,
    /// The index tip, `-1` while empty.
    pub height: i64,
    /// The index tip's hash, `""` while empty.
    pub blockhash: String,
    /// The active chain's height.
    pub chain_height: i64,
    /// `startHeight`.
    pub start_height: i64,
    /// The index is healthy.
    pub healthy: bool,
    /// Why not, `""`.
    pub unhealthy_reason: String,
    /// W20.
    pub supply_cap_reached: bool,
    /// H-1.
    pub mint_requires_armed: bool,
    /// H10: outpoints the wallet layer holds locked (`0`: kogany has no wallet, K-3).
    pub locked_outputs: i64,
    /// H10: a wallet layer is attached (`false` on kogany).
    pub protected_by_index: bool,
    /// The index was rebuilt at this start.
    pub rebuilt: bool,
    /// The vault upgrade.
    pub upgrade: UpgradeJson,
    /// The arming state.
    pub attest: InfoAttestJson,
    /// The miner state.
    pub miner: MinerJson,
    /// The parameters.
    pub params: serde_json::Value,
}

/// `yed_getinfo.attest`.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InfoAttestJson {
    /// The arming status.
    pub status: &'static str,
    /// `triggerHeight`.
    pub trigger_height: i64,
    /// `armHeight`.
    pub arm_height: i64,
    /// `|seated|`.
    pub seated_count: i64,
    /// The pool's size.
    pub pool_size: i64,
    /// Seated `seq`s with a citable pooled attestation.
    pub pool_fresh: i64,
    /// `BUNDLE_CARRIER`.
    pub carrier_mode: &'static str,
    /// `ATTEST_REQUIRED`.
    pub required: bool,
    /// `status == ARMED && required`.
    pub armed: bool,
}

/// `yed_getinfo.miner`.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MinerJson {
    /// The payout address, `null` without a payout key.
    pub payout_address: Option<String>,
    /// `"quote"` or `"none"`.
    pub quote_kind: &'static str,
    /// The held quote's age, `null` without one.
    pub quote_age_seconds: Option<i64>,
    /// REG-1.
    pub registered: bool,
    /// FEE-2.
    pub eligible: bool,
}

/// `yed_getstatehash`'s result.
#[derive(Clone, Debug, Serialize)]
pub struct StateHashJson {
    /// The index tip.
    pub height: i64,
    /// Its hash, `""` while empty.
    pub blockhash: String,
    /// The state hash, display order.
    pub statehash: String,
}

/// The `Totals` shape.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TotalsJson {
    /// `supplyCents`.
    pub supply_cents: i64,
    /// `collateralZat`.
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
    /// `openDebtCents`.
    pub open_debt_cents: i64,
}

/// `yed_verifyindex`'s result.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifyIndexJson {
    /// The index tip.
    pub height: i64,
    /// No mismatch.
    pub ok: bool,
    /// Live tokens read.
    pub tokens: i64,
    /// Vault records read.
    pub vaults: i64,
    /// The stored `Totals`.
    pub stored: TotalsJson,
    /// The re-derived totals.
    pub records: TotalsJson,
    /// Every set's locked value.
    pub sets: Vec<SetAuditJson>,
    /// One line per disagreement.
    pub mismatches: Vec<String>,
    /// The index is healthy.
    pub healthy: bool,
    /// `RULES_VERSION`.
    pub rules_version: i64,
}

/// A `yed_verifyindex.sets` row.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SetAuditJson {
    /// The set id, display order.
    pub setid: String,
    /// The stored `lockedValue`.
    pub locked_value_zat: i64,
    /// The re-derived value.
    pub records_zat: i64,
}

/// `yed_getstats`'s result.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StatsJson {
    /// The index tip.
    pub height: i64,
    /// `supplyCents`.
    pub supply_cents: i64,
    /// `collateralZat`.
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
    /// `openDebtCents`.
    pub open_debt_cents: i64,
    /// The circulating YEC at the tip snapshot.
    pub issued_zat: i64,
    /// `P_fast`.
    pub p_fast: Option<i64>,
    /// `P_mid`.
    pub p_mid: Option<i64>,
    /// `P_slow`.
    pub p_slow: Option<i64>,
    /// `pMint`.
    pub p_mint: Option<i64>,
    /// `pClaim`.
    pub p_claim: Option<i64>,
    /// SIGMA-1.
    pub sigma_mult_bps: i64,
    /// HALT-2's ratio.
    pub global_ratio_bps: Option<i64>,
    /// `"openDebt"`.
    pub global_ratio_denominator: &'static str,
    /// MINT-6's cap.
    pub supply_cap_cents: Option<i64>,
    /// The halt-mask names.
    pub halt_mask: Vec<&'static str>,
    /// `mintingAllowed`.
    pub minting_allowed: bool,
    /// The classes a mint can use now.
    pub mintable_classes: Vec<String>,
}

/// One window of `yed_getprice.fill`.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FillJson {
    /// Quote tags in the window.
    pub quote_tags: i64,
    /// The window.
    pub window: i64,
    /// Its minimum fill.
    pub min_fill: i64,
}

/// `yed_getprice.fill`.
#[derive(Clone, Debug, Serialize)]
pub struct FillsJson {
    /// `P_fast`'s window.
    pub fast: FillJson,
    /// `P_mid`'s window.
    pub mid: FillJson,
    /// `P_slow`'s window.
    pub slow: FillJson,
}

/// `yed_gettag`'s result (and `yed_getprice.tag`); the fields after `kind` are absent when
/// `found` is false.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TagJson {
    /// A valid tag was found.
    pub found: bool,
    /// `"quote"`, `"signal"` or `"none"`.
    pub kind: &'static str,
    /// `TAG_VERSION`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<i64>,
    /// The quote.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub price_micro_usd: Option<u64>,
    /// The source bits.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_mask: Option<u16>,
    /// The payout address.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payout_address: Option<String>,
}

/// `yed_getprice`'s result.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PriceJson {
    /// The height.
    pub height: i64,
    /// `P_fast`.
    pub p_fast: Option<i64>,
    /// `P_mid`.
    pub p_mid: Option<i64>,
    /// `P_slow`.
    pub p_slow: Option<i64>,
    /// `pMint` (the cross-section).
    pub p_mint: Option<i64>,
    /// `pClaim` (the cross-section).
    pub p_claim: Option<i64>,
    /// = `pMint`.
    pub x_mint: Option<i64>,
    /// = `pClaim`.
    pub x_claim: Option<i64>,
    /// ARMED and required.
    pub armed: bool,
    /// The arming status.
    pub attest_status: &'static str,
    /// `seated[]`.
    pub seated: Vec<u16>,
    /// PIN-1's keys as addresses.
    pub pinned_keys: Vec<String>,
    /// PIN-2's `seq`s.
    pub pinned_seqs: Vec<u16>,
    /// The window fills.
    pub fill: FillsJson,
    /// The block's tag.
    pub tag: TagJson,
}

/// A `yed_listminers` row.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MinerRowJson {
    /// The payout address.
    pub payout_address: String,
    /// The latest quote tag's height.
    pub last_tag_height: i64,
    /// Its quote.
    pub last_quote: i64,
    /// Quote tags in the window.
    pub quote_tags: i64,
    /// The share, bps.
    pub share: i64,
    /// REG-1.
    pub registered: bool,
    /// FEE-2.
    pub eligible: bool,
    /// REG-2's end, 0.
    pub penalized_until: i64,
    /// REG-3.
    pub accuracy_bps: Option<i64>,
    /// Judged tags.
    pub quoted: i64,
    /// In band.
    pub in_band: i64,
}

/// `yed_setquote`'s result.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SetQuoteJson {
    /// The stored quote.
    pub price_micro_usd: i64,
    /// The stored source bits.
    pub source_mask: i64,
    /// Unix seconds.
    pub received_at: i64,
    /// The next tag.
    pub next_tag: NextTagJson,
}

/// `yed_setquote.nextTag`.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NextTagJson {
    /// `"quote"` or `"none"`.
    pub kind: &'static str,
    /// The payout address.
    pub payout_address: Option<String>,
}

/// `yed_getfeepayee`'s result.
#[derive(Clone, Debug, Serialize)]
pub struct FeePayeeJson {
    /// `E(refHeight)`.
    pub eligible: Vec<String>,
    /// The FEE-W choice (an empty object when there is none).
    pub default: serde_json::Value,
    /// The preferred payee, when configured and eligible.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preferred: Option<String>,
    /// The L6 policy.
    pub policy: PolicyJson,
}

/// The L6 policy.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicyJson {
    /// `penaltyBlocks`.
    pub penalty_blocks: i64,
    /// `accuracyWindow`.
    pub accuracy_window: i64,
    /// `tiltBps`.
    pub tilt_bps: i64,
}

/// A vault intent of a CLAIMING vault.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultIntentJson {
    /// The intent's txid.
    pub txid: String,
    /// Its output.
    pub vout: u32,
    /// `"claimant"` or `"residual"`.
    pub role: &'static str,
    /// Its height.
    pub height: i64,
    /// `height + CLAIM_DELAY`.
    pub release_height: i64,
}

/// A vault (`yed_getvault`, `yed_listvaults`).
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultJson {
    /// The txid.
    pub txid: String,
    /// `0`.
    pub vout: u32,
    /// The status.
    pub status: &'static str,
    /// The owner's scheme.
    pub owner_scheme: u8,
    /// The owner's key hash, as the V pushes it.
    pub owner_hash: String,
    /// The owner's PQ YED address (`""` for an unregistered scheme).
    pub owner_address: String,
    /// `"A"`, `"B"` or `"C"`.
    pub term_class: String,
    /// `lockHeight`.
    pub lock_height: i64,
    /// `claimHeight`.
    pub claim_height: i64,
    /// The collateral.
    pub collateral_zat: i64,
    /// Its decimal twin.
    pub collateral: Yec,
    /// The debt.
    pub minted_cents: i64,
    /// `mintHeight`.
    pub mint_height: i64,
    /// `refHeight`.
    pub ref_height: i64,
    /// The mint's protocol fee.
    pub fee_paid_zat: i64,
    /// The stored mint price.
    pub p_mint: i64,
    /// `null` while open.
    pub close_height: Option<i64>,
    /// `""` while open.
    pub closing_txid: String,
    /// `burnedCents`.
    pub burned_cents: i64,
    /// IN-2.
    pub unbacked: bool,
    /// CAN-2.
    pub cancel_count: i64,
    /// CAN-2.
    pub cancels_required: i64,
    /// CAN-2.
    pub cancel_quiet_until: Option<i64>,
    /// RED-4 would pass.
    pub claimable: bool,
    /// The claimable price.
    pub underwater_at: Option<i64>,
    /// The failing MINT rule.
    pub void_reason: String,
    /// The V template.
    pub script_pub_key: String,
    /// While CLAIMING.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub intents: Option<Vec<VaultIntentJson>>,
    /// While CLAIMING.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refund_holder: Option<String>,
    /// CAN-3.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub held_residuals: Option<Vec<OutPointJson>>,
    /// NOT-1.
    pub noticed: bool,
    /// NOT-1.
    pub notice_height: Option<i64>,
    /// NOT-1.
    pub emergency_open_at: Option<i64>,
    /// `yed_getvault` only: a mempool spend is pending.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub spend_pending: Option<bool>,
    /// `yed_getvault` only, while pending.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub spend_txid: Option<String>,
}

/// A `yed_listtokens` row.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TokenJson {
    /// The txid.
    pub txid: String,
    /// The output.
    pub vout: u32,
    /// Its YED.
    pub cents: i64,
    /// Its YEC.
    pub value_zat: i64,
    /// Its height.
    pub height: i64,
    /// The YED address.
    pub address: String,
    /// The `s…` or `sq…` twin.
    pub transparent_address: String,
}

/// A `yed_listclaimable` row.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ClaimableJson {
    /// `"txid:0"`.
    pub vault: String,
    /// The owner's address.
    pub owner_address: String,
    /// The collateral.
    pub collateral_zat: i64,
    /// The debt.
    pub minted_cents: i64,
    /// The stored mint price.
    pub p_mint: i64,
    /// RED-3′.
    pub fee_zat: i64,
    /// `claimHeight`.
    pub claim_height: i64,
    /// `lockHeight`.
    pub lock_height: i64,
    /// RED-4 would pass.
    pub claimable: bool,
    /// The claimable price.
    pub underwater_at: Option<i64>,
    /// The tip's claim price.
    pub p_claim: Option<i64>,
    /// The clause.
    pub claim_path: &'static str,
    /// CAN-2.
    pub cancel_count: i64,
    /// CAN-2.
    pub cancels_required: i64,
    /// CAN-2.
    pub cancel_quiet_until: Option<i64>,
    /// NOT-1.
    pub noticed: bool,
    /// NOT-1.
    pub notice_height: Option<i64>,
    /// NOT-1.
    pub emergency_open_at: Option<i64>,
    /// RED-5.
    pub residual_zat: i64,
    /// AFEE-1′.
    pub attest_fee_zat: i64,
}

/// `{"vout", "cents"}`.
#[derive(Clone, Debug, Serialize)]
pub struct AssignedJson {
    /// The output.
    pub vout: u32,
    /// Its cents.
    pub cents: i64,
}

/// `yed_gettxinfo`'s result.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TxInfoJson {
    /// The txid.
    pub txid: String,
    /// Its height.
    pub height: i64,
    /// The type.
    #[serde(rename = "type")]
    pub kind: String,
    /// The path.
    pub path: String,
    /// The verdict.
    pub verdict: String,
    /// `yedIn`.
    pub yed_in: i64,
    /// `yedOut`.
    pub yed_out: i64,
    /// `burned`.
    pub burned: i64,
    /// The protocol fee.
    pub fee_zat: i64,
    /// The fee payee.
    pub payee: Option<String>,
    /// The assignments.
    pub assigned: Vec<AssignedJson>,
    /// Consumed tokens.
    pub spent_tokens: Vec<OutPointJson>,
    /// Closed vaults.
    pub closed_vaults: Vec<OutPointJson>,
    /// Re-created vaults.
    pub reopened_vaults: Vec<OutPointJson>,
    /// An expired wallet transaction.
    pub expired: bool,
    /// The cross-section.
    pub x_mint: Option<i64>,
    /// The cross-section.
    pub x_claim: Option<i64>,
    /// The bundle statistic.
    pub a_mint: Option<i64>,
    /// The bundle statistic.
    pub a_claim: Option<i64>,
    /// PRICE-2.
    pub p_mint: Option<i64>,
    /// PRICE-2.
    pub p_claim: Option<i64>,
    /// `C`.
    pub bundle_seqs: Vec<u16>,
    /// AFEE-1′.
    pub attest_fee_zat: i64,
    /// The attestor-fee payee.
    pub attest_payee: Option<String>,
    /// RED-5.
    pub residual_zat: i64,
    /// The clause.
    pub claim_path: String,
    /// NOT-1 accepted.
    pub notice: bool,
    /// The carrier input, -1.
    pub carrier_vin: i64,
    /// The bundle's carrier.
    pub bundle_source: String,
    /// The attestor `seq` of a `"register"` or `"set_act"` row.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seq: Option<u16>,
}

/// `yed_validaterawtransaction`'s result.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ValidateJson {
    /// Every input verifies.
    pub valid: bool,
    /// Why not.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub invalid_reason: Option<String>,
    /// The verdict.
    pub verdict: String,
    /// The type.
    #[serde(rename = "type")]
    pub kind: String,
    /// The path.
    pub path: String,
    /// `yedIn`.
    pub yed_in: i64,
    /// `yedOut`.
    pub yed_out: i64,
    /// `burned`.
    pub burned: i64,
    /// The protocol fee.
    pub fee_zat: i64,
    /// The payee.
    pub payee: Option<String>,
    /// RED-1..5.
    pub block_valid: bool,
    /// The mempool refuses it.
    pub would_be_rejected: bool,
    /// MP-1.
    pub mempool_expiry_ok: bool,
    /// Unknown inputs.
    pub unconfirmed_inputs: Vec<OutPointJson>,
}

/// `yed_getblockverdict`'s result.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BlockVerdictJson {
    /// A transaction is invalid.
    pub block_invalid: bool,
    /// `"<verdict>:<txid>"`.
    pub reason: String,
    /// The first invalid verdict.
    pub verdict: String,
    /// Every relevant transaction.
    pub transactions: Vec<BlockVerdictTxJson>,
}

/// A `yed_getblockverdict.transactions` row.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BlockVerdictTxJson {
    /// The txid.
    pub txid: String,
    /// The type.
    #[serde(rename = "type")]
    pub kind: String,
    /// The path.
    pub path: String,
    /// The verdict.
    pub verdict: String,
    /// `yedIn`.
    pub yed_in: i64,
    /// `yedOut`.
    pub yed_out: i64,
    /// The protocol fee.
    pub fee_zat: i64,
    /// The payee.
    pub payee: Option<String>,
    /// Closed vaults.
    pub closed_vaults: Vec<OutPointJson>,
}

/// `yed_estimatecollateral`'s result.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CollateralJson {
    /// MINT-5's ratio clause.
    pub required_zat: Option<i64>,
    /// What a mint locks.
    pub required_zat_floored: Option<i64>,
    /// FEE-1′, cents.
    pub protocol_fee_cents: i64,
    /// FEE-1′, zat.
    pub protocol_fee_zat: i64,
    /// The class.
    pub term_class: String,
    /// `lockHeight`.
    pub lock_height: i64,
    /// `claimHeight`.
    pub claim_height: i64,
    /// The minimum ratio.
    pub min_ratio_bps: i64,
    /// The base ratio.
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
    /// The bound used.
    pub source: &'static str,
    /// Armed.
    pub armed: bool,
    /// The `seq`s used.
    pub bundle_seqs: Vec<u16>,
    /// AFEE-1′.
    pub attest_fee_zat: i64,
    /// MINT-10's divergence.
    pub divergence_bps: Option<i64>,
    /// MINTPOL-1 would refuse.
    pub mint_blocked: bool,
    /// Its identifier, `""`.
    pub mint_blocked_reason: &'static str,
}

/// `yed_estimatefee`'s result.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FeeJson {
    /// FEE-1′, cents.
    pub fee_cents: i64,
    /// The price.
    pub p_mint: Option<i64>,
    /// FEE-1′, zat.
    pub fee_zat: Option<i64>,
    /// AFEE-1′.
    pub attest_fee_zat: Option<i64>,
}

/// A `yed_gethistory` row.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HistoryJson {
    /// The height.
    pub height: i64,
    /// The block hash.
    pub block_hash: String,
    /// A valid tag.
    pub tagged: bool,
    /// A quote tag.
    pub quote: bool,
    /// `P_fast`.
    pub p_fast: Option<i64>,
    /// `P_mid`.
    pub p_mid: Option<i64>,
    /// `P_slow`.
    pub p_slow: Option<i64>,
    /// `pMint`.
    pub p_mint: Option<i64>,
    /// `pClaim`.
    pub p_claim: Option<i64>,
    /// SIGMA-1.
    pub sigma_mult_bps: i64,
    /// The circulating YEC.
    pub issued_zat: i64,
    /// `supplyCents`.
    pub supply_cents: i64,
    /// `collateralZat`.
    pub collateral_zat: i64,
    /// `openDebtCents`.
    pub open_debt_cents: i64,
    /// HALT-2's ratio.
    pub global_ratio_bps: Option<i64>,
    /// `"openDebt"`.
    pub global_ratio_denominator: &'static str,
    /// The halt names.
    pub halt_mask: Vec<&'static str>,
}

/// The registration flags.
#[derive(Clone, Debug, Serialize)]
pub struct FlagsJson {
    /// Bits 0-1.
    pub tier: u8,
    /// Bit 2.
    pub pool: bool,
}

impl FlagsJson {
    /// `FlagsToJSON`.
    pub fn new(flags: u8) -> Self {
        Self {
            tier: flags & 0x03,
            pool: flags & 0x04 != 0,
        }
    }
}

/// A `yed_listattestors` row.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AttestorJson {
    /// The `seq`.
    pub seq: u16,
    /// The hot key.
    pub attestor_pub_key: String,
    /// The bond's P2SH address.
    pub bond_address: String,
    /// The bond key's P2PKH address.
    pub bond_key_address: String,
    /// The bond output.
    pub bond_outpoint: OutPointJson,
    /// The bond.
    pub bond_zat: i64,
    /// Its locktime.
    pub bond_locktime: u32,
    /// The flags.
    pub flags: FlagsJson,
    /// `registerHeight`.
    pub register_height: i64,
    /// The status.
    pub status: &'static str,
    /// `statusHeight`.
    pub status_height: i64,
    /// `bondSpentHeight`.
    pub bond_spent_height: Option<i64>,
    /// `seatedSince`.
    pub seated_since: Option<i64>,
    /// `lastAct`.
    pub last_act: i64,
    /// `bondFrozen`.
    pub bond_frozen: bool,
    /// `founding`.
    pub founding: bool,
    /// The bond weight.
    pub weight: String,
    /// The seat weight.
    pub seat_weight: String,
    /// Evicted.
    pub evicted: bool,
    /// Seated.
    pub seated: bool,
    /// Pinned.
    pub pinned: bool,
    /// `lastBundleHeight`.
    pub last_bundle_height: Option<i64>,
    /// `poolFresh`.
    pub pool_fresh: bool,
}

/// A `yed_getattestations` row.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PooledJson {
    /// The `seq`.
    pub seq: u16,
    /// The price.
    pub price_micro_usd: u32,
    /// The cited height.
    pub cited_height: u32,
    /// The tip when pooled.
    pub received_height: i64,
    /// Seated at the tip.
    pub seated: bool,
    /// Citable now.
    pub fresh: bool,
    /// The 74 bytes.
    pub hex: String,
}

/// `yed_addattestation`'s result.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AddAttestationJson {
    /// `true`.
    pub accepted: bool,
    /// The `seq`.
    pub seq: u16,
    /// The price.
    pub price_micro_usd: u32,
    /// The cited height.
    pub cited_height: u32,
    /// An older one was dropped.
    pub replaced: bool,
    /// The pool's size.
    pub pool_size: i64,
}

/// `yed_buildbundle`'s result.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BundleJson {
    /// `R`.
    pub ref_height: i64,
    /// The selector, hex.
    pub selector: String,
    /// Armed.
    pub armed: bool,
    /// Draw order.
    pub selected: Vec<u16>,
    /// Contributing.
    pub seqs: Vec<u16>,
    /// Without an attestation.
    pub missing: Vec<u16>,
    /// `|seqs|`.
    pub count: i64,
    /// The bundle bytes.
    pub hex: String,
    /// The statistic.
    pub a_mint: Option<i64>,
    /// The statistic.
    pub a_claim: Option<i64>,
}

/// `yed_getselection`'s result.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SelectionJson {
    /// `R`.
    pub ref_height: i64,
    /// The selector, hex.
    pub selector: String,
    /// Armed.
    pub armed: bool,
    /// The selectable pool.
    pub pool: Vec<u16>,
    /// Its weight.
    pub sum_weight: String,
    /// `sumWeight == 0` with a non-empty pool.
    pub fallback: bool,
    /// `M_SELECT`.
    pub m_select: i64,
    /// `K_SLACK`.
    pub k_slack: i64,
    /// The drawn attestors.
    pub selected: Vec<SelectedJson>,
    /// `poolFresh` among `selected`.
    pub reachable: i64,
}

/// A `yed_getselection.selected` row.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SelectedJson {
    /// The `seq`.
    pub seq: u16,
    /// Its weight.
    pub weight: String,
    /// Its bond key address.
    pub bond_key_address: Option<String>,
    /// Its status, `""` without a record.
    pub status: &'static str,
    /// Usable attestation pooled.
    pub pool_fresh: bool,
}

/// `yed_getnotice`'s result; every field after `found` is absent when it is false.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NoticeJson {
    /// A record stands.
    pub found: bool,
    /// `"txid:0"`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vault: Option<String>,
    /// The notice transaction.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub txid: Option<String>,
    /// Its block.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub height: Option<i64>,
    /// `R₁`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ref_height: Option<i64>,
    /// The emergency price.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub p_emerg: Option<i64>,
    /// `refHeight + EMERGENCY_PERSIST`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub emergency_open_at: Option<i64>,
    /// `refHeight + EMERGENCY_NOTICE_TTL`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<i64>,
}
