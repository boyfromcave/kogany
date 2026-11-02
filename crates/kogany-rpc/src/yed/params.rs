//! `yed_getinfo.params` (ycash6 `src/rpc/yellowback.cpp` `yed_getinfo`, rpcversion 8): every
//! value the Mint page derives from, in ycashd's order. The parameters come from
//! `kogany_yellowback::params::Params`; the four values a block can move (`supplyCap`'s base
//! and price, `fees.network`'s price, `attest.bondMinZat`) from the snapshot.

use kogany_yellowback::{
    math::{max_vault_cents, supply_cap_cents},
    params::{FeeBand, MINT_PAYLOAD_VERSION, NUM_CLASSES, PAYLOAD_VERSION},
};
use serde_json::{json, Value};

use crate::json::display_hex;

use super::{
    format::class_letter,
    state::{AttestInfo, SnapshotView, YedSnapshot},
};

/// `yed_getinfo.params` at `tip` (the tip snapshot, `None` for ycashd's virtual snapshot).
pub fn params_json(
    s: &YedSnapshot,
    tip: Option<&SnapshotView>,
    attest: &AttestInfo,
    payout: impl Fn(&[u8; 20]) -> String,
) -> Value {
    let p = &s.params;
    let node = &s.node;
    let issued = tip.map_or(0, |t| t.issued_zat);
    let x_mint = tip.and_then(|t| t.p_mint);
    let cap = supply_cap_cents(issued, x_mint, p.supply_cap_bps);
    let max_vault = max_vault_cents(cap, p.max_vault_share_bps, p.vault_share_floor_cents);
    let bands: Vec<Value> = p
        .fee_bands
        .iter()
        .map(|b: &FeeBand| json!({"uptoCents": (b.upto_cents > 0).then_some(b.upto_cents), "bps": b.bps}))
        .collect();
    let classes: Vec<Value> = (0..NUM_CLASSES)
        .map(|i| {
            // `i` is below NUM_CLASSES (3), so it fits in a u8.
            json!({
                "class": class_letter(i as u8),
                "minBlocks": p.class_min.get(i),
                "maxBlocks": p.class_max.get(i),
                "baseRatioBps": p.base_ratio_bps.get(i),
                "earlyRedeemFeeBps": p.early_redeem_fee_bps.get(i),
            })
        })
        .collect();
    let nf = &node.network_fees;
    let mut schemes = vec![1u8];
    if node.falcon_active_next {
        schemes.push(2);
    }
    let pp = &node.payee_policy;
    let supply_cap = json!({
        "circulatingZat": issued,
        "issuedBeforeStartZat": p.issued_before_start,
        "priceMicroUsd": x_mint,
        "capCents": cap,
        "maxVaultShareBps": p.max_vault_share_bps,
        "vaultShareFloorCents": p.vault_share_floor_cents,
        "maxVaultCents": max_vault,
    });
    let fees = json!({
        "protocol": {
            "bands": bands,
            "floorCents": p.fee_floor_cents,
            "attestFeeBps": p.attest_fee_bps,
            "priceSource": "pMint",
        },
        "earlyRedeemFeeBps": p.early_redeem_fee_bps,
        "network": {
            "priceMicroUsd": nf.price_micro_usd,
            "priceSource": if nf.price_micro_usd.is_some() { "tip" } else { "fallback" },
            "plain": {"usdPerKBMicro": nf.plain_usd_per_kb_micro, "zatPerKB": nf.plain_zat_per_kb},
            "yellowback": {
                "usdPerKBMicro": nf.yed_usd_per_kb_micro,
                "zatPerKB": nf.yed_zat_per_kb,
                "maxTxFeeUsdMicro": nf.yed_max_tx_fee_usd_micro,
                "maxTxFeeCeilingZat": nf.yed_max_tx_fee_ceiling_zat,
                "maxTxFeeZat": nf.yed_max_tx_fee_zat,
            },
            "floorZatPerKB": nf.floor_zat_per_kb,
            "fallbackZatPerKB": nf.fallback_zat_per_kb,
            "flatZat": node.fee_zat,
            "maxTxFeeZat": nf.max_tx_fee_zat,
        },
    });
    let pq = json!({
        "schemes": schemes,
        "falconActive": node.falcon_active_next,
        "falconHeight": p.pq_falcon_height,
        "feeRateZatPerKB": nf.plain_zat_per_kb,
        "plainAddressVersion": hex::encode(node.plain_pq_address_version),
    });
    let policy = json!({
        "penaltyBlocks": pp.penalty_blocks,
        "accuracyWindow": pp.accuracy_window,
        "tiltBps": pp.tilt_bps,
        "preferredPayee": pp.preferred.as_ref().map(&payout),
        "preferredAttestor": node.preferred_attestor,
    });
    let attest = json!({
        "payloadVersion": PAYLOAD_VERSION,
        "mintPayloadVersion": MINT_PAYLOAD_VERSION,
        "armMin": p.attest_arm_min,
        "armDelay": p.attest_arm_delay,
        "required": p.attest_required,
        "carrierMode": p.bundle_carrier.name(),
        "nSlots": p.n_slots,
        "mSelect": p.m_select,
        "kSlack": p.k_slack,
        "bundleMax": p.bundle_max,
        "qLowBps": p.q_low_bps,
        "qHighBps": p.q_high_bps,
        "attestMaxAge": p.attest_max_age,
        "pinWindow": p.pin_window,
        "pinDeltaBps": p.pin_delta_bps,
        "pinMinTags": p.pin_min_tags,
        "pinMinBundles": p.pin_min_bundles,
        "divergeBpsAttest": p.diverge_bps_attest,
        "emergencyRatioBps": p.emergency_ratio_bps,
        "emergencyPersist": p.emergency_persist,
        "emergencyNoticeTtl": p.emergency_notice_ttl,
        "residualMinZat": p.residual_min_zat,
        "attestFeeBps": p.attest_fee_bps,
        "bondMinZat": attest.bond_min_zat,
        "bondMinFloorZat": p.bond_min_floor_zat,
        "bondMinCapZat": p.bond_min_cap_zat,
        "bondShareBps": p.bond_share_bps,
        "bondMinLock": p.bond_min_lock,
        "bondMaturity": p.bond_maturity,
        "ageCap": p.age_cap,
        "foundingWindow": p.founding_window,
        "seats": p.attestor_seats,
        "seatAgeUnit": p.seat_age_unit,
        "seatAgeCap": p.seat_age_cap,
        "seatMarginBps": p.seat_margin_bps,
        "evictMarginBps": p.evict_margin_bps,
        "dormancyBlocks": p.dormancy_blocks,
        "dormancyMinBundles": p.dormancy_min_bundles,
        "dormancyCheck": p.dormancy_check,
        "carrierValueZat": p.carrier_value,
    });
    json!({
        "startHeight": p.start_height,
        "attestorSetId": attestor_set_hex(&p.attestor_set_id),
        "claimDelay": p.claim_delay,
        "sigmaRefBps": p.sigma_ref_bps,
        "supplyCapBps": p.supply_cap_bps,
        "supplyCap": supply_cap,
        "refLag": node.ref_lag,
        "refWindow": p.ref_window,
        "grace": p.grace,
        "payeeWindow": p.payee_window,
        "tokenValueZat": p.token_value,
        "feeZat": node.fee_zat,
        "maxMintCents": p.max_mint,
        "fees": fees,
        "addressVersion": p.address_version.map(hex::encode).unwrap_or_default(),
        "pqAddressVersion": p.pq_address_version.map(hex::encode).unwrap_or_default(),
        "windows": {"fast": p.p_fast_window, "mid": p.p_mid_window, "slow": p.p_slow_window},
        "minFill": {"fast": p.p_fast_min_fill, "mid": p.p_mid_min_fill, "slow": p.p_slow_min_fill},
        "classes": classes,
        "earlyRedeemFeeBps": p.early_redeem_fee_bps,
        "globalRatioHaltBps": p.global_ratio_halt_bps,
        "globalRatioDenominator": "openDebt",
        "recapRatioBps": p.recap_ratio_bps,
        "claimThresholdBps": p.claim_threshold_bps,
        "sigmaMultMaxBps": p.sigma_mult_max_bps,
        "inTermClaims": true,
        "pq": pq,
        "policy": policy,
        "attest": attest,
    })
}

/// The attestor set id in display order (the C++ `uint256::GetHex()` of the memory bytes).
pub fn attestor_set_hex(id: &[u8; 32]) -> String {
    display_hex(&kogany_vault::Hash32(*id))
}
