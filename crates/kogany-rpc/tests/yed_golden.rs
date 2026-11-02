//! The YED mock's golden-chain facts are those of the pinned vector
//! `testdata/yellowback/yellowback_golden.json` (read, never modified: plan §4.2 rule 4 (iv)).

use kogany_rpc::yed::mock::{
    golden_params, GOLDEN_ATTESTOR_SET, GOLDEN_STATE_HASH, GOLDEN_TIP_HASH, GOLDEN_TIP_HEIGHT,
    GOLDEN_TOTALS,
};
use kogany_yellowback::params::BundleCarrier;
use serde_json::Value;

fn golden() -> Value {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../testdata/yellowback/yellowback_golden.json"
    );
    let text = std::fs::read_to_string(path).expect("the pinned golden vector is in testdata");
    serde_json::from_str(&text).expect("the golden vector is JSON")
}

#[test]
fn mock_tip_state_hash_and_totals_are_the_golden_chains() {
    let g = golden();
    assert_eq!(g["tip"]["height"], GOLDEN_TIP_HEIGHT);
    assert_eq!(g["tip"]["hash"], GOLDEN_TIP_HASH);
    assert_eq!(g["stateHash"], GOLDEN_STATE_HASH);
    let t = &g["totals"];
    assert_eq!(t["supplyCents"], GOLDEN_TOTALS.supply_cents);
    assert_eq!(t["collateralZat"], GOLDEN_TOTALS.collateral_zat);
    assert_eq!(t["activeVaults"], GOLDEN_TOTALS.active_vaults);
    assert_eq!(t["voidVaults"], GOLDEN_TOTALS.void_vaults);
    assert_eq!(t["closedVaults"], GOLDEN_TOTALS.closed_vaults);
    assert_eq!(t["claimedVaults"], GOLDEN_TOTALS.claimed_vaults);
    assert_eq!(t["unbackedCents"], GOLDEN_TOTALS.unbacked_cents);
    assert_eq!(t["openDebtCents"], GOLDEN_TOTALS.open_debt_cents);
    assert_eq!(t.as_object().map(|o| o.len()), Some(8));
    // The last block entry is the tip.
    let last = g["blocks"]
        .as_array()
        .and_then(|b| b.last())
        .cloned()
        .unwrap_or_default();
    assert_eq!(last["height"], GOLDEN_TIP_HEIGHT);
    assert_eq!(last["hash"], GOLDEN_TIP_HASH);
}

#[test]
fn mock_params_are_the_golden_chains_regtest_flags() {
    let g = golden();
    let gp = &g["params"];
    let p = golden_params();
    assert_eq!(gp["startHeight"], p.start_height);
    assert_eq!(gp["sigmaRefBps"], p.sigma_ref_bps);
    assert_eq!(gp["supplyCapBps"], p.supply_cap_bps);
    assert_eq!(gp["attestorSetId"], GOLDEN_ATTESTOR_SET);
    let mut display = p.attestor_set_id;
    display.reverse();
    assert_eq!(gp["attestorSetId"], hex::encode(display));
    assert_eq!(gp["attestArmMin"], p.attest_arm_min);
    assert_eq!(gp["bundleCarrier"], p.bundle_carrier as u8);
    assert_eq!(p.bundle_carrier, BundleCarrier::ScriptSig);
    assert_eq!(gp["mintRequiresArmed"], p.mint_requires_armed);
    assert_eq!(gp["pqFalconHeight"], p.pq_falcon_height);
    assert_eq!(p.network, "regtest");
}
