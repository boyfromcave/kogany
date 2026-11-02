// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

//! The pinned cross-line chains replayed through the state machine (ycash6
//! `src/test/yellowback_state_tests.cpp` `statehash_golden_vector`,
//! `pq_vectors_chain_across_falcon`): every block is evaluated over the running state; an
//! invalid block must be one the vector lists, with its verdict, and is not applied; a valid one
//! is applied by its delta. At the end the state hash, the tip and the totals equal the pinned
//! values, the open-debt invariant holds, and reverting every delta restores the empty state.

// Test reporting: a gate run shows what was compared.
#![allow(clippy::print_stderr)]

mod common;
mod state_common;

use common::{h, load_pinned, uint256_display};
use kogany_yellowback::params::{regtest_params_with, BundleCarrier, Params};
use kogany_yellowback::state::{
    evaluate_block, state_hash, VaultStatus, YedDelta, YedRead, YedState,
};
use serde_json::Value;
use state_common::rawtx::parse_v4;

fn chain_params(v: &Value) -> Params {
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
        uint256_display(v["attestorSetId"].as_str().unwrap()).0,
        int("attestArmMin"),
        carrier,
        v["mintRequiresArmed"].as_bool().unwrap(),
    );
    if v.get("pqFalconHeight").is_some() {
        p.pq_falcon_height = int("pqFalconHeight");
    }
    p
}

struct Replay {
    state: YedState,
    deltas: Vec<YedDelta>,
    invalid: Vec<(i64, String)>,
}

fn replay(p: &Params, blocks: &[Value]) -> Replay {
    let mut state = YedState::new();
    let mut deltas = Vec::new();
    let mut invalid = Vec::new();
    for b in blocks {
        let height = b["height"].as_i64().unwrap();
        let txs: Vec<_> = b["txs"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| parse_v4(&h(t.as_str().unwrap())))
            .collect();
        let hash = uint256_display(b["hash"].as_str().unwrap());
        let subsidy = b["subsidyZat"].as_i64().unwrap();
        let ev = evaluate_block(&state, p, &txs, height, &hash, subsidy, None);
        let marked = b.get("invalid").and_then(Value::as_bool).unwrap_or(false);
        if ev.block_invalid {
            assert!(
                marked,
                "block {height} invalid but not marked: {}",
                ev.reason
            );
            assert!(ev.reason.starts_with(&format!("{}:", ev.verdict)));
            invalid.push((height, ev.verdict));
            continue;
        }
        assert!(!marked, "block {height} should be invalid");
        state.apply(&ev.delta);
        deltas.push(ev.delta);
    }
    Replay {
        state,
        deltas,
        invalid,
    }
}

fn open_debt_invariant(s: &YedState) {
    let t = s.totals();
    let open: i64 = s
        .vaults()
        .iter()
        .filter(|(_, v)| matches!(v.status, VaultStatus::Active | VaultStatus::Claiming))
        .map(|(_, v)| v.minted_cents)
        .sum();
    assert_eq!(
        t.open_debt_cents, open,
        "openDebtCents is the open vaults' debt"
    );
    assert!(t.supply_cents <= t.open_debt_cents);
}

#[test]
fn statehash_golden_vector() {
    let doc = load_pinned("yellowback_golden.json");
    let p = chain_params(&doc["params"]);
    let r = replay(&p, doc["blocks"].as_array().unwrap());
    let expected: Vec<(i64, &str)> = vec![
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
    let got: Vec<(i64, &str)> = r.invalid.iter().map(|(h, v)| (*h, v.as_str())).collect();
    assert_eq!(got, expected, "the rejected blocks, in order");
    let hash = hex::encode(state_hash(&r.state, "regtest"));
    eprintln!(
        "golden: {} blocks applied, state hash {hash}",
        r.deltas.len()
    );
    assert_eq!(hash, doc["stateHash"].as_str().unwrap());
    assert_eq!(
        hash,
        "ee6a9f157175b6e084df52f96dc5039e4d411189352542f329971e6dd7bb0c0b"
    );
    let tip = r.state.tip().unwrap();
    assert_eq!(
        i64::from(tip.height),
        doc["tip"]["height"].as_i64().unwrap()
    );
    assert_eq!(
        tip.block_hash,
        uint256_display(doc["tip"]["hash"].as_str().unwrap())
    );
    let t = r.state.totals();
    let tj = &doc["totals"];
    assert_eq!(t.supply_cents, tj["supplyCents"].as_i64().unwrap());
    assert_eq!(t.collateral_zat, tj["collateralZat"].as_i64().unwrap());
    assert_eq!(
        i64::from(t.active_vaults),
        tj["activeVaults"].as_i64().unwrap()
    );
    assert_eq!(i64::from(t.void_vaults), tj["voidVaults"].as_i64().unwrap());
    assert_eq!(
        i64::from(t.closed_vaults),
        tj["closedVaults"].as_i64().unwrap()
    );
    assert_eq!(
        i64::from(t.claimed_vaults),
        tj["claimedVaults"].as_i64().unwrap()
    );
    assert_eq!(t.unbacked_cents, tj["unbackedCents"].as_i64().unwrap());
    assert_eq!(t.open_debt_cents, tj["openDebtCents"].as_i64().unwrap());
    open_debt_invariant(&r.state);
    // FEE-1': every vault record carries its mint price
    let vaults = r.state.vaults();
    assert!(!vaults.is_empty());
    assert!(vaults
        .iter()
        .all(|(_, v)| v.p_mint > 0 && v.p_mint <= kogany_yellowback::params::PRICE_MAX));
    // UNDO: reverting the whole vector restores the empty state byte for byte
    let mut s = r.state;
    for d in r.deltas.iter().rev() {
        s.revert(d);
    }
    assert_eq!(s, YedState::new());
}

#[test]
fn pq_vectors_chain_across_falcon() {
    let doc = load_pinned("yellowback_pq_vectors.json");
    let c = &doc["chain"];
    let p = chain_params(&c["params"]);
    let r = replay(&p, c["blocks"].as_array().unwrap());
    let expected: Vec<(i64, String)> = c["invalid"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| {
            (
                x["height"].as_i64().unwrap(),
                x["verdict"].as_str().unwrap().to_owned(),
            )
        })
        .collect();
    assert_eq!(expected.len(), 6);
    assert_eq!(r.invalid, expected);
    let hash = hex::encode(state_hash(&r.state, "regtest"));
    eprintln!(
        "pq chain: {} blocks applied, state hash {hash}",
        r.deltas.len()
    );
    assert_eq!(hash, c["stateHash"].as_str().unwrap());
    let tip = r.state.tip().unwrap();
    assert_eq!(i64::from(tip.height), c["tip"]["height"].as_i64().unwrap());
    assert_eq!(
        r.state.totals().supply_cents,
        c["totals"]["supplyCents"].as_i64().unwrap()
    );
    assert_eq!(
        i64::from(r.state.totals().active_vaults),
        c["totals"]["activeVaults"].as_i64().unwrap()
    );
    let mut s = r.state;
    for d in r.deltas.iter().rev() {
        s.revert(d);
    }
    assert_eq!(s, YedState::new());
}
