// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

//! Replays `testdata/yellowback/yellowback_math_cases.json` (67 cases, pinned by SHA-256 in
//! `testdata/yellowback/PIN`): the YED arithmetic computed in exact rationals from the spec text by
//! ycash6 `qa/rpc-tests/test_framework/test_yellowback_math_spec.py` (audit 03/T-3). ycash6's
//! `yellowback_math_tests.cpp` `math_spec_rational_cases` replays the same rows through `math.h`;
//! this is its Rust twin, with mainnet's parameters as the C++ test uses.
//!
//! Every row is checked, an unknown `fn` fails, and the case count is asserted, so a vector change
//! (a PIN bump) that adds a function cannot pass silently.

// Test reporting: a gate run shows what was compared.
#![allow(clippy::print_stderr)]

use kogany_yellowback::{math, params};
use serde_json::Value;
use sha2::{Digest, Sha256};

/// The cases, after checking the file against `testdata/yellowback/PIN`, so the replay runs only
/// on the bytes the C++ lines test (plan §4.2 rule 4 (i)).
fn cases() -> Vec<Value> {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../../testdata/yellowback");
    let name = "yellowback_math_cases.json";
    let bytes =
        std::fs::read(format!("{dir}/{name}")).unwrap_or_else(|e| panic!("read {name}: {e}"));
    let pin = std::fs::read_to_string(format!("{dir}/PIN")).expect("testdata/yellowback/PIN");
    let want = pin
        .lines()
        .filter(|l| !l.starts_with('#'))
        .find_map(|l| {
            let mut f = l.split_whitespace();
            let sha = f.next()?;
            (f.next()? == format!("testdata/yellowback/{name}")).then(|| sha.to_owned())
        })
        .unwrap_or_else(|| panic!("{name} is not pinned in PIN"));
    assert_eq!(
        hex::encode(Sha256::digest(&bytes)),
        want,
        "{name} differs from its PIN"
    );
    let doc: Value = serde_json::from_slice(&bytes).expect("the pinned vector file is JSON");
    doc["cases"].as_array().expect("cases is an array").clone()
}

fn opt(e: &Value) -> Option<i64> {
    assert!(
        e.is_null() || e.is_i64(),
        "expect is an integer or null: {e}"
    );
    e.as_i64()
}

#[test]
fn math_spec_rational_cases() {
    let rows = cases();
    assert_eq!(
        rows.len(),
        67,
        "the pinned file has 67 cases (plan W5-a exit gate)"
    );
    let p = params::main_params();
    let mut checked = 0usize;
    for r in &rows {
        let f = r["fn"].as_str().expect("fn is a string");
        let a: Vec<i64> = r["args"]
            .as_array()
            .expect("args")
            .iter()
            .map(|x| x.as_i64().expect("integer arg"))
            .collect();
        let e = &r["expect"];
        let what = format!("{f} {:?}", a);
        let i32a = |k: usize| i32::try_from(a[k]).expect("an int argument fits int");
        match f {
            "RequiredCollateral" => assert_eq!(
                math::required_collateral(a[0], i32a(1), a[2]),
                opt(e),
                "{what}"
            ),
            "ProtocolFeeZat" => {
                assert_eq!(math::protocol_fee_zat(a[0], a[1], &p), opt(e), "{what}")
            }
            "ProtocolFeeCents" => {
                assert_eq!(Some(math::protocol_fee_cents(a[0], &p)), opt(e), "{what}")
            }
            "EarlyRedeemFeeZat" => assert_eq!(
                Some(math::early_redeem_fee_zat(a[0], i32a(1), a[2])),
                opt(e),
                "{what}"
            ),
            "AttestFeeZat" => {
                assert_eq!(Some(math::attest_fee_zat(a[0], i32a(1))), opt(e), "{what}")
            }
            "ClaimantMaxZat" => assert_eq!(
                math::claimant_max_zat(a[0], i32a(1), a[2]),
                opt(e),
                "{what}"
            ),
            "ResidualMinZat" => {
                assert_eq!(Some(math::residual_min_zat(a[0], &p)), opt(e), "{what}")
            }
            "GlobalRatioBps" => assert_eq!(
                math::global_ratio_bps(a[0], Some(a[1]), a[2]),
                opt(e),
                "{what}"
            ),
            "CapCents" => assert_eq!(math::cap_cents(a[0], Some(a[1])), opt(e), "{what}"),
            "SupplyCapCents" => assert_eq!(
                math::supply_cap_cents(a[0], Some(a[1]), i32a(2)),
                opt(e),
                "{what}"
            ),
            "IsUnderwater" => assert_eq!(
                math::is_underwater(a[0], Some(a[1]), a[2], i32a(3)),
                e.as_bool().expect("IsUnderwater expects a bool"),
                "{what}"
            ),
            other => panic!("unknown case {other}"),
        }
        checked += 1;
    }
    assert_eq!(checked, rows.len());
}

/// The build profile this replay ran under, so the debug and release runs are told apart in logs.
#[test]
fn reports_profile() {
    eprintln!(
        "yellowback math cases: debug assertions {}",
        if cfg!(debug_assertions) { "on" } else { "off" }
    );
}
