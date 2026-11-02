// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

//! The parameter-table cases of ycash6 `src/test/yellowback_math_tests.cpp`
//! (`mint2_term_classes_are_contiguous_and_disjoint`, `params_class_ranges_contiguous_or_empty`,
//! `halt2_floor_below_every_enabled_class_ratio`, `act5_params_tables`, `arm1_v3_params_tables`)
//! and of `src/test/testnet_params_tests.cpp` (`testnet_yed_columns`: the column invariants and
//! the testnet-yb-fast scaling rule). The field-by-field equality with `params.cpp` itself is
//! `tests/params_cpp.rs`; these cases check the rules the values were chosen by.

// Test reporting: a gate run shows what was compared.
#![allow(clippy::print_stderr)]

use kogany_yellowback::math::early_redeem_fee_zat;
use kogany_yellowback::params::*;

fn test_set() -> [u8; 32] {
    let mut s = [0u8; 32];
    s[0] = 0xe7;
    s[31] = 0x5e;
    s
}

/// H-5's "contiguous or empty": the enabled classes, in order, start at >= 1 and each one block
/// after the previous enabled one ends; at least one is enabled.
fn classes_contiguous_or_empty(p: &Params) -> bool {
    let mut prev_max: Option<i32> = None;
    for i in 0..NUM_CLASSES {
        if !p.is_class_enabled(i as i64) {
            continue;
        }
        if p.class_min[i] < 1 {
            return false;
        }
        if let Some(m) = prev_max {
            if p.class_min[i] != m + 1 {
                return false;
            }
        }
        prev_max = Some(p.class_max[i]);
    }
    prev_max.is_some()
}

#[test]
fn mint2_term_classes_are_contiguous_and_disjoint() {
    for m in [main_params(), test_params()] {
        for (blocks, class) in [
            (34559, None),
            (34560, Some(0)),
            (103680, Some(0)),
            (103681, Some(1)),
            (207360, Some(1)),
            (207361, Some(2)),
            (420480, Some(2)),
            (420481, None),
            (2102400, None),
            (0, None),
            (-5, None),
        ] {
            assert_eq!(m.class_for_lock_blocks(blocks), class, "{blocks}");
        }
        assert!(
            i64::from(m.class_max[2]) + i64::from(m.grace) + 10000000
                < i64::from(LOCKTIME_THRESHOLD)
        );
        for i in 0..NUM_CLASSES {
            assert!(m.is_class_enabled(i as i64));
        }
        assert!(classes_contiguous_or_empty(&m));
        assert_eq!(m.base_ratio_bps, [30000, 40000, 50000]);
    }
    let r = regtest_params(10, 0, 0, test_set());
    assert!(classes_contiguous_or_empty(&r));
    for i in 1..NUM_CLASSES {
        assert_eq!(r.class_min[i], r.class_max[i - 1] + 1);
    }
    for (blocks, class) in [
        (48, Some(0)),
        (96, Some(0)),
        (97, Some(1)),
        (144, Some(1)),
        (145, Some(2)),
        (240, Some(2)),
        (241, None),
    ] {
        assert_eq!(r.class_for_lock_blocks(blocks), class);
    }
}

#[test]
fn params_class_ranges_contiguous_or_empty() {
    let p = regtest_params(10, 0, 0, test_set());
    assert!(classes_contiguous_or_empty(&p));
    let mut no_b = p;
    no_b.class_min[1] = 97;
    no_b.class_max[1] = 96;
    assert!(!no_b.is_class_enabled(1));
    assert!(!classes_contiguous_or_empty(&no_b));
    no_b.class_min[2] = 97;
    assert!(classes_contiguous_or_empty(&no_b));
    assert_eq!(no_b.class_for_lock_blocks(100), Some(2));
    let mut a_only = p;
    a_only.class_min[1] = 97;
    a_only.class_min[2] = 97;
    a_only.class_max[1] = 96;
    a_only.class_max[2] = 96;
    assert!(classes_contiguous_or_empty(&a_only));
    assert_eq!(a_only.class_for_lock_blocks(96), Some(0));
    assert_eq!(a_only.class_for_lock_blocks(97), None);
    assert_eq!(a_only.class_for_lock_blocks(240), None);
    let mut overlap = p;
    overlap.class_min[1] = 96;
    assert!(!classes_contiguous_or_empty(&overlap));
    let mut none = p;
    none.class_min = [2; NUM_CLASSES];
    none.class_max = [1; NUM_CLASSES];
    assert!(!classes_contiguous_or_empty(&none));
    let mut zero = p;
    zero.class_min[0] = 0;
    assert!(!classes_contiguous_or_empty(&zero));
    assert!(!p.is_class_enabled(-1));
    assert!(!p.is_class_enabled(NUM_CLASSES as i64));
    assert!(p.is_valid_class(2) && !p.is_valid_class(3) && !p.is_valid_class(-1));
}

#[test]
fn halt2_floor_below_every_enabled_class_ratio() {
    for m in [main_params(), test_params()] {
        assert_eq!(m.global_ratio_halt_bps, 20000);
        assert_eq!(m.recap_ratio_bps, 50000);
        assert_eq!(m.recap_ratio_bps, m.base_ratio_bps[2]);
        for i in 0..NUM_CLASSES {
            assert!(m.global_ratio_halt_bps < m.base_ratio_bps[i]);
        }
        assert!(m.base_ratio_bps[0] < m.recap_ratio_bps && m.base_ratio_bps[1] < m.recap_ratio_bps);
    }
    let r = regtest_params(10, 0, 0, test_set());
    assert_eq!(r.recap_ratio_bps, r.base_ratio_bps[2]);
    for i in 0..NUM_CLASSES {
        assert!(r.global_ratio_halt_bps < r.base_ratio_bps[i]);
    }
}

#[test]
fn act5_params_tables() {
    let m = main_params();
    assert_eq!(m.network, "main");
    assert!(!m.is_configured());
    assert_eq!(m.start_height, 0);
    assert_eq!(m.attestor_set_id, [0u8; 32]);
    assert_eq!(m.claim_delay, 576);
    assert_eq!((m.p_fast_window, m.p_fast_min_fill), (96, 48));
    assert_eq!((m.p_mid_window, m.p_mid_min_fill), (576, 384));
    assert_eq!((m.p_slow_window, m.p_slow_min_fill), (2016, 1344));
    assert_eq!(
        (
            m.min_fill(96),
            m.min_fill(576),
            m.min_fill(2016),
            m.min_fill(7)
        ),
        (48, 384, 1344, 1344)
    );
    assert_eq!(m.n_reg, 576);
    assert_eq!(m.n_penalty, 288);
    assert_eq!(
        (m.peer_lag, m.peer_min, m.deviation_bps, m.accuracy_band_bps),
        (10, 5, 1000, 300)
    );
    assert_eq!(
        (m.accuracy_window, m.payee_tilt_bps, m.payee_window),
        (576, 10000, 100)
    );
    assert_eq!(m.fee_floor_cents, 100);
    assert_eq!(m.fee_bands[0].bps, 100);
    assert_eq!(m.early_redeem_fee_bps, [500, 250, 100]);
    assert_eq!(early_redeem_fee_zat(10000, 500, 50000), 10000000000);
    assert_eq!(m.grace, 34560);
    assert_eq!(m.claim_threshold_bps, 12500);
    assert_eq!(m.supply_cap_bps, 1500);
    assert_eq!(m.global_ratio_halt_bps, 20000);
    assert_eq!(m.recap_ratio_bps, 50000);
    assert_eq!(m.divergence_bps, 2000);
    assert_eq!(
        (m.vol_window, m.vol_step, m.vol_periods_per_year),
        (2016, 48, 8760)
    );
    assert_eq!((m.sigma_ref_bps, m.sigma_mult_max_bps), (0, 10000));
    assert_eq!(
        (m.min_mint, m.max_mint, m.min_output, m.max_output),
        (10000, 10000000, 100, 10000000)
    );
    assert_eq!(m.token_value, TOKEN_VALUE);
    assert_eq!(m.ref_window, REF_WINDOW);
    assert_eq!(m.vol_window / m.vol_step, 42);
    assert_eq!(test_params().network, "test");
    assert_eq!(test_params().grace, 34560);

    let r = regtest_params(150, 12345, 700, test_set());
    assert_eq!(r.network, "regtest");
    assert!(r.is_configured());
    assert_eq!(
        (r.start_height, r.sigma_ref_bps, r.supply_cap_bps),
        (150, 12345, 700)
    );
    assert_eq!(r.attestor_set_id, test_set());
    assert_eq!(r.claim_delay, 10);
    assert_eq!((r.p_fast_window, r.p_fast_min_fill), (8, 4));
    assert_eq!((r.p_mid_window, r.p_mid_min_fill), (24, 16));
    assert_eq!((r.p_slow_window, r.p_slow_min_fill), (64, 43));
    assert_eq!(
        (r.n_reg, r.n_penalty, r.peer_lag, r.peer_min),
        (24, 12, 4, 3)
    );
    assert_eq!((r.accuracy_window, r.payee_window, r.grace), (24, 10, 24));
    assert_eq!(
        (r.vol_window, r.vol_step, r.vol_periods_per_year),
        (64, 8, 8760)
    );
    assert_eq!(r.vol_window / r.vol_step, 8);
    assert_eq!(r.fee_floor_cents, m.fee_floor_cents);
    assert_eq!(r.fee_bands[2].bps, m.fee_bands[2].bps);
    assert_eq!(r.claim_threshold_bps, m.claim_threshold_bps);
    assert_eq!(r.global_ratio_halt_bps, 25000);
    assert_eq!(r.recap_ratio_bps, 50000);
    assert_eq!(r.max_mint, m.max_mint);
    assert!(!regtest_params(0, 0, 0, test_set()).is_configured());
    assert!(!regtest_params(150, 0, 0, [0u8; 32]).is_configured());
    assert!(!params_for_network("regtest").unwrap().is_configured());
    assert_eq!(params_for_network("nope"), None);
    assert_eq!(params_for_network("main"), Some(main_params()));
    assert_eq!(params_for_network("test"), Some(test_params()));
}

#[test]
fn arm1_v3_params_tables() {
    let m = main_params();
    assert_eq!(PAYLOAD_VERSION, 3);
    assert_eq!(MINT_PAYLOAD_VERSION, 4);
    assert_eq!(m.attest_arm_min, 7);
    assert!(m.mint_requires_armed);
    assert_eq!(m.attest_arm_delay, 1152);
    assert!(m.attest_required);
    assert_eq!(m.bundle_carrier, BundleCarrier::ScriptSig);
    assert_eq!(
        (m.n_slots, m.m_select, m.k_slack, m.bundle_max),
        (9, 4, 2, 6)
    );
    assert_eq!((m.q_low_bps, m.q_high_bps), (3333, 6667));
    assert_eq!(m.attest_max_age, 20);
    assert_eq!(m.attest_max_age, 2 * m.attest_interval);
    assert_eq!(
        (
            m.pin_window,
            m.pin_delta_bps,
            m.pin_min_tags,
            m.pin_min_bundles
        ),
        (288, 500, 3, 2)
    );
    assert_eq!(m.diverge_bps_attest, 1500);
    assert_eq!(
        (
            m.emergency_ratio_bps,
            m.emergency_persist,
            m.emergency_notice_ttl
        ),
        (10500, 48, 1152)
    );
    assert_eq!(m.residual_min_zat, 100000);
    assert_eq!(m.attest_fee_bps, 5000);
    assert_eq!(
        (m.bond_min_floor_zat, m.bond_min_cap_zat, m.bond_share_bps),
        (10000 * COIN, 20000 * COIN, 500)
    );
    assert_eq!(
        (
            m.bond_min_lock,
            m.bond_maturity,
            m.age_cap,
            m.founding_window
        ),
        (0, 16128, 207360, 8064)
    );
    assert_eq!(
        (m.dormancy_blocks, m.dormancy_min_bundles, m.dormancy_check),
        (16128, 20, 48)
    );
    assert_eq!(
        (m.carrier_value, m.attest_interval, m.wallet_confirmations),
        (10000, 10, 6)
    );
    let t = test_params();
    assert_eq!(
        (
            t.attest_arm_min,
            t.mint_requires_armed,
            t.attest_fee_bps,
            t.fee_floor_cents
        ),
        (7, true, 5000, 100)
    );
    assert_eq!(t.bond_min_cap_zat, 20000 * COIN);
    assert!(m.is_armed(true));
    assert!(!m.is_armed(false));
    let mut off = m;
    off.attest_required = false;
    assert!(!off.is_armed(true));

    let r = regtest_params(150, 0, 0, test_set());
    assert_eq!(r.attest_arm_min, 3);
    assert!(!r.mint_requires_armed);
    assert!(
        regtest_params_with(150, 0, 0, test_set(), 3, BundleCarrier::ScriptSig, true)
            .mint_requires_armed
    );
    assert!(!Params::default().mint_requires_armed);
    assert_eq!(r.bundle_carrier, BundleCarrier::ScriptSig);
    assert_eq!((r.attest_arm_delay, r.attest_required), (8, true));
    assert_eq!(
        (r.n_slots, r.m_select, r.k_slack, r.bundle_max),
        (5, 2, 1, 6)
    );
    assert_eq!(
        (r.q_low_bps, r.q_high_bps, r.attest_max_age),
        (3333, 6667, 8)
    );
    assert_eq!(r.attest_max_age, 2 * r.attest_interval);
    assert_eq!(
        (
            r.pin_window,
            r.pin_delta_bps,
            r.pin_min_tags,
            r.pin_min_bundles
        ),
        (16, 500, 2, 2)
    );
    assert_eq!(
        (
            r.diverge_bps_attest,
            r.emergency_ratio_bps,
            r.emergency_persist,
            r.emergency_notice_ttl
        ),
        (1500, 10500, 4, 64)
    );
    assert_eq!((r.residual_min_zat, r.attest_fee_bps), (100000, 2500));
    assert_eq!(
        (
            r.bond_min_floor_zat,
            r.bond_min_cap_zat,
            r.bond_share_bps,
            r.bond_min_lock
        ),
        (5 * COIN, 10 * COIN, 500, 0)
    );
    assert_eq!((r.bond_maturity, r.age_cap, r.founding_window), (8, 64, 16));
    assert_eq!(
        (r.dormancy_blocks, r.dormancy_min_bundles, r.dormancy_check),
        (16, 2, 4)
    );
    assert_eq!(
        (r.carrier_value, r.attest_interval, r.wallet_confirmations),
        (10000, 4, 1)
    );
    let never = regtest_params_with(150, 0, 0, test_set(), 0, BundleCarrier::Either, false);
    assert_eq!(never.attest_arm_min, 0);
    assert_eq!(never.bundle_carrier, BundleCarrier::Either);
    assert_eq!(
        regtest_params_with(1, 0, 0, test_set(), 7, BundleCarrier::OpReturn, false).bundle_carrier,
        BundleCarrier::OpReturn
    );
    assert_eq!(
        BundleCarrier::parse("scriptsig"),
        Some(BundleCarrier::ScriptSig)
    );
    assert_eq!(
        BundleCarrier::parse("opreturn"),
        Some(BundleCarrier::OpReturn)
    );
    assert_eq!(BundleCarrier::parse("either"), Some(BundleCarrier::Either));
    for bad in ["", "ScriptSig", "op_return"] {
        assert_eq!(BundleCarrier::parse(bad), None);
    }
    for c in [
        BundleCarrier::ScriptSig,
        BundleCarrier::OpReturn,
        BundleCarrier::Either,
    ] {
        assert_eq!(BundleCarrier::parse(c.name()), Some(c));
    }
    assert_eq!(BundleCarrier::ScriptSig.name(), "scriptsig");
    assert!(Params::default().attest_required);
    assert_eq!(Params::default().bundle_carrier, BundleCarrier::ScriptSig);
    assert_eq!(Params::default().pq_falcon_height, -1);
    assert_eq!(Params::default().address_version, None);
    assert_eq!(main_params().address_version, Some([0x1F, 0xDD]));
    assert_eq!(main_params().pq_address_version, Some([0x56, 0xAB]));
    assert_eq!(
        regtest_params(1, 0, 0, test_set()).address_version,
        Some([0x20, 0x02])
    );
    assert_eq!(
        regtest_params(1, 0, 0, test_set()).pq_address_version,
        Some([0x57, 0x10])
    );
    assert!(!Params::default().is_pq_falcon_active(0));
}

/// testnet_params_tests.cpp `CheckColumnInvariants`, and the liveness invariant every column
/// constructor asserts (`bondMaturity >= attestMaxAge`).
fn check_column_invariants(p: &Params) {
    assert!(p.bond_maturity >= p.attest_max_age);
    assert!(p.claim_delay >= p.attest_max_age);
    assert!(p.attest_arm_delay >= p.attest_max_age);
    assert!(p.emergency_notice_ttl >= p.emergency_persist + p.ref_window);
    assert!(p.attestor_liveness_min >= 2 * p.attest_max_age);
    assert!(p.cancel_quiet >= p.cancel_signers_max * p.claim_delay);
    assert!(p.dormancy_blocks >= p.dormancy_min_bundles);
    assert!(p.dormancy_check >= 1 && p.dormancy_check <= p.dormancy_blocks);
    assert!(p.seat_age_unit >= 1 && p.seat_age_cap >= p.seat_age_unit);
    assert!(p.class_min[0] > 0);
    for i in 0..NUM_CLASSES {
        assert!(p.class_min[i] <= p.class_max[i]);
    }
    for i in 1..NUM_CLASSES {
        assert_eq!(p.class_min[i], p.class_max[i - 1] + 1);
    }
    assert!(
        i64::from(p.class_max[NUM_CLASSES - 1]) + i64::from(p.grace) + 10000000
            < i64::from(LOCKTIME_THRESHOLD)
    );
}

/// `ceil(mainnet x 48 / 16,128)`, the fast column's scaling before its floor.
fn scaled(mainnet: i32) -> i32 {
    ((i64::from(mainnet) * 48 + 16128 - 1) / 16128) as i32
}

#[test]
fn testnet_yed_columns() {
    let main = main_params();
    let slow = test_params();
    let fast = test_fast_params();
    let regtest = regtest_params(1, 0, 0, test_set());
    for p in [&main, &slow, &fast, &regtest] {
        check_column_invariants(p);
    }
    for p in [&slow, &fast] {
        assert_eq!(p.network, "test");
        assert_eq!(p.address_version, Some([0x20, 0x07]));
        assert_eq!(p.pq_address_version, Some([0x57, 0x1E]));
        assert_eq!(p.start_height, 0);
        assert_eq!(p.attestor_set_id, [0u8; 32]);
    }
    // slow is mainnet's column but for the network and the address versions.
    let mut slow_as_main = slow;
    slow_as_main.network = main.network;
    slow_as_main.address_version = main.address_version;
    slow_as_main.pq_address_version = main.pq_address_version;
    assert_eq!(slow_as_main, main);

    assert_eq!(
        fast.bond_maturity,
        fast.attest_max_age.max(scaled(main.bond_maturity))
    );
    assert_eq!(fast.bond_maturity, 48);
    assert_eq!(
        fast.claim_delay,
        fast.attest_max_age.max(scaled(main.claim_delay))
    );
    assert_eq!(fast.grace, scaled(main.grace));
    assert_eq!(fast.class_min[0], scaled(main.class_min[0]));
    for i in 1..NUM_CLASSES {
        assert_eq!(
            fast.class_min[i],
            (fast.class_max[i - 1] + 1).max(scaled(main.class_min[i]))
        );
    }
    for i in 0..NUM_CLASSES {
        assert_eq!(fast.class_max[i], scaled(main.class_max[i]));
    }
    assert_eq!(
        fast.attest_arm_delay,
        fast.attest_max_age.max(scaled(main.attest_arm_delay))
    );
    assert_eq!(
        fast.emergency_notice_ttl,
        (fast.emergency_persist + fast.ref_window).max(scaled(main.emergency_notice_ttl))
    );
    assert_eq!(fast.age_cap, scaled(main.age_cap));
    assert_eq!(fast.founding_window, scaled(main.founding_window));
    assert_eq!(fast.seat_age_unit, 1.max(scaled(main.seat_age_unit)));
    assert_eq!(
        fast.seat_age_cap,
        fast.seat_age_unit.max(scaled(main.seat_age_cap))
    );
    assert_eq!(
        fast.attestor_liveness_min,
        (2 * fast.attest_max_age).max(scaled(main.attestor_liveness_min))
    );
    assert_eq!(
        fast.cancel_quiet,
        (fast.cancel_signers_max * fast.claim_delay).max(scaled(main.cancel_quiet))
    );
    assert_eq!(
        fast.dormancy_blocks,
        fast.dormancy_min_bundles.max(scaled(main.dormancy_blocks))
    );
    assert_eq!(fast.dormancy_check, 1.max(scaled(main.dormancy_check)));
    // The bond amounts are the one non-window difference: a thousandth of mainnet's.
    assert_eq!(fast.bond_min_floor_zat, main.bond_min_floor_zat / 1000);
    assert_eq!(fast.bond_min_cap_zat, main.bond_min_cap_zat / 1000);
    // ... and nothing else moves: every other field equals the testnet column's.
    let mut fast_rest = fast;
    for (dst, src) in [
        (&mut fast_rest.bond_maturity, slow.bond_maturity),
        (&mut fast_rest.claim_delay, slow.claim_delay),
        (&mut fast_rest.grace, slow.grace),
        (&mut fast_rest.attest_arm_delay, slow.attest_arm_delay),
        (
            &mut fast_rest.emergency_notice_ttl,
            slow.emergency_notice_ttl,
        ),
        (&mut fast_rest.age_cap, slow.age_cap),
        (&mut fast_rest.founding_window, slow.founding_window),
        (&mut fast_rest.seat_age_unit, slow.seat_age_unit),
        (&mut fast_rest.seat_age_cap, slow.seat_age_cap),
        (
            &mut fast_rest.attestor_liveness_min,
            slow.attestor_liveness_min,
        ),
        (&mut fast_rest.cancel_quiet, slow.cancel_quiet),
        (&mut fast_rest.dormancy_blocks, slow.dormancy_blocks),
        (&mut fast_rest.dormancy_check, slow.dormancy_check),
    ] {
        *dst = src;
    }
    fast_rest.class_min = slow.class_min;
    fast_rest.class_max = slow.class_max;
    fast_rest.bond_min_floor_zat = slow.bond_min_floor_zat;
    fast_rest.bond_min_cap_zat = slow.bond_min_cap_zat;
    assert_eq!(fast_rest, slow);
}

#[test]
fn select_params_by_height() {
    let mut a = regtest_params(10, 0, 0, test_set());
    let mut b = a;
    b.start_height = 20;
    a.claim_delay = 1;
    b.claim_delay = 2;
    let sets = [a, b];
    assert_eq!(select_params(&sets, 5).map(|p| p.claim_delay), Some(1)); // none qualifies: the first
    assert_eq!(select_params(&sets, 10).map(|p| p.claim_delay), Some(1));
    assert_eq!(select_params(&sets, 19).map(|p| p.claim_delay), Some(1));
    assert_eq!(select_params(&sets, 20).map(|p| p.claim_delay), Some(2));
    assert_eq!(
        select_params(&sets, 1_000_000).map(|p| p.claim_delay),
        Some(2)
    );
    let mut c = b;
    c.claim_delay = 3;
    assert_eq!(
        select_params(&[a, b, c], 25).map(|p| p.claim_delay),
        Some(3)
    ); // a tie: the last
    assert_eq!(select_params(&[], 25), None);
}
