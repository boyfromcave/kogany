// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

//! ycash6 `src/test/yellowback_math_tests.cpp` (at 65cb4ae0f), case for case: the worked examples
//! of the plans, the K14 overflow corners, the V17 regression and the v3 quantities. One Rust test
//! per BOOST test case, under the same name; the JSON replay (`math_spec_rational_cases`) is
//! `tests/math_cases.rs`. The parameter-table cases (`act5_params_tables`, `arm1_v3_params_tables`,
//! the class-range cases) are `tests/params_tables.rs`.

// Test reporting: a gate run shows what was compared.
#![allow(clippy::print_stderr)]

use kogany_yellowback::math::*;
use kogany_yellowback::params::*;

/// A non-null YED attestor set for the regtest columns (the C++ cases' `TestSet()`; only its being
/// non-null matters to these cases).
fn test_set() -> [u8; 32] {
    [0x5e; 32]
}

fn series(n: usize, value: MicroUsd) -> Vec<Option<MicroUsd>> {
    vec![Some(value); n]
}

fn w(x: u64) -> U256 {
    U256::from_u64(x)
}

const SIGMA_REF_V2: i32 = 10000;
const SIGMA_MAX_V2: i32 = 30000;

#[test]
fn price1_lower_median_is_the_smaller_middle() {
    assert_eq!(lower_median(&[]), None);
    assert_eq!(lower_median(&[5]), Some(5));
    assert_eq!(lower_median(&[1, 2]), Some(1));
    assert_eq!(lower_median(&[3, 1, 2]), Some(2));
    assert_eq!(lower_median(&[4, 1, 3, 2]), Some(2));
    assert_eq!(lower_median(&[7, 7, 7, 1]), Some(7));
    assert_eq!(lower_median(&[PRICE_MAX, PRICE_MIN]), Some(PRICE_MIN));
    let alt: Vec<MicroUsd> = (0..96)
        .map(|i| if i % 2 == 1 { 51000 } else { 49000 })
        .collect();
    assert_eq!(lower_median(&alt), Some(49000));
}

#[test]
fn sigma1_isqrt_is_the_floor_root() {
    for (x, r) in [
        (0u64, 0u64),
        (1, 1),
        (2, 1),
        (3, 1),
        (4, 2),
        (15, 3),
        (16, 4),
    ] {
        assert_eq!(isqrt_u256(w(x)), w(r));
    }
    let m = w(1_000_000).wrapping_mul(w(1_000_000));
    assert_eq!(isqrt_u256(m), w(1_000_000));
    assert_eq!(isqrt_u256(m.wrapping_sub(U256::ONE)), w(999_999));
    assert_eq!(isqrt_u256(w(10000).wrapping_mul(w(420480))), w(64844));
    let maxv = U256::ZERO.bit_not();
    let root = isqrt_u256(maxv);
    assert_eq!(root, U256::ONE.wrapping_shl(128).wrapping_sub(U256::ONE));
    assert!(root.wrapping_mul(root) <= maxv);
}

#[test]
fn sigma1_flat_series_and_worked_example() {
    let mut m = main_params();
    m.sigma_ref_bps = SIGMA_REF_V2;
    m.sigma_mult_max_bps = SIGMA_MAX_V2;
    let f = |s: &[Option<MicroUsd>], r: i32| {
        sigma_mult_bps(s, r, m.vol_periods_per_year, m.sigma_mult_max_bps)
    };
    assert_eq!(f(&series(43, 50000), m.sigma_ref_bps), 10000);
    let mut s = series(43, 50000);
    s[0] = Some(55000);
    assert_eq!(f(&s, m.sigma_ref_bps), 14441);
    let mut d = series(43, 55000);
    d[0] = Some(50000);
    assert_eq!(f(&d, m.sigma_ref_bps), 13127);
    let mut wild = series(43, 50000);
    for i in (0..wild.len()).step_by(2) {
        wild[i] = Some(100000);
    }
    assert_eq!(f(&wild, m.sigma_ref_bps), m.sigma_mult_max_bps);
    assert_eq!(f(&s, 1_000_000), 10000);
    assert_eq!(f(&wild, 0), 10000);
    assert_eq!(f(&[], 0), 10000);
    let live = main_params();
    assert_eq!(live.sigma_ref_bps, 0);
    let lm = sigma_mult_bps(
        &wild,
        live.sigma_ref_bps,
        live.vol_periods_per_year,
        live.sigma_mult_max_bps,
    );
    assert_eq!(lm, 10000);
    for &base in live.base_ratio_bps.iter() {
        assert_eq!(min_ratio_bps(base, lm), base);
    }
}

#[test]
fn sigma1_cross_pool_noise_is_not_volatility() {
    let mut m = main_params();
    m.sigma_ref_bps = SIGMA_REF_V2;
    m.sigma_mult_max_bps = SIGMA_MAX_V2;
    let raw: Vec<MicroUsd> = (0..2016 + 96)
        .map(|i| if i % 2 == 1 { 51000 } else { 49000 })
        .collect();
    let mut pfast = Vec::new();
    for k in 0..=(m.vol_window / m.vol_step) as usize {
        let end = raw.len() - k * m.vol_step as usize;
        pfast.push(lower_median(&raw[end - m.p_fast_window as usize..end]));
    }
    assert_eq!(pfast.len(), 43);
    assert_eq!(
        sigma_mult_bps(
            &pfast,
            m.sigma_ref_bps,
            m.vol_periods_per_year,
            m.sigma_mult_max_bps
        ),
        10000
    );
    let raw_samples: Vec<Option<MicroUsd>> = raw[..43].iter().map(|x| Some(*x)).collect();
    assert_eq!(
        sigma_mult_bps(
            &raw_samples,
            m.sigma_ref_bps,
            m.vol_periods_per_year,
            m.sigma_mult_max_bps
        ),
        m.sigma_mult_max_bps
    );
}

#[test]
fn sigma1_first_sample_at_start_height() {
    let mut m = main_params();
    m.sigma_ref_bps = SIGMA_REF_V2;
    m.sigma_mult_max_bps = SIGMA_MAX_V2;
    let f = |s: &[Option<MicroUsd>]| {
        sigma_mult_bps(
            s,
            m.sigma_ref_bps,
            m.vol_periods_per_year,
            m.sigma_mult_max_bps,
        )
    };
    let mut s = series(43, 50000);
    assert_eq!(f(&s), 10000);
    s[42] = None;
    assert_eq!(f(&s), m.sigma_mult_max_bps);
    let mut mid = series(43, 50000);
    mid[20] = None;
    assert_eq!(f(&mid), m.sigma_mult_max_bps);
    assert_eq!(f(&series(1, 50000)), m.sigma_mult_max_bps);
    assert_eq!(f(&[]), m.sigma_mult_max_bps);
}

#[test]
fn mint5_min_ratio_and_required_collateral_worked_example() {
    assert_eq!(min_ratio_bps(50000, 10000), 50000);
    assert_eq!(min_ratio_bps(50000, 30000), 150000);
    assert_eq!(min_ratio_bps(30000, 14441), 43323);
    assert_eq!(min_ratio_bps(0, 10000), 0);
    assert_eq!(required_collateral(10000, 30000, 50000), Some(600000000000));
    assert_eq!(required_collateral(100, 30000, 70000), Some(4285714286));
    let g = DEFAULT_COLLATERAL_GRANULARITY;
    assert_eq!(
        required_collateral_rounded(100, 30000, 70000, g),
        Some(4285715000)
    );
    assert_eq!(
        required_collateral_rounded(10000, 30000, 50000, g),
        Some(600000000000)
    );
    assert_eq!(
        required_collateral_rounded(100, 30000, 70000, 1),
        Some(4285714286)
    );
    assert_eq!(required_collateral(0, 30000, 50000), None);
    assert_eq!(required_collateral(10000, 0, 50000), None);
    assert_eq!(required_collateral(10000, 30000, 0), None);
}

#[test]
fn mint5_required_collateral_overflow_at_max_mint_and_price_min() {
    let m = main_params();
    let big = m.max_mint;
    assert_eq!(big, 10000000);
    assert_eq!(regtest_params(1, 0, 0, test_set()).max_mint, big);
    assert_eq!(big, m.max_output);
    let worst = min_ratio_bps(50000, SIGMA_MAX_V2);
    assert_eq!(worst, 150000);
    assert_eq!(
        min_ratio_bps(m.base_ratio_bps[2], m.sigma_mult_max_bps),
        50000
    );
    assert_eq!(required_collateral(big, worst, PRICE_MIN), None);
    assert_eq!(
        required_collateral_rounded(big, worst, PRICE_MIN, DEFAULT_COLLATERAL_GRANULARITY),
        None
    );
    assert_eq!(
        required_collateral(big, m.base_ratio_bps[0], PRICE_MIN),
        None
    );
    for (ratio, ok, bad) in [
        (30000, 14286, 14285),
        (40000, 19048, 19047),
        (50000, 23810, 23809),
    ] {
        assert!(required_collateral(big, ratio, ok).is_some());
        assert!(required_collateral(big, ratio, bad).is_none());
    }
    assert_eq!(required_collateral(big, worst, 50000), None);
    assert_eq!(
        required_collateral(big, worst, 500000),
        Some(300000000000000)
    );
    assert_eq!(
        required_collateral(210000000000, 10000, 100000000),
        Some(MAX_MONEY)
    );
    assert_eq!(required_collateral(210000000001, 10000, 100000000), None);
    assert_eq!(
        required_collateral(m.max_output, 30000, 100000000),
        Some(3000 * COIN)
    );
}

#[test]
fn mint5_required_collateral_at_uint32_price_max() {
    let m = main_params();
    assert_eq!(PRICE_MAX, 4294967295);
    assert_eq!(PRICE_MAX, MicroUsd::from(u32::MAX));
    assert_eq!(
        required_collateral(9019431319500, 10000, PRICE_MAX),
        Some(MAX_MONEY)
    );
    assert_eq!(required_collateral(9019431319501, 10000, PRICE_MAX), None);
    assert_eq!(
        required_collateral(m.max_output, 30000, PRICE_MAX),
        Some(6984919312)
    );
    assert_eq!(
        required_collateral(1000000, min_ratio_bps(50000, SIGMA_MAX_V2), PRICE_MAX),
        Some(3492459656)
    );
    assert_eq!(required_collateral(1, 1, PRICE_MAX), Some(1));
    assert_eq!(
        required_collateral_rounded(
            m.max_output,
            30000,
            PRICE_MAX,
            DEFAULT_COLLATERAL_GRANULARITY
        ),
        Some(6984920000)
    );
    assert_eq!(
        required_collateral(m.min_mint, 30000, PRICE_MAX),
        Some(6984920)
    );
}

#[test]
fn mint6_market_cap_and_supply_cap() {
    let issued = 1000000 * COIN;
    assert_eq!(cap_cents(issued, Some(50000)), Some(5000000));
    assert_eq!(supply_cap_cents(issued, Some(50000), 1500), Some(750000));
    assert_eq!(cap_cents(3, Some(50000)), Some(0));
    assert_eq!(supply_cap_cents(issued, Some(50000), 1), Some(500));
    assert_eq!(supply_cap_cents(issued, Some(50000), 0), None);
    assert_eq!(cap_cents(issued, None), None);
    assert_eq!(supply_cap_cents(issued, None, 1500), None);
    assert_eq!(cap_cents(MAX_MONEY, Some(100000000)), Some(210000000000));
    assert_eq!(cap_cents(MAX_MONEY, Some(PRICE_MAX)), Some(9019431319500));
    assert_eq!(
        supply_cap_cents(MAX_MONEY, Some(PRICE_MAX), 1500),
        Some(1352914697925)
    );
}

#[test]
fn halt2_global_ratio() {
    assert_eq!(
        global_ratio_bps(600000000000, Some(50000), 10000),
        Some(30000)
    );
    assert_eq!(
        global_ratio_bps(500000000000, Some(50000), 10000),
        Some(25000)
    );
    assert_eq!(
        global_ratio_bps(500000000000, Some(50000), 10001),
        Some(24997)
    );
    assert_eq!(global_ratio_bps(500000000000, Some(50000), 0), None);
    assert_eq!(global_ratio_bps(500000000000, None, 10000), None);
    assert_eq!(
        global_ratio_bps(MAX_MONEY, Some(100000000), 1),
        Some(2100000000000000)
    );
    assert_eq!(
        global_ratio_bps(MAX_MONEY, Some(PRICE_MAX), 1),
        Some(90194313195000000)
    );
}

#[test]
fn red4_underwater_worked_example() {
    let c = 600000000000;
    assert!(is_underwater(c, Some(18333), 10000, 11000));
    assert!(!is_underwater(c, Some(18334), 10000, 11000));
    assert!(is_underwater(c, Some(PRICE_MIN), 10000, 11000));
    assert!(!is_underwater(c, Some(PRICE_MAX), 10000, 11000));
    assert!(!is_underwater(c, None, 10000, 11000));
    assert!(is_underwater(0, Some(50000), 1, 11000));
    assert!(!is_underwater(0, Some(50000), 0, 11000));
    assert!(!is_underwater(MAX_MONEY, Some(PRICE_MAX), 1000000, 11000));
    assert!(is_underwater(1, Some(PRICE_MAX), 1, 11000));
    assert!(is_underwater(256, Some(PRICE_MAX), 1, 11000));
    assert!(!is_underwater(257, Some(PRICE_MAX), 1, 11000));
}

#[test]
fn fee1_bands_and_floor() {
    let m = main_params();
    assert_eq!(FEE_BANDS, 3);
    assert_eq!(
        m.fee_bands[0],
        FeeBand {
            upto_cents: 100000,
            bps: 100
        }
    );
    assert_eq!(
        m.fee_bands[1],
        FeeBand {
            upto_cents: 1000000,
            bps: 50
        }
    );
    assert_eq!(
        m.fee_bands[2],
        FeeBand {
            upto_cents: 0,
            bps: 10
        }
    );
    assert_eq!(m.fee_floor_cents, 100);
    for (debt, units) in [
        (m.min_mint, 1000000),
        (1, 1000000),
        (0, 0),
        (-1, 0),
        (10001, 1000100),
        (100000, 10000000),
        (100001, 10000050),
        (1000000, 55000000),
        (1000001, 55000010),
        (10000000, 145000000),
    ] {
        assert_eq!(protocol_fee_units(debt, &m), units, "debt {debt}");
    }
    assert_eq!(protocol_fee_cents(10000, &m), 100);
    assert_eq!(protocol_fee_cents(100001, &m), 1001);
    assert_eq!(protocol_fee_cents(1000000, &m), 5500);
    assert_eq!(protocol_fee_cents(10000000, &m), 14500);
    let r = regtest_params(1, 0, 0, test_set());
    assert_eq!(
        protocol_fee_units(1000000, &r),
        protocol_fee_units(1000000, &m)
    );
    assert_eq!(r.fee_floor_cents, m.fee_floor_cents);
    let mut t = m;
    t.fee_bands[1].bps = -5;
    assert_eq!(protocol_fee_units(1000000, &t), 10000000);
    t.fee_bands[2].upto_cents = 2000000;
    assert_eq!(
        protocol_fee_units(5000000, &t),
        protocol_fee_units(2000000, &t)
    );
}

#[test]
fn fee1_zat_at_the_mint_price() {
    let m = main_params();
    assert_eq!(protocol_fee_zat(10000, PRICE_MIN, &m), Some(1000000000000));
    assert_eq!(protocol_fee_zat(10000, 18000, &m), Some(5555555556));
    assert_eq!(protocol_fee_zat(10000, PRICE_MAX, &m), Some(23284));
    assert!(protocol_fee_zat(10000, PRICE_MAX, &m).unwrap() > TOKEN_VALUE);
    assert_eq!(protocol_fee_zat(100000, 18000, &m), Some(55555555556));
    assert_eq!(protocol_fee_zat(1000000, 18000, &m), Some(305555555556));
    assert_eq!(
        protocol_fee_zat(10000000, PRICE_MIN, &m),
        Some(145000000000000)
    );
    assert!(money_range(
        protocol_fee_zat(10000000, PRICE_MIN, &m).unwrap()
    ));
    assert_eq!(protocol_fee_zat(10000000, 18000, &m), Some(805555555556));
    assert_eq!(protocol_fee_zat(10000000, PRICE_MAX, &m), Some(3376045));
    assert_eq!(protocol_fee_zat(10000, 0, &m), None);
    assert_eq!(protocol_fee_zat(10000, -1, &m), None);
    assert_eq!(protocol_fee_zat(0, 18000, &m), Some(0));
    let mut t = m;
    t.fee_floor_cents = 300000000000;
    assert_eq!(protocol_fee_zat(1, PRICE_MIN, &t), Some(MAX_MONEY));
}

#[test]
fn it9_early_fee_of_the_debt_and_k14_bound() {
    let m = main_params();
    assert_eq!(early_redeem_fee_zat(10000, 500, 50000), 10000000000);
    assert_eq!(early_redeem_fee_zat(10000000, 500, 18000), 27777777777778);
    assert_eq!(early_redeem_fee_zat(10000000, 500, PRICE_MAX), 116415322);
    assert_eq!(early_redeem_fee_zat(10000000, 500, PRICE_MIN), MAX_MONEY);
    assert_eq!(early_redeem_fee_zat(10000, 0, 50000), 0);
    assert_eq!(early_redeem_fee_zat(0, 500, 50000), 0);
    assert_eq!(early_redeem_fee_zat(10000, 500, 0), 0);
    assert_eq!(early_redeem_fee_zat(1, 1, PRICE_MAX), 1);
    for p in [PRICE_MIN, 14286, 18000, 50000, 1000000, PRICE_MAX] {
        for d in [m.min_mint, 100000, 1000000, m.max_mint] {
            for cls in 0..NUM_CLASSES {
                let Some(c) = required_collateral(d, m.base_ratio_bps[cls], p) else {
                    continue;
                };
                let early = early_redeem_fee_zat(d, m.early_redeem_fee_bps[cls], p);
                let protocol = protocol_fee_zat(d, p, &m).unwrap();
                assert!(early < MAX_MONEY);
                assert!(
                    protocol + early <= c / 50 + 2,
                    "K14' at p {p} d {d} class {cls}"
                );
            }
        }
    }
    assert_eq!(m.max_mint, 10000000);
}

#[test]
fn dq28_bond_min_from_collateral() {
    let m = main_params();
    let r = regtest_params(1, 0, 0, test_set());
    let f = bond_min_from_collateral_zat;
    assert_eq!(f(0, &m), 10000 * COIN);
    assert_eq!(f(-1, &m), 10000 * COIN);
    assert_eq!(f(900000 * COIN, &m), 10000 * COIN);
    assert_eq!(f(1800000 * COIN, &m), 10000 * COIN);
    assert_eq!(f(1800000 * COIN + 1, &m), 10000 * COIN + 1);
    assert_eq!(f(2700000 * COIN, &m), 15000 * COIN);
    assert_eq!(f(3600000 * COIN - 1, &m), 20000 * COIN);
    assert_eq!(f(3600000 * COIN - 180, &m), 20000 * COIN - 1);
    assert_eq!(f(3600000 * COIN, &m), 20000 * COIN);
    assert_eq!(f(10000000 * COIN, &m), 20000 * COIN);
    assert_eq!(f(MAX_MONEY, &m), 20000 * COIN);
    assert_eq!(f(i64::MAX, &m), 20000 * COIN);
    assert_eq!(f(0, &r), 5 * COIN);
    assert_eq!(f(500 * COIN, &r), 5 * COIN);
    assert_eq!(f(700 * COIN, &r), 7 * COIN);
    assert_eq!(f(1000 * COIN, &r), 10 * COIN);
    assert_eq!(f(1300 * COIN, &r), 10 * COIN);
    let mut z = m;
    z.n_slots = 0;
    assert_eq!(f(0, &z), 20000 * COIN);
    let mut z = m;
    z.bond_share_bps = 0;
    assert_eq!(f(MAX_MONEY, &z), 10000 * COIN);
    for q in [&m, &r] {
        for c in [
            -1,
            0,
            1,
            250 * COIN,
            900000 * COIN,
            900000 * COIN + 1,
            2000000 * COIN,
            3600000 * COIN,
            MAX_MONEY,
            i64::MAX,
        ] {
            let v = f(c, q);
            assert!(v >= q.bond_min_floor_zat && v <= q.bond_min_cap_zat);
        }
    }
}

#[test]
fn bundle1_bond_weight_clamps_age() {
    let m = main_params();
    let cap = m.bond_min_cap_zat;
    let age_cap = m.age_cap;
    assert_eq!(bond_weight(cap, 0, age_cap), U256::ZERO);
    assert_eq!(bond_weight(cap, -5, age_cap), U256::ZERO);
    assert_eq!(bond_weight(cap, 1, age_cap), U256::from_i64(cap));
    assert_eq!(
        bond_weight(cap, 100, age_cap),
        U256::from_i64(cap).wrapping_mul(w(100))
    );
    assert_eq!(
        bond_weight(cap, age_cap.into(), age_cap),
        U256::from_i64(cap).wrapping_mul(w(age_cap as u64))
    );
    assert_eq!(
        bond_weight(cap, i64::from(age_cap) + 1, age_cap),
        bond_weight(cap, age_cap.into(), age_cap)
    );
    assert_eq!(
        bond_weight(cap, 1000000000, age_cap),
        bond_weight(cap, age_cap.into(), age_cap)
    );
    assert_eq!(
        bond_weight(cap, age_cap.into(), age_cap),
        w(414720000000000000)
    );
    assert_eq!(
        bond_weight(MAX_MONEY, age_cap.into(), age_cap),
        U256::from_i64(MAX_MONEY).wrapping_mul(w(age_cap as u64))
    );
    assert!(!fits_i64(
        &bond_weight(MAX_MONEY, age_cap.into(), age_cap).wrapping_mul(w(9))
    ));
    assert_eq!(bond_weight(0, 10, age_cap), U256::ZERO);
    assert_eq!(bond_weight(-1, 10, age_cap), U256::ZERO);
    assert_eq!(bond_weight(cap, 10, 0), U256::ZERO);
    let r = regtest_params(1, 0, 0, test_set());
    assert_eq!(
        bond_weight(r.bond_min_cap_zat, 100, r.age_cap),
        w(10 * COIN as u64).wrapping_mul(w(64))
    );
}

#[test]
fn seat_weight_log_tenure_factor() {
    assert_eq!(log2_q16(0), 0);
    assert_eq!(log2_q16(1), 0);
    assert_eq!(log2_q16(2), 65536);
    assert_eq!(log2_q16(1024), 10 << 16);
    assert_eq!(log2_q16(3), 103872);
    assert_eq!(log2_q16(1u64 << 40), 40 << 16);
    assert_eq!(log2_q16(u64::MAX), (63 << 16) | 0xFFFF);
    for x in 1u64..5000 {
        assert!(log2_q16(x + 1) >= log2_q16(x));
    }
    let m = main_params();
    let (u, cap) = (i64::from(m.seat_age_unit), i64::from(m.seat_age_cap));
    assert_eq!(u, 1152);
    assert_eq!(cap, 420480);
    assert_eq!(seat_age_factor_q16(0, u, cap), 65536);
    assert_eq!(seat_age_factor_q16(-10, u, cap), 65536);
    assert_eq!(seat_age_factor_q16(cap, u, cap), 65536 + 58982);
    assert_eq!(seat_age_factor_q16(cap * 3, u, cap), 65536 + 58982);
    assert_eq!(seat_age_factor_q16(1152, u, cap), 72462);
    assert_eq!(seat_age_factor_q16(8064, u, cap), 86314);
    assert_eq!(seat_age_factor_q16(210240, u, cap), 117619);
    assert_eq!(seat_age_factor_q16(100, 0, cap), 65536);
    assert_eq!(seat_age_factor_q16(100, u, 0), 65536);
    for a in (0..20000).step_by(7) {
        assert!(seat_age_factor_q16(a + 7, u, cap) >= seat_age_factor_q16(a, u, cap));
    }
    let sw = |bond: i64, age: i64| seat_weight(bond, age, u, cap);
    assert_eq!(
        sw(8000 * COIN, 8064),
        w((8000 * COIN) as u64).wrapping_mul(w(86314))
    );
    assert_eq!(
        sw(8000 * COIN, 8064).checked_div(w(65536)),
        Some(w(1053637695312))
    );
    assert!(
        sw(20000 * COIN, 0).wrapping_mul(w(10000)) > sw(8000 * COIN, cap).wrapping_mul(w(10500))
    );
    assert!(
        sw(3000 * COIN, 0).wrapping_mul(w(10000)) > sw(2000 * COIN, 8064).wrapping_mul(w(10500))
    );
    assert!(sw(3000 * COIN, 0) < sw(2000 * COIN, cap));
    assert!(!fits_i64(&sw(MAX_MONEY, cap)));
    assert_eq!(sw(0, 10), U256::ZERO);
    assert_eq!(sw(-1, 10), U256::ZERO);
    let r = regtest_params(1, 0, 0, test_set());
    assert_eq!(r.seat_age_unit, 1152);
    assert_eq!(r.seat_age_cap, 420480);
    assert_eq!(r.seat_margin_bps, 500);
    assert_eq!(r.evict_margin_bps, 500);
    assert_eq!(r.attestor_seats, 15);
    assert_eq!(r.attestor_liveness_min, 16);
    assert!(r.bond_maturity >= r.attest_max_age);
    assert!(test_params().bond_maturity >= test_params().attest_max_age);
    assert_eq!(test_params().attestor_liveness_min, 1152);
}

#[test]
fn price2_weighted_quantile_thresholds() {
    let m = main_params();
    let wp = |p: MicroUsd, x: u64| WeightedPrice::new(p, w(x));
    let one = [wp(50000, 1000)];
    for q in [m.q_low_bps, m.q_high_bps, 0, 10000] {
        assert_eq!(weighted_quantile(&one, q), Some(50000));
    }
    assert_eq!(weighted_quantile(&[], m.q_low_bps), None);
    assert_eq!(weighted_quantile(&one, 10001), None);
    let four = [wp(10, 1000), wp(20, 1000), wp(30, 1000), wp(40, 1000)];
    assert_eq!(weighted_quantile(&four, m.q_low_bps), Some(20));
    assert_eq!(weighted_quantile(&four, m.q_high_bps), Some(30));
    let shuffled = [wp(40, 1000), wp(10, 1000), wp(30, 1000), wp(20, 1000)];
    assert_eq!(weighted_quantile(&shuffled, m.q_low_bps), Some(20));
    assert_eq!(weighted_quantile(&shuffled, m.q_high_bps), Some(30));
    let three = [wp(10, 1), wp(20, 1), wp(30, 1)];
    for (q, p) in [(3333, 10), (3334, 20), (6666, 20), (6667, 30), (10000, 30)] {
        assert_eq!(weighted_quantile(&three, q), Some(p), "q {q}");
    }
    let two = [wp(10, 1), wp(20, 1)];
    assert_eq!(weighted_quantile(&two, 5000), Some(10));
    assert_eq!(weighted_quantile(&two, 5001), Some(20));
    let heavy_low = [wp(10, 3), wp(20, 1)];
    assert_eq!(weighted_quantile(&heavy_low, 7500), Some(10));
    assert_eq!(weighted_quantile(&heavy_low, 7501), Some(20));
    let whale = [wp(10, 1), wp(20, 100), wp(30, 1)];
    assert_eq!(weighted_quantile(&whale, m.q_low_bps), Some(20));
    assert_eq!(weighted_quantile(&whale, m.q_high_bps), Some(20));
    let tied = [
        wp(10, 1000),
        wp(20, 1000),
        wp(20, 1000),
        wp(20, 1000),
        wp(30, 1000),
    ];
    assert_eq!(weighted_quantile(&tied, m.q_low_bps), Some(20));
    assert_eq!(weighted_quantile(&tied, m.q_high_bps), Some(20));
    assert_eq!(weighted_quantile(&tied, 2000), Some(10));
    assert_eq!(weighted_quantile(&tied, 8001), Some(30));
    assert_eq!(
        weighted_quantile(&[wp(10, 0), wp(20, 1)], m.q_low_bps),
        Some(20)
    );
    assert_eq!(
        weighted_quantile(&[wp(30, 0), wp(10, 0)], m.q_low_bps),
        Some(10)
    );
    let big: Vec<WeightedPrice> = (0..6)
        .map(|i| {
            WeightedPrice::new(
                10 * (i + 1),
                bond_weight(MAX_MONEY, m.age_cap.into(), m.age_cap),
            )
        })
        .collect();
    assert_eq!(weighted_quantile(&big, m.q_low_bps), Some(20));
    assert_eq!(weighted_quantile(&big, m.q_high_bps), Some(50));
    assert_eq!(weighted_quantile(&four, -1), Some(10));
}

#[test]
fn red5_claimant_max_and_residual_worked_example() {
    let m = main_params();
    assert_eq!(m.claim_threshold_bps, 12500);
    let c = claimant_max_zat(10000, m.claim_threshold_bps, 18333);
    assert_eq!(c, Some(681830578738));
    assert_eq!(c.unwrap() / COIN, 6818);
    assert_eq!(claimant_max_zat(10000, 11000, 18333), Some(600010909290));
    assert_eq!(claimant_max_zat(10000, 10000, 18333), Some(545464462991));
    let at = 625000000000;
    assert!(!is_underwater(
        at,
        Some(20000),
        10000,
        m.claim_threshold_bps
    ));
    assert!(is_underwater(
        at - 1,
        Some(20000),
        10000,
        m.claim_threshold_bps
    ));
    let c = claimant_max_zat(10000, m.claim_threshold_bps, 20000);
    assert_eq!(c, Some(at));
    assert_eq!(residual_zat(at, c), 0);
    assert_eq!(residual_zat(at - 1, c), 0);
    assert_eq!(residual_zat(at + 1, c), 1);
    assert_eq!(residual_zat(at + m.residual_min_zat, c), m.residual_min_zat);
    assert_eq!(
        residual_zat(
            600000000000,
            claimant_max_zat(10000, m.claim_threshold_bps, 18333)
        ),
        0
    );
    let c = claimant_max_zat(10000, 10000, 30000);
    assert_eq!(c, Some(333333333334));
    assert_eq!(residual_zat(600000000000, c), 266666666666);
    assert_eq!(claimant_max_zat(100, 11000, 70000), Some(1571428572));
    assert_eq!(claimant_max_zat(0, 11000, 18333), None);
    assert_eq!(claimant_max_zat(10000, 0, 18333), None);
    assert_eq!(claimant_max_zat(10000, 11000, 0), None);
    assert_eq!(claimant_max_zat(-1, 11000, 18333), None);
    assert_eq!(residual_zat(600000000000, None), 0);
    assert_eq!(residual_zat(0, claimant_max_zat(10000, 11000, 18333)), 0);
    assert_eq!(residual_zat(-5, claimant_max_zat(10000, 11000, 18333)), 0);
}

#[test]
fn red5_claimant_max_overflow_at_price_min() {
    let m = main_params();
    assert_eq!(
        claimant_max_zat(m.max_mint, m.claim_threshold_bps, PRICE_MIN),
        None
    );
    assert_eq!(claimant_max_zat(m.max_mint, 10000, PRICE_MIN), None);
    assert_eq!(
        residual_zat(
            MAX_MONEY,
            claimant_max_zat(m.max_mint, m.claim_threshold_bps, PRICE_MIN)
        ),
        0
    );
    assert_eq!(
        claimant_max_zat(m.min_mint, m.claim_threshold_bps, PRICE_MIN),
        Some(125000000000000)
    );
    assert_eq!(
        claimant_max_zat(210000000000, 10000, 100000000),
        Some(MAX_MONEY)
    );
    assert_eq!(claimant_max_zat(210000000001, 10000, 100000000), None);
    assert_eq!(
        claimant_max_zat(m.max_output, m.claim_threshold_bps, 100000000),
        Some(125000000000)
    );
    assert_eq!(
        claimant_max_zat(9019431319500, 10000, PRICE_MAX),
        Some(MAX_MONEY)
    );
    assert_eq!(claimant_max_zat(9019431319501, 10000, PRICE_MAX), None);
    assert_eq!(
        claimant_max_zat(m.max_output, m.claim_threshold_bps, PRICE_MAX),
        Some(2910383047)
    );
}

#[test]
fn red5_residual_threshold_in_dollars() {
    let m = main_params();
    assert_eq!(m.residual_min_cents, 48);
    assert_eq!(m.residual_min_zat, 100000);
    assert_eq!(residual_min_zat(18000, &m), 2666666667);
    assert_eq!(residual_min_zat(50000, &m), 960000000);
    assert_eq!(residual_min_zat(PRICE_MAX, &m), m.residual_min_zat);
    assert_eq!(residual_min_zat(480000000, &m), 100000);
    assert_eq!(residual_min_zat(479999999, &m), 100001);
    assert_eq!(residual_min_zat(0, &m), m.residual_min_zat);
    assert_eq!(residual_min_zat(PRICE_MIN, &m), 480000000000);
    let mut t = m;
    t.residual_min_cents = 0;
    assert_eq!(residual_min_zat(18000, &t), m.residual_min_zat);
}

#[test]
fn mint6b_max_vault_cents() {
    let m = main_params();
    let (s, f) = (m.max_vault_share_bps, m.vault_share_floor_cents);
    assert_eq!(s, 1000);
    assert_eq!(f, 1000000);
    assert_eq!(max_vault_cents(None, s, f), None);
    assert_eq!(max_vault_cents(Some(100000000), 0, f), None);
    assert_eq!(max_vault_cents(Some(100000000), s, f), Some(10000000));
    assert_eq!(max_vault_cents(Some(5000000), s, f), Some(1000000));
    assert_eq!(max_vault_cents(Some(10000000), s, f), Some(1000000));
    assert_eq!(max_vault_cents(Some(10000010), s, f), Some(1000001));
    assert_eq!(max_vault_cents(Some(0), s, f), Some(1000000));
    assert_eq!(
        max_vault_cents(cap_cents(MAX_MONEY, Some(PRICE_MAX)), s, f),
        Some(901943131950)
    );
}

#[test]
fn afee1_attestor_fee_is_half_of_the_pool_fee() {
    let m = main_params();
    let fee = protocol_fee_zat(10000, 50000, &m).unwrap();
    assert_eq!(fee, 20 * COIN);
    assert_eq!(attest_fee_zat(fee, m.attest_fee_bps), 10 * COIN);
    assert_eq!(
        attest_fee_zat(
            protocol_fee_zat(1000000, 18000, &m).unwrap(),
            m.attest_fee_bps
        ),
        152777777778
    );
    assert_eq!(attest_fee_zat(1, m.attest_fee_bps), 0);
    assert_eq!(attest_fee_zat(3, m.attest_fee_bps), 1);
    assert_eq!(attest_fee_zat(7, m.attest_fee_bps), 3);
    let r = regtest_params(1, 0, 0, test_set());
    assert_eq!(attest_fee_zat(15 * COIN, r.attest_fee_bps), 375000000);
    assert_eq!(attest_fee_zat(7, r.attest_fee_bps), 1);
    assert_eq!(attest_fee_zat(0, m.attest_fee_bps), 0);
    assert_eq!(attest_fee_zat(-1, m.attest_fee_bps), 0);
    assert_eq!(attest_fee_zat(fee, 0), 0);
    assert_eq!(attest_fee_zat(fee, 10000), fee);
    assert_eq!(attest_fee_zat(MAX_MONEY, m.attest_fee_bps), MAX_MONEY / 2);
    assert_eq!(attest_fee_zat(MAX_MONEY, 10000), MAX_MONEY);
}

#[test]
fn price2_combine_takes_the_conservative_side() {
    let c = price_combine(Some(50000), Some(52000), Some(48000), Some(55000));
    assert_eq!(
        (c.p_mint, c.p_claim, c.p_emerg),
        (Some(48000), Some(55000), Some(52000))
    );
    let c = price_combine(Some(48000), Some(55000), Some(50000), Some(52000));
    assert_eq!(
        (c.p_mint, c.p_claim, c.p_emerg),
        (Some(48000), Some(55000), Some(52000))
    );
    let c = price_combine(Some(50000), Some(50000), Some(50000), Some(50000));
    assert_eq!(
        (c.p_mint, c.p_claim, c.p_emerg),
        (Some(50000), Some(50000), Some(50000))
    );
    let c = price_combine(None, Some(52000), Some(48000), Some(55000));
    assert_eq!(
        (c.p_mint, c.p_claim, c.p_emerg),
        (None, Some(55000), Some(52000))
    );
    let c = price_combine(Some(50000), None, Some(48000), Some(55000));
    assert_eq!((c.p_mint, c.p_claim, c.p_emerg), (Some(48000), None, None));
    let c = price_combine(Some(50000), Some(52000), None, Some(55000));
    assert_eq!(
        (c.p_mint, c.p_claim, c.p_emerg),
        (None, Some(55000), Some(52000))
    );
    let c = price_combine(Some(50000), Some(52000), Some(48000), None);
    assert_eq!((c.p_mint, c.p_claim, c.p_emerg), (Some(48000), None, None));
    let c = price_combine(None, None, None, None);
    assert_eq!((c.p_mint, c.p_claim, c.p_emerg), (None, None, None));
    assert_eq!(CombinedPrices::default().p_mint, None);
    let c = price_combine(
        Some(PRICE_MIN),
        Some(PRICE_MAX),
        Some(PRICE_MAX),
        Some(PRICE_MIN),
    );
    assert_eq!(
        (c.p_mint, c.p_claim, c.p_emerg),
        (Some(PRICE_MIN), Some(PRICE_MAX), Some(PRICE_MIN))
    );
    assert_eq!(
        sigma_mult_bps(
            &[Some(PRICE_MAX), Some(PRICE_MIN), Some(PRICE_MAX)],
            10000,
            1152,
            30000
        ),
        30000
    );
    assert_eq!(
        sigma_mult_bps(&[Some(PRICE_MAX), Some(PRICE_MAX)], 10000, 1152, 30000),
        10000
    );
}

/// Not in the C++ file: the U256 operations against u128 arithmetic where both fit, and the
/// wrapping corners `arith_uint256` has.
#[test]
fn u256_matches_u128_and_wraps_like_arith_uint256() {
    let samples: [u128; 9] = [
        0,
        1,
        2,
        3,
        0xffff_ffff,
        u64::MAX as u128,
        (u64::MAX as u128) + 1,
        1 << 100,
        u128::MAX >> 1,
    ];
    for a in samples {
        for b in samples {
            let (ua, ub) = (U256::from_u128(a), U256::from_u128(b));
            if let Some(s) = a.checked_add(b) {
                assert_eq!(ua.wrapping_add(ub), U256::from_u128(s));
                assert_eq!(ua.checked_add(ub), Some(U256::from_u128(s)));
            }
            if let Some(p) = a.checked_mul(b) {
                assert_eq!(ua.wrapping_mul(ub), U256::from_u128(p));
                assert_eq!(ua.checked_mul(ub), Some(U256::from_u128(p)));
            }
            match (a.checked_div(b), a.checked_rem(b)) {
                (Some(q), Some(r)) => assert_eq!(
                    ua.checked_div_rem(ub),
                    Some((U256::from_u128(q), U256::from_u128(r)))
                ),
                _ => assert_eq!(ua.checked_div(ub), None),
            }
            if a >= b {
                assert_eq!(ua.checked_sub(ub), Some(U256::from_u128(a - b)));
            } else {
                assert_eq!(ua.checked_sub(ub), None);
            }
            assert_eq!(ua.cmp(&ub), a.cmp(&b));
        }
        for s in [0u32, 1, 7, 63, 64, 65, 100, 127] {
            if a.leading_zeros() >= s {
                assert_eq!(U256::from_u128(a).wrapping_shl(s), U256::from_u128(a << s));
            }
            assert_eq!(U256::from_u128(a).wrapping_shr(s), U256::from_u128(a >> s));
        }
        assert_eq!(U256::from_u128(a).bits(), 128 - a.leading_zeros());
        assert_eq!(
            U256::from_le_bytes(U256::from_u128(a).to_le_bytes()),
            U256::from_u128(a)
        );
    }
    // modulo 2^256
    assert_eq!(U256::MAX.wrapping_add(U256::ONE), U256::ZERO);
    assert_eq!(U256::ZERO.wrapping_sub(U256::ONE), U256::MAX);
    assert_eq!(U256::MAX.wrapping_mul(U256::MAX), U256::ONE);
    assert_eq!(U256::MAX.checked_add(U256::ONE), None);
    assert_eq!(U256::MAX.checked_mul(U256::from_u64(2)), None);
    let half = U256::ONE.wrapping_shl(128);
    assert_eq!(half.checked_mul(half), None);
    assert_eq!(half.wrapping_mul(half), U256::ZERO);
    assert_eq!(U256::ONE.wrapping_shl(255).wrapping_shl(1), U256::ZERO);
    assert_eq!(U256::ONE.wrapping_shl(256), U256::ZERO);
    assert_eq!(U256::MAX.bits(), 256);
    assert_eq!(U256::MAX.checked_div(U256::MAX), Some(U256::ONE));
    assert_eq!(
        U256::MAX.checked_div_rem(half),
        Some((U256::MAX.wrapping_shr(128), half.wrapping_sub(U256::ONE)))
    );
    assert_eq!(U256::from_i64(-1), U256::from_u64(u64::MAX));
    assert_eq!(U256::from_u64(1 << 63).to_i64(), None);
    assert_eq!(U256::from_u64((1 << 63) - 1).to_i64(), Some(i64::MAX));
    assert_eq!(
        ceil_div(U256::from_u64(7), U256::from_u64(2)),
        Some(U256::from_u64(4))
    );
    assert_eq!(
        ceil_div(U256::from_u64(8), U256::from_u64(2)),
        Some(U256::from_u64(4))
    );
    assert_eq!(ceil_div(U256::ZERO, U256::from_u64(3)), Some(U256::ZERO));
    assert_eq!(ceil_div(U256::ONE, U256::ZERO), None);
}
