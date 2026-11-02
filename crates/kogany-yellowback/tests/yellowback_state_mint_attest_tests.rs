// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

//! The ARMED-mint cases of ycash6 `src/test/yellowback_state_tests.cpp` at `65cb4ae0f` (W5-d1):
//! MINT-9/10, PRICE-2, the MINT-8′ lower bound, AFEE-0/1, W15, and the attest cases the W5-c
//! agent left to the state machine that fall in part 1 (`mint9_*`, `pin2_excludes_seq`,
//! `rev1_heartbeat_revives_s15_dormant`, `dq28_bond_min_from_collateral`).

mod state_common;

use std::collections::{BTreeMap, BTreeSet};

use kogany_yellowback::attest::bundle::{encode_bundle, Bundle};
use kogany_yellowback::attest::registry::{AttestStatus, AttestorStatus, BundleLogRecord};
use kogany_yellowback::math::{
    attest_fee_zat, min_ratio_bps, required_collateral_rounded, seat_weight, U256,
};
use kogany_yellowback::params::COIN;
use kogany_yellowback::state::{bond_min_zat, verdict, VaultStatus, YedKey, YedRecord};
use state_common::fixture::*;

fn o() -> MintOpts {
    MintOpts::default()
}

fn armed(n: usize) -> Fixture {
    let mut f = Fixture::new();
    f.arm(n, 50000);
    f
}

fn ticks(f: &mut Fixture, n: usize, price: i64) {
    for _ in 0..n {
        let t = Fixture::quote(price, (f.tip + 1) % 3);
        f.mine(Some(t), Vec::new());
    }
}

fn v3(f: &mut Fixture, cents: i64, price: i64) -> MTx {
    f.mint_v3(cents, price, o(), &none_skip(), 48)
}

fn v3o(f: &mut Fixture, cents: i64, price: i64, opts: MintOpts) -> MTx {
    f.mint_v3(cents, price, opts, &none_skip(), 48)
}

// Rule: MINT-9
#[test]
fn mint9_no_bundle_void() {
    let mut f = armed(3);
    let m = f.mint_tx(10000, 48, f.tip - 1, o());
    assert_eq!(mv(&mut f, &m), verdict::MINT9_NO_BUNDLE);
    assert!(f.bundle_row(f.tip).is_none());
    let m = v3(&mut f, 10000, 50000);
    assert_eq!(mv(&mut f, &m), "");
    let row = f.bundle_row(f.tip).unwrap();
    assert_eq!(row.a_mint, 50000);
    assert_eq!(row.selected_seqs.len(), 3);
    // A malformed bundle behind a carrier is "mint9-bundle-shape"; two carriers "mint9-bundle-two-carriers".
    let m = f.mint_tx(
        10000,
        48,
        f.tip - 1,
        MintOpts {
            bundle: Some(vec![0x41; 10]),
            ..o()
        },
    );
    assert_eq!(mv(&mut f, &m), "mint9-bundle-shape");
    let mut m = v3(&mut f, 10000, 50000);
    let last = m.vin.last().unwrap().clone();
    m.vin.push(last);
    assert_eq!(mv(&mut f, &m), "mint9-bundle-two-carriers");
}

// Rule: MINT-9
// Rule: BUNDLE-1
#[test]
fn mint9_bundle_from_unselected_void() {
    let mut f = armed(4);
    let r = f.tip - 1;
    let sel = f.selected(r, &[]);
    assert_eq!(sel.len(), 3);
    let outsider = (0u16..4).find(|q| !sel.contains(q)).unwrap();
    let b = encode_bundle(&Bundle::of(vec![
        f.att(usize::from(sel[0]), 50000, r, None),
        f.att(usize::from(outsider), 50000, r, None),
    ]));
    let opts = |b: Vec<u8>| MintOpts {
        bundle: Some(b),
        attest_payee: i64::from(sel[0]),
        ..o()
    };
    let m = f.mint_tx(10000, 48, r, opts(b));
    assert_eq!(mv(&mut f, &m), "mint9-bundle-member");
    // and a duplicate seq, a short count
    let d = encode_bundle(&Bundle::of(vec![
        f.att(usize::from(sel[0]), 50000, r, None),
        f.att(usize::from(sel[0]), 50000, r, None),
    ]));
    let m = f.mint_tx(10000, 48, f.tip - 1, opts(d));
    assert_eq!(mv(&mut f, &m), "mint9-bundle-dup");
    let one = encode_bundle(&Bundle::of(vec![f.att(
        usize::from(sel[0]),
        50000,
        r,
        None,
    )]));
    let m = f.mint_tx(10000, 48, f.tip - 1, opts(one));
    assert_eq!(mv(&mut f, &m), "mint9-bundle-count");
}

// Rule: MINT-9
// Rule: BUNDLE-1
#[test]
fn mint9_stale_attestation_void() {
    let mut f = armed(3);
    ticks(&mut f, 10, 50000);
    let r = f.tip - 1;
    let max_age = i64::from(f.p.attest_max_age);
    let with_cited = |f: &mut Fixture, r: i64, cited: i64| {
        let b = f.bundle_for(
            r,
            &[],
            50000,
            &BTreeSet::new(),
            Some(cited),
            &BTreeMap::new(),
        );
        let payee = f.selected(r, &[])[0];
        f.mint_tx(
            10000,
            48,
            r,
            MintOpts {
                bundle: Some(b),
                attest_payee: i64::from(payee),
                ..o()
            },
        )
    };
    let m = with_cited(&mut f, r, r - max_age); // citedHeight == R - ATTEST_MAX_AGE: stale
    assert_eq!(mv(&mut f, &m), "mint9-bundle-stale");
    let r = f.tip - 1;
    let m = with_cited(&mut f, r, r - max_age + 1); // the oldest admissible
    assert_eq!(mv(&mut f, &m), "");
    let r = f.tip - 1;
    let tip = f.tip;
    let m = with_cited(&mut f, r, tip); // citedHeight > R
    assert_eq!(mv(&mut f, &m), "mint9-bundle-stale");
    // a signature over the wrong block hash
    let r = f.tip - 1;
    let atts: Vec<_> = f
        .selected(r, &[])
        .into_iter()
        .map(|q| f.att(usize::from(q), 50000, r, Some(fake_hash(r + 1))))
        .collect();
    let payee = atts[0].seq;
    let m = f.mint_tx(
        10000,
        48,
        r,
        MintOpts {
            bundle: Some(encode_bundle(&Bundle::of(atts))),
            attest_payee: i64::from(payee),
            ..o()
        },
    );
    assert_eq!(mv(&mut f, &m), "mint9-bundle-sig");
}

// Rule: MINT-10
#[test]
fn mint10_diverged_void() {
    let mut f = armed(3);
    // pools 50,000; attestors 40,000: |x - a| / min = 25 % > 15 %
    let m = v3(&mut f, 10000, 40000);
    assert_eq!(mv(&mut f, &m), verdict::MINT10_DIVERGED);
    assert!(f.vault(&m.txid()).is_none());
    assert_eq!(f.log(&m.txid()).unwrap().a_mint, 40000); // the evaluation's bundle facts
                                                         // U-21: the invalid mint is not in the block, so its bundle writes no BundleLog row
    assert!(f.bundle_row(f.tip).is_none());
    // above as well: 57,501 > 57,500
    let m = v3(&mut f, 10000, 57501);
    assert_eq!(mv(&mut f, &m), verdict::MINT10_DIVERGED);
}

// Rule: MINT-10
#[test]
fn mint10_reads_the_fast_median_so_a_rally_mints() {
    let mut f = armed(3);
    ticks(&mut f, 10, 100_000);
    let s = f.snap(f.tip - 1);
    assert_eq!(s.pfast(), Some(100_000));
    assert_eq!(s.pmint(), Some(50000));
    let m = v3(&mut f, 10000, 100_000);
    assert_eq!(mv(&mut f, &m), ""); // MINT-5 sized it at the minimum, 50,000
    let first = f.evals[&f.tip].txlogs[0].0;
    assert_eq!(f.log(&first).unwrap().a_mint, 100_000);
    // attestors that stayed at the old price now disagree with the market: refused
    let m = v3(&mut f, 10000, 50000);
    assert_eq!(mv(&mut f, &m), verdict::MINT10_DIVERGED);
}

// Rule: MINT-10
#[test]
fn mint10_exact_boundary_ok() {
    let mut f = armed(3);
    // (a - x) x 10^4 <= 1,500 x min(x, a) with x = 50,000: a = 57,500 is the exact boundary
    let m = v3(&mut f, 10000, 57500);
    assert_eq!(mv(&mut f, &m), "");
    let first = f.evals[&f.tip].txlogs[0].0;
    assert_eq!(f.log(&first).unwrap().a_mint, 57500);
}

// Rule: PRICE-2
// Rule: AFEE-0
#[test]
fn price2_unarmed_reads_x_only() {
    let mut f = Fixture::new();
    f.activate(50000);
    assert!(!f.armed());
    // Unarmed: a garbage carrier and no attestor fee are ignored; the collateral is judged at xMint alone.
    let m = f.mint_tx(
        10000,
        48,
        f.tip - 1,
        MintOpts {
            bundle: Some(vec![0; 20]),
            ..o()
        },
    );
    assert_eq!(mv(&mut f, &m), "");
    let log = f.log(&f.evals[&f.tip].txlogs[0].0).unwrap();
    assert_eq!(log.a_mint, 0);
    assert!(log.bundle_seqs.is_empty());
    assert_eq!(log.attest_fee_zat, 0);
    assert!(f.bundle_row(f.tip).is_none());
}

// Rule: PRICE-2
// Rule: MINT-5
#[test]
fn price2_min_max() {
    let mut f = armed(3);
    let req = |f: &Fixture, price: i64| {
        let s = f.snap(f.tip - 1);
        required_collateral_rounded(
            10000,
            min_ratio_bps(f.p.base_ratio_bps[0], s.sigma_mult_bps),
            price,
            1000,
        )
        .unwrap()
    };
    // Attestors at 45,000 under pools at 50,000: pMint = 45,000, so the collateral for 50,000 is short.
    let c = req(&f, 50000);
    let m = v3o(
        &mut f,
        10000,
        45000,
        MintOpts {
            collateral: c,
            ..o()
        },
    );
    assert_eq!(mv(&mut f, &m), verdict::BAD_MINT_COLLATERAL);
    let c = req(&f, 45000);
    let m = v3o(
        &mut f,
        10000,
        45000,
        MintOpts {
            collateral: c,
            ..o()
        },
    );
    assert_eq!(mv(&mut f, &m), "");
    // Attestors above the pools: pMint stays at xMint (the min)
    let c = req(&f, 50000);
    let m = v3o(
        &mut f,
        10000,
        55000,
        MintOpts {
            collateral: c,
            ..o()
        },
    );
    assert_eq!(mv(&mut f, &m), "");
    // pClaim = max(x, a): underwater under pools at 9,000 but not when attestors say 21,000 (126 % >= 125 %).
    let m = v3(&mut f, 10000, 50000);
    assert_eq!(mv(&mut f, &m), "");
    let v = f.evals[&f.tip].txlogs[0].0;
    ticks(&mut f, 64, 9000);
    assert_eq!(f.snap(f.tip).pclaim(), Some(9000));
    let sel = vault_selector(&v);
    let r = f.tip - 1;
    let b = f.bundle_simple(r, &sel, 21000);
    let payee = f.selected(r, &sel)[0];
    let tx = f.spend_tx(
        &v,
        &[op(v, 1)],
        r,
        SpendOpts {
            owner_path: false,
            bundle: Some(b),
            attest_payee: i64::from(payee),
            ..SpendOpts::default()
        },
    );
    let res = spend(&mut f, &v, &tx);
    assert_eq!(res.verdict, verdict::VAULT_CLAIM_NOT_UNDERWATER);
    assert!(res.invalid);
}

// Rule: MINT-8
#[test]
fn mint8_lower_bound_before_mint9() {
    let mut f = armed(4);
    assert!(f.armed());
    // a 1-zat fee with a well-signed bundle: bad-mint-fee, and the bundle was never verified
    let m = v3o(
        &mut f,
        10000,
        50000,
        MintOpts {
            fee_value: 1,
            ..o()
        },
    );
    assert_eq!(mv(&mut f, &m), verdict::BAD_MINT_FEE);
    let log = f.log(&m.txid()).unwrap();
    assert!(log.bundle_seqs.is_empty());
    assert_eq!(log.a_mint, 0);
    // a 1-zat fee and no bundle at all: bad-mint-fee, not mint9-no-bundle (MINT-9 not reached)
    let m = f.mint_tx(
        10000,
        48,
        f.tip - 1,
        MintOpts {
            fee_value: 1,
            ..o()
        },
    );
    assert_eq!(mv(&mut f, &m), verdict::BAD_MINT_FEE);
    // one zat under the xMint fee: refused before MINT-9 as well
    let fee = f.mint_fee(10000, f.tip - 1);
    let m = f.mint_tx(
        10000,
        48,
        f.tip - 1,
        MintOpts {
            fee_value: fee - 1,
            ..o()
        },
    );
    assert_eq!(mv(&mut f, &m), verdict::BAD_MINT_FEE);
    // exactly the xMint fee and no bundle: the bound holds, MINT-9 runs and refuses
    let fee = f.mint_fee(10000, f.tip - 1);
    let m = f.mint_tx(
        10000,
        48,
        f.tip - 1,
        MintOpts {
            fee_value: fee,
            ..o()
        },
    );
    assert_eq!(mv(&mut f, &m), verdict::MINT9_NO_BUNDLE);
    // aMint below xMint: the bundle is verified, and MINT-8' at pMint = aMint refuses the xMint fee
    let a = f.pmint_at(f.tip - 1) * 9 / 10;
    let fee = f.mint_fee(10000, f.tip - 1);
    let m = v3o(
        &mut f,
        10000,
        a,
        MintOpts {
            fee_value: fee,
            ..o()
        },
    );
    assert_eq!(mv(&mut f, &m), verdict::BAD_MINT_FEE);
    assert!(!f.log(&m.txid()).unwrap().bundle_seqs.is_empty());
    // the honest mint still holds
    let m = v3(&mut f, 10000, 50000);
    assert_eq!(mv(&mut f, &m), "");
}

// Rule: AFEE-1
// Rule: MINT-8
// Rule: RED-3
#[test]
fn afee1_fee_to_contributor() {
    let mut f = armed(4);
    let fee = f.mint_fee(10000, f.tip - 1); // MintV3's $100: the $1 floor at $0.05 = 20 YEC
    assert_eq!(fee, 2_000_000_000);
    let afee = attest_fee_zat(fee, f.p.attest_fee_bps);
    assert_eq!(afee, fee / 4);
    let sel = f.selected(f.tip - 1, &[]);
    let outsider = (0u16..4).find(|q| !sel.contains(q)).unwrap();
    let m = v3o(
        &mut f,
        10000,
        50000,
        MintOpts {
            attest_payee: i64::from(outsider),
            ..o()
        },
    );
    assert_eq!(mv(&mut f, &m), verdict::AFEE1_FEE);
    let m = v3o(
        &mut f,
        10000,
        50000,
        MintOpts {
            attest_fee_value: afee - 1,
            ..o()
        },
    );
    assert_eq!(mv(&mut f, &m), verdict::AFEE1_FEE);
    let m = v3o(
        &mut f,
        10000,
        50000,
        MintOpts {
            attest_fee_vout: 3,
            ..o()
        },
    ); // the pool fee's vout
    assert_eq!(mv(&mut f, &m), verdict::AFEE1_FEE);
    let m = v3o(
        &mut f,
        10000,
        50000,
        MintOpts {
            attest_fee_vout: 9,
            ..o()
        },
    ); // out of range
    assert_eq!(mv(&mut f, &m), verdict::AFEE1_FEE);
    let s = p2pkh_of(&f.owner_pub()); // not the member key
    let m = v3o(
        &mut f,
        10000,
        50000,
        MintOpts {
            attest_fee_script: Some(s),
            ..o()
        },
    );
    assert_eq!(mv(&mut f, &m), verdict::AFEE1_FEE);
    // a contributor who is not the first signer is fine, and the log names it
    let last = *f.selected(f.tip - 1, &[]).last().unwrap();
    let m = v3o(
        &mut f,
        10000,
        50000,
        MintOpts {
            attest_payee: i64::from(last),
            ..o()
        },
    );
    assert_eq!(mv(&mut f, &m), "");
    let log = f.log(&m.txid()).unwrap();
    assert!(log.has_attest_payee);
    assert_eq!(log.attest_payee, last);
    assert_eq!(log.attest_fee_zat, afee);
    assert_eq!(log.bundle_seqs.len(), 3);
    // the claim side (RED-3's clause)
    let m = v3(&mut f, 10000, 50000);
    assert_eq!(mv(&mut f, &m), "");
    let v = m.txid();
    ticks(&mut f, 64, 9000);
    let vsel = vault_selector(&v);
    let b = f.bundle_simple(f.tip - 1, &vsel, 9000);
    let tx = f.spend_tx(
        &v,
        &[op(v, 1)],
        f.tip - 1,
        SpendOpts {
            owner_path: false,
            bundle: Some(b),
            ..SpendOpts::default()
        },
    );
    let r = spend(&mut f, &v, &tx); // no attestor fee output
    assert_eq!(r.verdict, verdict::AFEE1_FEE);
    assert!(r.invalid);
}

// Rule: AFEE-0
#[test]
fn afee0_unarmed_vacuous() {
    let mut f = Fixture::new();
    f.activate(50000);
    f.register(3, 0); // PENDING, then TRIGGERED: not yet ARMED
    let m = f.mint_tx(10000, 48, f.tip - 1, o());
    assert_eq!(mv(&mut f, &m), "");
    while f.attest().status != AttestStatus::Triggered {
        ticks(&mut f, 1, 50000);
    }
    let m = f.mint_tx(10000, 48, f.tip - 1, o());
    assert_eq!(mv(&mut f, &m), "");
    let v = f.evals[&f.tip].txlogs[0].0;
    assert_eq!(f.log(&v).unwrap().attest_fee_zat, 0);
    // a claim with R before armHeight needs no bundle and no attestor fee either
    while !f.attest().is_armed() {
        ticks(&mut f, 1, 50000);
    }
    ticks(&mut f, 3, 50000);
    assert!(f.armed());
    let r = i64::from(f.attest().arm_height) - 1;
    assert!(r >= f.tip - i64::from(f.p.ref_window) + 1);
    assert!(!f.armed_at(r));
    let tx = f.spend_tx(
        &v,
        &[op(v, 1)],
        r,
        SpendOpts {
            owner_path: false,
            ..SpendOpts::default()
        },
    );
    let res = spend(&mut f, &v, &tx);
    assert!(
        res.verdict == verdict::OK || res.verdict == verdict::VAULT_CLAIM_NOT_UNDERWATER,
        "{}",
        res.verdict
    );
    assert!(!res.verdict.contains("red1-bundle"));
    assert_ne!(res.verdict, verdict::AFEE1_FEE);
}

// Rule: PRICE-2
// Rule: MINT-9
#[test]
fn attest_required_false_reads_x_only() {
    let mut f = Fixture::new();
    f.p.attest_required = false; // W15: the disarm switch of a later parameter set
    f.arm(3, 50000);
    assert!(f.attest().is_armed());
    assert!(f.snap(f.tip - 1).attest.is_armed());
    assert!(!f.armed());
    assert!(!f.armed_at(f.tip));
    let m = f.mint_tx(10000, 48, f.tip - 1, o());
    assert_eq!(mv(&mut f, &m), ""); // no bundle needed
    let m = f.mint_tx(
        10000,
        48,
        f.tip - 1,
        MintOpts {
            bundle: Some(vec![0; 7]),
            ..o()
        },
    );
    assert_eq!(mv(&mut f, &m), "");
    assert!(f.bundle_row(f.tip).is_none());
    let v = f.evals[&f.tip].txlogs[0].0;
    ticks(&mut f, 64, 9000);
    let tx = f.spend_tx(
        &v,
        &[op(v, 1)],
        f.tip - 1,
        SpendOpts {
            owner_path: false,
            ..SpendOpts::default()
        },
    );
    let r = spend(&mut f, &v, &tx);
    assert_eq!(r.verdict, verdict::OK);
    assert_eq!(r.log.claim_path, "a");
}

// Rule: PIN-2
#[test]
fn pin2_excludes_seq() {
    let mut f = armed(4);
    // xMint falls by 20 % within PIN_WINDOW: PIN-2 arms.
    ticks(&mut f, 8, 40000);
    assert_eq!(f.snap(f.tip).pmint(), Some(40000));
    assert_eq!(
        f.snap(f.tip - i64::from(f.p.pin_window)).pmint(),
        Some(50000)
    );
    // seq 2 appears in two rows of W at one price; seq 1 in two rows at two prices; seq 3 in one row.
    let r1 = BundleLogRecord {
        a_mint: 40000,
        a_claim: 40000,
        selected_seqs: vec![1, 2, 3],
        seqs: vec![1, 2, 3],
        prices: vec![40000, 40000, 40000],
        cited_heights: vec![10, 10, 10],
    };
    let mut r2 = BundleLogRecord {
        a_mint: 40000,
        a_claim: 40000,
        selected_seqs: vec![1, 2],
        seqs: vec![1, 2],
        prices: vec![40100, 40000],
        cited_heights: vec![11, 10],
    };
    let t = u32::try_from(f.tip).unwrap();
    f.put(YedKey::BundleLog(t - 2), YedRecord::BundleLog(r1));
    f.put(YedKey::BundleLog(t), YedRecord::BundleLog(r2.clone()));
    ticks(&mut f, 1, 40000);
    // Audit A-2: one attestation (cited height 10) reused by two bundles pins nothing.
    assert!(f.snap(f.tip).pinned_seqs.is_empty());
    r2.cited_heights = vec![11, 11];
    let t = u32::try_from(f.tip).unwrap();
    f.put(YedKey::BundleLog(t - 1), YedRecord::BundleLog(r2));
    ticks(&mut f, 1, 40000);
    let s = f.snap(f.tip);
    assert_eq!(s.pinned_seqs, vec![2]);
    assert!(s.pinned_keys.is_empty()); // PIN-1 is not armed: the rows' aMint agree
                                       // Selection at this R never draws seq 2; the pool has three left, all drawn.
    let got = f.selected(f.tip, &[]);
    assert_eq!(got.len(), 3);
    assert!(!got.contains(&2));
    // and a bundle from seq 2 at this R is "member"
    ticks(&mut f, 1, 40000);
    let r = f.tip - 1;
    let b = encode_bundle(&Bundle::of(vec![
        f.att(2, 40000, r, None),
        f.att(usize::from(got[0]), 40000, r, None),
    ]));
    let m = f.mint_tx(
        10000,
        48,
        r,
        MintOpts {
            bundle: Some(b),
            attest_payee: i64::from(got[0]),
            ..o()
        },
    );
    assert_eq!(mv(&mut f, &m), "mint9-bundle-member");
}

// Rule: REV-1
// Rule: S15
#[test]
fn rev1_heartbeat_revives_s15_dormant() {
    let mut f = armed(4);
    // A heartbeat of an ELIGIBLE attestor only moves lastAct.
    let hb0 = f.heartbeat_tx(0);
    assert_eq!(verdict_of(&mut f, &hb0), verdict::OK);
    assert_eq!(f.attestor(0).unwrap().status, AttestorStatus::Eligible);
    assert_eq!(i64::from(f.attestor(0).unwrap().last_act), f.tip);
    // Make seq L dormant (S15): mints whose selection includes L, signed by the others.
    let mut l: Option<u16> = None;
    let mut rows = 0;
    while rows < f.p.dormancy_min_bundles {
        let r = f.tip - 1;
        let sel = f.selected(r, &[]);
        let ll = *l.get_or_insert(sel[0]);
        if sel.contains(&ll) {
            let skip: BTreeSet<u16> = [ll].into_iter().collect();
            let m = f.mint_v3(10000, 50000, o(), &skip, 48);
            assert_eq!(mv(&mut f, &m), "");
            rows += 1;
        } else {
            ticks(&mut f, 1, 50000);
        }
    }
    let l = l.unwrap();
    while f.tip % i64::from(f.p.dormancy_check) != 0
        || f.tip - i64::from(f.p.dormancy_blocks) < i64::from(f.attestor(l).unwrap().seated_since)
    {
        ticks(&mut f, 1, 50000);
    }
    assert_eq!(f.attestor(l).unwrap().status, AttestorStatus::Dormant);
    assert_eq!(i64::from(f.attestor(l).unwrap().status_height), f.tip);
    // the retired payload is invalid; a heartbeat revives at its own SNAP
    let a = f.att(usize::from(l), 50000, f.tip, None);
    let rv = f.revive_tx(&a);
    assert_eq!(verdict_of(&mut f, &rv), verdict::ATTESTOR_REVIVE_RETIRED);
    assert_eq!(f.attestor(l).unwrap().status, AttestorStatus::Dormant);
    let r = f.heartbeat_tx(usize::from(l));
    assert_eq!(verdict_of(&mut f, &r), verdict::OK);
    assert_eq!(f.attestor(l).unwrap().status, AttestorStatus::Eligible);
    assert_eq!(f.log(&r.txid()).unwrap().attestor_seq, l);
    assert!(f.snap(f.tip).seated.contains(&l));
}

// Rule: D-Q-30
#[test]
fn dq28_bond_min_from_collateral() {
    let five: i64 = 5_000_000; // $5: a $100 mint needs 60 YEC at 300 %
    let mut f = Fixture::with(1, 0, 0, 0); // attestArmMin 0: never arms, mints need no bundle
    let quote = |f: &mut Fixture| ticks(f, 1, five);
    let bond_min = |f: &Fixture| bond_min_zat(&f.state, &f.p, f.tip + 1);
    let mint = |f: &mut Fixture, collateral: i64| {
        let m = f.mint_tx(10000, 48, f.tip - 1, MintOpts { collateral, ..o() });
        let t = Fixture::quote(five, (f.tip + 1) % 3);
        f.mine(Some(t), vec![m.clone()]);
        assert!(f.vault(&m.txid()).is_some());
    };
    let start = i64::from(f.p.start_height);
    assert_eq!(bond_min_zat(&f.state, &f.p, start), 5 * COIN); // the virtual snapshot: no collateral
    f.activate(five);
    assert_eq!(f.totals().collateral_zat, 0);
    assert_eq!(bond_min(&f), 5 * COIN); // empty vaults: the 5-YEC floor
    let refused_as = |f: &Fixture, m: &MTx| {
        f.refused
            .get(&m.txid())
            .map_or("none".to_owned(), |l| l.verdict.clone())
    };
    let below0 = f.register_tx(0, 5 * COIN - 1, -1, None);
    let r1 = f.register_tx(1, 5 * COIN, -1, None);
    let t = Fixture::quote(five, (f.tip + 1) % 3);
    f.mine(Some(t), vec![below0.clone(), r1]);
    assert_eq!(refused_as(&f, &below0), verdict::ATTESTOR_BOND_BELOW_MIN);
    // the minimum rises with collateral: 700 YEC locked -> 7 YEC
    mint(&mut f, 700 * COIN);
    assert_eq!(f.totals().collateral_zat, 700 * COIN);
    assert_eq!(bond_min(&f), 7 * COIN);
    let below2 = f.register_tx(2, 7 * COIN - 1, -1, None);
    let r3 = f.register_tx(3, 7 * COIN, -1, None);
    let t = Fixture::quote(five, (f.tip + 1) % 3);
    f.mine(Some(t), vec![below2.clone(), r3]); // seq 1
    assert_eq!(refused_as(&f, &below2), verdict::ATTESTOR_BOND_BELOW_MIN);
    let reg1 = f.tip;
    while f.tip < reg1 + i64::from(f.p.bond_maturity) {
        quote(&mut f);
    }
    assert_eq!(f.attestor(0).unwrap().status, AttestorStatus::Eligible);
    assert_eq!(f.attestor(1).unwrap().status, AttestorStatus::Eligible);
    // the cap: 1,700 YEC locked would ask 17 YEC; the minimum stops at 10 YEC
    mint(&mut f, 1000 * COIN);
    assert_eq!(bond_min(&f), 10 * COIN);
    let below4 = f.register_tx(4, 10 * COIN - 1, -1, None);
    let r5 = f.register_tx(5, 10 * COIN, -1, None);
    let t = Fixture::quote(five, (f.tip + 1) % 3);
    f.mine(Some(t), vec![below4.clone(), r5]); // seq 2
    assert_eq!(refused_as(&f, &below4), verdict::ATTESTOR_BOND_BELOW_MIN);
    let reg2 = f.tip;
    while f.tip < reg2 + i64::from(f.p.bond_maturity) {
        quote(&mut f);
    }
    assert_eq!(f.attestor(2).unwrap().status, AttestorStatus::Eligible);
    // checked once: the 5- and 7-YEC records stay ELIGIBLE under a 10-YEC minimum
    ticks(&mut f, 70, 50000);
    assert_eq!(f.attestor(0).unwrap().status, AttestorStatus::Eligible);
    assert_eq!(f.attestor(1).unwrap().status, AttestorStatus::Eligible);
    assert_eq!(bond_min(&f), 10 * COIN);
    assert_eq!(f.snap(f.tip).seated, vec![0, 1, 2]);
    let r6 = f.register_tx(6, 10 * COIN, -1, None);
    let r7 = f.register_tx(7, 10 * COIN, -1, None);
    let t = Fixture::quote(50000, (f.tip + 1) % 3);
    f.mine(Some(t), vec![r6, r7]);
    let reg34 = f.tip;
    while f.tip < reg34 + i64::from(f.p.bond_maturity) {
        quote(&mut f);
    }
    assert_eq!(f.snap(f.tip).seated, vec![0, 1, 2, 3, 4]);
    // the bump: seq 5 posts 10 YEC and, by SeatRank, outranks seq 0 (5 YEC) once ELIGIBLE
    let r8 = f.register_tx(8, 10 * COIN, -1, None);
    let t = Fixture::quote(50000, (f.tip + 1) % 3);
    f.mine(Some(t), vec![r8]);
    let reg5 = f.tip;
    assert!(f.attestor(5).is_some());
    let reg0 = i64::from(f.attestor(0).unwrap().register_height);
    let (u, cap, mat) = (
        i64::from(f.p.seat_age_unit),
        i64::from(f.p.seat_age_cap),
        i64::from(f.p.bond_maturity),
    );
    assert!(
        seat_weight(10 * COIN, mat, u, cap).wrapping_mul(U256::from_u64(10000))
            > seat_weight(5 * COIN, reg5 + mat - reg0, u, cap).wrapping_mul(U256::from_u64(10500))
    );
    while f.tip < reg5 + mat - 1 {
        quote(&mut f);
    }
    assert_eq!(f.snap(f.tip).seated, vec![0, 1, 2, 3, 4]);
    quote(&mut f);
    assert_eq!(f.snap(f.tip).seated, vec![1, 2, 3, 4, 5]);
    assert_eq!(f.attestor(0).unwrap().status, AttestorStatus::Eligible); // bumped, still a member
    assert_eq!(f.attestor(0).unwrap().seated_since, 0);
    let _ = VaultStatus::Active;
}
