// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

//! The SNAP cases of ycash6 `src/test/yellowback_state_tests.cpp` at `65cb4ae0f` (W5-d2): TAG-3/4,
//! PRICE-1, HALT-1..4, SIGMA-1, REG-1..4, FEE-0..2 and FEE-W (the wallet's default payee), block
//! chaining, totality, the virtual snapshot, the snapshot records, parameter selection, the N6
//! bench, and HALT-2's open-debt invariant through undo. Each is a test of the same name over the
//! ported `Fixture`; the C++ `// Rule:` tags are kept.

mod state_common;

use kogany_vault::state::{VaultTx, VaultTxIn, VaultTxOut};
use kogany_vault::OutPoint;
use kogany_yellowback::attest::bundle::encode_cancel_cosigns;
use kogany_yellowback::attest::price::{
    HALT_DIVERGENCE, HALT_GLOBAL_RATIO, HALT_NOT_ACTIVE, HALT_NO_PRICE,
};
use kogany_yellowback::codecs::payload::{encode_payload, payload_script, Assignment, Payload};
use kogany_yellowback::codecs::script::{yed_vault_script, yed_vault_script_at};
use kogany_yellowback::math::{global_ratio_bps, protocol_fee_cents, protocol_fee_zat};
use kogany_yellowback::params::{
    regtest_params, select_params, Params, COIN, FEE_VOUT_NONE, TOKEN_VALUE,
};
use kogany_yellowback::state::{
    accuracy_bps, default_payee, eligible_payees, evaluate_block, halt_mask_names,
    mempool_check_reason, open_debt_invariant_violation, penalized, process_tx, registered,
    snapshot_at, verdict, Judgement, PayeePolicy, VaultStatus, YedKey, YedRead, YedRecord,
    YedState, SCHEMA_VERSION,
};
use state_common::fixture::*;

fn q(f: &Fixture, price: i64) -> Option<kogany_yellowback::codecs::tag::CoinbaseTag> {
    Some(Fixture::quote(price, (f.tip + 1) % 3))
}

// Rule: TAG-3
// Rule: TAG-4
// Rule: SNAP
// Rule: REG-1
#[test]
fn tag3_signal_only_registers_nobody() {
    let mut f = Fixture::new();
    f.mine(Some(Fixture::signal_only(1)), Vec::new()); // signal-only: no quote, no payee
    assert!(f.snap(1).tagged);
    assert!(!f.snap(1).quote);
    assert!(eligible_payees(&f.state, &f.p, 1).is_empty());
    assert!(!registered(&f.state, &f.p, &key_of(1), 1));
    f.mine(Some(Fixture::quote(50000, 2)), Vec::new());
    assert!(f.snap(2).quote);
    assert!(registered(&f.state, &f.p, &key_of(2), 2));
    assert_eq!(eligible_payees(&f.state, &f.p, 2).len(), 1);
    // TAG-4: garbage in the coinbase (an invalid tag, or no tag) never makes a block invalid and
    // is "no tag".
    let mut bad = Fixture::quote(50000, 1);
    bad.flags = 0x03;
    let ev = f.mine(Some(bad), Vec::new());
    assert!(!ev.block_invalid);
    assert!(!f.snap(3).tagged);
    let ev = f.mine(None, Vec::new());
    assert!(!ev.block_invalid);
    assert!(!f.snap(4).tagged);
    // REG-1 lapse: registration ends N_REG blocks after the last quote.
    let n_reg = i64::from(f.p.n_reg);
    assert!(registered(&f.state, &f.p, &key_of(2), 2 + n_reg - 1));
    assert!(!registered(&f.state, &f.p, &key_of(2), 2 + n_reg));
}

// Rule: PRICE-1
// Rule: PRICE-2
// Rule: HALT-1
#[test]
fn price1_half_fill_boundary_and_selectors() {
    let mut f = Fixture::new();
    // Fast window 8, fill ceil(8/2) = 4: three quotes in the last 8 blocks => undefined; four => defined.
    f.mine(Some(Fixture::quote(50000, 0)), Vec::new());
    f.mine(Some(Fixture::quote(50100, 1)), Vec::new());
    f.mine(Some(Fixture::quote(50200, 2)), Vec::new());
    assert!(f.snap(3).pfast().is_none());
    assert!(f.snap(3).halt_mask & HALT_NO_PRICE != 0);
    f.mine(Some(Fixture::quote(50300, 0)), Vec::new());
    assert_eq!(f.snap(4).pfast(), Some(50100)); // lower median of {50000,50100,50200,50300}
    assert!(f.snap(4).pmint().is_none()); // mid/slow still undefined => pMint undefined, NO_PRICE
    assert!(f.snap(4).halt_mask & HALT_NO_PRICE != 0);
    // Rising series: pMint = min = the slowest median; falling: pMint = the fast one;
    // pClaim = max(mid, slow).
    f.mine_quotes_to(70, 50000);
    for h in 71..=90 {
        f.mine(Some(Fixture::quote(60000, h % 3)), Vec::new());
    }
    let s = f.snap(90);
    assert_eq!(s.pfast(), Some(60000));
    assert_eq!(s.pslow(), Some(50000));
    assert_eq!(s.pmint(), Some(50000));
    assert_eq!(
        s.pclaim().unwrap(),
        s.pmid().unwrap().max(s.pslow().unwrap())
    );
    for h in 91..=110 {
        f.mine(Some(Fixture::quote(40000, h % 3)), Vec::new());
    }
    let s = f.snap(110);
    assert_eq!(s.pfast(), Some(40000));
    assert_eq!(s.pmint(), Some(40000));
    assert!(s.pclaim().unwrap() >= s.pmid().unwrap());
}

// Rule: PRICE-1
#[test]
fn price1_mid_slow_need_two_thirds() {
    // Mid window 24 needs ceil(2*24/3) = 16 quotes; 15 is not enough (L9). Quote every block from 2.
    let mut f = Fixture::new();
    f.mine(None, Vec::new());
    for h in 2..=16 {
        f.mine(Some(Fixture::quote(50000, h % 3)), Vec::new()); // 15 quotes at 16
    }
    assert!(f.snap(16).pmid().is_none());
    f.mine(Some(Fixture::quote(50000, 2)), Vec::new()); // 16 quotes at 17
    assert!(f.snap(17).pmid().is_some());
    // Slow window 64 needs 43: at 44 there are 43 quotes (heights 2..44).
    for h in 18..=43 {
        f.mine(Some(Fixture::quote(50000, h % 3)), Vec::new());
    }
    assert!(f.snap(43).pslow().is_none());
    f.mine(Some(Fixture::quote(50000, 1)), Vec::new());
    assert!(f.snap(44).pslow().is_some());
    assert!(f.snap(44).pmint().is_some());
}

// Rule: HALT-1
// Rule: HALT-2
// Rule: HALT-3
// Rule: HALT-4
#[test]
fn halt2_halt3_clear_with_undefined_price() {
    let mut f = Fixture::new();
    // Before any price: HALT-1 by name, HALT-2/3 clear (M1); HALT-4 marks only the virtual
    // snapshot (U-22).
    f.mine(Some(Fixture::quote(50000, 0)), Vec::new());
    assert_eq!(f.snap(1).halt_mask, HALT_NO_PRICE);
    f.activate(50000);
    let _vault = f.mint_active(10000, 48, 0);
    let s = f.snap(f.tip);
    assert!(s.global_ratio().is_some());
    assert!(s.global_ratio().unwrap() >= 30000 - 1); // 300 % (class A, D-IT-4) at pMint 50,000
                                                     // Crash the fast median to 1/3: divergence and, once pMint follows, the global ratio halt.
    for _ in 0..8 {
        let t = q(&f, 15000);
        f.mine(t, Vec::new());
    }
    let s = f.snap(f.tip);
    assert!(s.halt_mask & HALT_DIVERGENCE != 0); // pFast 15,000 < 0.8 * pMid
    assert!(s.halt_mask & HALT_GLOBAL_RATIO != 0); // 10,000 YEC * 0.015 / $100 = 150%
    assert!(s.halt_mask & HALT_NO_PRICE == 0);
}

// Rule: HALT-2
#[test]
fn halt2_fires_at_exact_threshold() {
    // GLOBAL_RATIO is set iff globalRatioBps < GLOBAL_RATIO_HALT_BPS (25,000), by the math directly.
    assert_eq!(
        global_ratio_bps(5000 * COIN, Some(50000), 10000),
        Some(25000)
    ); // 250 % exactly
    assert!(global_ratio_bps(5000 * COIN, Some(50000), 10000).unwrap() >= 25000);
    assert!(global_ratio_bps(5000 * COIN - 1, Some(50000), 10000).unwrap() < 25000);
}

// Rule: HALT-3
#[test]
fn halt3_fires_on_mid_vs_slow() {
    let mut f = Fixture::new();
    f.mine_quotes_to(64, 50000);
    // 24 blocks at 39,000: pMid falls to 39,000 while pSlow stays 50,000: 39,000 < 0.8 * 50,000.
    for _ in 0..24 {
        let t = q(&f, 39000);
        f.mine(t, Vec::new());
    }
    let s = f.snap(f.tip);
    assert_eq!(s.pmid(), Some(39000));
    assert_eq!(s.pslow(), Some(50000));
    assert!(s.halt_mask & HALT_DIVERGENCE != 0);
}

// Rule: SIGMA-1
#[test]
fn sigma1_undefined_sample_gives_cap() {
    // Non-zero SIGMA_REF: below START + VOL_WINDOW a sample is virtual => the cap (K12); after, 1x
    // on a flat series. D-IT-5 (IT-4) sets the cap itself to 1x, so the multiplier is 1x throughout.
    let mut f = Fixture::with(1, 10000, 0, 0);
    assert_eq!(f.p.sigma_mult_max_bps, 10000);
    f.mine_quotes_to(64, 50000);
    assert_eq!(f.snap(64).sigma_mult_bps, f.p.sigma_mult_max_bps); // s_8 = Snapshots[0] is virtual
    f.mine_quotes_to(67, 50000);
    assert_eq!(f.snap(67).sigma_mult_bps, f.p.sigma_mult_max_bps); // s_8 = Snapshots[3].pFast undefined
    f.mine_quotes_to(68, 50000);
    assert_eq!(f.snap(68).sigma_mult_bps, 10000); // every sample defined and equal
                                                  // With SIGMA_REF 0 the multiplier is fixed at 1 before the sample check.
    let mut g = Fixture::with(1, 0, 0, 0);
    g.mine_quotes_to(10, 50000);
    assert_eq!(g.snap(10).sigma_mult_bps, 10000);
}

// Rule: SIGMA-1
#[test]
fn sigma1_one_pool_cannot_inflate() {
    // One of three pools alternates +-20%: the lower median of the fast window ignores it.
    let mut f = Fixture::with(1, 10000, 0, 0);
    for h in 1..=140i64 {
        let mut p = 50000;
        if h % 3 == 0 {
            p = if h % 2 != 0 { 60000 } else { 40000 };
        }
        f.mine(Some(Fixture::quote(p, h % 3)), Vec::new());
    }
    for h in 70..=140 {
        assert_eq!(f.snap(h).sigma_mult_bps, 10000, "h {h}");
    }
}

// ===========================================================================
// Judgement, eligible payees, the wallet default (§3.7 REG-2..4, FEE-0..2, FEE-W)

// Rule: REG-4
// Rule: REG-2
// Rule: REG-3
#[test]
fn reg4_judgement_lag_and_bands() {
    let mut f = Fixture::new();
    // Quotes at 1..12 from three pools; pool 0 quotes 12% high at 6 (penalised) and 2% high at 9.
    for h in 1..=12i64 {
        let mut p = 50000;
        if h == 6 {
            p = 56000;
        }
        if h == 9 {
            p = 51000;
        }
        f.mine(Some(Fixture::quote(p, h % 3)), Vec::new());
    }
    // The judgement for t is written at t + PEER_LAG (4): t = 8 exists after block 12, t = 9 does not.
    assert!(f.state.judgement(8).is_some());
    assert!(f.state.judgement(9).is_none());
    // t = 6: peers at 2..9 minus 6 = 7 quotes, median 50,000, dev 1,200 bps > 1,000 => penalized.
    let j6 = f.state.judgement(6).unwrap();
    assert!(j6.evaluated);
    assert!(j6.penalized);
    assert!(!j6.in_band);
    // t = 1: peers in [-3, 4] are 2, 3, 4 = 3 >= PEER_MIN: evaluated, in band.
    let j1 = f.state.judgement(1).unwrap();
    assert!(j1.evaluated && j1.in_band && !j1.penalized);
    f.mine_quotes_to(20, 50000);
    // t = 9: dev 200 bps <= 300 => in band.
    let j9 = f.state.judgement(9).unwrap();
    assert!(j9.evaluated && j9.in_band);
    // Too few peers: a lone quote among untagged blocks is written but not evaluated.
    let mut g = Fixture::new();
    g.mine(None, Vec::new());
    g.mine(None, Vec::new());
    g.mine(Some(Fixture::quote(50000, 0)), Vec::new());
    for _ in 0..6 {
        g.mine(None, Vec::new());
    }
    assert!(!g.state.judgement(3).unwrap().evaluated);
    // REG-2 window edges: penalised at t = 6 counts for R in (10, 22] (lag 4, N_PENALTY 12).
    let k2 = key_of(0); // 6 % 3 == 0
    let np = f.p.n_penalty;
    assert!(!penalized(&f.state, &f.p, &k2, 10, np));
    assert!(penalized(&f.state, &f.p, &k2, 11, np));
    assert!(penalized(&f.state, &f.p, &k2, 22, np));
    assert!(!penalized(&f.state, &f.p, &k2, 23, np));
    assert!(!penalized(&f.state, &f.p, &k2, 11, 0));
    // REG-3: pool 0 quoted at 3, 6, 9, 12, 15, 18 (judged up to R - 4 = 16 at R = 20): 3, 6, 9,
    // 12, 15 evaluated; 6 out of band.
    assert_eq!(
        accuracy_bps(&f.state, &f.p, &k2, 20, f.p.accuracy_window),
        8000
    );
    assert_eq!(accuracy_bps(&f.state, &f.p, &k2, 20, 1), 0); // t = 16 only (pool 1's)
    assert_eq!(accuracy_bps(&f.state, &f.p, &k2, 20, 4), 10000); // t in [13, 16]: pool 0's 15
    assert_eq!(accuracy_bps(&f.state, &f.p, &key_of(7), 20, 24), 0);
}

// Rule: FEE-2
// Rule: FEE-0
#[test]
fn fee2_eligible_set_window_edges() {
    let mut f = Fixture::new();
    f.mine(Some(Fixture::quote(50000, 0)), Vec::new()); // 1
    f.mine(Some(Fixture::signal_only(1)), Vec::new()); // 2: signal-only, never eligible
    for _ in 3..=12 {
        f.mine(None, Vec::new());
    }
    // PAYEE_WINDOW 10: E(R) contains key 0 for R in [1, 10], not at 11.
    assert_eq!(eligible_payees(&f.state, &f.p, 10), vec![key_of(0)]);
    assert!(eligible_payees(&f.state, &f.p, 11).is_empty()); // FEE-0
    assert_eq!(eligible_payees(&f.state, &f.p, 2).len(), 1); // the signal-only tag adds nobody
                                                             // Dedup and height order.
    f.mine(Some(Fixture::quote(50000, 2)), Vec::new()); // 13
    f.mine(Some(Fixture::quote(50000, 0)), Vec::new()); // 14
    f.mine(Some(Fixture::quote(50000, 2)), Vec::new()); // 15
    assert_eq!(
        eligible_payees(&f.state, &f.p, 15),
        vec![key_of(2), key_of(0)]
    );
}

// Rule: FEE-1'
#[test]
fn fee1_floor_dominates_small_vault() {
    let p = regtest_params(1, 0, 0, test_set().0);
    // The regtest column carries mainnet's bands and floor: $100 pays the $1 floor, $10,000 pays $55.
    assert_eq!(protocol_fee_cents(10000, &p), 100);
    assert_eq!(protocol_fee_cents(1_000_000, &p), 5500);
    assert_eq!(protocol_fee_zat(10000, 50000, &p), Some(2_000_000_000)); // $1 at $0.05 = 20 YEC
    assert_eq!(protocol_fee_zat(10000, 50000 + 1, &p), Some(1_999_960_001)); // ceil
    assert!(protocol_fee_zat(10000, 0, &p).is_none()); // no price, no fee
}

/// `PayeeFixture`: a 10-block window with alternating perfect (A = key 0) and never-in-band
/// (B = key 1) miners, judged.
fn payee_fixture() -> Fixture {
    let mut f = Fixture::new();
    f.mine_quotes_to(40, 50000); // three pools so every tag is evaluated
    for h in 41..=60i64 {
        f.mine(Some(Fixture::quote(50000, h % 2)), Vec::new());
    }
    f.mine_quotes_to(70, 50000); // judge the last of them (lag 4)
                                 // Rewrite the judgements: A always in band, B never (evaluated, not penalised).
    for t in 33..=60u32 {
        let j = Judgement {
            evaluated: true,
            in_band: if t <= 40 { t % 3 == 0 } else { t % 2 == 0 },
            penalized: false,
        };
        f.put(YedKey::Judgement(t), YedRecord::Judgement(j));
    }
    f
}

/// `Selector(i)`: 33 bytes shaped like an owner key, `0x02 ‖ i` little-endian (N28).
fn selector(i: i32) -> Vec<u8> {
    let mut s = vec![0u8; 33];
    s[0] = 0x02;
    s[1] = (i & 0xff) as u8;
    s[2] = ((i >> 8) & 0xff) as u8;
    s
}

fn penalised_judgement() -> Judgement {
    Judgement {
        evaluated: true,
        in_band: false,
        penalized: true,
    }
}

// Rule: FEE-W
// Rule: FEE-2
#[test]
fn feew_accuracy_tilt_ratio() {
    let f = payee_fixture();
    // R = 60: E(R) = {A, B}; accuracy over (32, 56]: A 10000, B 0.
    assert_eq!(
        accuracy_bps(&f.state, &f.p, &key_of(0), 60, f.p.accuracy_window),
        10000
    );
    assert_eq!(
        accuracy_bps(&f.state, &f.p, &key_of(1), 60, f.p.accuracy_window),
        0
    );
    let def = PayeePolicy::defaults(&f.p);
    let (mut a, mut b) = (0, 0);
    for i in 0..1000 {
        let k = default_payee(&f.state, &f.p, 60, &selector(i), &def).unwrap();
        if k == key_of(0) {
            a += 1;
        } else if k == key_of(1) {
            b += 1;
        } else {
            panic!("pick outside E(R)");
        }
    }
    assert!(
        a >= 18 * b / 10 && a <= 22 * b / 10,
        "default tilt ratio {a}:{b}"
    );
    let flat = PayeePolicy { tilt_bps: 0, ..def };
    let (mut a, mut b) = (0, 0);
    for i in 0..1000 {
        if default_payee(&f.state, &f.p, 60, &selector(i), &flat).unwrap() == key_of(0) {
            a += 1;
        } else {
            b += 1;
        }
    }
    assert!(a >= 9 * b / 10 && a <= 11 * b / 10, "tilt 0 ratio {a}:{b}");
    // E(R) empty => None.
    assert!(default_payee(&f.state, &f.p, 0, &selector(1), &def).is_none());
}

// Rule: FEE-W
// Rule: REG-2
#[test]
fn feew_penalised_skipped_and_fallback() {
    let mut f = payee_fixture();
    let def = PayeePolicy::defaults(&f.p);
    // Penalise B at t = 53 (R = 60: 57 < 60 <= 69): every pick is A.
    f.put(
        YedKey::Judgement(53),
        YedRecord::Judgement(penalised_judgement()),
    );
    for i in 0..100 {
        assert_eq!(
            default_payee(&f.state, &f.p, 60, &selector(i), &def),
            Some(key_of(0))
        );
    }
    // Penalise A too: the all-penalised fallback picks among all of E(R) at equal weights.
    f.put(
        YedKey::Judgement(54),
        YedRecord::Judgement(penalised_judgement()),
    );
    let (mut a, mut b) = (0, 0);
    for i in 0..1000 {
        if default_payee(&f.state, &f.p, 60, &selector(i), &def).unwrap() == key_of(0) {
            a += 1;
        } else {
            b += 1;
        }
    }
    assert!(a > 350 && b > 350, "{a}:{b}");
}

// Rule: FEE-W
#[test]
fn feew_override_flags_change_pick() {
    let mut f = payee_fixture();
    let def = PayeePolicy::defaults(&f.p);
    // B penalised for R in (57, 69] at the default N_PENALTY 12
    f.put(
        YedKey::Judgement(53),
        YedRecord::Judgement(penalised_judgement()),
    );
    let count = |f: &Fixture, pp: &PayeePolicy, r: i64| {
        (0..300)
            .filter(|i| default_payee(&f.state, &f.p, r, &selector(*i), pp) == Some(key_of(1)))
            .count()
    };
    assert_eq!(count(&f, &def, 60), 0);
    // -yellowbackpayeepenaltyblocks=2: the penalty has lapsed by R = 60 (t + 4 + 2 = 59 < 60).
    let short_penalty = PayeePolicy {
        penalty_blocks: 2,
        ..def
    };
    assert!(count(&f, &short_penalty, 60) > 0);
    // -yellowbackpayeeaccuracywindow=1 at R = 60 reads t = 56 only (A's, rewritten out of band):
    // A's accuracy becomes 0 => equal weights, so B is picked more often than with the default.
    f.put(
        YedKey::Judgement(56),
        YedRecord::Judgement(Judgement {
            evaluated: true,
            in_band: false,
            penalized: false,
        }),
    );
    let narrow = PayeePolicy {
        accuracy_window: 1,
        ..short_penalty
    };
    let (b_narrow, b_wide) = (count(&f, &narrow, 60), count(&f, &short_penalty, 60));
    assert!(b_narrow > b_wide, "{b_narrow} {b_wide}");
    // -yellowbackpayeetiltbps=0 flattens the weights the same way.
    let flat = PayeePolicy {
        tilt_bps: 0,
        ..short_penalty
    };
    assert!(count(&f, &flat, 60) > b_wide);
    // -yellowbackpreferredpayee replaces the pick when in E(R), never otherwise.
    let mut pref = PayeePolicy {
        preferred: Some(key_of(1)),
        ..def
    };
    assert_eq!(count(&f, &pref, 60), 300);
    pref.preferred = Some(key_of(7));
    assert_eq!(count(&f, &pref, 60), 0);
}

// ===========================================================================
// Chaining, totality, virtual snapshot, parameter sets, bench

// Rule: SNAP
// Rule: IN-1
#[test]
fn tpl1_overlay_order_in_block_chaining() {
    // A mint and a transfer of its token in the same block, in order: the transfer sees the token.
    let mut f = Fixture::new();
    f.activate(50000);
    let r = f.tip - 1;
    let m = f.mint_tx(10000, 48, r, MintOpts::default());
    let mid = m.txid();
    let t = f.transfer_tx(&[op(mid, 1)], &[Assignment::new(0, 10000)], false, 0);
    f.mine(Some(Fixture::quote(50000, 0)), vec![m.clone(), t.clone()]);
    assert!(f.token(&mid, 1).is_none());
    assert_eq!(f.token(&t.txid(), 0).unwrap().cents, 10000);
    assert_eq!(f.log(&t.txid()).unwrap().verdict, verdict::OK);
    assert_eq!(f.totals().supply_cents, 10000);
    // Reverse order: the transfer comes first and spends nothing.
    f.undo();
    f.mine(Some(Fixture::quote(50000, 0)), vec![t.clone(), m]);
    assert!(f.token(&mid, 1).is_some());
    assert!(f.log(&t.txid()).is_none());
}

// Rule: MINT-1
// Rule: XFER-3
// Rule: RED-1
// Rule: SNAP
#[test]
fn totality_every_lookup_misses() {
    // An empty view at H = START_HEIGHT: a MINT, a REDEEM naming a non-existent vault and a
    // TRANSFER of unknown tokens all get verdicts and nothing panics; the mint (refHeight not below
    // H) is invalid (U-21), the rest is not.
    let p = regtest_params(1, 0, 0, test_set().0);
    let view = YedState::new();
    let k = pubkey(&det_secret("totality", 0));
    let owner = test_pq_owner(&k);
    let mut mint = MTx::default();
    mint.vin.push(txin(op(u256s("11"), 0)));
    mint.vout.push(txout(
        1_000_000_000_000,
        yed_vault_script(&p, &owner, 1).unwrap(),
    ));
    mint.vout.push(txout(TOKEN_VALUE, p2pkh_of(&k)));
    mint.vout.push(payload_out(&Payload::mint(
        0,
        10000,
        49,
        1,
        &owner,
        FEE_VOUT_NONE,
        FEE_VOUT_NONE,
    )));
    let mut redeem = MTx::default();
    let mut sig = vec![0x00, 0x05];
    sig.extend([1u8; 5]);
    redeem.vin.push(VaultTxIn {
        prevout: op(u256s("22"), 0),
        script_sig: sig,
    });
    redeem.vout.push(txout(1, p2pkh_of(&k)));
    redeem.vout.push(payload_out(&Payload::redeem(
        1,
        0,
        Vec::new(),
        FEE_VOUT_NONE,
    )));
    let mut xfer = MTx::default();
    xfer.vin.push(txin(op(u256s("33"), 0)));
    xfer.vout.push(txout(TOKEN_VALUE, p2pkh_of(&k)));
    xfer.vout
        .push(payload_out(&transfer_payload(&[Assignment::new(0, 100)])));
    let empty = MTx::default(); // no inputs, no outputs
    let block: Vec<VaultTx> = vec![
        Fixture::coinbase(1, None).tx(),
        mint.tx(),
        redeem.tx(),
        xfer.tx(),
        empty.tx(),
    ];
    let ev = evaluate_block(&view, &p, &block, 1, &u256s("aa"), SUBSIDY, None);
    assert!(ev.block_invalid);
    assert_eq!(ev.txlogs.len(), 1); // the evaluation stops at the invalid mint
    assert_eq!(ev.txlogs[0].1.verdict, "bad-mint-ref-height"); // refHeight 1 is not <= H - 1 = 0
    assert_eq!(ev.verdict, "bad-mint-ref-height");
    // Without the mint the block is valid and nothing touched the state.
    let mut rest = block.clone();
    rest.remove(1);
    let ev = evaluate_block(&view, &p, &rest, 1, &u256s("aa"), SUBSIDY, None);
    assert!(!ev.block_invalid);
    assert!(ev.txlogs.is_empty());
    assert_eq!(ev.snapshot.halt_mask, HALT_NO_PRICE);
    // A missing Snapshots[H - 1] above START_HEIGHT (a hole) is "undefined": the mint still invalid.
    let ev = evaluate_block(&view, &p, &block, 500, &u256s("bb"), SUBSIDY, None);
    assert!(ev.block_invalid);
    assert_eq!(ev.txlogs.len(), 1);
    assert_eq!(ev.txlogs[0].1.verdict, "bad-mint-ref-height");
    // ProcessTx on a lone state with no Totals/Activation records.
    let bare = YedState::new();
    let _ = process_tx(&bare, &p, &redeem.tx(), 7, None);
    let _ = process_tx(&bare, &p, &mint.tx(), 7, None);
    assert!(default_payee(&bare, &p, 7, &[], &PayeePolicy::defaults(&p)).is_none());
}

// Rule: SNAP
// Rule: MINT-4
#[test]
fn virtual_snapshot_below_start_height() {
    let mut f = Fixture::with(50, 0, 0, 3);
    let v = snapshot_at(&f.state, &f.p, 49).unwrap();
    assert_eq!(v.halt_mask, HALT_NOT_ACTIVE | HALT_NO_PRICE);
    assert!(v.pfast().is_none() && v.pmint().is_none() && v.pclaim().is_none());
    assert_eq!(v.issued_zat, 0);
    // Blocks below START_HEIGHT are ignored completely.
    let below = f.mine_at(Some(Fixture::quote(50000, 0)), Vec::new(), 49);
    assert!(f.state.entries.is_empty());
    assert!(!below.block_invalid && below.txlogs.is_empty());
    // At H = START_HEIGHT: the tag counts, issuedZat starts from 0, MINT-4 is false.
    let at = f.mine_at(Some(Fixture::quote(50000, 0)), Vec::new(), 50);
    assert!(!at.block_invalid);
    assert_eq!(f.snap(50).issued_zat, SUBSIDY);
    assert!(f.snap(50).tagged);
    assert!(f.state.snapshot(49).is_none());
    let o = MintOpts {
        collateral: 1_000_000_000_000,
        fee_key: 0,
        ..MintOpts::default()
    };
    let m = f.mint_tx(10000, 48, 50, o.clone());
    assert_eq!(mv(&mut f, &m), "mint-halted-no-price"); // active from START (U-22), no price yet
    let m = f.mint_tx(10000, 48, 49, o);
    assert_eq!(mv(&mut f, &m), "bad-mint-ref-height");
}

// Rule: SNAP
#[test]
fn snapshot_undefined_price_is_zero() {
    let mut f = Fixture::new();
    f.mine(Some(Fixture::quote(50000, 0)), Vec::new());
    let s = f.snap(1);
    assert_eq!(s.p_fast, 0);
    assert_eq!(s.p_mint, 0);
    assert_eq!(s.p_claim, 0);
    assert_eq!(s.global_ratio_bps, 0);
    assert!(s.pfast().is_none());
    // The stored bytes carry the zeros, and the hash covers them.
    assert!(f.state.get(&YedKey::Snapshot(1)).is_some());
    let h1 = hash_hex(&f.state);
    let mut t = s.clone();
    t.p_fast = 1;
    f.put(YedKey::Snapshot(1), YedRecord::Snapshot(Box::new(t)));
    assert_ne!(hash_hex(&f.state), h1);
    assert_eq!(halt_mask_names(s.halt_mask)[0], "NO_PRICE");
}

// Rule: SNAP
#[test]
fn snap_written_for_every_height_ge_start() {
    let mut f = Fixture::with(5, 0, 0, 3);
    f.mine_at(None, Vec::new(), 3);
    f.mine_at(None, Vec::new(), 4);
    assert!(f.state.entries.is_empty());
    for h in 5..=40i64 {
        let t = if h % 4 == 0 {
            None
        } else {
            Some(Fixture::quote(50000, h % 3))
        };
        f.mine(t, Vec::new());
    }
    for h in 5..=40u32 {
        let s = f.state.snapshot(h).unwrap();
        assert_eq!(s.block_hash, fake_hash(i64::from(h)));
        assert_eq!(s.issued_zat, i64::from(h - 4) * SUBSIDY);
    }
    assert!(f.state.snapshot(4).is_none());
    assert_eq!(f.state.params_record().unwrap().start_height, 5);
    let tip = f.state.tip().unwrap();
    assert_eq!(tip.height, 40);
    assert_eq!(tip.schema_version, SCHEMA_VERSION);
    assert_eq!(tip.network, "regtest");
}

// Rule: SNAP
#[test]
fn params_selected_by_height() {
    // Two regtest sets: the second starts at 100 with a supply cap; EvaluateBlock reads the set
    // SelectParams picks.
    let mut f = Fixture::new();
    let sets: Vec<Params> = vec![
        regtest_params(1, 0, 0, f.p.attestor_set_id),
        regtest_params(100, 0, 1, f.p.attestor_set_id),
    ];
    let sel = |h: i32| select_params(&sets, h).unwrap().start_height;
    assert_eq!(sel(1), 1);
    assert_eq!(sel(99), 1);
    assert_eq!(sel(100), 100);
    assert_eq!(sel(5000), 100);
    assert_eq!(sel(0), 1); // none qualifies: the first set
    f.activate(50000);
    // A mint under the first set passes; the same mint under the second set hits its supply cap
    // (class A, lock 48: below the W20/IT-5 recapitalisation floor, so the cap is hard for it).
    let r = f.tip - 1;
    let m = f.mint_tx(10000, 48, r, MintOpts::default());
    let h = f.tip + 1;
    let block = vec![
        Fixture::coinbase(h, Some(&Fixture::quote(50000, 0))).tx(),
        m.tx(),
    ];
    let e1 = evaluate_block(
        &f.state,
        select_params(&sets, 99).unwrap(),
        &block,
        h,
        &fake_hash(h),
        SUBSIDY,
        None,
    );
    let e2 = evaluate_block(
        &f.state,
        select_params(&sets, i32::try_from(h).unwrap()).unwrap(),
        &block,
        h,
        &fake_hash(h),
        SUBSIDY,
        None,
    );
    assert_eq!(e1.txlogs.len(), 1);
    assert_eq!(e2.txlogs.len(), 1);
    assert_eq!(e1.txlogs[0].1.verdict, verdict::OK);
    assert_eq!(e2.txlogs[0].1.verdict, "mint-supply-cap");
}

/// `BenchBudgetScale` (`test/yellowback_bench.h`): `YELLOWBACK_BENCH_SCALE=<n>` overrides; an
/// unoptimised build (the C++ instrumented build) scales the budget by 10.
fn bench_budget_scale() -> u128 {
    if let Some(n) = std::env::var("YELLOWBACK_BENCH_SCALE")
        .ok()
        .and_then(|s| s.parse::<u128>().ok())
        .filter(|n| *n > 0)
    {
        return n;
    }
    if cfg!(debug_assertions) {
        10
    } else {
        1
    }
}

/// The network serialisation size of a v4 transaction with only transparent parts.
fn ser_size(m: &MTx) -> usize {
    let compact = |n: usize| if n < 253 { 1 } else { 3 };
    let mut s = 4 + 4 + compact(m.vin.len()) + compact(m.vout.len()) + 4 + 4 + 8 + 3;
    for i in &m.vin {
        s += 36 + compact(i.script_sig.len()) + i.script_sig.len() + 4;
    }
    for o in &m.vout {
        s += 8 + compact(o.script_pubkey.len()) + o.script_pubkey.len();
    }
    s
}

// Rule: SNAP
#[test]
#[allow(clippy::disallowed_types)] // a wall-clock budget in a test, never in the module
fn mempoolcheck_bench() {
    // N6: a 2 MB block of OP_RETURN-carrying transactions through EvaluateBlock in < 200 ms, and
    // 10,000 plain transactions through the mempool check in < 1 s.
    let mut f = Fixture::new();
    f.activate(50000);
    let h = f.tip + 1;
    let mut block = vec![Fixture::coinbase(h, Some(&Fixture::quote(50000, 0))).tx()];
    let mut bytes = 0usize;
    let mut i = 0;
    while bytes < 2_000_000 {
        let mut m = MTx::default();
        let fi = f.fake_input();
        m.vin.push(txin(fi));
        m.vout.push(txout(1000, f.user_p2pkh()));
        let data = match i % 3 {
            // a REDEEM of nothing: XFER-3 (a failing mint is invalid since U-21)
            0 => encode_payload(&Payload::redeem(
                u32::try_from(f.tip - 1).unwrap(),
                FEE_VOUT_NONE,
                Vec::new(),
                FEE_VOUT_NONE,
            ))
            .unwrap(),
            // XFER-3 fails
            1 => encode_payload(&transfer_payload(&[Assignment::new(0, 100)])).unwrap(),
            // non-Yellowback
            _ => vec![0x42u8; 80],
        };
        m.vout.push(txout(0, payload_script(&data)));
        bytes += ser_size(&m);
        block.push(m.tx());
        i += 1;
    }
    let t0 = std::time::Instant::now();
    let ev = evaluate_block(&f.state, &f.p, &block, h, &fake_hash(h), SUBSIDY, None);
    let elapsed = t0.elapsed().as_micros();
    println!(
        "EvaluateBlock over {} transactions ({bytes} bytes): {elapsed} us",
        block.len()
    );
    assert!(!ev.block_invalid);
    assert!(ev.txlogs.is_empty()); // nothing created or spent: no TxLog entry (N7)
    let budget = 200_000 * bench_budget_scale();
    assert!(
        elapsed < budget,
        "EvaluateBlock took {elapsed} us (budget {budget} us)"
    );
    // The mempool half: plain transactions (no payload, no YED input or output) are irrelevant.
    let plain: Vec<VaultTx> = (0..10_000)
        .map(|_| {
            let fi = f.fake_input();
            MTx {
                vin: vec![txin(fi)],
                vout: vec![VaultTxOut {
                    value: 1000,
                    script_pubkey: f.user_p2pkh(),
                }],
                lock_time: 0,
            }
            .tx()
        })
        .collect();
    let t0 = std::time::Instant::now();
    for tx in &plain {
        assert!(mempool_check_reason(&f.state, &f.p, h, tx, 0, None).is_none());
    }
    let elapsed = t0.elapsed().as_micros();
    let budget = 1_000_000 * bench_budget_scale();
    assert!(
        elapsed < budget,
        "MempoolCheck took {elapsed} us (budget {budget} us)"
    );
}

// ===========================================================================
// HALT-2 reads open debt (owner 2026-10-28): Totals.openDebtCents, the mintedCents of every
// ACTIVE and CLAIMING vault, and the invariant supply <= open debt

/// `CScript() << valtype(65, 0) << OP_<sel>`: the cancel's placeholder set signature and selector.
fn set_sig(sel: u8) -> Vec<u8> {
    let mut s = vec![65u8];
    s.extend([0u8; 65]);
    s.push(0x50 + sel);
    s
}

/// `RelockOf`: the V script of the YED position at `pos`, carrying `value`.
fn relock_of(f: &Fixture, pos: &OutPoint, value: i64) -> VaultTxOut {
    let r = f.state.vault(pos).unwrap();
    txout(
        value,
        yed_vault_script_at(
            &f.p,
            &r.owner(),
            i64::from(r.owner_height),
            i64::from(r.app_height),
        )
        .unwrap(),
    )
}

fn check(f: &Fixture, supply: i64, debt: i64, step: &str) {
    let t = f.totals();
    assert_eq!(t.supply_cents, supply, "{step}: supplyCents");
    assert_eq!(t.open_debt_cents, debt, "{step}: openDebtCents");
    assert!(t.supply_cents <= t.open_debt_cents, "{step}");
    let bad = open_debt_invariant_violation(&f.state);
    assert!(bad.is_none(), "{step}: {bad:?}");
    assert_eq!(f.snap(f.tip).open_debt_cents, debt, "{step}"); // the snapshot carries the denominator
    assert_eq!(f.snap(f.tip).supply_cents, supply, "{step}");
}

// Rule: HALT-2
// Rule: IT-6
// Rule: RED-2
// Rule: CAN-1
// Rule: UNDO
#[test]
fn halt2_open_debt_totals_invariant_and_undo() {
    // ATTEST_ARM_MIN 10: the four members never arm the chain, so the claims stay unarmed
    let mut f = Fixture::with(1, 0, 0, 10);
    f.activate(50000);
    f.register(4, 0); // CAN-2: a member to co-sign the cancel
    let base = f.tip;
    let before = f.state.clone();
    assert!(open_debt_invariant_violation(&f.state).is_none());
    // MINT: both totals rise by the debt
    let a = f.mint_active(10000, 48, 0);
    check(&f, 10000, 10000, "mint a");
    let b = f.mint_active(10000, 48, 0);
    let c = f.mint_active(10000, 48, 0);
    check(&f, 30000, 30000, "mint b, c");
    // RED-2 over-burn: a's owner burns 15,000 (a's token and b's) for a 10,000 debt and keeps
    // 5,000; open debt falls by a's mintedCents only, supply by the whole burn
    let redeem = f.spend_tx(
        &a,
        &[op(a, 1), op(b, 1)],
        f.tip,
        SpendOpts {
            assigned: vec![Assignment::new(3, 5000)],
            ..SpendOpts::default()
        },
    );
    assert_eq!(spend(&mut f, &a, &redeem).verdict, verdict::OK);
    assert_eq!(f.vault(&a).unwrap().status, VaultStatus::Closed);
    check(&f, 15000, 20000, "over-burn redeem");
    // a failed transfer (XFER-2, the cenotaph rule): the whole input burns, the debt stays open
    let xfer = f.transfer_tx(
        &[op(redeem.txid(), 3)],
        &[Assignment::new(0, 6000)],
        false,
        0,
    );
    let t = q(&f, 50000);
    f.mine(t, vec![xfer.clone()]);
    assert_eq!(
        f.log(&xfer.txid()).unwrap().verdict,
        "transfer-over-assigned"
    );
    check(&f, 10000, 20000, "cenotaph");
    // the pools fall to $0.009: b (stranded: its YED is gone) and c are under theta
    for _ in 0..64 {
        let t = q(&f, 9000);
        f.mine(t, Vec::new());
    }
    let each = f.vault(&c).unwrap().collateral_zat;
    // CLAIM: the burn leaves supply, the debt stays open with the CLAIMING collateral (IT-6)
    let co = SpendOpts {
        owner_path: false,
        ..SpendOpts::default()
    };
    let claim_ref = f.tip;
    let claim = f.spend_tx(&c, &[op(c, 1)], claim_ref, co.clone());
    assert_eq!(spend(&mut f, &c, &claim).verdict, verdict::OK);
    assert_eq!(f.vault(&c).unwrap().status, VaultStatus::Claiming);
    check(&f, 0, 20000, "claim");
    // HALT-2 divides by open debt: with no supply left the ratio is still defined and halts
    let after_claim = f.snap(f.tip);
    assert_eq!(
        after_claim.global_ratio(),
        global_ratio_bps(f.totals().collateral_zat, after_claim.pmint(), 20000)
    );
    assert!(after_claim.global_ratio().is_some());
    assert!(global_ratio_bps(
        f.totals().collateral_zat,
        after_claim.pmint(),
        after_claim.supply_cents
    )
    .is_none());
    assert!(after_claim.halt_mask & HALT_GLOBAL_RATIO != 0);
    // CANCEL (CAN-1): the refund re-credits supply, the re-created vault carries the same open debt
    let intent = op(claim.txid(), 0);
    let mut cancel = MTx::default();
    cancel.vin.push(VaultTxIn {
        prevout: intent,
        script_sig: set_sig(2),
    });
    let fi = f.fake_input();
    cancel.vin.push(txin(fi));
    cancel.vout.push(relock_of(&f, &op(c, 0), each));
    cancel
        .vout
        .push(txout(TOKEN_VALUE, p2pkh_of(&f.owner_pub())));
    let cos = encode_cancel_cosigns(&[f.cosign(0, 50000, &intent, claim_ref, None)]).unwrap();
    let ci = f.carrier_in(&cos);
    cancel.vin.push(ci);
    cancel.vout.push(payload_out(&Payload::CancelCosign));
    let t = q(&f, 9000);
    f.mine(t, vec![cancel.clone()]);
    assert_eq!(f.refused_verdict(&cancel.txid()), "");
    let reopened = cancel.txid();
    assert_eq!(f.vault(&reopened).unwrap().status, VaultStatus::Active);
    check(&f, 10000, 20000, "cancel");
    // CLAIM again with the refund, then RELEASE after CLAIM_DELAY: the debt closes with the collateral
    let reclaim_ref = f.tip;
    let reclaim = f.spend_tx(&reopened, &[op(reopened, 1)], reclaim_ref, co);
    assert_eq!(spend(&mut f, &reopened, &reclaim).verdict, verdict::OK);
    check(&f, 0, 20000, "reclaim");
    let fi = f.fake_input();
    let rel = MTx {
        vin: vec![
            VaultTxIn {
                prevout: op(reclaim.txid(), 0),
                script_sig: vec![0x51], // OP_1
            },
            txin(fi),
        ],
        vout: vec![txout(each, f.user_p2pkh())],
        lock_time: 0,
    };
    let t = q(&f, 9000);
    f.mine(t, vec![rel.clone()]);
    assert_eq!(f.refused_verdict(&rel.txid()), "");
    assert_eq!(f.vault(&reopened).unwrap().status, VaultStatus::Claimed);
    check(&f, 0, 10000, "release"); // b's debt: open, its collateral stranded
                                    // UNDO: key-level, so the appended field rolls back with the record; undoing every block
                                    // restores the start byte for byte
    let at_end = f.totals();
    f.undo();
    check(&f, 0, 20000, "undo release");
    assert_ne!(f.totals().encode(), at_end.encode());
    while f.tip > base {
        f.undo();
    }
    assert!(f.state == before);
    assert_eq!(f.totals().open_debt_cents, 0);
    // the check reports a corrupt record (a consistency check, never a verdict)
    let mut t = f.totals();
    t.supply_cents = 1;
    t.open_debt_cents = 1;
    f.put(YedKey::Totals, YedRecord::Totals(t));
    assert!(open_debt_invariant_violation(&f.state).is_some()); // 1 open debt with no vault
    t.open_debt_cents = 0;
    f.put(YedKey::Totals, YedRecord::Totals(t));
    assert!(open_debt_invariant_violation(&f.state).is_some()); // supply above open debt
}
