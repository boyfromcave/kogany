// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

//! The claim cases of ycash6 `src/test/yellowback_state_tests.cpp` at `65cb4ae0f` (W5-d1): a
//! claim of an ACTIVE vault into claim intents (U-23) — RED-1's bundle, RED-4 (a) and (b) with
//! NOT-1's notices, RED-5 / 5a / 5b's residual intent — and the in-term (IT-*) cases that mint
//! and claim. The claimant intent's release here only completes a claim; the release rules are
//! W5-d2's.

mod state_common;

use kogany_vault::template::parse_vault;
use kogany_yellowback::attest::price::{HALT_DIVERGENCE, HALT_GLOBAL_RATIO};
use kogany_yellowback::codecs::script::{yed_vault_script, yed_vault_script_at};
use kogany_yellowback::math::{
    claimant_max_zat, global_ratio_bps, is_underwater, min_ratio_bps, required_collateral,
    residual_min_zat, residual_zat,
};
use kogany_yellowback::params::{main_params, regtest_params, COIN, MAX_MONEY, PRICE_MAX};
use kogany_yellowback::state::{
    eligible_payees, verdict, IntentRole, NoticeRecord, TxLogType, VaultStatus, YedKey, YedRead,
    YedRecord,
};
use state_common::fixture::*;

fn o() -> MintOpts {
    MintOpts::default()
}

fn claim_opts() -> SpendOpts {
    SpendOpts {
        owner_path: false,
        ..SpendOpts::default()
    }
}

fn ticks(f: &mut Fixture, n: usize, price: i64) {
    for _ in 0..n {
        let t = Fixture::quote(price, (f.tip + 1) % 3);
        f.mine(Some(t), Vec::new());
    }
}

/// A claimant intent's release (selector 1) paying `value` to the user.
fn release_tx(f: &mut Fixture, intent: kogany_vault::OutPoint, value: i64) -> MTx {
    let fi = f.fake_input();
    MTx {
        vin: vec![
            kogany_vault::state::VaultTxIn {
                prevout: intent,
                script_sig: vec![0x51], // OP_1
            },
            txin(fi),
        ],
        vout: vec![txout(value, f.user_p2pkh())],
        lock_time: 0,
    }
}

// Rule: RED-4
#[test]
fn red4_claim_path_underwater_at_r() {
    let mut f = Fixture::new();
    f.activate(50000);
    let v = f.mint_active10k();
    // Not underwater at $0.05: the claim is invalid (U-21); the vault stays ACTIVE.
    let tx = f.spend_tx(&v, &[op(v, 1)], f.tip, claim_opts());
    let r = spend(&mut f, &v, &tx);
    assert_eq!(r.verdict, "vault-claim-not-underwater");
    assert!(r.invalid);
    assert_eq!(r.log.path, "claim");
    assert_eq!(r.vault.status, VaultStatus::Active);
    // Crash to $0.009 for a whole slow window: 6,000 YEC backs $100 at 54% < 125%.
    let w = f.mint_active10k();
    ticks(&mut f, 64, 9000);
    assert_eq!(f.snap(f.tip).pclaim(), Some(9000));
    assert!(is_underwater(
        600_000_000_000,
        Some(9000),
        10000,
        f.p.claim_threshold_bps
    ));
    let claim = f.spend_tx(&w, &[op(w, 1)], f.tip, claim_opts());
    let r = spend(&mut f, &w, &claim);
    assert_eq!(r.verdict, verdict::OK);
    assert!(!r.invalid);
    // U-23: the claim leaves the vault CLAIMING; the release closes it.
    assert_eq!(r.vault.status, VaultStatus::Claiming);
    assert_eq!(f.totals().claimed_vaults, 0);
    assert_eq!(f.totals().active_vaults, 1); // v only
    let intent = op(claim.txid(), 0);
    assert!(f.state.intent(&intent).is_some());
    let rel = release_tx(&mut f, intent, 600_000_000_000);
    let t = Fixture::quote(9000, (f.tip + 1) % 3);
    f.mine(Some(t), vec![rel.clone()]);
    assert_eq!(f.refused_verdict(&rel.txid()), "");
    assert_eq!(f.vault(&w).unwrap().status, VaultStatus::Claimed);
    assert!(f.state.intent(&intent).is_none());
    assert_eq!(f.log(&rel.txid()).unwrap().tx_type, TxLogType::ClaimRelease);
    assert_eq!(f.totals().claimed_vaults, 1);
    assert_eq!(f.totals().closed_vaults, 0);
    // A vault minted at $0.009 is fully backed at that price, so the same claim fails (RED-4 reads R).
    ticks(&mut f, 1, 9000);
    let x = f.mint_active(10000, 145, 2); // class C under HALT-2 (IT-5)
    let tx = f.spend_tx(&x, &[op(x, 1)], f.tip, claim_opts());
    assert_eq!(spend(&mut f, &x, &tx).verdict, "vault-claim-not-underwater");
}

// Rule: RED-4
#[test]
fn red4_undefined_pclaim() {
    let mut f = Fixture::new();
    f.activate(50000);
    let v = f.mint_active10k();
    let w = f.mint_active10k();
    // Nine untagged blocks: the mid window drops below two-thirds fill => pClaim undefined.
    for _ in 0..9 {
        f.mine_empty();
    }
    assert!(f.snap(f.tip).pclaim().is_none());
    let r = f.tip;
    // E(R) still holds the keys quoted before the gap (PAYEE_WINDOW 10 > 9 untagged blocks).
    assert!(!eligible_payees(&f.state, &f.p, r).is_empty());
    let tx = f.spend_tx(
        &v,
        &[op(v, 1)],
        r,
        SpendOpts {
            fee_key: r % 3,
            ..claim_opts()
        },
    );
    let res = spend(&mut f, &v, &tx);
    assert_eq!(res.verdict, "vault-claim-not-underwater"); // undefined pClaim: not underwater (M1)
    assert!(res.invalid);
    // The owner path at the same R is unaffected.
    let tx = f.spend_tx(
        &w,
        &[op(w, 1)],
        r,
        SpendOpts {
            fee_key: r % 3,
            ..SpendOpts::default()
        },
    );
    assert_eq!(spend(&mut f, &w, &tx).verdict, verdict::OK);
}

// Rule: RED-1
// Rule: BUNDLE-1
#[test]
fn red1_claim_needs_bundle() {
    let mut f = Fixture::new();
    f.arm(3, 50000);
    let m = f.mint_v3(10000, 50000, o(), &none_skip(), 48);
    assert_eq!(mv(&mut f, &m), "");
    let v = m.txid();
    ticks(&mut f, 64, 9000);
    // No carrier: red1-bundle-shape.
    let tx = f.spend_tx(&v, &[op(v, 1)], f.tip - 1, claim_opts());
    let r = spend(&mut f, &v, &tx);
    assert_eq!(r.verdict, "red1-bundle-shape");
    assert!(r.invalid);
    assert_eq!(r.vault.status, VaultStatus::Active);
    // The claim's selection is selected(R, vaultOutpoint): an attestor outside it is "member".
    let mut g = Fixture::new();
    g.arm(4, 50000);
    let m2 = g.mint_v3(10000, 50000, o(), &none_skip(), 48);
    assert_eq!(mv(&mut g, &m2), "");
    let v2 = m2.txid();
    let r = g.tip - 1;
    let sel = vault_selector(&v2);
    let chosen = g.selected(r, &sel);
    assert_eq!(chosen.len(), 3);
    let outsider = (0u16..4).find(|q| !chosen.contains(q)).unwrap();
    let b = kogany_yellowback::attest::bundle::encode_bundle(
        &kogany_yellowback::attest::bundle::Bundle::of(vec![
            g.att(usize::from(chosen[0]), 50000, r, None),
            g.att(usize::from(outsider), 50000, r, None),
        ]),
    );
    let tx = g.spend_tx(
        &v2,
        &[op(v2, 1)],
        r,
        SpendOpts {
            bundle: Some(b),
            attest_payee: i64::from(chosen[0]),
            ..claim_opts()
        },
    );
    let res = spend(&mut g, &v2, &tx);
    assert_eq!(res.verdict, "red1-bundle-member");
    assert!(res.invalid);
}

// Rule: RED-4
// Rule: NOT-1
#[test]
fn red4b_needs_notice_and_persist() {
    let mut e = EmergencyFixture::new(64);
    // Without a notice, (b) is false: not underwater under pClaim = max(x, a).
    let c = e.claim(SpendOpts::default(), None);
    let r = e.mine(&c);
    assert_eq!(r.verdict, verdict::VAULT_CLAIM_NOT_UNDERWATER);
    assert!(r.invalid);
    let mut g = EmergencyFixture::new(64);
    assert!(g.post_notice(None));
    let n = g.f.notice(&g.w).unwrap();
    assert_eq!(i64::from(n.height), g.f.tip);
    assert_eq!(i64::from(n.ref_height), g.f.tip - 2); // the notice at H had refHeight H - 2
    assert_eq!(n.p_emerg, g.att_price);
    let first = g.f.evals[&g.f.tip].txlogs[0].0;
    assert_eq!(g.f.log(&first).unwrap().tx_type, TxLogType::ClaimNotice);
    assert!(g.f.log(&first).unwrap().notice);
    // R - notice.refHeight must reach EMERGENCY_PERSIST: the claim at R = refHeight + 3 is early.
    while g.f.tip - 1 < i64::from(n.ref_height) + i64::from(g.f.p.emergency_persist) - 1 {
        g.tick();
    }
    {
        let c = g.claim(SpendOpts::default(), None);
        let ev = g.dry(&[c]);
        assert!(ev.block_invalid);
        assert_eq!(ev.txlogs[0].1.verdict, verdict::VAULT_CLAIM_NOT_UNDERWATER);
    }
    g.tick();
    assert_eq!(
        g.f.tip - 1 - i64::from(n.ref_height),
        i64::from(g.f.p.emergency_persist)
    );
    let residual = g.residual(g.f.tip - 1);
    let c = g.claim(
        SpendOpts {
            residual_value: Some(residual),
            ..SpendOpts::default()
        },
        None,
    );
    let r = g.mine(&c);
    assert_eq!(r.verdict, verdict::OK);
    assert!(!r.invalid);
    assert_eq!(r.log.claim_path, "b");
    assert_eq!(r.vault.status, VaultStatus::Claiming);
    assert_eq!(r.log.a_claim, g.att_price);
}

// Rule: RED-4
// Rule: NOT-1
#[test]
fn red4b_notice_too_old() {
    let mut g = EmergencyFixture::new(64);
    assert!(g.post_notice(None));
    let n = g.f.notice(&g.w).unwrap();
    while g.f.tip - 1 <= i64::from(n.ref_height) + i64::from(g.f.p.emergency_notice_ttl) {
        g.tick();
    }
    let residual = g.residual(g.f.tip - 1);
    let c = g.claim(
        SpendOpts {
            residual_value: Some(residual),
            ..SpendOpts::default()
        },
        None,
    );
    let r = g.mine(&c);
    assert_eq!(r.verdict, verdict::VAULT_CLAIM_NOT_UNDERWATER);
    assert!(r.invalid);
}

// Rule: RED-4
// Rule: NOT-1
#[test]
fn red4b_before_arming_false() {
    let mut f = Fixture::new();
    f.activate(50000);
    let v = f.mint_active10k();
    ticks(&mut f, 64, 21000); // 6,000 YEC back $100 at 126 %: not (a)
                              // Unarmed: a notice registers nothing and a claim is judged by (a) alone.
    let n = f.notice_tx(&v, f.tip - 1, &[0x59; 4]);
    let t = Fixture::quote(21000, (f.tip + 1) % 3);
    f.mine(Some(t), vec![n]);
    assert!(f.notice(&v).is_none());
    assert!(f.evals[&f.tip].txlogs.is_empty());
    // Force a notice record in and see (b) still false before arming.
    let rec = NoticeRecord {
        height: i32::try_from(f.tip - 6).unwrap(),
        ref_height: i32::try_from(f.tip - 8).unwrap(),
        p_emerg: 17000,
    };
    f.put(YedKey::Notice(op(v, 0)), YedRecord::Notice(rec));
    let tx = f.spend_tx(&v, &[op(v, 1)], f.tip - 1, claim_opts());
    let ev = f.evaluate(Some(Fixture::quote(21000, (f.tip + 1) % 3)), &[tx], None);
    assert!(ev.block_invalid);
    assert_eq!(ev.txlogs[0].1.verdict, verdict::VAULT_CLAIM_NOT_UNDERWATER);
    assert!(f.notice(&v).is_some()); // U-21: the invalid claim is never applied
}

fn emergency_persisted() -> EmergencyFixture {
    let mut g = EmergencyFixture::new(64);
    assert!(g.post_notice(None));
    for _ in 0..=g.f.p.emergency_persist {
        g.tick();
    }
    g
}

// Rule: RED-5
#[test]
fn red5_residual_paid() {
    let mut g = emergency_persisted();
    let residual = g.residual(g.f.tip - 1);
    assert!(residual >= g.f.p.residual_min_zat);
    assert_eq!(
        residual,
        EmergencyFixture::COLLATERAL - claimant_max_zat(10000, 10000, g.att_price).unwrap()
    );
    // Missing residual output: invalid. One zat short: invalid. Exact: ok.
    {
        let a = g.claim(SpendOpts::default(), None);
        let b = g.claim(
            SpendOpts {
                residual_value: Some(residual - 1),
                ..SpendOpts::default()
            },
            None,
        );
        let ev = g.dry(&[a, b]);
        assert_eq!(ev.txlogs[0].1.verdict, verdict::RED5_RESIDUAL);
        assert_eq!(ev.txlogs[0].1.residual_zat, residual);
    }
    {
        let b = g.claim(
            SpendOpts {
                residual_value: Some(residual - 1),
                ..SpendOpts::default()
            },
            None,
        );
        let ev = g.dry(&[b]);
        assert_eq!(ev.txlogs[0].1.verdict, verdict::RED5_RESIDUAL);
    }
    let c = g.claim(
        SpendOpts {
            residual_value: Some(residual),
            ..SpendOpts::default()
        },
        None,
    );
    let r = g.mine(&c);
    assert_eq!(r.verdict, verdict::OK);
    assert_eq!(r.log.residual_zat, residual);
    assert_eq!(r.log.claim_path, "b");
    assert!(r.log.has_attest_payee);
    assert!(
        r.log.attest_fee_zat
            >= kogany_yellowback::math::attest_fee_zat(
                g.f.vault_fee(&r.vault),
                g.f.p.attest_fee_bps
            )
    );
}

// Rule: RED-5
#[test]
fn red5_residual_below_dust_vacuous() {
    let mut g = EmergencyFixture::new(64);
    g.f.p.residual_min_zat = MAX_MONEY;
    assert!(g.post_notice(None));
    for _ in 0..=g.f.p.emergency_persist {
        g.tick();
    }
    let residual = g.residual(g.f.tip - 1);
    let c = g.claim(SpendOpts::default(), None);
    let r = g.mine(&c);
    assert_eq!(r.verdict, verdict::OK);
    assert_eq!(r.log.residual_zat, residual);
    assert!(residual < g.f.p.residual_min_zat);
    // and the math: a residual under the floor needs no output
    let cm = claimant_max_zat(10000, 10000, 11500);
    assert_eq!(residual_zat(cm.unwrap() + 50000, cm), 50000);
    assert!(50000 < regtest_params(1, 0, 0, test_set().0).residual_min_zat);
}

// Rule: RED-5
#[test]
fn red5_residual_to_wrong_key_invalid() {
    let mut g = emergency_persisted();
    let residual = g.residual(g.f.tip - 1);
    let s = g.f.user_p2pkh();
    let c = g.claim(
        SpendOpts {
            residual_value: Some(residual),
            residual_script: Some(s),
            ..SpendOpts::default()
        },
        None,
    );
    let r = g.mine(&c);
    assert_eq!(r.verdict, verdict::RED5_RESIDUAL);
    assert!(r.invalid);
    assert_eq!(r.vault.status, VaultStatus::Active);
}

// Rule: RED-5
// Rule: RED-5a
#[test]
fn red5a_roles_are_positional_and_the_claimant_is_floored() {
    let mut g = emergency_persisted();
    let residual = g.residual(g.f.tip - 1);
    let collateral = EmergencyFixture::COLLATERAL;
    let floor = collateral - residual;
    let verdict_of = |g: &EmergencyFixture, tx: &MTx| {
        let ev = g.dry(std::slice::from_ref(tx));
        assert!(!ev.txlogs.is_empty());
        ev.txlogs[0].1.verdict.clone()
    };
    let honest = g.claim(
        SpendOpts {
            residual_value: Some(residual),
            ..SpendOpts::default()
        },
        None,
    );
    assert_eq!(verdict_of(&g, &honest), verdict::OK); // claimant first, residual second
    let last = honest.vout.len() - 1;
    {
        let mut self_pay = honest.clone(); // the claimant may still pay the owner
        self_pay.vout[0].script_pubkey = self_pay.vout[last].script_pubkey.clone();
        assert_eq!(verdict_of(&g, &self_pay), verdict::OK);
    }
    {
        let mut tiny = honest.clone(); // residual = the whole collateral, 1-zat claimant
        tiny.vout[0].value = 1;
        tiny.vout[last].value = collateral;
        assert_eq!(verdict_of(&g, &tiny), verdict::RED5_CLAIMANT_SHORT);
    }
    {
        let mut short = honest.clone(); // one zat under collateral − residual
        short.vout[0].value = floor - 1;
        assert_eq!(verdict_of(&g, &short), verdict::RED5_CLAIMANT_SHORT);
    }
    {
        let mut swapped = honest.clone(); // residual first
        swapped.vout.swap(0, last);
        assert_eq!(verdict_of(&g, &swapped), verdict::RED5_RESIDUAL);
    }
    {
        let mut big_first = honest.clone(); // big owner intent first, 1-zat intent second
        big_first.vout[0].script_pubkey = big_first.vout[last].script_pubkey.clone();
        big_first.vout[0].value = collateral - 1;
        big_first.vout[last].value = 1;
        assert_eq!(verdict_of(&g, &big_first), verdict::RED5_RESIDUAL);
    }
}

// Rule: RED-5
// Rule: RED-5b
#[test]
fn red5b_path_b_caps_at_p_emerg() {
    // Worked example (W3-Y-5, A1): D = $100,000, 300,000 YEC, pEmerg = $0.349, pClaim = $0.42.
    let debt = 10_000_000;
    let collateral = 300_000 * COIN;
    let p_emerg = 349_000;
    let residual = residual_zat(collateral, claimant_max_zat(debt, 10000, p_emerg));
    assert_eq!(residual, 1_346_704_871_060); // 13,467.04871060 YEC
    let close = 380_000;
    assert!(is_underwater(collateral, Some(p_emerg), debt, 10500));
    assert!(is_underwater(collateral, Some(close), debt, 12500));
    assert_eq!(
        residual_zat(collateral, claimant_max_zat(debt, 12500, close)),
        0
    );
    let g = emergency_persisted();
    let at_emerg = residual_zat(
        EmergencyFixture::COLLATERAL,
        claimant_max_zat(10000, 10000, g.att_price),
    );
    let at_claim = residual_zat(
        EmergencyFixture::COLLATERAL,
        claimant_max_zat(10000, 10000, g.pool_price),
    );
    assert!(at_emerg < at_claim);
    assert_eq!(g.residual(g.f.tip - 1), at_emerg);
}

// Rule: RED-5
// Rule: RED-4
#[test]
fn red5_normal_claim_residual_zero() {
    let mut f = Fixture::new();
    f.arm(3, 50000);
    let m = f.mint_v3(10000, 50000, o(), &none_skip(), 48);
    assert_eq!(mv(&mut f, &m), "");
    let v = m.txid();
    ticks(&mut f, 64, 9000);
    let sel = vault_selector(&v);
    let r = f.tip - 1;
    let b = f.bundle_simple(r, &sel, 9000);
    let payee = f.selected(r, &sel)[0];
    let tx = f.spend_tx(
        &v,
        &[op(v, 1)],
        r,
        SpendOpts {
            bundle: Some(b),
            attest_payee: i64::from(payee),
            ..claim_opts()
        },
    );
    let res = spend(&mut f, &v, &tx);
    assert_eq!(res.verdict, verdict::OK);
    assert_eq!(res.log.claim_path, "a");
    assert_eq!(res.log.residual_zat, 0);
    assert_eq!(res.vault.status, VaultStatus::Claiming);
    assert_eq!(f.bundle_row(f.tip).unwrap().a_claim, 9000);
}

// Rule: RED-5'
#[test]
fn red5_residual_threshold_at_p_mint() {
    let mut f = Fixture::new();
    f.activate(1_000_000); // $1/YEC: the threshold is 0.48 YEC
    assert_eq!(residual_min_zat(1_000_000, &f.p), 48_000_000);
    assert_eq!(residual_min_zat(PRICE_MAX, &f.p), f.p.residual_min_zat);
}

// Rule: NOT-1
#[test]
fn not1_standing_notice_not_replaced() {
    let mut g = EmergencyFixture::new(64);
    assert!(g.post_notice(None));
    let first = g.f.notice(&g.w).unwrap();
    // The reset attack: a second notice inside EMERGENCY_NOTICE_TTL registers nothing.
    for _ in 0..3 {
        g.tick();
    }
    let r2 = g.f.tip - 1;
    let b = g.f.bundle_simple(r2, &g.selector(), g.att_price);
    let w = g.w;
    let second = g.f.notice_tx(&w, r2, &b);
    let t = g.quote();
    g.f.mine(t, vec![second.clone()]);
    assert!(g.f.evals[&g.f.tip].txlogs.is_empty());
    let again = g.f.notice(&g.w).unwrap();
    assert_eq!(again.height, first.height);
    assert_eq!(again.ref_height, first.ref_height);
    // the unheld notice would refresh its signers' liveness, so it is invalid (liveness-unheld)
    assert_eq!(
        g.f.refused_verdict(&second.txid()),
        verdict::LIVENESS_UNHELD
    );
    assert!(g.f.bundle_row(g.f.tip).is_none());
    // Past the TTL a new notice replaces it.
    while g.f.tip + 1 - i64::from(first.height) <= i64::from(g.f.p.emergency_notice_ttl) {
        g.tick();
    }
    assert!(g.post_notice(None));
    assert_eq!(i64::from(g.f.notice(&g.w).unwrap().height), g.f.tip);
    // NOT-1's other clauses: pEmerg not under the emergency ratio, unknown vault
    assert!(g.post_notice(Some(11600)));
    assert!(g.f.evals[&g.f.tip].txlogs.is_empty());
    let unknown = u256s("11");
    let r = g.f.tip - 1;
    let b = g.f.bundle_simple(r, &vault_selector(&unknown), g.att_price);
    let n = g.f.notice_tx(&unknown, r, &b);
    let t = g.quote();
    g.f.mine(t, vec![n]);
    assert!(g.f.evals[&g.f.tip].txlogs.is_empty());
}

// Rule: IT-1
#[test]
fn in_term_vault_app_height_is_mint_height() {
    let mut f = Fixture::new();
    f.activate(50000);
    let v = f.mint_active10k();
    let r = f.vault(&v).unwrap();
    assert_eq!(r.app_height, r.ref_height + 1);
    assert_eq!(r.owner_height, r.ref_height + 1);
    assert_eq!(r.claim_height, r.lock_height + f.p.grace);
    let (oh, ah) = (i64::from(r.owner_height), i64::from(r.app_height));
    let vp = parse_vault(&yed_vault_script_at(&f.p, &r.owner(), oh, ah).unwrap()).unwrap();
    assert_eq!(vp.app_height, i64::from(r.ref_height) + 1);
    assert_eq!(vp.owner_height, i64::from(r.ref_height) + 1);
    let rh = i64::from(r.ref_height);
    assert_eq!(
        yed_vault_script(&f.p, &r.owner(), rh),
        yed_vault_script_at(&f.p, &r.owner(), rh + 1, rh + 1)
    );
}

// Rule: IT-1
// Rule: MINT-3
#[test]
fn in_term_old_shape_vault_spendable_but_not_mintable() {
    let mut f = Fixture::new();
    f.activate(50000);
    // A new mint carrying the pre-plan V (appHeight = lockHeight + GRACE) is refused.
    let lock = f.tip - 1 + 48;
    let s = yed_vault_script_at(
        &f.p,
        &test_pq_owner(&f.owner_pub()),
        lock,
        lock + i64::from(f.p.grace),
    );
    let m = f.mint_tx(
        10000,
        48,
        f.tip - 1,
        MintOpts {
            vault_script_override: s,
            ..o()
        },
    );
    assert_eq!(mv(&mut f, &m), "bad-mint-vault-script");
    // A vault minted before the plan still spends: owner path ...
    let v = f.mint_active10k();
    let old_shape = |f: &mut Fixture, id: &kogany_vault::Hash32| {
        let mut r = f.vault(id).unwrap();
        r.app_height = r.claim_height;
        r.owner_height = r.lock_height;
        f.put(YedKey::Vault(op(*id, 0)), YedRecord::Vault(Box::new(r)));
    };
    old_shape(&mut f, &v);
    assert_eq!(
        f.vault(&v).unwrap().app_height,
        f.vault(&v).unwrap().claim_height
    );
    let tx = f.spend_tx(&v, &[op(v, 1)], f.tip, SpendOpts::default());
    assert_eq!(
        i64::from(tx.lock_time),
        i64::from(f.vault(&v).unwrap().lock_height)
    ); // the pre-plan owner CLTV
    let r = spend(&mut f, &v, &tx);
    assert_eq!(r.verdict, verdict::OK);
    assert_eq!(r.vault.status, VaultStatus::Closed);
    // ... and the claim path, whose intents commit to the V as minted.
    let w = f.mint_active10k();
    old_shape(&mut f, &w);
    ticks(&mut f, 64, 9000);
    let claim = f.spend_tx(&w, &[op(w, 1)], f.tip, claim_opts());
    assert_eq!(
        i64::from(claim.lock_time),
        i64::from(f.vault(&w).unwrap().claim_height)
    );
    let r = spend(&mut f, &w, &claim);
    assert_eq!(r.verdict, verdict::OK);
    assert_eq!(r.vault.status, VaultStatus::Claiming);
}

// Rule: IT-2
// Rule: RED-4
#[test]
fn in_term_claim_valid_at_theta_invalid_above() {
    let mut f = Fixture::new();
    f.activate(50000);
    let v = f.mint_active10k(); // 6,000 YEC back $100 at 300 %; lock = ref + 48
    let rec = f.vault(&v).unwrap();
    assert!(f.tip < i64::from(rec.lock_height));
    let tx = f.spend_tx(&v, &[op(v, 1)], f.tip, claim_opts());
    let r = spend(&mut f, &v, &tx);
    assert_eq!(r.verdict, verdict::VAULT_CLAIM_NOT_UNDERWATER);
    assert!(r.invalid);
    assert_eq!(r.vault.status, VaultStatus::Active);
    // Still in term, just above theta: 6,000 YEC at 21,000 uUSD = $126 >= $125: invalid.
    ticks(&mut f, 34, 21000);
    assert!(f.tip < i64::from(rec.lock_height));
    assert_eq!(f.snap(f.tip).pclaim(), Some(21000));
    assert!(!is_underwater(
        rec.collateral_zat,
        Some(21000),
        rec.minted_cents,
        f.p.claim_threshold_bps
    ));
    let tx = f.spend_tx(&v, &[op(v, 1)], f.tip, claim_opts());
    let r = spend(&mut f, &v, &tx);
    assert_eq!(r.verdict, verdict::VAULT_CLAIM_NOT_UNDERWATER);
    assert!(r.invalid);
    // One tick under theta in term: $124.8 < $125: the claim is valid (path (a)).
    let w = f.mint_active(10000, 145, 2); // minted at 21,000
    ticks(&mut f, 34, 20800);
    assert!(f.tip < i64::from(rec.lock_height) + 48);
    assert_eq!(f.snap(f.tip).pclaim(), Some(20800));
    assert!(is_underwater(
        rec.collateral_zat,
        Some(20800),
        rec.minted_cents,
        f.p.claim_threshold_bps
    ));
    let claim = f.spend_tx(&v, &[op(v, 1)], f.tip, claim_opts());
    assert_eq!(i64::from(claim.lock_time), i64::from(rec.app_height)); // the APP branch's CLTV
    let r = spend(&mut f, &v, &claim);
    assert_eq!(r.verdict, verdict::OK);
    assert!(!r.invalid);
    assert_eq!(r.log.claim_path, "a");
    assert_eq!(r.log.residual_zat, 0);
    assert_eq!(r.vault.status, VaultStatus::Claiming);
    // The vault minted at 21,000 is at 495 % under 20,800: its in-term claim is invalid, its owner's redeem valid.
    let tx = f.spend_tx(&w, &[op(w, 1)], f.tip, claim_opts());
    assert_eq!(
        spend(&mut f, &w, &tx).verdict,
        verdict::VAULT_CLAIM_NOT_UNDERWATER
    );
    assert!(f.tip < i64::from(f.vault(&w).unwrap().lock_height));
    let redeem = f.spend_tx(&w, &[op(w, 1)], f.tip, SpendOpts::default());
    assert_eq!(
        i64::from(redeem.lock_time),
        i64::from(f.vault(&w).unwrap().owner_height)
    );
    let r = spend(&mut f, &w, &redeem);
    assert_eq!(r.verdict, verdict::OK);
    assert_eq!(r.vault.status, VaultStatus::Closed);
}

// Rule: IT-2
// Rule: RED-4
#[test]
fn in_term_claim_valid_post_term_as_before() {
    let mut f = Fixture::new();
    f.activate(50000);
    let v = f.mint_active10k();
    let rec = f.vault(&v).unwrap();
    while f.tip <= i64::from(rec.claim_height) {
        ticks(&mut f, 1, 9000); // past lockHeight + GRACE
    }
    assert_eq!(f.snap(f.tip).pclaim(), Some(9000));
    let tx = f.spend_tx(&v, &[op(v, 1)], f.tip, claim_opts());
    let r = spend(&mut f, &v, &tx);
    assert_eq!(r.verdict, verdict::OK);
    assert_eq!(r.log.claim_path, "a");
    assert_eq!(r.vault.status, VaultStatus::Claiming);
}

// Rule: IT-2
// Rule: IT-3
// Rule: RED-5
// Rule: NOT-1
#[test]
fn in_term_emergency_claim_pays_the_residual_to_the_owner() {
    let mut g = EmergencyFixture::new(35);
    let rec = g.f.vault(&g.w).unwrap();
    assert!(g.f.tip < i64::from(rec.lock_height));
    assert!(g.post_notice(None));
    for _ in 0..=g.f.p.emergency_persist {
        g.tick();
    }
    assert!(g.f.tip + 1 < i64::from(rec.lock_height)); // the claim block is still in term
    let residual = g.residual(g.f.tip - 1);
    assert!(residual >= g.f.p.residual_min_zat);
    let c = g.claim(SpendOpts::default(), None);
    let r = g.mine(&c);
    assert_eq!(r.verdict, verdict::RED5_RESIDUAL); // no residual intent
    assert!(r.invalid);
    let c = g.claim(
        SpendOpts {
            residual_value: Some(residual),
            ..SpendOpts::default()
        },
        None,
    );
    let r = g.mine(&c);
    assert_eq!(r.verdict, verdict::OK);
    assert_eq!(r.log.claim_path, "b");
    assert_eq!(r.log.residual_zat, residual);
    assert_eq!(r.vault.status, VaultStatus::Claiming);
    assert!(g.f.tip < i64::from(rec.lock_height));
    // the residual intent is the owner's (RED-5a)
    let res =
        g.f.state
            .intent(&op(c.txid(), u32::try_from(c.vout.len() - 1).unwrap()))
            .unwrap();
    assert_eq!(res.role, IntentRole::Residual);
}

// Rule: IT-5
// Rule: MINT-4
// Rule: MINT-6
#[test]
fn in_term_recap_gate_is_class_c_only() {
    let mp = main_params();
    assert!(mp.base_ratio_bps[0] < mp.recap_ratio_bps);
    assert!(mp.base_ratio_bps[1] < mp.recap_ratio_bps);
    assert_eq!(mp.base_ratio_bps[2], mp.recap_ratio_bps);
    // Under HALT-2 (one 300 % vault, price / 5.5): classes A and B are halted, C mints.
    let mut f = Fixture::new();
    f.activate(50000);
    f.mint_active10k();
    ticks(&mut f, 64, 9000);
    assert!(f.snap(f.tip).halt_mask & HALT_GLOBAL_RATIO != 0);
    assert!(f.snap(f.tip).halt_mask & HALT_DIVERGENCE == 0);
    let a = || MintOpts {
        collateral: 10_000_000_000_000,
        ..o()
    };
    let b = || MintOpts {
        term_class: 1,
        ..a()
    };
    let c = || MintOpts {
        term_class: 2,
        ..a()
    };
    let m = f.mint_tx(10000, 48, f.tip - 1, a());
    assert_eq!(mv(&mut f, &m), "mint-halted-global-ratio");
    let m = f.mint_tx(10000, 100, f.tip - 1, b());
    assert_eq!(mv(&mut f, &m), "mint-halted-global-ratio");
    let m = f.mint_tx(10000, 145, f.tip - 1, c());
    assert_eq!(mv(&mut f, &m), "");
    // Above the soft cap: the same gate.
    let mut g = Fixture::with(1, 0, 1, 0);
    g.activate(50000);
    let m = g.mint_tx(10000, 48, g.tip - 1, a());
    assert_eq!(mv(&mut g, &m), "mint-supply-cap");
    let m = g.mint_tx(10000, 100, g.tip - 1, b());
    assert_eq!(mv(&mut g, &m), "mint-supply-cap");
    let m = g.mint_tx(10000, 145, g.tip - 1, c());
    assert_eq!(mv(&mut g, &m), "");
}

// Rule: IT-4
// Rule: SIGMA-1
// Rule: MINT-5
#[test]
fn in_term_sigma_multiplier_fixed_at_one() {
    assert_eq!(main_params().sigma_ref_bps, 0);
    assert_eq!(main_params().sigma_mult_max_bps, 10000);
    let mut f = Fixture::with(1, 10000, 0, 0);
    f.activate(50000);
    for i in 0..64 {
        let price = if i % 2 == 1 { 46000 } else { 54000 };
        ticks(&mut f, 1, price); // +-8 %: noisy, not divergent
    }
    assert_eq!(f.snap(f.tip).sigma_mult_bps, 10000);
    let s = f.snap(f.tip - 1);
    assert_eq!(s.halt_mask & !HALT_GLOBAL_RATIO, 0);
    assert_eq!(
        min_ratio_bps(f.p.base_ratio_bps[0], s.sigma_mult_bps),
        f.p.base_ratio_bps[0]
    );
    let required = required_collateral(10000, f.p.base_ratio_bps[0], s.pmint().unwrap()).unwrap();
    let m = f.mint_tx(
        10000,
        48,
        f.tip - 1,
        MintOpts {
            collateral: required - 1,
            ..o()
        },
    );
    assert_eq!(mv(&mut f, &m), "bad-mint-collateral");
    let m = f.mint_tx(
        10000,
        48,
        f.tip - 1,
        MintOpts {
            collateral: required,
            ..o()
        },
    );
    assert_eq!(mv(&mut f, &m), "");
}

// Rule: IT-6
// Rule: HALT-2
#[test]
fn in_term_halt_ratio_counts_claiming_vault() {
    let mut f = Fixture::new();
    f.activate(50000);
    let v = f.mint_active10k();
    let w = f.mint_active10k();
    let each = f.vault(&v).unwrap().collateral_zat;
    assert_eq!(f.totals().collateral_zat, 2 * each);
    ticks(&mut f, 64, 9000);
    let claim = f.spend_tx(&w, &[op(w, 1)], f.tip, claim_opts());
    assert_eq!(spend(&mut f, &w, &claim).verdict, verdict::OK);
    // D-IT-14: the debt left supply with the burn, the collateral stays until release.
    assert_eq!(f.vault(&w).unwrap().status, VaultStatus::Claiming);
    assert_eq!(f.totals().supply_cents, 10000);
    assert_eq!(f.totals().open_debt_cents, 20000);
    assert_eq!(f.totals().collateral_zat, 2 * each);
    assert_eq!(f.totals().active_vaults, 1);
    assert_eq!(f.snap(f.tip).collateral_zat, 2 * each);
    assert_eq!(f.snap(f.tip).open_debt_cents, 20000);
    assert_eq!(
        f.snap(f.tip).global_ratio(),
        global_ratio_bps(2 * each, Some(9000), 20000)
    );
    // Release after CLAIM_DELAY: the collateral leaves.
    let rel = release_tx(&mut f, op(claim.txid(), 0), each);
    let t = Fixture::quote(9000, (f.tip + 1) % 3);
    f.mine(Some(t), vec![rel.clone()]);
    assert_eq!(f.refused_verdict(&rel.txid()), "");
    assert_eq!(f.vault(&w).unwrap().status, VaultStatus::Claimed);
    assert_eq!(f.totals().collateral_zat, each);
    assert_eq!(f.snap(f.tip).collateral_zat, each);
    assert_eq!(f.totals().open_debt_cents, 10000);
    assert_eq!(
        f.snap(f.tip).global_ratio(),
        global_ratio_bps(each, Some(9000), 10000)
    );
}
