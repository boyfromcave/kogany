// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

//! The owner's redeem and the supply cap of ycash6 `src/test/yellowback_state_tests.cpp` at
//! `65cb4ae0f` (W5-d2): RED-1..3 over the owner path, IN-2/IN-3 on a close, M3, IT-9's early
//! redeem fee, NOT-1's deletion on close, and MINT-6/6b. Each is a test of the same name over the
//! ported `Fixture`; the C++ `// Rule:` tags are kept.

mod state_common;

use kogany_vault::state::VaultTxIn;
use kogany_yellowback::codecs::payload::{Assignment, Payload};
use kogany_yellowback::math::{
    early_redeem_fee_zat, is_underwater, max_vault_cents, min_ratio_bps, supply_cap_cents,
};
use kogany_yellowback::params::{COIN, NUM_CLASSES};
use kogany_yellowback::state::{eligible_payees, verdict, TxLogType, VaultStatus};
use state_common::fixture::*;

fn q(f: &Fixture, price: i64) -> Option<kogany_yellowback::codecs::tag::CoinbaseTag> {
    Some(Fixture::quote(price, (f.tip + 1) % 3))
}

fn so() -> SpendOpts {
    SpendOpts::default()
}

/// `CScript() << valtype(n, b) << <tail>`.
fn push_then(n: usize, b: u8, tail: &[u8]) -> Vec<u8> {
    let mut s = vec![u8::try_from(n).unwrap()];
    s.extend(std::iter::repeat_n(b, n));
    s.extend_from_slice(tail);
    s
}

/// The owner redeem of `v` with the default options at refHeight `tip`.
fn owner_redeem(f: &mut Fixture, v: &kogany_vault::Hash32, o: SpendOpts) -> RedResult {
    let r = f.tip;
    let tx = f.spend_tx(v, &[op(*v, 1)], r, o);
    spend(f, v, &tx)
}

// ===========================================================================
// MINT-6, MINT-6b

// Rule: MINT-6b
// D-Q-23a: the debt of one mint may not exceed max(maxVaultShareBps of the cap,
// vaultShareFloorCents), every class alike, right after MINT-6; with no cap the rule is silent.
#[test]
fn mint6b_vault_share() {
    let mut f = Fixture::with(1, 0, 10000, 0); // cap = 100 % of market cap ...
    f.p.issued_before_start = 50000 * COIN; // ... of 50,000 YEC circulating below the start (D-Q-25)
    f.activate(1_000_000); // $1/YEC: the cap is ~$50,800, 10 % of it ~$5,080
    f.p.vault_share_floor_cents = 10000; // the floor at minMint so the share binds
                                         // the cap (and so the bound) grows with every block's issuance: read it at the mint's own R
    let max_vault_at = |f: &Fixture, r: i64| {
        let s = f.snap(r);
        max_vault_cents(
            supply_cap_cents(s.issued_zat, s.pmint(), f.p.supply_cap_bps),
            f.p.max_vault_share_bps,
            f.p.vault_share_floor_cents,
        )
        .unwrap()
    };
    let mv0 = max_vault_at(&f, f.tip - 1);
    assert!(mv0 > 10000 && mv0 < f.p.max_mint);
    // class C (500 %) passes MINT-6's soft cap: MINT-6b is the one that binds
    let c = MintOpts {
        term_class: 2,
        ..MintOpts::default()
    };
    let (r, m) = (f.tip - 1, max_vault_at(&f, f.tip - 1));
    let tx = f.mint_tx(m, 145, r, c.clone());
    assert_eq!(mv(&mut f, &tx), "");
    let (r, m) = (f.tip - 1, max_vault_at(&f, f.tip - 1));
    let tx = f.mint_tx(m + 1, 145, r, c.clone());
    assert_eq!(mv(&mut f, &tx), verdict::MINT_VAULT_SHARE);
    // class A too: every class alike
    let (r, m) = (f.tip - 1, max_vault_at(&f, f.tip - 1));
    let tx = f.mint_tx(m + 1, 48, r, MintOpts::default());
    assert_eq!(mv(&mut f, &tx), verdict::MINT_VAULT_SHARE);
    // the floor always lets the debt through (here up to maxMint itself)
    f.p.vault_share_floor_cents = f.p.max_mint;
    let (r, mm) = (f.tip - 1, f.p.max_mint);
    let tx = f.mint_tx(mm, 145, r, c.clone());
    assert_eq!(mv(&mut f, &tx), "");
    // the parameter off: no bound
    f.p.max_vault_share_bps = 0;
    f.p.vault_share_floor_cents = 1;
    let r = f.tip - 1;
    let tx = f.mint_tx(600_000, 145, r, c);
    assert_eq!(mv(&mut f, &tx), "");
    // no cap on regtest: silent
    let mut g = Fixture::new();
    g.activate(50000);
    g.p.vault_share_floor_cents = 1;
    g.p.max_vault_share_bps = 1000;
    let r = g.tip - 1;
    let tx = g.mint_tx(10000, 48, r, MintOpts::default());
    assert_eq!(mv(&mut g, &tx), "");
}

// Rule: MINT-6 (D-Q-25)
// The virtual snapshot's issuedZat is Params::issuedBeforeStart, so every snapshot's issuedZat is
// the circulating supply at its height and the cap is supplyCapBps of market capitalisation.
#[test]
fn mint6_issued_seeded_with_the_circulating_supply() {
    let mut f = Fixture::with(1, 0, 1500, 0);
    f.p.issued_before_start = 1_000_000 * COIN; // 1,000,000 YEC circulating below height 1
    f.activate(1_000_000);
    let issued_since_start = f.snap(f.tip).issued_zat - f.p.issued_before_start;
    assert_eq!(issued_since_start, f.tip * SUBSIDY); // the fixture's subsidies since block 1
    assert_eq!(f.snap(1).issued_zat, f.p.issued_before_start + SUBSIDY);
    // 15 % of (1,000,000 YEC + the fixture's blocks) at $1 is the cap: > $150,000; the pre-D-Q-25
    // base (the issuance since the start alone) was a few hundred dollars on a young chain
    let cap = supply_cap_cents(f.snap(f.tip - 1).issued_zat, Some(1_000_000), 1500).unwrap();
    assert!(cap > 15_000_000);
    assert!(supply_cap_cents(issued_since_start, Some(1_000_000), 1500).unwrap() < 100_000);
    let r = f.tip - 1;
    let tx = f.mint_tx(10000, 48, r, MintOpts::default());
    assert_eq!(mv(&mut f, &tx), "");
    // the default seed is 0: issuedZat counts from the start, as before
    let mut g = Fixture::new();
    g.activate(50000);
    assert_eq!(g.snap(g.tip).issued_zat, g.tip * SUBSIDY);
}

#[test]
fn mint6_supply_cap() {
    let mut f = Fixture::with(1, 0, 1, 0); // cap = 0.01% of market cap: below $100 on a young chain
    f.activate(50000);
    assert!(supply_cap_cents(f.snap(f.tip).issued_zat, Some(50000), 1).unwrap() < 10000);
    // class A (300 %): below the W20/IT-5 floor, so the cap is hard for it
    let r = f.tip - 1;
    let tx = f.mint_tx(10000, 48, r, MintOpts::default());
    assert_eq!(mv(&mut f, &tx), "mint-supply-cap");
    let mut g = Fixture::with(1, 0, 10000, 0); // cap = 100% of market cap: ~$818 at $1/YEC
    g.activate(1_000_000);
    let r = g.tip - 1;
    let tx = g.mint_tx(10000, 48, r, MintOpts::default());
    assert_eq!(mv(&mut g, &tx), "");
}

// Rule: MINT-6
#[test]
fn mint6_cap_is_soft_above_the_recap_floor() {
    // W20 / IT-5: a mint that would take supply over the cap is refused unless its class base
    // ratio reaches RECAP_RATIO_BPS (500 %): class A and B are mint-supply-cap, class C goes
    // through and takes supply above the cap.
    let mut f = Fixture::with(1, 0, 100_000, 0); // cap = 10x market cap: ~ $409 at $0.05
    f.activate(50000);
    let cap_at = |x: &Fixture, r: i64| {
        let s = x.snap(r);
        supply_cap_cents(s.issued_zat, s.pmint(), x.p.supply_cap_bps).unwrap()
    };
    let cap0 = cap_at(&f, f.tip - 1);
    assert!(cap0 > 2 * f.p.min_mint && cap0 - 5000 <= f.p.max_mint);
    f.mint_active(cap0 - 5000, 48, 0); // supply sits at the cap: less than MIN_MINT of headroom
    let mut r = f.tip - 1;
    assert!(f.totals().supply_cents <= cap_at(&f, r));
    assert!(f.totals().supply_cents + f.p.min_mint > cap_at(&f, r));
    let a = MintOpts {
        collateral: 10_000_000_000_000,
        ..MintOpts::default()
    };
    let b = MintOpts {
        term_class: 1, // class B, lock 100
        ..a.clone()
    };
    let c = MintOpts {
        term_class: 2, // class C, lock 145
        ..a.clone()
    };
    let tx = f.mint_tx(10000, 48, r, a.clone());
    assert_eq!(mv(&mut f, &tx), "mint-supply-cap");
    let tx = f.mint_tx(10000, 100, r, b.clone());
    assert_eq!(mv(&mut f, &tx), "mint-supply-cap");
    let tx = f.mint_tx(10000, 145, r, c.clone());
    assert_eq!(mv(&mut f, &tx), "");
    f.mint_active(10000, 145, 2); // class C, lock 145: accepted above the cap
    r = f.tip - 1;
    assert!(f.totals().supply_cents > cap_at(&f, r));
    let tx = f.mint_tx(10000, 48, r, a.clone());
    assert_eq!(mv(&mut f, &tx), "mint-supply-cap");
    let tx = f.mint_tx(10000, 145, r, c.clone());
    assert_eq!(mv(&mut f, &tx), "");
    // IT-5 judges the class base, not the sigma-scaled minimum: with SIGMA_REF set and an undefined
    // fast-window sample inside VOL_WINDOW the multiplier sits at its cap, which IT-4 pins at 1x,
    // so class B stays below the floor and the cap stays hard for it.
    let mut g = Fixture::with(1, 10000, 100_000, 0);
    g.activate(50000);
    for _ in 0..8 {
        g.mine_empty();
    }
    let to = g.tip + 8;
    g.mine_quotes_to(to, 50000);
    assert_eq!(g.snap(g.tip - 1).halt_mask, 0);
    assert_eq!(g.snap(g.tip - 1).sigma_mult_bps, g.p.sigma_mult_max_bps);
    assert_eq!(g.snap(g.tip - 1).sigma_mult_bps, 10000);
    let cap_g = cap_at(&g, g.tip - 1);
    g.mint_active(cap_g - 5000, 48, 0);
    r = g.tip - 1;
    assert!(g.totals().supply_cents + g.p.min_mint > cap_at(&g, r));
    assert!(min_ratio_bps(g.p.base_ratio_bps[1], g.snap(r).sigma_mult_bps) < g.p.recap_ratio_bps);
    let tx = g.mint_tx(10000, 100, r, b);
    assert_eq!(mv(&mut g, &tx), "mint-supply-cap");
    let tx = g.mint_tx(10000, 48, r, a);
    assert_eq!(mv(&mut g, &tx), "mint-supply-cap");
    let tx = g.mint_tx(10000, 145, r, c);
    assert_eq!(mv(&mut g, &tx), "");
}

// ===========================================================================
// Vault spends (§3.8 RED-1..4, IN-2, M3; §3.9 BLK-1)

// Rule: RED-1
// Rule: RED-2
// Rule: RED-3
// Rule: RED-4
// Rule: IN-2
// Rule: IN-3
// Rule: FEE-1
#[test]
fn red_owner_redeem_passes_and_closes() {
    let mut f = Fixture::new();
    f.activate(50000);
    let v = f.mint_active10k();
    let before = f.totals();
    let r = owner_redeem(&mut f, &v, so());
    assert_eq!(r.verdict, verdict::OK);
    assert!(!r.invalid);
    assert_eq!(r.vault.status, VaultStatus::Closed);
    assert_eq!(r.vault.burned_cents, 10000);
    assert!(!r.vault.unbacked);
    assert_eq!(i64::from(r.vault.close_height), f.tip);
    // rewritten by the close; IT-9': redeemed in term
    assert_eq!(
        r.vault.fee_paid_zat,
        f.vault_fee(&r.vault)
            + early_redeem_fee_zat(
                r.vault.minted_cents,
                f.p.early_redeem_fee_bps[0],
                r.vault.p_mint
            )
    );
    assert_eq!(r.log.tx_type, TxLogType::Redeem);
    assert_eq!(r.log.path, "owner");
    assert_eq!(r.log.burned, 10000);
    assert_eq!(r.log.closed_vaults.len(), 1);
    let t = f.totals();
    assert_eq!(t.supply_cents, before.supply_cents - 10000);
    assert_eq!(t.collateral_zat, 0);
    assert_eq!(t.active_vaults, 0);
    assert_eq!(t.closed_vaults, 1);
    assert_eq!(t.unbacked_cents, 0);
    // Spending a CLOSED vault again is an ordinary spend (nothing in the log).
    let tip = f.tip;
    let again = f.spend_tx(&v, &[], tip, so());
    f.mine(Some(Fixture::quote(50000, 0)), vec![again.clone()]);
    assert!(f.log(&again.txid()).is_none());
}

// Rule: RED-2
#[test]
fn red2_missing_and_short_burn() {
    let mut f = Fixture::new();
    f.activate(50000);
    let a = f.mint_active10k();
    let b = f.mint_active10k();
    // Assign everything: burn 0 => missing.
    {
        let tip = f.tip;
        let o = SpendOpts {
            assigned: vec![Assignment::new(3, 10000)],
            ..so()
        };
        let tx = f.spend_tx(&a, &[op(a, 1)], tip, o);
        let r = spend(&mut f, &a, &tx);
        assert_eq!(r.verdict, "vault-spend-missing-burn");
        assert!(r.invalid); // U-21: an invalid transaction, never mined
        assert_eq!(r.vault.status, VaultStatus::Active);
        assert!(f.token(&a, 1).is_some()); // nothing burned either
        assert!(f.token(&tx.txid(), 3).is_none());
        assert_eq!(f.totals().unbacked_cents, 0);
    }
    // Assign 6,000 of 10,000: burn 4,000 < 10,000 => short.
    {
        let o = SpendOpts {
            assigned: vec![Assignment::new(3, 6000)],
            ..so()
        };
        let r = owner_redeem(&mut f, &b, o);
        assert_eq!(r.verdict, "vault-spend-short-burn");
        assert!(r.invalid);
        assert_eq!(r.vault.status, VaultStatus::Active);
        assert_eq!(r.log.yed_out, 0);
        assert_eq!(f.totals().supply_cents, 20000); // nothing burned
    }
}

// Rule: RED-2
// Rule: IN-2
// Rule: IN-3
#[test]
fn in3_burn_recorded_on_closed_vault() {
    // A spend that burns only 4,000 against a 10,000 debt is invalid (U-21; v2 closed the vault
    // unbacked): the vault, the supply and the collateral are untouched.
    let mut f = Fixture::new();
    f.activate(50000);
    let a = f.mint_active10k();
    let split = f.transfer_tx(
        &[op(a, 1)],
        &[Assignment::new(0, 4000), Assignment::new(1, 6000)],
        false,
        0,
    );
    f.mine(Some(Fixture::quote(50000, 0)), vec![split.clone()]);
    let sid = split.txid();
    let tip = f.tip;
    let tx = f.spend_tx(&a, &[op(sid, 0)], tip, so());
    let r = spend(&mut f, &a, &tx);
    assert_eq!(r.verdict, "vault-spend-short-burn");
    assert!(r.invalid);
    assert_eq!(r.vault.status, VaultStatus::Active);
    assert_eq!(r.vault.burned_cents, 0);
    assert!(!r.vault.unbacked);
    assert_eq!(f.totals().unbacked_cents, 0);
    assert_eq!(f.totals().supply_cents, 10000);
    assert_eq!(f.totals().collateral_zat, 600_000_000_000);
}

// Rule: RED-3
// Rule: FEE-0
// Rule: FEE-2
#[test]
fn red3_fee_and_payee_edges() {
    let mut f = Fixture::new();
    f.activate(50000);
    {
        let v = f.mint_active10k();
        let r = owner_redeem(&mut f, &v, SpendOpts { fee_key: 7, ..so() });
        assert_eq!(r.verdict, "vault-spend-bad-payee");
    }
    {
        let v = f.mint_active10k();
        let fee = f.vault_fee(&f.vault(&v).unwrap()) - 1;
        let r = owner_redeem(
            &mut f,
            &v,
            SpendOpts {
                fee_value: fee,
                ..so()
            },
        );
        assert_eq!(r.verdict, "vault-spend-bad-fee");
    }
    {
        let v = f.mint_active10k(); // 0xFF with E(R) non-empty
        let r = owner_redeem(
            &mut f,
            &v,
            SpendOpts {
                fee_key: -1,
                ..so()
            },
        );
        assert_eq!(r.verdict, "vault-spend-bad-fee");
    }
    {
        let v = f.mint_active10k(); // the OP_RETURN
        let r = owner_redeem(
            &mut f,
            &v,
            SpendOpts {
                fee_vout: 2,
                ..so()
            },
        );
        assert_eq!(r.verdict, "vault-spend-bad-fee");
    }
    {
        let v = f.mint_active10k(); // out of range
        let r = owner_redeem(
            &mut f,
            &v,
            SpendOpts {
                fee_vout: 9,
                ..so()
            },
        );
        assert_eq!(r.verdict, "vault-spend-bad-fee");
    }
    {
        // an assigned vout (K23)
        let v = f.mint_active10k();
        let w = f.mint_active10k();
        let o = SpendOpts {
            fee_vout: 3,
            assigned: vec![Assignment::new(3, 5000)],
            ..so()
        };
        let tip = f.tip;
        let tx = f.spend_tx(&v, &[op(v, 1), op(w, 1)], tip, o);
        assert_eq!(spend(&mut f, &v, &tx).verdict, "vault-spend-bad-fee");
    }
    {
        // the collateral destination may be the fee (K23)
        let v = f.mint_active10k();
        let o = SpendOpts {
            fee_vout: 0,
            fee_key: f.tip % 3,
            ..so()
        };
        let tip = f.tip;
        let mut m = f.spend_tx(&v, &[op(v, 1)], tip, o);
        m.vout[0].script_pubkey = kogany_yellowback::codecs::script::p2pkh_script(&key_of(tip % 3));
        assert_eq!(spend(&mut f, &v, &m).verdict, verdict::OK);
    }
    // FEE-0: an empty E(R) makes RED-3 vacuous; a stray fee output to nobody is fine and
    // feePaidZat is 0.
    {
        let v = f.mint_active10k();
        for _ in 0..12 {
            f.mine_empty();
        }
        assert!(eligible_payees(&f.state, &f.p, f.tip).is_empty());
        let r = owner_redeem(
            &mut f,
            &v,
            SpendOpts {
                fee_key: -1,
                fee_value: 1,
                ..so()
            },
        );
        assert_eq!(r.verdict, verdict::OK);
        assert_eq!(r.vault.fee_paid_zat, 0);
        assert_eq!(r.log.fee_zat, 0);
        assert!(!r.log.has_payee);
    }
}

// Rule: RED-1
#[test]
fn red1_structure_and_selectors() {
    let mut f = Fixture::new();
    f.activate(50000);
    // The vault at vin[1] fails.
    {
        let v = f.mint_active10k();
        let r = owner_redeem(
            &mut f,
            &v,
            SpendOpts {
                vault_first: false,
                ..so()
            },
        );
        assert_eq!(r.verdict, "vault-spend-malformed");
        assert!(r.invalid);
    }
    // Two ACTIVE vaults in one transaction fail (the primitive's S-1 refuses it too); both stay
    // ACTIVE.
    {
        let v = f.mint_active10k();
        let w = f.mint_active10k();
        let o = SpendOpts {
            extra_vaults: vec![op(w, 0)],
            ..so()
        };
        let tip = f.tip;
        let tx = f.spend_tx(&v, &[op(v, 1), op(w, 1)], tip, o);
        let r = spend(&mut f, &v, &tx);
        assert_eq!(r.verdict, "vault-spend-malformed");
        assert!(r.invalid);
        assert_eq!(f.vault(&w).unwrap().status, VaultStatus::Active);
    }
    // A one-push scriptSig and a non-push-only scriptSig fail RED-1 (M1).
    {
        let v = f.mint_active10k();
        let o = SpendOpts {
            script_sig: Some(push_then(20, 1, &[])),
            ..so()
        };
        assert_eq!(owner_redeem(&mut f, &v, o).verdict, "vault-spend-malformed");
    }
    {
        let v = f.mint_active10k();
        let mut s = vec![0x51]; // OP_1
        s.extend(push_then(20, 1, &[0x75])); // <20 bytes> OP_DROP
        let o = SpendOpts {
            script_sig: Some(s),
            ..so()
        };
        assert_eq!(owner_redeem(&mut f, &v, o).verdict, "vault-spend-malformed");
    }
    // No REDEEM payload (a sweep) and a TRANSFER payload fail.
    {
        let v = f.mint_active10k();
        let r = owner_redeem(
            &mut f,
            &v,
            SpendOpts {
                payload: false,
                ..so()
            },
        );
        assert_eq!(r.verdict, "vault-spend-malformed");
    }
    {
        let v = f.mint_active10k();
        let o = SpendOpts {
            payload_override: Some(Payload::Transfer(Vec::new())),
            ..so()
        };
        assert_eq!(owner_redeem(&mut f, &v, o).verdict, "vault-spend-malformed");
    }
    // refHeight outside the window or below START_HEIGHT.
    for (delta, want) in [
        (1i64, "vault-spend-malformed"),
        (-40, "vault-spend-malformed"),
        (-39, verdict::OK),
    ] {
        let v = f.mint_active10k();
        let r = f.tip + delta;
        let tx = f.spend_tx(&v, &[op(v, 1)], r, so());
        assert_eq!(
            spend(&mut f, &v, &tx).verdict,
            want,
            "refHeight tip{delta:+}"
        );
    }
    // An assignment outside [MIN_OUTPUT, MAX_OUTPUT] is RED-1 (XFER-1 inside a vault spend).
    {
        let v = f.mint_active10k();
        let w = f.mint_active10k();
        let o = SpendOpts {
            assigned: vec![Assignment::new(3, 99)],
            ..so()
        };
        let tip = f.tip;
        let tx = f.spend_tx(&v, &[op(v, 1), op(w, 1)], tip, o);
        assert_eq!(spend(&mut f, &v, &tx).verdict, "vault-spend-malformed");
    }
    // U-23 selectors (§15.3): OP_2 and OP_3 are the owner's, OP_4 the claim, OP_1 (a set unlock)
    // never a YED path; anything but the exact one-byte OP_1..OP_4 is not a selector.
    for sel in [0x52u8, 0x53] {
        let v = f.mint_active10k();
        let o = SpendOpts {
            script_sig: Some(push_then(71, 0x30, &[sel])),
            ..so()
        };
        let r = owner_redeem(&mut f, &v, o);
        assert_eq!(r.verdict, verdict::OK);
        assert_eq!(r.log.path, "owner");
    }
    {
        let v = f.mint_active10k();
        let o = SpendOpts {
            script_sig: Some(push_then(65, 0x1f, &[0x51])),
            ..so()
        };
        let r = owner_redeem(&mut f, &v, o);
        assert_eq!(r.verdict, "vault-spend-malformed");
        assert!(r.invalid);
    }
    {
        // a non-minimal 2
        let v = f.mint_active10k();
        let o = SpendOpts {
            script_sig: Some(push_then(71, 0x30, &[0x01, 0x02])),
            ..so()
        };
        assert_eq!(owner_redeem(&mut f, &v, o).verdict, "vault-spend-malformed");
    }
    {
        // the claim selector with the owner's outputs: no intents
        let v = f.mint_active10k();
        let o = SpendOpts {
            script_sig: Some(vec![0x54]),
            ..so()
        };
        let r = owner_redeem(&mut f, &v, o);
        assert_eq!(r.verdict, verdict::VAULT_CLAIM_INTENTS);
        assert_eq!(r.log.path, "claim");
    }
    {
        let v = f.mint_active10k();
        let r = owner_redeem(
            &mut f,
            &v,
            SpendOpts {
                owner_path: false,
                ..so()
            },
        );
        assert_eq!(r.verdict, "vault-claim-not-underwater");
        assert_eq!(r.log.path, "claim");
    }
}

// Rule: RED-1
// Rule: MINT-1
// Rule: IN-2
#[test]
fn m3_vault_spend_with_mint_payload() {
    let mut f = Fixture::new();
    f.activate(50000);
    let v = f.mint_active10k();
    // A vault spend carrying a well-formed MINT payload: RED-1..4 only, no new vault, TxLog.type
    // REDEEM.
    let r = f.tip - 1;
    let mut m = f.mint_tx(10000, 48, r, MintOpts::default());
    m.vin.insert(
        0,
        VaultTxIn {
            prevout: op(v, 0),
            script_sig: push_then(71, 0x30, &[0x52]),
        },
    );
    let ev = f.evaluate(
        Some(Fixture::quote(50000, 0)),
        std::slice::from_ref(&m),
        None,
    );
    let txid = m.txid();
    assert!(ev.block_invalid); // U-21
    assert_eq!(ev.verdict, "vault-spend-malformed");
    assert_eq!(ev.txlogs.len(), 1);
    assert_eq!(ev.txlogs[0].1.tx_type, TxLogType::Redeem);
    f.mine(Some(Fixture::quote(50000, 0)), vec![m]);
    assert!(f.vault(&txid).is_none());
    assert!(f.token(&txid, 1).is_none());
    assert_eq!(f.vault(&v).unwrap().status, VaultStatus::Active);
    assert_eq!(f.totals().unbacked_cents, 0);
    assert_eq!(f.totals().supply_cents, 10000);
    // A full burn to the wrong payee: RED-3 fails; invalid like any other failure.
    let w = f.mint_active10k();
    let r = owner_redeem(&mut f, &w, SpendOpts { fee_key: 7, ..so() });
    assert_eq!(r.verdict, "vault-spend-bad-payee");
    assert!(r.invalid);
    assert_eq!(r.vault.status, VaultStatus::Active);
    assert_eq!(f.totals().unbacked_cents, 0);
}

// Rule: RED-1
// Rule: AFEE-0
#[test]
fn red1_owner_path_ignores_bundle() {
    let mut f = Fixture::new();
    f.arm(3, 50000);
    let m = f.mint_v3(10000, 50000, MintOpts::default(), &none_skip(), 48);
    assert_eq!(mv(&mut f, &m), "");
    let v = m.txid();
    // ARMED owner redeem with no carrier and no attestor fee: RED-1..3 as in v2.
    let r = f.tip - 1;
    let tx = f.spend_tx(&v, &[op(v, 1)], r, so());
    let r = spend(&mut f, &v, &tx);
    assert_eq!(r.verdict, verdict::OK);
    assert!(!r.invalid);
    assert_eq!(r.vault.status, VaultStatus::Closed);
    assert_eq!(r.log.claim_path, "");
    assert_eq!(r.log.residual_zat, 0);
    assert!(f.bundle_row(f.tip).is_none());
}

// Rule: NOT-1
// Rule: IN-2
#[test]
fn not1_deleted_when_vault_closes() {
    let mut g = EmergencyFixture::new(64);
    assert!(g.post_notice(None));
    // An owner redeem (any close) deletes Notices[vault]; undo restores it.
    let before = hash_hex(&g.f.state);
    let w = g.w;
    let r = g.f.tip - 1;
    let tx = g.f.spend_tx(&w, &[op(w, 1)], r, so());
    let res = g.mine(&tx);
    assert_eq!(res.verdict, verdict::OK);
    assert!(g.f.notice(&w).is_none());
    g.f.undo();
    assert!(g.f.notice(&w).is_some());
    assert_eq!(hash_hex(&g.f.state), before);
    // a spend with no payload is invalid (RED-1, U-21): the vault and its notice stay
    let r = g.f.tip - 1;
    let tx = g.f.spend_tx(
        &w,
        &[],
        r,
        SpendOpts {
            payload: false,
            ..so()
        },
    );
    let bad = g.mine(&tx);
    assert!(bad.invalid);
    assert!(g.f.notice(&w).is_some());
}

// Rule: IT-1
// Rule: RED-1
// Rule: RED-2
#[test]
fn in_term_owner_redeem_below_theta_before_any_claim() {
    // The owner redeems in term while under theta, before anyone claims: valid, the full debt
    // burned.
    let mut f = Fixture::new();
    f.activate(50000);
    let v = f.mint_active10k();
    for _ in 0..34 {
        let t = q(&f, 9000);
        f.mine(t, Vec::new());
    }
    let vr = f.vault(&v).unwrap();
    assert!(f.tip < i64::from(vr.lock_height));
    assert!(is_underwater(
        vr.collateral_zat,
        f.snap(f.tip).pclaim(),
        10000,
        f.p.claim_threshold_bps
    ));
    let r = owner_redeem(&mut f, &v, so());
    assert_eq!(r.verdict, verdict::OK);
    assert_eq!(r.vault.status, VaultStatus::Closed);
    assert_eq!(r.vault.burned_cents, 10000);
    assert_eq!(f.totals().supply_cents, 0);
    // and a claim of the closed vault no longer exists to be made
    assert!(!f.vault(&v).unwrap().is_open());
}

// Rule: IT-9
// Rule: RED-3
#[test]
fn in_term_early_redeem_fee_per_class_and_boundary() {
    let mut f = Fixture::new();
    f.activate(50000);
    assert_eq!(f.p.early_redeem_fee_bps, [500, 250, 100]);
    for cls in 0..NUM_CLASSES {
        let v = f.mint_active(
            10000,
            i64::from(f.p.class_min[cls]),
            u8::try_from(cls).unwrap(),
        );
        let r = f.vault(&v).unwrap();
        let fee1 = f.vault_fee(&r);
        let early = early_redeem_fee_zat(r.minted_cents, f.p.early_redeem_fee_bps[cls], r.p_mint);
        // IT-9': bps of the debt at pMint: $100 x 5 / 2.5 / 1 % at $0.05 = 100 / 50 / 20 YEC
        assert_eq!(
            early,
            10000 * i64::from(f.p.early_redeem_fee_bps[cls]) * COIN / r.p_mint
        );
        assert!(f.tip + 1 < i64::from(r.lock_height));
        // FEE-1 alone, and one zat short of FEE-1 + the early fee: bad-redeem-early-fee; the
        // vault stays ACTIVE
        let x = owner_redeem(
            &mut f,
            &v,
            SpendOpts {
                fee_value: fee1,
                ..so()
            },
        );
        assert_eq!(x.verdict, verdict::BAD_REDEEM_EARLY_FEE);
        assert!(x.invalid);
        assert_eq!(x.vault.status, VaultStatus::Active);
        let x = owner_redeem(
            &mut f,
            &v,
            SpendOpts {
                fee_value: fee1 + early - 1,
                ..so()
            },
        );
        assert_eq!(x.verdict, verdict::BAD_REDEEM_EARLY_FEE);
        assert!(x.invalid);
        // short of FEE-1 itself is still RED-3's vault-spend-bad-fee
        let x = owner_redeem(
            &mut f,
            &v,
            SpendOpts {
                fee_value: fee1 - 1,
                ..so()
            },
        );
        assert_eq!(x.verdict, verdict::VAULT_SPEND_BAD_FEE);
        // exact: valid, the fee logged in full
        let x = owner_redeem(
            &mut f,
            &v,
            SpendOpts {
                fee_value: fee1 + early,
                ..so()
            },
        );
        assert_eq!(x.verdict, verdict::OK);
        assert_eq!(x.vault.status, VaultStatus::Closed);
        assert_eq!(x.vault.fee_paid_zat, fee1 + early);
    }
    // The boundary: a redeem mined at lockHeight - 1 pays the early fee, one mined at lockHeight
    // pays FEE-1 only.
    let w = f.mint_active10k();
    let r = f.vault(&w).unwrap();
    let fee1 = f.vault_fee(&r);
    let lock = i64::from(r.lock_height);
    while f.tip + 1 < lock - 1 {
        let t = q(&f, 50000);
        f.mine(t, Vec::new());
    }
    assert_eq!(f.tip + 1, lock - 1);
    {
        let tip = f.tip;
        let tx = f.spend_tx(
            &w,
            &[op(w, 1)],
            tip,
            SpendOpts {
                fee_value: fee1,
                ..so()
            },
        );
        let ev = f.evaluate(q(&f, 50000), &[tx], None);
        assert!(ev.block_invalid);
        assert_eq!(ev.txlogs[0].1.verdict, verdict::BAD_REDEEM_EARLY_FEE);
    }
    let t = q(&f, 50000);
    f.mine(t, Vec::new());
    assert_eq!(f.tip + 1, lock);
    let x = owner_redeem(
        &mut f,
        &w,
        SpendOpts {
            fee_value: fee1,
            ..so()
        },
    );
    assert_eq!(x.verdict, verdict::OK);
    assert_eq!(x.vault.fee_paid_zat, fee1);
}
