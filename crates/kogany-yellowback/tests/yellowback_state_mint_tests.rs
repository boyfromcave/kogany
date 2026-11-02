// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

//! The MINT, TRANSFER and TX-0 cases of ycash6 `src/test/yellowback_state_tests.cpp` at
//! `65cb4ae0f` (W5-d1), each a test of the same name over the ported `Fixture`. The C++ `// Rule:`
//! tags are kept on each case.

mod state_common;

use kogany_vault::template::{build_vault, PQ_SCHEME_FN_DSA_512};
use kogany_vault::{Hash32, PqOwner};
use kogany_yellowback::attest::price::{HALT_DIVERGENCE, HALT_GLOBAL_RATIO, HALT_NO_PRICE};
use kogany_yellowback::codecs::payload::{encode_payload, payload_script, Assignment, Payload};
use kogany_yellowback::codecs::script::{
    holder_key, p2sh_script, pq_channel_script, pq_key_script, v2_vault_script, yed_vault_params,
    Holder, PqChannelParams,
};
use kogany_yellowback::math::{min_ratio_bps, required_collateral};
use kogany_yellowback::params::{COIN, LOCKTIME_THRESHOLD, MAX_MONEY, PRICE_MIN, TOKEN_VALUE};
use kogany_yellowback::state::{
    eligible_payees, process_tx, verdict, TxLogType, VaultStatus, YedRead,
};
use state_common::fixture::*;

fn quote_next(f: &Fixture) -> Option<kogany_yellowback::codecs::tag::CoinbaseTag> {
    Some(Fixture::quote(50000, (f.tip + 1) % 3))
}

fn o() -> MintOpts {
    MintOpts::default()
}

/// A PQ key id with a hash of `seed` bytes (the C++ draws `GetRandHash()`).
fn pq(scheme: u8, seed: u8) -> PqOwner {
    PqOwner {
        scheme,
        hash: Hash32([seed; 32]),
    }
}

// Rule: MINT-1
// Rule: IN-1
// Rule: IN-3
// Rule: TX-0
#[test]
fn mint1_wellformed_creates_vault_and_token() {
    let mut f = Fixture::new();
    f.activate(50000);
    let r = f.tip - 1;
    let m = f.mint_tx(10000, 48, r, o());
    let ev = f.mine(Some(Fixture::quote(50000, 0)), vec![m.clone()]);
    let txid = m.txid();
    assert!(!ev.block_invalid);
    let v = f.vault(&txid).unwrap();
    assert_eq!(v.status, VaultStatus::Active);
    assert_eq!(v.minted_cents, 10000);
    assert_eq!(v.collateral_zat, 600_000_000_000); // $100 at 300 % (class A, D-IT-4) and $0.05
    assert_eq!(i64::from(v.lock_height), r + 48);
    assert_eq!(i64::from(v.claim_height), r + 48 + 24);
    assert_eq!(i64::from(v.app_height), r + 1); // IT-1
    assert_eq!(i64::from(v.owner_height), r + 1); // IT-1 (extended)
    assert_eq!(i64::from(v.ref_height), r);
    assert_eq!(v.p_mint, f.pmint_at(r)); // FEE-1'
    assert_eq!(v.fee_paid_zat, f.vault_fee(&v));
    assert_eq!(v.owner(), test_pq_owner(&f.owner_pub()));
    assert_eq!(f.token(&txid, 1).unwrap().cents, 10000);
    let log = f.log(&txid).unwrap();
    assert_eq!(log.verdict, verdict::OK);
    assert_eq!(log.tx_type, TxLogType::Mint);
    assert_eq!(log.yed_out, 10000);
    assert_eq!(log.burned, 0);
    assert!(log.has_payee);
    assert_eq!(f.totals().supply_cents, 10000);
    assert_eq!(f.totals().collateral_zat, v.collateral_zat);
    assert_eq!(f.totals().active_vaults, 1);
    // MINT-1 fails (version 1 payload): non-Yellowback, so its YED vault output is one no rule
    // created (U-23): the transaction is invalid; no vault.
    let mut bad = f.mint_tx(10000, 48, f.tip - 1, o());
    let mut data = encode_payload(&Payload::mint(
        0,
        10000,
        u32::try_from(f.tip + 47).unwrap(),
        u32::try_from(f.tip - 1).unwrap(),
        &test_pq_owner(&f.owner_pub()),
        3,
        kogany_yellowback::params::FEE_VOUT_NONE,
    ))
    .unwrap();
    data[2] = 0x01;
    bad.vout[2] = txout(0, payload_script(&data));
    f.mine(Some(Fixture::quote(50000, 1)), vec![bad.clone()]);
    assert!(f.vault(&bad.txid()).is_none());
    assert_eq!(f.refused_verdict(&bad.txid()), verdict::YED_TEMPLATE_OUTPUT);
    // The same with the vault output a plain P2PKH: non-Yellowback, no vault, no log.
    bad.vout[0].script_pubkey = f.user_p2pkh();
    f.mine(Some(Fixture::quote(50000, 1)), vec![bad.clone()]);
    assert!(f.vault(&bad.txid()).is_none());
    assert!(f.log(&bad.txid()).is_none());
    // TX-0: a coinbase carrying a MINT payload registers nothing
    let mut cb = Fixture::coinbase(f.tip + 1, Some(&Fixture::quote(50000, 2)));
    cb.vout = f.mint_tx(10000, 48, f.tip - 1, o()).vout;
    {
        // ...but a coinbase may not create a YED vault either (U-23).
        let ev2 = f.evaluate_raw(&[cb.tx()], f.tip + 1);
        assert!(ev2.block_invalid);
        assert_eq!(ev2.verdict, verdict::YED_TEMPLATE_OUTPUT);
    }
    cb.vout[0].script_pubkey = f.user_p2pkh();
    let cb_ev = f.evaluate_raw(&[cb.tx()], f.tip + 1);
    assert!(cb_ev.txlogs.is_empty());
    let after = f.state.with(&cb_ev.delta);
    assert!(after.vault(&op(cb.txid(), 0)).is_none());
    assert!(cb_ev.snapshot.quote);
}

// Rule: TX-0
#[test]
fn tx0_coinbase_payload_registers_nothing() {
    let mut f = Fixture::new();
    f.activate(50000);
    let mut cb = Fixture::coinbase(f.tip + 1, None);
    cb.vout
        .push(payload_out(&transfer_payload(&[Assignment::new(0, 100)])));
    let r = process_tx(&f.state, &f.p, &cb.tx(), f.tip + 1, None).outcome;
    assert!(!r.relevant && !r.vault_spend && !r.invalid);
    assert_eq!(r.log.verdict, verdict::NON_YELLOWBACK);
}

// Rule: MINT-2
#[test]
fn mint2_every_clause_voids() {
    let mut f = Fixture::new();
    f.activate(50000);
    let m = f.mint_tx(
        10000,
        48,
        f.tip - 1,
        MintOpts {
            term_class: 3,
            ..o()
        },
    );
    let (v, invalid) = mint_verdict_of(&mut f, &m);
    assert_eq!(v, "bad-mint-class");
    assert!(invalid); // U-21: a failing mint is an invalid transaction
    let m = f.mint_tx(5000, 48, f.tip - 1, o());
    assert_eq!(mv(&mut f, &m), "bad-mint-amount");
    let m = f.mint_tx(10_000_001, 48, f.tip - 1, o());
    assert_eq!(mv(&mut f, &m), "bad-mint-amount"); // D-Q-24: $100,000 + one cent
    assert_eq!(f.p.max_mint, 10_000_000);
    let lb = i64::from(LOCKTIME_THRESHOLD) - i64::from(f.p.grace) - (f.tip - 1);
    let m = f.mint_tx(10000, lb, f.tip - 1, o());
    assert_eq!(mv(&mut f, &m), "bad-mint-lock-height");
    let m = f.mint_tx(10000, 47, f.tip - 1, o());
    assert_eq!(mv(&mut f, &m), "bad-mint-lock-height"); // below class A
    let m = f.mint_tx(10000, 97, f.tip - 1, o());
    assert_eq!(mv(&mut f, &m), "bad-mint-lock-height"); // class A, 97 blocks
    let m = f.mint_tx(
        10000,
        97,
        f.tip - 1,
        MintOpts {
            term_class: 1,
            ..o()
        },
    );
    assert_eq!(mv(&mut f, &m), "");
    // ref = H
    let r = f.tip + 1;
    let m = f.mint_tx(
        10000,
        48,
        r,
        MintOpts {
            collateral: 1_000_000_000_000,
            ..o()
        },
    );
    assert_eq!(mv(&mut f, &m), "bad-mint-ref-height");
    let m = f.mint_tx(10000, 48, f.tip, o());
    assert_eq!(mv(&mut f, &m), ""); // ref = H - 1
    f.mine_quotes_to(f.tip + 40, 50000); // so that H - 40 is past activation
    let m = f.mint_tx(10000, 48, f.tip - 39, o());
    assert_eq!(mv(&mut f, &m), ""); // ref = H - 40 (H = tip + 1)
    let m = f.mint_tx(10000, 48, f.tip - 40, o());
    assert_eq!(mv(&mut f, &m), "bad-mint-ref-height"); // ref = H - 41
                                                       // §15.10: no VOID record; the failing mint leaves nothing behind.
    let before = f.totals();
    let m = f.mint_tx(5000, 48, f.tip - 1, o());
    assert_eq!(mv(&mut f, &m), "bad-mint-amount");
    assert!(f.vault(&m.txid()).is_none());
    assert_eq!(f.totals().collateral_zat, before.collateral_zat);
    assert_eq!(f.totals().void_vaults, before.void_vaults);
    assert_eq!(f.totals().supply_cents, before.supply_cents);
    assert_eq!(f.log(&m.txid()).unwrap().verdict, "bad-mint-amount");
    assert_eq!(f.log(&m.txid()).unwrap().yed_out, 0);
}

// Rule: MINT-2
#[test]
fn mint2_regtest_height_underflow() {
    // H < REF_WINDOW on regtest: H - 40 is negative and must not wrap; refHeight 1 at H = 5 is inside the window.
    let mut f = Fixture::new();
    f.mine_quotes_to(4, 50000);
    let opts = || MintOpts {
        collateral: 1_000_000_000_000,
        fee_key: 0,
        ..o()
    };
    // the module is active; no price yet
    let m = f.mint_tx(10000, 48, 1, opts());
    assert_eq!(mv(&mut f, &m), "mint-halted-no-price");
    let m = f.mint_tx(10000, 48, 0, opts());
    assert_eq!(mv(&mut f, &m), "bad-mint-ref-height"); // below START_HEIGHT
}

// Rule: MINT-3
#[test]
fn mint3_outputs_owner_key_vault_script() {
    let mut f = Fixture::new();
    f.activate(50000);
    let mut two = f.mint_tx(10000, 48, f.tip - 1, o());
    two.vout.truncate(2);
    two.vout[1] = txout(0, two.vout[0].script_pubkey.clone()); // keep vout[0] the V; no third output
                                                               // Two outputs cannot carry an OP_RETURN at all: non-Yellowback, its YED vaults are outputs no rule created
    assert_eq!(mv(&mut f, &two), verdict::YED_TEMPLATE_OUTPUT);
    let mut m = f.mint_tx(10000, 48, f.tip - 1, o());
    m.vout.truncate(3);
    m.vout[1] = m.vout[2].clone();
    m.vout.truncate(2);
    assert_eq!(mv(&mut f, &m), "bad-mint-outputs");
    let m = f.mint_tx(
        10000,
        48,
        f.tip - 1,
        MintOpts {
            raw_owner: Some([0x04; 33]),
            ..o()
        },
    );
    assert_eq!(mv(&mut f, &m), "bad-mint-owner-key");
    {
        let mut raw = f.owner_pub().0;
        raw[5] ^= 0x01; // a 0x02 prefix: no registered scheme byte
        let m = f.mint_tx(
            10000,
            48,
            f.tip - 1,
            MintOpts {
                raw_owner: Some(raw),
                ..o()
            },
        );
        let v = mv(&mut f, &m);
        assert!(
            v == "bad-mint-owner-key" || v == "bad-mint-vault-script",
            "{v}"
        );
    }
    {
        let s = v2_vault_script(
            u32::try_from(f.tip + 60).unwrap(),
            &f.owner_pub(),
            u32::try_from(f.tip + 84).unwrap(),
        )
        .unwrap();
        let m = f.mint_tx(
            10000,
            48,
            f.tip - 1,
            MintOpts {
                vault_script_override: Some(s),
                ..o()
            },
        );
        assert_eq!(mv(&mut f, &m), "bad-mint-vault-script");
    }
    // U-23: v2's P2SH vault (with the payload's own lock) is refused for new mints.
    {
        let lock = u32::try_from(f.tip - 1 + 48).unwrap();
        let s = p2sh_script(
            &v2_vault_script(
                lock,
                &f.owner_pub(),
                lock + u32::try_from(f.p.grace).unwrap(),
            )
            .unwrap(),
        );
        let m = f.mint_tx(
            10000,
            48,
            f.tip - 1,
            MintOpts {
                vault_script_override: Some(s),
                ..o()
            },
        );
        assert_eq!(mv(&mut f, &m), "bad-mint-vault-script");
    }
    // A V under another delay is not the YED vault either.
    {
        let mut vp = yed_vault_params(&f.p, &test_pq_owner(&f.owner_pub()), f.tip - 1);
        vp.delay += 1;
        let m = f.mint_tx(
            10000,
            48,
            f.tip - 1,
            MintOpts {
                vault_script_override: build_vault(&vp),
                ..o()
            },
        );
        assert_eq!(mv(&mut f, &m), "bad-mint-vault-script");
    }
    let m = f.mint_tx(
        10000,
        48,
        f.tip - 1,
        MintOpts {
            p2sh_vault: false,
            ..o()
        },
    );
    assert_eq!(mv(&mut f, &m), "bad-mint-vault-script"); // no V at all
}

// Rule: MINT-3
// Rule: TOK-PQ
#[test]
#[allow(clippy::too_many_lines)]
fn mint3_tokpq_falcon_height_boundary() {
    let mut f = Fixture::new();
    f.activate(50000);
    let falcon_height = f.tip + 7;
    f.p.pq_falcon_height = i32::try_from(falcon_height).unwrap(); // not hashed: set after the first block is fine
    assert!(!f.p.is_pq_falcon_active(falcon_height - 1));
    assert!(f.p.is_pq_falcon_active(falcon_height));
    let slh_owner = pq(1, 0xa1);
    let falcon_owner = pq(PQ_SCHEME_FN_DSA_512, 0xa2);
    let falcon_holder = pq(PQ_SCHEME_FN_DSA_512, 0xa3);
    let slh_holder = pq(1, 0xa4);
    let _ = slh_owner;
    let falcon_spk = pq_key_script(&falcon_holder).unwrap();
    assert_eq!(falcon_spk.len(), 35);
    let verdict_of = |f: &mut Fixture, m: &MTx| -> (String, bool) {
        let t = quote_next(f);
        f.mine(t, vec![m.clone()]);
        let refused = f.refused_verdict(&m.txid());
        if !refused.is_empty() {
            return (refused, true);
        }
        (
            f.log(&m.txid()).map(|l| l.verdict).unwrap_or_default(),
            false,
        )
    };
    assert_eq!(holder_key(&falcon_spk), Some(Holder::Pq(falcon_holder)));
    let channel = |client: PqOwner, f: &Fixture, refund: i64| {
        pq_channel_script(&PqChannelParams {
            client,
            server: f.user_pub(),
            refund_height: refund,
        })
        .unwrap()
    };

    // Below the Falcon height: a Falcon owner is refused (MINT-3), a P2PKH or any PQPKH token is fine.
    let m = f.mint_tx(
        10000,
        48,
        f.tip - 1,
        MintOpts {
            pq_owner: Some(falcon_owner),
            ..o()
        },
    );
    assert_eq!(mv(&mut f, &m), verdict::BAD_MINT_OWNER_KEY);
    assert!(f.tip + 1 < falcon_height);
    let mut below = f.mint_tx(10000, 48, f.tip - 1, o()); // P2PKH token
    assert_eq!(mv(&mut f, &below), "");
    let below_id = below.txid();
    let m = f.mint_tx(
        10000,
        48,
        f.tip - 1,
        MintOpts {
            token_script: pq_key_script(&slh_holder),
            ..o()
        },
    );
    assert_eq!(mv(&mut f, &m), "");
    let ch = channel(slh_holder, &f, 1000);
    let m = f.mint_tx(
        10000,
        48,
        f.tip - 1,
        MintOpts {
            token_script: Some(ch),
            ..o()
        },
    );
    assert_eq!(mv(&mut f, &m), ""); // D-Q-19 below
                                    // A TRANSFER below the height to P2PKH and to an SLH-DSA PQPKH: no shape rule yet.
    {
        let mut t = f.transfer_tx(
            &[op(below_id, 1)],
            &[Assignment::new(0, 6000), Assignment::new(1, 4000)],
            false,
            0,
        );
        t.vout[1].script_pubkey = pq_key_script(&slh_holder).unwrap();
        let (v, invalid) = verdict_of(&mut f, &t);
        assert_eq!(v, verdict::OK);
        assert!(!invalid);
        assert!(f.token(&t.txid(), 0).is_some());
        below = t; // its P2PKH output 0 is a pre-height token
    }
    let pre_height_p2pkh = op(below.txid(), 0);
    while f.tip + 1 < falcon_height {
        let t = quote_next(&f);
        f.mine(t, Vec::new());
    }
    assert_eq!(f.tip + 1, falcon_height);

    // At the Falcon height: a P2PKH (or SLH-DSA PQPKH) token output of a MINT is bad-yed-holder.
    let m = f.mint_tx(10000, 48, f.tip - 1, o());
    let (v, invalid) = mint_verdict_of(&mut f, &m);
    assert_eq!(v, verdict::BAD_YED_HOLDER);
    assert!(invalid);
    let m = f.mint_tx(
        10000,
        48,
        f.tip - 1,
        MintOpts {
            token_script: pq_key_script(&slh_holder),
            ..o()
        },
    );
    assert_eq!(mv(&mut f, &m), verdict::BAD_YED_HOLDER);
    // A Falcon owner mints now (MINT-3), and a Falcon holder takes the token.
    let pq_mint = f.mint_tx(
        10000,
        48,
        f.tip - 1,
        MintOpts {
            pq_owner: Some(falcon_owner),
            token_script: Some(falcon_spk.clone()),
            ..o()
        },
    );
    assert_eq!(mv(&mut f, &pq_mint), "");
    let slh_falcon = f.mint_tx(
        10000,
        48,
        f.tip - 1,
        MintOpts {
            token_script: Some(falcon_spk.clone()),
            ..o()
        },
    );
    assert_eq!(mv(&mut f, &slh_falcon), ""); // SLH-DSA owner, Falcon holder
    assert_eq!(f.vault(&pq_mint.txid()).unwrap().owner(), falcon_owner);
    // D-Q-19: a hybrid channel holds YED from the Falcon height iff its client is a Falcon key.
    {
        let ch = channel(falcon_holder, &f, f.tip + 100);
        let m = f.mint_tx(
            10000,
            48,
            f.tip - 1,
            MintOpts {
                token_script: Some(ch),
                ..o()
            },
        );
        assert_eq!(mv(&mut f, &m), "");
        let ch = channel(slh_holder, &f, f.tip + 100);
        let m = f.mint_tx(
            10000,
            48,
            f.tip - 1,
            MintOpts {
                token_script: Some(ch),
                ..o()
            },
        );
        assert_eq!(mv(&mut f, &m), verdict::BAD_YED_HOLDER);
    }
    // The pre-height P2PKH token stays valid and spendable: a TRANSFER of it to a Falcon holder holds...
    {
        let mut t = f.transfer_tx(&[pre_height_p2pkh], &[Assignment::new(0, 6000)], false, 0);
        t.vout[0].script_pubkey = falcon_spk.clone();
        let (v, invalid) = verdict_of(&mut f, &t);
        assert_eq!(v, verdict::OK);
        assert!(!invalid);
        assert_eq!(f.token(&t.txid(), 0).unwrap().cents, 6000);
    }
    // ...while a TRANSFER (or a REDEEM payload with no vault) to P2PKH is refused, not burned.
    let ok_token;
    {
        let tok = op(pq_mint.txid(), 1);
        let t = f.transfer_tx(&[tok], &[Assignment::new(0, 10000)], false, 0); // P2PKH(userKey)
        let q = quote_next(&f);
        f.mine(q, vec![t.clone()]);
        assert_eq!(f.refused_verdict(&t.txid()), verdict::BAD_YED_HOLDER);
        assert!(f.token(&tok.txid, tok.n).is_some());
        let r = f.transfer_tx(
            &[tok],
            &[Assignment::new(0, 10000)],
            true,
            u32::try_from(f.tip - 1).unwrap(),
        );
        let q = quote_next(&f);
        f.mine(q, vec![r.clone()]);
        assert_eq!(f.refused_verdict(&r.txid()), verdict::BAD_YED_HOLDER);
        let mut ok = f.transfer_tx(&[tok], &[Assignment::new(0, 10000)], false, 0);
        ok.vout[0].script_pubkey = falcon_spk.clone();
        assert_eq!(verdict_of(&mut f, &ok).0, verdict::OK);
        ok_token = op(ok.txid(), 0);
    }
    // A vault-spending REDEEM whose YED change is P2PKH is refused too (RED-1's TOK-PQ clause).
    {
        let vault_id = pq_mint.txid();
        let yed = [op(slh_falcon.txid(), 1), ok_token]; // 10,000 + 10,000
        let so = || SpendOpts {
            assigned: vec![Assignment::new(3, 10000)],
            ..SpendOpts::default()
        };
        let p2pkh_change = f.spend_tx(&vault_id, &yed, f.tip - 1, so());
        let q = quote_next(&f);
        f.mine(q, vec![p2pkh_change.clone()]);
        assert_eq!(
            f.refused_verdict(&p2pkh_change.txid()),
            verdict::BAD_YED_HOLDER
        );
        assert_eq!(f.vault(&vault_id).unwrap().status, VaultStatus::Active);
        let mut pq_change = f.spend_tx(&vault_id, &yed, f.tip - 1, so());
        pq_change.vout[3].script_pubkey = falcon_spk.clone();
        let (v, invalid) = verdict_of(&mut f, &pq_change);
        assert_eq!(v, verdict::OK);
        assert!(!invalid);
        assert_eq!(f.vault(&vault_id).unwrap().status, VaultStatus::Closed);
        assert_eq!(f.token(&pq_change.txid(), 3).unwrap().cents, 10000);
    }
}

// Rule: MINT-4
// Rule: HALT-4
// Rule: HALT-1
#[test]
fn mint4_not_active_and_halts() {
    let mut f = Fixture::with(10, 0, 0, 3);
    f.mine_quotes_to(20, 50000); // the slow window is not filled yet: no price
    let m = f.mint_tx(
        10000,
        48,
        f.tip - 1,
        MintOpts {
            collateral: 1_000_000_000_000,
            ..o()
        },
    );
    assert_eq!(mv(&mut f, &m), "mint-halted-no-price");
    let m = f.mint_tx(
        10000,
        48,
        9,
        MintOpts {
            collateral: 1_000_000_000_000,
            fee_key: -1,
            ..o()
        },
    );
    assert_eq!(mv(&mut f, &m), "bad-mint-ref-height"); // R below START
    f.activate(50000);
    let m = f.mint_tx(10000, 48, f.tip - 1, o());
    assert_eq!(mv(&mut f, &m), "");
    // Non-signal tags halt nothing (v2's PARTICIPATION halt is gone).
    for _ in 0..26 {
        let t = Fixture::quote_with(50000, (f.tip + 1) % 3, false, 7);
        f.mine(Some(t), Vec::new());
    }
    assert_eq!(f.snap(f.tip).halt_mask, 0);
    let m = f.mint_tx(10000, 48, f.tip, o());
    assert_eq!(mv(&mut f, &m), "");
    // A refHeight whose snapshot was clear still mints (MINT-4 reads R, not H).
    let m = f.mint_tx(10000, 48, f.tip - 25, o());
    assert_eq!(mv(&mut f, &m), "");
    // No price: nine untagged blocks empty the fast window.
    for _ in 0..9 {
        f.mine_empty();
    }
    assert!(f.snap(f.tip).halt_mask & HALT_NO_PRICE != 0);
    let m = f.mint_tx(
        10000,
        48,
        f.tip - 1,
        MintOpts {
            collateral: 1_000_000_000_000,
            fee_key: 0,
            ..o()
        },
    );
    assert_eq!(mv(&mut f, &m), "mint-halted-no-price");
}

// Rule: MINT-4
#[test]
fn mint4_divergence_and_global_ratio() {
    let mut f = Fixture::new();
    f.activate(50000);
    f.mint_active10k();
    for _ in 0..8 {
        let t = Fixture::quote(15000, (f.tip + 1) % 3);
        f.mine(Some(t), Vec::new());
    }
    assert!(f.snap(f.tip).halt_mask & HALT_DIVERGENCE != 0);
    assert!(f.snap(f.tip).halt_mask & HALT_GLOBAL_RATIO != 0);
    let a = || MintOpts {
        collateral: 10_000_000_000_000,
        ..o()
    }; // class A, lock 48
    let c = || MintOpts {
        term_class: 2,
        ..a()
    }; // class C, lock 145
       // W16 / IT-5: class A is below the recap floor: GLOBAL_RATIO stops it, before DIVERGENCE
    let m = f.mint_tx(10000, 48, f.tip - 1, a());
    assert_eq!(mv(&mut f, &m), "mint-halted-global-ratio");
    // class C reaches the floor: through to the next halt, DIVERGENCE
    let m = f.mint_tx(10000, 145, f.tip - 1, c());
    assert_eq!(mv(&mut f, &m), "mint-halted-divergence");
    // Once the windows agree again the ratio is still low: class C mints, class A does not
    for _ in 0..64 {
        let t = Fixture::quote(15000, (f.tip + 1) % 3);
        f.mine(Some(t), Vec::new());
    }
    assert!(f.snap(f.tip).halt_mask & HALT_DIVERGENCE == 0);
    assert!(f.snap(f.tip).halt_mask & HALT_GLOBAL_RATIO != 0);
    let m = f.mint_tx(10000, 48, f.tip - 1, a());
    assert_eq!(mv(&mut f, &m), "mint-halted-global-ratio");
    let m = f.mint_tx(10000, 145, f.tip - 1, c());
    assert_eq!(mv(&mut f, &m), "");
}

// Rule: MINT-4
#[test]
fn mint4_requires_armed() {
    let mut f = Fixture::new();
    f.p.mint_requires_armed = true;
    f.mine_quotes_to(20, 50000); // no price yet: mint-halted-no-price precedes the new clause
    let m = f.mint_tx(
        10000,
        48,
        f.tip - 1,
        MintOpts {
            collateral: 1_000_000_000_000,
            ..o()
        },
    );
    assert_eq!(mv(&mut f, &m), "mint-halted-no-price");
    f.activate(50000);
    assert!(!f.armed());
    let m = f.mint_tx(10000, 48, f.tip - 1, o());
    let (v, invalid) = mint_verdict_of(&mut f, &m);
    assert_eq!(v, verdict::MINT_HALTED_UNARMED);
    assert!(invalid);
    assert_eq!(verdict::MINT_HALTED_UNARMED, "mint-halted-unarmed");
    let mut g = Fixture::new(); // the same chain without the parameter mints (v2 path)
    g.activate(50000);
    let m = g.mint_tx(10000, 48, g.tip - 1, o());
    assert_eq!(mv(&mut g, &m), "");
    // ARMED: the clause is vacuous; MINT-9 judges the bundle as before
    let mut a = Fixture::new();
    a.p.mint_requires_armed = true;
    a.arm(3, 50000);
    assert!(a.armed());
    let m = a.mint_tx(10000, 48, a.tip - 1, o());
    assert_eq!(mv(&mut a, &m), verdict::MINT9_NO_BUNDLE);
    let m = a.mint_v3(10000, 50000, o(), &none_skip(), 48);
    assert_eq!(mv(&mut a, &m), "");
    // ATTEST_REQUIRED false means never ARMED (W15): with the parameter nothing mints
    let mut off = Fixture::new();
    off.p.mint_requires_armed = true;
    off.p.attest_required = false;
    off.arm(3, 50000);
    assert!(!off.armed());
    let m = off.mint_tx(10000, 48, off.tip - 1, o());
    assert_eq!(mv(&mut off, &m), verdict::MINT_HALTED_UNARMED);
}

// Rule: MINT-2
#[test]
fn mint2_disabled_class_refused() {
    let mut f = Fixture::new();
    f.p.class_min[1] = 97;
    f.p.class_max[1] = 96; // B empty
    f.p.class_min[2] = 97;
    f.p.class_max[2] = 96; // C empty (the mainnet shape)
    f.activate(50000);
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
    for (lb, opts) in [(100, b()), (97, b()), (96, b()), (145, c())] {
        let m = f.mint_tx(10000, lb, f.tip - 1, opts);
        assert_eq!(mv(&mut f, &m), "bad-mint-lock-height");
    }
    let m = f.mint_tx(10000, 48, f.tip - 1, a());
    assert_eq!(mv(&mut f, &m), "");
}

// Rule: HALT-2
#[test]
fn recap_floor_is_the_class_minimum_with_sigma() {
    assert!(min_ratio_bps(50000, 10000) >= 50000);
    assert!(min_ratio_bps(40000, 10000) < 50000);
    assert!(min_ratio_bps(40000, 13000) >= 50000);
    assert!(min_ratio_bps(30000, 13000) < 50000);
}

// Rule: MINT-5
#[test]
fn mint5_collateral_and_unsatisfiable() {
    let mut f = Fixture::new();
    f.activate(50000);
    let m = f.mint_tx(
        10000,
        48,
        f.tip - 1,
        MintOpts {
            collateral: 600_000_000_000 - 1,
            ..o()
        },
    );
    assert_eq!(mv(&mut f, &m), "bad-mint-collateral"); // 300 %, D-IT-4
    let m = f.mint_tx(
        10000,
        48,
        f.tip - 1,
        MintOpts {
            collateral: 600_000_000_000,
            ..o()
        },
    );
    assert_eq!(mv(&mut f, &m), "");
    // At PRICE_MIN the maximum mint needs 5 x 10^16 zat > MAX_MONEY: unsatisfiable (K14).
    let mut g = Fixture::new();
    g.activate(PRICE_MIN);
    let m = g.mint_tx(
        1_000_000,
        48,
        g.tip - 1,
        MintOpts {
            collateral: MAX_MONEY,
            ..o()
        },
    );
    assert_eq!(mv(&mut g, &m), "mint-unsatisfiable");
    assert!(required_collateral(1_000_000, 50000, PRICE_MIN).is_none());
}

// Rule: MINT-7
#[test]
fn mint7_token_output_is_not_the_opreturn() {
    let mut f = Fixture::new();
    f.activate(50000);
    let mut m = f.mint_tx(10000, 48, f.tip - 1, o());
    m.vout.swap(1, 2); // OP_RETURN at vout[1]
    let (v, invalid) = mint_verdict_of(&mut f, &m);
    assert_eq!(v, "bad-mint-token-output");
    assert!(invalid);
}

// Rule: MINT-8
// Rule: FEE-0
// Rule: FEE-2
#[test]
fn mint8_fee_edges() {
    let mut f = Fixture::new();
    f.activate(50000);
    let m = f.mint_tx(10000, 48, f.tip - 1, MintOpts { fee_key: -1, ..o() });
    assert_eq!(mv(&mut f, &m), "bad-mint-fee"); // 0xFF with a non-empty E(R)
    let m = f.mint_tx(10000, 48, f.tip - 1, MintOpts { fee_key: 7, ..o() });
    assert_eq!(mv(&mut f, &m), "bad-mint-fee"); // not in E(R)
    let fee = f.mint_fee(10000, f.tip - 1) - 1;
    let m = f.mint_tx(
        10000,
        48,
        f.tip - 1,
        MintOpts {
            fee_value: fee,
            ..o()
        },
    );
    assert_eq!(mv(&mut f, &m), "bad-mint-fee");
    for fv in [0u8, 1, 2, 4] {
        // the vault, the token, the OP_RETURN, out of range
        let m = f.mint_tx(
            10000,
            48,
            f.tip - 1,
            MintOpts {
                fee_vout: fv,
                ..o()
            },
        );
        assert_eq!(mv(&mut f, &m), "bad-mint-fee", "feeVout {fv}");
    }
    let m = f.mint_tx(
        10000,
        48,
        f.tip - 1,
        MintOpts {
            fee_vout: 4,
            extra_outputs: 1,
            ..o()
        },
    );
    assert_eq!(mv(&mut f, &m), "bad-mint-fee"); // vout 4 is not the fee
                                                // Any key of E(R) is a valid payee, and a larger fee is fine.
    let key = (f.tip - 1 - 5) % 3;
    let m = f.mint_tx(
        10000,
        48,
        f.tip - 1,
        MintOpts {
            fee_key: key,
            ..o()
        },
    );
    assert_eq!(mv(&mut f, &m), "");
    let m = f.mint_tx(
        10000,
        48,
        f.tip - 1,
        MintOpts {
            fee_value: 100 * COIN,
            ..o()
        },
    );
    assert_eq!(mv(&mut f, &m), "");
    // FEE-0: with an empty E(R) the fee clause is vacuous; the fast window is empty too, so the
    // verdict is the price halt, never bad-mint-fee.
    for _ in 0..12 {
        f.mine_empty();
    }
    assert!(eligible_payees(&f.state, &f.p, f.tip - 1).is_empty());
    let m = f.mint_tx(
        10000,
        48,
        f.tip - 1,
        MintOpts {
            collateral: 1_000_000_000_000,
            fee_key: -1,
            ..o()
        },
    );
    assert_eq!(mv(&mut f, &m), "mint-halted-no-price");
    let m = f.mint_tx(
        10000,
        48,
        f.tip - 1,
        MintOpts {
            collateral: 1_000_000_000_000,
            fee_key: 7,
            fee_value: 1,
            ..o()
        },
    );
    assert_eq!(mv(&mut f, &m), "mint-halted-no-price");
}

// Rule: IN-3
// Rule: MINT-1
#[test]
fn in3_mint_with_yed_inputs_burns_them() {
    let mut f = Fixture::new();
    f.activate(50000);
    let first = f.mint_active10k();
    let m = f.mint_tx(
        20000,
        48,
        f.tip - 1,
        MintOpts {
            yed_inputs: vec![op(first, 1)],
            ..o()
        },
    );
    assert_eq!(mv(&mut f, &m), "");
    let log = f.log(&m.txid()).unwrap();
    assert_eq!(log.yed_in, 10000);
    assert_eq!(log.yed_out, 20000);
    assert_eq!(log.burned, 10000); // N19: the burn formula's yedOut is 0 for a mint
    assert_eq!(f.totals().supply_cents, 20000); // 10,000 + 20,000 - 10,000
    assert!(f.token(&first, 1).is_none());
}

// Rule: XFER-1
// Rule: XFER-2
// Rule: XFER-3
// Rule: IN-1
#[test]
fn xfer1_xfer2_xfer3_and_burns() {
    let mut f = Fixture::new();
    f.activate(50000);
    let mint = f.mint_active10k();
    // 6,000 + 4,000
    let t1 = f.transfer_tx(
        &[op(mint, 1)],
        &[Assignment::new(0, 6000), Assignment::new(1, 4000)],
        false,
        0,
    );
    f.mine(Some(Fixture::quote(50000, 0)), vec![t1.clone()]);
    let t1id = t1.txid();
    assert!(f.token(&mint, 1).is_none());
    assert_eq!(f.token(&t1id, 0).unwrap().cents, 6000);
    assert_eq!(f.token(&t1id, 1).unwrap().cents, 4000);
    assert_eq!(f.log(&t1id).unwrap().verdict, verdict::OK);
    assert_eq!(f.log(&t1id).unwrap().spent_tokens.len(), 1);
    assert_eq!(f.totals().supply_cents, 10000);
    // xfer2: over-assigned burns everything.
    let t2 = f.transfer_tx(&[op(t1id, 1)], &[Assignment::new(0, 5000)], false, 0);
    f.mine(Some(Fixture::quote(50000, 1)), vec![t2.clone()]);
    let t2id = t2.txid();
    assert_eq!(f.log(&t2id).unwrap().verdict, "transfer-over-assigned");
    assert_eq!(f.log(&t2id).unwrap().burned, 4000);
    assert!(f.token(&t2id, 0).is_none());
    assert_eq!(f.totals().supply_cents, 6000);
    // xfer1: an assignment below MIN_OUTPUT.
    let t3 = f.transfer_tx(
        &[op(t1id, 0)],
        &[Assignment::new(0, 99), Assignment::new(1, 5901)],
        false,
        0,
    );
    f.mine(Some(Fixture::quote(50000, 2)), vec![t3.clone()]);
    assert_eq!(
        f.log(&t3.txid()).unwrap().verdict,
        "bad-transfer-assignment"
    );
    assert_eq!(f.totals().supply_cents, 0);
    // xfer3: no YED input: nothing is created and nothing is logged (N7).
    let fi = f.fake_input();
    let t4 = f.transfer_tx(&[fi], &[Assignment::new(0, 100)], false, 0);
    f.mine(Some(Fixture::quote(50000, 0)), vec![t4.clone()]);
    assert!(f.log(&t4.txid()).is_none());
    assert!(f.token(&t4.txid(), 0).is_none());
    // A burn by rule: assigning less than the inputs is "burned".
    let m2 = f.mint_active10k();
    let t5 = f.transfer_tx(&[op(m2, 1)], &[Assignment::new(0, 9000)], false, 0);
    f.mine(Some(Fixture::quote(50000, 1)), vec![t5.clone()]);
    assert_eq!(f.log(&t5.txid()).unwrap().verdict, verdict::BURNED);
    assert_eq!(f.totals().supply_cents, 9000);
    // A payload-less transaction that spends a token burns it (type NONE, verdict burned).
    let t6 = MTx {
        vin: vec![txin(op(t5.txid(), 0))],
        vout: vec![txout(TOKEN_VALUE, f.user_p2pkh())],
        lock_time: 0,
    };
    f.mine(Some(Fixture::quote(50000, 2)), vec![t6.clone()]);
    assert_eq!(f.log(&t6.txid()).unwrap().verdict, verdict::BURNED);
    assert_eq!(f.log(&t6.txid()).unwrap().tx_type, TxLogType::None);
    assert_eq!(f.totals().supply_cents, 0);
}
