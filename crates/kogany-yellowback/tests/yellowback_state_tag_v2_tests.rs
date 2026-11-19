// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

//! Tag v2, a post-quantum payout key (docs/plans/beta4/price-feed.md §4.3, §4.5 D-3, D-4, D-7):
//! ycash-dd `src/test/yellowback_state_tests.cpp` `tag_v2_fee_payees` and
//! `tag_v2_malformed_is_no_tag_block_valid` (ycash-dd #207), case for case over the ported
//! `Fixture`; the C++ `// Rule:` tags are kept.

mod state_common;

use kogany_vault::template::{PQ_SCHEME_FN_DSA_512, PQ_SCHEME_SLH_DSA_SHA2_128S};
use kogany_yellowback::codecs::script::p2pkh_script;
use kogany_yellowback::codecs::tag::{CoinbaseTag, Payee, TAG_VERSION_V2};
use kogany_yellowback::state::{
    default_payee, eligible_payees, verdict, PayeePolicy, VaultStatus, YedRead,
};
use state_common::fixture::*;

/// `v2Window`: one payee window plus one of v2-only quotes, FN-DSA and SLH-DSA alternating.
fn v2_window(f: &mut Fixture, price: i64) {
    for i in 0..=f.p.payee_window {
        let scheme = if i % 2 == 1 {
            PQ_SCHEME_SLH_DSA_SHA2_128S
        } else {
            PQ_SCHEME_FN_DSA_512
        };
        f.mine(Some(Fixture::quote_v2(price, scheme)), Vec::new());
    }
}

fn script(p: &Payee) -> Vec<u8> {
    p.script().unwrap()
}

fn mint_with_fee(f: &mut Fixture, fee_script: Vec<u8>) -> MTx {
    let r = f.tip - 1;
    f.mint_tx(
        10000,
        48,
        r,
        MintOpts {
            fee_script: Some(fee_script),
            ..MintOpts::default()
        },
    )
}

// Tag v2 (D-3, D-4): with only v2 quotes in the payee window, a MINT, an owner REDEEM and a claim
// REDEEM paying the 35-byte script of an eligible post-quantum payee hold, and a P2PKH in its
// place is refused (bad-mint-fee; vault-spend-bad-payee on both redeem paths); with v1 and v2 in
// the window both kinds pay.
// Rule: MINT-8, RED-3, FEE-2
#[test]
fn tag_v2_fee_payees() {
    let mut f = Fixture::new();
    f.activate(50000);
    let fn_dsa = pq_payee(PQ_SCHEME_FN_DSA_512);
    let slh = pq_payee(PQ_SCHEME_SLH_DSA_SHA2_128S);
    let owned = f.mint_active10k(); // minted from a v1 window; redeemed from a v2 one below
    v2_window(&mut f, 50000);
    {
        let e = eligible_payees(&f.state, &f.p, f.tip);
        assert!(e.len() == 2 && e.contains(&fn_dsa) && e.contains(&slh));
        let t = f.state.tag(u32::try_from(f.tip).unwrap()).unwrap();
        assert!(t.payee == slh || t.payee == fn_dsa);
    }
    // MINT-8 (D-3): the FN-DSA payee's TX_PQPKH holds; a P2PKH (a v1 key, not in E(R)) is
    // bad-mint-fee
    let m = mint_with_fee(&mut f, p2pkh_script(&key_of(0)));
    assert_eq!(mint_verdict_of(&mut f, &m).0, "bad-mint-fee");
    let m = mint_with_fee(&mut f, script(&fn_dsa));
    assert_eq!(m.vout[3].script_pubkey.len(), 35);
    assert_eq!(mint_verdict_of(&mut f, &m).0, "");
    let l = f.log(&m.txid()).unwrap();
    assert!(l.has_payee && l.payee == fn_dsa);
    // a payee script one byte off (an unknown scheme) is not a payee
    let mut bad = script(&fn_dsa);
    bad[33] = 0x53; // OP_3
    let m = mint_with_fee(&mut f, bad);
    assert_eq!(mint_verdict_of(&mut f, &m).0, "bad-mint-fee");

    // RED-3' owner path (D-3): P2PKH refused vault-spend-bad-payee, the SLH-DSA payee holds
    v2_window(&mut f, 50000);
    let tip = f.tip;
    let tx = f.spend_tx(
        &owned,
        &[op(owned, 1)],
        tip,
        SpendOpts {
            fee_script: Some(p2pkh_script(&key_of(0))),
            ..SpendOpts::default()
        },
    );
    assert_eq!(spend(&mut f, &owned, &tx).verdict, "vault-spend-bad-payee");
    let r = f.tip - 1;
    let tx = f.spend_tx(
        &owned,
        &[op(owned, 1)],
        r,
        SpendOpts {
            fee_script: Some(script(&slh)),
            ..SpendOpts::default()
        },
    );
    let res = spend(&mut f, &owned, &tx);
    assert_eq!(res.verdict, verdict::OK);
    assert!(res.log.has_payee && res.log.payee == slh);
    assert_eq!(res.vault.status, VaultStatus::Closed);

    // D-4: v1 and v2 quotes in the window: E(R) lists both kinds, and a fee to either holds
    for _ in 0..f.p.payee_window / 2 {
        f.mine(
            Some(Fixture::quote_v2(50000, PQ_SCHEME_FN_DSA_512)),
            Vec::new(),
        );
    }
    for _ in 0..f.p.payee_window / 2 {
        f.mine(Some(Fixture::quote(50000, 1)), Vec::new());
    }
    {
        let e = eligible_payees(&f.state, &f.p, f.tip - 1);
        assert!(e.contains(&fn_dsa) && e.contains(&pk(1)));
        let a = mint_with_fee(&mut f, script(&fn_dsa));
        assert_eq!(mint_verdict_of(&mut f, &a).0, "");
        let b = mint_with_fee(&mut f, p2pkh_script(&key_of(1)));
        assert_eq!(mint_verdict_of(&mut f, &b).0, "");
    }

    // RED-3' claim path (D-3): crash the price, then a v2-only window; P2PKH refused
    // vault-spend-bad-payee, FN-DSA holds
    for _ in 0..f.p.payee_window {
        let t = Fixture::quote(50000, (f.tip + 1) % 3);
        f.mine(Some(t), Vec::new());
    }
    let w = f.mint_active10k();
    for _ in 0..64 {
        let t = Fixture::quote(9000, (f.tip + 1) % 3);
        f.mine(Some(t), Vec::new());
    }
    v2_window(&mut f, 9000);
    assert_eq!(f.snap(f.tip).pclaim(), Some(9000));
    let tip = f.tip;
    let tx = f.spend_tx(
        &w,
        &[op(w, 1)],
        tip,
        SpendOpts {
            owner_path: false,
            fee_script: Some(p2pkh_script(&key_of(0))),
            ..SpendOpts::default()
        },
    );
    assert_eq!(spend(&mut f, &w, &tx).verdict, "vault-spend-bad-payee");
    let r = f.tip - 1;
    let tx = f.spend_tx(
        &w,
        &[op(w, 1)],
        r,
        SpendOpts {
            owner_path: false,
            fee_script: Some(script(&fn_dsa)),
            ..SpendOpts::default()
        },
    );
    let res = spend(&mut f, &w, &tx);
    assert_eq!(res.verdict, verdict::OK);
    assert_eq!(res.log.path, "claim");
    assert!(res.log.has_payee && res.log.payee == fn_dsa);
    assert_eq!(res.vault.status, VaultStatus::Claiming);
}

// D-7: a v2 tag with an unknown scheme (0x03) is no tag, and the block stays valid (TAG-4):
// applied, nothing recorded at its height.
// Rule: TAG-2, TAG-4
#[test]
fn tag_v2_malformed_is_no_tag_block_valid() {
    let mut f = Fixture::new();
    f.activate(50000);
    let mut bad = pq_payee(PQ_SCHEME_FN_DSA_512);
    bad.kind = 0x03;
    let t = CoinbaseTag {
        flags: 0x01,
        price_micro_usd: 50000,
        source_mask: 7,
        payee: bad,
    };
    assert_eq!(t.version(), TAG_VERSION_V2);
    assert!(!t.is_valid());
    let ev = f.evaluate(Some(t), &[], None);
    assert!(!ev.block_invalid);
    let h = f.tip + 1;
    f.mine(Some(t), Vec::new());
    assert_eq!(f.tip, h);
    assert!(f.state.tag(u32::try_from(h).unwrap()).is_none());
    assert!(!f.snap(h).tagged);
    // a good v2 tag at the next height is recorded with its payee
    f.mine(
        Some(Fixture::quote_v2(50000, PQ_SCHEME_SLH_DSA_SHA2_128S)),
        Vec::new(),
    );
    assert_eq!(
        f.state.tag(u32::try_from(f.tip).unwrap()).unwrap().payee,
        pq_payee(PQ_SCHEME_SLH_DSA_SHA2_128S)
    );
    assert!(f.snap(f.tip).tagged);
}

/// `Selector(i)`: 33 bytes shaped like an owner key, `0x02 ‖ i` little-endian (N28).
fn selector(i: i32) -> Vec<u8> {
    let mut s = vec![0u8; 33];
    s[0] = 0x02;
    s[1] = (i & 0xff) as u8;
    s[2] = ((i >> 8) & 0xff) as u8;
    s
}

// beta4 P1 follow-up (policy, FEE-W): a draw for a transaction at a height where Falcon is not
// active skips the FN-DSA payees of E(R), the preference included, while another payee is
// eligible; with only FN-DSA payees, or no transaction height, or Falcon active, nothing is
// skipped. The rules are unchanged (MINT-8 still accepts an FN-DSA payee).
// Rule: FEE-W
#[test]
fn feew_skips_fn_dsa_payees_before_falcon() {
    let mut f = Fixture::new();
    f.activate(50000);
    let fn_dsa = pq_payee(PQ_SCHEME_FN_DSA_512);
    let slh = pq_payee(PQ_SCHEME_SLH_DSA_SHA2_128S);
    v2_window(&mut f, 50000);
    let r = f.tip;
    let mut e = eligible_payees(&f.state, &f.p, r);
    e.sort();
    let mut both = vec![fn_dsa, slh];
    both.sort();
    assert_eq!(e, both);
    assert_eq!(f.p.pq_falcon_height, -1, "the fixture has no Falcon height");

    let picks = |f: &Fixture, pp: &PayeePolicy| {
        (0..200)
            .map(|i| default_payee(&f.state, &f.p, r, &selector(i), pp).unwrap())
            .collect::<std::collections::BTreeSet<Payee>>()
    };
    let view = PayeePolicy::defaults(&f.p);
    let next = PayeePolicy {
        tx_height: Some(r + 1),
        ..view
    };
    assert_eq!(picks(&f, &view), both.iter().copied().collect());
    assert_eq!(picks(&f, &next), [slh].into_iter().collect());
    let prefer_fn = PayeePolicy {
        preferred: Some(fn_dsa),
        ..next
    };
    assert_eq!(picks(&f, &prefer_fn), [slh].into_iter().collect());
    let prefer_fn_view = PayeePolicy {
        preferred: Some(fn_dsa),
        ..view
    };
    assert_eq!(picks(&f, &prefer_fn_view), [fn_dsa].into_iter().collect());

    // Falcon active at the transaction's height: nothing is skipped.
    f.p.pq_falcon_height = i32::try_from(r + 1).unwrap();
    assert_eq!(picks(&f, &next), both.iter().copied().collect());
    let before = PayeePolicy {
        tx_height: Some(r),
        ..view
    };
    assert_eq!(picks(&f, &before), [slh].into_iter().collect());
    f.p.pq_falcon_height = -1;

    // Only FN-DSA payees in E(R): the draw keeps them (the rules accept them).
    for _ in 0..=f.p.payee_window {
        f.mine(
            Some(Fixture::quote_v2(50000, PQ_SCHEME_FN_DSA_512)),
            Vec::new(),
        );
    }
    let r2 = f.tip;
    assert_eq!(eligible_payees(&f.state, &f.p, r2), vec![fn_dsa]);
    let next2 = PayeePolicy {
        tx_height: Some(r2 + 1),
        ..view
    };
    assert_eq!(
        default_payee(&f.state, &f.p, r2, &selector(1), &next2),
        Some(fn_dsa)
    );
}
