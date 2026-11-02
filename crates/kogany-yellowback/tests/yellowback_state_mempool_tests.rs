// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

//! The mempool-time check, `mempool_check_reason` (W5-d2; the pure half of ycash6
//! `src/yellowback/index.cpp` `MempoolCheckInner` at `65cb4ae0f`): the reasons of
//! `yellowback_index_tests.cpp` `mempoolcheck_bench` (MP-1) that do not need the index — the
//! index's unhealthy and storage-fault guards, the timing and the ConnectTip sweep stay with
//! W5-e / W6-c — plus the structural attestor-set refusal and the gates in front of the
//! relevance filter.

mod state_common;

use kogany_yellowback::state::{mempool_check_reason, verdict, MEMPOOL_EXPIRY};
use state_common::fixture::*;

fn check(f: &Fixture, m: &MTx, expiry: u32) -> Option<String> {
    mempool_check_reason(&f.state, &f.p, f.tip + 1, &m.tx(), expiry, None)
}

// Rule: MP-1
#[test]
fn mempool_check_reasons() {
    let mut f = Fixture::new();
    f.activate(50000);
    let v = f.mint_active10k();
    let r = f.tip - 1;
    let window = u32::try_from(r + i64::from(f.p.ref_window)).unwrap();
    // a plain transaction is not relevant: admitted without evaluation
    let (a, b) = (f.fake_input(), f.fake_input());
    let plain = MTx {
        vin: vec![txin(a), txin(b)],
        vout: vec![txout(1000, f.user_p2pkh())],
        lock_time: 0,
    };
    assert_eq!(check(&f, &plain, 0), None);
    // a well-formed owner redeem with the expiry bound is admitted
    let good = f.spend_tx(&v, &[op(v, 1)], r, SpendOpts::default());
    assert_eq!(check(&f, &good, window), None);
    // a malformed one is refused with its verdict, before the expiry bound is looked at
    let malformed = f.spend_tx(
        &v,
        &[],
        r,
        SpendOpts {
            payload: false,
            ..SpendOpts::default()
        },
    );
    assert_eq!(
        check(&f, &malformed, window).as_deref(),
        Some(verdict::VAULT_SPEND_MALFORMED)
    );
    assert_eq!(
        check(&f, &malformed, 0).as_deref(),
        Some(verdict::VAULT_SPEND_MALFORMED)
    );
    // no expiry, or one past refHeight + REF_WINDOW: mempool-expiry
    assert_eq!(check(&f, &good, 0).as_deref(), Some(MEMPOOL_EXPIRY));
    assert_eq!(
        check(&f, &good, window + 1).as_deref(),
        Some(MEMPOOL_EXPIRY)
    );
    // a mint spends no vault: never refused for its expiry
    let mint = f.mint_tx(10000, 48, r, MintOpts::default());
    assert_eq!(check(&f, &mint, 0), None);
    // the check matches the block verdict of the same transaction at the next height
    let ev = f.evaluate(Some(Fixture::quote(50000, 0)), &[malformed], None);
    assert!(ev.block_invalid);
    assert_eq!(ev.verdict, verdict::VAULT_SPEND_MALFORMED);
    // nothing is written: the state is unchanged
    let before = f.state.clone();
    let _ = check(&f, &good, window);
    assert!(f.state == before);
}

// Rule: P4-b
#[test]
fn mempool_check_refuses_attestor_set_act() {
    // Owner 2026-10-11: a SET_REMOVE of the attestor set is invalid (structural, ahead of the
    // relevance filter: an act is neither a payload nor a YED template).
    let mut f = Fixture::new();
    f.mine_quotes_to(20, 50000);
    f.register(2, 0);
    let rm = f.remove_tx(1, 0, false);
    assert_eq!(
        check(&f, &rm, 0).as_deref(),
        Some(verdict::ATTESTOR_SET_ACT)
    );
    // a heartbeat of the set is relevant and valid
    let hb = f.heartbeat_tx(0);
    assert_eq!(check(&f, &hb, 0), None);
    // a join below the module's bond floor is refused with the mirror's verdict
    let low = f.register_tx(2, 1, -1, None);
    assert_eq!(
        check(&f, &low, 0).as_deref(),
        Some(verdict::ATTESTOR_BOND_BELOW_MIN)
    );
}

#[test]
fn mempool_check_gates() {
    // below the start height and for a coinbase, the module admits everything
    let mut f = Fixture::with(50, 0, 0, 3);
    let r = f.tip - 1;
    let m = f.mint_tx(
        10000,
        48,
        r,
        MintOpts {
            collateral: 1_000_000_000_000,
            fee_key: 0,
            ..MintOpts::default()
        },
    );
    assert_eq!(
        mempool_check_reason(&f.state, &f.p, 10, &m.tx(), 0, None),
        None
    );
    assert!(mempool_check_reason(&f.state, &f.p, 50, &m.tx(), 0, None).is_some());
    let cb = Fixture::coinbase(51, None).tx();
    assert_eq!(mempool_check_reason(&f.state, &f.p, 51, &cb, 0, None), None);
}
