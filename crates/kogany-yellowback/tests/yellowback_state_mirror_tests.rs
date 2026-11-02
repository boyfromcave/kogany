// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

//! The attestor cases of ycash6 `src/test/yellowback_state_tests.cpp` at `65cb4ae0f` that run
//! through the state machine (W5-d2): P4-b's mirror of the attestor set (joins, rejoins,
//! dormancy, the seat eviction, the exhausted seq space), liveness, ARM-1/2, EQV-1's ejection,
//! S15 dormancy, PIN-1/2, IN-2's bond spend, seating, BUNDLE-1's selector and signature cache,
//! and R12. Each is a test of the same name over the ported `Fixture`; the C++ `// Rule:` tags
//! are kept.

mod state_common;

use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

use kogany_vault::act::{decode_act, encode_act, ActBody, SetJoinBody};
use kogany_vault::template::p2sh_script_pubkey;
use kogany_vault::Hash32;
use kogany_yellowback::attest::bundle::{sig_cache_key, SigCache};
use kogany_yellowback::attest::price::HALT_NO_PRICE;
use kogany_yellowback::attest::registry::{
    AttestStatus, AttestorStatus, BundleLogRecord, RegistryRead, ATTESTOR_FLAG_EVICTED,
};
use kogany_yellowback::attest::seats::outpoint_selector;
use kogany_yellowback::codecs::payload::{AttestorRegister, Payload};
use kogany_yellowback::codecs::script::bond_script;
use kogany_yellowback::params::COIN;
use kogany_yellowback::state::{
    armed_at, default_payee, eligible_payees, evaluate_block, verdict, PayeePolicy, TxLogType,
    VaultStatus, YedKey, YedRecord,
};
use state_common::fixture::*;

fn q(f: &Fixture) -> Option<kogany_yellowback::codecs::tag::CoinbaseTag> {
    Some(Fixture::quote(50000, (f.tip + 1) % 3))
}

fn tick(f: &mut Fixture) {
    let t = q(f);
    f.mine(t, Vec::new());
}

fn status(f: &Fixture, seq: u16) -> AttestorStatus {
    f.attestor(seq).unwrap().status
}

fn seated_has(f: &Fixture, seq: u16) -> bool {
    f.snap(f.tip).seated.contains(&seq)
}

/// `VerdictOf` with its `invalid` out-parameter.
fn verdict_and_invalid(f: &mut Fixture, m: &MTx) -> (String, bool) {
    let t = q(f);
    let ev = f.mine(t, vec![m.clone()]);
    let _ = ev;
    let refused = !f.refused_verdict(&m.txid()).is_empty();
    (
        f.log(&m.txid()).map_or("none".to_owned(), |l| l.verdict),
        refused,
    )
}

/// `LegacyRegisterTx`: the pre-P4-b ATTESTOR_REGISTER payload (invalid since P4-b).
fn legacy_register_tx(f: &mut Fixture, i: usize) -> MTx {
    let locktime = u32::try_from(f.tip + 1 + i64::from(f.p.bond_min_lock)).unwrap();
    let mut m = MTx::default();
    let fi = f.fake_input();
    m.vin.push(txin(fi));
    let key = f.hot_pub(i);
    m.vout.push(txout(
        10 * COIN,
        p2sh_script_pubkey(&bond_script(&key, locktime).unwrap()),
    ));
    m.vout
        .push(payload_out(&Payload::AttestorRegister(AttestorRegister {
            attestor_key: key,
            bond_key: key,
            bond_locktime: locktime,
            flags: 0,
        })));
    m.vout.push(txout(1000, f.user_p2pkh()));
    m
}

/// `MapSigCache`: an unbounded map that counts its hits.
#[derive(Default)]
struct MapSigCache {
    entries: Mutex<BTreeMap<Hash32, bool>>,
    hits: AtomicUsize,
}

impl SigCache for MapSigCache {
    fn lookup(&self, key: &Hash32) -> Option<bool> {
        let hit = self.entries.lock().unwrap().get(key).copied();
        if hit.is_some() {
            self.hits.fetch_add(1, Ordering::SeqCst);
        }
        hit
    }
    fn insert(&self, key: &Hash32, valid: bool) {
        self.entries.lock().unwrap().insert(*key, valid);
    }
}

// Rule: P4-b (§15.10): ATTESTOR_REGISTER and ATTESTOR_REVIVE are invalid; the registry is the
// primitive set
#[test]
fn p4b_register_and_revive_payloads_invalid() {
    let mut f = Fixture::new();
    f.mine_quotes_to(20, 50000);
    let reg = legacy_register_tx(&mut f, 0);
    let (v, invalid) = verdict_and_invalid(&mut f, &reg);
    assert_eq!(v, verdict::ATTESTOR_REGISTER_RETIRED);
    assert!(invalid);
    assert_eq!(
        f.refused_verdict(&reg.txid()),
        verdict::ATTESTOR_REGISTER_RETIRED
    );
    assert!(f.attestor(0).is_none());
    let a = f.att(0, 50000, f.tip, None);
    let rev = f.revive_tx(&a);
    assert_eq!(verdict_of(&mut f, &rev), verdict::ATTESTOR_REVIVE_RETIRED);
    assert_eq!(
        f.refused_verdict(&rev.txid()),
        verdict::ATTESTOR_REVIVE_RETIRED
    );
    // A block carrying either is invalid (BLK-1, U-21).
    let h = f.tip + 1;
    let l1 = legacy_register_tx(&mut f, 1);
    let block = vec![
        Fixture::coinbase(h, Some(&Fixture::quote(50000, 0))).tx(),
        l1.tx(),
    ];
    let ev = f.evaluate_raw(&block, h);
    assert!(ev.block_invalid);
    assert_eq!(ev.verdict, verdict::ATTESTOR_REGISTER_RETIRED);
}

// Rule: P4-b: the seat source is the set (SET_CREATE, SET_JOIN mirrored; maturity and the
// module's bond floor)
#[test]
fn p4b_join_mirrors_member() {
    let mut f = Fixture::new();
    f.mine_quotes_to(20, 50000);
    assert!(f.state.attestor_set().is_none());
    f.ensure_set();
    let z = f.state.attestor_set().unwrap();
    assert_eq!(i64::from(z.create_height), f.tip);
    assert_eq!(z.seats, 15);
    assert_eq!(z.maturity, 8); // BOND_MATURITY: the bond exit delay
    assert_eq!(
        f.log(&f.set_create.txid()).unwrap().tx_type,
        TxLogType::AttestorSetAct
    );
    // a join to another set is not mirrored
    {
        let locktime = u32::try_from(f.tip + 1 + i64::from(f.p.bond_min_lock)).unwrap();
        let key = f.hot_pub(0);
        let body = ActBody::Join(SetJoinBody {
            set_id: test_set(),
            member_key: key,
            bond_locktime: locktime,
            bond_vout: 0,
        });
        let bond = txout(
            10 * COIN,
            p2sh_script_pubkey(&bond_script(&key, locktime).unwrap()),
        );
        let other = f.act_tx(body, &[0], vec![bond]);
        assert_eq!(verdict_of(&mut f, &other), "none");
        assert!(f.attestor(0).is_none());
    }
    let lock = i64::from(f.p.bond_min_lock);
    let ok = f.register_tx(0, 10 * COIN, lock, None);
    assert_eq!(verdict_of(&mut f, &ok), verdict::OK);
    let rec = f.attestor(0).unwrap();
    let member = f.hot_pub(0);
    assert_eq!(rec.attestor_pub_key, member);
    assert_eq!(rec.bond_pub_key, rec.attestor_pub_key);
    assert_eq!(rec.status, AttestorStatus::Pending);
    assert_eq!(i64::from(rec.register_height), f.tip);
    assert_eq!(i64::from(rec.last_act), f.tip + 8); // joinHeight + the set's maturity
    assert_eq!(rec.bond_zat, 10 * COIN);
    assert_eq!(rec.flags, 0);
    assert!(!rec.bond_frozen);
    assert_eq!(rec.bond_outpoint, op(ok.txid(), 0));
    assert_eq!(f.state.bond_seq(&rec.bond_outpoint), Some(0));
    assert_eq!(f.state.next_seq(), 1);
    let log = f.log(&ok.txid()).unwrap();
    assert_eq!(log.tx_type, TxLogType::AttestorRegister);
    assert_eq!(log.attestor_seq, 0);
    // below the module's floor at its block: invalid since the seats re-review; BOND_MIN_LOCK is 0
    // since the bond exit delay, so a bond locked for one block qualifies
    let low = f.register_tx(1, 5 * COIN - 1, -1, None);
    assert_eq!(verdict_of(&mut f, &low), verdict::ATTESTOR_BOND_BELOW_MIN); // D-Q-30
    assert_eq!(f.state.next_seq(), 1);
    let r2 = f.register_tx(2, 10 * COIN, 0, None);
    assert_eq!(verdict_of(&mut f, &r2), verdict::OK);
    assert_eq!(f.state.next_seq(), 2);
    let joined0 = i64::from(f.attestor(0).unwrap().register_height);
    while f.tip < joined0 + i64::from(f.p.bond_maturity) - 1 {
        tick(&mut f);
    }
    assert_eq!(status(&f, 0), AttestorStatus::Pending);
    tick(&mut f); // registerHeight + max(maturity 8, BOND_MATURITY 8)
    assert_eq!(status(&f, 0), AttestorStatus::Eligible);
    assert_eq!(i64::from(f.attestor(0).unwrap().status_height), f.tip);
    for _ in 0..20 {
        tick(&mut f);
    }
    assert_eq!(status(&f, 1), AttestorStatus::Eligible);
    assert!(f.attestor(2).is_none());
}

// Rule: P4-b
// Rule: IN-2
#[test]
fn p4b_rejoin_after_withdraw_new_seq() {
    let mut f = Fixture::new();
    f.mine_quotes_to(20, 50000);
    f.register(1, 0);
    while f.tip < i64::from(f.attestor(0).unwrap().bond_locktime) {
        tick(&mut f);
    }
    let bs = f.bond_spend_tx(0);
    assert_eq!(verdict_of(&mut f, &bs), verdict::OK);
    assert_eq!(status(&f, 0), AttestorStatus::Withdrawn);
    // the same key joins again (the set allows a key that is not ACTIVE): a new seq, the old
    // record stays WITHDRAWN
    let again = f.register_tx(1, 10 * COIN, -1, Some(0));
    assert_eq!(verdict_of(&mut f, &again), verdict::OK);
    let r1 = f.attestor(1).unwrap();
    assert_eq!(r1.attestor_pub_key, f.attestor(0).unwrap().attestor_pub_key);
    assert_eq!(r1.status, AttestorStatus::Pending);
    // a heartbeat reaches the key's newest record only
    let last_act0 = f.attestor(0).unwrap().last_act;
    tick(&mut f);
    let hb = f.heartbeat_tx(0);
    assert_eq!(verdict_of(&mut f, &hb), verdict::OK);
    assert_eq!(i64::from(f.attestor(1).unwrap().last_act), f.tip);
    assert_eq!(f.attestor(0).unwrap().last_act, last_act0);
    let log = f.log(&hb.txid()).unwrap();
    assert_eq!(log.tx_type, TxLogType::AttestorSetAct);
    assert_eq!(log.attestor_seq, 1);
}

// Rule: P4-b: the set's member dormancy (lastAct < H - livenessWindow) and revival by
// SET_HEARTBEAT
#[test]
fn p4b_set_dormancy_and_heartbeat_revival() {
    let mut f = Fixture::new();
    f.recreate_set(20, 8, 15); // livenessWindow 20
    f.mine_quotes_to(20, 50000);
    f.register(1, 0);
    let joined = f.tip;
    let last_act = i64::from(f.attestor(0).unwrap().last_act);
    assert_eq!(last_act, joined + 8); // the set's maturity (BOND_MATURITY)
    while f.tip < joined + i64::from(f.p.bond_maturity) {
        tick(&mut f);
    }
    assert_eq!(status(&f, 0), AttestorStatus::Eligible);
    while f.tip < last_act + 20 {
        tick(&mut f);
    }
    assert_eq!(status(&f, 0), AttestorStatus::Eligible); // lastAct >= H - 20
    tick(&mut f);
    assert_eq!(status(&f, 0), AttestorStatus::Dormant);
    assert_eq!(i64::from(f.attestor(0).unwrap().status_height), f.tip);
    assert!(f.snap(f.tip).seated.is_empty());
    let hb = f.heartbeat_tx(0);
    assert_eq!(verdict_of(&mut f, &hb), verdict::OK);
    assert_eq!(status(&f, 0), AttestorStatus::Eligible); // at the heartbeat's own SNAP
    assert_eq!(i64::from(f.attestor(0).unwrap().last_act), f.tip);
    assert_eq!(f.snap(f.tip).seated, vec![0]);
    f.undo();
    assert_eq!(status(&f, 0), AttestorStatus::Dormant);
}

// Rule: P4-b: the module adopts only an OPEN attestor set of ATTESTOR_SEATS (15) seats
#[test]
fn p4b_attestor_set_adopted_only_open_15() {
    // OPEN, 15 seats, maturity BOND_MATURITY (8 on regtest): only variant 3 is adopted
    for variant in 0..4 {
        let mut f = Fixture::new();
        // 2 seats; closed; maturity 1; the one
        f.recreate_set(
            1_000_000,
            if variant == 2 { 1 } else { 8 },
            if variant == 0 { 2 } else { 15 },
        );
        if variant == 1 {
            let mut a = decode_act(&f.set_create.vout[0].script_pubkey).unwrap();
            if let ActBody::Create(c) = &mut a.body {
                c.flags = 0;
            }
            f.set_create.vout[0].script_pubkey = encode_act(&a);
            f.p.attestor_set_id = f.set_create.txid().0;
        }
        let t = q(&f);
        let sc = f.set_create.clone();
        f.mine(t, vec![sc]);
        assert_eq!(
            f.state.attestor_set().is_some(),
            variant == 3,
            "variant {variant}"
        );
    }
}

// Rule: seat ranking and eviction (owner 2026-10-11): the mirror of a join into the full set
#[test]
fn seat_eviction_mirror() {
    let mut f = Fixture::new();
    f.activate(50000);
    f.register(15, 0); // seq i = key i, one per block, 10 YEC each
    for i in 0..15 {
        assert!(f.attestor(i).is_some());
    }
    // equal bond: no eviction (the primitive refuses; the mirror, given the block anyway, leaves
    // every record alone)
    let eq = f.register_tx(15, 10 * COIN, -1, None);
    assert_eq!(verdict_of(&mut f, &eq), verdict::OK);
    for i in 0..15 {
        assert_ne!(status(&f, i), AttestorStatus::Withdrawn);
    }
    f.undo();
    // 11 YEC evicts the youngest 10-YEC member (seq 14): WITHDRAWN, flagged, bond neither frozen
    // nor spent
    let big = f.register_tx(15, 11 * COIN, -1, None);
    assert_eq!(verdict_of(&mut f, &big), verdict::OK);
    let r14 = f.attestor(14).unwrap();
    assert_eq!(r14.status, AttestorStatus::Withdrawn);
    assert_eq!(i64::from(r14.status_height), f.tip);
    assert!(r14.flags & ATTESTOR_FLAG_EVICTED != 0);
    assert!(!r14.bond_frozen);
    assert_eq!(r14.bond_spent_height, 0);
    assert_eq!(status(&f, 15), AttestorStatus::Pending);
    for i in 0..14 {
        assert_ne!(status(&f, i), AttestorStatus::Withdrawn);
    }
    // the evicted bond is spent later: still WITHDRAWN, statusHeight kept, bondSpentHeight set
    let evicted_at = f.tip;
    while f.tip < i64::from(f.attestor(14).unwrap().bond_locktime) {
        tick(&mut f);
    }
    let bs = f.bond_spend_tx(14);
    assert_eq!(verdict_of(&mut f, &bs), verdict::OK);
    let r14 = f.attestor(14).unwrap();
    assert_eq!(r14.status, AttestorStatus::Withdrawn);
    assert_eq!(i64::from(r14.status_height), evicted_at);
    assert_eq!(i64::from(r14.bond_spent_height), f.tip);
    // the evicted key can rejoin (a new seq) and is not barred: it is not slashed
    let rj = f.register_tx(16, 50 * COIN, -1, Some(14));
    assert_eq!(verdict_of(&mut f, &rj), verdict::OK);
    assert_eq!(
        f.attestor(16).unwrap().attestor_pub_key,
        f.attestor(14).unwrap().attestor_pub_key
    );
}

// Rule: seats review B2 (focused review): a bundle credits liveness only inside a held YED act,
// and only within REF_WINDOW of its refHeight
#[test]
fn liveness_needs_held_act_and_fresh_ref() {
    let mut f = Fixture::new();
    f.arm(3, 50000);
    let no_vault = u256s("11");
    let sel = outpoint_selector(&op(no_vault, 0));
    // a CLAIM_NOTICE of a vault that does not exist (not held) whose bundle would refresh
    // liveness: invalid
    let r = f.tip - 1;
    let b = f.bundle_simple(r, &sel, 50000);
    let bad = f.notice_tx(&no_vault, r, &b);
    let t = q(&f);
    f.mine(t, vec![bad.clone()]);
    assert_eq!(
        f.refused.get(&bad.txid()).unwrap().verdict,
        verdict::LIVENESS_UNHELD
    );
    // the same kind of notice at a refHeight older than REF_WINDOW credits nobody: an ordinary
    // transaction
    for _ in 0..f.p.ref_window + 2 {
        tick(&mut f);
    }
    let old = f.tip + 1 - i64::from(f.p.ref_window) - 1;
    let signers = f.selected(old, &sel);
    assert!(!signers.is_empty());
    let before: BTreeMap<u16, i32> = signers
        .iter()
        .map(|s| (*s, f.attestor(*s).unwrap().last_act))
        .collect();
    let b = f.bundle_simple(old, &sel, 50000);
    let replay = f.notice_tx(&no_vault, old, &b);
    let t = q(&f);
    f.mine(t, vec![replay.clone()]);
    assert!(!f.refused.contains_key(&replay.txid()));
    for s in &signers {
        assert_eq!(f.attestor(*s).unwrap().last_act, before[s]);
    }
}

// Rule: P4-b (focused review): once the u16 seq space is used up a SET_JOIN of the attestor set is
// invalid, so the primitive never admits a member the mirror cannot record
#[test]
fn attestor_seq_exhausted() {
    let mut f = Fixture::new();
    f.mine_quotes_to(20, 50000);
    f.register(1, 0); // seq 0
    f.put(YedKey::AttestorSeq, YedRecord::AttestorSeq(0xFFFF)); // forced: 65,534 joins later
    let r1 = f.register_tx(1, 10 * COIN, -1, None);
    assert_eq!(verdict_of(&mut f, &r1), verdict::OK); // the last seq, 65,535
    assert!(f.attestor(0xFFFF).is_some());
    assert_eq!(f.state.next_seq(), 0); // wrapped onto seq 0, which exists
    let r2 = f.register_tx(2, 10 * COIN, -1, None);
    assert_eq!(verdict_of(&mut f, &r2), verdict::ATTESTOR_SEQ_EXHAUSTED);
    assert_eq!(f.state.next_seq(), 0);
}

// Rule: ARM-1
#[test]
fn arm1_triggers_at_exact_block() {
    let mut f = Fixture::new();
    f.activate(50000);
    f.register(3, 0); // seq 2 registered at f.tip; ELIGIBLE at f.tip + BOND_MATURITY
    let third = f.tip;
    while f.tip < third + i64::from(f.p.bond_maturity) - 1 {
        tick(&mut f);
    }
    assert_eq!(status(&f, 2), AttestorStatus::Pending);
    assert_eq!(f.attest().status, AttestStatus::Unarmed);
    tick(&mut f);
    assert_eq!(status(&f, 2), AttestorStatus::Eligible);
    assert_eq!(i64::from(f.attestor(2).unwrap().status_height), f.tip);
    let a = f.attest();
    assert_eq!(a.status, AttestStatus::Triggered);
    assert_eq!(i64::from(a.trigger_height), f.tip);
    assert_eq!(
        i64::from(a.arm_height),
        f.tip + i64::from(f.p.attest_arm_delay)
    );
    assert_eq!(f.snap(f.tip).attest.status, AttestStatus::Triggered);
    assert!(!f.armed());
    // attestArmMin 0 never arms
    let mut g = Fixture::with(1, 0, 0, 0);
    g.activate(50000);
    g.register(3, 0);
    for _ in 0..20 {
        tick(&mut g);
    }
    assert_eq!(g.attest().status, AttestStatus::Unarmed);
}

// Rule: ARM-2
#[test]
fn arm2_arms_after_delay() {
    let mut f = Fixture::new();
    f.activate(50000);
    f.register(3, 0);
    while f.attest().status != AttestStatus::Triggered {
        tick(&mut f);
    }
    let arm = i64::from(f.attest().arm_height);
    while f.tip < arm - 1 {
        tick(&mut f);
    }
    assert_eq!(f.attest().status, AttestStatus::Triggered);
    assert!(!armed_at(&f.state, &f.p, f.tip));
    tick(&mut f);
    assert_eq!(f.tip, arm);
    assert_eq!(f.attest().status, AttestStatus::Armed);
    assert!(armed_at(&f.state, &f.p, f.tip));
    assert!(!armed_at(&f.state, &f.p, f.tip - 1));
}

// Rule: ARM-1
// Rule: ARM-2
#[test]
fn arm_never_reverses() {
    let mut f = Fixture::new();
    f.arm(3, 50000);
    let before = f.attest();
    // Eject every attestor: fewer than ATTEST_ARM_MIN remain ELIGIBLE, the layer stays ARMED.
    for seq in 0..3 {
        let cited = f.tip;
        tick(&mut f);
        let (a, b) = (
            f.att(seq, 50000, cited, None),
            f.att(seq, 52000, cited, None),
        );
        let e = f.equivocation_tx(&a, &b);
        assert_eq!(verdict_of(&mut f, &e), verdict::OK);
    }
    for _ in 0..10 {
        tick(&mut f);
    }
    assert_eq!(f.attest(), before);
    assert!(f.snap(f.tip).seated.is_empty());
    assert!(f.armed());
    // and a mint now needs a bundle nobody can sign
    let r = f.tip - 1;
    let m = f.mint_tx(10000, 48, r, MintOpts::default());
    assert_eq!(mv(&mut f, &m), verdict::MINT9_NO_BUNDLE);
}

// Rule: EQV-1
#[test]
fn eqv1_two_prices_one_hash_ejects() {
    let mut f = Fixture::new();
    f.arm(3, 50000);
    let cited = f.tip;
    tick(&mut f);
    // same price: not an equivocation; different seq: no; different cited heights: no
    for (a, b) in [
        (f.att(1, 50000, cited, None), f.att(1, 50000, cited, None)),
        (f.att(1, 50000, cited, None), f.att(2, 51000, cited, None)),
        (
            f.att(1, 50000, cited, None),
            f.att(1, 51000, cited - 1, None),
        ),
    ] {
        let e = f.equivocation_tx(&a, &b);
        assert_eq!(verdict_of(&mut f, &e), "none");
    }
    assert_eq!(status(&f, 1), AttestorStatus::Eligible);
    let (a, b) = (f.att(1, 50000, cited, None), f.att(1, 51000, cited, None));
    let e = f.equivocation_tx(&a, &b);
    assert_eq!(verdict_of(&mut f, &e), verdict::OK);
    let r1 = f.attestor(1).unwrap();
    assert_eq!(r1.status, AttestorStatus::Ejected);
    assert_eq!(i64::from(r1.status_height), f.tip);
    assert!(r1.bond_frozen); // P4-b: the set's frozen-bond rule
    let log = f.log(&e.txid()).unwrap();
    assert_eq!(log.tx_type, TxLogType::Equivocation);
    assert_eq!(log.attestor_seq, 1);
    // an ejected attestor leaves seated at the next SNAP and cannot be ejected twice
    assert!(!seated_has(&f, 1));
    let (a, b) = (f.att(1, 50000, cited, None), f.att(1, 52000, cited, None));
    let e2 = f.equivocation_tx(&a, &b);
    assert_eq!(verdict_of(&mut f, &e2), "none");
    // EQUIVOCATION bundles never enter BundleLog (R12)
    assert!(f.bundle_row(f.tip - 1).is_none());
}

// Rule: EQV-1
#[test]
fn eqv1_fork_hashes_not_equivocation() {
    let mut f = Fixture::new();
    f.arm(3, 50000);
    let cited = f.tip;
    tick(&mut f);
    // Two honest prices for the same height on two forks: the second signature is over another
    // block hash and does not verify here.
    let other = Hash32([0x99; 32]);
    let (a, b) = (
        f.att(2, 50000, cited, None),
        f.att(2, 51000, cited, Some(other)),
    );
    let e = f.equivocation_tx(&a, &b);
    assert_eq!(verdict_of(&mut f, &e), "none");
    assert_eq!(status(&f, 2), AttestorStatus::Eligible);
    // a cited height the index does not know
    let (a, b) = (
        f.att(2, 50000, f.tip + 5, None),
        f.att(2, 51000, f.tip + 5, None),
    );
    let e = f.equivocation_tx(&a, &b);
    assert_eq!(verdict_of(&mut f, &e), "none");
}

fn mint_v3_skip(f: &mut Fixture, skip: &BTreeSet<u16>) -> MTx {
    f.mint_v3(10000, 50000, MintOpts::default(), skip, 48)
}

// Rule: SNAP
#[test]
fn dormancy_needs_selection_evidence() {
    let mut f = Fixture::new();
    f.arm(4, 50000);
    // Rows where L signed count as evidence of life; rows where it was not selected are no
    // evidence at all.
    let mut l: Option<u16> = None;
    let mut signed_rows = 0;
    while signed_rows < 3 {
        let r = f.tip - 1;
        let sel = f.selected(r, &[]);
        let lv = *l.get_or_insert(sel[0]);
        let m = mint_v3_skip(&mut f, &none_skip());
        assert_eq!(mv(&mut f, &m), "");
        if sel.contains(&lv) {
            signed_rows += 1;
        }
    }
    let l = l.unwrap();
    for _ in 0..2 * f.p.dormancy_blocks {
        tick(&mut f);
    }
    for s in 0..4 {
        assert_eq!(status(&f, s), AttestorStatus::Eligible);
    }
    // One unsigned row is below DORMANCY_MIN_BUNDLES.
    loop {
        let r = f.tip - 1;
        if f.selected(r, &[]).contains(&l) {
            let m = mint_v3_skip(&mut f, &BTreeSet::from([l]));
            assert_eq!(mv(&mut f, &m), "");
            break;
        }
        tick(&mut f);
    }
    for _ in 0..f.p.dormancy_check {
        tick(&mut f);
    }
    assert_eq!(status(&f, l), AttestorStatus::Eligible);
}

// Rule: SNAP
#[test]
fn dormancy_unseated_never_dormant() {
    let mut f = Fixture::new();
    f.activate(50000);
    f.register(6, 0);
    while !f.attest().is_armed() {
        tick(&mut f);
    }
    assert_eq!(f.attestor(5).unwrap().seated_since, 0); // ties by seq: seq 5 is never seated
    for i in 0..2 * f.p.dormancy_blocks {
        if i % 3 == 0 {
            let m = mint_v3_skip(&mut f, &none_skip());
            let _ = mv(&mut f, &m);
        } else {
            tick(&mut f);
        }
    }
    assert_eq!(status(&f, 5), AttestorStatus::Eligible);
    assert_eq!(f.attestor(5).unwrap().seated_since, 0);
}

// Rule: SNAP
#[test]
fn dormancy_only_at_check_heights() {
    let mut f = Fixture::new();
    f.arm(4, 50000);
    for _ in 0..f.p.dormancy_blocks {
        tick(&mut f);
    }
    let check = i64::from(f.p.dormancy_check);
    let min_bundles = f.p.dormancy_min_bundles;
    let mut l: Option<u16> = None;
    let mut rows = 0;
    while rows < min_bundles {
        let r = f.tip - 1;
        let sel = f.selected(r, &[]);
        let lv = *l.get_or_insert(sel[0]);
        if sel.contains(&lv) && (rows < min_bundles - 1 || (f.tip + 1) % check != 0) {
            let m = mint_v3_skip(&mut f, &BTreeSet::from([lv]));
            assert_eq!(mv(&mut f, &m), "");
            rows += 1;
        } else {
            tick(&mut f);
        }
    }
    let l = l.unwrap();
    // The evidence is complete at a non-check height: nothing happens until H mod DORMANCY_CHECK == 0.
    assert_ne!(f.tip % check, 0);
    assert_eq!(status(&f, l), AttestorStatus::Eligible);
    while f.tip % check != 0 {
        tick(&mut f);
        if f.tip % check != 0 {
            assert_eq!(status(&f, l), AttestorStatus::Eligible);
        }
    }
    let rec = f.attestor(l).unwrap();
    assert_eq!(rec.status, AttestorStatus::Dormant);
    assert_eq!(i64::from(rec.status_height), f.tip);
    tick(&mut f);
    assert_eq!(f.attestor(l).unwrap().seated_since, 0); // cleared when it leaves seated
}

fn row(a: i64) -> BundleLogRecord {
    BundleLogRecord {
        a_mint: a,
        a_claim: a,
        ..BundleLogRecord::default()
    }
}

fn put_row(f: &mut Fixture, h: i64, r: BundleLogRecord) {
    f.put(
        YedKey::BundleLog(u32::try_from(h).unwrap()),
        YedRecord::BundleLog(r),
    );
}

// Rule: PIN-1
#[test]
fn pin1_arms_from_bundlelog() {
    let mut f = Fixture::new();
    f.activate(50000);
    // Two rows in W whose aMint spread exceeds PIN_DELTA_BPS arm PIN-1; a key with >= PIN_MIN_TAGS
    // quotes all at one price is pinned.
    let t = f.tip;
    put_row(&mut f, t - 3, row(50000));
    put_row(&mut f, t - 1, row(53000)); // 6 % > 5 %
    f.mine(Some(Fixture::quote(50000, 0)), Vec::new());
    assert_eq!(f.snap(f.tip).pinned_keys.len(), 3); // every pool quoted 50,000: all three pinned
    assert!(f.snap(f.tip).halt_mask & HALT_NO_PRICE != 0); // nothing left for the medians
                                                           // 5 % exactly is not enough
    let mut g = Fixture::new();
    g.activate(50000);
    let t = g.tip;
    put_row(&mut g, t - 3, row(50000));
    put_row(&mut g, t - 1, row(52500));
    g.mine(Some(Fixture::quote(50000, 0)), Vec::new());
    assert!(g.snap(g.tip).pinned_keys.is_empty());
    // a row outside W does not count
    let mut h = Fixture::new();
    h.activate(50000);
    let t = h.tip;
    let w = i64::from(h.p.pin_window);
    put_row(&mut h, t - w, row(50000)); // h = H - 1 - PIN_WINDOW: excluded
    put_row(&mut h, t - 1, row(53000));
    h.mine(Some(Fixture::quote(50000, 0)), Vec::new());
    assert!(h.snap(h.tip).pinned_keys.is_empty());
}

// Rule: PIN-1
// Rule: FEE-2
// Rule: PRICE-1
#[test]
#[allow(non_snake_case)] // the C++ case name
fn pin1_excludes_key_from_medians_and_E() {
    let mut f = Fixture::new();
    f.activate(50000);
    // Pool 0 repeats 50,000; pools 1 and 2 move (49,000 / 51,000 alternating) for a full slow window.
    for i in 0..70 {
        let key = (f.tip + 1) % 3;
        let price = match key {
            0 => 50000,
            1 => 49000 + (i % 2) * 10,
            _ => 51000 + (i % 2) * 10,
        };
        f.mine(Some(Fixture::quote(price, key)), Vec::new());
    }
    let t = f.tip;
    put_row(&mut f, t - 3, row(50000));
    put_row(&mut f, t - 1, row(53000));
    f.mine(Some(Fixture::quote(50000, 0)), Vec::new());
    let s = f.snap(f.tip);
    assert_eq!(s.pinned_keys, vec![key_of(0)]);
    // the medians no longer see 50,000: pFast over pools 1 and 2 only (the slow window's 2/3 fill
    // is then one short: pMint undefined, HALT-1)
    assert_ne!(s.p_fast, 50000);
    assert!(s.p_fast > 0);
    assert!(s.halt_mask & HALT_NO_PRICE != 0);
    // E(H) excludes the pinned key; E(H - 1) still has it
    let e = eligible_payees(&f.state, &f.p, f.tip);
    assert!(!e.contains(&key_of(0)));
    assert_eq!(e.len(), 2);
    assert!(eligible_payees(&f.state, &f.p, f.tip - 1).contains(&key_of(0)));
    // and FEE-W never picks it
    for i in 0..8u8 {
        let pick =
            default_payee(&f.state, &f.p, f.tip, &[i], &PayeePolicy::defaults(&f.p)).unwrap();
        assert_ne!(pick, key_of(0));
    }
}

// Rule: PIN-1
// Rule: PIN-2
#[test]
fn pin_not_armed_without_bundles() {
    let mut f = Fixture::new();
    f.arm(4, 50000);
    for _ in 0..8 {
        let t = Some(Fixture::quote(40000, (f.tip + 1) % 3));
        f.mine(t, Vec::new());
    }
    assert_eq!(f.snap(f.tip).pmint(), Some(40000));
    // The price step arms PIN-2's test, but with no BundleLog rows nothing is pinned; PIN-1 needs
    // rows to arm at all.
    let s = f.snap(f.tip);
    assert!(s.pinned_seqs.is_empty());
    assert!(s.pinned_keys.is_empty());
    // One row is below PIN_MIN_BUNDLES for PIN-1, and one appearance below PIN_MIN_TAGS for PIN-2.
    let r = BundleLogRecord {
        a_mint: 40000,
        a_claim: 40000,
        selected_seqs: vec![0, 1, 2],
        seqs: vec![0, 1, 2],
        prices: vec![40000, 40000, 40000],
        cited_heights: vec![9, 9, 9],
    };
    let t = f.tip;
    put_row(&mut f, t, r);
    let t = Some(Fixture::quote(40000, (f.tip + 1) % 3));
    f.mine(t, Vec::new());
    assert!(f.snap(f.tip).pinned_seqs.is_empty());
    assert!(f.snap(f.tip).pinned_keys.is_empty());
}

// Rule: PIN-1
#[test]
fn pin1_ignores_undefined_amint() {
    // Audit A-4: a row whose aMint is stored as 0 is not the window minimum; two rows at one price
    // plus the 0 row leave PIN-1 unarmed.
    let mut f = Fixture::new();
    f.activate(50000);
    let t = f.tip;
    put_row(&mut f, t - 3, row(0));
    put_row(&mut f, t - 2, row(50000));
    put_row(&mut f, t - 1, row(50000));
    f.mine(Some(Fixture::quote(50000, 0)), Vec::new());
    assert!(f.snap(f.tip).pinned_keys.is_empty());
    assert!(f.snap(f.tip).halt_mask & HALT_NO_PRICE == 0);
}

// Rule: IN-2
#[test]
fn in2_bond_spend_withdraws() {
    let mut f = Fixture::new();
    f.arm(3, 50000);
    while f.tip < i64::from(f.attestor(1).unwrap().bond_locktime) {
        tick(&mut f);
    }
    let sp = f.bond_spend_tx(1);
    assert_eq!(verdict_of(&mut f, &sp), verdict::OK);
    let rec = f.attestor(1).unwrap();
    assert_eq!(rec.status, AttestorStatus::Withdrawn);
    assert_eq!(i64::from(rec.status_height), f.tip);
    assert_eq!(i64::from(rec.bond_spent_height), f.tip);
    assert_eq!(rec.seated_since, 0); // left seated at this SNAP
    assert!(!seated_has(&f, 1));
    // relevant, but no payload family
    assert_eq!(f.log(&sp.txid()).unwrap().tx_type, TxLogType::None);
    assert!(f.state.bond_seq(&rec.bond_outpoint).is_some()); // the index row stays with the record
    f.undo();
    assert_eq!(status(&f, 1), AttestorStatus::Eligible);
}

// Rule: SNAP
#[test]
fn seated_since_tracks_seating() {
    let mut f = Fixture::new();
    f.activate(50000);
    f.register(3, 0);
    let reg0 = i64::from(f.attestor(0).unwrap().register_height);
    let maturity = i64::from(f.p.bond_maturity);
    while f.tip < reg0 + maturity - 1 {
        tick(&mut f);
    }
    assert_eq!(f.attestor(0).unwrap().seated_since, 0);
    tick(&mut f);
    assert_eq!(status(&f, 0), AttestorStatus::Eligible);
    assert_eq!(i64::from(f.attestor(0).unwrap().seated_since), f.tip); // seated the SNAP it became ELIGIBLE
    assert_eq!(f.snap(f.tip).seated, vec![0]);
    for _ in 0..5 {
        tick(&mut f);
    }
    assert_eq!(
        i64::from(f.attestor(0).unwrap().seated_since),
        reg0 + maturity
    ); // unchanged while seated
       // eject: leaves seated at that SNAP, seatedSince cleared
    let cited = f.tip;
    tick(&mut f);
    let (a, b) = (f.att(0, 50000, cited, None), f.att(0, 51000, cited, None));
    let e = f.equivocation_tx(&a, &b);
    assert_eq!(verdict_of(&mut f, &e), verdict::OK);
    assert_eq!(f.attestor(0).unwrap().seated_since, 0);
}

// Rule: BUNDLE-1
// Rule: MINT-9
#[test]
fn selection_ignores_owner_key() {
    let mut f = Fixture::new();
    f.arm(4, 50000);
    // Two mints at one R with different owner keys share selected(R, ""): one bundle serves both.
    let r = f.tip - 1;
    let other = pubkey(&det_secret("selection-ignores-owner-key", 0));
    let m1 = f.mint_v3(10000, 50000, MintOpts::default(), &none_skip(), 48);
    let m2 = f.mint_v3(
        10000,
        50000,
        MintOpts {
            owner: Some(other),
            ..MintOpts::default()
        },
        &none_skip(),
        48,
    );
    let t = q(&f);
    let ev = f.mine(t, vec![m1.clone(), m2.clone()]);
    assert!(!ev.block_invalid);
    assert_eq!(f.vault(&m1.txid()).unwrap().status, VaultStatus::Active);
    assert_eq!(f.vault(&m2.txid()).unwrap().status, VaultStatus::Active);
    assert_eq!(
        f.log(&m1.txid()).unwrap().bundle_seqs,
        f.log(&m2.txid()).unwrap().bundle_seqs
    );
    // the v2 FEE-W selector (the owner key) would have been a free grind: it is not the selector
    assert_eq!(f.selected(r, &[]).len(), 3);
    assert_eq!(f.selected(r, &other.0).len(), 3);
}

// Rule: BUNDLE-1
#[test]
fn cache_hit_equals_cold() {
    let mut f = Fixture::new();
    f.arm(3, 50000);
    let cache = MapSigCache::default();
    let m = f.mint_v3(10000, 50000, MintOpts::default(), &none_skip(), 48);
    let h = f.tip + 1;
    let block = vec![
        Fixture::coinbase(h, Some(&Fixture::quote(50000, h % 3))).tx(),
        m.tx(),
    ];
    let eval = |c: Option<&dyn SigCache>| {
        evaluate_block(&f.state, &f.p, &block, h, &fake_hash(h), SUBSIDY, c)
    };
    // cold: the block fills the cache with one entry per attestation
    let a = eval(Some(&cache));
    assert_eq!(cache.entries.lock().unwrap().len(), 3);
    // the liveness credit and its whole-BUNDLE-1 check re-read BUNDLE-1's three entries
    assert_eq!(cache.hits.load(Ordering::SeqCst), 6);
    assert!(cache.entries.lock().unwrap().values().all(|v| *v));
    // hit: the same block again reads the cache and agrees byte for byte
    let b = eval(Some(&cache));
    assert_eq!(cache.hits.load(Ordering::SeqCst), 15); // 6 + 3 (BUNDLE-1) + 6 (liveness)
    assert_eq!(a.snapshot.encode(), b.snapshot.encode());
    assert_eq!(a.txlogs[0].1.encode(), b.txlogs[0].1.encode());
    assert_eq!(a.txlogs[0].1.verdict, verdict::OK);
    // and without any cache the verdict is the same
    let c = eval(None);
    assert_eq!(a.txlogs[0].1.encode(), c.txlogs[0].1.encode());
    // the same attestation on two branches keys two entries: the block hash of citedHeight is in
    // the key, and the key binds the public key
    let att = f.att(0, 50000, f.tip - 1, None);
    let (pk0, pk1) = (f.hot_pub(0), f.hot_pub(1));
    assert_ne!(
        sig_cache_key(&att, &fake_hash(f.tip - 1), &pk0),
        sig_cache_key(&att, &fake_hash(f.tip), &pk0)
    );
    assert_ne!(
        sig_cache_key(&att, &fake_hash(f.tip - 1), &pk0),
        sig_cache_key(&att, &fake_hash(f.tip - 1), &pk1)
    );
    // a poisoned entry is believed (the cache is trusted node-local state): the invariant is that
    // entries are only ever written by verification
    for v in cache.entries.lock().unwrap().values_mut() {
        *v = false;
    }
    let d = eval(Some(&cache));
    assert_eq!(d.txlogs[0].1.verdict, "mint9-bundle-sig");
}

// Rule: R12
// Rule: NOT-1
#[test]
fn r12_failing_notice_leaves_no_bundle_row() {
    // 03/M-2 (R12 hardened): a CLAIM_NOTICE that does not hold -- here because a notice already
    // stands -- is a valid no-op, and its verified bundle of already-credited attestations adds no
    // BundleLog[H] row; one carrying a fresh attestation is LIVENESS_UNHELD.
    let mut g = EmergencyFixture::new(64);
    let r = g.f.tip - 1;
    assert!(g.post_notice(None));
    assert!(g.f.bundle_row(g.f.tip).is_some()); // the held notice's row
    let standing = g.f.notice(&g.w).unwrap();
    let w = g.w;
    let b = g.f.bundle_simple(r, &g.selector(), g.att_price);
    let again = g.f.notice_tx(&w, r, &b); // the same R: nothing fresh
    let t = g.quote();
    g.f.mine(t, vec![again.clone()]);
    assert_eq!(g.f.refused_verdict(&again.txid()), "");
    assert!(g.f.bundle_row(g.f.tip).is_none());
    assert_eq!(g.f.notice(&w).unwrap().height, standing.height); // not replaced
    let fresh = g.f.tip - 1;
    let b = g.f.bundle_simple(fresh, &g.selector(), g.att_price);
    let third = g.f.notice_tx(&w, fresh, &b);
    let t = g.quote();
    g.f.mine(t, vec![third.clone()]);
    assert_eq!(g.f.refused_verdict(&third.txid()), verdict::LIVENESS_UNHELD);
}
