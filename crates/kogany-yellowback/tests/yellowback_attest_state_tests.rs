// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

//! The attest cases of ycash6 `src/test/yellowback_state_tests.cpp` (weights, seats, eviction,
//! W9 selection, the AFEE-W payee, the founding cohort, adoption of the attestor set), C++ names
//! kept, plus the registry mirror's rules (set acts, bond spends, EQV-1, liveness, the SNAP
//! passes) on the attestor half of that file's fixture ([`attest_common::chain::MiniChain`]).
//! The cases that need mints, prices or vaults stay with the state machine (W5-d).

mod attest_common;
mod common;

use attest_common::chain::{act_tx, det_key, fake_hash, set_create_body, MiniChain};
use attest_common::{carrier_in, enc, signed_att, u256s};
use kogany_vault::act::{
    act_msg, encode_act, encode_payload, sign_recoverable, Act, ActBody, SetHeartbeatBody,
    SetRemoveBody, SetWindDownBody,
};
use kogany_vault::state::{VaultTx, VaultTxIn, VaultTxOut};
use kogany_vault::{Hash32, OutPoint, PubKeyBytes};
use kogany_yellowback::attest::mirror::{
    apply_bond_spend, apply_equivocation, apply_liveness_credits, attestor_join_refused,
    current_member_seq, latest_record, mirror_live_member, refused_attestor_set_act, SetActEffect,
    ATTESTOR_BOND_BELOW_MIN, ATTESTOR_SEQ_EXHAUSTED,
};
use kogany_yellowback::attest::registry::{
    key_attest, key_attestor, key_attestor_set, key_bond_index, key_bundle_log, AttestState,
    AttestStatus, AttestorRecord, AttestorSetRecord, AttestorStatus, BundleLogRecord, Registry,
    RegistryRead, RegistryWrite, ATTESTOR_FLAG_EVICTED,
};
use kogany_yellowback::attest::seats::{
    age_origin, arm_pass, attestor_weight, default_attest_payee, dormancy_due, dormancy_pass,
    eviction_victim, outpoint_selector, pin1_triggered, pin2_pinned_seqs, pin2_triggered,
    seat_rank, seated, select_attestors, selected, SeatCandidate,
};
use kogany_yellowback::attest::{attestation_liveness, equivocation_evidence, Equivocation};
use kogany_yellowback::codecs::payload::{
    encode_payload as encode_yed_payload, payload_script, ClaimNotice, Payload,
};
use kogany_yellowback::math::U256;
use kogany_yellowback::params::{regtest_params, COIN};

fn h32(hex: &str) -> Hash32 {
    u256s(hex)
}

#[test]
fn selected_matches_python() {
    // The vectors of test_framework/test_yellowback_attest.py SelectionTests (select_attestors).
    let bh_ab = h32(&"ab".repeat(32));
    let bh_01 = h32(&"01".repeat(32));
    let u = U256::from_u64;
    let pool = [(3u16, u(3)), (1, u(1)), (2, u(2))];
    assert_eq!(select_attestors(&bh_ab, &[], &pool, 3), vec![2, 1, 3]);
    assert_eq!(select_attestors(&bh_ab, &[], &pool, 1), vec![2]);
    let sel = outpoint_selector(&OutPoint {
        txid: h32(&"11".repeat(32)),
        n: 1,
    });
    assert_eq!(hex::encode(&sel), format!("{}01000000", "1".repeat(64)));
    assert_eq!(select_attestors(&bh_ab, &sel, &pool, 3), vec![3, 2, 1]);
    // 256-bit modulus: three bonds of 2^70; a 64-bit pick would choose seq 1 first.
    let big = U256::ONE.wrapping_shl(70);
    assert_eq!(
        select_attestors(&bh_01, &[], &[(1, big), (2, big), (3, big)], 3),
        vec![3, 1, 2]
    );
    // zero and short pools
    let zeros = [
        (9u16, U256::ZERO),
        (4, U256::ZERO),
        (6, U256::ZERO),
        (1, U256::ZERO),
    ];
    assert_eq!(select_attestors(&bh_ab, &[], &zeros, 3), vec![1, 4, 6]);
    assert_eq!(
        select_attestors(&bh_ab, &[], &[(9, U256::ZERO), (4, u(5))], 3),
        vec![4, 9]
    );
    assert_eq!(select_attestors(&bh_ab, &[], &[(5, u(1))], 3), vec![5]);
    assert!(select_attestors(&bh_ab, &[], &[], 3).is_empty());
}

#[test]
fn seat_eviction_victim_rule() {
    let p = regtest_params(1, 0, 0, u256s("5e7").0);
    let key = |i: u32| det_key("yellowback-evict", i);
    let cand = |i: u32, bond: i64, join: i64, last_act: i64| SeatCandidate {
        key: key(i),
        bond_zat: bond,
        join_height: join,
        last_act,
    };
    let (h, lw) = (100_000i64, 1000i64);
    // all live: the least seat weight, only above x1.05
    let mut m = vec![
        cand(0, 20 * COIN, h - 8064, h),
        cand(1, 8 * COIN, h - 8064, h),
        cand(2, 8 * COIN, h - 10, h),
    ];
    assert_eq!(eviction_victim(&m, h, 8 * COIN, lw, &p), None); // equal bond, no tenure: never
    assert_eq!(eviction_victim(&m, h, 9 * COIN, lw, &p), Some(key(2))); // the youngest 8 YEC
    assert_eq!(eviction_victim(&m, h, 8 * COIN * 105 / 100, lw, &p), None);
    // 1.5x beats a one-week member, loses to a one-year member
    assert!(eviction_victim(&[cand(0, 6 * COIN, h - 8064, h)], h, 9 * COIN, lw, &p).is_some());
    assert!(eviction_victim(&[cand(0, 6 * COIN, h - 420_480, h)], h, 9 * COIN, lw, &p).is_none());
    // a new 20,000 YEC bond beats 8,000 YEC at any tenure
    assert!(eviction_victim(
        &[cand(0, 8000 * COIN, h - 10 * 420_480, h)],
        h,
        20_000 * COIN,
        lw,
        &p
    )
    .is_some());
    // a member that is not live goes first, with any bond at the module's floor -- never below it
    m.push(cand(3, 1000 * COIN, h - 420_480, h - lw - 1));
    assert_eq!(
        eviction_victim(&m, h, p.bond_min_floor_zat, lw, &p),
        Some(key(3))
    );
    assert_eq!(
        eviction_victim(&m, h, p.bond_min_floor_zat - 1, lw, &p),
        None
    );
    m[3].last_act = h - lw; // lastAct = H - LW is live
    assert_eq!(eviction_victim(&m, h, p.bond_min_floor_zat, lw, &p), None);
    // among the not-live, the least weight; ties by key bytes
    m.push(cand(4, 10 * COIN, h - 420_480, h - lw - 5));
    m[3].last_act = h - lw - 1;
    assert_eq!(
        eviction_victim(&m, h, p.bond_min_floor_zat, lw, &p),
        Some(key(4))
    );
    let (k5, k6) = (key(5), key(6));
    let lo = if k5.0 < k6.0 { k5 } else { k6 };
    let tie = [cand(5, 8 * COIN, h - 50, h), cand(6, 8 * COIN, h - 50, h)];
    assert_eq!(eviction_victim(&tie, h, 100 * COIN, lw, &p), Some(lo));
    assert_eq!(eviction_victim(&[], h, 100 * COIN, lw, &p), None);
}

#[test]
fn weight_clamped_before_trigger() {
    let mut rec = AttestorRecord::new(det_key("w", 0));
    rec.bond_zat = 10 * COIN;
    rec.register_height = 100;
    let p = regtest_params(1, 0, 0, u256s("5e7").0);
    let m = AttestState {
        status: AttestStatus::Triggered,
        trigger_height: 150,
        arm_height: 0,
    };
    let bond = U256::from_i64(10 * COIN);
    assert_eq!(attestor_weight(&rec, &m, &p, 149), U256::ZERO); // before the shared origin
    assert_eq!(attestor_weight(&rec, &m, &p, 150), U256::ZERO);
    assert_eq!(attestor_weight(&rec, &m, &p, 151), bond);
    assert_eq!(
        attestor_weight(&rec, &m, &p, 150 + i64::from(p.age_cap) + 500),
        bond.wrapping_mul(U256::from_i64(i64::from(p.age_cap)))
    );
    assert_eq!(
        attestor_weight(&rec, &AttestState::default(), &p, 99),
        U256::ZERO
    );
    assert_eq!(
        attestor_weight(&rec, &AttestState::default(), &p, 101),
        bond
    );
}

#[test]
fn founding_cohort_origin() {
    let mut f = MiniChain::new();
    f.register(3, 0);
    while f.attest.status != AttestStatus::Triggered {
        f.mine(&[]);
    }
    let trigger = i64::from(f.attest.trigger_height);
    // A registrant inside FOUNDING_WINDOW is founding; one a block later is not.
    while f.tip < trigger + i64::from(f.p.founding_window) - 1 {
        f.mine(&[]);
    }
    f.register(1, 3); // registerHeight == trigger + FOUNDING_WINDOW
    f.register(1, 4); // registerHeight == trigger + FOUNDING_WINDOW + 1
    let m = f.attest;
    assert_eq!(age_origin(&f.attestor(0), &m, &f.p), trigger);
    assert_eq!(age_origin(&f.attestor(3), &m, &f.p), trigger);
    assert_eq!(
        age_origin(&f.attestor(4), &m, &f.p),
        i64::from(f.attestor(4).register_height)
    );
    assert!(i64::from(f.attestor(4).register_height) > trigger + i64::from(f.p.founding_window));
    // Before the trigger the origin is the registration itself.
    assert_eq!(
        age_origin(&f.attestor(0), &AttestState::default(), &f.p),
        i64::from(f.attestor(0).register_height)
    );
    // Seq 0 and seq 3 share the origin, so they weigh the same; seq 4 is lighter.
    let h = f.tip + 30;
    assert_eq!(
        attestor_weight(&f.attestor(0), &m, &f.p, h),
        attestor_weight(&f.attestor(3), &m, &f.p, h)
    );
    assert!(
        attestor_weight(&f.attestor(4), &m, &f.p, h) < attestor_weight(&f.attestor(0), &m, &f.p, h)
    );
}

#[test]
fn seating_ties_by_seq() {
    let mut f = MiniChain::new();
    f.register(6, 0); // one per block: seq 0 is the oldest
    while f.attestor(5).status != AttestorStatus::Eligible {
        f.mine(&[]);
    }
    // Every bond is 10 YEC and all six are founding, so weights tie: the five lowest seq are seated.
    f.empty(3);
    assert_ne!(f.attest.status, AttestStatus::Unarmed);
    let expect = vec![0u16, 1, 2, 3, 4];
    assert_eq!(f.bases[&f.tip].seated, expect);
    assert_eq!(
        seated(
            &f.reg.attestors(),
            f.reg.attestor_set().as_ref(),
            &f.attest,
            &f.p,
            f.tip
        ),
        expect
    );
    assert_eq!(f.attestor(5).seated_since, 0);
    assert!(f.attestor(4).seated_since > 0);
    // The hysteresis: a seated record ranks x(1 + SEAT_MARGIN) of an unseated equal one.
    let (r4, r5) = (
        seat_rank(&f.attestor(4), &f.attest, &f.p, f.tip),
        seat_rank(&f.attestor(5), &f.attest, &f.p, f.tip),
    );
    assert!(r4 > r5 || f.p.seat_margin_bps <= 0);
}

#[test]
fn selected_excludes_pinned() {
    let mut f = MiniChain::new();
    f.arm(5);
    let r = f.tip;
    let s = f.bases[&r].clone();
    assert_eq!(s.seated.len(), 5);
    for trial in 0..5u16 {
        // Pin seq `trial` at R (the stored array is what Selected reads, R11): never drawn.
        let mut pinned = s.clone();
        pinned.pinned_seqs = vec![trial];
        let got = selected(Some(&pinned), &f.reg, &f.p, r, &[]);
        assert_eq!(got.len(), 3);
        assert!(!got.contains(&trial));
    }
    assert_eq!(selected(Some(&s), &f.reg, &f.p, r, &[]).len(), 3);
    assert!(selected(f.bases.get(&(r + 1)), &f.reg, &f.p, r + 1, &[]).is_empty()); // no snapshot
    assert!(selected(Some(&s), &f.reg, &f.p, 0, &[]).is_empty()); // below the start height
}

#[test]
#[allow(non_snake_case)]
fn default_attest_payee_in_A() {
    let mut f = MiniChain::new();
    f.arm(4);
    let r = f.tip - 1;
    let a = selected(f.bases.get(&r), &f.reg, &f.p, r, &[]);
    let bh = f.block_hash(r).unwrap_or_default();
    let pick = default_attest_payee(&bh, &[], &a, None).unwrap();
    assert!(a.contains(&pick));
    assert_eq!(default_attest_payee(&bh, &[], &a, None), Some(pick)); // deterministic
    let last = *a.last().unwrap();
    assert_eq!(default_attest_payee(&bh, &[], &a, Some(last)), Some(last));
    assert!(a.contains(&default_attest_payee(&bh, &[], &a, Some(99)).unwrap()));
    assert_eq!(default_attest_payee(&bh, &[], &[], None), None);
}

#[test]
fn attestor_set_adopted_only_with_threshold_one() {
    // 03/I-3: the cancel and unlock thresholds are pinned at 1; W3-Y-3: rateLimitBps at 0.
    for variant in 0..4 {
        let mut body = set_create_body();
        match variant {
            0 => body.cancel_threshold = 2,
            1 => body.unlock_threshold = 2,
            2 => body.rate_limit_bps = 1,
            _ => {}
        }
        let mut f = MiniChain::with_create(body);
        let c = f.set_create.clone();
        f.mine(&[c]);
        assert_eq!(
            f.reg.attestor_set().is_some(),
            variant == 3,
            "variant {variant}"
        );
    }
    // Other shapes the module does not adopt: closed, another seat count, another maturity, a
    // liveness window below ATTESTOR_LIVENESS_MIN; and a SET_CREATE that is not attestorSetId.
    for variant in 0..5 {
        let mut body = set_create_body();
        match variant {
            0 => body.flags = 0,
            1 => body.seats = 14,
            2 => body.maturity = 9,
            3 => body.liveness_window = 15,
            _ => {}
        }
        let mut f = MiniChain::with_create(body);
        let c = if variant == 4 {
            act_tx(ActBody::Create(body), Vec::new(), 77)
        } else {
            f.set_create.clone()
        };
        f.mine(&[c]);
        assert!(f.reg.attestor_set().is_none(), "variant {variant}");
    }
    // Adopted once: a second SET_CREATE with the same txid changes nothing.
    let mut f = MiniChain::new();
    f.ensure_set();
    let z = f.reg.attestor_set().unwrap();
    assert_eq!(
        z,
        AttestorSetRecord {
            create_height: 100,
            seats: 15,
            maturity: 8,
            liveness_window: 1_000_000
        }
    );
    let c = f.set_create.clone();
    assert_eq!(f.last_effect(&c), None);
}

#[test]
fn mirror_join_heartbeat_remove() {
    let mut f = MiniChain::new();
    let seqs = f.register(2, 0);
    assert_eq!(seqs, vec![0, 1]);
    let r0 = f.attestor(0);
    assert_eq!(r0.attestor_pub_key, f.hot_key(0));
    assert_eq!(r0.bond_pub_key, f.hot_key(0));
    assert_eq!(r0.bond_zat, 10 * COIN);
    assert_eq!(r0.register_height, 101);
    assert_eq!(r0.last_act, 101 + 8); // registerHeight + the set's maturity
    assert_eq!(r0.status, AttestorStatus::Pending);
    assert_eq!(f.reg.bond_seq(&r0.bond_outpoint), Some(0));
    assert_eq!(f.reg.next_seq(), 2);
    // maturity: ELIGIBLE at registerHeight + max(set maturity, BOND_MATURITY)
    while f.tip < 101 + 8 - 1 {
        f.mine(&[]);
        assert_eq!(f.attestor(0).status, AttestorStatus::Pending);
    }
    f.mine(&[]);
    assert_eq!(f.attestor(0).status, AttestorStatus::Eligible);
    assert_eq!(f.attestor(0).status_height, 109);
    assert_eq!(current_member_seq(&f.reg, &f.hot_key(0), 109), Some(0));
    assert_eq!(current_member_seq(&f.reg, &f.hot_key(1), 109), None); // registered at 102
                                                                      // SET_HEARTBEAT: lastAct = h on the key's newest record
    let set_id = Hash32(f.p.attestor_set_id);
    let hb = act_tx(
        ActBody::Heartbeat(SetHeartbeatBody {
            set_id,
            member_key: f.hot_key(1),
        }),
        vec![],
        500,
    );
    f.mine(&[hb]);
    assert_eq!(f.attestor(1).last_act, i32::try_from(f.tip).unwrap());
    // A member's own exit (burn 0): WITHDRAWN; an unknown key: nothing.
    let exit = remove_tx(&f, 1, 0, true);
    assert!(!refused_attestor_set_act(&exit, &f.p));
    f.mine(&[exit]);
    assert_eq!(f.attestor(1).status, AttestorStatus::Withdrawn);
    assert_eq!(f.attestor(1).status_height, i32::try_from(f.tip).unwrap());
    // Rejoin: a new seq for the same key; the newest record mirrors the member.
    f.register(1, 1);
    assert_eq!(latest_record(&f.reg, &f.hot_key(1)).unwrap().0, 2);
    // IN-2: a bond spend withdraws (once) and records the height; EJECTED keeps its status.
    let bond0 = f.attestor(0).bond_outpoint;
    assert_eq!(apply_bond_spend(&mut f.reg, &bond0, 300), Some(0));
    assert_eq!(f.attestor(0).status, AttestorStatus::Withdrawn);
    assert_eq!(f.attestor(0).bond_spent_height, 300);
    assert_eq!(apply_bond_spend(&mut f.reg, &bond0, 301), None);
    assert_eq!(
        apply_bond_spend(&mut f.reg, &OutPoint::default(), 301),
        None
    );
}

/// A SET_REMOVE of hot key `i` with `burn`, signed by itself when `own`.
fn remove_tx(f: &MiniChain, i: usize, burn: u8, own: bool) -> VaultTx {
    let body = ActBody::Remove(SetRemoveBody {
        set_id: Hash32(f.p.attestor_set_id),
        member_key: f.hot_key(i),
        burn,
    });
    let vin0 = OutPoint {
        txid: Hash32([0xab; 32]),
        n: u32::try_from(i).unwrap(),
    };
    let signer = if own { f.hot[i] } else { f.hot[(i + 1) % 20] };
    let sig = sign_recoverable(&signer, &act_msg(&encode_payload(&body), &vin0)).unwrap();
    let outputs = vec![VaultTxOut {
        value: 0,
        script_pubkey: encode_act(&Act {
            body,
            sigs: vec![sig],
        }),
    }];
    VaultTx {
        txid: attest_common::chain::txid_of(&outputs, 9000 + u64::try_from(i).unwrap()),
        coinbase: false,
        inputs: vec![VaultTxIn {
            prevout: vin0,
            script_sig: vec![],
        }],
        outputs,
    }
}

#[test]
fn p4b_slashed_key_barred_remove_winddown_refused() {
    let mut f = MiniChain::new();
    f.register(3, 0);
    f.empty(10);
    let set_id = Hash32(f.p.attestor_set_id);
    // A SET_REMOVE by others, a SET_REMOVE with burn, and a SET_WINDDOWN are refused.
    assert!(refused_attestor_set_act(&remove_tx(&f, 0, 0, false), &f.p));
    assert!(refused_attestor_set_act(&remove_tx(&f, 0, 1, true), &f.p));
    let wd = act_tx(ActBody::WindDown(SetWindDownBody { set_id }), vec![], 600);
    assert!(refused_attestor_set_act(&wd, &f.p));
    assert_eq!(f.mine(&[wd]), vec!["attestor-set-act".to_owned()]);
    // ... but not of another set.
    let other = act_tx(
        ActBody::WindDown(SetWindDownBody {
            set_id: u256s("42"),
        }),
        vec![],
        601,
    );
    assert!(!refused_attestor_set_act(&other, &f.p));
    // A burnt remove applied to the mirror (as the primitive would never let through, stated for
    // totality) ejects and freezes; the slashed key is barred for good on rejoin.
    let burn = remove_tx(&f, 0, 1, true);
    assert_eq!(f.last_effect(&burn), Some(SetActEffect::Acted(0)));
    assert_eq!(f.attestor(0).status, AttestorStatus::Ejected);
    assert!(f.attestor(0).bond_frozen);
    let seq = f.register(1, 0)[0];
    f.empty(20);
    assert_eq!(f.attestor(seq).status, AttestorStatus::Pending); // never ELIGIBLE
    assert_eq!(current_member_seq(&f.reg, &f.hot_key(0), f.tip), Some(seq)); // still a member of the set
}

#[test]
fn mirror_join_refusals_and_eviction() {
    // Below the module's bond floor (BondMinZat at the join's height): invalid.
    let mut f = MiniChain::new();
    f.ensure_set();
    let low = f.join_tx(f.hot_key(0), f.p.bond_min_floor_zat - 1);
    assert_eq!(f.mine(&[low]), vec![ATTESTOR_BOND_BELOW_MIN.to_owned()]);
    assert!(f.reg.attestors().is_empty());
    // The seq space exhausted: the next seq is taken.
    let mut reg = Registry::new();
    reg.put_attestor_set(f.reg.attestor_set().unwrap());
    reg.put_next_seq(7);
    reg.put_attestor(7, AttestorRecord::new(f.hot_key(3)));
    let ok = f.join_tx(f.hot_key(1), 10 * COIN);
    assert_eq!(
        attestor_join_refused(&reg, &ok, &f.p, 200, &|_: i64| 0),
        Some(ATTESTOR_SEQ_EXHAUSTED)
    );
    assert_eq!(
        attestor_join_refused(&f.reg, &ok, &f.p, 200, &|_: i64| 0),
        None
    );
    // Into a full set the join evicts the victim's newest record (WITHDRAWN, flagged, not frozen).
    let mut body = set_create_body();
    body.seats = 15;
    let mut g = MiniChain::with_create(body);
    g.p.attestor_seats = 15;
    g.register(15, 0);
    g.empty(10);
    let joiner = g.join_tx(det_key("big", 0), 1000 * COIN);
    g.mine(&[joiner]);
    let evicted: Vec<(u16, AttestorRecord)> = g
        .reg
        .attestors()
        .into_iter()
        .filter(|(_, r)| r.flags & ATTESTOR_FLAG_EVICTED != 0)
        .collect();
    assert_eq!(evicted.len(), 1);
    assert_eq!(evicted[0].1.status, AttestorStatus::Withdrawn);
    assert!(!evicted[0].1.bond_frozen);
    assert_eq!(evicted[0].1.bond_spent_height, 0);
    assert_eq!(g.reg.next_seq(), 16);
}

#[test]
fn mirror_equivocation_by_key_trial() {
    let mut f = MiniChain::new();
    f.register(3, 0);
    f.empty(5);
    let cited = f.tip - 2;
    let bh = f.block_hash(cited).unwrap();
    let k = f.hot[1];
    let eqv = |a, b| {
        let raw = enc(&[a, b]);
        VaultTx {
            txid: Hash32([0x77; 32]),
            coinbase: false,
            inputs: vec![carrier_in(&raw, None, 0)],
            outputs: vec![VaultTxOut {
                value: 0,
                script_pubkey: payload_script(&encode_yed_payload(&Payload::Equivocation).unwrap()),
            }],
        }
    };
    let c32 = u32::try_from(cited).unwrap();
    // Evidence names seq 9 (any seq: the key is found by trial), signed by hot key 1.
    let tx = eqv(
        signed_att(&k, 9, 50_000, c32, &bh),
        signed_att(&k, 9, 51_000, c32, &bh),
    );
    assert!(matches!(
        equivocation_evidence(&tx, &f.p),
        Some(Equivocation::Attestations(..))
    ));
    let hashes = |h: i64| f.block_hash(h);
    let mut reg = f.reg.clone();
    assert_eq!(
        apply_equivocation(&mut reg, &tx, &f.p, f.tip + 1, &hashes),
        Some((1, 9))
    );
    assert_eq!(reg.attestor(1).unwrap().status, AttestorStatus::Ejected);
    assert!(reg.attestor(1).unwrap().bond_frozen);
    assert_eq!(reg.attestor(0).unwrap().status, f.attestor(0).status);
    // Not evidence: equal prices, different cited heights, a cited height at the block, below the start.
    let same = eqv(
        signed_att(&k, 9, 50_000, c32, &bh),
        signed_att(&k, 9, 50_000, c32, &bh),
    );
    assert!(equivocation_evidence(&same, &f.p).is_none());
    let mut reg = f.reg.clone();
    assert_eq!(
        apply_equivocation(&mut reg, &tx, &f.p, cited, &hashes),
        None
    );
    // Another chain's block hash at the cited height: nobody.
    let other = |h: i64| Some(fake_hash(h, 0x01));
    assert_eq!(
        apply_equivocation(&mut reg, &tx, &f.p, f.tip + 1, &other),
        None
    );
    // An outsider's evidence: nobody.
    let o = attest_common::chain::det_secret("outsider", 0);
    let out_tx = eqv(
        signed_att(&o, 9, 50_000, c32, &bh),
        signed_att(&o, 9, 51_000, c32, &bh),
    );
    assert_eq!(
        apply_equivocation(&mut reg, &out_tx, &f.p, f.tip + 1, &hashes),
        None
    );
    assert_eq!(reg, f.reg);
}

#[test]
fn mirror_liveness_credit() {
    let mut f = MiniChain::new();
    f.register(2, 0);
    f.empty(60);
    let r = f.tip - 2;
    let c = |h: i64| u32::try_from(h).unwrap();
    let notice = Payload::ClaimNotice(ClaimNotice::from_outpoint(
        &OutPoint {
            txid: u256s("77"),
            n: 0,
        },
        c(r),
    ));
    let tx_of = |atts: Vec<kogany_yellowback::attest::Attestation>, p: &Payload| VaultTx {
        txid: Hash32([0x66; 32]),
        coinbase: false,
        inputs: vec![carrier_in(&enc(&atts), None, 0)],
        outputs: vec![VaultTxOut {
            value: 0,
            script_pubkey: payload_script(&encode_yed_payload(p).unwrap()),
        }],
    };
    let bh = |h: i64| f.block_hash(h).unwrap();
    let all = f.reg.attestors();
    let live = |seq: u16| mirror_live_member(&all, seq);
    let hashes = |h: i64| f.block_hash(h);
    let tx = tx_of(
        vec![
            signed_att(&f.hot[0], 0, 50_000, c(r), &bh(r)),
            signed_att(&f.hot[1], 1, 50_000, c(r - 1), &bh(r - 1)),
        ],
        &notice,
    );
    let credits = attestation_liveness(&tx, &f.p, f.tip + 1, Some(&live), Some(&hashes), None);
    assert_eq!(credits, vec![(0, r), (1, r - 1)]);
    let mut reg = f.reg.clone();
    apply_liveness_credits(&mut reg, &credits);
    assert_eq!(i64::from(reg.attestor(0).unwrap().last_act), r);
    // An EQUIVOCATION payload, a key under another seq, a stale ref height: nobody.
    let eqv = tx_of(
        vec![
            signed_att(&f.hot[0], 0, 50_000, c(r), &bh(r)),
            signed_att(&f.hot[1], 1, 50_000, c(r), &bh(r)),
        ],
        &Payload::Equivocation,
    );
    assert!(
        attestation_liveness(&eqv, &f.p, f.tip + 1, Some(&live), Some(&hashes), None).is_empty()
    );
    let swapped = tx_of(
        vec![
            signed_att(&f.hot[0], 1, 50_000, c(r), &bh(r)),
            signed_att(&f.hot[1], 0, 50_000, c(r), &bh(r)),
        ],
        &notice,
    );
    assert!(
        attestation_liveness(&swapped, &f.p, f.tip + 1, Some(&live), Some(&hashes), None)
            .is_empty()
    );
    let far = f.tip + 1 + i64::from(f.p.ref_window);
    assert!(attestation_liveness(&tx, &f.p, far, Some(&live), Some(&hashes), None).is_empty());
    // A withdrawn record is not a live member.
    let mut reg = f.reg.clone();
    let mut rec = reg.attestor(1).unwrap();
    rec.status = AttestorStatus::Withdrawn;
    reg.put_attestor(1, rec);
    let all2 = reg.attestors();
    let live2 = |seq: u16| mirror_live_member(&all2, seq);
    assert!(
        attestation_liveness(&tx, &f.p, f.tip + 1, Some(&live2), Some(&hashes), None).is_empty()
    );
    assert!(attestation_liveness(&tx, &f.p, f.tip + 1, None, Some(&hashes), None).is_empty());
}

#[test]
fn snap_passes_arm_dormancy_pin() {
    let p = regtest_params(100, 0, 0, u256s("5e7").0);
    // ARM-1/2: UNARMED -> TRIGGERED at ATTEST_ARM_MIN eligible, ARMED after the delay; never back.
    let m0 = AttestState::default();
    assert_eq!(arm_pass(&m0, &p, 200, 2), m0);
    let m1 = arm_pass(&m0, &p, 200, 3);
    assert_eq!(
        m1,
        AttestState {
            status: AttestStatus::Triggered,
            trigger_height: 200,
            arm_height: 208
        }
    );
    assert_eq!(arm_pass(&m1, &p, 207, 0), m1);
    assert_eq!(arm_pass(&m1, &p, 208, 0).status, AttestStatus::Armed);
    let mut never = p;
    never.attest_arm_min = 0;
    assert_eq!(arm_pass(&m0, &never, 200, 100), m0);
    // S15 only at check heights, with selection evidence and no signature.
    assert!(dormancy_due(&p, 204) && !dormancy_due(&p, 205));
    let mut rec = AttestorRecord::new(det_key("d", 0));
    rec.status = AttestorStatus::Eligible;
    rec.seated_since = 100;
    let row = |sel: Vec<u16>, signed: Vec<u16>| BundleLogRecord {
        selected_seqs: sel,
        seqs: signed.clone(),
        prices: vec![50_000; signed.len()],
        cited_heights: vec![1; signed.len()],
        ..Default::default()
    };
    let rows = vec![row(vec![0], vec![]), row(vec![0], vec![])];
    let mut a = vec![(0u16, rec)];
    dormancy_pass(&mut a, &rows, &p, 205);
    assert_eq!(a[0].1.status, AttestorStatus::Eligible); // not a check height
    dormancy_pass(&mut a, &rows[..1], &p, 204);
    assert_eq!(a[0].1.status, AttestorStatus::Eligible); // too little evidence
    dormancy_pass(
        &mut a,
        &[row(vec![0], vec![]), row(vec![0], vec![0])],
        &p,
        204,
    );
    assert_eq!(a[0].1.status, AttestorStatus::Eligible); // it signed one
    dormancy_pass(&mut a, &rows, &p, 204);
    assert_eq!(a[0].1.status, AttestorStatus::Dormant);
    assert_eq!(a[0].1.status_height, 204);
    // PIN-1/2's bundle side.
    let mint_row = |m: i64| BundleLogRecord {
        a_mint: m,
        ..Default::default()
    };
    assert!(!pin1_triggered(&[mint_row(100_000)], &p) || p.pin_min_bundles <= 1);
    assert!(pin1_triggered(&[mint_row(100_000), mint_row(200_000)], &p));
    assert!(!pin1_triggered(&[mint_row(100_000), mint_row(0)], &p));
    assert!(pin2_triggered(Some(100_000), Some(200_000), &p));
    assert!(!pin2_triggered(Some(100_000), None, &p));
    let pin_rows = vec![
        BundleLogRecord {
            seqs: vec![3, 4],
            prices: vec![50_000, 1],
            cited_heights: vec![10, 10],
            ..Default::default()
        },
        BundleLogRecord {
            seqs: vec![3, 4],
            prices: vec![50_000, 2],
            cited_heights: vec![11, 11],
            ..Default::default()
        },
        BundleLogRecord {
            seqs: vec![5],
            prices: vec![7],
            cited_heights: vec![12],
            ..Default::default()
        },
        BundleLogRecord {
            seqs: vec![5],
            prices: vec![7],
            cited_heights: vec![12],
            ..Default::default()
        },
    ];
    // seq 3: one price at two cited heights: pinned; seq 4: two prices; seq 5: one cited height (A-2).
    assert_eq!(pin2_pinned_seqs(&pin_rows, &p), vec![3]);
}

#[test]
fn registry_records_encode() {
    let mut rec = AttestorRecord::new(det_key("enc", 0));
    rec.bond_outpoint = OutPoint {
        txid: Hash32([9; 32]),
        n: 2,
    };
    rec.bond_zat = 10 * COIN;
    rec.bond_locktime = 1234;
    rec.flags = ATTESTOR_FLAG_EVICTED;
    rec.register_height = 101;
    rec.status = AttestorStatus::Withdrawn;
    rec.status_height = 150;
    rec.seated_since = 120;
    rec.last_act = 140;
    rec.bond_frozen = true;
    let e = rec.encode();
    // keys 2 x (1 + 33), outpoint 36, bond 8, locktime 4, flags 1, five i32 and the status, frozen 1
    assert_eq!(e.len(), 68 + 36 + 8 + 4 + 1 + 4 + 1 + 4 * 4 + 1);
    assert_eq!(e[0], 33);
    assert_eq!(AttestorRecord::decode(&e), Some(rec));
    assert!(AttestorRecord::decode(&e[..e.len() - 1]).is_none());
    let z = AttestorSetRecord {
        create_height: 100,
        seats: 15,
        maturity: 8,
        liveness_window: 1_000_000,
    };
    assert_eq!(z.encode().len(), 13);
    assert_eq!(AttestorSetRecord::decode(&z.encode()), Some(z));
    let m = AttestState {
        status: AttestStatus::Armed,
        trigger_height: 5,
        arm_height: 13,
    };
    assert_eq!(m.encode(), vec![2, 5, 0, 0, 0, 13, 0, 0, 0]);
    assert_eq!(AttestState::decode(&m.encode()), Some(m));
    let row = BundleLogRecord {
        a_mint: 1,
        a_claim: 2,
        selected_seqs: vec![1, 2],
        seqs: vec![1],
        prices: vec![50_000],
        cited_heights: vec![7],
    };
    assert_eq!(BundleLogRecord::decode(&row.encode()), Some(row.clone()));
    assert_eq!(row.encode().len(), 16 + 1 + 4 + 1 + 2 + 1 + 8 + 1 + 4);
    assert_eq!(key_attestor(0x0102), vec![b'A', 1, 2]);
    assert_eq!(key_bundle_log(0x0102_0304), vec![b'W', 1, 2, 3, 4]);
    assert_eq!(key_attest(), b"M".to_vec());
    assert_eq!(key_attestor_set(), b"Z".to_vec());
    let k = key_bond_index(&OutPoint {
        txid: Hash32([3; 32]),
        n: 1,
    });
    assert_eq!(k.len(), 37);
    assert_eq!(k[33..], [0, 0, 0, 1]);
    let _ = PubKeyBytes::from_slice(&[2; 33]);
}
