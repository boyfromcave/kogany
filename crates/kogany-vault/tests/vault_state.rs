//! ycash6 `src/test/vault_state_tests.cpp` (at `65cb4ae0f`), re-expressed case by case: each
//! Rust test carries the C++ test name. Cases or parts of cases that exercise another layer
//! (the LevelDB, the interpreter, ZIP-243 sighashes, the YED module's own rules) say where
//! that part lands instead; the state-machine half of every case is here.

mod state_common;

use std::collections::BTreeMap;
use std::sync::Mutex;

use kogany_vault::act::{
    encode_act, public_key, set_sig_msg, Act, ActBody, SetEquivocationBody, SetRemoveBody,
    MAX_MONEY,
};
use kogany_vault::script::{op, Builder};
use kogany_vault::state::{
    apply_block, audit_locked_value as audit, check_tx, count_active, display_hex,
    eject_and_freeze, find_module, rate_cap, registered_modules, BlockHashFn, BondRecord,
    MemberRecord, MemberStatus, Module, ModuleContext, ModuleEntry, Rules, SetRecord, SetState,
    SpentCoin, StateRead, TemplateOutKind, TemplateOutRecord, VaultOverlay, VaultReject, VaultTx,
    MIN_SET_MATURITY, YED_TAG,
};
use kogany_vault::template::{
    build_intent, build_vault, intent_for, match_vault, Shape, ROLE_CANCEL, ROLE_UNLOCK,
};
use kogany_vault::{Hash32, OutPoint, PubKeyBytes, SetId, Tag};

use state_common::*;

fn leak<T>(v: T) -> &'static T {
    Box::leak(Box::new(v))
}

#[test]
fn create_set() {
    let mut c = Chain::new();
    let s = make_set(&mut c, params(false));
    let rec = c.st.set(&s).unwrap();
    assert_eq!(rec.create_height, 100);
    assert_eq!(rec.params.seats, 5);
    assert_eq!(rec.wind_down_height, 0);
    assert_eq!(c.st.set_ids().len(), 1);

    let mut p = params(false);
    p.seats = 0;
    let t = act_tx(&mut c, ActBody::Create(p), &[], vec![]);
    assert_eq!(c.try_tx(&t), "bad-vault-act-params");
    let t = act_tx(
        &mut c,
        ActBody::Create(params(false)),
        &[make_key(1)],
        vec![],
    );
    assert_eq!(c.try_tx(&t), "bad-vault-act-sigs");

    // In a coinbase: refused.
    let a = Act {
        body: ActBody::Create(params(false)),
        sigs: vec![],
    };
    let cb = mk(
        vec![txin(null_prevout(), vec![])],
        vec![txout(0, encode_act(&a))],
    );
    assert!(cb.coinbase);
    assert_eq!(c.try_tx(&cb), "bad-vault-act-coinbase");
    // A transaction with two YV outputs.
    let mut two = act_tx(&mut c, ActBody::Create(params(false)), &[], vec![]);
    let last = two.outputs.last().unwrap().clone();
    two.outputs.push(last);
    let two = rehash(two);
    assert_eq!(c.try_tx(&two), "bad-vault-act-multi");
    // An unknown type.
    let mut unk = act_tx(&mut c, ActBody::Create(params(false)), &[], vec![]);
    unk.outputs.last_mut().unwrap().script_pubkey = Builder::new()
        .op(op::OP_RETURN)
        .push(&[b'Y', b'V', 1, 9])
        .into_bytes();
    let unk = rehash(unk);
    assert_eq!(c.try_tx(&unk), "bad-vault-act-type");
}

#[test]
fn join_open() {
    let mut c = Chain::new();
    let (k1, k2) = (make_key(1), make_key(2));
    let create = act_tx(&mut c, ActBody::Create(params(true)), &[], vec![]);
    let s = create.txid;
    // A join in the creating block sees no set (created in an earlier block only).
    let j = join_tx(&mut c, s, &k1, &[]);
    assert_eq!(c.block(&[create.clone(), j]), "bad-vault-act-noset");
    assert_eq!(c.block1(&create), "OK");

    // Bond checks.
    let t = join_tx_with(&mut c, s, &k1, &[], 999, 1000);
    assert_eq!(c.try_tx(&t), "bad-vault-act-bond");
    let t = join_tx_with(&mut c, s, &k1, &[], 1000, 9); // < h + bondLockMin
    assert_eq!(c.try_tx(&t), "bad-vault-act-bond");
    let mut wrong = join_tx(&mut c, s, &k1, &[]);
    wrong.outputs[0].script_pubkey = recipient(5);
    let wrong = rehash(wrong);
    assert_eq!(c.try_tx(&wrong), "bad-vault-act-bond");
    // The member must sign first; an open set takes no second signature.
    let mut jb = kogany_vault::act::SetJoinBody {
        set_id: s,
        member_key: k1.pubkey(),
        bond_locktime: (c.h + 1000) as u32,
        bond_vout: 0,
    };
    let bond_out = txout(
        1000,
        kogany_vault::template::bond_script_pubkey(jb.bond_locktime, &k1.pubkey()).unwrap(),
    );
    let t = act_tx(&mut c, ActBody::Join(jb), &[k2], vec![bond_out.clone()]);
    assert_eq!(c.try_tx(&t), "bad-vault-act-sig");
    let t = act_tx(&mut c, ActBody::Join(jb), &[k1, k2], vec![bond_out.clone()]);
    assert_eq!(c.try_tx(&t), "bad-vault-act-sigs");
    jb.bond_vout = 5;
    let t = act_tx(&mut c, ActBody::Join(jb), &[k1], vec![bond_out]);
    assert_eq!(c.try_tx(&t), "bad-vault-act-bond");

    let join = join_tx(&mut c, s, &k1, &[]);
    assert_eq!(c.block1(&join), "OK");
    let m = c.member(&s, &k1);
    assert_eq!(m.status, MemberStatus::Active);
    assert_eq!(m.join_height, 101);
    assert_eq!(m.last_act, 101 + 5);
    assert_eq!(m.bond_value, 1000);
    assert_eq!(
        m.bond_outpoint,
        OutPoint {
            txid: join.txid,
            n: 0
        }
    );
    let bond = c.st.bond(&m.bond_outpoint).unwrap();
    assert!(bond.set_id == s && bond.member_key == k1.pubkey() && !bond.frozen);
    // Joining again while ACTIVE.
    let t = join_tx(&mut c, s, &k1, &[]);
    assert_eq!(c.try_tx(&t), "bad-vault-act-join");
}

#[test]
fn join_seats() {
    let mut c = Chain::new();
    let mut p = params(true);
    p.seats = 2;
    p.unlock_threshold = 1;
    p.cancel_threshold = 1;
    p.slash_threshold = 1;
    let s = make_set(&mut c, p);
    let t = join_tx(&mut c, s, &make_key(1), &[]);
    assert_eq!(c.block1(&t), "OK");
    let t = join_tx(&mut c, s, &make_key(2), &[]);
    assert_eq!(c.block1(&t), "OK");
    // Immature members hold seats too.
    let t = join_tx(&mut c, s, &make_key(3), &[]);
    assert_eq!(c.try_tx(&t), "bad-vault-act-seats");
}

#[test]
fn admission_closed() {
    let mut c = Chain::new();
    let (admit, k1, k2, k3, k4) = (
        make_key(200),
        make_key(1),
        make_key(2),
        make_key(3),
        make_key(4),
    );
    let s = make_set(&mut c, params(false)); // slashThreshold 2, maturity 5
                                             // Fewer than slashThreshold current members: the admit key admits.
    let t = join_tx(&mut c, s, &k1, &[]);
    assert_eq!(c.try_tx(&t), "bad-vault-act-sigs");
    let t = join_tx(&mut c, s, &k1, &[k2]);
    assert_eq!(c.try_tx(&t), "bad-vault-act-sigs");
    let t = join_tx(&mut c, s, &k1, &[admit]);
    assert_eq!(c.block1(&t), "OK");
    let t = join_tx(&mut c, s, &k2, &[admit]);
    assert_eq!(c.block1(&t), "OK");
    // k1, k2 not mature yet: still the admit key.
    let t = join_tx(&mut c, s, &k3, &[admit]);
    assert_eq!(c.block1(&t), "OK");
    c.empty(5);
    // Now three current members >= slashThreshold: two of them must admit.
    for cos in [vec![admit], vec![k1], vec![k1, k1], vec![k1, admit]] {
        let t = join_tx(&mut c, s, &k4, &cos);
        assert_eq!(c.try_tx(&t), "bad-vault-act-sigs");
    }
    let t = join_tx(&mut c, s, &k4, &[k1, k2]);
    assert_eq!(c.block1(&t), "OK");
}

#[test]
fn maturity_heartbeat_dormancy() {
    let mut c = Chain::new();
    let k1 = make_key(1);
    let s = make_set(&mut c, params(true)); // maturity 5, liveness 50, cancelThreshold 1
    let t = join_tx(&mut c, s, &k1, &[]);
    assert_eq!(c.block1(&t), "OK"); // joined at 101
    let snap = c.st.clone();
    assert!(!snap.is_current_member(&s, &k1.pubkey(), 105));
    assert!(snap.is_current_member(&s, &k1.pubkey(), 106));
    assert!(snap.is_dormant(&s, 105)); // no current member yet
    assert!(!snap.is_dormant(&s, 106));
    assert!(!snap.is_dormant(&s, 156)); // lastAct 106 >= 156 - 50
    assert!(snap.is_dormant(&s, 157));
    assert!(snap.is_released(&s, 157));
    assert!(!snap.is_released(&s, 156));
    assert_eq!(snap.threshold(&s, ROLE_UNLOCK), Some(2));
    assert_eq!(snap.threshold(&s, ROLE_CANCEL), Some(1));
    assert_eq!(snap.threshold(&s, 3), None);
    assert_eq!(snap.threshold(&Hash32::ZERO, 1), None);
    // Unknown sets are released, not dormant.
    assert!(snap.is_released(&Hash32::ZERO, 100));
    assert!(!snap.is_dormant(&Hash32::ZERO, 100));

    // Heartbeat while immature is refused.
    let t = heartbeat_tx(&mut c, s, &k1);
    assert_eq!(c.try_tx(&t), "bad-vault-act-heartbeat"); // h = 102
    let t = heartbeat_tx(&mut c, s, &make_key(9));
    assert_eq!(c.try_tx(&t), "bad-vault-act-heartbeat");
    // Signed by someone else.
    let hb = ActBody::Heartbeat(kogany_vault::act::SetHeartbeatBody {
        set_id: s,
        member_key: k1.pubkey(),
    });
    let t = act_tx(&mut c, hb, &[make_key(9)], vec![]);
    assert_eq!(c.try_tx(&t), "bad-vault-act-sig");
    c.empty(60); // h = 162: dormant
    assert!(c.st.is_dormant(&s, c.h));
    let t = heartbeat_tx(&mut c, s, &k1);
    assert_eq!(c.block1(&t), "OK"); // at 162
    assert_eq!(c.member(&s, &k1).last_act, 162);
    assert!(!c.st.is_dormant(&s, 163));
    assert!(!c.st.is_dormant(&s, 212));
    assert!(c.st.is_dormant(&s, 213));
}

#[test]
fn winddown_release() {
    let mut c = Chain::new();
    let (k1, k2, k3) = (make_key(1), make_key(2), make_key(3));
    let s = set_with_members(&mut c, &[k1, k2]);
    let t = winddown_tx(&mut c, s, &[k1]);
    assert_eq!(c.try_tx(&t), "bad-vault-act-sigs");
    let t = winddown_tx(&mut c, s, &[k1, k3]);
    assert_eq!(c.try_tx(&t), "bad-vault-act-sigs");
    let wd = c.h;
    let t = winddown_tx(&mut c, s, &[k1, k2]);
    assert_eq!(c.block1(&t), "OK");
    assert_eq!(c.st.set(&s).unwrap().wind_down_height, wd);
    let t = winddown_tx(&mut c, s, &[k1, k2]);
    assert_eq!(c.try_tx(&t), "bad-vault-act-winddown");
    let t = join_tx(&mut c, s, &k3, &[]);
    assert_eq!(c.try_tx(&t), "bad-vault-act-winddown");
    // Keep the set live so only the wind-down releases it.
    let t = heartbeat_tx(&mut c, s, &k1);
    assert_eq!(c.block1(&t), "OK");
    assert!(!c.st.is_released(&s, wd + 49));
    assert!(c.st.is_released(&s, wd + 50));
    assert!(!c.st.is_dormant(&s, wd + 50));
}

#[test]
fn remove_without_and_with_burn() {
    let mut c = Chain::new();
    let (k1, k2, k3) = (make_key(1), make_key(2), make_key(3));
    let s = set_with_members(&mut c, &[k1, k2, k3]);
    // The target cannot sign its own removal; signers must be current and distinct.
    for signers in [vec![k1, k3], vec![k1, k1], vec![k1]] {
        let t = remove_tx(&mut c, s, k3.pubkey(), false, &signers);
        assert_eq!(c.try_tx(&t), "bad-vault-act-sigs");
    }
    let t = remove_tx(&mut c, s, make_key(9).pubkey(), false, &[k1, k2]);
    assert_eq!(c.try_tx(&t), "bad-vault-act-remove");

    // burn = 0 (O-6): REMOVED, bond returned the set's maturity (5) after the removal.
    let removed_at = c.h;
    let t = remove_tx(&mut c, s, k3.pubkey(), false, &[k1, k2]);
    assert_eq!(c.block1(&t), "OK");
    let m3 = c.member(&s, &k3);
    assert_eq!(m3.status, MemberStatus::Removed);
    assert!(!m3.bond_frozen);
    assert_eq!(
        c.st.bond(&m3.bond_outpoint).unwrap().exit_height,
        removed_at
    );
    assert!(!c.st.is_current_member(&s, &k3.pubkey(), c.h));
    let t = remove_tx(&mut c, s, k3.pubkey(), false, &[k1, k2]);
    assert_eq!(c.try_tx(&t), "bad-vault-act-remove");
    let spend3 = spend_tx(
        &mut c,
        m3.bond_outpoint,
        1,
        vec![txout(900, recipient(7))],
        false,
    );
    c.empty(removed_at + 5 - 1 - c.h);
    assert_eq!(c.h, removed_at + 4);
    assert_eq!(c.try_tx(&spend3), "bad-vault-bond-locked");
    c.empty(1);
    assert_eq!(c.block1(&spend3), "OK");
    assert!(c.st.bond(&m3.bond_outpoint).is_none());
    assert_eq!(c.member(&s, &k3).status, MemberStatus::Removed); // not WITHDRAWN

    // burn = 1: REMOVED and the bond frozen; spending it is invalid.
    let k4 = make_key(4);
    let t = join_tx(&mut c, s, &k4, &[]);
    assert_eq!(c.block1(&t), "OK");
    c.empty(5);
    let t = remove_tx(&mut c, s, k4.pubkey(), true, &[k1, k2]);
    assert_eq!(c.block1(&t), "OK");
    let m4 = c.member(&s, &k4);
    assert_eq!(m4.status, MemberStatus::Removed);
    assert!(m4.bond_frozen);
    assert!(c.st.bond(&m4.bond_outpoint).unwrap().frozen);
    let t = spend(&mut c, m4.bond_outpoint, 1, vec![txout(900, recipient(7))]);
    assert_eq!(c.try_tx(&t), "bad-vault-bond-frozen");

    // burn must be 0 or 1.
    let k5 = make_key(5);
    let r = ActBody::Remove(SetRemoveBody {
        set_id: s,
        member_key: k1.pubkey(),
        burn: 2,
    });
    let t = act_tx(&mut c, r, &[k2, k5], vec![]);
    assert_eq!(c.try_tx(&t), "bad-vault-act-params");
}

fn equivocation_body(
    s: SetId,
    spent: OutPoint,
    signer: &Key,
    role_a: u8,
    a: Hash32,
    role_b: u8,
    b: Hash32,
) -> SetEquivocationBody {
    SetEquivocationBody {
        set_id: s,
        prevout: spent,
        role_a,
        sighash_a: a,
        sig_a: signer.sign(&set_sig_msg(&s, role_a, &spent, &a)),
        role_b,
        sighash_b: b,
        sig_b: signer.sign(&set_sig_msg(&s, role_b, &spent, &b)),
    }
}

#[test]
fn equivocation() {
    let mut c = Chain::new();
    let (k1, k2) = (make_key(1), make_key(2));
    let s = set_with_members(&mut c, &[k1, k2]);
    let spent = OutPoint {
        txid: u256(0x1234),
        n: 3,
    };
    let (sh_a, sh_b) = (u256(0xaa), u256(0xbb));
    let eq = |c: &mut Chain, e: SetEquivocationBody, signers: &[Key]| {
        act_tx(c, ActBody::Equivocation(e), signers, vec![])
    };

    // Same (role, sighash) twice is not equivocation.
    let t = eq(
        &mut c,
        equivocation_body(s, spent, &k1, 1, sh_a, 1, sh_a),
        &[],
    );
    assert_eq!(c.try_tx(&t), "bad-vault-act-equivocation");
    // Two keys.
    let mut mixed = equivocation_body(s, spent, &k1, 1, sh_a, 1, sh_b);
    mixed.sig_b = equivocation_body(s, spent, &k2, 1, sh_a, 1, sh_b).sig_b;
    let t = eq(&mut c, mixed, &[]);
    assert_eq!(c.try_tx(&t), "bad-vault-act-equivocation");
    // A non-member.
    let t = eq(
        &mut c,
        equivocation_body(s, spent, &make_key(9), 1, sh_a, 1, sh_b),
        &[],
    );
    assert_eq!(c.try_tx(&t), "bad-vault-act-equivocation");
    // A bad role.
    let t = eq(
        &mut c,
        equivocation_body(s, spent, &k1, 3, sh_a, 1, sh_b),
        &[],
    );
    assert_eq!(c.try_tx(&t), "bad-vault-act-params");
    // Signed by the submitter: none expected.
    let t = eq(
        &mut c,
        equivocation_body(s, spent, &k1, 1, sh_a, 1, sh_b),
        &[k2],
    );
    assert_eq!(c.try_tx(&t), "bad-vault-act-sigs");

    // Unlock vs cancel on one outpoint, by k1: EJECTED, bond frozen.
    let t = eq(
        &mut c,
        equivocation_body(s, spent, &k1, 1, sh_a, 2, sh_a),
        &[],
    );
    assert_eq!(c.block1(&t), "OK");
    let m = c.member(&s, &k1);
    assert_eq!(m.status, MemberStatus::Ejected);
    assert!(m.bond_frozen);
    assert!(c.st.bond(&m.bond_outpoint).unwrap().frozen);
    assert!(!c.st.is_current_member(&s, &k1.pubkey(), c.h));
    // Again: the bond is already frozen.
    let t = eq(
        &mut c,
        equivocation_body(s, spent, &k1, 1, sh_a, 1, sh_b),
        &[],
    );
    assert_eq!(c.try_tx(&t), "bad-vault-act-equivocation");
    let t = spend(&mut c, m.bond_outpoint, 1, vec![txout(900, recipient(7))]);
    assert_eq!(c.try_tx(&t), "bad-vault-bond-frozen");
}

#[test]
fn withdraw_and_rejoin() {
    let mut c = Chain::new();
    let (k1, k2) = (make_key(1), make_key(2));
    let s = set_with_members(&mut c, &[k1, k2]);
    let m = c.member(&s, &k1);
    // The bond exit delay: an ACTIVE member's bond is locked; the member leaves first.
    let t = spend_tx(
        &mut c,
        m.bond_outpoint,
        1,
        vec![txout(900, recipient(7))],
        false,
    );
    assert_eq!(c.try_tx(&t), "bad-vault-bond-locked");
    let t = remove_tx(&mut c, s, k1.pubkey(), true, &[k1]); // no self-burn
    assert_eq!(c.try_tx(&t), "bad-vault-act-sigs");
    let t = remove_tx(&mut c, s, k2.pubkey(), false, &[k1]); // not another's
    assert_eq!(c.try_tx(&t), "bad-vault-act-sigs");
    let left = c.h;
    let t = remove_tx(&mut c, s, k1.pubkey(), false, &[k1]);
    assert_eq!(c.block1(&t), "OK");
    assert_eq!(c.member(&s, &k1).status, MemberStatus::Removed);
    assert_eq!(c.st.bond(&m.bond_outpoint).unwrap().exit_height, left);
    assert_eq!(count_active(&c.st.members(&s)), 1);
    c.empty(left + 4 - c.h);
    let t = spend_tx(
        &mut c,
        m.bond_outpoint,
        1,
        vec![txout(900, recipient(7))],
        false,
    );
    assert_eq!(c.try_tx(&t), "bad-vault-bond-locked");
    c.empty(1);
    let t = spend_tx(
        &mut c,
        m.bond_outpoint,
        1,
        vec![txout(900, recipient(7))],
        false,
    );
    assert_eq!(c.block1(&t), "OK"); // at left + 5
    assert_eq!(c.member(&s, &k1).status, MemberStatus::Removed);
    assert!(c.st.bond(&m.bond_outpoint).is_none());
    // A departed member's old proof no longer slashes (bond spent).
    let e = equivocation_body(
        s,
        OutPoint {
            txid: u256(0x99),
            n: 0,
        },
        &k1,
        1,
        u256(1),
        1,
        u256(2),
    );
    let t = act_tx(&mut c, ActBody::Equivocation(e), &[], vec![]);
    assert_eq!(c.try_tx(&t), "bad-vault-act-equivocation");
    // Rejoin with a new bond.
    let t = join_tx(&mut c, s, &k1, &[]);
    assert_eq!(c.block1(&t), "OK");
    assert_eq!(c.member(&s, &k1).status, MemberStatus::Active);
    assert_eq!(c.member(&s, &k1).join_height, c.h - 1);
}

#[test]
fn exit_delay_slash_during_delay() {
    let mut c = Chain::new();
    let (k1, k2) = (make_key(1), make_key(2));
    let s = set_with_members(&mut c, &[k1, k2]);
    let bond = c.member(&s, &k1).bond_outpoint;
    let t = remove_tx(&mut c, s, k1.pubkey(), false, &[k1]);
    assert_eq!(c.block1(&t), "OK");
    assert!(c.st.bond(&bond).unwrap().exit_height > 0);
    let e = equivocation_body(
        s,
        OutPoint {
            txid: u256(0x99),
            n: 0,
        },
        &k1,
        1,
        u256(1),
        1,
        u256(2),
    );
    let t = act_tx(&mut c, ActBody::Equivocation(e), &[], vec![]);
    assert_eq!(c.block1(&t), "OK");
    assert_eq!(c.member(&s, &k1).status, MemberStatus::Ejected);
    assert!(c.st.bond(&bond).unwrap().frozen);
    c.empty(10);
    let t = spend_tx(&mut c, bond, 1, vec![txout(900, recipient(7))], false);
    assert_eq!(c.try_tx(&t), "bad-vault-bond-frozen");
    // The record round-trips with its exit height; a record without one keeps its pre-exit
    // bytes (67).
    let b = c.st.bond(&bond).unwrap();
    let back = BondRecord::decode(&b.encode()).unwrap();
    assert!(back.exit_height == b.exit_height && back.frozen && back.set_id == s);
    let plain = BondRecord {
        set_id: s,
        member_key: k2.pubkey(),
        frozen: false,
        exit_height: 0,
    };
    assert_eq!(plain.encode().len(), 67);
    assert_eq!(b.encode().len(), 75);
}

#[test]
fn exit_delay_no_slash_escape() {
    let mut c = Chain::new();
    let admit = make_key(200);
    let (k1, k2, k3, k4) = (make_key(1), make_key(2), make_key(3), make_key(4));
    let s = make_set(&mut c, params(false));
    for k in [k1, k2, k3, k4] {
        let t = join_tx(&mut c, s, &k, &[admit]);
        assert_eq!(c.block1(&t), "OK");
    }
    c.empty(5);
    let bond1 = c.member(&s, &k1).bond_outpoint;
    // A1: k1 exits on its own before the burn vote lands.
    let left = c.h;
    let t = remove_tx(&mut c, s, k1.pubkey(), false, &[k1]);
    assert_eq!(c.block1(&t), "OK");
    assert_eq!(c.st.bond(&bond1).unwrap().exit_height, left);
    // B1: no rejoin during the delay.
    let t = join_tx(&mut c, s, &k1, &[k2, k3]);
    assert_eq!(c.try_tx(&t), "bad-vault-act-join");
    // a burn = 0 vote on a member that already left stays refused; a burn by too few or by
    // the target too
    let t = remove_tx(&mut c, s, k1.pubkey(), false, &[k2, k3]);
    assert_eq!(c.try_tx(&t), "bad-vault-act-remove");
    let t = remove_tx(&mut c, s, k1.pubkey(), true, &[k2]);
    assert_eq!(c.try_tx(&t), "bad-vault-act-sigs");
    let t = remove_tx(&mut c, s, k1.pubkey(), true, &[k1, k2]);
    assert_eq!(c.try_tx(&t), "bad-vault-act-sigs");
    // the cosigned burn freezes the bond in its delay; the member stays REMOVED
    let t = remove_tx(&mut c, s, k1.pubkey(), true, &[k2, k3]);
    assert_eq!(c.block1(&t), "OK");
    assert_eq!(c.member(&s, &k1).status, MemberStatus::Removed);
    assert!(c.member(&s, &k1).bond_frozen);
    assert!(c.st.bond(&bond1).unwrap().frozen);
    let t = remove_tx(&mut c, s, k1.pubkey(), true, &[k2, k3]);
    assert_eq!(c.try_tx(&t), "bad-vault-act-remove"); // already frozen
    c.empty(10);
    let t = spend_tx(&mut c, bond1, 1, vec![txout(900, recipient(7))], false);
    assert_eq!(c.try_tx(&t), "bad-vault-bond-frozen");
    let t = join_tx(&mut c, s, &k1, &[k2, k3]);
    assert_eq!(c.try_tx(&t), "bad-vault-act-join"); // a frozen bond never leaves
                                                    // k2 exits; its rejoin waits for its old bond's spend at exit + maturity
    let bond2 = c.member(&s, &k2).bond_outpoint;
    let left2 = c.h;
    let t = remove_tx(&mut c, s, k2.pubkey(), false, &[k2]);
    assert_eq!(c.block1(&t), "OK");
    let t = join_tx(&mut c, s, &k2, &[k3, k4]);
    assert_eq!(c.try_tx(&t), "bad-vault-act-join");
    c.empty(left2 + 5 - c.h);
    let t = spend_tx(&mut c, bond2, 1, vec![txout(900, recipient(7))], false);
    assert_eq!(c.block1(&t), "OK");
    let t = join_tx(&mut c, s, &k2, &[k3, k4]);
    assert_eq!(c.block1(&t), "OK");
    assert_eq!(c.member(&s, &k2).status, MemberStatus::Active);
}

#[test]
fn min_set_maturity() {
    // D-Q-31: every signer set has at least the network's exit window. (The consensus
    // parameter itself, nVaultMinSetMaturity, is W2-b's: kogany's network profiles.)
    assert_eq!(MIN_SET_MATURITY, 16_128);
    let mut c = Chain::new();
    c.min_maturity = MIN_SET_MATURITY;
    let mut p = params(true);
    p.maturity = MIN_SET_MATURITY - 1;
    let t = act_tx(&mut c, ActBody::Create(p), &[], vec![]);
    assert_eq!(c.try_tx(&t), "bad-vault-act-params");
    p.maturity = MIN_SET_MATURITY;
    let t = act_tx(&mut c, ActBody::Create(p), &[], vec![]);
    assert_eq!(c.try_tx(&t), "OK");
    c.min_maturity = 8; // regtest
    p.maturity = 7;
    let t = act_tx(&mut c, ActBody::Create(p), &[], vec![]);
    assert_eq!(c.try_tx(&t), "bad-vault-act-params");
    p.maturity = 8;
    let t = act_tx(&mut c, ActBody::Create(p), &[], vec![]);
    assert_eq!(c.try_tx(&t), "OK");
}

#[test]
fn vault_create_rules() {
    let mut c = Chain::new();
    let owner = make_key(50);
    let create = act_tx(&mut c, ActBody::Create(params(true)), &[], vec![]);
    let s = create.txid;
    // V-1: a vault under a set created in the same block is invalid.
    let f = c.fund10();
    let lock_tx = mk(
        vec![txin(f, vec![])],
        vec![txout(5000, build_vault(&vault_for(s, &owner, 0)).unwrap())],
    );
    assert_eq!(
        c.block(&[create.clone(), lock_tx.clone()]),
        "bad-txns-vault-noset"
    );
    assert_eq!(c.block1(&create), "OK");
    // Unknown set / cancel set.
    let mut bad = vault_for(s, &owner, 0);
    bad.cancel_set_id = u256(0x77);
    let mut lock_bad = lock_tx.clone();
    lock_bad.outputs[0].script_pubkey = build_vault(&bad).unwrap();
    assert_eq!(c.try_tx(&rehash(lock_bad)), "bad-txns-vault-noset");
    // A V-shaped output outside the field ranges.
    let v = build_vault(&vault_for(s, &owner, 0)).unwrap();
    let mut b = v.clone();
    b[5 + 33] = op::OP_0; // delay 0
    let mut lock_mal = lock_tx.clone();
    lock_mal.outputs[0].script_pubkey = b;
    assert_eq!(c.try_tx(&rehash(lock_mal)), "bad-txns-vault-malformed");
    // I-0: an intent output outside an UNLOCK/APP spend.
    let mut lock_i = lock_tx.clone();
    lock_i.outputs[0].script_pubkey =
        build_intent(&intent_for(&vault_for(s, &owner, 0), &v, &recipient(1))).unwrap();
    assert_eq!(c.try_tx(&rehash(lock_i)), "bad-txns-vault-intent");
    // Valid: lockedValue grows.
    assert_eq!(c.block1(&lock_tx), "OK");
    assert_eq!(c.st.set(&s).unwrap().locked_value, 5000);
}

#[test]
fn unlock_release_cancel() {
    let mut c = Chain::new();
    let owner = make_key(50);
    let s = set_with_members(&mut c, &[make_key(1), make_key(2)]);
    let vp = vault_for(s, &owner, 0);
    let vspk = build_vault(&vp).unwrap();
    let vout = lock(&mut c, &vp, 10000);
    assert_eq!(c.st.set(&s).unwrap().locked_value, 10000);

    let recip = recipient(60);
    let ispk = build_intent(&intent_for(&vp, &vspk, &recip)).unwrap();

    // S-2: value leaves to an ordinary output.
    let t = spend(&mut c, vout, 1, vec![txout(10000, recip.clone())]);
    assert_eq!(c.try_tx(&t), "bad-txns-vault-value");
    let t = spend(
        &mut c,
        vout,
        1,
        vec![txout(9999, ispk.clone()), txout(1, recip.clone())],
    );
    assert_eq!(c.try_tx(&t), "bad-txns-vault-value");
    // S-2: an intent with the wrong vault hash.
    let mut wrong = intent_for(&vp, &vspk, &recip);
    wrong.vault_hash = u256(1);
    let t = spend(
        &mut c,
        vout,
        1,
        vec![txout(10000, build_intent(&wrong).unwrap())],
    );
    assert_eq!(c.try_tx(&t), "bad-txns-vault-covenant");
    // S-2: an intent with a different delay.
    let mut wrong_delay = intent_for(&vp, &vspk, &recip);
    wrong_delay.delay = 6;
    let t = spend(
        &mut c,
        vout,
        1,
        vec![txout(10000, build_intent(&wrong_delay).unwrap())],
    );
    assert_eq!(c.try_tx(&t), "bad-txns-vault-covenant");
    // S-2: a re-lock into a different vault.
    let mut other = vp;
    other.owner_height = 99999;
    let t = spend(
        &mut c,
        vout,
        1,
        vec![txout(10000, build_vault(&other).unwrap())],
    );
    assert_eq!(c.try_tx(&t), "bad-txns-vault-covenant");
    // S-4: APP disabled.
    let t = spend(&mut c, vout, 4, vec![txout(10000, ispk.clone())]);
    assert_eq!(c.try_tx(&t), "bad-txns-vault-app");
    // S-1: bad selector / not push-only.
    let t = spend(&mut c, vout, 5, vec![txout(10000, ispk.clone())]);
    assert_eq!(c.try_tx(&t), "bad-txns-vault-selector");
    let mut np = spend(&mut c, vout, 1, vec![txout(10000, ispk.clone())]);
    np.inputs[0].script_sig = vec![op::OP_DUP, op::OP_1];
    assert_eq!(c.try_tx(&rehash(np)), "bad-txns-vault-selector");
    // I-0 holds for owner spends: selector 2 cannot create an intent.
    let t = spend(&mut c, vout, 2, vec![txout(10000, ispk.clone())]);
    assert_eq!(c.try_tx(&t), "bad-txns-vault-intent");

    // Unlock: 4000 to an intent, 6000 re-locked, plus a change output and an OP_RETURN.
    let unlock = spend(
        &mut c,
        vout,
        1,
        vec![
            txout(4000, ispk.clone()),
            txout(6000, vspk.clone()),
            txout(500, recipient(61)),
            txout(
                0,
                Builder::new().op(op::OP_RETURN).push(&[1, 2]).into_bytes(),
            ),
        ],
    );
    assert_eq!(c.block1(&unlock), "OK");
    assert_eq!(c.st.set(&s).unwrap().locked_value, 6000);
    let iout = find_out(&unlock, &ispk);
    let relock = find_out(&unlock, &vspk);
    let ih = c.h - 1;

    // I-1: release must pay the recipient at least the intent's value.
    let t = spend(&mut c, iout, 1, vec![txout(3999, recip.clone())]);
    assert_eq!(c.try_tx(&t), "bad-txns-vault-release");
    let t = spend(&mut c, iout, 1, vec![txout(4000, recipient(62))]);
    assert_eq!(c.try_tx(&t), "bad-txns-vault-release");
    // Selector 4 is not an intent branch.
    let t = spend(&mut c, iout, 4, vec![txout(4000, recip.clone())]);
    assert_eq!(c.try_tx(&t), "bad-txns-vault-selector");
    // S-1: two template inputs.
    let mut both = spend(&mut c, iout, 1, vec![txout(4000, recip.clone())]);
    both.inputs.push(txin(relock, vec![op::OP_2]));
    assert_eq!(c.try_tx(&rehash(both)), "bad-txns-vault-multi");
    let t = spend(&mut c, iout, 1, vec![txout(4000, recip.clone())]);
    assert_eq!(c.try_tx(&t), "OK");
    // I-3: selector 3 has no template rule (script only).
    let t = spend(&mut c, iout, 3, vec![txout(4000, recipient(80))]);
    assert_eq!(c.try_tx(&t), "OK");

    // I-2: cancel must go back to the vault, and only before the delay has passed.
    let t = spend(&mut c, iout, 2, vec![txout(4000, recip.clone())]);
    assert_eq!(c.try_tx(&t), "bad-txns-vault-cancel");
    let t = spend(&mut c, iout, 2, vec![txout(3999, vspk.clone())]);
    assert_eq!(c.try_tx(&t), "bad-txns-vault-cancel");
    let cancel = spend(&mut c, iout, 2, vec![txout(4000, vspk.clone())]);
    assert_eq!(c.try_tx(&cancel), "OK");
    c.empty(ih + 4 - c.h); // h - coinHeight = 4 < delay 5
    assert_eq!(c.try_tx(&cancel), "OK");
    c.empty(1); // = delay
    assert_eq!(c.try_tx(&cancel), "bad-txns-vault-cancel");

    // Release after the delay; then the owner spends the re-lock (selector 2).
    let t = spend(&mut c, iout, 1, vec![txout(4000, recip.clone())]);
    assert_eq!(c.block1(&t), "OK");
    assert_eq!(c.st.set(&s).unwrap().locked_value, 6000);
    let t = spend(&mut c, relock, 2, vec![txout(6000, recipient(63))]);
    assert_eq!(c.block1(&t), "OK");
    assert_eq!(c.st.set(&s).unwrap().locked_value, 0);
}

#[test]
fn cancel_relocks() {
    let mut c = Chain::new();
    let owner = make_key(50);
    let s = set_with_members(&mut c, &[make_key(1)]);
    let vp = vault_for(s, &owner, 0);
    let vspk = build_vault(&vp).unwrap();
    let vout = lock(&mut c, &vp, 10000);
    let ispk = build_intent(&intent_for(&vp, &vspk, &recipient(60))).unwrap();
    let unlock = spend(&mut c, vout, 1, vec![txout(10000, ispk.clone())]);
    assert_eq!(c.block1(&unlock), "OK");
    assert_eq!(c.st.set(&s).unwrap().locked_value, 0);
    let iout = find_out(&unlock, &ispk);
    c.empty(3);
    let cancel = spend(&mut c, iout, 2, vec![txout(10000, vspk.clone())]);
    assert_eq!(c.block1(&cancel), "OK");
    assert_eq!(c.st.set(&s).unwrap().locked_value, 10000);
    // The re-created vault is byte-identical and spendable again.
    let back = find_out(&cancel, &vspk);
    let t = spend(&mut c, back, 2, vec![txout(10000, recipient(64))]);
    assert_eq!(c.try_tx(&t), "OK");
}

#[test]
fn audit_locked_value() {
    let mut c = Chain::new();
    let owner = make_key(50);
    let s = set_with_members(&mut c, &[make_key(1)]);
    let vp = vault_for(s, &owner, 0);
    let vspk = build_vault(&vp).unwrap();
    assert!(audit(&c.st).0.is_empty());
    let vout = lock(&mut c, &vp, 10000);
    let (m, sets) = audit(&c.st);
    assert!(m.is_empty());
    assert_eq!(sets.len(), 1);
    assert_eq!(sets[0].set_id, s);
    assert_eq!(sets[0].stored, 10000);
    assert_eq!(sets[0].derived, 10000);

    let ispk = build_intent(&intent_for(&vp, &vspk, &recipient(60))).unwrap();
    let unlock = spend(
        &mut c,
        vout,
        1,
        vec![txout(4000, ispk.clone()), txout(6000, vspk.clone())],
    );
    assert_eq!(c.block1(&unlock), "OK");
    assert!(audit(&c.st).0.is_empty());
    let iout = find_out(&unlock, &ispk);
    let relock = find_out(&unlock, &vspk);
    c.empty(2);
    let t = spend(&mut c, iout, 2, vec![txout(4000, vspk.clone())]); // cancel: back into the set
    assert_eq!(c.block1(&t), "OK");
    assert_eq!(c.st.set(&s).unwrap().locked_value, 10000);
    assert!(audit(&c.st).0.is_empty());

    // A corrupted lockedValue is caught.
    let good = c.st.clone();
    c.st.sets.get_mut(&s).unwrap().locked_value += 1;
    let m = audit(&c.st).0;
    assert_eq!(m.len(), 1);
    assert!(m[0].contains("lockedValue stored 10001, unspent V outputs 10000"));
    // So is a lost V record.
    c.st = good.clone();
    c.st.template_outs.remove(&relock);
    let m = audit(&c.st).0;
    assert_eq!(m.len(), 1);
    assert!(m[0].contains("lockedValue stored 10000, unspent V outputs 4000"));
    // Spending the vaults empties the set and the audit stays clean.
    c.st = good;
    let t = spend(&mut c, relock, 2, vec![txout(6000, recipient(63))]);
    assert_eq!(c.block1(&t), "OK");
    assert_eq!(c.st.set(&s).unwrap().locked_value, 4000);
    assert!(audit(&c.st).0.is_empty());
}

#[test]
fn template_out_index() {
    let mut c = Chain::new();
    let owner = make_key(50);
    let s = set_with_members(&mut c, &[make_key(1)]);
    let vp = vault_for(s, &owner, 0);
    let vspk = build_vault(&vp).unwrap();
    let vout = lock(&mut c, &vp, 10000);
    let rv = c.st.template_out(&vout).unwrap();
    assert_eq!(rv.kind, TemplateOutKind::Vault);
    assert_eq!(rv.height, c.h - 1);
    assert_eq!(rv.value, 10000);
    assert_eq!(rv.script_pubkey, vspk);
    assert!(rv.origin.is_empty());

    let ispk = build_intent(&intent_for(&vp, &vspk, &recipient(60))).unwrap();
    let unlock = spend(
        &mut c,
        vout,
        1,
        vec![txout(4000, ispk.clone()), txout(6000, vspk.clone())],
    );
    let before = c.st.clone();
    assert_eq!(c.block1(&unlock), "OK");
    assert!(c.st.template_out(&vout).is_none());
    let iout = find_out(&unlock, &ispk);
    let relock = find_out(&unlock, &vspk);
    let ri = c.st.template_out(&iout).unwrap();
    assert_eq!(ri.kind, TemplateOutKind::Intent);
    assert_eq!(ri.height, c.h - 1);
    assert_eq!(ri.value, 4000);
    assert_eq!(ri.origin, vspk);
    assert!(c.st.template_out(&relock).is_some());
    assert_eq!(c.st.template_outs.len(), 2);
    assert!(c
        .st
        .template_outs
        .keys()
        .all(|k| *k == iout || *k == relock));

    // The block undo restores the index byte for byte.
    let mut back = c.st.clone();
    back.revert(&c.history.last().unwrap().1);
    assert_eq!(back, before);
    assert_eq!(back.canonical_entries(), before.canonical_entries());

    // A failed transaction leaves no index entry; a release erases the intent's.
    let t = spend(&mut c, iout, 1, vec![txout(3999, recipient(60))]);
    assert_ne!(c.try_tx(&t), "OK");
    assert!(c.st.template_out(&iout).is_some());
    c.empty(4);
    let t = spend(&mut c, iout, 1, vec![txout(4000, recipient(60))]);
    assert_eq!(c.block1(&t), "OK");
    assert!(c.st.template_out(&iout).is_none());
    assert_eq!(c.st.template_outs.len(), 1);
}

/// A coin view that answers like the C++ replay accessor (`CoinsFromUndo`): scripts and values
/// from the spent coins, heights only where the undo would carry one; otherwise from the
/// template-output index of the state before the block, otherwise 0.
struct ReplayCoins<'a> {
    live: &'a BTreeMap<OutPoint, SpentCoin>,
    undo_heights: BTreeMap<OutPoint, i64>,
    index: &'a SetState,
}

impl kogany_vault::state::CoinAccessor for ReplayCoins<'_> {
    fn spent_coin(&self, prevout: &OutPoint) -> Option<SpentCoin> {
        let mut c = self.live.get(prevout)?.clone();
        c.height = match self.undo_heights.get(prevout) {
            Some(h) if *h != 0 => *h,
            _ => self
                .index
                .template_out(prevout)
                .map(|r| r.height)
                .unwrap_or(0),
        };
        Some(c)
    }
}

#[test]
fn coins_from_undo() {
    // The C++ CoinsFromUndo is the start-up replay's coin accessor over CCoins undo records,
    // which zakura does not have (its spent outputs carry their heights: M24-13, W4-c). The
    // rule-level facts the case pins are re-expressed: the template-output index holds the
    // intent's creation height (what replay derives it from), and an intent replayed with height
    // 0 is rejected by S-0 for RELEASE and CANCEL alike.
    let mut c = Chain::new();
    let owner = make_key(50);
    let s = set_with_members(&mut c, &[make_key(1)]);
    let vp = vault_for(s, &owner, 0);
    let vspk = build_vault(&vp).unwrap();
    let vout = lock(&mut c, &vp, 10000);
    let ispk = build_intent(&intent_for(&vp, &vspk, &recipient(60))).unwrap();
    let unlock = spend(&mut c, vout, 1, vec![txout(10000, ispk.clone())]);
    assert_eq!(c.block1(&unlock), "OK");
    let iout = find_out(&unlock, &ispk);
    let ih = c.h - 1;
    assert_eq!(c.st.template_out(&iout).unwrap().height, ih); // from the 'v' index

    let replay = ReplayCoins {
        live: &c.coins,
        undo_heights: BTreeMap::new(),
        index: &c.st,
    };
    use kogany_vault::state::CoinAccessor;
    let got = replay.spent_coin(&iout).unwrap();
    assert_eq!(got.height, ih);
    assert_eq!(got.script_pubkey, ispk);
    let mut h7 = BTreeMap::new();
    h7.insert(iout, 7);
    let replay7 = ReplayCoins {
        live: &c.coins,
        undo_heights: h7,
        index: &c.st,
    };
    assert_eq!(replay7.spent_coin(&iout).unwrap().height, 7); // the undo's height wins

    // No height anywhere: 0, and S-0 rejects both intent branches.
    let rel = spend_tx(&mut c, iout, 1, vec![txout(10000, recipient(60))], false);
    let cancel = spend_tx(&mut c, iout, 2, vec![txout(10000, vspk.clone())], false);
    let empty = SetState::new();
    let replay0 = ReplayCoins {
        live: &c.coins,
        undo_heights: BTreeMap::new(),
        index: &empty,
    };
    assert_eq!(replay0.spent_coin(&iout).unwrap().height, 0);
    let mut rules = c.rules();
    rules.activation_height = c.h - 1;
    assert_eq!(
        res(check_tx(&c.st, &rel, c.h, &replay0, &rules)),
        "bad-txns-vault-preactivation"
    );
    assert_eq!(
        res(check_tx(&c.st, &cancel, c.h, &replay0, &rules)),
        "bad-txns-vault-preactivation"
    );
}

#[test]
fn preactivation_floor() {
    // S-0: a template input whose coin was created below the activation height is invalid.
    let mut c = Chain::new(); // h = 100
    let owner = make_key(50);
    let s = set_with_members(&mut c, &[make_key(1)]);
    let activation = c.h;
    c.activation = activation;

    let mut vp = vault_for(s, &owner, activation + 1); // an APP branch, for selector 4
    vp.owner_height = activation;
    let vspk = build_vault(&vp).unwrap();
    let ispk = build_intent(&intent_for(&vp, &vspk, &recipient(60))).unwrap();
    let inject = |c: &mut Chain, spk: &[u8], value: i64, height: i64, seed: u8| {
        let mut h = [0u8; 32];
        h[0] = seed;
        h[31] = 0xab;
        let op = OutPoint {
            txid: Hash32(h),
            n: 0,
        };
        c.coins.insert(
            op,
            SpentCoin {
                script_pubkey: spk.to_vec(),
                value,
                height,
            },
        );
        op
    };
    let pre_v = inject(&mut c, &vspk, 5000, activation - 1, 1);
    let pre_i = inject(&mut c, &ispk, 5000, activation - 1, 2);
    c.empty(10);
    // V: UNLOCK (1), OWNER (2), OWNER-RELEASED (3), APP (4).
    let t = spend(&mut c, pre_v, 1, vec![txout(5000, ispk.clone())]);
    assert_eq!(c.try_tx(&t), "bad-txns-vault-preactivation");
    for sel in [2, 3] {
        let t = spend(&mut c, pre_v, sel, vec![txout(5000, recipient(70))]);
        assert_eq!(c.try_tx(&t), "bad-txns-vault-preactivation");
    }
    let t = spend(&mut c, pre_v, 4, vec![txout(5000, ispk.clone())]);
    assert_eq!(c.try_tx(&t), "bad-txns-vault-preactivation");
    // I: RELEASE (1), CANCEL (2), OWNER-RELEASED (3).
    let t = spend(&mut c, pre_i, 1, vec![txout(5000, recipient(60))]);
    assert_eq!(c.try_tx(&t), "bad-txns-vault-preactivation");
    let t = spend(&mut c, pre_i, 2, vec![txout(5000, vspk.clone())]);
    assert_eq!(c.try_tx(&t), "bad-txns-vault-preactivation");
    let t = spend(&mut c, pre_i, 3, vec![txout(5000, recipient(70))]);
    assert_eq!(c.try_tx(&t), "bad-txns-vault-preactivation");
    // In a block too.
    let t = spend(&mut c, pre_i, 1, vec![txout(5000, recipient(60))]);
    assert_eq!(c.block1(&t), "bad-txns-vault-preactivation");

    // The same shapes at the activation height pass the floor (and their rules apply).
    let at_i = inject(&mut c, &ispk, 5000, activation, 3);
    let t = spend(&mut c, at_i, 1, vec![txout(5000, recipient(60))]);
    assert_eq!(c.try_tx(&t), "OK");
    let t = spend(&mut c, at_i, 1, vec![txout(4999, recipient(60))]);
    assert_eq!(c.try_tx(&t), "bad-txns-vault-release");
    let mut vp0 = vault_for(s, &owner, 0);
    vp0.owner_height = activation;
    let at_v = lock(&mut c, &vp0, 7000);
    assert_eq!(c.st.set(&s).unwrap().locked_value, 7000);
    let t = spend(&mut c, at_v, 2, vec![txout(7000, recipient(70))]);
    assert_eq!(c.block1(&t), "OK");
    assert_eq!(c.st.set(&s).unwrap().locked_value, 0);

    // A MALFORMED-shaped pre-activation coin (delay 5 pushed non-minimally) is not a template
    // input: no floor, no rule.
    let mut nm = vspk[..38].to_vec();
    nm.extend_from_slice(&[0x01, 0x05]);
    nm.extend_from_slice(&vspk[39..]);
    assert!(matches!(match_vault(&nm), Shape::Malformed));
    let pre_m = inject(&mut c, &nm, 5000, activation - 1, 4);
    let t = spend(&mut c, pre_m, 1, vec![txout(5000, recipient(70))]);
    assert_eq!(c.try_tx(&t), "OK");

    // activation 0: no floor.
    c.activation = 0;
    let t = spend(&mut c, pre_v, 2, vec![txout(5000, recipient(70))]);
    assert_eq!(c.try_tx(&t), "OK");
}

#[test]
fn replay_parity() {
    // A post-activation V whose creating transaction is only partly spent: the template spend's
    // undo has no height, the replay takes it from the 'v' index, and the block applies over
    // the replay accessor exactly as over the live coins.
    let mut c = Chain::new();
    let owner = make_key(50);
    let s = set_with_members(&mut c, &[make_key(1)]);
    c.activation = 100;
    let vp = vault_for(s, &owner, 0);
    let vspk = build_vault(&vp).unwrap();
    let f = c.fund(20000);
    let lock_tx = mk(
        vec![txin(f, vec![])],
        vec![txout(10000, vspk.clone()), txout(9000, recipient(80))],
    );
    assert_eq!(c.block1(&lock_tx), "OK");
    let vout = OutPoint {
        txid: lock_tx.txid,
        n: 0,
    };
    let vh = c.h - 1;
    c.empty(2);
    let ispk = build_intent(&intent_for(&vp, &vspk, &recipient(60))).unwrap();
    let unlock = spend_tx(&mut c, vout, 1, vec![txout(10000, ispk)], false);
    let coinbase = mk(
        vec![txin(null_prevout(), vec![])],
        vec![txout(1, recipient(70))],
    );
    let block = vec![coinbase, unlock];
    let replay = ReplayCoins {
        live: &c.coins,
        undo_heights: BTreeMap::new(),
        index: &c.st,
    };
    use kogany_vault::state::CoinAccessor;
    assert_eq!(replay.spent_coin(&vout).unwrap().height, vh);

    let rules = c.rules();
    let live = apply_block(&c.st, &block, c.h, &c.coins, &rules).unwrap();
    let rep = apply_block(&c.st, &block, c.h, &replay, &rules).unwrap();
    assert_eq!(live, rep);
    assert_eq!(live.canonical_entries(), rep.canonical_entries());
    assert_eq!(c.st.with(&live).state_hash(), c.st.with(&rep).state_hash());
}

#[test]
fn app_branch() {
    let mut c = Chain::new();
    let owner = make_key(50);
    let s = set_with_members(&mut c, &[make_key(1)]);
    // V-1: an APP branch only on a tag a module governs. TEST has none: refused.
    let mut bad = vault_for(s, &owner, 500);
    let f = c.fund(9000);
    let lock_bad = mk(
        vec![txin(f, vec![])],
        vec![txout(8000, build_vault(&bad).unwrap())],
    );
    assert_eq!(c.try_tx(&lock_bad), "bad-txns-vault-app");
    // ... also when a template spend creates it.
    bad.app_height = 0;
    let plain = lock(&mut c, &bad, 8000);
    let mut bad_out = bad;
    bad_out.app_height = 500;
    let t = spend(
        &mut c,
        plain,
        2,
        vec![txout(8000, build_vault(&bad_out).unwrap())],
    );
    assert_eq!(c.try_tx(&t), "bad-txns-vault-app");
    // YED\0 has a registered module (inert here: it governs nothing).
    let mut vp = vault_for(s, &owner, 500);
    vp.tag = YED_TAG;
    assert!(find_module(registered_modules(), &vp.tag).is_some());
    let vspk = build_vault(&vp).unwrap();
    let vout = lock(&mut c, &vp, 8000);
    let ispk = build_intent(&intent_for(&vp, &vspk, &recipient(60))).unwrap();
    // Selector 4 obeys S-2 like an unlock.
    let t = spend(&mut c, vout, 4, vec![txout(8000, recipient(60))]);
    assert_eq!(c.try_tx(&t), "bad-txns-vault-value");
    let t = spend(&mut c, vout, 4, vec![txout(8000, ispk)]);
    assert_eq!(c.block1(&t), "OK");
    assert_eq!(c.st.set(&s).unwrap().locked_value, 8000); // only the plain V remains
}

#[test]
fn rate_limit_epochs() {
    let mut c = Chain::new(); // h = 100
    let owner = make_key(50);
    let mut p = params(true);
    p.rate_limit_bps = 5000; // 50 % of the epoch's basis
    p.rate_window = 20; // epochs [100,120) = 5, [120,140) = 6, ...
    let s = set_with_members_p(&mut c, &[make_key(1)], p); // created 100, joined 101, h = 107
    let vp = vault_for(s, &owner, 0);
    let vspk = build_vault(&vp).unwrap();
    let ispk = build_intent(&intent_for(&vp, &vspk, &recipient(60))).unwrap();
    let v1 = lock(&mut c, &vp, 1000);
    let v2 = lock(&mut c, &vp, 1000);
    assert_eq!(c.st.set(&s).unwrap().locked_value, 2000);
    // In the epoch the value was locked the basis is 0 (U-20): no unlock fits.
    let t = spend(
        &mut c,
        v1,
        1,
        vec![txout(1, ispk.clone()), txout(999, vspk.clone())],
    );
    assert_eq!(c.try_tx(&t), "bad-txns-vault-rate");

    c.empty(120 - c.h); // epoch 6: basis 2000, cap 1000
    let t = spend(&mut c, v1, 1, vec![txout(1000, ispk.clone())]);
    assert_eq!(c.try_tx(&t), "OK");
    let u1 = spend(
        &mut c,
        v1,
        1,
        vec![txout(600, ispk.clone()), txout(400, vspk.clone())],
    );
    assert_eq!(c.block1(&u1), "OK");
    let rec = c.st.set(&s).unwrap();
    assert_eq!(rec.epoch, 6);
    assert_eq!(rec.epoch_basis, 2000);
    assert_eq!(rec.epoch_used, 600);
    assert_eq!(rec.locked_value, 1400);
    // 400 more fits exactly; 401 does not.
    let t = spend(
        &mut c,
        v2,
        1,
        vec![txout(401, ispk.clone()), txout(599, vspk.clone())],
    );
    assert_eq!(c.try_tx(&t), "bad-txns-vault-rate");
    let u2 = spend(
        &mut c,
        v2,
        1,
        vec![txout(400, ispk.clone()), txout(600, vspk.clone())],
    );
    assert_eq!(c.block1(&u2), "OK");
    assert_eq!(c.st.set(&s).unwrap().epoch_used, 1000);
    assert_eq!(c.st.set(&s).unwrap().locked_value, 1000);
    let (r1, r2) = (find_out(&u1, &vspk), find_out(&u2, &vspk));
    let t = spend(
        &mut c,
        r1,
        1,
        vec![txout(1, ispk.clone()), txout(399, vspk.clone())],
    );
    assert_eq!(c.try_tx(&t), "bad-txns-vault-rate");
    // Owner spends (selector 2) are not rate-limited.
    let t = spend(&mut c, r2, 2, vec![txout(600, recipient(70))]);
    assert_eq!(c.try_tx(&t), "OK");

    // Epoch 7: the basis is the locked value at the epoch's start (1000) even if a lock lands
    // first in the epoch; cap 500.
    c.empty(140 - c.h);
    lock(&mut c, &vp, 5000);
    let rec = c.st.set(&s).unwrap();
    assert_eq!(rec.epoch, 7);
    assert_eq!(rec.epoch_basis, 1000);
    assert_eq!(rec.locked_value, 6000);
    let t = spend(
        &mut c,
        r2,
        1,
        vec![txout(501, ispk.clone()), txout(99, vspk.clone())],
    );
    assert_eq!(c.try_tx(&t), "bad-txns-vault-rate");
    let t = spend(
        &mut c,
        r2,
        1,
        vec![txout(500, ispk.clone()), txout(100, vspk.clone())],
    );
    assert_eq!(c.block1(&t), "OK");
    let t = spend(&mut c, r1, 1, vec![txout(1, ispk), txout(399, vspk)]);
    assert_eq!(c.try_tx(&t), "bad-txns-vault-rate");
    assert_eq!(rate_cap(MAX_MONEY, 10000), MAX_MONEY);
    assert_eq!(
        rate_cap(MAX_MONEY, 3333),
        ((MAX_MONEY as i128 * 3333) / 10000) as i64
    );
    assert_eq!(rate_cap(9999, 1), 0);
}

#[test]
fn apply_tx_is_atomic() {
    let mut c = Chain::new();
    let k1 = make_key(1);
    let s = set_with_members(&mut c, &[k1]);
    // k1 leaves; after the exit delay a spend of its bond then fails I-0: nothing may stick.
    let t = remove_tx(&mut c, s, k1.pubkey(), false, &[k1]);
    assert_eq!(c.block1(&t), "OK");
    c.empty(5);
    let m = c.member(&s, &k1);
    let vp = vault_for(s, &make_key(50), 0);
    let ispk = build_intent(&intent_for(&vp, &build_vault(&vp).unwrap(), &recipient(1))).unwrap();
    let bad = spend_tx(&mut c, m.bond_outpoint, 1, vec![txout(900, ispk)], false);
    let rules = c.rules();
    let mut st = VaultOverlay::new(&c.st);
    assert_eq!(
        res(st.apply_tx(&bad, c.h, &c.coins, &rules)),
        "bad-txns-vault-intent"
    );
    assert!(st.is_empty());
    assert!(st.delta().is_empty());
    assert_eq!(
        st.member(&s, &k1.pubkey()).unwrap().status,
        MemberStatus::Removed
    );
    assert!(st.bond(&m.bond_outpoint).is_some());
    // A missing input coin is a rejection, not a silent pass.
    let orphan = mk(
        vec![txin(
            OutPoint {
                txid: u256(0xdead),
                n: 0,
            },
            vec![],
        )],
        vec![txout(1, recipient(1))],
    );
    assert_eq!(
        res(st.apply_tx(&orphan, c.h, &c.coins, &rules)),
        "bad-txns-vault-inputs-missing"
    );
    // CheckTx over the tip.
    let hb = heartbeat_tx(&mut c, s, &k1);
    assert_eq!(
        res(check_tx(&c.st, &hb, c.h, &c.coins, &rules)),
        "bad-vault-act-heartbeat"
    ); // k1 left
    assert_eq!(
        res(check_tx(&c.st, &bad, c.h, &c.coins, &rules)),
        "bad-txns-vault-intent"
    );
}

#[test]
fn running_copy_sequential() {
    // The miner's running copy: acts apply in order, a failing candidate is skipped.
    let mut c = Chain::new();
    let (k1, k2) = (make_key(1), make_key(2));
    let mut p = params(true);
    p.seats = 1;
    p.unlock_threshold = 1;
    p.cancel_threshold = 1;
    p.slash_threshold = 1;
    let s = make_set(&mut c, p);
    let j1 = join_tx(&mut c, s, &k1, &[]);
    let j2 = join_tx(&mut c, s, &k2, &[]);
    let rules = c.rules();
    {
        let mut running = VaultOverlay::new(&c.st);
        assert_eq!(res(running.apply_tx(&j1, c.h, &c.coins, &rules)), "OK");
        assert_eq!(
            res(running.apply_tx(&j2, c.h, &c.coins, &rules)),
            "bad-vault-act-seats"
        );
        assert!(running.member(&s, &k1.pubkey()).is_some());
        assert!(running.member(&s, &k2.pubkey()).is_none());
    }
    assert!(c.st.member(&s, &k1.pubkey()).is_none()); // the base is untouched
                                                      // A block with both joins is invalid (seats apply sequentially).
    let (j1, j2) = (join_tx(&mut c, s, &k1, &[]), join_tx(&mut c, s, &k2, &[]));
    assert_eq!(c.block(&[j1, j2]), "bad-vault-act-seats");
}

#[test]
fn undo_roundtrip_byte_identical() {
    let mut c = Chain::new();
    let (k1, k2, k3, owner) = (make_key(1), make_key(2), make_key(3), make_key(50));
    let mut p = params(true);
    p.rate_limit_bps = 9000;
    p.rate_window = 10;
    let s = set_with_members_p(&mut c, &[k1, k2, k3], p);
    let vp = vault_for(s, &owner, 0);
    let vspk = build_vault(&vp).unwrap();
    let ispk = build_intent(&intent_for(&vp, &vspk, &recipient(60))).unwrap();
    let vout = lock(&mut c, &vp, 10000);
    c.empty(10);
    let unlock = spend(&mut c, vout, 1, vec![txout(3000, ispk), txout(7000, vspk)]);
    let hb = heartbeat_tx(&mut c, s, &k1);
    assert_eq!(c.block(&[unlock, hb]), "OK");
    let t = remove_tx(&mut c, s, k3.pubkey(), true, &[k1, k2]);
    assert_eq!(c.block1(&t), "OK");
    let t = remove_tx(&mut c, s, k2.pubkey(), false, &[k2]); // k2 leaves
    assert_eq!(c.block1(&t), "OK");
    c.empty(5);
    let b2 = c.member(&s, &k2).bond_outpoint;
    let t = spend_tx(&mut c, b2, 1, vec![txout(900, recipient(7))], false);
    assert_eq!(c.block1(&t), "OK");
    let t = winddown_tx(&mut c, s, &[k1, k3]);
    assert_eq!(c.try_tx(&t), "bad-vault-act-sigs"); // k3 removed
    assert!(!c.st.canonical_entries().is_empty());

    // Disconnect every block in reverse; each step restores the exact prior bytes.
    let mut st = c.st.clone();
    for (before, delta) in c.history.iter().rev() {
        st.revert(delta);
        assert_eq!(st.canonical_entries(), before.canonical_entries());
        assert_eq!(&st, before);
        // The inverse delta is the same undo.
        let mut fwd = before.clone();
        fwd.apply(delta);
        fwd.apply(&delta.inverse());
        assert_eq!(&fwd, before);
    }
    assert!(st.canonical_entries().is_empty());
}

#[test]
fn db_connect_disconnect() {
    // The C++ case drives the LevelDB (`VaultDB`: tip marker, version key, parent check, undo
    // records); kogany's storage is W4-c. The state-level contract it rests on is here: a
    // block's delta moves the state to the connected value and its revert back to the exact
    // prior state; a disconnect leaves no member behind.
    let mut c = Chain::new();
    let create = act_tx(&mut c, ActBody::Create(params(true)), &[], vec![]);
    let s = create.txid;
    assert!(c.st.set(&s).is_none());
    assert_eq!(c.block1(&create), "OK");
    assert!(c.st.set(&s).is_some());
    let after_create = c.st.clone();
    let k1 = make_key(1);
    let join = join_tx(&mut c, s, &k1, &[]);
    // An empty block's delta is empty.
    let rules = c.rules();
    assert!(apply_block(&c.st, &[], c.h, &c.coins, &rules)
        .unwrap()
        .is_empty());
    assert_eq!(c.block1(&join), "OK");
    assert!(c.st.member(&s, &k1.pubkey()).is_some());
    assert_eq!(c.st.members(&s).len(), 1);
    let (_, d2) = c.history.last().unwrap().clone();
    assert!(!d2.is_empty());
    c.st.revert(&d2);
    assert_eq!(c.st, after_create);
    assert!(c.st.member(&s, &k1.pubkey()).is_none());
    let (_, d1) = c.history[c.history.len() - 2].clone();
    c.st.revert(&d1);
    assert_eq!(c.st, SetState::new());
}

#[test]
fn db_undo_prune() {
    // Undo pruning (UNDO_KEEP) is storage (W4-c; kogany keeps the 1,000-block non-finalized
    // window, K-13, and refuses rollback past Vault, K-14). The state half: a run of blocks
    // reverts through every delta it kept.
    let mut c = Chain::new();
    let s = set_with_members(&mut c, &[make_key(1), make_key(2)]);
    let t = heartbeat_tx(&mut c, s, &make_key(1));
    assert_eq!(c.block1(&t), "OK");
    c.empty(20);
    let n = c.history.len();
    let mut st = c.st.clone();
    for (before, delta) in c.history.iter().rev() {
        st.revert(delta);
        assert_eq!(&st, before);
    }
    assert_eq!(n, 1 + 2 + 5 + 1 + 20);
    assert_eq!(st, SetState::new());
}

#[test]
fn set_sig_checker() {
    // The snapshot half of SetSigChecker (W3-c computes sighash = SignatureHash(scriptCode, tx,
    // nIn, SIGHASH_ALL|SIGHASH_ANYONECANPAY, amount, branch) and the message; its binding to
    // branch, amount, input index and the fee inputs is tested there). Here: threshold,
    // released, and check_set_sigs over msg = setSigMsg(setId, role, prevout, sighash).
    let mut c = Chain::new();
    let (k1, k2, k3) = (make_key(1), make_key(2), make_key(3));
    let s = set_with_members(&mut c, &[k1, k2]); // unlock 2, cancel 1
    let t = join_tx(&mut c, s, &k3, &[]);
    assert_eq!(c.block1(&t), "OK"); // k3 immature
    let snap = c.st.clone();
    assert_eq!(snap.threshold(&s, ROLE_UNLOCK), Some(2));
    assert_eq!(snap.threshold(&s, ROLE_CANCEL), Some(1));
    assert_eq!(snap.threshold(&u256(5), ROLE_UNLOCK), None);
    assert!(!snap.is_released(&s, c.h));
    assert!(snap.is_released(&u256(5), c.h));

    let prevout = OutPoint {
        txid: u256(0xabc),
        n: 1,
    };
    let sighash = u256(0x5151);
    let sig = |k: &Key, role: u8, p: &OutPoint, sh: &Hash32| {
        k.sign(&set_sig_msg(&s, role, p, sh)).0.to_vec()
    };
    let msg = |role: u8| set_sig_msg(&s, role, &prevout, &sighash);
    let h = c.h;
    let check = |role: u8, sigs: Vec<Vec<u8>>| snap.check_set_sigs(&s, role, &msg(role), &sigs, h);
    assert!(check(
        1,
        vec![
            sig(&k1, 1, &prevout, &sighash),
            sig(&k2, 1, &prevout, &sighash)
        ]
    ));
    assert!(check(
        1,
        vec![
            sig(&k2, 1, &prevout, &sighash),
            sig(&k1, 1, &prevout, &sighash)
        ]
    ));
    assert!(!check(1, vec![sig(&k1, 1, &prevout, &sighash)]));
    assert!(!check(
        1,
        vec![
            sig(&k1, 1, &prevout, &sighash),
            sig(&k1, 1, &prevout, &sighash)
        ]
    ));
    assert!(!check(
        1,
        vec![
            sig(&k1, 1, &prevout, &sighash),
            sig(&k3, 1, &prevout, &sighash)
        ]
    )); // immature
    assert!(!check(
        1,
        vec![
            sig(&k1, 1, &prevout, &sighash),
            sig(&make_key(9), 1, &prevout, &sighash)
        ]
    ));
    // Bound to the role, the sighash and the outpoint.
    assert!(!check(2, vec![sig(&k1, 1, &prevout, &sighash)]));
    assert!(check(2, vec![sig(&k1, 2, &prevout, &sighash)]));
    assert!(!check(2, vec![sig(&k1, 2, &prevout, &u256(0x5152))]));
    assert!(!snap.check_set_sigs(&u256(5), 2, &msg(2), &[sig(&k1, 2, &prevout, &sighash)], h));
    let other = OutPoint {
        txid: u256(0xabd),
        n: 1,
    };
    assert!(!check(
        1,
        vec![sig(&k1, 1, &other, &sighash), sig(&k2, 1, &other, &sighash)]
    ));
    assert!(!check(
        2,
        vec![sig(
            &k1,
            2,
            &OutPoint {
                txid: prevout.txid,
                n: 0
            },
            &sighash
        )]
    ));
    // Not a 65-byte recoverable signature; a high-S or bad-header signature.
    assert!(!check(1, vec![vec![0x11; 64], vec![0x22; 65]]));
    let mut bad_header = sig(&k1, 2, &prevout, &sighash);
    bad_header[0] = 27;
    assert!(!check(2, vec![bad_header]));
}

#[test]
fn vault_checksetsig_real_script() {
    // T-3 runs the templates through VerifyScript with the real checker: that is the
    // interpreter's (W3-a, the fork's zcash_script) and W3-c's (the Ycash checker over an
    // Arc<snapshot>). The snapshot answers the script consumes at the two heights the case
    // uses are pinned here: k = threshold, members current or not, released or not.
    let mut c = Chain::new();
    let (k1, k2, k3) = (make_key(1), make_key(2), make_key(3));
    let s = set_with_members(&mut c, &[k1, k2]);
    let t = join_tx(&mut c, s, &k3, &[]);
    assert_eq!(c.block1(&t), "OK");
    let snap = c.st.clone();
    let (h_current, h_released) = (c.h, c.h + 100);
    assert!(!snap.is_released(&s, h_current));
    assert!(snap.is_released(&s, h_released));
    assert!(snap.is_current_member(&s, &k1.pubkey(), h_current));
    assert!(!snap.is_current_member(&s, &k3.pubkey(), h_current));
    assert!(!snap.is_released(&s, h_current) && snap.threshold(&s, ROLE_UNLOCK) == Some(2));
    // A released set does not weaken the unlock branch: still two current members.
    let p = OutPoint {
        txid: u256(0x7a),
        n: 0,
    };
    let sh = u256(0x77);
    let msg = set_sig_msg(&s, 1, &p, &sh);
    assert!(!snap.check_set_sigs(&s, 1, &msg, &[k1.sign(&msg).0.to_vec()], h_released));
    assert!(snap.check_set_sigs(
        &s,
        1,
        &msg,
        &[k1.sign(&msg).0.to_vec(), k2.sign(&msg).0.to_vec()],
        h_current
    ));
    // An unknown set: no threshold (OP_CHECKSETSIG fails), released (OP_CHECKSETDORMANT true).
    assert_eq!(snap.threshold(&u256(0x5e7), 1), None);
    assert!(snap.is_released(&u256(0x5e7), h_current));
}

#[test]
fn set_sig_checker_refee() {
    // 01/V-2's sighash binding (SIGHASH_ALL|SIGHASH_ANYONECANPAY over ZIP-243) is W3-c's. The
    // state half: two re-funded builds have one sighash, and SET_EQUIVOCATION over them is
    // refused (equal is not equivocation); a different sighash with the same role is.
    let mut c = Chain::new();
    let (k1, k2) = (make_key(1), make_key(2));
    let s = set_with_members(&mut c, &[k1, k2]);
    let templ = OutPoint {
        txid: u256(0xabc),
        n: 1,
    };
    let sh = u256(0x1111);
    let e = equivocation_body(s, templ, &k1, 1, sh, 1, sh);
    let t = act_tx(&mut c, ActBody::Equivocation(e), &[], vec![]);
    assert_eq!(c.try_tx(&t), "bad-vault-act-equivocation");
    let e = equivocation_body(s, templ, &k1, 1, sh, 1, u256(0x1112));
    let t = act_tx(&mut c, ActBody::Equivocation(e), &[], vec![]);
    assert_eq!(c.try_tx(&t), "OK");
}

#[test]
fn module_table_registers_yed() {
    // P4 (§15.7): the table holds exactly YED; WYEC is never registered (§4). YED's own rules
    // (ValidateCreate / ValidateSpend once configured) are the YED module's (W5-f); until then
    // its entry is inert and accepts everything (the C++ unconfigured fallback).
    let table = registered_modules();
    assert_eq!(table.len(), 1);
    assert_eq!(table[0].0, Tag([b'Y', b'E', b'D', 0]));
    assert!(find_module(table, &YED_TAG).is_some());
    assert!(find_module(table, &Tag(*b"WYEC")).is_none());
    let yed = find_module(table, &YED_TAG).unwrap();
    let st = SetState::new();
    let ctx = ModuleContext {
        height: 0,
        state: &st,
        block_hash_at: None,
    };
    let tx = VaultTx::default();
    let vp = vault_for(u256(0x99), &make_key(1), 0);
    assert!(yed.validate_create(&tx, 0, &vp, &ctx).is_ok());
    let spend = kogany_vault::template::TemplateSpend {
        params: kogany_vault::template::TemplateParams::Vault(vp),
        selector: 1,
        sigs: vec![],
    };
    assert!(yed.validate_spend(&tx, 0, &spend, &ctx).is_ok());
    assert!(yed.check_block(&[], &ctx).is_ok());
    assert!(yed.governed_set().is_none());
    assert!(yed.ejections(&tx, &ctx).is_empty());
    assert!(yed.liveness(&tx, &ctx).is_empty());
}

#[test]
fn record_serialization() {
    let r = SetRecord {
        params: params(false),
        create_height: 7,
        wind_down_height: 9,
        locked_value: 123,
        epoch: 4,
        epoch_basis: 99,
        epoch_used: 3,
        join_count: 0,
    };
    let q = SetRecord::decode(&r.encode()).unwrap();
    assert_eq!(q, r);
    assert_eq!(q.wind_down_height, 9);
    assert_eq!(q.epoch_used, 3);
    // The C++ byte layout: params (5 u8, u16, 3 x u32... as SetCreateBody), the admit key as
    // CompactSize 33 ‖ 33 bytes, six i64; join_count only when non-zero.
    let e = r.encode();
    assert_eq!(e.len(), 5 + 2 + 4 + 4 + 8 + 4 + 4 + 34 + 6 * 8);
    assert_eq!(e[31], 33); // the admit key's CompactSize
    let mut rj = r;
    rj.join_count = 2;
    assert_eq!(rj.encode().len(), e.len() + 4);
    assert_eq!(SetRecord::decode(&rj.encode()).unwrap(), rj);

    let m = MemberRecord {
        bond_outpoint: OutPoint {
            txid: u256(1),
            n: 2,
        },
        bond_value: 5,
        status: MemberStatus::Ejected,
        bond_frozen: true,
        ..MemberRecord::default()
    };
    let n = MemberRecord::decode(&m.encode()).unwrap();
    assert!(
        n.bond_outpoint == m.bond_outpoint && n.status == MemberStatus::Ejected && n.bond_frozen
    );
    assert_eq!(m.encode().len(), 36 + 8 + 4 + 8 + 8 + 1 + 1);
    let t = TemplateOutRecord {
        kind: TemplateOutKind::Intent,
        height: 3,
        value: 4,
        script_pubkey: vec![1, 2, 3],
        origin: vec![],
    };
    assert_eq!(TemplateOutRecord::decode(&t.encode()).unwrap(), t);
    assert_eq!(
        t.encode(),
        [
            &[1u8][..],
            &3i64.to_le_bytes(),
            &4i64.to_le_bytes(),
            &[3, 1, 2, 3, 0]
        ]
        .concat()
    );
    // Trailing garbage or a short record does not decode.
    assert!(SetRecord::decode(&[e.clone(), vec![0]].concat()).is_none());
    assert!(MemberRecord::decode(&m.encode()[..10]).is_none());
}

/// `OP_RETURN <pubkey> <block hash> <height LE32>` outputs (C++ `EjectingTestModule`): every
/// member key whose evidence names the chain's block at that height.
#[derive(Default)]
struct EjectingTestModule {
    governed: Option<SetId>,
    heights_seen: Mutex<Vec<i64>>,
}

fn evidence_keys(tx: &VaultTx, ctx: &ModuleContext<'_>) -> Vec<PubKeyBytes> {
    let mut out = Vec::new();
    for o in &tx.outputs {
        let Some(t) = kogany_vault::script::tokenize(&o.script_pubkey) else {
            continue;
        };
        let [ret, key, hash, height, ..] = t.as_slice() else {
            continue;
        };
        if ret.op != op::OP_RETURN || hash.data.len() != 32 || height.data.len() != 4 {
            continue;
        }
        let Some(hashes) = ctx.block_hash_at else {
            continue;
        };
        let at = i64::from(u32::from_le_bytes(height.data.try_into().unwrap()));
        if hashes(at) != Hash32::from_slice(hash.data) {
            continue;
        }
        if let Some(k) = PubKeyBytes::from_slice(key.data) {
            out.push(k);
        }
    }
    out
}

impl Module for EjectingTestModule {
    fn governed_set(&self) -> Option<SetId> {
        self.governed
    }
    fn ejections(&self, tx: &VaultTx, ctx: &ModuleContext<'_>) -> Vec<PubKeyBytes> {
        self.heights_seen.lock().unwrap().push(ctx.height);
        evidence_keys(tx, ctx)
    }
}

fn fake_hash(h: i64, tag: u8) -> Hash32 {
    let mut x = [0u8; 32];
    x[0] = (h & 0xff) as u8;
    x[1] = ((h >> 8) & 0xff) as u8;
    x[31] = tag;
    Hash32(x)
}

fn hash_provider(tip: i64, tag: u8) -> BlockHashFn<'static> {
    leak(move |h: i64| (0..tip).contains(&h).then(|| fake_hash(h, tag)))
}

fn evidence(c: &mut Chain, k: &Key, at: i64, hash: Hash32) -> VaultTx {
    let f = c.fund10();
    let spk = Builder::new()
        .op(op::OP_RETURN)
        .push(&k.pubkey().0)
        .push(&hash.0)
        .push(&(at as u32).to_le_bytes())
        .into_bytes();
    mk(vec![txin(f, vec![])], vec![txout(0, spk)])
}

#[test]
fn module_ejection_hook_eqv1() {
    let mut c = Chain::new();
    let (k1, k2, k3, outsider) = (make_key(61), make_key(62), make_key(65), make_key(63));
    let s = set_with_members(&mut c, &[k1, k2]);
    let other = set_with_members(&mut c, &[k3]);
    let bond1 = c.member(&s, &k1).bond_outpoint;
    let bond3 = c.member(&other, &k3).bond_outpoint;
    let cited = c.h - 3;
    let hashes = hash_provider(c.h, 0xab);
    let e = evidence(&mut c, &k1, cited, fake_hash(cited, 0xab));
    let mut rules = c.rules();
    rules.block_hashes = Some(hashes);

    // Through apply_tx over the registered table (YED inert): nothing happens, valid.
    {
        let mut st = VaultOverlay::new(&c.st);
        assert_eq!(res(st.apply_tx(&e, c.h, &c.coins, &rules)), "OK");
        assert!(st.is_empty());
    }
    let mut module = EjectingTestModule::default();
    // No governed set; a governed set that does not exist: nothing happens, not asked.
    {
        let mut st = VaultOverlay::new(&c.st);
        st.apply_ejections_of(&module, &e, c.h, &rules);
        assert!(st.is_empty());
    }
    module.governed = Some(u256(0x5e7));
    {
        let mut st = VaultOverlay::new(&c.st);
        st.apply_ejections_of(&module, &e, c.h, &rules);
        assert!(st.is_empty());
    }
    assert!(module.heights_seen.lock().unwrap().is_empty());
    module.governed = Some(s);
    // No block hashes: the module cannot check its evidence.
    {
        let mut st = VaultOverlay::new(&c.st);
        st.apply_ejections_of(&module, &e, c.h, &c.rules());
        assert!(st.is_empty());
    }
    // Evidence over the wrong hash; a non-member; a member of another set: nothing happens.
    for ev in [
        evidence(&mut c, &k1, cited, fake_hash(cited + 1, 0xab)),
        evidence(&mut c, &outsider, cited, fake_hash(cited, 0xab)),
        evidence(&mut c, &k3, cited, fake_hash(cited, 0xab)),
    ] {
        let mut st = VaultOverlay::new(&c.st);
        st.apply_ejections_of(&module, &ev, c.h, &rules);
        assert!(st.is_empty());
        assert!(!st.bond(&bond3).unwrap().frozen);
        assert_eq!(
            st.member(&other, &k3.pubkey()).unwrap().status,
            MemberStatus::Active
        );
    }

    // The evidence: k1 EJECTED and its bond frozen; k2 untouched; the module saw the height.
    let ev2 = evidence(&mut c, &k1, cited - 1, fake_hash(cited - 1, 0xab));
    let mut st = VaultOverlay::new(&c.st);
    module.heights_seen.lock().unwrap().clear();
    st.apply_ejections_of(&module, &e, c.h, &rules);
    assert_eq!(*module.heights_seen.lock().unwrap(), vec![c.h]);
    assert_eq!(
        st.member(&s, &k1.pubkey()).unwrap().status,
        MemberStatus::Ejected
    );
    assert!(st.member(&s, &k1.pubkey()).unwrap().bond_frozen);
    assert!(st.bond(&bond1).unwrap().frozen);
    assert_eq!(
        st.member(&s, &k2.pubkey()).unwrap().status,
        MemberStatus::Active
    );
    // In the same overlay a later spend of the frozen bond is invalid; a second report changes
    // nothing.
    let spend_bond = mk(
        vec![txin(bond1, vec![])],
        vec![txout(500, p2pkh(&k1.pubkey()))],
    );
    assert_eq!(
        res(st.apply_tx(&spend_bond, c.h, &c.coins, &rules)),
        "bad-vault-bond-frozen"
    );
    let before = st.delta();
    st.apply_ejections_of(&module, &ev2, c.h, &rules);
    assert_eq!(st.delta(), before);
    assert!(!eject_and_freeze(&mut st, &s, &k1.pubkey()));
    assert!(!eject_and_freeze(&mut st, &s, &outsider.pubkey()));
    assert_eq!(st.delta(), before);
    // The undo restores the base byte for byte.
    let d = st.delta();
    let mut after = c.st.with(&d);
    after.revert(&d);
    assert_eq!(after, c.st);
    // AncestorHashes (the node's provider over the block index) is W4-d's.
}

#[test]
fn module_ejection_hook_eqv1_yed() {
    // The YED half (EQV-1: two signed prices for one (seq, citedHeight, blockHash)) is the
    // YED module's (W5-f). The primitive half — a registered module's ejection reaches the
    // governed set through apply_tx and apply_block, in the same overlay, undo-covered — with
    // a test module registered in the table.
    let mut c = Chain::new();
    let (k1, k2) = (make_key(61), make_key(62));
    let s = set_with_members(&mut c, &[k1, k2]);
    let bond1 = c.member(&s, &k1).bond_outpoint;
    let cited = c.h - 3;
    let module: &'static EjectingTestModule = leak(EjectingTestModule {
        governed: Some(s),
        ..Default::default()
    });
    let table: &'static [ModuleEntry<'static>] = leak([(Tag(*b"TST\0"), module as &dyn Module)]);
    c.modules = table;
    c.hashes = Some(hash_provider(c.h, 0xab));
    let e = evidence(&mut c, &k1, cited, fake_hash(cited, 0xab));
    // No block hashes: nothing happens.
    {
        let mut rules = c.rules();
        rules.block_hashes = None;
        let d = check_tx(&c.st, &e, c.h, &c.coins, &rules).unwrap();
        assert!(d.is_empty());
    }
    let rules = c.rules();
    let e2 = evidence(&mut c, &k1, cited - 1, fake_hash(cited - 1, 0xab));
    let mut st = VaultOverlay::new(&c.st);
    assert_eq!(res(st.apply_tx(&e, c.h, &c.coins, &rules)), "OK");
    assert_eq!(
        st.member(&s, &k1.pubkey()).unwrap().status,
        MemberStatus::Ejected
    );
    assert!(st.bond(&bond1).unwrap().frozen);
    assert_eq!(
        st.member(&s, &k2.pubkey()).unwrap().status,
        MemberStatus::Active
    );
    let spend_bond = mk(
        vec![txin(bond1, vec![])],
        vec![txout(500, p2pkh(&k1.pubkey()))],
    );
    assert_eq!(
        res(st.apply_tx(&spend_bond, c.h, &c.coins, &rules)),
        "bad-vault-bond-frozen"
    );
    let before = st.delta();
    assert_eq!(res(st.apply_tx(&e2, c.h, &c.coins, &rules)), "OK");
    assert_eq!(st.delta(), before);
    let d = st.delta();
    let mut after = c.st.with(&d);
    after.revert(&d);
    assert_eq!(after, c.st);
    // The same through apply_block (what the block connect does).
    let d = apply_block(&c.st, &[e], c.h, &c.coins, &rules).unwrap();
    assert!(c.st.with(&d).bond(&bond1).unwrap().frozen);
}

#[test]
fn module_ejection_hook_cancel_statement() {
    // C4b's evidence shape (an attestation and a cancel statement at one height with different
    // prices) is the YED module's (W5-f). The primitive's effect is the same ejection as
    // module_ejection_hook_eqv1_yed: here, a second evidence for another member in one block
    // ejects each, and the untouched member stays ACTIVE.
    let mut c = Chain::new();
    let (k1, k2, k3) = (make_key(71), make_key(72), make_key(73));
    let s = set_with_members(&mut c, &[k1, k2, k3]);
    let module: &'static EjectingTestModule = leak(EjectingTestModule {
        governed: Some(s),
        ..Default::default()
    });
    c.modules = leak([(Tag(*b"TST\0"), module as &dyn Module)]);
    c.hashes = Some(hash_provider(c.h, 0xcd));
    let cited = c.h - 3;
    let e1 = evidence(&mut c, &k1, cited, fake_hash(cited, 0xcd));
    let e2 = evidence(&mut c, &k2, cited - 1, fake_hash(cited - 1, 0xcd));
    assert_eq!(c.block(&[e1, e2]), "OK");
    assert_eq!(c.member(&s, &k1).status, MemberStatus::Ejected);
    assert_eq!(c.member(&s, &k2).status, MemberStatus::Ejected);
    assert_eq!(c.member(&s, &k3).status, MemberStatus::Active);
}

/// Credits `(key, height)` for every `OP_RETURN <pubkey> <height LE32>` output (a stand-in for
/// the YED module's attestation credit).
struct LivenessTestModule {
    governed: SetId,
}

impl Module for LivenessTestModule {
    fn governed_set(&self) -> Option<SetId> {
        Some(self.governed)
    }
    fn liveness(&self, tx: &VaultTx, _ctx: &ModuleContext<'_>) -> Vec<(PubKeyBytes, i64)> {
        let mut out = Vec::new();
        for o in &tx.outputs {
            let Some(t) = kogany_vault::script::tokenize(&o.script_pubkey) else {
                continue;
            };
            let [ret, key, height] = t.as_slice() else {
                continue;
            };
            if ret.op != op::OP_RETURN || height.data.len() != 4 {
                continue;
            }
            if let Some(k) = PubKeyBytes::from_slice(key.data) {
                out.push((
                    k,
                    i64::from(u32::from_le_bytes(height.data.try_into().unwrap())),
                ));
            }
        }
        out
    }
}

#[test]
fn module_liveness_hook() {
    // Seats review B2: the primitive half of the liveness hook — a credited (key, height) of an
    // ACTIVE member of the governed set with an unspent, unfrozen bond and
    // lastAct < height < block height sets lastAct = height; anything else is ignored. Which
    // bundles credit whom (BUNDLE-1, joinOrdinal → seq, REF_WINDOW, the signature cache) is
    // the YED module's (W5-f). joinOrdinal / joinCount are asserted here.
    let mut c = Chain::new();
    let (k1, k2, k3, outsider) = (make_key(61), make_key(62), make_key(64), make_key(63));
    let mut sp = params(true);
    sp.maturity = 2;
    let s = set_with_members_p(&mut c, &[k1, k2], sp);
    assert_eq!(c.member(&s, &k1).join_ordinal, 1);
    assert_eq!(c.member(&s, &k2).join_ordinal, 2);
    assert_eq!(c.st.set(&s).unwrap().join_count, 2);
    let other = set_with_members_p(&mut c, &[k3], sp);
    c.empty(60);
    c.modules = leak([(
        Tag(*b"TST\0"),
        leak(LivenessTestModule { governed: s }) as &dyn Module,
    )]);
    let credit = |c: &mut Chain, k: &Key, at: i64| {
        let f = c.fund10();
        let spk = Builder::new()
            .op(op::OP_RETURN)
            .push(&k.pubkey().0)
            .push(&(at as u32).to_le_bytes())
            .into_bytes();
        mk(vec![txin(f, vec![])], vec![txout(0, spk)])
    };
    let r = c.h - 2;
    let (before1, before2) = (c.member(&s, &k1).last_act, c.member(&s, &k2).last_act);
    assert!(before1 < r - 1 && before2 < r - 1);
    let try_last = |c: &Chain, tx: &VaultTx| {
        let d = check_tx(&c.st, tx, c.h, &c.coins, &c.rules()).unwrap();
        let st = c.st.with(&d);
        (
            st.member(&s, &k1.pubkey()).unwrap().last_act,
            st.member(&s, &k2.pubkey()).unwrap().last_act,
        )
    };
    let t = credit(&mut c, &k1, r);
    assert_eq!(try_last(&c, &t), (r, before2));
    let t = credit(&mut c, &k2, r - 1);
    assert_eq!(try_last(&c, &t), (before1, r - 1));
    // At or above the block height; at or below lastAct; an outsider; a member of another set:
    // nobody is credited.
    for (k, at) in [
        (k1, c.h),
        (k1, c.h + 5),
        (k1, before1),
        (k1, before1 - 1),
        (outsider, r),
        (k3, r),
    ] {
        let t = credit(&mut c, &k, at);
        assert_eq!(try_last(&c, &t), (before1, before2));
    }
    // The member of the other set is untouched by a credit naming it.
    let k3_before = c.st.member(&other, &k3.pubkey()).unwrap().last_act;
    let t = credit(&mut c, &k3, r);
    let d = check_tx(&c.st, &t, c.h, &c.coins, &c.rules()).unwrap();
    assert_eq!(
        c.st.with(&d).member(&other, &k3.pubkey()).unwrap().last_act,
        k3_before
    );
    // A frozen bond or a member that is not ACTIVE is not credited.
    let t = remove_tx(&mut c, s, k2.pubkey(), false, &[k2]);
    assert_eq!(c.block1(&t), "OK");
    let t = credit(&mut c, &k2, r);
    assert_eq!(try_last(&c, &t).1, before2);
    let e = equivocation_body(
        s,
        OutPoint {
            txid: u256(0x99),
            n: 0,
        },
        &k1,
        1,
        u256(1),
        1,
        u256(2),
    );
    let t = act_tx(&mut c, ActBody::Equivocation(e), &[], vec![]);
    assert_eq!(c.block1(&t), "OK");
    let t = credit(&mut c, &k1, r);
    assert_eq!(try_last(&c, &t).0, before1);
}

#[test]
fn join_ordinal_reorg() {
    // A disconnected SET_JOIN gives back its ordinal (joinCount restored by the undo); on one
    // chain no two joins share an ordinal.
    let mut c = Chain::new();
    let (k1, k2, k3) = (make_key(81), make_key(82), make_key(83));
    let s = set_with_members(&mut c, &[k1, k2]);
    assert_eq!(c.st.set(&s).unwrap().join_count, 2);
    let before = c.st.clone();
    let t = join_tx(&mut c, s, &k3, &[]);
    assert_eq!(c.block1(&t), "OK");
    assert_eq!(c.st.set(&s).unwrap().join_count, 3);
    assert_eq!(c.member(&s, &k3).join_ordinal, 3);
    {
        let mut back = c.st.clone();
        back.revert(&c.history.last().unwrap().1);
        assert_eq!(back.canonical_entries(), before.canonical_entries());
        assert_eq!(back.set(&s).unwrap().join_count, 2);
        assert!(back.member(&s, &k3.pubkey()).is_none());
    }
    // a member that leaves, withdraws and rejoins takes a new ordinal
    let t = remove_tx(&mut c, s, k1.pubkey(), false, &[k1]);
    assert_eq!(c.block1(&t), "OK");
    let bond1 = c.member(&s, &k1).bond_outpoint;
    c.empty(5);
    let t = spend_tx(&mut c, bond1, 1, vec![txout(900, recipient(7))], false);
    assert_eq!(c.block1(&t), "OK");
    let t = join_tx(&mut c, s, &k1, &[]);
    assert_eq!(c.block1(&t), "OK");
    assert_eq!(c.member(&s, &k1).join_ordinal, 4);
    assert_eq!(c.st.set(&s).unwrap().join_count, 4);
}

/// Names a fixed member to displace for joins into the governed set, and rejects a block
/// carrying a SET_REMOVE or SET_WINDDOWN of it (a stand-in for the YED module's eviction rule
/// and its CheckBlock).
struct DisplacingTestModule {
    governed: SetId,
    victim: Mutex<Option<PubKeyBytes>>,
}

impl Module for DisplacingTestModule {
    fn governed_set(&self) -> Option<SetId> {
        Some(self.governed)
    }
    fn displace(
        &self,
        _tx: &VaultTx,
        join: &kogany_vault::act::SetJoinBody,
        _ctx: &ModuleContext<'_>,
    ) -> Option<PubKeyBytes> {
        assert_eq!(join.set_id, self.governed);
        *self.victim.lock().unwrap()
    }
    fn check_block(&self, txs: &[VaultTx], _ctx: &ModuleContext<'_>) -> Result<(), VaultReject> {
        for tx in txs {
            for o in &tx.outputs {
                if let Ok(a) = kogany_vault::act::decode_act(&o.script_pubkey) {
                    let hits = matches!(a.body, ActBody::Remove(r) if r.set_id == self.governed)
                        || matches!(a.body, ActBody::WindDown(w) if w.set_id == self.governed);
                    if hits {
                        return Err(VaultReject::Module("bad-test-attestor-set-act".into()));
                    }
                }
            }
        }
        Ok(())
    }
}

#[test]
fn module_displace_hook() {
    // A SET_JOIN into a full set the module governs displaces the member the module names
    // (REMOVED, the bond neither frozen nor unindexed, exit delay from the join); an
    // ungoverned set, or a refused/invalid name, refuses the join as before. Which member the
    // YED module picks (bond weight, liveness, the dust floor) is W5-f's.
    let mut c = Chain::new();
    let mut p = params(true);
    p.seats = 15;
    p.unlock_threshold = 1;
    p.cancel_threshold = 1;
    p.slash_threshold = 1;
    p.maturity = 8;
    let keys: Vec<Key> = (0..15).map(|i| make_key(70 + i)).collect();
    let s = set_with_members_p(&mut c, &keys, p);
    let mut small = params(true);
    small.seats = 1;
    small.unlock_threshold = 1;
    small.cancel_threshold = 1;
    small.slash_threshold = 1;
    let s1 = set_with_members_p(&mut c, &[make_key(69)], small);
    assert_eq!(count_active(&c.st.members(&s)), 15);

    // Ungoverned: full is full, whatever the bond.
    let t = join_tx_with(&mut c, s, &make_key(90), &[], 100_000, 1000);
    assert_eq!(c.try_tx(&t), "bad-vault-act-seats");
    let module: &'static DisplacingTestModule = leak(DisplacingTestModule {
        governed: s,
        victim: Mutex::new(None),
    });
    c.modules = leak([(Tag(*b"TST\0"), module as &dyn Module)]);
    // Governed, but the module names nobody; another (ungoverned) full set: refused.
    let t = join_tx_with(&mut c, s, &make_key(90), &[], 2000, 1000);
    assert_eq!(c.try_tx(&t), "bad-vault-act-seats");
    *module.victim.lock().unwrap() = Some(keys[14].pubkey());
    let t = join_tx_with(&mut c, s1, &make_key(90), &[], 2000, 1000);
    assert_eq!(c.try_tx(&t), "bad-vault-act-seats");
    // A name that is not an ACTIVE member with its own unfrozen bond, or the joining key: refused.
    *module.victim.lock().unwrap() = Some(make_key(99).pubkey());
    let t = join_tx_with(&mut c, s, &make_key(90), &[], 2000, 1000);
    assert_eq!(c.try_tx(&t), "bad-vault-act-seats");
    *module.victim.lock().unwrap() = Some(make_key(90).pubkey());
    let t = join_tx_with(&mut c, s, &make_key(90), &[], 2000, 1000);
    assert_eq!(c.try_tx(&t), "bad-vault-act-seats");
    // A member's own join while ACTIVE is still bad-vault-act-join (after the seats check).
    *module.victim.lock().unwrap() = Some(keys[14].pubkey());
    let t = join_tx_with(&mut c, s, &keys[0], &[], 5000, 1000);
    assert_eq!(c.try_tx(&t), "bad-vault-act-join");
    let young_bond = c.member(&s, &keys[14]).bond_outpoint;
    let big = join_tx_with(&mut c, s, &make_key(90), &[], 2000, 1000);
    let before = c.st.clone();
    assert_eq!(c.block1(&big), "OK");
    assert_eq!(c.member(&s, &keys[14]).status, MemberStatus::Removed);
    assert!(!c.member(&s, &keys[14]).bond_frozen);
    assert!(!c.st.bond(&young_bond).unwrap().frozen);
    assert_eq!(c.member(&s, &make_key(90)).status, MemberStatus::Active);
    assert_eq!(count_active(&c.st.members(&s)), 15);
    for k in &keys[..14] {
        assert_eq!(c.member(&s, k).status, MemberStatus::Active);
    }
    // The block's undo restores the base byte for byte.
    {
        let mut back = c.st.clone();
        back.revert(&c.history.last().unwrap().1);
        assert_eq!(back.canonical_entries(), before.canonical_entries());
    }
    // The displaced bond is returned the set's maturity (8) after the displacement.
    let exit = c.h - 1;
    assert_eq!(c.st.bond(&young_bond).unwrap().exit_height, exit);
    let sp = mk(
        vec![txin(young_bond, vec![])],
        vec![txout(500, recipient(91))],
    );
    let rules = c.rules();
    assert_eq!(
        res(check_tx(&c.st, &sp, exit + 7, &c.coins, &rules)),
        "bad-vault-bond-locked"
    );
    let d = check_tx(&c.st, &sp, exit + 8, &c.coins, &rules).unwrap();
    let st = c.st.with(&d);
    assert!(st.bond(&young_bond).is_none());
    assert_eq!(
        st.member(&s, &keys[14].pubkey()).unwrap().status,
        MemberStatus::Removed
    );
    // The module's CheckBlock: a block with a SET_REMOVE or SET_WINDDOWN of the governed set is
    // invalid; of another set, not; per transaction the primitive admits it.
    let t = remove_tx(&mut c, s, keys[1].pubkey(), false, &[keys[2]]);
    assert_eq!(
        c.block(std::slice::from_ref(&t)),
        "bad-test-attestor-set-act"
    );
    let t2 = winddown_tx(&mut c, s, &[keys[2]]);
    assert_eq!(c.block1(&t2), "bad-test-attestor-set-act");
    assert_eq!(c.try_tx(&t), "OK");
    let t3 = winddown_tx(&mut c, s1, &[make_key(69)]);
    assert_eq!(c.block1(&t3), "OK");
    // Unconfigured again: no displacement.
    c.modules = registered_modules();
    let t = join_tx_with(&mut c, s, &make_key(92), &[], 100_000, 1000);
    assert_eq!(c.try_tx(&t), "bad-vault-act-seats");
}

#[test]
fn state_hash_preimage() {
    // The statehash preimage (C++ vault::StateHash): CompactSize-prefixed key and value, every
    // entry in key byte order ('b' < 'm' < 's' < 'v'), SHA256d. The empty state is
    // SHA256d("") = 5df6e0e2…, displayed reversed.
    assert_eq!(
        display_hex(&SetState::new().state_hash()),
        "56944c5d3f98413ef45cf54545538103cc9f298e0575820ad3591376e2e0f65d"
    );
    let mut c = Chain::new();
    let owner = make_key(50);
    let s = set_with_members(&mut c, &[make_key(1), make_key(2)]);
    lock(&mut c, &vault_for(s, &owner, 0), 7000);
    let entries = c.st.canonical_entries();
    let mut pre = Vec::new();
    for (k, v) in &entries {
        pre.push(k.len() as u8);
        pre.extend_from_slice(k);
        assert!(v.len() < 253);
        pre.push(v.len() as u8);
        pre.extend_from_slice(v);
    }
    assert_eq!(c.st.state_hash(), sha256d(&pre));
    let prefixes: Vec<u8> = entries.keys().map(|k| k[0]).collect();
    let mut sorted = prefixes.clone();
    sorted.sort();
    assert_eq!(prefixes, sorted);
    assert_eq!(prefixes.first(), Some(&b'b'));
    assert_eq!(prefixes.last(), Some(&b'v'));
    // A bond key orders by n's little-endian bytes, not numerically (the C++ string keys).
    let a = kogany_vault::state::records::key_bond(&OutPoint {
        txid: Hash32::ZERO,
        n: 256,
    });
    let b = kogany_vault::state::records::key_bond(&OutPoint {
        txid: Hash32::ZERO,
        n: 1,
    });
    assert!(a < b);
    let _ = public_key;
    let _: Rules<'static> = Rules::new(0, 0);
}
