// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

//! The YED halves of ycash6 `src/test/vault_state_tests.cpp` `module_ejection_hook_eqv1_yed`,
//! `module_ejection_hook_cancel_statement` and `module_liveness_hook` (P4-b, U-25, C4b, seats
//! review B2), C++ names kept: the attest hooks ([`kogany_yellowback::attest::hooks`]) in a test
//! module registered in the primitive's table, driven through `kogany-vault`'s own test chain
//! (`crates/kogany-vault/tests/state_common`, included read-only by path), plus the displacement
//! and `CheckBlock` hooks.

mod attest_common;
mod common;
#[path = "../../kogany-vault/tests/state_common/mod.rs"]
mod state_common;

use attest_common::{enc, sha256, RecordingCache};
use kogany_vault::act::{ActBody, SetCreateBody, SetJoinBody, SetWindDownBody};
use kogany_vault::state::{
    BlockHashFn, MemberStatus, Module, ModuleContext, ModuleEntry, StateRead, VaultReject, VaultTx,
    YED_TAG,
};
use kogany_vault::{Hash32, OutPoint, PubKeyBytes, SetId};
use kogany_yellowback::attest::hooks::{
    adopted_set, yed_check_block, yed_displace, yed_ejections, yed_liveness,
};
use kogany_yellowback::attest::{
    attest_message, cancel_cosign_message, encode_cancel_evidence, eviction_victim, Attestation,
    CancelStatement, SeatCandidate, SigCache,
};
use kogany_yellowback::codecs::payload::{
    encode_payload as encode_yed_payload, payload_script, ClaimNotice, Payload,
};
use kogany_yellowback::codecs::script::{carrier_script, carrier_script_sig};
use kogany_yellowback::params::{regtest_params, Params};
use state_common::*;

fn leak<T>(v: T) -> &'static T {
    Box::leak(Box::new(v))
}

/// The YED module's attest hooks, as W5-f will register them.
struct YedHooks {
    p: Params,
    cache: Option<&'static RecordingCache>,
}

impl Module for YedHooks {
    fn governed_set(&self) -> Option<SetId> {
        kogany_yellowback::attest::mirror::attestor_set_id(&self.p)
    }
    fn ejections(&self, tx: &VaultTx, ctx: &ModuleContext<'_>) -> Vec<PubKeyBytes> {
        yed_ejections(&self.p, tx, ctx)
    }
    fn check_block(&self, txs: &[VaultTx], _ctx: &ModuleContext<'_>) -> Result<(), VaultReject> {
        yed_check_block(&self.p, txs)
    }
    fn displace(
        &self,
        tx: &VaultTx,
        join: &SetJoinBody,
        ctx: &ModuleContext<'_>,
    ) -> Option<PubKeyBytes> {
        yed_displace(&self.p, tx, join, ctx)
    }
    fn liveness(&self, tx: &VaultTx, ctx: &ModuleContext<'_>) -> Vec<(PubKeyBytes, i64)> {
        yed_liveness(&self.p, tx, ctx, self.cache.map(|c| c as &dyn SigCache))
    }
}

fn register(c: &mut Chain, p: Params, cache: Option<&'static RecordingCache>) {
    let m: &'static YedHooks = leak(YedHooks { p, cache });
    let table: &'static [ModuleEntry<'static>] = leak([(YED_TAG, m as &dyn Module)]);
    c.modules = table;
}

fn fake_hash(h: i64, tag: u8) -> Hash32 {
    let mut x = [0u8; 32];
    x[0] = (h & 0xff) as u8;
    x[1] = ((h >> 8) & 0xff) as u8;
    x[31] = tag;
    Hash32(x)
}

fn hashes(tip: i64, tag: u8) -> BlockHashFn<'static> {
    leak(move |h: i64| (0..tip).contains(&h).then(|| fake_hash(h, tag)))
}

/// An attestation signed with the key's recoverable signer, its `r || s` (C++ `SignCompact`
/// with the header byte dropped).
fn att(k: &Key, seq: u16, price: u32, at: i64, tag: u8) -> Attestation {
    let cited = u32::try_from(at).unwrap();
    let rec = k.sign(&attest_message(seq, price, cited, &fake_hash(at, tag)));
    Attestation {
        seq,
        price_micro_usd: price,
        cited_height: cited,
        sig: rec.0[1..].try_into().unwrap(),
    }
}

/// A transaction spending a funded coin with a carrier scriptSig of `raw` and the payload `p`.
fn carrier_tx(c: &mut Chain, raw: &[u8], p: &Payload) -> VaultTx {
    let redeem = carrier_script(&make_key(64).pubkey(), &sha256(raw)).unwrap();
    let f = c.fund10();
    mk(
        vec![txin(f, carrier_script_sig(raw, &[0x30; 71], &redeem))],
        vec![txout(0, payload_script(&encode_yed_payload(p).unwrap()))],
    )
}

fn res_of(c: &Chain, tx: &VaultTx) -> (String, kogany_vault::state::SetState) {
    match kogany_vault::state::check_tx(&c.st, tx, c.h, &c.coins, &c.rules()) {
        Ok(d) => ("OK".to_owned(), c.st.with(&d)),
        Err(e) => (e.reason().to_owned(), c.st.clone()),
    }
}

#[test]
fn module_ejection_hook_eqv1_yed() {
    let mut c = Chain::new();
    let (k1, k2, outsider) = (make_key(61), make_key(62), make_key(63));
    let s = set_with_members(&mut c, &[k1, k2]);
    let bond1 = c.member(&s, &k1).bond_outpoint;
    let cited = c.h - 3;
    let eqv = |c: &mut Chain, a: Attestation, b: Attestation| {
        carrier_tx(c, &enc(&[a, b]), &Payload::Equivocation)
    };
    let e = eqv(
        &mut c,
        att(&k1, 7, 50_000, cited, 0xab),
        att(&k1, 7, 51_000, cited, 0xab),
    );
    // Unconfigured module (the inert table): nothing happens, the transaction is valid.
    c.hashes = Some(hashes(c.h, 0xab));
    let (r, st) = res_of(&c, &e);
    assert_eq!(r, "OK");
    assert!(!st.bond(&bond1).unwrap().frozen);
    let p = regtest_params(10, 0, 0, s.0);
    register(&mut c, p, None);
    // No block hashes: the module cannot verify, nothing happens.
    c.hashes = None;
    let (r, st) = res_of(&c, &e);
    assert_eq!(r, "OK");
    assert!(!st.bond(&bond1).unwrap().frozen);
    c.hashes = Some(hashes(c.h, 0xab));
    // Not an equivocation: the same price; another key; a cited height at the block.
    let same = eqv(
        &mut c,
        att(&k1, 7, 50_000, cited, 0xab),
        att(&k1, 7, 50_000, cited, 0xab),
    );
    let other = eqv(
        &mut c,
        att(&outsider, 7, 50_000, cited, 0xab),
        att(&outsider, 7, 51_000, cited, 0xab),
    );
    let hh = c.h;
    let at_block = eqv(
        &mut c,
        att(&k1, 7, 50_000, hh, 0xab),
        att(&k1, 7, 51_000, hh, 0xab),
    );
    for t in [&same, &other, &at_block] {
        let (r, st) = res_of(&c, t);
        assert_eq!(r, "OK");
        assert!(!st.bond(&bond1).unwrap().frozen);
        assert_eq!(
            st.member(&s, &k1.pubkey()).unwrap().status,
            MemberStatus::Active
        );
    }
    // The equivocation: k1 EJECTED and its bond frozen; k2 untouched.
    let (r, st) = res_of(&c, &e);
    assert_eq!(r, "OK");
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
    // Through a block: a later spend of the frozen bond in the same block is invalid.
    let spend = mk(
        vec![txin(bond1, vec![])],
        vec![txout(500, p2pkh(&k1.pubkey()))],
    );
    let rules = c.rules();
    let r = kogany_vault::state::apply_block(&c.st, &[e.clone(), spend], c.h, &c.coins, &rules);
    assert_eq!(res(r), "bad-vault-bond-frozen");
    assert_eq!(c.block1(&e), "OK");
    assert!(c.st.bond(&bond1).unwrap().frozen);
    // A second report changes nothing.
    let e2 = eqv(
        &mut c,
        att(&k1, 7, 50_000, cited, 0xab),
        att(&k1, 7, 52_000, cited, 0xab),
    );
    let before = c.st.clone();
    assert_eq!(c.block1(&e2), "OK");
    assert_eq!(c.st.canonical_entries(), before.canonical_entries());
}

#[test]
fn module_ejection_hook_cancel_statement() {
    let mut c = Chain::new();
    let (k1, k2) = (make_key(71), make_key(72));
    let s = set_with_members(&mut c, &[k1, k2]);
    let bond1 = c.member(&s, &k1).bond_outpoint;
    let cited = c.h - 3;
    c.hashes = Some(hashes(c.h, 0xab));
    let statement = |k: &Key, price: u32, set: &Hash32| {
        let intent = OutPoint {
            txid: u256(0x99),
            n: 1,
        };
        let msg = cancel_cosign_message(
            set,
            &intent.txid,
            intent.n,
            u32::try_from(cited).unwrap(),
            price,
            &fake_hash(cited, 0xab),
        );
        CancelStatement {
            intent,
            price_micro_usd: price,
            sig: k.sign(&msg),
        }
    };
    let ev = |c: &mut Chain, a: Attestation, st: CancelStatement| {
        carrier_tx(c, &encode_cancel_evidence(&a, &st), &Payload::Equivocation)
    };
    register(&mut c, regtest_params(10, 0, 0, s.0), None);
    // Not evidence: the same price (an honest canceller); another member's statement; another set.
    let honest = ev(
        &mut c,
        att(&k1, 3, 50_000, cited, 0xab),
        statement(&k1, 50_000, &s),
    );
    let mixed = ev(
        &mut c,
        att(&k1, 3, 50_000, cited, 0xab),
        statement(&k2, 60_000, &s),
    );
    let elsewhere = ev(
        &mut c,
        att(&k1, 3, 50_000, cited, 0xab),
        statement(&k1, 60_000, &u256(0x42)),
    );
    for t in [&honest, &mixed, &elsewhere] {
        let (r, st) = res_of(&c, t);
        assert_eq!(r, "OK");
        assert!(!st.bond(&bond1).unwrap().frozen);
        assert_eq!(
            st.member(&s, &k2.pubkey()).unwrap().status,
            MemberStatus::Active
        );
    }
    // The evidence: k1 EJECTED and its bond frozen; k2 untouched.
    let t = ev(
        &mut c,
        att(&k1, 3, 9000, cited, 0xab),
        statement(&k1, 50_000, &s),
    );
    let (r, st) = res_of(&c, &t);
    assert_eq!(r, "OK");
    assert_eq!(
        st.member(&s, &k1.pubkey()).unwrap().status,
        MemberStatus::Ejected
    );
    assert!(st.bond(&bond1).unwrap().frozen);
    assert_eq!(
        st.member(&s, &k2.pubkey()).unwrap().status,
        MemberStatus::Active
    );
}

#[test]
fn module_liveness_hook() {
    let mut c = Chain::new();
    let (k1, k2, outsider) = (make_key(61), make_key(62), make_key(63));
    let mut sp = params(true);
    sp.maturity = 2;
    let s = set_with_members_p(&mut c, &[k1, k2], sp);
    assert_eq!(c.member(&s, &k1).join_ordinal, 1); // seq 0
    assert_eq!(c.member(&s, &k2).join_ordinal, 2); // seq 1
    c.empty(60);
    c.hashes = Some(hashes(c.h, 0xcd));
    let r = c.h - 2;
    let r32 = u32::try_from(r).unwrap();
    let notice = Payload::ClaimNotice(ClaimNotice::from_outpoint(
        &OutPoint {
            txid: u256(0x77),
            n: 0,
        },
        r32,
    ));
    let (before1, before2) = (c.member(&s, &k1).last_act, c.member(&s, &k2).last_act);
    assert!(before1 < r - 1 && before2 < r - 1);
    let mut p = regtest_params(10, 0, 0, s.0);
    p.attestor_liveness_min = 1;
    p.attestor_seats = i32::from(sp.seats); // adopt this small test set
    p.bond_maturity = i32::try_from(sp.maturity).unwrap();
    p.attestor_unlock_threshold = i32::from(sp.unlock_threshold);
    p.attestor_cancel_threshold = i32::from(sp.cancel_threshold);
    assert_eq!(p.m_select, 2);
    let cache: &'static RecordingCache = leak(RecordingCache::default());
    register(&mut c, p, None);
    assert!(adopted_set(&p, &c.st).is_some());
    let last = |c: &Chain, t: &VaultTx| {
        let (r, st) = res_of(c, t);
        assert_eq!(r, "OK");
        (
            st.member(&s, &k1.pubkey()).unwrap().last_act,
            st.member(&s, &k2.pubkey()).unwrap().last_act,
        )
    };
    let a = |k: &Key, seq: u16, at: i64| att(k, seq, 50_000, at, 0xcd);
    // A bundle that passes: both signers credited at their cited heights.
    let pass = carrier_tx(&mut c, &enc(&[a(&k1, 0, r), a(&k2, 1, r - 1)]), &notice);
    assert_eq!(last(&c, &pass), (r, r - 1));
    // Through the node's cache: a second pass is all hits.
    register(&mut c, p, Some(cache));
    assert_eq!(last(&c, &pass), (r, r - 1));
    assert_eq!((cache.inserts(), cache.hits()), (2, 0));
    assert_eq!(last(&c, &pass), (r, r - 1));
    assert_eq!((cache.inserts(), cache.hits()), (2, 2));
    register(&mut c, p, None);
    // A refHeight older than REF_WINDOW credits nobody; exactly REF_WINDOW is credited.
    let old = c.h - i64::from(p.ref_window) - 1;
    assert!(old > before1 && old > before2);
    let old_notice = Payload::ClaimNotice(ClaimNotice::from_outpoint(
        &OutPoint {
            txid: u256(0x77),
            n: 0,
        },
        u32::try_from(old).unwrap(),
    ));
    let t = carrier_tx(&mut c, &enc(&[a(&k1, 0, old), a(&k2, 1, old)]), &old_notice);
    assert_eq!(last(&c, &t), (before1, before2));
    let edge = Payload::ClaimNotice(ClaimNotice::from_outpoint(
        &OutPoint {
            txid: u256(0x77),
            n: 0,
        },
        u32::try_from(old + 1).unwrap(),
    ));
    let t = carrier_tx(
        &mut c,
        &enc(&[a(&k1, 0, old + 1), a(&k2, 1, old + 1)]),
        &edge,
    );
    assert_eq!(last(&c, &t).0, old + 1);
    // Bundles that fail credit nobody.
    let mut forged = a(&k2, 1, r);
    forged.sig[5] ^= 1;
    let failing: Vec<(Vec<Attestation>, Payload)> = vec![
        (vec![a(&k1, 0, r)], notice.clone()),         // count < M_SELECT
        (vec![a(&k1, 0, r), forged], notice.clone()), // a forged signature
        (vec![a(&k1, 1, r), a(&k2, 0, r)], notice.clone()), // keys under each other's seq
        (vec![a(&k1, 0, r), a(&k2, 7, r)], notice.clone()), // an unknown seq
        (vec![a(&k1, 0, r), a(&outsider, 1, r)], notice.clone()), // an outsider
        (
            vec![a(&k1, 0, r), a(&k2, 1, r - i64::from(p.attest_max_age))],
            notice.clone(),
        ), // stale
        (vec![a(&k1, 0, r), a(&k1, 0, r - 1)], notice.clone()), // a duplicate seq
        (vec![a(&k1, 0, r), a(&k2, 1, r)], Payload::Equivocation), // not MINT/NOTICE/REDEEM
    ];
    for (atts, pl) in failing {
        let t = carrier_tx(&mut c, &enc(&atts), &pl);
        assert_eq!(last(&c, &t), (before1, before2));
    }
    // The module does not adopt a set below ATTESTOR_LIVENESS_MIN, nor one of another shape.
    for variant in 0..2 {
        let mut q = p;
        if variant == 0 {
            q.attestor_liveness_min = i32::try_from(sp.liveness_window).unwrap() + 1;
        } else {
            q.bond_maturity = 8;
        }
        register(&mut c, q, None);
        assert!(adopted_set(&q, &c.st).is_none());
        assert_eq!(last(&c, &pass).0, before1);
    }
}

#[test]
fn module_displace_and_check_block_hooks() {
    // The displacement hook names the eviction victim over the primitive's ACTIVE members of the
    // adopted set; CheckBlock refuses a SET_WINDDOWN (and a vote SET_REMOVE) of it.
    let mut c = Chain::new();
    let mut sp: SetCreateBody = params(true);
    sp.seats = 3;
    sp.unlock_threshold = 1;
    sp.cancel_threshold = 1;
    sp.slash_threshold = 1;
    sp.maturity = 8;
    sp.liveness_window = 1000;
    let keys = [make_key(81), make_key(82), make_key(83)];
    let s = set_with_members_p(&mut c, &keys, sp);
    let mut p = regtest_params(10, 0, 0, s.0);
    p.attestor_seats = 3;
    p.bond_maturity = 8;
    p.attestor_liveness_min = 16;
    register(&mut c, p, None);
    assert!(adopted_set(&p, &c.st).is_some());
    // A joiner at the module's floor far outweighs the members' small bonds: the member of least
    // seat weight (the latest joiner, least tenure) is displaced, as eviction_victim picks it.
    assert!(c.member(&s, &keys[0]).bond_value < p.bond_min_floor_zat);
    let bond = p.bond_min_floor_zat;
    let cands: Vec<SeatCandidate> =
        c.st.members(&s)
            .into_iter()
            .map(|(key, m)| SeatCandidate {
                key,
                bond_zat: m.bond_value,
                join_height: m.join_height,
                last_act: m.last_act,
            })
            .collect();
    let victim = eviction_victim(&cands, c.h, bond, i64::from(sp.liveness_window), &p).unwrap();
    assert_eq!(victim, keys[2].pubkey());
    let t = join_tx_with(&mut c, s, &make_key(90), &[], bond, 1000);
    assert_eq!(c.block1(&t), "OK");
    assert_eq!(
        c.st.member(&s, &victim).unwrap().status,
        MemberStatus::Removed
    );
    for k in &keys[..2] {
        assert_eq!(c.member(&s, k).status, MemberStatus::Active);
    }
    assert_eq!(c.member(&s, &make_key(90)).status, MemberStatus::Active);
    // A dust joiner below the module's floor is refused as into any full set.
    let t = join_tx_with(
        &mut c,
        s,
        &make_key(91),
        &[],
        p.bond_min_floor_zat - 1,
        1000,
    );
    assert_eq!(c.try_tx(&t), "bad-vault-act-seats");
    // CheckBlock: a SET_WINDDOWN of the attestor set makes the block invalid.
    let others: Vec<Key> = keys
        .iter()
        .copied()
        .filter(|k| k.pubkey() != victim)
        .collect();
    let wd = act_tx(
        &mut c,
        ActBody::WindDown(SetWindDownBody { set_id: s }),
        &others[..1],
        vec![],
    );
    assert_eq!(c.block1(&wd), "bad-yellowback-attestor-set-act");
    assert!(yed_check_block(&p, &[]).is_ok());
}
