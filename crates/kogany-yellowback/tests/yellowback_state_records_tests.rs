// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

//! The YED state's key space, record encodings and delta (W5-d1; ycash6 `view.{h,cpp}` at
//! `65cb4ae0f`): the typed key order is the canonical byte order, every key and record decodes
//! back from its canonical bytes (over the whole state the golden chain leaves), the fixed-width
//! records have the C++ sizes, and a block delta moves a state forward and back byte for byte.

mod common;
mod state_common;

use common::{h, load_pinned, uint256_display};
use kogany_vault::{Hash32, OutPoint};
use kogany_yellowback::attest::registry::AttestState;
use kogany_yellowback::params::{regtest_params_with, BundleCarrier};
use kogany_yellowback::state::{
    canonical_entries_of, evaluate_block, process_tx, state_hash, state_hash_preimage, Change,
    IntentRecord, IntentRole, Judgement, NoticeRecord, ParamsRecord, Snapshot, Table, TagRecord,
    TipRecord, TokenRecord, Totals, TxLogRecord, TxLogType, VaultRecord, VaultStatus, YedDelta,
    YedKey, YedOverlay, YedRead, YedRecord, YedState, NULL_OUTPOINT,
};
use state_common::fixture::*;
use state_common::rawtx::parse_v4;

fn some_op(seed: u8, n: u32) -> OutPoint {
    OutPoint {
        txid: Hash32([seed; 32]),
        n,
    }
}

#[test]
fn keys_order_is_byte_order() {
    let mut keys = vec![
        YedKey::Tip,
        YedKey::Totals,
        YedKey::Params,
        YedKey::Attest,
        YedKey::AttestorSeq,
        YedKey::AttestorSet,
    ];
    for x in [0u32, 1, 255, 256, 65_535, 65_536, 0x0100_0000, u32::MAX] {
        keys.extend([
            YedKey::Tag(x),
            YedKey::Judgement(x),
            YedKey::Snapshot(x),
            YedKey::BundleLog(x),
        ]);
    }
    for s in [0u16, 1, 255, 256, u16::MAX] {
        keys.push(YedKey::Attestor(s));
    }
    for (seed, n) in [
        (0u8, 0u32),
        (0, 1),
        (0, 256),
        (1, 0),
        (0xff, u32::MAX),
        (0x7f, 0x0100_0000),
    ] {
        let o = some_op(seed, n);
        keys.extend([
            YedKey::Vault(o),
            YedKey::Token(o),
            YedKey::Intent(o),
            YedKey::Notice(o),
            YedKey::BondIndex(o),
        ]);
        keys.push(YedKey::TxLog(Hash32([seed; 32])));
    }
    let mut by_ord = keys.clone();
    by_ord.sort();
    let mut by_bytes = keys.clone();
    by_bytes.sort_by_key(YedKey::encode);
    assert_eq!(
        by_ord, by_bytes,
        "the derived key order is the canonical byte order"
    );
    for k in &keys {
        assert_eq!(YedKey::decode(&k.encode()), Some(*k));
        let (lo, hi) = k.table().bounds();
        assert!(lo <= *k && *k <= hi, "{k:?} inside its table's bounds");
    }
    // the C++ key layouts
    assert_eq!(YedKey::Tag(0x0102_0304).encode(), vec![b'Q', 1, 2, 3, 4]);
    assert_eq!(YedKey::Attestor(0x0102).encode(), vec![b'A', 1, 2]);
    let v = YedKey::Vault(some_op(9, 0x0102_0304)).encode();
    assert_eq!(v.len(), 37);
    assert_eq!(v[0], b'V');
    assert_eq!(&v[33..], &[1, 2, 3, 4]);
    assert_eq!(YedKey::TxLog(Hash32([7; 32])).encode().len(), 33);
    assert!(YedKey::decode(b"U").is_none()); // the undo table is not state
    assert!(YedKey::decode(b"R").is_none()); // nor the node-local rules version
    assert!(YedKey::decode(b"Q123").is_none());
}

#[test]
fn record_encodings_round_trip_with_the_cpp_sizes() {
    let tip = TipRecord::zero("regtest");
    assert_eq!(TipRecord::decode(&tip.encode()), Some(tip.clone()));
    assert_eq!(tip.encode().len(), 4 + 32 + 4 + 1 + 7);
    let tag = TagRecord {
        payout_key: [3; 20],
        price_micro_usd: 50000,
        signal: true,
        source_mask: 7,
    };
    assert_eq!(tag.encode().len(), 31);
    assert_eq!(TagRecord::decode(&tag.encode()), Some(tag));
    let j = Judgement {
        evaluated: true,
        in_band: false,
        penalized: true,
    };
    assert_eq!(j.encode(), vec![1, 0, 1]);
    assert_eq!(Judgement::decode(&j.encode()), Some(j));
    let t = Totals {
        supply_cents: 1,
        collateral_zat: 2,
        active_vaults: 3,
        void_vaults: 4,
        closed_vaults: 5,
        claimed_vaults: 6,
        unbacked_cents: 7,
        open_debt_cents: 8,
    };
    assert_eq!(t.encode().len(), 48);
    assert_eq!(Totals::decode(&t.encode()), Some(t));
    let n = NoticeRecord {
        height: 1,
        ref_height: 2,
        p_emerg: 3,
    };
    assert_eq!(n.encode().len(), 16);
    assert_eq!(NoticeRecord::decode(&n.encode()), Some(n));
    let p = regtest_params_with(1, 2, 3, [9; 32], 4, BundleCarrier::Either, true);
    let pr = ParamsRecord::of(&p);
    assert_eq!(pr.encode().len(), 50);
    assert_eq!(pr.bundle_carrier, 2);
    assert_eq!(pr.mint_requires_armed, 1);
    assert_eq!(ParamsRecord::decode(&pr.encode()), Some(pr));
    let v = VaultRecord {
        owner_pub_key: [1; 33],
        status: VaultStatus::Claiming,
        p_mint: 50000,
        cancel_count: 2,
        last_cancel_height: 77,
        ..VaultRecord::default()
    };
    assert_eq!(VaultRecord::decode(&v.encode()), Some(v.clone()));
    assert_eq!(
        v.encode().len(),
        34 + 1 + 4 + 4 + 8 + 8 + 4 + 4 + 1 + 1 + 4 + 32 + 8 + 8 + 1 + 4 + 4 + 8 + 1 + 4
    );
    assert_eq!(VaultRecord::default().status, VaultStatus::Voided); // the C++ default record
    let tok = TokenRecord {
        cents: 5,
        n_value: 10_000,
        script_pub_key: vec![1, 2, 3],
        height: 9,
    };
    assert_eq!(TokenRecord::decode(&tok.encode()), Some(tok));
    let ir = IntentRecord {
        vault: some_op(1, 0),
        role: IntentRole::Residual,
        height: 5,
        refund_script: Vec::new(),
        claim_ref_height: 4,
        held_by: NULL_OUTPOINT,
    };
    // the null COutPoint is 32 zero bytes and n = 0xffffffff
    assert!(ir.encode().ends_with(&[0xff, 0xff, 0xff, 0xff]));
    assert_eq!(IntentRecord::decode(&ir.encode()), Some(ir));
    let s = Snapshot {
        seated: vec![1, 2],
        pinned_keys: vec![[4; 20]],
        pinned_seqs: vec![3],
        attest: AttestState::default(),
        ..Snapshot::default()
    };
    assert_eq!(Snapshot::decode(&s.encode()), Some(s.clone()));
    assert_eq!(Snapshot::default().sigma_mult_bps, 10_000);
    let log = TxLogRecord {
        tx_type: TxLogType::ClaimCancel,
        verdict: "ok".to_owned(),
        bundle_seqs: vec![0, 2],
        reopened_vaults: vec![some_op(5, 0)],
        ..TxLogRecord::default()
    };
    assert_eq!(TxLogRecord::decode(&log.encode()), Some(log));
    // trailing bytes and truncation fail
    let mut b = t.encode();
    b.push(0);
    assert!(Totals::decode(&b).is_none());
    assert!(Totals::decode(&t.encode()[..47]).is_none());
}

fn golden_state() -> YedState {
    let doc = load_pinned("yellowback_golden.json");
    let pj = &doc["params"];
    let int = |k: &str| i32::try_from(pj[k].as_i64().unwrap()).unwrap();
    let mut p = regtest_params_with(
        int("startHeight"),
        int("sigmaRefBps"),
        int("supplyCapBps"),
        uint256_display(pj["attestorSetId"].as_str().unwrap()).0,
        int("attestArmMin"),
        BundleCarrier::ScriptSig,
        false,
    );
    p.pq_falcon_height = int("pqFalconHeight");
    let mut s = YedState::new();
    for b in doc["blocks"].as_array().unwrap() {
        let txs: Vec<_> = b["txs"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| parse_v4(&h(t.as_str().unwrap())))
            .collect();
        let ev = evaluate_block(
            &s,
            &p,
            &txs,
            b["height"].as_i64().unwrap(),
            &uint256_display(b["hash"].as_str().unwrap()),
            b["subsidyZat"].as_i64().unwrap(),
            None,
        );
        if !ev.block_invalid {
            s.apply(&ev.delta);
        }
    }
    s
}

#[test]
fn golden_state_decodes_from_its_canonical_bytes() {
    let s = golden_state();
    let entries = canonical_entries_of(&s);
    assert_eq!(entries, s.canonical_entries());
    let mut tables = std::collections::BTreeSet::new();
    let mut rebuilt = YedState::new();
    for (k, v) in &entries {
        let key = YedKey::decode(k).unwrap();
        let rec = YedRecord::decode(key.table(), v).unwrap_or_else(|| panic!("{key:?} decodes"));
        assert_eq!(rec.table(), key.table());
        assert_eq!(&rec.encode(), v);
        tables.insert(key.table());
        rebuilt.entries.insert(key, rec);
    }
    assert_eq!(rebuilt, s);
    // the chain touches every table but none other than these
    for t in [
        Table::Tip,
        Table::Tag,
        Table::Judgement,
        Table::Vault,
        Table::Token,
        Table::Totals,
        Table::Snapshot,
        Table::Params,
        Table::Attestor,
        Table::AttestorSeq,
        Table::Attest,
        Table::BundleLog,
        Table::Intent,
        Table::AttestorSet,
        Table::TxLog,
        Table::BondIndex,
    ] {
        assert!(tables.contains(&t), "{t:?} present");
    }
    // the preimage starts with the tip and excludes TxLog and the bond index
    let pre = state_hash_preimage(&s, "regtest");
    assert_eq!(pre.first(), Some(&b'T'));
    let without: YedState = YedState {
        entries: s
            .entries
            .iter()
            .filter(|(k, _)| !matches!(k.table(), Table::TxLog | Table::BondIndex))
            .map(|(k, v)| (*k, v.clone()))
            .collect(),
    };
    assert_eq!(state_hash(&without, "regtest"), state_hash(&s, "regtest"));
    // the empty state's hash carries the zero tip with the network name
    let empty = YedState::new();
    assert_eq!(
        state_hash_preimage(&empty, "regtest"),
        [vec![b'T'], TipRecord::zero("regtest").encode()].concat()
    );
}

#[test]
fn delta_applies_reverts_and_inverts() {
    let mut f = Fixture::new();
    f.activate(50000);
    let base = f.state.clone();
    let m = f.mint_tx(10000, 48, f.tip - 1, MintOpts::default());
    let ev = f.evaluate(
        Some(Fixture::quote(50000, 0)),
        std::slice::from_ref(&m),
        None,
    );
    assert!(!ev.block_invalid);
    // every change's before is the base's value
    for (k, c) in &ev.delta.changes {
        assert_eq!(c.before, base.get(k));
    }
    let after = base.with(&ev.delta);
    assert_eq!(
        after.vault(&op(m.txid(), 0)).unwrap().status,
        VaultStatus::Active
    );
    let mut back = after.clone();
    back.revert(&ev.delta);
    assert_eq!(back, base);
    assert_eq!(after.with(&ev.delta.inverse()), base);
    assert_eq!(ev.delta.inverse().inverse(), ev.delta);
    let canon = ev.delta.canonical_entries();
    assert_eq!(canon.len(), ev.delta.len());
    let k = YedKey::Vault(op(m.txid(), 0)).encode();
    assert!(canon[&k].0.is_none() && canon[&k].1.is_some());
    assert!(YedDelta::default().is_empty());
    let _ = Change::<YedRecord> {
        before: None,
        after: None,
    };
}

#[test]
fn process_tx_returns_writes_and_leaves_the_base() {
    let mut f = Fixture::new();
    f.activate(50000);
    let base = f.state.clone();
    let m = f.mint_tx(10000, 48, f.tip - 1, MintOpts::default());
    // a standalone ProcessTx at the next height: the writes are returned, the base untouched
    let eff = process_tx(&f.state, &f.p, &m.tx(), f.tip + 1, None);
    assert!(eff.outcome.relevant && !eff.outcome.invalid);
    assert_eq!(f.state, base);
    let mut o = YedOverlay::new(&base);
    o.merge(eff.writes);
    assert_eq!(o.vault(&op(m.txid(), 0)).unwrap().minted_cents, 10000);
    assert_eq!(o.txlog(&m.txid()).unwrap().tx_type, TxLogType::Mint);
    assert!(eff.bundles.is_empty()); // unarmed: no bundle committed
                                     // an invalid mint's writes are returned too, and are discarded by the caller
    let bad = f.mint_tx(5000, 48, f.tip - 1, MintOpts::default());
    let eff = process_tx(&f.state, &f.p, &bad.tx(), f.tip + 1, None);
    assert!(eff.outcome.invalid);
    assert_eq!(eff.outcome.log.verdict, "bad-mint-amount");
}
