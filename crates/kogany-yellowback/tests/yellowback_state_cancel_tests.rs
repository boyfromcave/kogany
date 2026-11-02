// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

//! The cancel cases of ycash6 `src/test/yellowback_state_tests.cpp` at `65cb4ae0f` (W5-d1): the
//! attestor cancel of a claimant intent (U-23, U-24, I-2), CAN-1's refund, CAN-2's escalating
//! co-signatures and C4b's slashable statements, and CAN-3's held residual — with the C++
//! `CancelFixture`, `RoundsFixture` and `ResidualFixture` ported here.

mod state_common;

use kogany_vault::state::VaultTxIn;
use kogany_vault::{Hash32, OutPoint};
use kogany_yellowback::attest::bundle::{
    encode_bundle, encode_cancel_cosigns, encode_cancel_evidence, Bundle, CancelCosignEntry,
    CancelStatement,
};
use kogany_yellowback::attest::equivocation::{
    equivocated_by, equivocation_evidence, Equivocation,
};
use kogany_yellowback::attest::registry::AttestorStatus;
use kogany_yellowback::attest::Attestation;
use kogany_yellowback::codecs::payload::{Assignment, Payload};
use kogany_yellowback::codecs::script::yed_vault_script_at;
use kogany_yellowback::math::is_underwater;
use kogany_yellowback::params::{params_for_network, MicroUsd, PRICE_MAX, PRICE_MIN, TOKEN_VALUE};
use kogany_yellowback::state::{
    armed_at, cancels_required, verdict, IntentRecord, IntentRole, NoticeRecord, Totals, TxLogType,
    VaultRecord, VaultStatus, YedKey, YedRead, YedRecord, YedState,
};
use state_common::fixture::*;

const HONEST: MicroUsd = 50000;

/// `CScript() << valtype(65, 0) << OP_<sel>`: the cancel's placeholder set signature and selector.
fn set_sig(sel: u8) -> Vec<u8> {
    let mut s = vec![65u8];
    s.extend([0u8; 65]);
    s.push(0x50 + sel);
    s
}

/// The V script and value of the YED position at `pos`.
fn relock_of(f: &Fixture, pos: &OutPoint, value: i64) -> kogany_vault::state::VaultTxOut {
    let r = f.state.vault(pos).unwrap();
    txout(
        value,
        yed_vault_script_at(
            &f.p,
            &r.owner(),
            i64::from(r.owner_height),
            i64::from(r.app_height),
        )
        .unwrap(),
    )
}

/// The lowest price at which `collateral` backing `cents` is not claimable at the threshold.
fn first_not_claimable(collateral: i64, cents: i64, threshold_bps: i32) -> MicroUsd {
    let (mut lo, mut hi) = (1i64, PRICE_MAX);
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        if is_underwater(collateral, Some(mid), cents, threshold_bps) {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    lo
}

fn first_seqs(n: i64) -> Vec<usize> {
    (0..usize::try_from(n).unwrap()).collect()
}

struct CancelFixture {
    f: Fixture,
    v: Hash32,
    w: Hash32,
    claim_txid: Hash32,
    each: i64,
    before_claim: Totals,
    after_claim: Totals,
    claim_ref: i64,
}

impl CancelFixture {
    /// Two ACTIVE vaults; the pools fall to $0.009 and `w` is claimed on path (a), unarmed
    /// (ATTEST_ARM_MIN 10: the four members never arm the chain).
    fn new() -> CancelFixture {
        let mut f = Fixture::with(1, 0, 0, 10);
        f.activate(50000);
        f.register(4, 0); // CAN-2: members 0..3
        let v = f.mint_active10k();
        let w = f.mint_active10k();
        let each = f.vault(&w).unwrap().collateral_zat;
        for _ in 0..64 {
            let t = Fixture::quote(9000, (f.tip + 1) % 3);
            f.mine(Some(t), Vec::new());
        }
        let before_claim = f.totals();
        let claim_ref = f.tip;
        let claim = f.spend_tx(
            &w,
            &[op(w, 1)],
            f.tip,
            SpendOpts {
                owner_path: false,
                ..SpendOpts::default()
            },
        );
        assert_eq!(spend(&mut f, &w, &claim).verdict, verdict::OK);
        let after_claim = f.totals();
        assert_eq!(f.vault(&w).unwrap().status, VaultStatus::Claiming);
        CancelFixture {
            f,
            v,
            w,
            claim_txid: claim.txid(),
            each,
            before_claim,
            after_claim,
            claim_ref,
        }
    }
    fn intent(&self) -> OutPoint {
        op(self.claim_txid, 0)
    }
    fn vault_script(&self) -> Vec<u8> {
        let r = self.f.vault(&self.w).unwrap();
        yed_vault_script_at(
            &self.f.p,
            &r.owner(),
            i64::from(r.owner_height),
            i64::from(r.app_height),
        )
        .unwrap()
    }
    fn relock(&self) -> kogany_vault::state::VaultTxOut {
        txout(self.each, self.vault_script())
    }
    /// CAN-1: the holder the claim's burn came from (the mint's token script, P2PKH(owner)).
    fn holder(&self) -> Vec<u8> {
        p2pkh_of(&self.f.owner_pub())
    }
    fn refund(&self) -> kogany_vault::state::VaultTxOut {
        txout(TOKEN_VALUE, self.holder())
    }
    fn cosigns(&self, seqs: &[usize], price: MicroUsd) -> Vec<CancelCosignEntry> {
        self.cosigns_for(&self.intent(), self.claim_ref, seqs, price)
    }
    fn cosigns_for(
        &self,
        intent: &OutPoint,
        r: i64,
        seqs: &[usize],
        price: MicroUsd,
    ) -> Vec<CancelCosignEntry> {
        seqs.iter()
            .map(|s| self.f.cosign(*s, price, intent, r, None))
            .collect()
    }
    fn cancel_of(
        &mut self,
        intent: &OutPoint,
        outs: Vec<kogany_vault::state::VaultTxOut>,
        entries: &[CancelCosignEntry],
        script_sig: Vec<u8>,
    ) -> MTx {
        let mut m = MTx::default();
        m.vin.push(VaultTxIn {
            prevout: *intent,
            script_sig,
        });
        let fi = self.f.fake_input();
        m.vin.push(txin(fi)); // the canceller's fee input
        m.vout = outs;
        if !entries.is_empty() {
            let ci = self.f.carrier_in(&encode_cancel_cosigns(entries).unwrap());
            m.vin.push(ci);
            m.vout.push(payload_out(&Payload::CancelCosign));
        }
        m
    }
    /// The default cancel: re-lock and refund, co-signed by member 0 alone.
    fn cancel_tx(&mut self) -> MTx {
        let outs = vec![self.relock(), self.refund()];
        self.cancel_with(outs)
    }
    fn cancel_with(&mut self, outs: Vec<kogany_vault::state::VaultTxOut>) -> MTx {
        let e = self.cosigns(&[0], HONEST);
        let i = self.intent();
        self.cancel_of(&i, outs, &e, set_sig(2))
    }
    /// Mines `tx` at tip + 1 (pools at $0.009); the verdict that refused it, "" when applied.
    fn mine(&mut self, tx: &MTx) -> String {
        let t = Fixture::quote(9000, (self.f.tip + 1) % 3);
        self.f.mine(Some(t), vec![tx.clone()]);
        self.f.refused_verdict(&tx.txid())
    }
}

/// CancelFixture's position through claim-and-cancel rounds.
struct RoundsFixture {
    c: CancelFixture,
    pos: OutPoint,
    intent: OutPoint,
    r: i64,
}

impl RoundsFixture {
    fn new() -> RoundsFixture {
        let c = CancelFixture::new();
        let pos = op(c.w, 0);
        let intent = c.intent();
        let r = c.claim_ref;
        RoundsFixture { c, pos, intent, r }
    }
    /// Claims `pos` again with the refund token at pos:1.
    fn reclaim(&mut self) {
        self.r = self.c.f.tip;
        let p = self.pos.txid;
        let claim = self.c.f.spend_tx(
            &p,
            &[op(p, 1)],
            self.r,
            SpendOpts {
                owner_path: false,
                ..SpendOpts::default()
            },
        );
        assert_eq!(self.c.mine(&claim), "");
        self.intent = op(claim.txid(), 0);
        assert_eq!(self.c.f.vault(&p).unwrap().status, VaultStatus::Claiming);
    }
    fn cancel(&mut self, seqs: &[usize], price: MicroUsd) -> MTx {
        let outs = vec![
            relock_of(&self.c.f, &self.pos, self.c.each),
            self.c.refund(),
        ];
        let e = self.c.cosigns_for(&self.intent, self.r, seqs, price);
        let i = self.intent;
        self.c.cancel_of(&i, outs, &e, set_sig(2))
    }
    fn mine_cancel(&mut self, seqs: &[usize]) -> String {
        let tx = self.cancel(seqs, HONEST);
        self.mine_entries_tx(&tx)
    }
    fn mine_entries_tx(&mut self, tx: &MTx) -> String {
        let v = self.c.mine(tx);
        if v.is_empty() {
            self.pos = op(tx.txid(), 0);
        }
        v
    }
}

// Rule: U-23
// Rule: U-24
// Rule: I-2
// Rule: IT-6
#[test]
fn intent_cancel_recreates_the_vault_at_vout0() {
    let mut c = CancelFixture::new();
    let claiming = c.f.vault(&c.w).unwrap();
    assert_eq!(claiming.burned_cents, 10000);
    assert_eq!(
        c.after_claim.supply_cents,
        c.before_claim.supply_cents - 10000
    ); // RED-2
    assert_eq!(
        c.after_claim.active_vaults,
        c.before_claim.active_vaults - 1
    );
    assert_eq!(c.after_claim.collateral_zat, c.before_claim.collateral_zat); // IT-6
    let cancel = c.cancel_tx();
    assert_eq!(c.mine(&cancel), "");
    let txid = cancel.txid();
    assert!(c.f.vault(&c.w).is_none()); // the CLAIMING record moved
    let back = c.f.vault(&txid).unwrap();
    assert_eq!(back.status, VaultStatus::Active);
    assert_eq!(back.minted_cents, 10000);
    assert_eq!(back.burned_cents, 0);
    assert_eq!(back.collateral_zat, c.each);
    assert_eq!(back.close_height, 0);
    assert_eq!(back.closing_txid, Hash32::ZERO);
    assert_eq!(back.p_mint, claiming.p_mint); // FEE-1': the same position
    assert_eq!(back.mint_height, claiming.mint_height);
    assert!(c.f.state.intent(&c.intent()).is_none());
    let log = c.f.log(&txid).unwrap();
    assert_eq!(log.tx_type, TxLogType::ClaimCancel);
    assert_eq!(log.verdict, verdict::OK);
    assert_eq!(log.closed_vaults, vec![op(c.w, 0)]);
    assert_eq!(log.reopened_vaults, vec![op(txid, 0)]);
    let t = c.f.totals();
    assert_eq!(t.active_vaults, c.before_claim.active_vaults);
    assert_eq!(t.claimed_vaults, c.before_claim.claimed_vaults);
    assert_eq!(
        t.collateral_zat,
        c.after_claim.collateral_zat + c.each - claiming.collateral_zat
    );
    // CAN-1: the claim's burn is re-issued to the holder it came from at cancel:1
    let tok = c.f.token(&txid, 1).unwrap();
    assert_eq!(tok.cents, claiming.burned_cents);
    assert_eq!(tok.script_pub_key, c.holder());
    assert_eq!(tok.n_value, TOKEN_VALUE);
    assert_eq!(t.supply_cents, c.before_claim.supply_cents);
    assert_eq!(t.supply_cents, c.after_claim.supply_cents + 10000);
    assert_eq!(log.assigned.len(), 1);
    assert_eq!(log.assigned[0].outpoint, op(txid, 1));
    assert_eq!(log.assigned[0].cents, 10000);
    assert_eq!(log.yed_out, 10000);
    assert_eq!(log.burned, 0);
}

// Rule: CAN-1
#[test]
fn intent_claim_records_the_refund_holder() {
    let c = CancelFixture::new();
    let ir = c.f.state.intent(&c.intent()).unwrap();
    assert_eq!(ir.role, IntentRole::Claimant);
    assert_eq!(ir.refund_script, c.holder());
}

// Rule: CAN-1
#[test]
fn intent_cancel_without_refund_invalid() {
    let mut c = CancelFixture::new();
    let other = txout(TOKEN_VALUE, c.f.user_p2pkh());
    let outs = vec![c.relock()];
    let tx = c.cancel_with(outs);
    assert_eq!(c.mine(&tx), verdict::INTENT_CANCEL_NO_REFUND); // none
    let outs = vec![c.relock(), other];
    let tx = c.cancel_with(outs);
    assert_eq!(c.mine(&tx), verdict::INTENT_CANCEL_NO_REFUND); // another script
    let outs = vec![c.relock(), txout(0, c.holder())];
    let tx = c.cancel_with(outs);
    assert_eq!(c.mine(&tx), verdict::INTENT_CANCEL_NO_REFUND); // zero carrier
                                                               // the refund at vout 0 displaces the re-lock: the re-lock rule speaks first
    let outs = vec![c.refund(), c.relock()];
    let tx = c.cancel_with(outs);
    assert_eq!(c.mine(&tx), verdict::INTENT_CANCEL_NO_VAULT);
    assert_eq!(c.f.vault(&c.w).unwrap().status, VaultStatus::Claiming);
    assert_eq!(c.f.totals().supply_cents, c.after_claim.supply_cents);
}

// Rule: CAN-1
#[test]
fn intent_cancel_refund_at_lowest_holder_output() {
    let mut c = CancelFixture::new();
    let other = txout(777, c.f.user_p2pkh());
    let outs = vec![
        c.relock(),
        other,
        txout(5000, c.holder()),
        txout(6000, c.holder()),
    ];
    let cancel = c.cancel_with(outs);
    assert_eq!(c.mine(&cancel), "");
    let txid = cancel.txid();
    assert_eq!(c.f.token(&txid, 2).unwrap().cents, 10000);
    assert_eq!(c.f.token(&txid, 2).unwrap().n_value, 5000);
    assert!(c.f.token(&txid, 3).is_none());
}

// Rule: CAN-1
// Rule: IN-3
#[test]
fn intent_cancel_yed_inputs_still_burn() {
    let mut c = CancelFixture::new();
    let mut cancel = c.cancel_tx();
    cancel.vin.push(txin(op(c.v, 1))); // the other vault's 10,000 cents, spent by the canceller
    assert_eq!(c.mine(&cancel), "");
    let log = c.f.log(&cancel.txid()).unwrap();
    assert_eq!(log.yed_in, 10000);
    assert_eq!(log.yed_out, 10000);
    assert_eq!(log.burned, 10000);
    assert_eq!(
        c.f.totals().supply_cents,
        c.after_claim.supply_cents + 10000 - 10000
    );
}

// Rule: CAN-1
// Rule: XFER-1
// Rule: RED-2
#[test]
fn intent_cancel_refund_spendable_and_reclaims() {
    let mut c = CancelFixture::new();
    let cancel = c.cancel_tx();
    assert_eq!(c.mine(&cancel), "");
    let txid = cancel.txid();
    // the refunded YED claims the re-created vault again (still under theta at $0.009)
    let again = c.f.spend_tx(
        &txid,
        &[op(txid, 1)],
        c.f.tip,
        SpendOpts {
            owner_path: false,
            ..SpendOpts::default()
        },
    );
    assert_eq!(c.mine(&again), "");
    assert_eq!(c.f.vault(&txid).unwrap().status, VaultStatus::Claiming);
    assert!(c.f.token(&txid, 1).is_none());
    assert_eq!(c.f.totals().supply_cents, c.after_claim.supply_cents);
}

// Rule: CAN-1
// Rule: XFER-1
#[test]
fn intent_cancel_refund_transferable() {
    let mut c = CancelFixture::new();
    let cancel = c.cancel_tx();
    assert_eq!(c.mine(&cancel), "");
    let txid = cancel.txid();
    let t =
        c.f.transfer_tx(&[op(txid, 1)], &[Assignment::new(0, 10000)], false, 0);
    assert_eq!(c.mine(&t), "");
    assert!(c.f.token(&txid, 1).is_none());
    assert_eq!(c.f.token(&t.txid(), 0).unwrap().cents, 10000);
}

// Rule: CAN-1
// Rule: TOK-PQ
#[test]
fn intent_cancel_refund_crosses_the_falcon_boundary() {
    let mut c = CancelFixture::new();
    c.f.p.pq_falcon_height = i32::try_from(c.f.tip + 1).unwrap();
    let cancel = c.cancel_tx();
    assert_eq!(c.mine(&cancel), "");
    let txid = cancel.txid();
    assert_eq!(c.f.token(&txid, 1).unwrap().cents, 10000);
    let t =
        c.f.transfer_tx(&[op(txid, 1)], &[Assignment::new(0, 10000)], false, 0);
    assert_eq!(c.mine(&t), verdict::BAD_YED_HOLDER);
    assert!(c.f.token(&txid, 1).is_some());
}

// Rule: U-23
// Rule: U-24
#[test]
fn intent_cancel_of_residual_invalid() {
    let mut g = EmergencyFixture::new(64);
    assert!(g.post_notice(None));
    for _ in 0..=g.f.p.emergency_persist {
        g.tick();
    }
    let residual = g.residual(g.f.tip - 1);
    let claim = g.claim(
        SpendOpts {
            residual_value: Some(residual),
            ..SpendOpts::default()
        },
        None,
    );
    assert_eq!(g.mine(&claim).verdict, verdict::OK);
    let res_vout = u32::try_from(claim.vout.len() - 1).unwrap();
    let ir = g.f.state.intent(&op(claim.txid(), res_vout)).unwrap();
    assert_eq!(ir.role, IntentRole::Residual);
    let rec = g.f.vault(&g.w).unwrap();
    let vs = yed_vault_script_at(
        &g.f.p,
        &rec.owner(),
        i64::from(rec.owner_height),
        i64::from(rec.app_height),
    )
    .unwrap();
    let fi = g.f.fake_input();
    let cancel = MTx {
        vin: vec![
            VaultTxIn {
                prevout: op(claim.txid(), res_vout),
                script_sig: set_sig(2),
            },
            txin(fi),
        ],
        vout: vec![txout(
            claim.vout[usize::try_from(res_vout).unwrap()].value,
            vs,
        )],
        lock_time: 0,
    };
    let t = g.quote();
    g.f.mine(t, vec![cancel.clone()]);
    assert_eq!(
        g.f.refused_verdict(&cancel.txid()),
        verdict::INTENT_CANCEL_RESIDUAL
    );
    assert!(g.f.state.intent(&op(claim.txid(), res_vout)).is_some());
    assert_eq!(g.f.vault(&g.w).unwrap().status, VaultStatus::Claiming);
}

// Rule: U-23
// Rule: I-2
#[test]
fn intent_cancel_relock_not_vout0_invalid() {
    let mut c = CancelFixture::new();
    let change = txout(1000, c.f.user_p2pkh());
    let outs = vec![change, c.relock()];
    let tx = c.cancel_with(outs);
    assert_eq!(c.mine(&tx), verdict::INTENT_CANCEL_NO_VAULT);
    assert_eq!(c.f.vault(&c.w).unwrap().status, VaultStatus::Claiming);
    assert!(c.f.state.intent(&c.intent()).is_some());
}

// Rule: U-23
// Rule: I-2
#[test]
fn intent_cancel_two_relocks_invalid() {
    let mut c = CancelFixture::new();
    let outs = vec![c.relock(), txout(1000, c.vault_script())];
    let tx = c.cancel_with(outs);
    assert_eq!(c.mine(&tx), verdict::INTENT_CANCEL_NO_VAULT);
    assert_eq!(c.f.vault(&c.w).unwrap().status, VaultStatus::Claiming);
}

// Rule: U-23
// Rule: I-2
#[test]
fn intent_cancel_relock_script_differs_invalid() {
    let mut c = CancelFixture::new();
    let outs = vec![txout(c.each, c.f.user_p2pkh())];
    let tx = c.cancel_with(outs);
    assert_eq!(c.mine(&tx), verdict::INTENT_CANCEL_NO_VAULT);
    // a V of another owner at vout[0] is not the claimed vault either
    let r = c.f.vault(&c.w).unwrap();
    let other = test_pq_owner(&pubkey(&det_secret("yellowback-state-test-other", 0)));
    let other_v = yed_vault_script_at(
        &c.f.p,
        &other,
        i64::from(r.owner_height),
        i64::from(r.app_height),
    )
    .unwrap();
    assert_ne!(other_v, c.vault_script());
    let tx = c.cancel_with(vec![txout(c.each, other_v)]);
    assert_eq!(c.mine(&tx), verdict::INTENT_CANCEL_NO_VAULT);
    assert_eq!(c.f.vault(&c.w).unwrap().status, VaultStatus::Claiming);
}

// Rule: U-23
#[test]
fn intent_cancel_payload_or_selector3_malformed() {
    let mut c = CancelFixture::new();
    // a cancel carries no Yellowback payload but CANCEL_COSIGN (CAN-2)
    let outs = vec![
        c.relock(),
        c.refund(),
        payload_out(&Payload::Transfer(Vec::new())),
    ];
    let i = c.intent();
    let tx = c.cancel_of(&i, outs, &[], set_sig(2));
    assert_eq!(c.mine(&tx), verdict::INTENT_SPEND_MALFORMED);
    // selector 3 (the owner's released path) is not an intent path
    let outs = vec![c.relock(), c.refund()];
    let e = c.cosigns(&[0], HONEST);
    let tx = c.cancel_of(&i, outs, &e, set_sig(3));
    assert_eq!(c.mine(&tx), verdict::INTENT_SPEND_MALFORMED);
    assert_eq!(c.f.vault(&c.w).unwrap().status, VaultStatus::Claiming);
}

// Rule: U-23
// Rule: NOT-1
#[test]
fn intent_cancel_erases_the_notice() {
    let mut c = CancelFixture::new();
    let n = NoticeRecord {
        height: i32::try_from(c.f.tip).unwrap(),
        ref_height: i32::try_from(c.f.tip - 2).unwrap(),
        p_emerg: 9000,
    };
    let w = c.w;
    c.f.put(YedKey::Notice(op(w, 0)), YedRecord::Notice(n));
    assert!(c.f.notice(&w).is_some());
    let cancel = c.cancel_tx();
    assert_eq!(c.mine(&cancel), "");
    assert!(c.f.notice(&w).is_none());
    assert!(c.f.notice(&cancel.txid()).is_none());
}

// Rule: U-23
// Rule: UNDO
#[test]
fn intent_cancel_undo_roundtrip() {
    let mut c = CancelFixture::new();
    let claiming = hash_hex(&c.f.state);
    let before: YedState = c.f.state.clone();
    let cancel = c.cancel_tx();
    assert_eq!(c.mine(&cancel), "");
    assert_ne!(hash_hex(&c.f.state), claiming);
    assert!(c.f.token(&cancel.txid(), 1).is_some());
    c.f.undo();
    assert_eq!(hash_hex(&c.f.state), claiming);
    assert_eq!(c.f.state, before);
    assert!(c.f.token(&cancel.txid(), 1).is_none());
    assert_eq!(c.f.totals().supply_cents, c.after_claim.supply_cents);
    assert_eq!(c.f.vault(&c.w).unwrap().status, VaultStatus::Claiming);
    assert!(c.f.state.intent(&c.intent()).is_some());
}

// Rule: CAN-2
#[test]
fn cancel_limit_constants_per_network() {
    for net in ["main", "test"] {
        assert_eq!(params_for_network(net).unwrap().cancel_signers_max, 4);
        assert_eq!(params_for_network(net).unwrap().cancel_quiet, 8064);
    }
    assert_eq!(params_for_network("regtest").unwrap().cancel_signers_max, 3);
    assert_eq!(params_for_network("regtest").unwrap().cancel_quiet, 40);
    let v = VaultRecord {
        cancel_count: 9,
        last_cancel_height: 100,
        ..VaultRecord::default()
    };
    let main = params_for_network("main").unwrap();
    assert_eq!(cancels_required(&v, &main, 101), 4); // the schedule caps at four
    assert_eq!(cancels_required(&v, &main, 100 + 8064), 1);
}

// Rule: CAN-2
#[test]
fn cancel_limit_escalation_schedule_and_cap() {
    let mut c = RoundsFixture::new();
    assert_eq!(c.c.f.p.cancel_signers_max, 3); // regtest: schedule 1, 2, 3, 3, ...
    assert_eq!(c.c.f.p.cancel_quiet, 40);
    let w = c.c.w;
    let minted = c.c.f.vault(&w).unwrap();
    assert_eq!(minted.cancel_count, 0);
    assert_eq!(minted.last_cancel_height, 0);
    for round in 1..=5i64 {
        if round > 1 {
            c.reclaim();
        }
        let need = round.min(i64::from(c.c.f.p.cancel_signers_max));
        let pv = c.c.f.vault(&c.pos.txid).unwrap();
        assert_eq!(cancels_required(&pv, &c.c.f.p, c.c.f.tip + 1), need);
        if need > 1 {
            // one co-signer short: refused, the vault stays CLAIMING (U-21)
            assert_eq!(
                c.mine_cancel(&first_seqs(need - 1)),
                verdict::INTENT_CANCEL_COSIGN
            );
            assert_eq!(
                c.c.f.vault(&c.pos.txid).unwrap().status,
                VaultStatus::Claiming
            );
        }
        assert_eq!(c.mine_cancel(&first_seqs(need)), "");
        let r = c.c.f.vault(&c.pos.txid).unwrap();
        assert_eq!(r.status, VaultStatus::Active);
        assert_eq!(i64::from(r.cancel_count), round); // q + 1
        assert_eq!(i64::from(r.last_cancel_height), c.c.f.tip);
        assert_eq!(r.mint_height, minted.mint_height); // the same position across re-creations
        assert_eq!(r.p_mint, minted.p_mint);
        let seqs: Vec<u16> = first_seqs(need)
            .into_iter()
            .map(|s| u16::try_from(s).unwrap())
            .collect();
        assert_eq!(c.c.f.log(&c.pos.txid).unwrap().bundle_seqs, seqs);
    }
}

// Rule: CAN-2
#[test]
fn cancel_limit_quiet_resets_the_schedule() {
    let mut c = RoundsFixture::new();
    assert_eq!(c.mine_cancel(&[0]), "");
    let first = c.c.f.tip;
    let quiet = i64::from(c.c.f.p.cancel_quiet);
    while c.c.f.tip + 2 < first + quiet - 1 {
        let t = Fixture::quote(9000, (c.c.f.tip + 1) % 3);
        c.c.f.mine(Some(t), Vec::new());
    }
    c.reclaim();
    assert_eq!(c.c.f.tip + 1, first + quiet - 1);
    let pv = c.c.f.vault(&c.pos.txid).unwrap();
    assert_eq!(cancels_required(&pv, &c.c.f.p, c.c.f.tip + 1), 2);
    assert_eq!(c.mine_cancel(&[0]), verdict::INTENT_CANCEL_COSIGN);
    // one block later the quiet period has passed: q = 0, one co-signer again
    assert_eq!(c.c.f.tip + 1, first + quiet);
    let pv = c.c.f.vault(&c.pos.txid).unwrap();
    assert_eq!(cancels_required(&pv, &c.c.f.p, c.c.f.tip + 1), 1);
    assert_eq!(c.mine_cancel(&[1]), "");
    assert_eq!(c.c.f.vault(&c.pos.txid).unwrap().cancel_count, 1);
    assert_eq!(
        i64::from(c.c.f.vault(&c.pos.txid).unwrap().last_cancel_height),
        c.c.f.tip
    );
}

// Rule: CAN-2
// Rule: C4b
#[test]
#[allow(clippy::too_many_lines)]
fn cancel_cosign_refusals() {
    let mut c = CancelFixture::new();
    let outs = || {
        let c: &CancelFixture = &c;
        vec![c.relock(), c.refund()]
    };
    let base_outs = outs();
    let refused = |c: &mut CancelFixture, tx: &MTx| c.mine(tx) == verdict::INTENT_CANCEL_COSIGN;
    let i = c.intent();
    // no co-signature at all (CAN-1's shape): even the first cancel carries one statement
    let tx = c.cancel_of(&i, base_outs.clone(), &[], set_sig(2));
    assert!(refused(&mut c, &tx));
    // the marker without its carrier, and a carrier without the marker
    let mut no_carrier = c.cancel_tx();
    no_carrier.vin.pop();
    assert!(refused(&mut c, &no_carrier));
    let mut no_marker = c.cancel_tx();
    no_marker.vout.pop();
    assert!(refused(&mut c, &no_marker));
    // a price bundle ("YA") in the carrier is not a co-signature list
    let mut ya = c.cancel_tx();
    let b = encode_bundle(&Bundle::of(vec![c.f.att(0, HONEST, c.claim_ref, None)]));
    let ci = c.f.carrier_in(&b);
    *ya.vin.last_mut().unwrap() = ci;
    assert!(refused(&mut c, &ya));
    // a non-member, another intent, another height, another block hash
    let e = c.cosigns(&[10], HONEST);
    let tx = c.cancel_of(&i, base_outs.clone(), &e, set_sig(2));
    assert!(refused(&mut c, &tx));
    let e = c.cosigns_for(&op(c.claim_txid, 1), c.claim_ref, &[0], HONEST);
    let tx = c.cancel_of(&i, base_outs.clone(), &e, set_sig(2));
    assert!(refused(&mut c, &tx));
    let e = c.cosigns_for(&i, c.claim_ref - 1, &[0], HONEST);
    let tx = c.cancel_of(&i, base_outs.clone(), &e, set_sig(2));
    assert!(refused(&mut c, &tx));
    let e = vec![c.f.cosign(0, HONEST, &i, c.claim_ref, Some(u256s("01")))];
    let tx = c.cancel_of(&i, base_outs.clone(), &e, set_sig(2));
    assert!(refused(&mut c, &tx));
    // C4b: a statement at which the vault WAS claimable
    let edge = first_not_claimable(c.each, 10000, c.f.p.claim_threshold_bps);
    for price in [9000, edge - 1, PRICE_MIN - 1] {
        let e = c.cosigns(&[0], price);
        let tx = c.cancel_of(&i, base_outs.clone(), &e, set_sig(2));
        assert!(refused(&mut c, &tx), "price {price}");
    }
    // a malformed list fails whatever it holds
    let mut junk = c.cancel_tx();
    let mut bad = encode_cancel_cosigns(&c.cosigns(&[0], HONEST)).unwrap();
    bad.push(0);
    let ci = c.f.carrier_in(&bad);
    *junk.vin.last_mut().unwrap() = ci;
    assert!(refused(&mut c, &junk));
    // a member whose bond was spent (WITHDRAWN) and one that joined too recently cannot co-sign
    let one = c.f.attestor(1).unwrap();
    let exit = MTx {
        vin: vec![txin(one.bond_outpoint)],
        vout: vec![txout(one.bond_zat - 1000, c.f.user_p2pkh())],
        lock_time: 0,
    };
    let t = Fixture::quote(9000, (c.f.tip + 1) % 3);
    c.f.mine(Some(t), vec![exit]);
    assert_eq!(c.f.attestor(1).unwrap().status, AttestorStatus::Withdrawn);
    let e = c.cosigns(&[1], HONEST);
    let tx = c.cancel_of(&i, base_outs.clone(), &e, set_sig(2));
    assert!(refused(&mut c, &tx));
    let reg =
        c.f.register_tx(5, 10 * kogany_yellowback::params::COIN, -1, None);
    let t = Fixture::quote(9000, (c.f.tip + 1) % 3);
    c.f.mine(Some(t), vec![reg]);
    assert!(c.f.attestor(4).is_some()); // hot[5] became seq 4
    let e = c.cosigns(&[5], HONEST);
    let tx = c.cancel_of(&i, base_outs.clone(), &e, set_sig(2));
    assert!(refused(&mut c, &tx));
    assert_eq!(c.f.vault(&c.w).unwrap().status, VaultStatus::Claiming);
    assert!(c.f.state.intent(&i).is_some());
    // extra valid co-signatures are accepted, and the statement at the boundary price holds
    let e = c.cosigns(&[0, 2, 3], edge);
    let ok = c.cancel_of(&i, base_outs, &e, set_sig(2));
    assert_eq!(c.mine(&ok), "");
    assert_eq!(c.f.log(&ok.txid()).unwrap().bundle_seqs, vec![0, 2, 3]);
    assert_eq!(c.f.vault(&ok.txid()).unwrap().cancel_count, 1);
}

// Rule: CAN-2
#[test]
fn cancel_cosign_counts_distinct_valid_entries() {
    let mut c = RoundsFixture::new();
    assert_eq!(c.mine_cancel(&[0]), "");
    c.reclaim(); // the second cancel needs two
    let mine = |c: &mut RoundsFixture, e: &[CancelCosignEntry]| {
        let outs = vec![relock_of(&c.c.f, &c.pos, c.c.each), c.c.refund()];
        let i = c.intent;
        let tx = c.c.cancel_of(&i, outs, e, set_sig(2));
        c.mine_entries_tx(&tx)
    };
    let e = c.c.cosigns_for(&c.intent, c.r, &[0, 0], HONEST);
    assert_eq!(mine(&mut c, &e), verdict::INTENT_CANCEL_COSIGN); // one key twice
    let e = c.c.cosigns_for(&c.intent, c.r, &[0, 10], HONEST);
    assert_eq!(mine(&mut c, &e), verdict::INTENT_CANCEL_COSIGN); // a non-member
    let mut e = c.c.cosigns_for(&c.intent, c.r, &[0], HONEST);
    e.push(c.c.f.cosign(10, HONEST, &c.intent, c.r, None)); // ignored
    e.push(c.c.f.cosign(2, 9000, &c.intent, c.r, None)); // claimable: ignored
    e.push(c.c.f.cosign(0, HONEST, &c.intent, c.r, None)); // a repeat: ignored
    e.push(c.c.f.cosign(1, HONEST, &c.intent, c.r, None));
    let before = c.pos;
    assert_eq!(mine(&mut c, &e), "");
    assert_ne!(c.pos, before);
    assert_eq!(c.c.f.log(&c.pos.txid).unwrap().bundle_seqs, vec![0, 1]);
    assert_eq!(c.c.f.vault(&c.pos.txid).unwrap().cancel_count, 2);
}

// Rule: CAN-2
#[test]
fn cancel_cosign_holds_when_a_cosigner_leaves_in_the_same_block() {
    for spare in [false, true] {
        let mut c = RoundsFixture::new();
        assert_eq!(c.mine_cancel(&[0]), "");
        c.reclaim(); // two needed
        let one = c.c.f.attestor(1).unwrap();
        let exit = MTx {
            vin: vec![txin(one.bond_outpoint)],
            vout: vec![txout(one.bond_zat - 1000, c.c.f.user_p2pkh())],
            lock_time: 0,
        };
        let seqs: &[usize] = if spare { &[0, 1, 2] } else { &[0, 1] };
        let cancel = c.cancel(seqs, HONEST);
        let t = Fixture::quote(9000, (c.c.f.tip + 1) % 3);
        c.c.f.mine(Some(t), vec![exit, cancel.clone()]);
        assert_eq!(c.c.f.attestor(1).unwrap().status, AttestorStatus::Withdrawn);
        let want = if spare {
            ""
        } else {
            verdict::INTENT_CANCEL_COSIGN
        };
        assert_eq!(c.c.f.refused_verdict(&cancel.txid()), want);
        if spare {
            assert_eq!(c.c.f.log(&cancel.txid()).unwrap().bundle_seqs, vec![0, 2]);
        }
    }
}

// Rule: CAN-2
// Rule: UNDO
#[test]
fn cancel_limit_counter_undo_byte_identical() {
    let mut c = RoundsFixture::new();
    assert_eq!(c.mine_cancel(&[0]), "");
    c.reclaim();
    let before = c.c.f.state.clone();
    assert_eq!(c.mine_cancel(&[0, 1]), "");
    assert_eq!(c.c.f.vault(&c.pos.txid).unwrap().cancel_count, 2);
    c.c.f.undo();
    assert_eq!(c.c.f.state, before);
}

/// A path-(b) claim of EmergencyFixture's vault with the owner's residual intent.
struct ResidualFixture {
    g: EmergencyFixture,
    claimant: OutPoint,
    residual: OutPoint,
    pos: OutPoint,
    claim: MTx,
}

impl ResidualFixture {
    fn new() -> ResidualFixture {
        let mut g = EmergencyFixture::new(64);
        assert!(g.post_notice(None));
        for _ in 0..=g.f.p.emergency_persist {
            g.tick();
        }
        let res = g.residual(g.f.tip - 1);
        let claim = g.claim(
            SpendOpts {
                residual_value: Some(res),
                ..SpendOpts::default()
            },
            None,
        );
        assert_eq!(g.mine(&claim).verdict, verdict::OK);
        let id = claim.txid();
        let (mut claimant, mut residual) = (None, None);
        let mut claimant_rec: Option<IntentRecord> = None;
        for j in 0..claim.vout.len() {
            let o = op(id, u32::try_from(j).unwrap());
            if let Some(ir) = g.f.state.intent(&o) {
                if ir.role == IntentRole::Claimant {
                    claimant = Some(o);
                    claimant_rec = Some(ir);
                } else {
                    residual = Some(o);
                }
            }
        }
        let (claimant, residual) = (claimant.unwrap(), residual.unwrap());
        assert_eq!(
            i64::from(claimant_rec.unwrap().claim_ref_height),
            g.f.tip - 2
        );
        assert!(kogany_yellowback::state::is_null_outpoint(
            &g.f.state.intent(&residual).unwrap().held_by
        ));
        ResidualFixture {
            g,
            claimant,
            residual,
            pos: op(Hash32::ZERO, 0),
            claim,
        }
    }
    fn cancel_tx(
        &mut self,
        intent: &OutPoint,
        from: &OutPoint,
        value: i64,
        seqs: &[usize],
        price: MicroUsd,
    ) -> MTx {
        let ir = self.g.f.state.intent(intent).unwrap();
        let entries: Vec<_> = seqs
            .iter()
            .map(|s| {
                self.g
                    .f
                    .cosign(*s, price, intent, i64::from(ir.claim_ref_height), None)
            })
            .collect();
        let fi = self.g.f.fake_input();
        let ci = self
            .g
            .f
            .carrier_in(&encode_cancel_cosigns(&entries).unwrap());
        MTx {
            vin: vec![
                VaultTxIn {
                    prevout: *intent,
                    script_sig: set_sig(2),
                },
                txin(fi),
                ci,
            ],
            vout: vec![
                relock_of(&self.g.f, from, value),
                txout(TOKEN_VALUE, ir.refund_script.clone()),
                payload_out(&Payload::CancelCosign),
            ],
            lock_time: 0,
        }
    }
    /// Cancels the path-(b) claim (one co-signer at the honest pool price).
    fn cancel_first(&mut self) {
        let claimant = self.claimant;
        let from = op(self.g.w, 0);
        let value = self.claim.vout[usize::try_from(claimant.n).unwrap()].value;
        let price = self.g.pool_price;
        let c = self.cancel_tx(&claimant, &from, value, &[0], price);
        let t = self.g.quote();
        self.g.f.mine(t, vec![c.clone()]);
        assert_eq!(self.g.f.refused_verdict(&c.txid()), "");
        self.pos = op(c.txid(), 0);
    }
    /// Mines the residual's release; the verdict that refused it, "" when applied.
    fn release(&mut self) -> String {
        let fi = self.g.f.fake_input();
        let value = self.claim.vout[usize::try_from(self.residual.n).unwrap()].value;
        let rel = MTx {
            vin: vec![
                VaultTxIn {
                    prevout: self.residual,
                    script_sig: vec![0x51],
                },
                txin(fi),
            ],
            vout: vec![txout(value, p2pkh_of(&self.g.f.owner_pub()))],
            lock_time: 0,
        };
        let t = self.g.quote();
        self.g.f.mine(t, vec![rel.clone()]);
        self.g.f.refused_verdict(&rel.txid())
    }
}

// Rule: CAN-3
#[test]
fn cancel_limit_residual_held_until_quiet() {
    let mut r = ResidualFixture::new();
    r.cancel_first();
    assert_eq!(r.g.f.state.intent(&r.residual).unwrap().held_by, r.pos);
    let cancelled = r.g.f.tip;
    assert_eq!(r.release(), verdict::INTENT_RESIDUAL_HELD);
    let quiet = i64::from(r.g.f.p.cancel_quiet);
    while r.g.f.tip + 2 < cancelled + quiet {
        r.g.tick();
    }
    assert_eq!(r.g.f.tip + 1, cancelled + quiet - 1);
    assert_eq!(r.release(), verdict::INTENT_RESIDUAL_HELD); // one block inside CANCEL_QUIET
                                                            // past CANCEL_QUIET, but the re-created position is claimable on path (a): still held
    let pos = r.g.f.vault(&r.pos.txid).unwrap();
    assert!(is_underwater(
        pos.collateral_zat,
        r.g.f.snap(r.g.f.tip).pclaim(),
        pos.minted_cents,
        r.g.f.p.claim_threshold_bps
    ));
    assert_eq!(r.release(), verdict::INTENT_RESIDUAL_HELD);
    // the price recovers for a whole slow window: released
    r.g.pool_price = 50000;
    for _ in 0..128 {
        r.g.tick();
    }
    assert!(!is_underwater(
        pos.collateral_zat,
        r.g.f.snap(r.g.f.tip).pclaim(),
        pos.minted_cents,
        r.g.f.p.claim_threshold_bps
    ));
    assert_eq!(r.release(), "");
    assert!(r.g.f.state.intent(&r.residual).is_none());
}

// Rule: CAN-3
#[test]
fn cancel_limit_residual_release_mirrors_every_citable_ref() {
    let mut r = ResidualFixture::new();
    r.cancel_first();
    r.g.pool_price = 50000;
    for _ in 0..128 {
        r.g.tick();
    }
    let ref_window = i64::from(r.g.f.p.ref_window);
    assert_eq!(ref_window, 40);
    let attempt = |r: &mut ResidualFixture, back: i64, p_claim: i64| {
        let h = r.g.f.tip + 1 - back;
        let orig = r.g.f.snap(h);
        let mut s = orig.clone();
        s.p_claim = p_claim;
        let k = u32::try_from(h).unwrap();
        r.g.f
            .put(YedKey::Snapshot(k), YedRecord::Snapshot(Box::new(s)));
        let v = r.release();
        r.g.f
            .put(YedKey::Snapshot(k), YedRecord::Snapshot(Box::new(orig)));
        v
    };
    assert_eq!(attempt(&mut r, 1, 0), verdict::INTENT_RESIDUAL_HELD); // undefined price at H - 1
    assert_eq!(attempt(&mut r, 10, 9000), verdict::INTENT_RESIDUAL_HELD);
    assert_eq!(
        attempt(&mut r, ref_window, 9000),
        verdict::INTENT_RESIDUAL_HELD
    ); // the oldest citable ref
    assert_eq!(attempt(&mut r, ref_window + 1, 9000), ""); // too old to cite: released
}

// Rule: CAN-3
#[test]
fn cancel_limit_residual_armed_pool_low_fails_closed() {
    let mut r = ResidualFixture::new();
    r.cancel_first();
    assert!(armed_at(&r.g.f.state, &r.g.f.p, r.g.f.tip));
    let quiet = i64::from(r.g.f.p.cancel_quiet);
    while r.g.f.tip + 1 < i64::from(r.g.f.vault(&r.pos.txid).unwrap().last_cancel_height) + quiet {
        r.g.tick();
    }
    let pos = r.g.f.vault(&r.pos.txid).unwrap();
    assert!(is_underwater(
        pos.collateral_zat,
        r.g.f.snap(r.g.f.tip).pclaim(),
        pos.minted_cents,
        r.g.f.p.claim_threshold_bps
    ));
    assert_eq!(r.release(), verdict::INTENT_RESIDUAL_HELD);
}

// Rule: CAN-3
// Rule: NOT-1
#[test]
fn cancel_limit_residual_held_while_claimable_by_path_b() {
    let mut r = ResidualFixture::new();
    r.cancel_first();
    r.g.pool_price = 50000;
    for _ in 0..128 {
        r.g.tick();
    }
    let mut n = NoticeRecord {
        height: i32::try_from(r.g.f.tip - 4).unwrap(),
        ref_height: i32::try_from(r.g.f.tip - i64::from(r.g.f.p.emergency_persist)).unwrap(),
        p_emerg: 10000,
    };
    let pos = r.pos;
    r.g.f.put(YedKey::Notice(pos), YedRecord::Notice(n));
    assert_eq!(r.release(), verdict::INTENT_RESIDUAL_HELD);
    n.ref_height = i32::try_from(r.g.f.tip).unwrap(); // not yet persisted at any citable ref
    r.g.f.put(YedKey::Notice(pos), YedRecord::Notice(n));
    assert_eq!(r.release(), "");
}

// Rule: CAN-3
#[test]
fn cancel_limit_residual_released_when_the_position_closes() {
    let mut r = ResidualFixture::new();
    r.cancel_first();
    assert_eq!(r.release(), verdict::INTENT_RESIDUAL_HELD);
    // the owner redeems the re-created position with the refunded YED: CLOSED frees the residual
    let p = r.pos.txid;
    let redeem =
        r.g.f
            .spend_tx(&p, &[op(p, 1)], r.g.f.tip, SpendOpts::default());
    let t = r.g.quote();
    r.g.f.mine(t, vec![redeem.clone()]);
    assert_eq!(r.g.f.refused_verdict(&redeem.txid()), "");
    assert_eq!(r.g.f.vault(&p).unwrap().status, VaultStatus::Closed);
    assert_eq!(r.release(), "");
}

// Rule: CAN-3
#[test]
fn cancel_limit_residual_follows_the_position_and_holds_while_claiming() {
    let mut r = ResidualFixture::new();
    r.cancel_first();
    let first = r.pos;
    r.g.pool_price = 9000;
    r.g.att_price = 9000;
    for _ in 0..64 {
        r.g.tick();
    }
    r.g.w = first.txid; // the fixture's selector is the claimed position's outpoint
    let rr = r.g.f.tip - 1;
    let sel = r.g.selector();
    let b = r.g.f.bundle_simple(rr, &sel, 9000);
    let payee = r.g.f.selected(rr, &sel)[0];
    let claim2 = r.g.f.spend_tx(
        &first.txid,
        &[op(first.txid, 1)],
        rr,
        SpendOpts {
            owner_path: false,
            bundle: Some(b),
            attest_payee: i64::from(payee),
            ..SpendOpts::default()
        },
    );
    assert_eq!(r.g.mine(&claim2).verdict, verdict::OK);
    assert_eq!(
        r.g.f.vault(&first.txid).unwrap().status,
        VaultStatus::Claiming
    );
    // past CANCEL_QUIET, but CLAIMING: still held
    assert_eq!(r.release(), verdict::INTENT_RESIDUAL_HELD);
    // the second cancel (q = 0 after the quiet period: one co-signer) moves heldBy to the new position
    let claimant2 = op(claim2.txid(), 0);
    let cancel2 = r.cancel_tx(&claimant2, &first, claim2.vout[0].value, &[1], 60000);
    let t = r.g.quote();
    r.g.f.mine(t, vec![cancel2.clone()]);
    assert_eq!(r.g.f.refused_verdict(&cancel2.txid()), "");
    let second = op(cancel2.txid(), 0);
    assert_eq!(r.g.f.state.intent(&r.residual).unwrap().held_by, second);
    assert_eq!(r.release(), verdict::INTENT_RESIDUAL_HELD); // the new position's quiet period starts again
}

// Rule: CAN-3
#[test]
fn cancel_limit_residual_of_a_released_claim_unchanged() {
    let mut r = ResidualFixture::new();
    // the claimant intent is released (no cancel): the residual is released at once
    let fi = r.g.f.fake_input();
    let value = r.claim.vout[usize::try_from(r.claimant.n).unwrap()].value;
    let rel = MTx {
        vin: vec![
            VaultTxIn {
                prevout: r.claimant,
                script_sig: vec![0x51],
            },
            txin(fi),
        ],
        vout: vec![txout(value, r.g.f.user_p2pkh())],
        lock_time: 0,
    };
    let t = r.g.quote();
    r.g.f.mine(t, vec![rel.clone()]);
    assert_eq!(r.g.f.refused_verdict(&rel.txid()), "");
    assert!(kogany_yellowback::state::is_null_outpoint(
        &r.g.f.state.intent(&r.residual).unwrap().held_by
    ));
    assert_eq!(r.release(), "");
}

/// C4b: an EQUIVOCATION whose carrier holds attestation `a` and the cancel statement `s` ("YX").
fn cancel_evidence_tx(f: &mut Fixture, a: &Attestation, s: &CancelStatement) -> MTx {
    let ci = f.carrier_in(&encode_cancel_evidence(a, s));
    MTx {
        vin: vec![ci],
        vout: vec![
            payload_out(&Payload::Equivocation),
            txout(1000, f.user_p2pkh()),
        ],
        lock_time: 0,
    }
}

fn statement_of(intent: &OutPoint, e: &CancelCosignEntry) -> CancelStatement {
    CancelStatement {
        intent: *intent,
        price_micro_usd: e.price_micro_usd,
        sig: e.sig,
    }
}

// Rule: C4b
// Rule: EQV-1
#[test]
fn cancel_statement_slashed_by_eqv1() {
    let mut c = CancelFixture::new();
    let i = c.intent();
    let e = c.f.cosign(1, HONEST, &i, c.claim_ref, None);
    let att = c.f.att(1, 9000, c.claim_ref, None);
    let outs = vec![c.relock(), c.refund()];
    let cancel = c.cancel_of(&i, outs, &[e], set_sig(2));
    assert_eq!(c.mine(&cancel), "");
    let eqv = cancel_evidence_tx(&mut c.f, &att, &statement_of(&i, &e));
    let ev = equivocation_evidence(&eqv.tx(), &c.f.p).unwrap();
    assert!(matches!(ev, Equivocation::CancelStatement(..)));
    let set = Hash32(c.f.p.attestor_set_id);
    assert!(equivocated_by(
        &ev,
        &c.f.hot_pub(1),
        &fake_hash(c.claim_ref),
        &set
    ));
    assert!(!equivocated_by(
        &ev,
        &c.f.hot_pub(0),
        &fake_hash(c.claim_ref),
        &set
    ));
    assert!(!equivocated_by(
        &ev,
        &c.f.hot_pub(1),
        &fake_hash(c.claim_ref),
        &u256s("02")
    ));
    let t = Fixture::quote(9000, (c.f.tip + 1) % 3);
    c.f.mine(Some(t), vec![eqv.clone()]);
    let slashed = c.f.attestor(1).unwrap();
    assert_eq!(slashed.status, AttestorStatus::Ejected);
    assert!(slashed.bond_frozen);
    let log = c.f.log(&eqv.txid()).unwrap();
    assert_eq!(log.tx_type, TxLogType::Equivocation);
    assert_eq!(log.attestor_seq, 1);
    assert!(!c.f.attestor(0).unwrap().bond_frozen);
}

// Rule: C4b
// Rule: EQV-1
#[test]
fn cancel_statement_honest_canceller_never_slashed() {
    let mut c = CancelFixture::new();
    let i = c.intent();
    let e = c.f.cosign(0, HONEST, &i, c.claim_ref, None);
    let same = c.f.att(0, HONEST, c.claim_ref, None);
    let outs = vec![c.relock(), c.refund()];
    let cancel = c.cancel_of(&i, outs, &[e], set_sig(2));
    assert_eq!(c.mine(&cancel), "");
    let eqv = cancel_evidence_tx(&mut c.f, &same, &statement_of(&i, &e));
    assert!(equivocation_evidence(&eqv.tx(), &c.f.p).is_none());
    let t = Fixture::quote(9000, (c.f.tip + 1) % 3);
    c.f.mine(Some(t), vec![eqv]);
    assert_ne!(c.f.attestor(0).unwrap().status, AttestorStatus::Ejected);
    assert!(!c.f.attestor(0).unwrap().bond_frozen);
    // an attestation at another height is not evidence either, nor another member's attestation
    let other = c.f.att(0, 9000, c.claim_ref - 1, None);
    let eqv2 = cancel_evidence_tx(&mut c.f, &other, &statement_of(&i, &e));
    let ev2 = equivocation_evidence(&eqv2.tx(), &c.f.p).unwrap(); // structure only
    let set = Hash32(c.f.p.attestor_set_id);
    assert!(!equivocated_by(
        &ev2,
        &c.f.hot_pub(0),
        &fake_hash(c.claim_ref - 1),
        &set
    ));
    let a2 = c.f.att(2, 9000, c.claim_ref, None);
    let eqv3 = cancel_evidence_tx(&mut c.f, &a2, &statement_of(&i, &e));
    let t = Fixture::quote(9000, (c.f.tip + 1) % 3);
    c.f.mine(Some(t), vec![eqv2, eqv3]);
    for seq in [0u16, 2] {
        assert_ne!(c.f.attestor(seq).unwrap().status, AttestorStatus::Ejected);
        assert!(!c.f.attestor(seq).unwrap().bond_frozen);
    }
}
