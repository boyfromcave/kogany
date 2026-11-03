// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

//! MINT-1..10 (§3.8; ycash6 `state.cpp` `MintVerdict`, `SetVault`, `ApplyMint`). Not ARMED at R:
//! the v2 clause order MINT-2..8 with MINT-8's amount clause right after MINT-5. ARMED: MINT-2,
//! 3, 4, 6, 7, MINT-8 shape/payee, the MINT-8′ lower bound, MINT-9, MINT-5 (at the combined
//! price), MINT-8′ amount, AFEE-1′ and MINT-10 — so bundle signatures are verified only for a
//! mint with a well-formed fee output to an eligible pool. A failing mint makes the transaction
//! invalid (§15.10: no VOID vault).

use std::collections::BTreeSet;

use kogany_vault::state::VaultTx;
use kogany_vault::template::{is_owner_valid, PQ_SCHEME_FN_DSA_512};
use kogany_vault::{Hash32, OutPoint};

use super::eval::{log_bundle, Eval};
use super::lookups::p2pkh_key;
use super::records::{AssignedOutput, TokenRecord, Totals, TxLogRecord, VaultRecord, VaultStatus};
use super::verdict;
use crate::attest::price::ref_height_in_window;
use crate::attest::price::{
    BundleFacts, HALT_DIVERGENCE, HALT_GLOBAL_RATIO, HALT_NOT_ACTIVE, HALT_NO_PRICE,
};
use crate::codecs::payload::Mint;
use crate::codecs::script::{holder_allowed, yed_vault_script};
use crate::math::{
    attest_fee_zat, max_vault_cents, min_ratio_bps, price_combine, protocol_fee_zat,
    required_collateral, supply_cap_cents, BPS,
};
use crate::params::{Amount, MicroUsd, Params, FEE_VOUT_NONE, LOCKTIME_THRESHOLD, MAX_MONEY};

/// What MINT evaluation learns beyond the verdict (`MintFacts`).
#[derive(Default)]
struct MintFacts {
    bundle: Option<BundleFacts>,
    attest_payee: Option<u16>,
    /// MINT-5's price, stored in the vault (FEE-1′).
    p_mint: MicroUsd,
}

fn ok() -> Result<(), String> {
    Ok(())
}

fn fail(v: &str) -> Result<(), String> {
    Err(v.to_owned())
}

/// A 32-bit record height of an `i64` the rules have range-checked (heights are below 2^31).
pub(crate) fn h32(h: i64) -> i32 {
    i32::try_from(h).unwrap_or(if h < 0 { i32::MIN } else { i32::MAX })
}

/// `SetVault`: the record a mint creates (status left to the caller).
fn new_vault(m: &Mint, p: &Params, tx: &VaultTx, height: i64) -> VaultRecord {
    let lock = i64::from(m.lock_height);
    let app = i64::from(m.ref_height).saturating_add(1); // IT-1: MINT-3 passed exactly this V
    VaultRecord {
        owner_pub_key: m.owner_bytes,
        term_class: m.term_class,
        lock_height: h32(lock),
        claim_height: h32(lock.saturating_add(i64::from(p.grace))),
        collateral_zat: tx.outputs.first().map_or(0, |o| o.value),
        minted_cents: i64::from(m.cents),
        mint_height: h32(height),
        ref_height: h32(i64::from(m.ref_height)),
        app_height: h32(app),
        owner_height: h32(app), // IT-1 (extended): the owner redeems in term too
        ..VaultRecord::default()
    }
}

impl Eval<'_, '_> {
    /// MINT-5: the collateral at `p_mint`; records the price on success.
    fn mint5(
        &self,
        tx: &VaultTx,
        m: &Mint,
        sigma_mult_bps: i32,
        p_mint: Option<MicroUsd>,
        facts: &mut MintFacts,
    ) -> Result<(), String> {
        let p = self.p;
        let Some(pm) = p_mint else {
            return fail(verdict::MINT_HALTED_NO_PRICE);
        };
        let base = p
            .base_ratio_bps
            .get(usize::from(m.term_class))
            .copied()
            .unwrap_or(0);
        let Some(required) =
            required_collateral(i64::from(m.cents), min_ratio_bps(base, sigma_mult_bps), pm)
        else {
            return fail(verdict::MINT_UNSATISFIABLE);
        };
        // MINT-5' (D-Q-23): the 4 x FEE_MIN floor is gone
        if tx.outputs.first().map_or(0, |o| o.value) < required {
            return fail(verdict::BAD_MINT_COLLATERAL);
        }
        facts.p_mint = pm; // the vault's fee price (FEE-1'): exactly the price MINT-5 passed at
        ok()
    }

    /// MINT-8′ amount (FEE-1′): `vout[feeVout] >= ProtocolFeeZat(cents, pMint)`; FEE-0 when
    /// E(R) is empty.
    fn mint8_amount(
        &self,
        tx: &VaultTx,
        m: &Mint,
        eligible: &[[u8; 20]],
        facts: &MintFacts,
    ) -> Result<(), String> {
        if eligible.is_empty() {
            return ok();
        }
        let fee = protocol_fee_zat(i64::from(m.cents), facts.p_mint, self.p);
        let paid = tx.outputs.get(usize::from(m.fee_vout)).map(|o| o.value);
        match (fee, paid) {
            (Some(f), Some(v)) if v >= f => ok(),
            _ => fail(verdict::BAD_MINT_FEE),
        }
    }

    /// `MintVerdict`.
    fn mint_verdict(
        &self,
        tx: &VaultTx,
        m: &Mint,
        op_return_index: usize,
        totals: &Totals,
        eligible: &[[u8; 20]],
        facts: &mut MintFacts,
    ) -> Result<(), String> {
        let p = self.p;
        let h = self.h;
        let cents = i64::from(m.cents);
        // MINT-2 (signed 64-bit arithmetic, M1)
        if !p.is_valid_class(i64::from(m.term_class)) {
            return fail(verdict::BAD_MINT_CLASS);
        }
        let cls = usize::from(m.term_class);
        if cents < p.min_mint || cents > p.max_mint {
            return fail(verdict::BAD_MINT_AMOUNT);
        }
        let lock = i64::from(m.lock_height);
        let r = i64::from(m.ref_height);
        if lock.saturating_add(i64::from(p.grace)) >= i64::from(LOCKTIME_THRESHOLD) {
            return fail(verdict::BAD_MINT_LOCK_HEIGHT);
        }
        if !ref_height_in_window(p, h, r) {
            return fail(verdict::BAD_MINT_REF_HEIGHT);
        }
        let span = lock.saturating_sub(r);
        let class_min = p.class_min.get(cls).copied().map_or(i64::MAX, i64::from);
        let class_max = p.class_max.get(cls).copied().map_or(i64::MIN, i64::from);
        if lock <= r || span < class_min || span > class_max {
            return fail(verdict::BAD_MINT_LOCK_HEIGHT);
        }
        // MINT-3
        if tx.outputs.len() < 3 {
            return fail(verdict::BAD_MINT_OUTPUTS);
        }
        let owner = m.owner();
        if !is_owner_valid(&owner) {
            return fail(verdict::BAD_MINT_OWNER_KEY);
        }
        // a Falcon owner only from the Falcon height (quantum plan §4.4, spec A-4, R-A2)
        if owner.scheme == PQ_SCHEME_FN_DSA_512 && !p.is_pq_falcon_active(h) {
            return fail(verdict::BAD_MINT_OWNER_KEY);
        }
        // U-23 + IT-1: the collateral is the primitive's V
        let vault_ok = match (yed_vault_script(p, &owner, r), tx.outputs.first()) {
            (Some(expected), Some(o)) => !expected.is_empty() && o.script_pubkey == expected,
            _ => false,
        };
        if !vault_ok {
            return fail(verdict::BAD_MINT_VAULT_SCRIPT);
        }
        // MINT-4
        let Some(s) = self.snap(r) else {
            return fail(verdict::MINT_NOT_ACTIVE);
        };
        if s.halt_mask & HALT_NOT_ACTIVE != 0 {
            return fail(verdict::MINT_NOT_ACTIVE);
        }
        if s.halt_mask & HALT_NO_PRICE != 0 {
            return fail(verdict::MINT_HALTED_NO_PRICE);
        }
        let base = p.base_ratio_bps.get(cls).copied().unwrap_or(0);
        // HALT-2 (amended, W16; IT-5): only a class whose base ratio is below the recap floor
        if s.halt_mask & HALT_GLOBAL_RATIO != 0 && base < p.recap_ratio_bps {
            return fail(verdict::MINT_HALTED_GLOBAL_RATIO);
        }
        if s.halt_mask & HALT_DIVERGENCE != 0 {
            return fail(verdict::MINT_HALTED_DIVERGENCE);
        }
        if s.halt_mask & !HALT_GLOBAL_RATIO != 0 {
            return fail(verdict::MINT_NOT_ACTIVE); // an unknown bit
        }
        let armed = p.is_armed(s.attest.is_armed());
        // MINT-4 (H-1)
        if p.mint_requires_armed && !armed {
            return fail(verdict::MINT_HALTED_UNARMED);
        }
        let x_mint = s.pmint();
        if !armed {
            self.mint5(tx, m, s.sigma_mult_bps, x_mint, facts)?;
        }
        // MINT-6 (amended, W20; IT-5): the cap is soft above the recapitalisation floor
        let cap = supply_cap_cents(s.issued_zat, x_mint, p.supply_cap_bps);
        if let Some(c) = cap {
            if totals.supply_cents.saturating_add(cents) > c && base < p.recap_ratio_bps {
                return fail(verdict::MINT_SUPPLY_CAP);
            }
        }
        // MINT-6b (D-Q-23a)
        if let Some(mv) = max_vault_cents(cap, p.max_vault_share_bps, p.vault_share_floor_cents) {
            if cents > mv {
                return fail(verdict::MINT_VAULT_SHARE);
            }
        }
        // MINT-7
        if op_return_index == 1 {
            return fail(verdict::BAD_MINT_TOKEN_OUTPUT);
        }
        // TOK-PQ (quantum spec F-7)
        let token_ok = tx
            .outputs
            .get(1)
            .is_some_and(|o| holder_allowed(p, h, &o.script_pubkey));
        if !token_ok {
            return fail(verdict::BAD_YED_HOLDER);
        }
        // MINT-8 shape and payee
        let fv = usize::from(m.fee_vout);
        if !eligible.is_empty() {
            if m.fee_vout == FEE_VOUT_NONE || fv == 0 || fv == 1 || fv == op_return_index {
                return fail(verdict::BAD_MINT_FEE);
            }
            let payee = tx.outputs.get(fv).and_then(|o| p2pkh_key(&o.script_pubkey));
            if !payee.is_some_and(|k| eligible.contains(&k)) {
                return fail(verdict::BAD_MINT_FEE);
            }
        }
        if !armed {
            return self.mint8_amount(tx, m, eligible, facts); // pMint = xMint
        }
        // MINT-8' lower bound (ARMED), before MINT-9's signature work
        if let (false, Some(x)) = (eligible.is_empty(), x_mint) {
            if let Some(floor) = protocol_fee_zat(cents, x, p) {
                if tx.outputs.get(fv).map_or(0, |o| o.value) < floor {
                    return fail(verdict::BAD_MINT_FEE);
                }
            }
        }
        // MINT-9 (ARMED at R: BUNDLE-1 with the empty selector; aMint defined)
        let f = self.bundle(tx, r, &[], false);
        let combined = match &f.verdict {
            Err(e) => {
                let v = if f.carrier_present {
                    format!("{}{}", verdict::MINT9_BUNDLE_PREFIX, e.reason())
                } else {
                    verdict::MINT9_NO_BUNDLE.to_owned()
                };
                facts.bundle = Some(f);
                return Err(v);
            }
            Ok(v) if v.a_mint.is_none() => {
                facts.bundle = Some(f);
                return Err(format!(
                    "{}{}",
                    verdict::MINT9_BUNDLE_PREFIX,
                    verdict::BUNDLE_STAT
                ));
            }
            // PRICE-2 (revised): pMint = min(xMint, aMint)
            Ok(v) => price_combine(x_mint, s.pclaim(), v.a_mint, v.a_claim),
        };
        let a_mint = f.verdict.as_ref().ok().and_then(|v| v.a_mint);
        let seqs = f.seqs();
        facts.bundle = Some(f);
        self.mint5(tx, m, s.sigma_mult_bps, combined.p_mint, facts)?;
        self.mint8_amount(tx, m, eligible, facts)?;
        // AFEE-1' (MINT-8's attestor-fee clause): half the protocol fee, never the early fee
        let attest_fee = attest_fee_zat(
            protocol_fee_zat(cents, facts.p_mint, p).unwrap_or(MAX_MONEY),
            p.attest_fee_bps,
        );
        let excluded: BTreeSet<usize> = [0, 1, op_return_index, fv].into_iter().collect();
        facts.attest_payee =
            self.attest_fee_ok(tx, m.attest_fee_vout, &seqs, &excluded, attest_fee);
        if facts.attest_payee.is_none() {
            return fail(verdict::AFEE1_FEE);
        }
        // MINT-10 (amended W17): |pFast(R) - aMint| x 10^4 <= DIVERGE_BPS_ATTEST x min(pFast, aMint)
        let (Some(a), Some(xm)) = (a_mint, x_mint) else {
            return fail(verdict::MINT10_DIVERGED); // unreachable: aMint and xMint are defined here
        };
        let x = s.pfast().unwrap_or(xm);
        let diff = i128::from(x.abs_diff(a));
        let bound = i128::from(p.diverge_bps_attest.max(0)).saturating_mul(i128::from(x.min(a)));
        if diff.saturating_mul(i128::from(BPS)) > bound {
            return fail(verdict::MINT10_DIVERGED);
        }
        ok()
    }

    /// `ApplyMint` (MINT-1..10): true when the mint holds (an ACTIVE vault and its token are
    /// written); false makes the transaction invalid (`log.verdict` says why).
    pub(crate) fn apply_mint(
        &mut self,
        tx: &VaultTx,
        m: &Mint,
        op_return_index: usize,
        log: &mut TxLogRecord,
        totals: &mut Totals,
    ) -> bool {
        let r = i64::from(m.ref_height);
        let eligible = self.eligible(r);
        let mut facts = MintFacts::default();
        let v = self.mint_verdict(tx, m, op_return_index, totals, &eligible, &mut facts);
        log_bundle(log, facts.bundle.as_ref());
        if let Err(v) = v {
            log.verdict = v;
            log.yed_out = 0;
            return false;
        }
        if let Some(f) = &facts.bundle {
            self.commit_bundle(f); // R12 (03/M-2): the mint held
        }
        let mut vault = new_vault(m, self.p, tx, self.h);
        vault.status = VaultStatus::Active;
        vault.p_mint = facts.p_mint;
        if !eligible.is_empty() {
            let fee_out = tx.outputs.get(usize::from(m.fee_vout));
            vault.fee_paid_zat = fee_out.map_or(0, |o| o.value);
            log.fee_zat = vault.fee_paid_zat;
            let key = fee_out.and_then(|o| p2pkh_key(&o.script_pubkey));
            log.has_payee = key.is_some();
            if let Some(k) = key {
                log.payee = k;
            }
        }
        if let Some(seq) = facts.attest_payee {
            log.attest_fee_zat = tx
                .outputs
                .get(usize::from(m.attest_fee_vout))
                .map_or(0, |o| o.value);
            log.has_attest_payee = true;
            log.attest_payee = seq;
        }
        let txid: Hash32 = tx.txid;
        let collateral: Amount = vault.collateral_zat;
        let minted = vault.minted_cents;
        self.st.put_vault(OutPoint { txid, n: 0 }, vault);
        let tok_out = OutPoint { txid, n: 1 };
        let token = tx.outputs.get(1);
        let tok = TokenRecord {
            cents: i64::from(m.cents),
            n_value: token.map_or(0, |o| o.value),
            script_pub_key: token.map(|o| o.script_pubkey.clone()).unwrap_or_default(),
            height: h32(self.h),
        };
        log.assigned.push(AssignedOutput {
            outpoint: tok_out,
            cents: tok.cents,
            script_pub_key: tok.script_pub_key.clone(),
        });
        self.st.put_token(tok_out, tok);
        totals.supply_cents = totals.supply_cents.wrapping_add(i64::from(m.cents));
        totals.collateral_zat = totals.collateral_zat.wrapping_add(collateral);
        totals.open_debt_cents = totals.open_debt_cents.wrapping_add(minted); // HALT-2: open until its redeem or release
        totals.active_vaults = totals.active_vaults.wrapping_add(1);
        log.yed_out = i64::from(m.cents);
        log.verdict = verdict::OK.to_owned();
        true
    }
}
