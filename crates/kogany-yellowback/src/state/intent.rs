// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

//! The spend of a claim intent (U-23, U-24; ycash6 `state.cpp` `ApplyIntentSpend`,
//! `CancelCosignsHold`, `ResidualReleasable`, `ClaimableAtSnapshot`). The primitive has already
//! checked the delay and the payment; the module moves its records:
//!
//! - **release** (selector 1) of the claimant intent: the vault becomes CLAIMED, its collateral
//!   and debt leave the totals (IT-6, HALT-2); of a residual intent: nothing else moves, but
//!   CAN-3 holds the residual of a cancelled claim while its re-created position lives;
//! - **cancel** (selector 2) of the claimant intent by the attestor set: the byte-identical vault
//!   is re-created at vout 0 (the same position, ACTIVE again), CAN-1 re-issues the claim's burn
//!   as a YED token to the holder it came from, CAN-2 + C4b require `CancelsRequired` distinct
//!   current members' CANCEL_COSIGN statements, and CAN-3 moves every residual the position holds
//!   to the new outpoint. A residual intent can never be cancelled.

use std::collections::BTreeSet;

use kogany_vault::act::recover_sig;
use kogany_vault::state::VaultTx;
use kogany_vault::template::{SEL_OWNER, SEL_UNLOCK};
use kogany_vault::{Hash32, OutPoint, PubKeyBytes};

use super::eval::Eval;
use super::lookups::{block_hash_at, cancel_q, cancels_required};
use super::mint::h32;
use super::records::{
    is_null_outpoint, AssignedOutput, IntentRecord, IntentRole, TokenRecord, Totals, TxLogRecord,
    TxLogType, VaultRecord, VaultStatus,
};
use super::redeem::{selector_of, vault_script_of};
use super::verdict;
use super::view::YedRead;
use crate::attest::attestation::cancel_cosign_message;
use crate::attest::bundle::{decode_cancel_cosigns, extract_bundle};
use crate::attest::mirror::current_member_seq;
use crate::codecs::payload::{FoundPayload, PayloadType};
use crate::math::is_underwater;
use crate::params::{MicroUsd, PRICE_MAX, PRICE_MIN};

/// A spent claim intent (`SpentIntent`).
#[derive(Clone, Debug)]
pub(crate) struct SpentIntent {
    pub(crate) outpoint: OutPoint,
    pub(crate) record: IntentRecord,
    pub(crate) vin: usize,
}

impl Eval<'_, '_> {
    /// CAN-3 round 2 (`ClaimableAtSnapshot`): whether a claim of the position could pass RED-4 at
    /// any reference height it may cite, `R` in `[max(H - REF_WINDOW, START_HEIGHT), H - 1]`,
    /// judged fail-closed from chain state alone: an undefined `xClaim` counts as claimable;
    /// (a) underwater at `xClaim` under `CLAIM_THRESHOLD`; (b) R ARMED and a standing notice
    /// persisting for R.
    fn claimable_at_snapshot(&self, v: &VaultRecord, out: &OutPoint) -> bool {
        let p = self.p;
        let lo = self
            .h
            .saturating_sub(i64::from(p.ref_window))
            .max(i64::from(p.start_height));
        let notice = self.st.notice(out);
        let mut r = lo;
        while r < self.h {
            let Some(s) = self.snap(r).filter(|s| s.pclaim().is_some()) else {
                return true; // fail closed
            };
            if is_underwater(
                v.collateral_zat,
                s.pclaim(),
                v.minted_cents,
                p.claim_threshold_bps,
            ) {
                return true; // (a)
            }
            if let Some(n) = notice {
                let age = r.saturating_sub(i64::from(n.ref_height));
                if p.is_armed(s.attest.is_armed())
                    && age >= i64::from(p.emergency_persist)
                    && age <= i64::from(p.emergency_notice_ttl)
                {
                    return true; // (b)
                }
            }
            r = r.saturating_add(1);
        }
        false
    }

    /// CAN-3 (`ResidualReleasable`): a held residual is released once its position is CLOSED or
    /// CLAIMED, or ACTIVE with `CANCEL_QUIET` passed since its last cancel and no claim of it
    /// possible at any citable R; never while it is CLAIMING.
    fn residual_releasable(&self, pos: Option<&VaultRecord>, out: &OutPoint) -> bool {
        let Some(pos) = pos else {
            return false; // cannot happen: every cancel moves heldBy to the position it re-creates
        };
        match pos.status {
            VaultStatus::Closed | VaultStatus::Claimed => true,
            VaultStatus::Active
                if self.h.saturating_sub(i64::from(pos.last_cancel_height))
                    >= i64::from(self.p.cancel_quiet) =>
            {
                !self.claimable_at_snapshot(pos, out)
            }
            _ => false,
        }
    }

    /// CAN-2 + C4b (`CancelCosignsHold`): the cancel's carrier holds a well-formed `"YC"` list in
    /// which at least `required` distinct valid entries are found — price in `[PRICE_MIN,
    /// PRICE_MAX]`, the vault not claimable at it, recovering over `CancelCosignMessage` to a
    /// current member of the attestor set; each key counts once. The counted seqs, carrier order.
    fn cancel_cosigns_hold(
        &self,
        tx: &VaultTx,
        intent: &SpentIntent,
        vault: &VaultRecord,
        required: i64,
    ) -> Option<Vec<u16>> {
        let p = self.p;
        let (bytes, _) = extract_bundle(tx, p.bundle_carrier, false, &[]).ok()?;
        let entries = decode_cancel_cosigns(&bytes)?;
        let r = i64::from(intent.record.claim_ref_height);
        let block_hash = block_hash_at(&self.st, p, r)?;
        let set_id = Hash32(p.attestor_set_id);
        let r32 = u32::try_from(r).ok()?;
        let mut counted: BTreeSet<PubKeyBytes> = BTreeSet::new();
        let mut seqs = Vec::new();
        for e in &entries {
            let price = MicroUsd::from(e.price_micro_usd);
            if !(PRICE_MIN..=PRICE_MAX).contains(&price) {
                continue;
            }
            if is_underwater(
                vault.collateral_zat,
                Some(price),
                vault.minted_cents,
                p.claim_threshold_bps,
            ) {
                continue;
            }
            let msg = cancel_cosign_message(
                &set_id,
                &intent.outpoint.txid,
                intent.outpoint.n,
                r32,
                e.price_micro_usd,
                &block_hash,
            );
            let Some(key) = recover_sig(&msg, &e.sig) else {
                continue;
            };
            if counted.contains(&key) {
                continue;
            }
            let Some(seq) = current_member_seq(&self.st, &key, self.h) else {
                continue;
            };
            counted.insert(key);
            seqs.push(seq);
        }
        (i64::try_from(seqs.len()).unwrap_or(i64::MAX) >= required).then_some(seqs)
    }

    /// `ApplyIntentSpend`: the release or cancel of a claim intent. `Ok` on success, else the
    /// verdict that makes the transaction invalid.
    #[allow(clippy::too_many_lines)]
    pub(crate) fn apply_intent_spend(
        &mut self,
        tx: &VaultTx,
        spent: &SpentIntent,
        fp: Option<&FoundPayload>,
        log: &mut TxLogRecord,
        totals: &mut Totals,
        yed_outputs: &mut BTreeSet<usize>,
    ) -> Result<(), &'static str> {
        let p = self.p;
        let selector = tx
            .inputs
            .get(spent.vin)
            .and_then(|i| selector_of(&i.script_sig));
        let cancel = match selector {
            Some(SEL_UNLOCK) => false,
            Some(SEL_OWNER) => true,
            _ => return Err(verdict::INTENT_SPEND_MALFORMED),
        };
        // a release carries no Yellowback payload; a cancel none but CAN-2's CANCEL_COSIGN marker
        if let Some(f) = fp {
            if !(cancel && f.payload.payload_type() == PayloadType::CancelCosign) {
                return Err(verdict::INTENT_SPEND_MALFORMED);
            }
        }
        let role = spent.record.role;
        if cancel && role == IntentRole::Residual {
            return Err(verdict::INTENT_CANCEL_RESIDUAL);
        }
        // CAN-3: the residual of a cancelled claim is held while the re-created position lives
        if !cancel && role == IntentRole::Residual && !is_null_outpoint(&spent.record.held_by) {
            let held_by = spent.record.held_by;
            let pos = self.st.vault(&held_by);
            if !self.residual_releasable(pos.as_ref(), &held_by) {
                return Err(verdict::INTENT_RESIDUAL_HELD);
            }
        }
        let vault = self.st.vault(&spent.record.vault);
        self.st.erase(super::keys::YedKey::Intent(spent.outpoint));
        log.tx_type = if cancel {
            TxLogType::ClaimCancel
        } else {
            TxLogType::ClaimRelease
        };
        if role == IntentRole::Residual {
            return Ok(()); // the owner's residual: nothing else moves
        }
        let Some(vault) = vault.filter(|v| v.status == VaultStatus::Claiming) else {
            return Ok(()); // cannot happen; stated for totality
        };
        if !cancel {
            let mut v = vault.clone();
            v.status = VaultStatus::Claimed;
            self.st.put_vault(spent.record.vault, v);
            totals.collateral_zat = totals.collateral_zat.wrapping_sub(vault.collateral_zat); // IT-6
            totals.open_debt_cents = totals.open_debt_cents.wrapping_sub(vault.minted_cents); // HALT-2
            totals.claimed_vaults = totals.claimed_vaults.wrapping_add(1);
            log.closed_vaults.push(spent.record.vault);
            return Ok(());
        }
        // the re-created vault: exactly one output paying the byte-identical V, at vout 0
        let vault_spk = vault_script_of(p, &vault);
        let mut relock: Option<usize> = None;
        for (j, o) in tx.outputs.iter().enumerate() {
            if o.script_pubkey != vault_spk {
                continue;
            }
            if relock.is_some() {
                return Err(verdict::INTENT_CANCEL_NO_VAULT);
            }
            relock = Some(j);
        }
        let Some(relock_out) = tx.outputs.first().filter(|_| relock == Some(0)) else {
            return Err(verdict::INTENT_CANCEL_NO_VAULT);
        };
        // CAN-1: the refund output -- the lowest index >= 1 paying the recorded holder
        let refund = vault.burned_cents;
        if refund <= 0 || spent.record.refund_script.is_empty() {
            return Err(verdict::INTENT_CANCEL_NO_REFUND);
        }
        let holder = spent.record.refund_script.clone();
        let Some((refund_vout, refund_out)) = tx
            .outputs
            .iter()
            .enumerate()
            .skip(1)
            .find(|(_, o)| o.script_pubkey == holder && o.value > 0)
        else {
            return Err(verdict::INTENT_CANCEL_NO_REFUND);
        };
        // CAN-2 + C4b
        let required = cancels_required(&vault, p, self.h);
        let cosigners = match fp {
            Some(_) => self.cancel_cosigns_hold(tx, spent, &vault, required),
            None => None,
        };
        let Some(cosigners) = cosigners else {
            return Err(verdict::INTENT_CANCEL_COSIGN);
        };
        log.bundle_seqs = cosigners;
        let refund_op = OutPoint {
            txid: tx.txid,
            n: u32::try_from(refund_vout).unwrap_or(u32::MAX),
        };
        let tok = TokenRecord {
            cents: refund,
            n_value: refund_out.value,
            script_pub_key: holder.clone(),
            height: h32(self.h),
        };
        self.st.put_token(refund_op, tok);
        log.assigned.push(AssignedOutput {
            outpoint: refund_op,
            cents: refund,
            script_pub_key: holder,
        });
        log.yed_out = refund;
        totals.supply_cents = totals.supply_cents.wrapping_add(refund); // 03/M-1
        let reopened = OutPoint {
            txid: tx.txid,
            n: 0,
        };
        let mut v = vault.clone();
        v.status = VaultStatus::Active;
        v.collateral_zat = relock_out.value;
        v.close_height = 0;
        v.closing_txid = Hash32::ZERO;
        v.burned_cents = 0;
        // CAN-2: min(q + 1, 255)
        v.cancel_count =
            u8::try_from(cancel_q(&vault, p, self.h).saturating_add(1).min(255)).unwrap_or(u8::MAX);
        v.last_cancel_height = h32(self.h);
        let new_collateral = v.collateral_zat;
        self.st
            .erase(super::keys::YedKey::Vault(spent.record.vault));
        self.st.put_vault(reopened, v);
        // CAN-3: every residual the old position holds is held by the re-created one
        let held: Vec<(OutPoint, IntentRecord)> = self
            .st
            .intents()
            .into_iter()
            .filter(|(_, r)| {
                r.role == IntentRole::Residual
                    && (if is_null_outpoint(&r.held_by) {
                        r.vault
                    } else {
                        r.held_by
                    }) == spent.record.vault
            })
            .collect();
        for (op, mut r) in held {
            r.held_by = reopened;
            self.st.put_intent(op, r);
        }
        let notice_key = super::keys::YedKey::Notice(spent.record.vault);
        if self.st.has(&notice_key) {
            self.st.erase(notice_key);
        }
        // IT-6: the CLAIMING collateral was still counted
        totals.collateral_zat = totals
            .collateral_zat
            .wrapping_add(new_collateral.wrapping_sub(vault.collateral_zat));
        totals.active_vaults = totals.active_vaults.wrapping_add(1);
        log.closed_vaults.push(spent.record.vault);
        log.reopened_vaults.push(reopened);
        yed_outputs.insert(0);
        Ok(())
    }
}
