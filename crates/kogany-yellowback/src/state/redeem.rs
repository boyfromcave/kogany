// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

//! RED-1..5 over a transaction that spends an ACTIVE vault (M3; ycash6 `state.cpp`
//! `RedVerdict`, `ApplyVaultSpend`): the owner's redeem (selectors 2/3) closes the vault, a claim
//! (selector 4) moves it into claim intents (U-23) — one claimant intent and, when RED-5's
//! residual is due, the owner's residual intent — and leaves it CLAIMING until the claimant
//! intent is released or cancelled ([`super::intent`]). A failing spend makes the transaction
//! invalid.

use std::collections::BTreeSet;

use kogany_vault::state::VaultTx;
use kogany_vault::template::{is_owner_valid, script_hash256, SEL_APP, SEL_OWNER, SEL_RELEASED};
use kogany_vault::OutPoint;

use super::eval::{log_bundle, Eval};
use super::lookups::{p2pkh_key, yed_intent_output};
use super::mint::h32;
use super::records::{IntentRecord, IntentRole, Totals, TxLogRecord, VaultRecord, VaultStatus};
use super::verdict;
use super::view::YedRead;
use crate::attest::price::{ref_height_in_window, BundleFacts};
use crate::attest::seats::outpoint_selector;
use crate::codecs::payload::{FoundPayload, Payload, Redeem};
use crate::codecs::script::{holder_allowed, pq_key_script, yed_vault_script_at};
use crate::math::{
    attest_fee_zat, claimant_max_zat, early_redeem_fee_zat, is_underwater, price_combine,
    protocol_fee_zat, residual_min_zat, residual_zat, BPS,
};
use crate::params::{Amount, Cents, MicroUsd, FEE_VOUT_NONE, MAX_MONEY};

/// A vault being spent by the transaction under evaluation (`SpentVault`).
#[derive(Clone, Debug)]
pub(crate) struct SpentVault {
    pub(crate) outpoint: OutPoint,
    pub(crate) record: VaultRecord,
}

/// What RED evaluation learns beyond the verdict (`RedFacts`).
#[derive(Default)]
struct RedFacts {
    bundle: Option<BundleFacts>,
    attest_payee: Option<u16>,
    residual_zat: Amount,
    /// `"a"` | `"b"` | `""`.
    claim_path: &'static str,
    /// U-23: the claimant intent's vout.
    claimant_vout: Option<usize>,
    /// U-23: the owner's residual intent's vout, when one is due.
    residual_vout: Option<usize>,
}

/// The owner's selectors (§15.3): 2 (the owner's key) and 3 (the set released).
pub(crate) fn is_owner_selector(sel: u8) -> bool {
    sel == SEL_OWNER || sel == SEL_RELEASED
}

/// The selector of an input's scriptSig (`vault::ParseSelector`).
pub(crate) fn selector_of(script_sig: &[u8]) -> Option<u8> {
    kogany_vault::template::parse_selector(script_sig).map(|(s, _)| s)
}

/// `YedVaultScriptAt` of a record (the empty script when YED has no attestor set, as the C++).
pub(crate) fn vault_script_of(p: &crate::params::Params, v: &VaultRecord) -> Vec<u8> {
    yed_vault_script_at(
        p,
        &v.owner(),
        i64::from(v.owner_height),
        i64::from(v.app_height),
    )
    .unwrap_or_default()
}

/// `AssignedCents` of an assignment list (at most 13 x (2^32 - 1): no overflow).
fn assigned_cents(a: &[crate::codecs::payload::Assignment]) -> Cents {
    a.iter()
        .fold(0i64, |s, x| s.saturating_add(i64::from(x.cents)))
}

fn fail<T>(v: &str) -> Result<T, String> {
    Err(v.to_owned())
}

impl Eval<'_, '_> {
    /// `RedVerdict`.
    #[allow(clippy::too_many_lines)]
    fn red_verdict(
        &self,
        tx: &VaultTx,
        fp: Option<&FoundPayload>,
        active: &[SpentVault],
        selector: Option<u8>,
        yed_in: Cents,
        facts: &mut RedFacts,
    ) -> Result<(), String> {
        let p = self.p;
        let h = self.h;
        // RED-1
        let (Some(spent), Some(vin0)) = (active.first(), tx.inputs.first()) else {
            return fail(verdict::VAULT_SPEND_MALFORMED);
        };
        if active.len() != 1 || spent.outpoint != vin0.prevout {
            return fail(verdict::VAULT_SPEND_MALFORMED);
        }
        let Some(sel) = selector.filter(|s| is_owner_selector(*s) || *s == SEL_APP) else {
            return fail(verdict::VAULT_SPEND_MALFORMED);
        };
        let Some((red, op_return_index)) = fp.and_then(|f| match &f.payload {
            Payload::Redeem(r) => Some((r, f.op_return_index)),
            _ => None,
        }) else {
            return fail(verdict::VAULT_SPEND_MALFORMED);
        };
        let r = i64::from(red.ref_height);
        if !ref_height_in_window(p, h, r) {
            return fail(verdict::VAULT_SPEND_MALFORMED);
        }
        if red.assignments.iter().any(|a| {
            let c = i64::from(a.cents);
            c < p.min_output || c > p.max_output
        }) {
            return fail(verdict::VAULT_SPEND_MALFORMED);
        }
        // TOK-PQ: from the Falcon height every assigned output is a Falcon holder
        for a in &red.assignments {
            let ok = tx
                .outputs
                .get(usize::from(a.vout))
                .is_some_and(|o| holder_allowed(p, h, &o.script_pubkey));
            if !ok {
                return fail(verdict::BAD_YED_HOLDER);
            }
        }
        let vault = &spent.record;
        if vault.p_mint <= 0 {
            return fail(verdict::VAULT_SPEND_MALFORMED); // RED-1' (FEE-1'): the rule is total
        }
        let claim = sel == SEL_APP;
        // U-23: one claimant intent, at most one owner residual intent, no re-lock
        let mut intents: Vec<usize> = Vec::new();
        if claim {
            let vault_spk = vault_script_of(p, vault);
            let vault_hash = script_hash256(&vault_spk);
            for (j, o) in tx.outputs.iter().enumerate() {
                if o.script_pubkey == vault_spk {
                    return fail(verdict::VAULT_CLAIM_INTENTS);
                }
                if yed_intent_output(&o.script_pubkey).is_some_and(|ip| ip.vault_hash == vault_hash)
                {
                    intents.push(j);
                }
            }
            if intents.is_empty() || intents.len() > 2 {
                return fail(verdict::VAULT_CLAIM_INTENTS);
            }
        }
        let armed = claim && self.armed(r); // the owner path reads no bundle (RED-1 amended)
        if armed {
            let f = self.bundle(tx, r, &outpoint_selector(&spent.outpoint), true);
            let res = match &f.verdict {
                Err(e) => Err(format!("{}{}", verdict::RED1_BUNDLE_PREFIX, e.reason())),
                Ok(v) if v.a_claim.is_none() => Err(format!(
                    "{}{}",
                    verdict::RED1_BUNDLE_PREFIX,
                    verdict::BUNDLE_STAT
                )),
                Ok(_) => Ok(()),
            };
            facts.bundle = Some(f);
            res?;
        }
        // RED-2
        let burn = yed_in.saturating_sub(assigned_cents(&red.assignments));
        if burn < vault.minted_cents {
            return fail(if burn <= 0 {
                verdict::VAULT_SPEND_MISSING_BURN
            } else {
                verdict::VAULT_SPEND_SHORT_BURN
            });
        }
        // RED-3' (FEE-0 when E(R) is empty): the debt's protocol fee at the vault's pMint;
        // IT-9': an owner redeem below lockHeight pays the early fee on top
        let protocol_fee =
            protocol_fee_zat(vault.minted_cents, vault.p_mint, p).unwrap_or(MAX_MONEY);
        let eligible = self.eligible(r);
        let assigned: BTreeSet<usize> = red
            .assignments
            .iter()
            .map(|a| usize::from(a.vout))
            .collect();
        let fv = usize::from(red.fee_vout);
        if !eligible.is_empty() {
            if red.fee_vout == FEE_VOUT_NONE || fv == op_return_index || assigned.contains(&fv) {
                return fail(verdict::VAULT_SPEND_BAD_FEE);
            }
            let Some(fee_out) = tx.outputs.get(fv) else {
                return fail(verdict::VAULT_SPEND_BAD_FEE);
            };
            if !p2pkh_key(&fee_out.script_pubkey).is_some_and(|k| eligible.contains(&k)) {
                return fail(verdict::VAULT_SPEND_BAD_PAYEE);
            }
            if fee_out.value < protocol_fee {
                return fail(verdict::VAULT_SPEND_BAD_FEE);
            }
            if !claim
                && h < i64::from(vault.lock_height)
                && p.is_valid_class(i64::from(vault.term_class))
            {
                let early_bps = p
                    .early_redeem_fee_bps
                    .get(usize::from(vault.term_class))
                    .copied()
                    .unwrap_or(0);
                let early = early_redeem_fee_zat(vault.minted_cents, early_bps, vault.p_mint);
                if fee_out.value < protocol_fee.saturating_add(early) {
                    return fail(verdict::BAD_REDEEM_EARLY_FEE); // IT-9'
                }
            }
        }
        // AFEE-1' (RED-3's attestor-fee clause; AFEE-0 when not ARMED or on the owner path)
        if armed {
            let fee = attest_fee_zat(protocol_fee, p.attest_fee_bps);
            let mut excluded = assigned.clone();
            excluded.extend([0, 1, op_return_index, fv]);
            let seqs = facts
                .bundle
                .as_ref()
                .map(BundleFacts::seqs)
                .unwrap_or_default();
            facts.attest_payee = self.attest_fee_ok(tx, red.attest_fee_vout, &seqs, &excluded, fee);
            if facts.attest_payee.is_none() {
                return fail(verdict::AFEE1_FEE);
            }
        }
        if claim {
            self.red4_red5(tx, spent, r, armed, &intents, facts)?;
        }
        Ok(())
    }

    /// RED-4 (amended; IT-2) and RED-5 / RED-5a / RED-5b of a claim.
    fn red4_red5(
        &self,
        tx: &VaultTx,
        spent: &SpentVault,
        r: i64,
        armed: bool,
        intents: &[usize],
        facts: &mut RedFacts,
    ) -> Result<(), String> {
        let p = self.p;
        let vault = &spent.record;
        let s = self.snap(r);
        let x_claim = s.as_ref().and_then(|s| s.pclaim());
        let mut p_claim = x_claim;
        let mut p_emerg: Option<MicroUsd> = None;
        if armed {
            let (a_mint, a_claim) = facts
                .bundle
                .as_ref()
                .and_then(|f| f.verdict.as_ref().ok())
                .map_or((None, None), |v| (v.a_mint, v.a_claim));
            let c = price_combine(s.as_ref().and_then(|s| s.pmint()), x_claim, a_mint, a_claim);
            p_claim = c.p_claim;
            p_emerg = c.p_emerg;
        }
        if is_underwater(
            vault.collateral_zat,
            p_claim,
            vault.minted_cents,
            p.claim_threshold_bps,
        ) {
            facts.claim_path = "a";
        } else {
            // (b) is false before arming
            let notice = if armed {
                self.st.notice(&spent.outpoint)
            } else {
                None
            };
            let persisted = notice.is_some_and(|n| {
                let age = r.saturating_sub(i64::from(n.ref_height));
                age >= i64::from(p.emergency_persist) && age <= i64::from(p.emergency_notice_ttl)
            });
            if !persisted
                || !is_underwater(
                    vault.collateral_zat,
                    p_emerg,
                    vault.minted_cents,
                    p.emergency_ratio_bps,
                )
            {
                return fail(verdict::VAULT_CLAIM_NOT_UNDERWATER);
            }
            facts.claim_path = "b";
        }
        // RED-5 (RED-5b: path (a) caps at pClaim with the claim threshold, path (b) at pEmerg)
        let path_a = facts.claim_path == "a";
        let Some(cap_price) = (if path_a { p_claim } else { p_emerg }) else {
            return fail(verdict::RED5_RESIDUAL);
        };
        let margin = if path_a {
            p.claim_threshold_bps
        } else {
            i32::try_from(BPS).unwrap_or(i32::MAX)
        };
        facts.residual_zat = residual_zat(
            vault.collateral_zat,
            claimant_max_zat(vault.minted_cents, margin, cap_price),
        );
        if facts.residual_zat >= residual_min_zat(vault.p_mint, p) {
            // RED-5a: the lower-index intent is the claimant's, the higher-index one the owner's
            let owner = vault.owner();
            let (true, [claimant, residual]) = (is_owner_valid(&owner), intents) else {
                return fail(verdict::RED5_RESIDUAL);
            };
            let owner_hash = script_hash256(&pq_key_script(&owner).unwrap_or_default());
            facts.claimant_vout = Some(*claimant);
            facts.residual_vout = Some(*residual);
            let res_out = tx.outputs.get(*residual);
            let pays_owner = res_out
                .and_then(|o| yed_intent_output(&o.script_pubkey))
                .is_some_and(|ip| ip.recipient_hash == owner_hash);
            if !pays_owner || res_out.map_or(0, |o| o.value) < facts.residual_zat {
                return fail(verdict::RED5_RESIDUAL);
            }
            let claimant_value = tx.outputs.get(*claimant).map_or(0, |o| o.value);
            if claimant_value < vault.collateral_zat.saturating_sub(facts.residual_zat) {
                return fail(verdict::RED5_CLAIMANT_SHORT);
            }
        } else {
            let [claimant] = intents else {
                return fail(verdict::VAULT_CLAIM_INTENTS);
            };
            facts.claimant_vout = Some(*claimant);
        }
        Ok(())
    }

    /// `ApplyVaultSpend`: RED-1..5 over a spend of an ACTIVE vault. True iff they failed (the
    /// transaction is then invalid; `log.verdict` says why). On success `active[0].record` is
    /// the closed (CLOSED) or claimed (CLAIMING) record; IN-3 writes it with the burn.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn apply_vault_spend(
        &mut self,
        tx: &VaultTx,
        fp: Option<&FoundPayload>,
        active: &mut [SpentVault],
        yed_in: Cents,
        log: &mut TxLogRecord,
        totals: &mut Totals,
        yed_outputs: &mut BTreeSet<usize>,
    ) -> bool {
        let selector = tx.inputs.first().and_then(|i| selector_of(&i.script_sig));
        if let Some(sel) = selector.filter(|s| is_owner_selector(*s) || *s == SEL_APP) {
            log.path = if is_owner_selector(sel) {
                "owner"
            } else {
                "claim"
            }
            .to_owned();
        }
        let mut facts = RedFacts::default();
        let v = self.red_verdict(tx, fp, active, selector, yed_in, &mut facts);
        log_bundle(log, facts.bundle.as_ref());
        log.residual_zat = facts.residual_zat;
        log.claim_path = facts.claim_path.to_owned();
        let failed = |log: &mut TxLogRecord, v: &str| {
            log.verdict = v.to_owned();
            log.yed_out = 0;
            true
        };
        if let Err(v) = v {
            return failed(log, &v);
        }
        let owner_path = selector.is_some_and(is_owner_selector);
        // CAN-1 (03/H-1): a claim records the holder its burn came from (totality only)
        if !owner_path && log.spent_tokens.is_empty() {
            return failed(log, verdict::VAULT_SPEND_MALFORMED);
        }
        if let Some(f) = &facts.bundle {
            self.commit_bundle(f); // R12 (03/M-2): RED-1..5 held
        }
        let (Some(red), Some(spent)) = (
            fp.and_then(|f| match &f.payload {
                Payload::Redeem(r) => Some(r.clone()),
                _ => None,
            }),
            active.first_mut(),
        ) else {
            return failed(log, verdict::VAULT_SPEND_MALFORMED); // RED-1 held: unreachable
        };
        let red: Redeem = red;
        self.write_assignments(tx, &red.assignments, log);
        log.yed_out = assigned_cents(&red.assignments);
        log.verdict = verdict::OK.to_owned();
        // U-23: the owner's spend closes the vault; a claim leaves it CLAIMING
        let vault = &mut spent.record;
        vault.status = if owner_path {
            VaultStatus::Closed
        } else {
            VaultStatus::Claiming
        };
        vault.close_height = h32(self.h);
        vault.closing_txid = tx.txid;
        vault.unbacked = false;
        vault.fee_paid_zat = 0; // the fee this spend paid (0 under FEE-0)
        if !self.eligible(i64::from(red.ref_height)).is_empty() {
            let fee_out = tx.outputs.get(usize::from(red.fee_vout));
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
                .get(usize::from(red.attest_fee_vout))
                .map_or(0, |o| o.value);
            log.has_attest_payee = true;
            log.attest_payee = seq;
        }
        // IT-6 (D-IT-14): a claimed vault's collateral stays in the system ratio until its
        // release; HALT-2: and its debt; the owner's redeem removes both at once
        if owner_path {
            totals.collateral_zat = totals.collateral_zat.wrapping_sub(vault.collateral_zat);
            totals.open_debt_cents = totals.open_debt_cents.wrapping_sub(vault.minted_cents);
        }
        totals.active_vaults = totals.active_vaults.saturating_sub(1);
        if owner_path {
            totals.closed_vaults = totals.closed_vaults.wrapping_add(1);
        } else {
            let refund = log
                .spent_tokens
                .first()
                .map(|t| t.script_pub_key.clone())
                .unwrap_or_default();
            let roles = [
                (facts.claimant_vout, IntentRole::Claimant),
                (facts.residual_vout, IntentRole::Residual),
            ];
            for (j, role) in roles {
                let Some(j) = j else {
                    continue;
                };
                let rec = IntentRecord {
                    vault: spent.outpoint,
                    role,
                    height: h32(self.h),
                    // CAN-1: the refund holder is the token spent at the lowest-index YED input
                    refund_script: if role == IntentRole::Claimant {
                        refund.clone()
                    } else {
                        Vec::new()
                    },
                    claim_ref_height: h32(i64::from(red.ref_height)), // C4b
                    ..IntentRecord::default()
                };
                let n = u32::try_from(j).unwrap_or(u32::MAX);
                self.st.put_intent(OutPoint { txid: tx.txid, n }, rec);
                yed_outputs.insert(j);
            }
        }
        log.closed_vaults.push(spent.outpoint);
        false
    }
}
