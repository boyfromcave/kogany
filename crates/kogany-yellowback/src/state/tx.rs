// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

//! One transaction's effect on the YED state (§3.8; ycash6 `state.cpp` `ProcessTxImpl`):
//! inputs (IN-1, IN-2's bond spends) before the attestor set's acts on the mirror, then the
//! outputs' rule — a claim intent's spend, an ACTIVE vault's spend (RED, M3), a MINT, a TRANSFER
//! (or a REDEEM spending no vault), or a v3 type (NOT-1, EQV-1; the retired REG-A1 / REV-1
//! payloads are invalid) — then the liveness credit, U-23's template-output rule, and IN-3's
//! burn. A coinbase is TX-0: nothing happens.
//!
//! [`process_tx`] evaluates on its own overlay over `base` and returns the writes; the caller
//! merges them only when the transaction is valid (a block evaluation stops at the first invalid
//! transaction, BLK-1).

use std::collections::BTreeSet;

use kogany_vault::state::VaultTx;
use kogany_vault::Hash32;

use super::eval::{log_bundle, Eval};
use super::intent::SpentIntent;
use super::keys::YedKey;
use super::lookups::{block_hash_at, bond_min_zat, is_yed_vault_output, yed_intent_output};
use super::records::{AssignedOutput, NoticeRecord, TxLogRecord, TxLogType, VaultStatus};
use super::redeem::SpentVault;
use super::verdict;
use super::view::{Writes, YedRead};
use crate::attest::bundle::SigCache;
use crate::attest::liveness::attestation_liveness;
use crate::attest::mirror::{
    apply_bond_spend, apply_equivocation, apply_liveness_credits, apply_set_act,
    attestor_join_refused, mirror_live_member, refused_attestor_set_act, SetActEffect,
};
use crate::attest::price::{ref_height_in_window, verify_tx_bundle, BundleFacts};
use crate::attest::registry::RegistryRead;
use crate::attest::seats::outpoint_selector;
use crate::codecs::payload::{find_payload, ClaimNotice, FoundPayload, Payload};
use crate::math::{is_underwater, price_combine};
use crate::params::{Cents, Params};

/// The result of one transaction (`TxOutcome`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TxOutcome {
    /// The TxLog entry (written to the state when `relevant`).
    pub log: TxLogRecord,
    /// A TxLog entry was written: the transaction created or spent a Tokens / Vaults entry (N7).
    pub relevant: bool,
    /// The transaction spent an ACTIVE vault (RED-1..5 applied, M3).
    pub vault_spend: bool,
    /// The transaction is invalid under the module (`log.verdict` says why; BLK-1, U-21).
    pub invalid: bool,
}

/// [`process_tx`]'s result: the outcome, the writes to merge when it is valid, and the verified
/// bundles its held rules committed to `BundleLog[H]` (R12).
#[derive(Clone, Debug)]
pub struct TxEffect {
    /// The outcome.
    pub outcome: TxOutcome,
    /// The transaction's writes over the base it was evaluated on.
    pub writes: Writes,
    /// `CommitBundle`'s facts, commit order.
    pub bundles: Vec<BundleFacts>,
}

/// `ProcessTx`: one non-coinbase transaction at `height` over `base` (the running block state).
/// Total. The writes are returned, not applied; an invalid outcome's writes are to be discarded.
pub fn process_tx(
    base: &dyn YedRead,
    p: &Params,
    tx: &VaultTx,
    height: i64,
    cache: Option<&dyn SigCache>,
) -> TxEffect {
    let mut ev = Eval::new(base, p, height, cache);
    let outcome = ev.process(tx);
    TxEffect {
        outcome,
        bundles: ev.commits,
        writes: ev.st.into_writes(),
    }
}

/// The output scripts of a transaction, in order (`FindPayload`'s input).
fn output_scripts(tx: &VaultTx) -> Vec<&[u8]> {
    tx.outputs
        .iter()
        .map(|o| o.script_pubkey.as_slice())
        .collect()
}

impl Eval<'_, '_> {
    /// NOT-1: step one of an emergency claim. True iff the rule held and the notice was written.
    fn apply_notice(&mut self, tx: &VaultTx, n: &ClaimNotice, log: &mut TxLogRecord) -> bool {
        let p = self.p;
        let vault_out = n.vault_outpoint();
        let Some(vault) = self
            .st
            .vault(&vault_out)
            .filter(|v| v.status == VaultStatus::Active)
        else {
            return false;
        };
        let r = i64::from(n.ref_height);
        if !ref_height_in_window(p, self.h, r) || !self.armed(r) {
            return false;
        }
        let f = self.bundle(tx, r, &outpoint_selector(&vault_out), false);
        let Ok(v) = &f.verdict else {
            return false;
        };
        let Some(s) = self.snap(r) else {
            return false;
        };
        let c = price_combine(s.pmint(), s.pclaim(), v.a_mint, v.a_claim);
        let Some(p_emerg) = c.p_emerg else {
            return false;
        };
        if !is_underwater(
            vault.collateral_zat,
            Some(p_emerg),
            vault.minted_cents,
            p.emergency_ratio_bps,
        ) {
            return false;
        }
        // the reset attack: a standing notice is not replaced within its TTL
        if let Some(standing) = self.st.notice(&vault_out) {
            if self.h.saturating_sub(i64::from(standing.height))
                <= i64::from(p.emergency_notice_ttl)
            {
                return false;
            }
        }
        self.st.put_notice(
            vault_out,
            NoticeRecord {
                height: super::mint::h32(self.h),
                ref_height: super::mint::h32(r),
                p_emerg,
            },
        );
        self.commit_bundle(&f); // R12 (03/M-2): NOT-1 held
        log_bundle(log, Some(&f));
        log.notice = true;
        true
    }

    /// `ProcessTxImpl`.
    #[allow(clippy::too_many_lines)]
    pub(crate) fn process(&mut self, tx: &VaultTx) -> TxOutcome {
        let p = self.p;
        let h = self.h;
        let mut out = TxOutcome::default();
        out.log.height = super::mint::h32(h);
        out.log.verdict = verdict::NON_YELLOWBACK.to_owned();
        if tx.coinbase {
            return out; // TX-0: only the coinbase's scriptSig (the tag) is read
        }
        let txid: Hash32 = tx.txid;
        let mut totals = self.st.totals();
        let before = totals;
        let mut log = TxLogRecord {
            height: super::mint::h32(h),
            verdict: verdict::NON_YELLOWBACK.to_owned(),
            ..TxLogRecord::default()
        };

        // ---- inputs (IN-1, and the vaults IN-2 will close)
        let mut yed_in: Cents = 0;
        let mut bond_spent = false;
        let mut active: Vec<SpentVault> = Vec::new();
        let mut voids: Vec<SpentVault> = Vec::new();
        let mut intents: Vec<SpentIntent> = Vec::new();
        for (vin, input) in tx.inputs.iter().enumerate() {
            let prev = input.prevout;
            if let Some(tok) = self.st.token(&prev) {
                yed_in = yed_in.wrapping_add(tok.cents);
                log.spent_tokens.push(AssignedOutput {
                    outpoint: prev,
                    cents: tok.cents,
                    script_pub_key: tok.script_pub_key,
                });
                self.st.erase(YedKey::Token(prev));
            }
            if let Some(v) = self.st.vault(&prev) {
                let seen = |l: &[SpentVault]| l.iter().any(|s| s.outpoint == prev);
                if v.status == VaultStatus::Active && !seen(&active) {
                    active.push(SpentVault {
                        outpoint: prev,
                        record: v,
                    });
                } else if v.status == VaultStatus::Voided && !seen(&voids) {
                    voids.push(SpentVault {
                        outpoint: prev,
                        record: v,
                    });
                }
            }
            if let Some(ir) = self.st.intent(&prev) {
                if !intents.iter().any(|si| si.outpoint == prev) {
                    intents.push(SpentIntent {
                        outpoint: prev,
                        record: ir,
                        vin,
                    });
                }
            }
            // IN-2 (amended): a bond spend withdraws the attestor unless it is EJECTED
            if apply_bond_spend(&mut self.st, &prev, h).is_some() {
                bond_spent = true;
            }
        }
        log.yed_in = yed_in;
        log.verdict = verdict::OK.to_owned();
        // P4-b: the attestor set's acts on the mirror (after the bond spends)
        let set_act_refused = refused_attestor_set_act(tx, p);
        let join_refused = if set_act_refused {
            None
        } else {
            let st = &self.st;
            let bond_min = |rh: i64| bond_min_zat(st, p, rh);
            attestor_join_refused(st, tx, p, h, &bond_min)
        };
        let set_act = if set_act_refused || join_refused.is_some() {
            None
        } else {
            apply_set_act(&mut self.st, tx, p, h)
        };
        match set_act {
            Some(SetActEffect::Adopted) => log.tx_type = TxLogType::AttestorSetAct,
            Some(SetActEffect::Registered(seq)) => {
                log.tx_type = TxLogType::AttestorRegister;
                log.attestor_seq = seq;
            }
            Some(SetActEffect::Acted(seq)) => {
                log.tx_type = TxLogType::AttestorSetAct;
                log.attestor_seq = seq;
            }
            None => {}
        }
        let set_act_type = log.tx_type;

        // ---- outputs
        let scripts = output_scripts(tx);
        let fp: Option<FoundPayload> = find_payload(&scripts);
        let mut yed_outputs: BTreeSet<usize> = BTreeSet::new();
        let mut touched = !log.spent_tokens.is_empty()
            || !active.is_empty()
            || !voids.is_empty()
            || bond_spent
            || !intents.is_empty()
            || set_act.is_some();
        let fail = |mut log: TxLogRecord, out: &mut TxOutcome, v: &str| {
            log.verdict = v.to_owned();
            log.yed_out = 0;
            out.log = log;
            out.invalid = true;
        };
        if set_act_refused {
            log.tx_type = TxLogType::AttestorSetAct;
            fail(log, &mut out, verdict::ATTESTOR_SET_ACT);
            return out;
        }
        if let Some(v) = join_refused {
            log.tx_type = TxLogType::AttestorRegister;
            fail(log, &mut out, v);
            return out;
        }
        // focused review: a held YED act may carry liveness; its BUNDLE-1 inputs
        let mut liveness_held = false;
        let mut liveness_selector: Vec<u8> = Vec::new();
        let mut liveness_skip_vin0 = false;
        if let Some(first) = intents.first() {
            // U-23: a claim intent's release or cancel (one template input per transaction, S-1)
            if intents.len() != 1 || !active.is_empty() {
                fail(log, &mut out, verdict::INTENT_SPEND_MALFORMED);
                return out;
            }
            let first = first.clone();
            if let Err(v) = self.apply_intent_spend(
                tx,
                &first,
                fp.as_ref(),
                &mut log,
                &mut totals,
                &mut yed_outputs,
            ) {
                fail(log, &mut out, v);
                return out;
            }
            touched = true;
        } else if !active.is_empty() {
            // M3: a transaction spending an ACTIVE vault sees RED-1..5 only, whatever its payload
            log.tx_type = TxLogType::Redeem;
            out.vault_spend = true;
            if self.apply_vault_spend(
                tx,
                fp.as_ref(),
                &mut active,
                yed_in,
                &mut log,
                &mut totals,
                &mut yed_outputs,
            ) {
                let v = log.verdict.clone();
                fail(log, &mut out, &v);
                return out;
            }
            touched = true;
            if let (Some(Payload::Redeem(_)), Some(a)) =
                (fp.as_ref().map(|f| &f.payload), active.first())
            {
                liveness_held = true;
                liveness_selector = outpoint_selector(&a.outpoint);
                liveness_skip_vin0 = true;
            }
        } else if let Some(FoundPayload {
            payload: Payload::Mint(m),
            op_return_index,
        }) = fp.as_ref()
        {
            log.tx_type = TxLogType::Mint;
            if !self.apply_mint(tx, m, *op_return_index, &mut log, &mut totals) {
                let v = log.verdict.clone();
                fail(log, &mut out, &v); // §15.10: no VOID vault
                return out;
            }
            yed_outputs.insert(0);
            touched = true;
            liveness_held = true;
        } else if let Some(
            f @ FoundPayload {
                payload: Payload::Transfer(_) | Payload::Redeem(_),
                ..
            },
        ) = fp.as_ref()
        {
            log.tx_type = if matches!(f.payload, Payload::Transfer(_)) {
                TxLogType::Transfer
            } else {
                TxLogType::Redeem
            };
            if let Some(v) = self.apply_transfer(tx, f.payload.assignments(), yed_in, &mut log) {
                fail(log, &mut out, v); // TOK-PQ
                return out;
            }
        } else {
            // the v3 types: a holding rule writes its table and a TxLog entry; a failing one is
            // non-Yellowback for outputs
            let mut held = false;
            match fp.as_ref().map(|f| &f.payload) {
                Some(Payload::AttestorRegister(_)) => {
                    log.tx_type = TxLogType::AttestorRegister;
                    fail(log, &mut out, verdict::ATTESTOR_REGISTER_RETIRED); // P4-b
                    return out;
                }
                Some(Payload::ClaimNotice(n)) => {
                    log.tx_type = TxLogType::ClaimNotice;
                    held = self.apply_notice(tx, n, &mut log);
                    if held {
                        liveness_held = true;
                        liveness_selector = outpoint_selector(&n.vault_outpoint());
                    }
                }
                Some(Payload::Equivocation) => {
                    log.tx_type = TxLogType::Equivocation;
                    if let Some((ejected, evidence_seq)) = self.equivocation(tx) {
                        log.attestor_seq = ejected;
                        log.bundle_seqs.push(evidence_seq);
                        held = true;
                    }
                }
                Some(Payload::AttestorRevive(_)) => {
                    log.tx_type = TxLogType::AttestorRevive;
                    fail(log, &mut out, verdict::ATTESTOR_REVIVE_RETIRED); // P4-b
                    return out;
                }
                _ => {}
            }
            if held {
                touched = true;
            } else {
                log.tx_type = if set_act.is_some() {
                    set_act_type
                } else {
                    TxLogType::None
                };
                if yed_in > 0 {
                    log.verdict = verdict::BURNED.to_owned();
                }
            }
        }

        // ---- seats review B2: a member's attestation carried here is liveness
        if self.st.attestor_set().is_some() {
            let credits = {
                let all = self.st.attestors();
                let live = |seq: u16| mirror_live_member(&all, seq);
                let st = &self.st;
                let hash_at = |hh: i64| block_hash_at(st, p, hh);
                attestation_liveness(tx, p, h, Some(&live), Some(&hash_at), self.cache)
            };
            // a crediting bundle must ride a held YED act whose bundle passes the whole BUNDLE-1
            if !credits.is_empty() {
                let held_ok = liveness_held
                    && fp
                        .as_ref()
                        .and_then(|f| f.payload.ref_height())
                        .is_some_and(|r| {
                            let r = i64::from(r);
                            let st = &self.st;
                            let basis = super::lookups::selection_basis(st, p, r);
                            let hash_at = |hh: i64| block_hash_at(st, p, hh);
                            verify_tx_bundle(
                                tx,
                                p,
                                r,
                                &liveness_selector,
                                liveness_skip_vin0,
                                basis.as_ref(),
                                st,
                                &hash_at,
                                self.cache,
                            )
                            .1
                            .is_ok()
                        });
                if !held_ok {
                    fail(log, &mut out, verdict::LIVENESS_UNHELD);
                    return out;
                }
            }
            apply_liveness_credits(&mut self.st, &credits);
        }

        // ---- U-23: a YED-tagged V or I exists only as a rule above created it
        for (j, o) in tx.outputs.iter().enumerate() {
            let spk = &o.script_pubkey;
            if !yed_outputs.contains(&j)
                && (is_yed_vault_output(spk) || yed_intent_output(spk).is_some())
            {
                fail(log, &mut out, verdict::YED_TEMPLATE_OUTPUT);
                return out;
            }
        }

        // ---- IN-2 for VOID vaults (none is created since the vault upgrade)
        for s in &mut voids {
            s.record.status = VaultStatus::Closed;
            s.record.close_height = super::mint::h32(h);
            s.record.closing_txid = txid;
            s.record.unbacked = false;
            totals.void_vaults = totals.void_vaults.saturating_sub(1);
            totals.closed_vaults = totals.closed_vaults.wrapping_add(1);
            log.closed_vaults.push(s.outpoint);
        }

        // ---- IN-3 (a MINT's and a CLAIM_CANCEL's yedOut is not carried from its inputs, N19)
        let burn_out = if matches!(log.tx_type, TxLogType::Mint | TxLogType::ClaimCancel) {
            0
        } else {
            log.yed_out
        };
        let burned = yed_in.wrapping_sub(burn_out);
        log.burned = burned;
        totals.supply_cents = totals.supply_cents.wrapping_sub(burned);
        for s in &mut active {
            s.record.burned_cents = burned;
            self.st.put_vault(s.outpoint, s.record.clone());
            let nk = YedKey::Notice(s.outpoint);
            if self.st.has(&nk) {
                self.st.erase(nk); // IN-2: the vault left ACTIVE
            }
        }
        for s in &mut voids {
            s.record.burned_cents = burned;
            self.st.put_vault(s.outpoint, s.record.clone());
        }
        if touched {
            if totals != before || !self.st.has(&YedKey::Totals) {
                self.st.put_totals(totals);
            }
            self.st.put_txlog(txid, log.clone());
            out.relevant = true;
        } else {
            log.verdict = verdict::NON_YELLOWBACK.to_owned();
        }
        out.log = log;
        out
    }

    /// EQV-1 on the mirror (`ApplyEquivocation`): `(ejected seq, the evidence's seq)`.
    fn equivocation(&mut self, tx: &VaultTx) -> Option<(u16, u16)> {
        let p = self.p;
        // the block hashes are read before the mirror is written (they are snapshots below H)
        let hashes: std::collections::BTreeMap<i64, Option<Hash32>> = {
            let e = crate::attest::equivocation::equivocation_evidence(tx, p)?;
            let c = i64::from(e.attestation().cited_height);
            [(c, block_hash_at(&self.st, p, c))].into_iter().collect()
        };
        let hash_at = |hh: i64| hashes.get(&hh).copied().flatten();
        apply_equivocation(&mut self.st, tx, p, self.h, &hash_at)
    }
}
