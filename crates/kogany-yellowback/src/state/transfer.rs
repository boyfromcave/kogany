// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

//! XFER-1..3 (ycash6 `state.cpp` `ApplyTransfer`) for a TRANSFER, or a REDEEM payload that
//! spends no ACTIVE vault. A failing XFER clause is not invalid: everything burns (the Runes
//! "cenotaph" rule). Only TOK-PQ — from the Falcon height an assignment that would receive YED
//! must be a Falcon holder — makes the transaction invalid (refused, not burned).

use kogany_vault::state::VaultTx;
use kogany_vault::OutPoint;

use super::eval::Eval;
use super::mint::h32;
use super::records::{AssignedOutput, TokenRecord, TxLogRecord};
use super::verdict;
use crate::codecs::payload::Assignment;
use crate::codecs::script::holder_allowed;
use crate::params::Cents;

impl Eval<'_, '_> {
    /// `ApplyTransfer`: `None`, or TOK-PQ's verdict (the transaction is then invalid).
    pub(crate) fn apply_transfer(
        &mut self,
        tx: &VaultTx,
        assignments: &[Assignment],
        yed_in: Cents,
        log: &mut TxLogRecord,
    ) -> Option<&'static str> {
        let p = self.p;
        let total: Cents = assignments
            .iter()
            .fold(0i64, |s, a| s.saturating_add(i64::from(a.cents)));
        let mut v = verdict::OK;
        if assignments.iter().any(|a| {
            let c = i64::from(a.cents);
            c < p.min_output || c > p.max_output
        }) {
            v = verdict::BAD_TRANSFER_ASSIGNMENT; // XFER-1
        }
        if v == verdict::OK && total > yed_in {
            v = verdict::TRANSFER_OVER_ASSIGNED; // XFER-2
        }
        if v == verdict::OK && yed_in <= 0 {
            v = verdict::TRANSFER_NO_YED_INPUT; // XFER-3
        }
        if v != verdict::OK {
            log.verdict = v.to_owned(); // everything burns (cenotaph)
            log.yed_out = 0;
            return None;
        }
        // TOK-PQ: only the assignments that actually receive YED are bound
        for a in assignments {
            let ok = tx
                .outputs
                .get(usize::from(a.vout))
                .is_some_and(|o| holder_allowed(p, self.h, &o.script_pubkey));
            if !ok {
                return Some(verdict::BAD_YED_HOLDER);
            }
        }
        self.write_assignments(tx, assignments, log);
        log.yed_out = total;
        log.verdict = if total < yed_in {
            verdict::BURNED
        } else {
            verdict::OK
        }
        .to_owned();
        None
    }

    /// Writes one token per assignment at `txid:vout` and logs it (XFER and RED alike).
    pub(crate) fn write_assignments(
        &mut self,
        tx: &VaultTx,
        assignments: &[Assignment],
        log: &mut TxLogRecord,
    ) {
        for a in assignments {
            let out = OutPoint {
                txid: tx.txid,
                n: u32::from(a.vout),
            };
            let o = tx.outputs.get(usize::from(a.vout));
            let tok = TokenRecord {
                cents: i64::from(a.cents),
                n_value: o.map_or(0, |o| o.value),
                script_pub_key: o.map(|o| o.script_pubkey.clone()).unwrap_or_default(),
                height: h32(self.h),
            };
            log.assigned.push(AssignedOutput {
                outpoint: out,
                cents: tok.cents,
                script_pub_key: tok.script_pub_key.clone(),
            });
            self.st.put_token(out, tok);
        }
    }
}
