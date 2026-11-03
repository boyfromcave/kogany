//! The invariant audit of the set state (C++ `vault::AuditLockedValue`, ycash6
//! `src/vault/node.cpp`): every set's `locked_value` re-derived as the sum of the values of the
//! unspent V outputs in the template-output index whose set is that set, in one read-only pass.

use std::collections::BTreeMap;

use super::records::TemplateOutKind;
use super::view::SetState;
use crate::bytes::SetId;
use crate::template::{match_vault, Shape};

/// One set's locked value, stored and re-derived.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SetValueAudit {
    /// The set.
    pub set_id: SetId,
    /// Its record's `locked_value`.
    pub stored: i64,
    /// The sum over its unspent V outputs.
    pub derived: i64,
}

fn hex(id: &SetId) -> String {
    super::hash::display_hex(id)
}

/// One line per mismatch (empty = consistent), and every set's pair, in set-id order.
pub fn audit_locked_value(st: &SetState) -> (Vec<String>, Vec<SetValueAudit>) {
    let mut mismatches = Vec::new();
    let mut derived: BTreeMap<SetId, i64> = BTreeMap::new();
    for (op, r) in &st.template_outs {
        if r.kind != TemplateOutKind::Vault {
            continue; // an intent's value left its set's locked value at the unlock
        }
        let Shape::Match(v) = match_vault(&r.script_pubkey) else {
            mismatches.push(format!(
                "vault {}:{}: its indexed scriptPubKey is not a V",
                hex(&op.txid),
                op.n
            ));
            continue;
        };
        let e = derived.entry(v.set_id).or_insert(0);
        *e = e.wrapping_add(r.value);
    }
    let mut sets = Vec::new();
    for (id, s) in &st.sets {
        let a = SetValueAudit {
            set_id: *id,
            stored: s.locked_value,
            derived: derived.remove(id).unwrap_or(0),
        };
        if a.stored != a.derived {
            mismatches.push(format!(
                "set {}: lockedValue stored {}, unspent V outputs {}",
                hex(id),
                a.stored,
                a.derived
            ));
        }
        sets.push(a);
    }
    for (id, d) in derived {
        mismatches.push(format!(
            "set {}: no set record, unspent V outputs {}",
            hex(&id),
            d
        ));
    }
    (mismatches, sets)
}
