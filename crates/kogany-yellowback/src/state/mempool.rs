// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

//! The mempool-time check (W5-d2; ycash6 `src/yellowback/index.cpp` `MempoolCheckInner` at
//! `65cb4ae0f`, K7, N5, N6): whether the module admits a transaction to the mempool at the next
//! height, and if not, why.
//!
//! This is the pure half of the C++ `YellowbackIndex::MempoolCheckReason`. The index's own
//! guards stay with the index (W5-e / W6-c): a stopped index admits everything (`None`), an
//! unhealthy one refuses with [`UNHEALTHY`], and a storage failure during the check marks the
//! index unhealthy and refuses with [`UNHEALTHY`]. The caller also picks the parameter set
//! (`ParamsAt(tip + 1)`, [`crate::params::select_params`]).

use kogany_vault::act::{decode_act, is_act_output};
use kogany_vault::state::VaultTx;
use kogany_vault::Hash32;

use super::lookups::{is_yed_vault_output, yed_intent_output};
use super::records::VaultStatus;
use super::tx::process_tx;
use super::verdict;
use super::view::YedRead;
use crate::attest::bundle::SigCache;
use crate::attest::mirror::refused_attestor_set_act;
use crate::codecs::payload::{find_payload, Payload};
use crate::params::Params;

/// The reason of a spend of an ACTIVE vault whose `nExpiryHeight` does not bound it within
/// RED-1's window (MP-1, N5).
pub const MEMPOOL_EXPIRY: &str = "mempool-expiry";

/// The index's refusal while it cannot evaluate the module (the caller returns it; never this
/// function).
pub const UNHEALTHY: &str = "yellowback-unhealthy";

/// `MempoolCheckInner`: `None` = admitted, else the reason — the module's verdict for a
/// transaction it makes invalid (the node reports `mempool-check-failed:<verdict>`, K7), or
/// [`MEMPOOL_EXPIRY`].
///
/// `base` is the state at the tip, `next_height` the tip's height + 1, `p` the parameter set at
/// `next_height`, `expiry_height` the transaction's `nExpiryHeight` (0 = none). The rules read
/// `Snapshots[ref <= next_height - 1]` only, so no SNAP is computed (N6, audit A-1): the
/// transaction is evaluated by [`process_tx`] alone, on writes that are discarded. `cache` is
/// the node's signature cache (RED-1's bundle fills it, W8). Total.
pub fn mempool_check_reason(
    base: &dyn YedRead,
    p: &Params,
    next_height: i64,
    tx: &VaultTx,
    expiry_height: u32,
    cache: Option<&dyn SigCache>,
) -> Option<String> {
    if tx.coinbase {
        return None;
    }
    if next_height < i64::from(p.start_height) {
        return None;
    }
    // Owner 2026-10-11: a SET_REMOVE or SET_WINDDOWN of the attestor set is invalid (structural;
    // an act is neither a payload nor a YED template, so it is checked before the relevance filter)
    if refused_attestor_set_act(tx, p) {
        return Some(verdict::ATTESTOR_SET_ACT.to_owned());
    }
    // Relevance in O(inputs + outputs) (N6): a payload, a token / vault / intent input, a
    // YED-tagged template output, or an act on the attestor set.
    let found = find_payload(
        &tx.outputs
            .iter()
            .map(|o| o.script_pubkey.as_slice())
            .collect::<Vec<_>>(),
    );
    let mut relevant = found.is_some();
    let mut spends_active = false;
    for i in &tx.inputs {
        let v = base.vault(&i.prevout);
        if v.as_ref().is_some_and(|v| v.status == VaultStatus::Active) {
            spends_active = true;
        }
        if v.is_some() || base.token(&i.prevout).is_some() || base.intent(&i.prevout).is_some() {
            relevant = true;
        }
    }
    if tx.outputs.iter().any(|o| {
        is_yed_vault_output(&o.script_pubkey) || yed_intent_output(&o.script_pubkey).is_some()
    }) {
        relevant = true;
    }
    // seats re-review: an act on the attestor set (a SET_JOIN below BondMinZat is
    // attestor-bond-below-min)
    let set_id = Hash32(p.attestor_set_id);
    if tx.outputs.iter().any(|o| {
        is_act_output(&o.script_pubkey)
            && decode_act(&o.script_pubkey).is_ok_and(|a| a.body.target_set() == Some(set_id))
    }) {
        relevant = true;
    }
    if !relevant {
        return None;
    }
    // The module's validity at the next height, exactly as the template filter dry-runs a
    // candidate; the verdict first (K7), the expiry bound second.
    let effect = process_tx(base, p, tx, next_height, cache);
    if effect.outcome.invalid {
        return Some(effect.outcome.log.verdict);
    }
    if !spends_active {
        return None;
    }
    // MP-1 (N5): nExpiryHeight != 0 and <= refHeight + REF_WINDOW, so the spend expires from
    // every mempool before RED-1's window closes.
    let ref_height = match found.map(|f| f.payload) {
        Some(Payload::Redeem(r)) => i64::from(r.ref_height),
        _ => -1,
    };
    if expiry_height == 0
        || ref_height < 0
        || i64::from(expiry_height) > ref_height.saturating_add(i64::from(p.ref_window))
    {
        return Some(MEMPOOL_EXPIRY.to_owned());
    }
    None
}
