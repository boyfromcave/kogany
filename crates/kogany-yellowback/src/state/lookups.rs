// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

//! The §3.7 lookups every rule reads (ycash6 `state.cpp` at `65cb4ae0f`: `TagAt`,
//! `JudgementAt`, `BlockHashAt`, `SnapshotAt`, `EligiblePayees`, `ArmedAt`, `BondMinZat`,
//! `CancelsRequired`, `P2PKHKey`, `IsYedVaultOutput` / `IsYedIntentOutput`). Totality (K1, M1):
//! a lookup that misses is `None`, and a rule reading it is false.

use kogany_vault::template::{parse_intent, parse_vault, IntentParams};
use kogany_vault::{Hash32, OutPoint};

use super::records::{Judgement, Snapshot, TagRecord, VaultRecord};
use super::view::{attestor_of, attestor_set_of, attestors_of, bond_seq_of, next_seq_of, YedRead};
use crate::attest::registry::{AttestorRecord, AttestorSetRecord, RegistryRead};
use crate::attest::seats::SelectionBasis;
use crate::codecs::script::YED_TAG;
use crate::math::bond_min_from_collateral_zat;
use crate::params::{Amount, Params};

/// A height the stored tables can key (`0..=u32::MAX`).
fn key_height(h: i64) -> Option<u32> {
    u32::try_from(h).ok()
}

/// `TagAt`: `Tags[h]` for `h >= START_HEIGHT` (nothing below it is read).
pub fn tag_at(r: &dyn YedRead, p: &Params, h: i64) -> Option<TagRecord> {
    if h < i64::from(p.start_height) {
        return None;
    }
    r.tag(key_height(h)?)
}

/// `JudgementAt`: `Judgements[h]` for `h >= START_HEIGHT`.
pub fn judgement_at(r: &dyn YedRead, p: &Params, h: i64) -> Option<Judgement> {
    if h < i64::from(p.start_height) {
        return None;
    }
    r.judgement(key_height(h)?)
}

/// `SnapshotAt`: the virtual snapshot below `START_HEIGHT`, the stored record at or above it,
/// `None` when missing.
pub fn snapshot_at(r: &dyn YedRead, p: &Params, h: i64) -> Option<Snapshot> {
    if h < i64::from(p.start_height) {
        return Some(Snapshot::virtual_snapshot());
    }
    r.snapshot(key_height(h)?)
}

/// `BlockHashAt`: `Snapshots[h].blockHash` for a stored snapshot at `h >= START_HEIGHT` whose
/// hash is not null (BUNDLE-1, EQV-1, CAN-2).
pub fn block_hash_at(r: &dyn YedRead, p: &Params, h: i64) -> Option<Hash32> {
    if h < i64::from(p.start_height) {
        return None;
    }
    let s = r.snapshot(key_height(h)?)?;
    (s.block_hash != Hash32::ZERO).then_some(s.block_hash)
}

/// What `Selected(R, ·)` reads of `Snapshots[R]`; `None` when R is below the start height or the
/// snapshot is missing.
pub fn selection_basis(r: &dyn YedRead, p: &Params, h: i64) -> Option<SelectionBasis> {
    if h < i64::from(p.start_height) {
        return None;
    }
    let s = r.snapshot(key_height(h)?)?;
    Some(SelectionBasis {
        block_hash: s.block_hash,
        seated: s.seated,
        pinned_seqs: s.pinned_seqs,
        attest: s.attest,
    })
}

/// `EligiblePayees` E(R) (FEE-2): the payout keys of the quote tags in
/// `(R - PAYEE_WINDOW, R]`, height order, deduplicated, minus `Snapshots[R].pinnedKeys` (PIN-1);
/// empty = FEE-0.
pub fn eligible_payees(r: &dyn YedRead, p: &Params, ref_height: i64) -> Vec<[u8; 20]> {
    let pinned: Vec<[u8; 20]> = if ref_height >= i64::from(p.start_height) {
        key_height(ref_height)
            .and_then(|h| r.snapshot(h))
            .map(|s| s.pinned_keys)
            .unwrap_or_default()
    } else {
        Vec::new()
    };
    let lo = ref_height
        .saturating_sub(i64::from(p.payee_window))
        .saturating_add(1)
        .max(i64::from(p.start_height));
    let mut keys: Vec<[u8; 20]> = Vec::new();
    let mut h = lo;
    while h <= ref_height {
        if let Some(t) = tag_at(r, p, h).filter(TagRecord::is_quote) {
            if !pinned.contains(&t.payout_key) && !keys.contains(&t.payout_key) {
                keys.push(t.payout_key);
            }
        }
        h = h.saturating_add(1);
    }
    keys
}

/// `ArmedAt`: `Snapshots[R].attest` is ARMED and the set's `ATTEST_REQUIRED` (W15).
pub fn armed_at(r: &dyn YedRead, p: &Params, ref_height: i64) -> bool {
    snapshot_at(r, p, ref_height).is_some_and(|s| p.is_armed(s.attest.is_armed()))
}

/// `BondMinZat` (D-Q-30): the bond floor of a SET_JOIN in block `register_height`, from
/// `Snapshots[register_height - 1].collateralZat` (a missing or virtual snapshot counts zero).
pub fn bond_min_zat(r: &dyn YedRead, p: &Params, register_height: i64) -> Amount {
    let c = snapshot_at(r, p, register_height.saturating_sub(1)).map_or(0, |s| s.collateral_zat);
    bond_min_from_collateral_zat(c, p)
}

/// CAN-2's `q`: the position's recent cancels, 0 once `CANCEL_QUIET` has passed since its last.
pub fn cancel_q(v: &VaultRecord, p: &Params, h: i64) -> i64 {
    if h.saturating_sub(i64::from(v.last_cancel_height)) < i64::from(p.cancel_quiet) {
        i64::from(v.cancel_count)
    } else {
        0
    }
}

/// `CancelsRequired` (CAN-2): `min(q + 1, max(1, CANCEL_SIGNERS_MAX))` distinct current members.
pub fn cancels_required(v: &VaultRecord, p: &Params, h: i64) -> i64 {
    cancel_q(v, p, h)
        .saturating_add(1)
        .min(i64::from(p.cancel_signers_max.max(1)))
}

/// `P2PKHKey`: the key hash of `OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG`.
pub fn p2pkh_key(s: &[u8]) -> Option<[u8; 20]> {
    match s {
        [0x76, 0xa9, 20, key @ .., 0x88, 0xac] => <[u8; 20]>::try_from(key).ok(),
        _ => None,
    }
}

/// `IsYedVaultOutput` (U-23): a YED-tagged V.
pub fn is_yed_vault_output(spk: &[u8]) -> bool {
    parse_vault(spk).is_some_and(|v| v.tag == YED_TAG)
}

/// `IsYedIntentOutput` (U-23): a YED-tagged I, with its parameters.
pub fn yed_intent_output(spk: &[u8]) -> Option<IntentParams> {
    parse_intent(spk).filter(|i| i.tag == YED_TAG)
}

/// The attest module's [`RegistryRead`] over any [`YedRead`] (read-only).
#[derive(Clone, Copy)]
pub struct RegistryView<'a>(pub &'a dyn YedRead);

impl RegistryRead for RegistryView<'_> {
    fn attestor(&self, seq: u16) -> Option<AttestorRecord> {
        attestor_of(self.0, seq)
    }
    fn attestors(&self) -> Vec<(u16, AttestorRecord)> {
        attestors_of(self.0)
    }
    fn attestor_set(&self) -> Option<AttestorSetRecord> {
        attestor_set_of(self.0)
    }
    fn next_seq(&self) -> u16 {
        next_seq_of(self.0)
    }
    fn bond_seq(&self, bond: &OutPoint) -> Option<u16> {
        bond_seq_of(self.0, bond)
    }
}
