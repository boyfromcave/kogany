// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

//! Liveness by attestation (seats review B2, bounded at the re-review): ycash6
//! `src/yellowback/state.cpp` `AttestationLiveness` at `65cb4ae0f`. The primitive's liveness hook
//! ([`super::hooks::yed_liveness`]) and the module's mirror ([`super::mirror`]) call it over the
//! same members, so in a valid block both credit the same `(seq, citedHeight)` pairs.

use std::collections::BTreeMap;

use kogany_vault::state::VaultTx;
use kogany_vault::{Hash32, PubKeyBytes};

use super::bundle::{decode_bundle, extract_bundle, verify_bundle, BundleLimits, SigCache};
use super::equivocation::output_scripts;
use crate::codecs::payload::{find_payload, PayloadType};
use crate::params::Params;

/// A seq's live member (`liveMember`): its key and `lastAct`; `None` = not a live member of the
/// attestor set.
pub type LiveMember<'a> = &'a dyn Fn(u16) -> Option<(PubKeyBytes, i64)>;

/// `AttestationLiveness`: for a MINT, CLAIM_NOTICE or REDEEM payload (vin 0 skipped for a
/// REDEEM), its bundle credits its signers only when it passes BUNDLE-1 at the payload's
/// `refHeight` R in everything but the selection — the bundle's own seqs are the selected list —
/// with every seq naming a live member (checked before any signature or cache line), every
/// signature verifying under that member's key, and `R < height`, `height - R <= REF_WINDOW` (no
/// replay of an old public attestation). Any failure credits nobody. Result: `(seq, citedHeight)`
/// for each signer whose cited height exceeds its `lastAct`, in bundle order.
pub fn attestation_liveness(
    tx: &VaultTx,
    p: &Params,
    height: i64,
    live_member: Option<LiveMember<'_>>,
    block_hash_at: Option<&dyn Fn(i64) -> Option<Hash32>>,
    cache: Option<&dyn SigCache>,
) -> Vec<(u16, i64)> {
    let (Some(live_member), Some(block_hash_at)) = (live_member, block_hash_at) else {
        return Vec::new();
    };
    let Some(fp) = find_payload(&output_scripts(tx)) else {
        return Vec::new();
    };
    let t = fp.payload.payload_type();
    if !matches!(
        t,
        PayloadType::Mint | PayloadType::ClaimNotice | PayloadType::Redeem
    ) {
        return Vec::new();
    }
    let skip_vin0 = t == PayloadType::Redeem;
    let Ok((bytes, _)) = extract_bundle(tx, p.bundle_carrier, skip_vin0, &[]) else {
        return Vec::new();
    };
    let limits = BundleLimits::from_params(p);
    let Some(bundle) = decode_bundle(&bytes, limits.bundle_max) else {
        return Vec::new();
    };
    if bundle.atts.is_empty() {
        return Vec::new();
    }
    // every seq must name a live member before any signature is checked
    let mut members: BTreeMap<u16, (PubKeyBytes, i64)> = BTreeMap::new();
    let mut seqs = Vec::with_capacity(bundle.atts.len());
    for a in &bundle.atts {
        let Some(m) = live_member(a.seq) else {
            return Vec::new();
        };
        members.insert(a.seq, m);
        seqs.push(a.seq);
    }
    let Some(r) = fp.payload.ref_height().map(i64::from) else {
        return Vec::new();
    };
    if r < 0 || r >= height || height.saturating_sub(r) > i64::from(p.ref_window) {
        return Vec::new();
    }
    let pubkey_of = |seq: u16| members.get(&seq).map(|(k, _)| *k);
    let Ok(c) = verify_bundle(
        tx,
        p.bundle_carrier,
        skip_vin0,
        &[],
        r,
        &seqs,
        &limits,
        Some(&pubkey_of),
        Some(block_hash_at),
        cache,
    ) else {
        return Vec::new();
    };
    c.iter()
        .filter_map(|a| {
            let cited = i64::from(a.cited_height);
            let (_, last_act) = members.get(&a.seq)?;
            (cited > *last_act).then_some((a.seq, cited))
        })
        .collect()
}
