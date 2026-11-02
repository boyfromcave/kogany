// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

//! The YED module's attestor-set hooks on the primitive side (U-25, P4-b, seats review B2): ycash6
//! `src/yellowback/module.cpp` `AdoptedSet`, `Ejections`, `CheckBlock`, `Displace` and `Liveness`
//! at `65cb4ae0f`, over the primitive's set state ([`StateRead`]).
//!
//! These read the vault primitive's members of the attestor set (key order, the primitive's
//! records), where the mirror ([`super::mirror`]) reads the module's own `Attestors` records:
//! the two pick the same member because both apply the same rules to the same transactions.
//! The module's registration (W5-f) implements [`kogany_vault::state::Module`] by calling these
//! with the parameter set in force at the height.

use kogany_vault::act::SetJoinBody;
use kogany_vault::state::{
    MemberStatus, ModuleContext, SetRecord, StateRead, VaultReject, VaultTx,
};
use kogany_vault::PubKeyBytes;

use super::bundle::SigCache;
use super::equivocation::{equivocated_by, equivocation_evidence};
use super::liveness::attestation_liveness;
use super::mirror::{adopts_set, attestor_set_id, refused_attestor_set_act, BAD_ATTESTOR_SET_ACT};
use super::seats::{eviction_victim, SeatCandidate};
use crate::params::Params;

/// `AdoptedSet`: the attestor set's record when it has the shape the module adopts
/// ([`adopts_set`]); `None` = the module has no set (its hooks do nothing).
pub fn adopted_set(p: &Params, state: &dyn StateRead) -> Option<SetRecord> {
    let s = state.set(&attestor_set_id(p)?)?;
    adopts_set(&s.params, p).then_some(s)
}

/// The member's bond is recorded and not frozen.
fn bond_unfrozen(state: &dyn StateRead, m: &kogany_vault::state::MemberRecord) -> bool {
    state.bond(&m.bond_outpoint).is_some_and(|b| !b.frozen)
}

/// `Module::Ejections` (EQV-1 on the primitive side): an EQUIVOCATION transaction whose evidence
/// (cited height in `[START_HEIGHT, height)`, block hash known) verifies under a member key of
/// the attestor set names that member — the first in key order whose bond is recorded and not
/// frozen. Empty without a block-hash provider.
pub fn yed_ejections(p: &Params, tx: &VaultTx, ctx: &ModuleContext<'_>) -> Vec<PubKeyBytes> {
    let (Some(set_id), Some(hashes)) = (attestor_set_id(p), ctx.block_hash_at) else {
        return Vec::new();
    };
    let Some(e) = equivocation_evidence(tx, p) else {
        return Vec::new();
    };
    let cited = i64::from(e.attestation().cited_height);
    if cited >= ctx.height {
        return Vec::new();
    }
    let Some(block_hash) = hashes(cited) else {
        return Vec::new();
    };
    ctx.state
        .members(&set_id)
        .into_iter()
        .find(|(key, m)| {
            bond_unfrozen(ctx.state, m) && equivocated_by(&e, key, &block_hash, &set_id)
        })
        .map(|(key, _)| vec![key])
        .unwrap_or_default()
}

/// `Module::CheckBlock`: a block holding a refused act of the attestor set
/// ([`refused_attestor_set_act`]) is invalid (`bad-yellowback-attestor-set-act`).
pub fn yed_check_block(p: &Params, txs: &[VaultTx]) -> Result<(), VaultReject> {
    if txs.iter().any(|tx| refused_attestor_set_act(tx, p)) {
        return Err(VaultReject::Module(BAD_ATTESTOR_SET_ACT.to_owned()));
    }
    Ok(())
}

/// `Module::Displace`: a SET_JOIN into the full adopted attestor set displaces the
/// [`eviction_victim`] over its ACTIVE members with an unfrozen bond (the mirror withdraws the
/// same member's record). `None` refuses the join, as into any full set.
pub fn yed_displace(
    p: &Params,
    tx: &VaultTx,
    join: &SetJoinBody,
    ctx: &ModuleContext<'_>,
) -> Option<PubKeyBytes> {
    if Some(join.set_id) != attestor_set_id(p) {
        return None;
    }
    let bond = tx.outputs.get(usize::from(join.bond_vout))?;
    let s = adopted_set(p, ctx.state)?;
    let members: Vec<SeatCandidate> = ctx
        .state
        .members(&join.set_id)
        .into_iter()
        .filter(|(_, m)| m.status == MemberStatus::Active && !m.bond_frozen)
        .filter(|(_, m)| bond_unfrozen(ctx.state, m))
        .map(|(key, m)| SeatCandidate {
            key,
            bond_zat: m.bond_value,
            join_height: m.join_height,
            last_act: m.last_act,
        })
        .collect();
    eviction_victim(
        &members,
        ctx.height,
        bond.value,
        i64::from(s.params.liveness_window),
        p,
    )
}

/// `Module::Liveness`: [`attestation_liveness`] over the ACTIVE members of the adopted attestor
/// set with an unfrozen bond, seq `s` being the member whose `join_ordinal` is `s + 1`; the
/// credits as `(member key, citedHeight)`. Through the node's signature cache when given (BUNDLE-1
/// already verified the same signatures under the same keys).
pub fn yed_liveness(
    p: &Params,
    tx: &VaultTx,
    ctx: &ModuleContext<'_>,
    cache: Option<&dyn SigCache>,
) -> Vec<(PubKeyBytes, i64)> {
    let Some(hashes) = ctx.block_hash_at else {
        return Vec::new();
    };
    let Some(set_id) = attestor_set_id(p) else {
        return Vec::new();
    };
    if adopted_set(p, ctx.state).is_none() {
        return Vec::new();
    }
    let all = ctx.state.members(&set_id);
    let live_member = |seq: u16| -> Option<(PubKeyBytes, i64)> {
        let ordinal = u32::from(seq).saturating_add(1);
        let (key, m) = all.iter().find(|(_, m)| m.join_ordinal == ordinal)?;
        let ok = m.status == MemberStatus::Active && !m.bond_frozen && bond_unfrozen(ctx.state, m);
        ok.then_some((*key, m.last_act))
    };
    let hash_at = |h: i64| hashes(h);
    attestation_liveness(tx, p, ctx.height, Some(&live_member), Some(&hash_at), cache)
        .into_iter()
        .filter_map(|(seq, cited)| live_member(seq).map(|(key, _)| (key, cited)))
        .collect()
}
