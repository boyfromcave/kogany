// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

//! The attestor registry as the YED module mirrors it from `attestorSetId`'s set acts (P4-b):
//! ycash6 `src/yellowback/state.cpp` at `65cb4ae0f` — `RefusedAttestorSetAct`,
//! `AttestorJoinRefused`, `ApplySetAct`, the IN-2 bond spend, `ApplyEquivocation`,
//! `LatestRecord`, `CurrentMemberSeq` and the mirror's liveness credit.
//!
//! The module applies the set's acts to its own `Attestors` records from the transactions
//! themselves (the primitive has validated them: a block whose act fails is invalid before the
//! module sees it), so the YED index replays without reading the vault database. Every join
//! gets the next seq, so a key that rejoins gets a new seq; a key's *newest* record is the one
//! that mirrors the set's current member record.
//!
//! The state machine (W5-d) calls these from its transaction pass in the C++ order: bond spends
//! (inputs) → [`refused_attestor_set_act`] → [`attestor_join_refused`] → [`apply_set_act`] →
//! the outputs' rules ([`apply_equivocation`] for an EQUIVOCATION payload) → the liveness credit
//! ([`mirror_live_member`], [`super::attestation_liveness`], [`apply_liveness_credits`]); it
//! writes the TxLog entry from the returned effects.

use kogany_vault::act::{
    act_fields_valid, act_msg, decode_act, encode_payload, is_act_output, recover_sig, set_sig_msg,
    ActBody,
};
use kogany_vault::state::VaultTx;
use kogany_vault::{Hash32, OutPoint, PubKeyBytes};

use super::equivocation::{equivocated_by, equivocation_evidence};
use super::registry::{
    AttestorRecord, AttestorSetRecord, AttestorStatus, RegistryRead, RegistryWrite,
    ATTESTOR_FLAG_EVICTED,
};
use super::seats::{eviction_victim, BondMinAt, SeatCandidate};
use crate::params::Params;

/// `verdict::ATTESTOR_SET_ACT`: a SET_REMOVE or SET_WINDDOWN of the attestor set.
pub const ATTESTOR_SET_ACT: &str = "attestor-set-act";
/// `verdict::ATTESTOR_BOND_BELOW_MIN`: a SET_JOIN of the attestor set below `BondMinZat`.
pub const ATTESTOR_BOND_BELOW_MIN: &str = "attestor-bond-below-min";
/// `verdict::LIVENESS_UNHELD`: a bundle that credits liveness on a transaction that is not a held
/// YED act, or fails BUNDLE-1.
pub const LIVENESS_UNHELD: &str = "liveness-unheld";
/// `verdict::ATTESTOR_SEQ_EXHAUSTED`: a SET_JOIN once the u16 seq space is used up.
pub const ATTESTOR_SEQ_EXHAUSTED: &str = "attestor-seq-exhausted";
/// The primitive-side reject of [`refused_attestor_set_act`] in a block (`Module::CheckBlock`).
pub const BAD_ATTESTOR_SET_ACT: &str = "bad-yellowback-attestor-set-act";

/// The network's attestor set id, `None` when unset (YED off).
pub fn attestor_set_id(p: &Params) -> Option<Hash32> {
    let id = Hash32(p.attestor_set_id);
    (id != Hash32::ZERO).then_some(id)
}

/// The first act output of a transaction (the C++ loops stop at the first `IsActOutput`).
fn first_act_output(tx: &VaultTx) -> Option<&[u8]> {
    tx.outputs
        .iter()
        .map(|o| o.script_pubkey.as_slice())
        .find(|s| is_act_output(s))
}

/// `RefusedAttestorSetAct` (2026-10-11: the attestor set is open and never shrinks by vote): the
/// transaction's act is a SET_WINDDOWN of the attestor set, or a SET_REMOVE of it other than a
/// member's own exit (burn 0, exactly one signature, recovering over `actMsg(P, vin[0].prevout)`
/// to the removed key). An act that does not decode is the primitive's to refuse: false.
pub fn refused_attestor_set_act(tx: &VaultTx, p: &Params) -> bool {
    let Some(set_id) = attestor_set_id(p) else {
        return false;
    };
    let Some(spk) = first_act_output(tx) else {
        return false;
    };
    let Ok(act) = decode_act(spk) else {
        return false;
    };
    if act.body.target_set() != Some(set_id) {
        return false;
    }
    match &act.body {
        ActBody::WindDown(_) => true,
        ActBody::Remove(r) => {
            let own_exit = r.burn == 0
                && match (act.sigs.as_slice(), tx.inputs.first()) {
                    ([sig], Some(vin0)) => {
                        recover_sig(&act_msg(&encode_payload(&act.body), &vin0.prevout), sig)
                            .is_some_and(|signer| signer == r.member_key)
                    }
                    _ => false,
                };
            !own_exit
        }
        _ => false,
    }
}

/// `AttestorJoinRefused`: a well-formed SET_JOIN of the adopted attestor set the module makes
/// invalid — the u16 seq space is used up ([`ATTESTOR_SEQ_EXHAUSTED`]), or its bond is below
/// `BondMinZat(height)` ([`ATTESTOR_BOND_BELOW_MIN`], seats re-review). `None` otherwise
/// (including every act the primitive refuses anyway).
pub fn attestor_join_refused(
    reg: &dyn RegistryRead,
    tx: &VaultTx,
    p: &Params,
    height: i64,
    bond_min_at: BondMinAt<'_>,
) -> Option<&'static str> {
    let set_id = attestor_set_id(p)?;
    reg.attestor_set()?;
    let act = decode_act(first_act_output(tx)?).ok()?;
    if !act_fields_valid(&act) {
        return None;
    }
    let ActBody::Join(j) = act.body else {
        return None;
    };
    if j.set_id != set_id {
        return None;
    }
    let bond = tx.outputs.get(usize::from(j.bond_vout))?;
    if reg.attestor(reg.next_seq()).is_some() {
        return Some(ATTESTOR_SEQ_EXHAUSTED);
    }
    (bond.value < bond_min_at(height)).then_some(ATTESTOR_BOND_BELOW_MIN)
}

/// What [`apply_set_act`] did (the TxLog entry's type and seq).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SetActEffect {
    /// The attestor set's SET_CREATE was adopted (TxLog `ATTESTOR_SET_ACT`).
    Adopted,
    /// A SET_JOIN registered `seq` (TxLog `ATTESTOR_REGISTER`).
    Registered(u16),
    /// A SET_HEARTBEAT, SET_REMOVE or SET_EQUIVOCATION moved `seq` (TxLog `ATTESTOR_SET_ACT`).
    Acted(u16),
}

/// Whether `rec`'s key appears in a later record than index `i` of `all`.
fn is_newest(all: &[(u16, AttestorRecord)], i: usize) -> bool {
    let Some((_, rec)) = all.get(i) else {
        return false;
    };
    all.iter()
        .skip(i.saturating_add(1))
        .all(|(_, later)| later.attestor_pub_key != rec.attestor_pub_key)
}

/// `LatestRecord`: the newest `Attestors` record of a member key.
pub fn latest_record(reg: &dyn RegistryRead, key: &PubKeyBytes) -> Option<(u16, AttestorRecord)> {
    reg.attestors()
        .into_iter()
        .rfind(|(_, r)| r.attestor_pub_key == *key)
}

/// `CurrentMemberSeq`: the seq of `key` when it is a current member of the attestor set at `h`
/// on the mirror — its newest record, neither EJECTED nor WITHDRAWN, bond unspent and unfrozen,
/// `h >= registerHeight + the set's maturity`.
pub fn current_member_seq(reg: &dyn RegistryRead, key: &PubKeyBytes, h: i64) -> Option<u16> {
    let set = reg.attestor_set()?;
    let (seq, rec) = latest_record(reg, key)?;
    if !rec.is_standing() {
        return None;
    }
    (h >= i64::from(rec.register_height).saturating_add(i64::from(set.maturity))).then_some(seq)
}

/// EJECTED (`statusHeight` moves only on a change), frozen when `freeze` (`EjectRecord`).
fn eject_record(
    reg: &mut dyn RegistryWrite,
    seq: u16,
    mut rec: AttestorRecord,
    freeze: bool,
    height: i32,
) {
    if rec.status != AttestorStatus::Ejected {
        rec.status = AttestorStatus::Ejected;
        rec.status_height = height;
    }
    if freeze {
        rec.bond_frozen = true;
    }
    reg.put_attestor(seq, rec);
}

/// A height as the C++ `int32_t` record fields hold it (heights are below 2^31).
fn h32(height: i64) -> i32 {
    i32::try_from(height.clamp(0, i64::from(i32::MAX))).unwrap_or(i32::MAX)
}

/// The adoption rule of `attestorSetId`'s SET_CREATE (2026-10-11, 03/I-3, W3-Y-3, seats review
/// B3): OPEN, `ATTESTOR_SEATS` seats, the pinned cancel and unlock thresholds and rate limit,
/// maturity `BOND_MATURITY` (the bond exit delay), `livenessWindow >= ATTESTOR_LIVENESS_MIN`.
pub fn adopts_set(c: &kogany_vault::act::SetCreateBody, p: &Params) -> bool {
    c.is_open()
        && i32::from(c.seats) == p.attestor_seats
        && i32::from(c.cancel_threshold) == p.attestor_cancel_threshold
        && i32::from(c.unlock_threshold) == p.attestor_unlock_threshold
        && i32::from(c.rate_limit_bps) == p.attestor_rate_limit_bps
        && i64::from(c.maturity) == i64::from(p.bond_maturity)
        && i64::from(c.liveness_window) >= i64::from(p.attestor_liveness_min)
}

/// `ApplySetAct`: the attestor set's acts on the mirror (see the module docs). `None` when the
/// transaction carries no act the mirror applies. The caller has already run
/// [`refused_attestor_set_act`] and [`attestor_join_refused`].
///
/// - SET_CREATE of `attestorSetId` (its txid), not yet adopted and of the adopted shape
///   ([`adopts_set`]): writes `AttestorSet`.
/// - SET_JOIN: into a full set (as many standing newest records as seats), first the
///   [`eviction_victim`]'s record becomes WITHDRAWN with [`ATTESTOR_FLAG_EVICTED`]; then a
///   PENDING record at `next_seq` (`lastAct = h + maturity`), the bond index, `next_seq + 1`.
/// - SET_HEARTBEAT: `lastAct = h` on the key's newest record. SET_REMOVE with burn 0 (the own
///   exit): WITHDRAWN unless already WITHDRAWN or EJECTED. SET_REMOVE with burn 1, and
///   SET_EQUIVOCATION (the key recovered from `sigA`): EJECTED, frozen when burnt or equivocated.
pub fn apply_set_act(
    reg: &mut dyn RegistryWrite,
    tx: &VaultTx,
    p: &Params,
    height: i64,
) -> Option<SetActEffect> {
    let set_id = attestor_set_id(p)?;
    let act = decode_act(first_act_output(tx)?).ok()?;
    if !act_fields_valid(&act) {
        return None; // the primitive refuses it
    }
    let h = h32(height);
    if let ActBody::Create(c) = &act.body {
        if tx.txid != set_id || reg.attestor_set().is_some() || !adopts_set(c, p) {
            return None;
        }
        reg.put_attestor_set(AttestorSetRecord {
            create_height: h,
            seats: c.seats,
            maturity: c.maturity,
            liveness_window: c.liveness_window,
        });
        return Some(SetActEffect::Adopted);
    }
    if act.body.target_set() != Some(set_id) {
        return None;
    }
    let z = reg.attestor_set()?;
    let key = match &act.body {
        ActBody::Join(j) => {
            let bond = tx.outputs.get(usize::from(j.bond_vout))?;
            let next = reg.next_seq();
            if reg.attestor(next).is_some() {
                return None; // the u16 counter wrapped (totality)
            }
            evict_for_join(reg, &z, p, height, bond.value);
            let mut rec = AttestorRecord::new(j.member_key);
            rec.bond_outpoint = OutPoint {
                txid: tx.txid,
                n: u32::from(j.bond_vout),
            };
            rec.bond_zat = bond.value;
            rec.bond_locktime = j.bond_locktime;
            rec.register_height = h;
            rec.status = AttestorStatus::Pending;
            rec.status_height = h;
            rec.last_act = h32(height.saturating_add(i64::from(z.maturity)));
            reg.put_attestor(next, rec);
            reg.put_bond_seq(rec.bond_outpoint, next);
            reg.put_next_seq(next.wrapping_add(1));
            return Some(SetActEffect::Registered(next));
        }
        ActBody::Heartbeat(b) => b.member_key,
        ActBody::Remove(b) => b.member_key,
        ActBody::Equivocation(e) => recover_sig(
            &set_sig_msg(&e.set_id, e.role_a, &e.prevout, &e.sighash_a),
            &e.sig_a,
        )?,
        _ => return None,
    };
    let (seq, mut rec) = latest_record(reg, &key)?;
    match &act.body {
        ActBody::Heartbeat(_) => {
            rec.last_act = h;
            reg.put_attestor(seq, rec);
        }
        ActBody::Remove(r) if r.burn == 0 => {
            if !matches!(
                rec.status,
                AttestorStatus::Withdrawn | AttestorStatus::Ejected
            ) {
                rec.status = AttestorStatus::Withdrawn;
                rec.status_height = h;
                reg.put_attestor(seq, rec);
            }
        }
        ActBody::Remove(_) => eject_record(reg, seq, rec, true, h), // burn 1
        _ => eject_record(reg, seq, rec, true, h),                  // SET_EQUIVOCATION
    }
    Some(SetActEffect::Acted(seq))
}

/// A join into the full set evicts the [`eviction_victim`] over the standing newest records
/// (the member the primitive's displacement hook removed).
fn evict_for_join(
    reg: &mut dyn RegistryWrite,
    z: &AttestorSetRecord,
    p: &Params,
    height: i64,
    new_bond: i64,
) {
    let all = reg.attestors();
    let standing: Vec<(u16, SeatCandidate)> = (0..all.len())
        .filter(|i| is_newest(&all, *i))
        .filter_map(|i| all.get(i))
        .filter(|(_, a)| a.is_standing())
        .map(|(seq, a)| {
            (
                *seq,
                SeatCandidate {
                    key: a.attestor_pub_key,
                    bond_zat: a.bond_zat,
                    join_height: i64::from(a.register_height),
                    last_act: i64::from(a.last_act),
                },
            )
        })
        .collect();
    if standing.len() < usize::from(z.seats) {
        return;
    }
    let candidates: Vec<SeatCandidate> = standing.iter().map(|(_, c)| *c).collect();
    let Some(victim) = eviction_victim(
        &candidates,
        height,
        new_bond,
        i64::from(z.liveness_window),
        p,
    ) else {
        return;
    };
    for (seq, c) in &standing {
        if c.key != victim {
            continue;
        }
        if let Some(mut v) = reg.attestor(*seq) {
            v.status = AttestorStatus::Withdrawn;
            v.status_height = h32(height);
            v.flags |= ATTESTOR_FLAG_EVICTED;
            reg.put_attestor(*seq, v);
        }
    }
}

/// IN-2 (amended): a spend of a recorded bond marks it spent at `height` and withdraws the
/// attestor unless it is EJECTED or already WITHDRAWN (an evicted record keeps its
/// `statusHeight`); the record stays. The seq whose record changed, if any.
pub fn apply_bond_spend(
    reg: &mut dyn RegistryWrite,
    prevout: &OutPoint,
    height: i64,
) -> Option<u16> {
    let seq = reg.bond_seq(prevout)?;
    let mut rec = reg.attestor(seq)?;
    if rec.bond_spent_height != 0 {
        return None;
    }
    let h = h32(height);
    if !matches!(
        rec.status,
        AttestorStatus::Ejected | AttestorStatus::Withdrawn
    ) {
        rec.status = AttestorStatus::Withdrawn;
        rec.status_height = h;
    }
    rec.bond_spent_height = h;
    reg.put_attestor(seq, rec);
    Some(seq)
}

/// `ApplyEquivocation` (EQV-1, P4-b): with [`equivocation_evidence`] at a cited height in
/// `[START_HEIGHT, height)` whose block hash is known, the first record in seq order that is its
/// key's newest, with an unspent, unfrozen bond, under whose key the evidence verifies
/// ([`equivocated_by`]) is EJECTED and frozen. Returns `(ejected seq, the evidence's seq)` (the
/// TxLog's `attestorSeq` and `bundleSeqs`); `None` = the rule did not hold.
pub fn apply_equivocation(
    reg: &mut dyn RegistryWrite,
    tx: &VaultTx,
    p: &Params,
    height: i64,
    block_hash_at: &dyn Fn(i64) -> Option<Hash32>,
) -> Option<(u16, u16)> {
    let e = equivocation_evidence(tx, p)?;
    let a = *e.attestation();
    if i64::from(a.cited_height) >= height {
        return None;
    }
    let block_hash = block_hash_at(i64::from(a.cited_height))?;
    let set_id = Hash32(p.attestor_set_id);
    let all = reg.attestors();
    let (seq, rec) = (0..all.len()).find_map(|i| {
        let (seq, rec) = all.get(i)?;
        let candidate = rec.bond_spent_height == 0
            && !rec.bond_frozen
            && is_newest(&all, i)
            && equivocated_by(&e, &rec.attestor_pub_key, &block_hash, &set_id);
        candidate.then_some((*seq, *rec))
    })?;
    eject_record(reg, seq, rec, true, h32(height));
    Some((seq, a.seq))
}

/// The mirror's `liveMember` for [`super::attestation_liveness`]: a record that is standing and
/// its key's newest; its key and `lastAct`.
pub fn mirror_live_member(all: &[(u16, AttestorRecord)], seq: u16) -> Option<(PubKeyBytes, i64)> {
    let i = all.iter().position(|(s, _)| *s == seq)?;
    let (_, a) = all.get(i)?;
    (a.is_standing() && is_newest(all, i)).then_some((a.attestor_pub_key, i64::from(a.last_act)))
}

/// Writes the liveness credits: `lastAct = citedHeight` on each credited record. The state
/// machine has already required (LIVENESS_UNHELD) that a non-empty credit comes from a held YED
/// act whose bundle passes the whole BUNDLE-1.
pub fn apply_liveness_credits(reg: &mut dyn RegistryWrite, credits: &[(u16, i64)]) {
    for (seq, cited) in credits {
        if let Some(mut rec) = reg.attestor(*seq) {
            rec.last_act = h32(*cited);
            reg.put_attestor(*seq, rec);
        }
    }
}
