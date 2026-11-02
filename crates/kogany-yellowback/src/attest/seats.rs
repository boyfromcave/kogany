// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

//! Weights, seats, eviction, selection (W9) and the attestor passes of SNAP (maturity and set
//! dormancy, ARM-1/2, seating, PIN-1/2's bundle side, S15 dormancy): the attestor half of ycash6
//! `src/yellowback/state.cpp` at `65cb4ae0f` (`AgeOrigin`, `AttestorWeight`, `SeatRank`,
//! `EvictionVictim`, `Seated`, `SelectAttestors`, `Selected`, `DefaultAttestPayee`,
//! `OutPointSelector` and the v3 passes of `ComputeSnapshot`).
//!
//! The state machine (W5-d) owns the snapshot and the order of SNAP; it calls these passes over
//! the `Attestors` records it read, then writes back every record that changed.

use std::collections::{BTreeMap, BTreeSet};
use std::ops::RangeInclusive;

use kogany_vault::{Hash32, OutPoint, PubKeyBytes};
use sha2::{Digest, Sha256};

use super::registry::{
    AttestState, AttestStatus, AttestorRecord, AttestorSetRecord, AttestorStatus, BundleLogRecord,
    RegistryRead,
};
use crate::math::{bond_weight, seat_weight, BPS, U256};
use crate::params::{Amount, MicroUsd, Params};

/// `ageOrigin` (§3.7): `Attest.triggerHeight` for a founding member (registered at most
/// `FOUNDING_WINDOW` after the trigger, status not UNARMED), else its registration height.
pub fn age_origin(rec: &AttestorRecord, attest: &AttestState, p: &Params) -> i64 {
    let founding_until =
        i64::from(attest.trigger_height).saturating_add(i64::from(p.founding_window));
    if attest.status != AttestStatus::Unarmed && i64::from(rec.register_height) <= founding_until {
        i64::from(attest.trigger_height)
    } else {
        i64::from(rec.register_height)
    }
}

/// `AttestorWeight`: `bondZat x clamp(H - ageOrigin, 0, AGE_CAP)` (§3.7) — the price statistic's
/// and W9's weight.
pub fn attestor_weight(
    rec: &AttestorRecord,
    attest: &AttestState,
    p: &Params,
    height: i64,
) -> U256 {
    bond_weight(
        rec.bond_zat,
        height.saturating_sub(age_origin(rec, attest, p)),
        p.age_cap,
    )
}

/// `SeatRank` (2026-10-11): `SeatWeight(bondZat, H - ageOrigin) x (10^4 + SEAT_MARGIN_BPS)` for
/// a currently seated record (`seatedSince != 0`: the hysteresis), else `x 10^4`. Seats only.
pub fn seat_rank(rec: &AttestorRecord, attest: &AttestState, p: &Params, height: i64) -> U256 {
    let w = seat_weight(
        rec.bond_zat,
        height.saturating_sub(age_origin(rec, attest, p)),
        i64::from(p.seat_age_unit),
        i64::from(p.seat_age_cap),
    );
    let margin = if rec.seated_since != 0 {
        i64::from(p.seat_margin_bps.max(0))
    } else {
        0
    };
    w.wrapping_mul(U256::from_i64(BPS.saturating_add(margin)))
}

/// A member of the attestor set as the primitive records it (`SeatCandidate`; the mirror's equal
/// fields).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SeatCandidate {
    /// The member key.
    pub key: PubKeyBytes,
    /// Its bond.
    pub bond_zat: Amount,
    /// Its (latest) join height.
    pub join_height: i64,
    /// Its last proven act.
    pub last_act: i64,
}

/// `EvictionVictim` (2026-10-11): for a `SET_JOIN` of `new_bond_zat` into the full attestor set
/// at `height`, over its ACTIVE members with an unfrozen bond. Never below the module's bond
/// floor. A member that is not live (`last_act < height - liveness_window`) goes first: the
/// not-live member of least seat weight; otherwise the member of least weight, only when
/// `SeatWeight(new, 0) x 10^4 > w x (10^4 + EVICT_MARGIN_BPS)`. Ties by key bytes ascending.
pub fn eviction_victim(
    members: &[SeatCandidate],
    height: i64,
    new_bond_zat: Amount,
    liveness_window: i64,
    p: &Params,
) -> Option<PubKeyBytes> {
    if new_bond_zat < p.bond_min_floor_zat.max(0) {
        return None; // no dust evictions (seats review B2)
    }
    let unit = i64::from(p.seat_age_unit);
    let cap = i64::from(p.seat_age_cap);
    let live_from = height.saturating_sub(liveness_window);
    let mut best: Option<(bool, U256, PubKeyBytes)> = None;
    for c in members {
        let dead = c.last_act < live_from;
        let w = seat_weight(c.bond_zat, height.saturating_sub(c.join_height), unit, cap);
        let better = match &best {
            None => true,
            Some((best_dead, best_w, best_key)) => {
                if dead != *best_dead {
                    dead
                } else if w != *best_w {
                    w < *best_w
                } else {
                    c.key.0 < best_key.0
                }
            }
        };
        if better {
            best = Some((dead, w, c.key));
        }
    }
    let (dead, w, key) = best?;
    if dead {
        return Some(key);
    }
    let joiner = seat_weight(new_bond_zat, 0, unit, cap).wrapping_mul(U256::from_i64(BPS));
    let bar = w.wrapping_mul(U256::from_i64(
        BPS.saturating_add(i64::from(p.evict_margin_bps.max(0))),
    ));
    (joiner > bar).then_some(key)
}

/// The number of seats: `min(max(0, N_SLOTS), the set's seats)`, 0 without a set.
fn slots(p: &Params, set: Option<&AttestorSetRecord>) -> usize {
    let n = usize::try_from(p.n_slots.max(0)).unwrap_or(0);
    set.map_or(0, |s| n.min(usize::from(s.seats)))
}

/// `Seated`: the `min(N_SLOTS, seats)` ELIGIBLE records of greatest [`seat_rank`] at `height`,
/// ties by seq ascending; returned ascending.
pub fn seated(
    attestors: &[(u16, AttestorRecord)],
    set: Option<&AttestorSetRecord>,
    attest: &AttestState,
    p: &Params,
    height: i64,
) -> Vec<u16> {
    let mut ranked: Vec<(U256, u16)> = attestors
        .iter()
        .filter(|(_, r)| r.status == AttestorStatus::Eligible)
        .map(|(s, r)| (seat_rank(r, attest, p, height), *s))
        .collect();
    ranked.sort_by(|x, y| y.0.cmp(&x.0).then(x.1.cmp(&y.1)));
    let mut out: Vec<u16> = ranked
        .into_iter()
        .take(slots(p, set))
        .map(|(_, s)| s)
        .collect();
    out.sort_unstable();
    out
}

/// `SelectAttestors` (W9) over an explicit pool `(seq, weight)`: for round `i` in
/// `0..rounds` while the pool is non-empty, `seed_i = SHA256(blockHash ‖ selector ‖ "S" ‖
/// u8 i)` read little-endian as a 256-bit integer, `pick = seed_i mod Σ weight` (256-bit, R10),
/// chosen = the first seq in ascending order whose cumulative weight exceeds `pick`, removed. A
/// zero total over the remaining pool draws the lowest seq. The Python reference is
/// `test_framework/yellowback_attest.py:select_attestors`.
pub fn select_attestors(
    block_hash: &Hash32,
    selector: &[u8],
    pool: &[(u16, U256)],
    rounds: i32,
) -> Vec<u16> {
    let mut pool = pool.to_vec();
    pool.sort_by_key(|(s, _)| *s); // stable, as std::sort over distinct seqs
    let mut chosen = Vec::new();
    let mut i: i32 = 0;
    while i < rounds && !pool.is_empty() {
        let total = pool
            .iter()
            .fold(U256::ZERO, |acc, (_, w)| acc.wrapping_add(*w));
        let pick_at = if total.is_zero() {
            Some(0) // every remaining weight is zero: lowest seq first
        } else {
            let round = u8::try_from(i & 0xff).unwrap_or(0);
            let digest: [u8; 32] = Sha256::new()
                .chain_update(block_hash.0)
                .chain_update(selector)
                .chain_update(b"S")
                .chain_update([round])
                .finalize()
                .into();
            let pick = U256::from_le_bytes(digest)
                .checked_rem(total)
                .unwrap_or(U256::ZERO);
            let mut cumulative = U256::ZERO;
            pool.iter().position(|(_, w)| {
                cumulative = cumulative.wrapping_add(*w);
                cumulative > pick
            })
        };
        if let Some(j) = pick_at.filter(|j| *j < pool.len()) {
            chosen.push(pool.remove(j).0);
        }
        i = i.saturating_add(1);
    }
    chosen
}

/// What `Selected` reads of `Snapshots[R]`: the stored arrays (R11) and the carried arming
/// state. The state machine builds it from the snapshot; `None` = missing or virtual.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SelectionBasis {
    /// `Snapshots[R].blockHash`.
    pub block_hash: Hash32,
    /// `Snapshots[R].seated`.
    pub seated: Vec<u16>,
    /// `Snapshots[R].pinnedSeqs`.
    pub pinned_seqs: Vec<u16>,
    /// `Snapshots[R].attest`.
    pub attest: AttestState,
}

/// `Selected(R, selector)`: [`select_attestors`] over `seated \ pinnedSeqs` at R with
/// [`attestor_weight`] at R under the snapshot's arming state, `M_SELECT + K_SLACK` rounds,
/// seeded by the snapshot's block hash. Empty below the start height or without a snapshot.
pub fn selected(
    basis: Option<&SelectionBasis>,
    reg: &dyn RegistryRead,
    p: &Params,
    ref_height: i64,
    selector: &[u8],
) -> Vec<u16> {
    if ref_height < i64::from(p.start_height) || ref_height < 0 {
        return Vec::new();
    }
    let Some(s) = basis else {
        return Vec::new();
    };
    let pool: Vec<(u16, U256)> = s
        .seated
        .iter()
        .filter(|seq| !s.pinned_seqs.contains(seq))
        .filter_map(|seq| {
            // a seated seq always has a record (records are never deleted); stated for totality
            reg.attestor(*seq)
                .map(|rec| (*seq, attestor_weight(&rec, &s.attest, p, ref_height)))
        })
        .collect();
    let rounds = p.m_select.max(0).saturating_add(p.k_slack.max(0));
    select_attestors(&s.block_hash, selector, &pool, rounds)
}

/// `OutPointSelector`: the 36-byte serialised outpoint (txid internal bytes ‖ n LE32), the
/// selector of REDEEM claims and CLAIM_NOTICE (R13).
pub fn outpoint_selector(out: &OutPoint) -> Vec<u8> {
    out.to_bytes().to_vec()
}

/// `DefaultAttestPayee` (AFEE-W, wallet policy): `preferred` when it is in `a`; else `a` sorted
/// and deduplicated, `a[SHA256(blockHash(R) ‖ selector ‖ "A") mod |a|]`. `block_hash` is
/// `Snapshots[R].blockHash`, or zero when R is below the start height or has no snapshot (the
/// C++ default `uint256`). `None` iff `a` is empty.
pub fn default_attest_payee(
    block_hash: &Hash32,
    selector: &[u8],
    a: &[u16],
    preferred: Option<u16>,
) -> Option<u16> {
    let set: BTreeSet<u16> = a.iter().copied().collect();
    if set.is_empty() {
        return None;
    }
    if let Some(pref) = preferred.filter(|s| set.contains(s)) {
        return Some(pref);
    }
    let digest: [u8; 32] = Sha256::new()
        .chain_update(block_hash.0)
        .chain_update(selector)
        .chain_update(b"A")
        .finalize()
        .into();
    let n = U256::from_u64(u64::try_from(set.len()).ok()?);
    let idx = U256::from_le_bytes(digest).checked_rem(n)?.low_u64();
    set.into_iter().nth(usize::try_from(idx).ok()?)
}

// ---------------------------------------------------------------- SNAP passes

/// `BondMinZat(registerHeight)` as the state machine computes it from
/// `Snapshots[registerHeight - 1].collateralZat` (D-Q-30).
pub type BondMinAt<'a> = &'a dyn Fn(i64) -> Amount;

/// SNAP's first attestor pass (P4-b): maturity and the set's member dormancy, in seq order.
/// PENDING → ELIGIBLE at `registerHeight + max(set maturity, BOND_MATURITY)` when
/// `bondLocktime >= registerHeight + BOND_MIN_LOCK`, the key has no frozen bond in any record,
/// and the bond meets `BondMinZat(registerHeight)` (read only between the floor and the cap);
/// ELIGIBLE → DORMANT when `lastAct < H - livenessWindow`; DORMANT → ELIGIBLE once live again
/// with `lastAct > statusHeight`. Without an adopted set nothing moves. Returns the number of
/// ELIGIBLE records after the pass (ARM-1's count).
pub fn maturity_pass(
    attestors: &mut [(u16, AttestorRecord)],
    set: Option<&AttestorSetRecord>,
    p: &Params,
    height: i32,
    bond_min_at: BondMinAt<'_>,
) -> usize {
    let h = i64::from(height);
    let slashed: BTreeSet<PubKeyBytes> = attestors
        .iter()
        .filter(|(_, r)| r.bond_frozen)
        .map(|(_, r)| r.attestor_pub_key)
        .collect();
    let mut eligible = 0usize;
    for (_, a) in attestors.iter_mut() {
        if let Some(z) = set {
            let reg = i64::from(a.register_height);
            let mature_at =
                reg.saturating_add(i64::from(z.maturity).max(i64::from(p.bond_maturity)));
            let floor_ok = i64::from(a.bond_locktime)
                >= reg.saturating_add(i64::from(p.bond_min_lock))
                && !slashed.contains(&a.attestor_pub_key);
            let live = i64::from(a.last_act) >= h.saturating_sub(i64::from(z.liveness_window));
            let bond_ok = || {
                let floor = p.bond_min_floor_zat.max(0);
                if a.bond_zat >= floor.max(p.bond_min_cap_zat) {
                    return true;
                }
                if a.bond_zat < floor {
                    return false;
                }
                a.bond_zat >= bond_min_at(reg)
            };
            if a.status == AttestorStatus::Pending && floor_ok && h >= mature_at && bond_ok() {
                a.status = AttestorStatus::Eligible;
                a.status_height = height;
            }
            if a.status == AttestorStatus::Eligible && !live {
                a.status = AttestorStatus::Dormant;
                a.status_height = height;
            } else if a.status == AttestorStatus::Dormant && live && a.last_act > a.status_height {
                a.status = AttestorStatus::Eligible;
                a.status_height = height;
            }
        }
        if a.status == AttestorStatus::Eligible {
            eligible = eligible.saturating_add(1);
        }
    }
    eligible
}

/// ARM-1/2 (status never moves backward; `ATTEST_ARM_MIN` 0 never arms): UNARMED → TRIGGERED at
/// `eligible >= ATTEST_ARM_MIN` (`trigger = H`, `arm = H + ATTEST_ARM_DELAY`), TRIGGERED → ARMED
/// at `H >= arm`. The caller writes `Attest` when it changed or was never written.
pub fn arm_pass(m: &AttestState, p: &Params, height: i32, eligible: usize) -> AttestState {
    let mut m = *m;
    let arm_min = usize::try_from(p.attest_arm_min).unwrap_or(0);
    if m.status == AttestStatus::Unarmed && p.attest_arm_min > 0 && eligible >= arm_min {
        m.status = AttestStatus::Triggered;
        m.trigger_height = height;
        m.arm_height = height.saturating_add(p.attest_arm_delay);
    }
    if m.status == AttestStatus::Triggered && height >= m.arm_height {
        m.status = AttestStatus::Armed;
    }
    m
}

/// SNAP's seating: [`seated`] at `H` under the new arming state (the seat ranks read
/// `seatedSince` before this block: the hysteresis), then `seatedSince` follows membership
/// (`H` on entry, 0 on exit). Returns `Snapshots[H].seated`.
pub fn seating_pass(
    attestors: &mut [(u16, AttestorRecord)],
    set: Option<&AttestorSetRecord>,
    attest: &AttestState,
    p: &Params,
    height: i32,
) -> Vec<u16> {
    let seats = seated(attestors, set, attest, p, i64::from(height));
    for (seq, r) in attestors.iter_mut() {
        let inside = seats.binary_search(seq).is_ok();
        if inside && r.seated_since == 0 {
            r.seated_since = height;
        }
        if !inside && r.seated_since != 0 {
            r.seated_since = 0;
        }
    }
    seats
}

/// The heights of PIN-1/2's window `W = [max(H - PIN_WINDOW, START_HEIGHT), H - 1]` whose
/// `BundleLog` rows the passes read (heights outside `0..=u32::MAX` skipped by the caller).
pub fn pin_window(p: &Params, height: i64) -> RangeInclusive<i64> {
    height
        .saturating_sub(i64::from(p.pin_window))
        .max(i64::from(p.start_height))..=height.saturating_sub(1)
}

/// PIN-1's bundle condition: at least `max(1, PIN_MIN_BUNDLES)` rows in the window, and the
/// spread of their defined `aMint` exceeds `PIN_DELTA_BPS` of the lowest (an undefined statistic
/// is never a value, audit A-4). When it holds, the state machine pins the quote-tag keys.
pub fn pin1_triggered(window: &[BundleLogRecord], p: &Params) -> bool {
    let min_bundles = usize::try_from(p.pin_min_bundles.max(1)).unwrap_or(1);
    if window.len() < min_bundles {
        return false;
    }
    let mints: Vec<i64> = window.iter().filter_map(BundleLogRecord::a_mint).collect();
    let (Some(lo), Some(hi)) = (mints.iter().min(), mints.iter().max()) else {
        return false;
    };
    exceeds_delta(*lo, hi.saturating_sub(*lo), p)
}

/// `diff x 10^4 > max(0, PIN_DELTA_BPS) x lo`, in `i128` (no overflow).
fn exceeds_delta(lo: i64, diff: i64, p: &Params) -> bool {
    i128::from(diff).saturating_mul(i128::from(BPS))
        > i128::from(p.pin_delta_bps.max(0)).saturating_mul(i128::from(lo))
}

/// PIN-2's trigger: `Snapshots[H-1].pMint` (`x1`) and `Snapshots[H-1-PIN_WINDOW].pMint` (`x0`)
/// both defined and apart by more than `PIN_DELTA_BPS` of the lower.
pub fn pin2_triggered(x1: Option<MicroUsd>, x0: Option<MicroUsd>, p: &Params) -> bool {
    match (x1, x0) {
        (Some(a), Some(b)) => exceeds_delta(a.min(b), a.max(b).saturating_sub(a.min(b)), p),
        _ => false,
    }
}

/// PIN-2's pinned seqs (`Snapshots[H].pinnedSeqs`), when [`pin2_triggered`]: a seq that appears
/// in at least `max(1, PIN_MIN_TAGS)` window rows, signed one price only, at at least
/// `PIN_MIN_TAGS` distinct cited heights (one attestation reused by several bundles cannot pin,
/// audit A-2). Ascending.
pub fn pin2_pinned_seqs(window: &[BundleLogRecord], p: &Params) -> Vec<u16> {
    let min_tags = usize::try_from(p.pin_min_tags.max(1)).unwrap_or(1);
    let mut per_seq: BTreeMap<u16, (usize, BTreeSet<i64>, BTreeSet<u32>)> = BTreeMap::new();
    for row in window {
        let mut seen = BTreeSet::new();
        for (i, (seq, price)) in row.seqs.iter().zip(row.prices.iter()).enumerate() {
            let e = per_seq.entry(*seq).or_default();
            if seen.insert(*seq) {
                e.0 = e.0.saturating_add(1);
            }
            e.1.insert(*price);
            if let Some(c) = row.cited_heights.get(i) {
                e.2.insert(*c);
            }
        }
    }
    per_seq
        .into_iter()
        .filter(|(_, (rows, prices, cited))| {
            *rows >= min_tags && prices.len() == 1 && cited.len() >= min_tags
        })
        .map(|(s, _)| s)
        .collect()
}

/// S15 runs at `H` only when `DORMANCY_CHECK > 0` and `H mod DORMANCY_CHECK == 0`.
pub fn dormancy_due(p: &Params, height: i64) -> bool {
    p.dormancy_check > 0 && height.checked_rem(i64::from(p.dormancy_check)) == Some(0)
}

/// The heights of S15's window `[max(H - DORMANCY_BLOCKS + 1, START_HEIGHT), H]`.
pub fn dormancy_window(p: &Params, height: i64) -> RangeInclusive<i64> {
    height
        .saturating_sub(i64::from(p.dormancy_blocks))
        .saturating_add(1)
        .max(i64::from(p.start_height))..=height
}

/// S15 (v3 dormancy), when [`dormancy_due`]: an ELIGIBLE, seated record seated since at least
/// `DORMANCY_BLOCKS` that was selected in at least `max(1, DORMANCY_MIN_BUNDLES)` window rows and
/// signed in none becomes DORMANT at `H`.
pub fn dormancy_pass(
    attestors: &mut [(u16, AttestorRecord)],
    rows: &[BundleLogRecord],
    p: &Params,
    height: i32,
) {
    if !dormancy_due(p, i64::from(height)) {
        return;
    }
    let h = i64::from(height);
    let min_bundles = usize::try_from(p.dormancy_min_bundles.max(1)).unwrap_or(1);
    for (seq, r) in attestors.iter_mut() {
        if r.status != AttestorStatus::Eligible || r.seated_since == 0 {
            continue;
        }
        if i64::from(r.seated_since) > h.saturating_sub(i64::from(p.dormancy_blocks)) {
            continue;
        }
        let picked: Vec<&BundleLogRecord> = rows
            .iter()
            .filter(|row| row.selected_seqs.contains(seq))
            .collect();
        let signed_any = picked.iter().any(|row| row.seqs.contains(seq));
        if picked.len() >= min_bundles && !signed_any {
            r.status = AttestorStatus::Dormant;
            r.status_height = height;
        }
    }
}
