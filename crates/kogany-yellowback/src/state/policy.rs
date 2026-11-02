// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

//! The wallet's payee policy and the consistency checks around the state (W5-d2; ycash6
//! `state.{h,cpp}` at `65cb4ae0f`): REG-1 `Registered`, REG-2 `Penalized`, REG-3 `AccuracyBps`,
//! FEE-W `PayeePolicy` / `DefaultPayee`, the HALT-2 `OpenDebtInvariantViolation`, and
//! `HaltMaskNames` (`view.cpp`).
//!
//! None of these is a validity rule (L1, L6): the payee functions are the wallet's default pick
//! and the invariant is a check for tests, the fuzz harness and audits. They are total like the
//! rules (K1): a lookup that misses counts as nothing.

use sha2::{Digest, Sha256};

use super::lookups::{eligible_payees, judgement_at, tag_at};
use super::records::{TagRecord, VaultStatus};
use super::view::YedRead;
use crate::attest::price::{
    HALT_DIVERGENCE, HALT_ENFORCEMENT, HALT_GLOBAL_RATIO, HALT_NOT_ACTIVE, HALT_NO_PRICE,
    HALT_PARTICIPATION,
};
use crate::math::BPS;
use crate::params::Params;

/// The quote tag at `h` paying `key`, if any.
fn quote_of(r: &dyn YedRead, p: &Params, h: i64, key: &[u8; 20]) -> Option<TagRecord> {
    tag_at(r, p, h).filter(|t| t.is_quote() && t.payout_key == *key)
}

/// REG-1 (informational, `Registered`): some quote tag with this payout key exists in
/// `(R - N_REG, R]`.
pub fn registered(r: &dyn YedRead, p: &Params, key: &[u8; 20], ref_height: i64) -> bool {
    let lo = ref_height
        .saturating_sub(i64::from(p.n_reg))
        .saturating_add(1)
        .max(i64::from(p.start_height));
    (lo..=ref_height).any(|h| quote_of(r, p, h, key).is_some())
}

/// REG-2 (wallet policy, L6, `Penalized`): a penalised quote at `t` with
/// `t + PEER_LAG < R <= t + PEER_LAG + penalty_blocks`.
pub fn penalized(
    r: &dyn YedRead,
    p: &Params,
    key: &[u8; 20],
    ref_height: i64,
    penalty_blocks: i32,
) -> bool {
    // t + PEER_LAG < R <= t + PEER_LAG + N_PENALTY  <=>  R - PEER_LAG - N_PENALTY <= t < R - PEER_LAG
    let lo = ref_height
        .saturating_sub(i64::from(p.peer_lag))
        .saturating_sub(i64::from(penalty_blocks.max(0)));
    let hi = ref_height
        .saturating_sub(i64::from(p.peer_lag))
        .saturating_sub(1);
    (lo.max(i64::from(p.start_height))..=hi).any(|t| {
        quote_of(r, p, t, key).is_some() && judgement_at(r, p, t).is_some_and(|j| j.penalized)
    })
}

/// REG-3 (wallet policy, L6, `AccuracyBps`): `10^4 · inBand / quoted` over the judged quotes in
/// `(R - PEER_LAG - window, R - PEER_LAG]`; 0 when there are none.
pub fn accuracy_bps(
    r: &dyn YedRead,
    p: &Params,
    key: &[u8; 20],
    ref_height: i64,
    accuracy_window: i32,
) -> i32 {
    let hi = ref_height.saturating_sub(i64::from(p.peer_lag));
    let lo = hi
        .saturating_sub(i64::from(accuracy_window.max(0)))
        .saturating_add(1);
    let (mut quoted, mut in_band) = (0i64, 0i64);
    for t in lo.max(i64::from(p.start_height))..=hi {
        if quote_of(r, p, t, key).is_none() {
            continue;
        }
        let Some(j) = judgement_at(r, p, t).filter(|j| j.evaluated) else {
            continue;
        };
        quoted = quoted.saturating_add(1);
        if j.in_band {
            in_band = in_band.saturating_add(1);
        }
    }
    if quoted == 0 {
        return 0;
    }
    i32::try_from(BPS.saturating_mul(in_band).checked_div(quoted).unwrap_or(0)).unwrap_or(0)
}

/// The L6 knobs of FEE-W (`PayeePolicy`): node overrides of the §3.1 wallet defaults.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PayeePolicy {
    /// `N_PENALTY` (`-yellowbackpayeepenaltyblocks`).
    pub penalty_blocks: i32,
    /// `ACCURACY_WINDOW` (`-yellowbackpayeeaccuracywindow`).
    pub accuracy_window: i32,
    /// `PAYEE_TILT_BPS` (`-yellowbackpayeetiltbps`).
    pub tilt_bps: i32,
    /// `-yellowbackpreferredpayee`: replaces the pick when it is in E(R).
    pub preferred: Option<[u8; 20]>,
}

impl PayeePolicy {
    /// `PayeePolicy::Defaults`: the §3.1 defaults of a parameter set.
    pub fn defaults(p: &Params) -> PayeePolicy {
        PayeePolicy {
            penalty_blocks: p.n_penalty,
            accuracy_window: p.accuracy_window,
            tilt_bps: p.payee_tilt_bps,
            preferred: None,
        }
    }
}

/// FEE-W, the wallet's default payee (`DefaultPayee`; policy, never a validity rule, L1): over
/// the quote tags in `(R - PAYEE_WINDOW, R]` whose key is in E(R) and not penalised, weight
/// `10^4 + tiltBps · accuracyBps / 10^4` each; `seed = SHA256(blockHash(R) ‖ selector)` read as a
/// little-endian `u64` from its first eight bytes; `pick = seed mod Σw`; the first tag whose
/// cumulative weight exceeds `pick`. All penalised: every key of E(R) at equal weights.
/// `blockHash(R)` is `Snapshots[R].blockHash` (zero when missing). `None` iff E(R) is empty.
pub fn default_payee(
    r: &dyn YedRead,
    p: &Params,
    ref_height: i64,
    selector: &[u8],
    policy: &PayeePolicy,
) -> Option<[u8; 20]> {
    let eligible = eligible_payees(r, p, ref_height);
    let first = *eligible.first()?;
    if let Some(pref) = policy.preferred.filter(|k| eligible.contains(k)) {
        return Some(pref);
    }
    let mut candidates: Vec<([u8; 20], i64)> = Vec::new();
    let lo = ref_height
        .saturating_sub(i64::from(p.payee_window))
        .saturating_add(1)
        .max(i64::from(p.start_height));
    for h in lo..=ref_height {
        let Some(t) = tag_at(r, p, h).filter(TagRecord::is_quote) else {
            continue;
        };
        let k = t.payout_key;
        if !eligible.contains(&k) {
            continue; // pinned at R (PIN-1)
        }
        if penalized(r, p, &k, ref_height, policy.penalty_blocks) {
            continue;
        }
        let acc = i64::from(accuracy_bps(r, p, &k, ref_height, policy.accuracy_window));
        let w = BPS.saturating_add(
            i64::from(policy.tilt_bps.max(0))
                .saturating_mul(acc)
                .checked_div(BPS)
                .unwrap_or(0),
        );
        candidates.push((k, w));
    }
    if candidates.is_empty() {
        candidates = eligible.iter().map(|k| (*k, BPS)).collect();
    }
    let total = candidates
        .iter()
        .fold(0i64, |acc, c| acc.saturating_add(c.1));
    let Ok(total_u) = u64::try_from(total) else {
        return Some(first);
    };
    if total_u == 0 {
        return Some(first);
    }
    let block_hash = if ref_height >= i64::from(p.start_height) {
        u32::try_from(ref_height)
            .ok()
            .and_then(|h| r.snapshot(h))
            .map(|s| s.block_hash.0)
            .unwrap_or([0u8; 32])
    } else {
        [0u8; 32]
    };
    let mut hasher = Sha256::new();
    hasher.update(block_hash);
    hasher.update(selector);
    let digest: [u8; 32] = hasher.finalize().into();
    let mut seed_bytes = [0u8; 8];
    seed_bytes.copy_from_slice(digest.get(..8).unwrap_or(&[0u8; 8]));
    let seed = u64::from_le_bytes(seed_bytes);
    let pick = seed.checked_rem(total_u).unwrap_or(0);
    let mut cumulative: u64 = 0;
    for (k, w) in &candidates {
        cumulative = cumulative.saturating_add(u64::try_from(*w).unwrap_or(0));
        if cumulative > pick {
            return Some(*k);
        }
    }
    candidates.last().map(|c| c.0)
}

/// The open-debt invariant (HALT-2, `OpenDebtInvariantViolation`): `Totals.openDebtCents` is the
/// sum of `mintedCents` over the ACTIVE and CLAIMING vaults, and `supplyCents <= openDebtCents`.
/// `None` when both hold, else which one failed. Never a verdict. The sum wraps (`u64`) rather
/// than overflows on a corrupt record, as the C++ does.
pub fn open_debt_invariant_violation(r: &dyn YedRead) -> Option<String> {
    let t = r.totals();
    let open = r
        .vaults()
        .iter()
        .filter(|(_, v)| matches!(v.status, VaultStatus::Active | VaultStatus::Claiming))
        .fold(0u64, |acc, (_, v)| acc.wrapping_add(v.minted_cents as u64));
    if t.open_debt_cents as u64 != open {
        return Some(format!(
            "openDebtCents {} is not the ACTIVE and CLAIMING vaults' mintedCents {}",
            t.open_debt_cents, open as i64
        ));
    }
    if t.supply_cents > t.open_debt_cents {
        return Some(format!(
            "supplyCents {} exceeds openDebtCents {}",
            t.supply_cents, t.open_debt_cents
        ));
    }
    None
}

/// `HaltMaskNames` (`view.cpp`): the names of the bits set in a halt mask, bit order.
pub fn halt_mask_names(mask: u32) -> Vec<&'static str> {
    [
        (HALT_NOT_ACTIVE, "NOT_ACTIVE"),
        (HALT_NO_PRICE, "NO_PRICE"),
        (HALT_PARTICIPATION, "PARTICIPATION"),
        (HALT_GLOBAL_RATIO, "GLOBAL_RATIO"),
        (HALT_DIVERGENCE, "DIVERGENCE"),
        (HALT_ENFORCEMENT, "ENFORCEMENT"),
    ]
    .into_iter()
    .filter(|(bit, _)| mask & bit != 0)
    .map(|(_, n)| n)
    .collect()
}
