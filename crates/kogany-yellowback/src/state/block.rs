// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

//! A whole block (§3.8, §3.9 BLK-1; ycash6 `state.cpp` `EvaluateBlock`, `Judge`,
//! `ComputeSnapshot`): the coinbase tag first (TAG-1..5), every transaction in block order
//! (stopping at the first invalid one: the block is invalid), `BundleLog[H]`, then SNAP — REG-4,
//! the attestor passes (maturity, ARM-1/2, PIN-1/2, seating), PRICE-1, SIGMA-1, issuance, totals,
//! HALT-1..3, S15 dormancy — and the tip. Below the start height nothing is written. Total.
//!
//! The evaluation is over a read-only base: the result carries the block's [`YedDelta`], which
//! the caller applies when the block is valid (and reverts on a reorg).

use std::collections::{BTreeMap, BTreeSet};

use kogany_vault::state::VaultTx;
use kogany_vault::Hash32;

use super::keys::YedKey;
use super::lookups::{bond_min_zat, is_yed_vault_output, snapshot_at, tag_at, yed_intent_output};
use super::mint::h32;
use super::records::{
    Judgement, ParamsRecord, Snapshot, TagRecord, TipRecord, TxLogRecord, SCHEMA_VERSION,
};
use super::tx::process_tx;
use super::verdict;
use super::view::{YedDelta, YedOverlay, YedRead};
use crate::attest::bundle::SigCache;
use crate::attest::price::{
    BundleLogAccumulator, HALT_DIVERGENCE, HALT_GLOBAL_RATIO, HALT_NO_PRICE,
};
use crate::attest::registry::{BundleLogRecord, RegistryRead, RegistryWrite};
use crate::attest::seats::{
    arm_pass, dormancy_due, dormancy_pass, dormancy_window, maturity_pass, pin1_triggered,
    pin2_pinned_seqs, pin2_triggered, pin_window, seating_pass,
};
use crate::codecs::tag::{find_tag, CoinbaseTag};
use crate::math::{global_ratio_bps, lower_median, sigma_mult_bps, BPS};
use crate::params::{Amount, MicroUsd, Params};

/// The result of [`evaluate_block`] (`BlockEvaluation`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BlockEvaluation {
    /// BLK-1: some transaction (or the coinbase) is invalid under the module.
    pub block_invalid: bool,
    /// The first invalid transaction's verdict (the reject reason is `bad-yellowback-<verdict>`).
    pub verdict: String,
    /// `"<verdict>:<txid display hex>"` of the first invalid transaction, else `""`.
    pub reason: String,
    /// The TxLog entries of the relevant transactions, block order (and the invalid one's last).
    pub txlogs: Vec<(Hash32, TxLogRecord)>,
    /// `Snapshots[H]` (default when invalid or below the start height).
    pub snapshot: Snapshot,
    /// The block's changes with their undo; empty when invalid or below the start height.
    pub delta: YedDelta,
}

/// A txid in the display (reversed) hex the C++ `uint256::GetHex` prints.
pub fn display_hex(h: &Hash32) -> String {
    let mut b = h.0;
    b.reverse();
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// `EvaluateBlock` over `base`: `txs[0]` is the coinbase. `block_hash` is internal byte order.
/// On a valid block the delta moves `base` to the state after it.
pub fn evaluate_block(
    base: &dyn YedRead,
    p: &Params,
    txs: &[VaultTx],
    height: i64,
    block_hash: &Hash32,
    subsidy_zat: Amount,
    cache: Option<&dyn SigCache>,
) -> BlockEvaluation {
    let mut ev = BlockEvaluation::default();
    if height < i64::from(p.start_height) {
        return ev; // ignored completely (§3.8)
    }
    let mut st = YedOverlay::new(base);
    // The records the state hash always carries exist from the first applied block.
    if !st.has(&YedKey::Params) {
        st.put(
            YedKey::Params,
            super::keys::YedRecord::Params(ParamsRecord::of(p)),
        );
    }
    if !st.has(&YedKey::Totals) {
        st.put_totals(super::records::Totals::default());
    }
    if !st.has(&YedKey::AttestorSeq) {
        st.put_next_seq(0);
    }
    // TAG-1..5: the coinbase scriptSig, read first
    let tag: Option<CoinbaseTag> = txs
        .first()
        .filter(|cb| cb.coinbase)
        .and_then(|cb| cb.inputs.first())
        .and_then(|i| find_tag(&i.script_sig, h32(height)));
    if let (Some(t), Ok(hk)) = (tag, u32::try_from(height)) {
        st.put_tag(
            hk,
            TagRecord {
                payout_key: t.payout_key,
                price_micro_usd: t.price_micro_usd,
                signal: t.signal(),
                source_mask: t.source_mask,
            },
        );
    }
    // Transactions in block order; BLK-1 stops at the first invalid one.
    let mut acc = BundleLogAccumulator::new();
    for tx in txs {
        if tx.coinbase {
            // a coinbase's outputs may not be YED templates either (U-23)
            if tx.outputs.iter().any(|o| {
                is_yed_vault_output(&o.script_pubkey)
                    || yed_intent_output(&o.script_pubkey).is_some()
            }) {
                ev.block_invalid = true;
                ev.verdict = verdict::YED_TEMPLATE_OUTPUT.to_owned();
                ev.reason = format!("{}:{}", ev.verdict, display_hex(&tx.txid));
                return ev;
            }
            continue;
        }
        let effect = process_tx(&st, p, tx, height, cache);
        if effect.outcome.invalid {
            ev.block_invalid = true;
            ev.verdict = effect.outcome.log.verdict.clone();
            ev.reason = format!("{}:{}", ev.verdict, display_hex(&tx.txid));
            ev.txlogs.push((tx.txid, effect.outcome.log));
            return ev;
        }
        st.merge(effect.writes);
        for f in &effect.bundles {
            acc.commit(f);
        }
        if effect.outcome.relevant {
            ev.txlogs.push((tx.txid, effect.outcome.log));
        }
    }
    // BundleLog[H] (R12), before SNAP: dormancy reads the row of H
    if let (Some(row), Ok(hk)) = (acc.row(), u32::try_from(height)) {
        st.put_bundle_log(hk, row);
    }
    ev.snapshot = compute_snapshot(&mut st, p, height, block_hash, subsidy_zat, tag.as_ref());
    if let Ok(hk) = u32::try_from(height) {
        st.put_snapshot(hk, ev.snapshot.clone());
    }
    st.put(
        YedKey::Tip,
        super::keys::YedRecord::Tip(TipRecord {
            height: h32(height),
            block_hash: *block_hash,
            schema_version: SCHEMA_VERSION,
            network: p.network.to_owned(),
        }),
    );
    ev.delta = st.delta();
    ev
}

/// REG-4 (`Judge`), performed at H for the quote tag at `t = H - PEER_LAG`: its deviation from
/// the lower median of the peers' quotes in `[t - lag, t + lag - 1] \ {t}`, when at least
/// `PEER_MIN` peers quoted.
fn judge(st: &mut YedOverlay<'_>, p: &Params, height: i64) {
    let lag = i64::from(p.peer_lag);
    let t = height.saturating_sub(lag);
    if t < i64::from(p.start_height) {
        return;
    }
    let Some(tag) = tag_at(st, p, t).filter(TagRecord::is_quote) else {
        return;
    };
    let mut peers: Vec<MicroUsd> = Vec::new();
    let mut hh = t.saturating_sub(lag);
    while hh < t.saturating_add(lag) {
        if hh != t {
            if let Some(q) = tag_at(st, p, hh).filter(TagRecord::is_quote) {
                peers.push(i64::try_from(q.price_micro_usd).unwrap_or(i64::MAX));
            }
        }
        hh = hh.saturating_add(1);
    }
    let mut j = Judgement::default();
    if i64::try_from(peers.len()).unwrap_or(i64::MAX) >= i64::from(p.peer_min) {
        if let Some(m) = lower_median(&peers).filter(|m| *m > 0) {
            // price, med <= PRICE_MAX: no overflow
            let price = tag.price_micro_usd;
            let med = m.unsigned_abs();
            let dev = price
                .abs_diff(med)
                .saturating_mul(BPS.unsigned_abs())
                .checked_div(med)
                .unwrap_or(0);
            j.evaluated = true;
            j.in_band = dev <= u64::try_from(p.accuracy_band_bps.max(0)).unwrap_or(0);
            j.penalized = dev > u64::try_from(p.deviation_bps.max(0)).unwrap_or(0);
        }
    }
    if let Ok(tk) = u32::try_from(t) {
        st.put_judgement(tk, j);
    }
}

/// The `BundleLog` rows of the heights in `range` (heights outside `0..=u32::MAX` skipped).
fn bundle_rows(st: &dyn YedRead, range: core::ops::RangeInclusive<i64>) -> Vec<BundleLogRecord> {
    let (lo, hi) = (*range.start(), *range.end());
    let mut out = Vec::new();
    let mut hh = lo;
    while hh <= hi {
        if let Some(row) = u32::try_from(hh).ok().and_then(|k| st.bundle_log(k)) {
            out.push(row);
        }
        hh = hh.saturating_add(1);
    }
    out
}

/// PRICE-1's `median(W, H)`: the lower median of the quote prices in `(H - W, H]`, undefined
/// below `min_fill` quotes.
fn window_median(
    prices: &[(i64, MicroUsd)],
    height: i64,
    window: i32,
    min_fill: i32,
) -> Option<MicroUsd> {
    let lo = height.saturating_sub(i64::from(window));
    let v: Vec<MicroUsd> = prices
        .iter()
        .filter(|(hh, _)| *hh > lo && *hh <= height)
        .map(|(_, x)| *x)
        .collect();
    if i64::try_from(v.len()).unwrap_or(i64::MAX) < i64::from(min_fill) {
        return None;
    }
    lower_median(&v)
}

/// SNAP for height H after the block's transactions (`ComputeSnapshot`); writes the Judgement
/// of H - PEER_LAG, the Attest state and every attestor record the passes changed.
#[allow(clippy::too_many_lines)]
pub fn compute_snapshot(
    st: &mut YedOverlay<'_>,
    p: &Params,
    height: i64,
    block_hash: &Hash32,
    subsidy_zat: Amount,
    tag: Option<&CoinbaseTag>,
) -> Snapshot {
    let hh32 = h32(height);
    judge(st, p, height); // REG-4
    let mut s = Snapshot {
        block_hash: *block_hash,
        tagged: tag.is_some(),
        quote: tag.is_some_and(CoinbaseTag::is_quote),
        ..Snapshot::default()
    };

    // ---- v3 SNAP: maturity, ARM-1/2, PIN-1/2, seating; dormancy after the halts
    let mut attestors = st.attestors();
    let before: Vec<Vec<u8>> = attestors.iter().map(|(_, r)| r.encode()).collect();
    let aset = st.attestor_set();
    let eligible = {
        let ro: &YedOverlay<'_> = st;
        let bond_min = |rh: i64| bond_min_zat(ro, p, rh);
        maturity_pass(&mut attestors, aset.as_ref(), p, hh32, &bond_min)
    };
    let m0 = st.attest();
    let m = arm_pass(&m0, p, hh32, eligible);
    if m != m0 || !st.has(&YedKey::Attest) {
        st.put_attest(m);
    }
    s.attest = m;
    // PIN-1/2 over W = [max(H - PIN_WINDOW, START), H - 1]: prior snapshots and BundleLog only
    let window = bundle_rows(st, pin_window(p, height));
    if pin1_triggered(&window, p) {
        let mut per_key: BTreeMap<[u8; 20], (i64, BTreeSet<u64>)> = BTreeMap::new();
        let range = pin_window(p, height);
        let mut hh = *range.start();
        while hh <= *range.end() {
            if let Some(t) = tag_at(st, p, hh).filter(TagRecord::is_quote) {
                let e = per_key.entry(t.payout_key).or_default();
                e.0 = e.0.saturating_add(1);
                e.1.insert(t.price_micro_usd);
            }
            hh = hh.saturating_add(1);
        }
        let min_tags = i64::from(p.pin_min_tags.max(1));
        s.pinned_keys = per_key
            .into_iter()
            .filter(|(_, (n, prices))| *n >= min_tags && prices.len() == 1)
            .map(|(k, _)| k)
            .collect(); // BTreeMap order: ascending bytes, as the C++ std::sort of uint160
    }
    {
        let x1 = snapshot_at(st, p, height.saturating_sub(1)).and_then(|x| x.pmint());
        let x0 = snapshot_at(
            st,
            p,
            height
                .saturating_sub(1)
                .saturating_sub(i64::from(p.pin_window)),
        )
        .and_then(|x| x.pmint());
        if pin2_triggered(x1, x0, p) {
            s.pinned_seqs = pin2_pinned_seqs(&window, p);
        }
    }
    // seating (seatedSince before this block: the hysteresis)
    s.seated = seating_pass(&mut attestors, aset.as_ref(), &m, p, hh32);

    // ---- PRICE-1..2 (the medians skip the quote tags of keys pinned at H)
    let max_window = p.p_fast_window.max(p.p_mid_window).max(p.p_slow_window);
    let prices: Vec<(i64, MicroUsd)> = {
        let lo = height
            .saturating_sub(i64::from(max_window))
            .saturating_add(1)
            .max(i64::from(p.start_height));
        let mut v = Vec::new();
        let mut hh = lo;
        while hh <= height {
            if let Some(t) = tag_at(st, p, hh).filter(TagRecord::is_quote) {
                if !s.pinned_keys.contains(&t.payout_key) {
                    v.push((hh, i64::try_from(t.price_micro_usd).unwrap_or(i64::MAX)));
                }
            }
            hh = hh.saturating_add(1);
        }
        v
    };
    let p_fast = window_median(&prices, height, p.p_fast_window, p.p_fast_min_fill);
    let p_mid = window_median(&prices, height, p.p_mid_window, p.p_mid_min_fill);
    let p_slow = window_median(&prices, height, p.p_slow_window, p.p_slow_min_fill);
    let p_mint = match (p_fast, p_mid, p_slow) {
        (Some(f), Some(m), Some(sl)) => Some(f.min(m).min(sl)),
        _ => None,
    };
    let p_claim = match (p_mid, p_slow) {
        (Some(m), Some(sl)) => Some(m.max(sl)),
        _ => None,
    };
    s.p_fast = p_fast.unwrap_or(0);
    s.p_mid = p_mid.unwrap_or(0);
    s.p_slow = p_slow.unwrap_or(0);
    s.p_mint = p_mint.unwrap_or(0);
    s.p_claim = p_claim.unwrap_or(0);

    // ---- SIGMA-1: s_0 = this pFast, s_k = Snapshots[H - k x VOL_STEP].pFast
    let mut samples: Vec<Option<MicroUsd>> = vec![p_fast];
    if p.vol_step > 0 {
        let n = p.vol_window.checked_div(p.vol_step).unwrap_or(0);
        let mut k: i32 = 1;
        while k <= n {
            let at = height.saturating_sub(i64::from(k).saturating_mul(i64::from(p.vol_step)));
            samples.push(snapshot_at(st, p, at).and_then(|x| x.pfast()));
            k = k.saturating_add(1);
        }
    }
    s.sigma_mult_bps = sigma_mult_bps(
        &samples,
        p.sigma_ref_bps,
        p.vol_periods_per_year,
        p.sigma_mult_max_bps,
    );

    // ---- issuance (D-Q-25), totals, the global ratio
    let prev = snapshot_at(st, p, height.saturating_sub(1));
    let issued_before = match prev {
        Some(x) if height.saturating_sub(1) >= i64::from(p.start_height) => x.issued_zat,
        _ => p.issued_before_start,
    };
    s.issued_zat = issued_before.wrapping_add(subsidy_zat); // wraps rather than overflows (total)
    let totals = st.totals();
    s.supply_cents = totals.supply_cents;
    s.collateral_zat = totals.collateral_zat;
    s.open_debt_cents = totals.open_debt_cents;
    // HALT-2 (2026-10-28): the open vaults' collateral against their open debt
    let ratio = global_ratio_bps(s.collateral_zat, p_mint, s.open_debt_cents);
    s.global_ratio_bps = ratio.unwrap_or(0);

    // ---- HALT-1..3
    let mut mask = 0u32;
    if p_mint.is_none() {
        mask |= HALT_NO_PRICE; // HALT-1
    }
    if p_mint.is_some()
        && s.open_debt_cents > 0
        && ratio.is_some_and(|r| r < i64::from(p.global_ratio_halt_bps))
    {
        mask |= HALT_GLOBAL_RATIO; // HALT-2
    }
    if let (Some(f), Some(m), Some(sl)) = (p_fast, p_mid, p_slow) {
        // HALT-3: pFast x 10^4 < k x pMid or pMid x 10^4 < k x pSlow, k = 10^4 - DIVERGENCE_BPS
        let k = i128::from(BPS).saturating_sub(i128::from(p.divergence_bps));
        let bps = i128::from(BPS);
        if i128::from(f).saturating_mul(bps) < k.saturating_mul(i128::from(m))
            || i128::from(m).saturating_mul(bps) < k.saturating_mul(i128::from(sl))
        {
            mask |= HALT_DIVERGENCE;
        }
    }
    s.halt_mask = mask;

    // ---- dormancy (S15): only at H mod DORMANCY_CHECK == 0
    if dormancy_due(p, height) {
        let rows = bundle_rows(st, dormancy_window(p, height));
        dormancy_pass(&mut attestors, &rows, p, hh32);
    }
    // write every attestor record the passes changed
    for ((seq, rec), b) in attestors.iter().zip(before.iter()) {
        if rec.encode() != *b {
            st.put_attestor(*seq, *rec);
        }
    }
    s
}
