// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

//! The reference price a transaction's bundle yields, the per-block bundle log, and the
//! network-fee price: ycash6 `src/yellowback/state.cpp` `VerifyTxBundle`, `BundleFacts`,
//! `EvalContext::{Bundle, CommitBundle, BundleRow}`, and `index.{h,cpp}` `FeePriceTrusted`,
//! `PublishFeePrice` at `65cb4ae0f`.
//!
//! A rule with a reference height R (MINT-9/10, RED-1/5, NOT-1) checks R against
//! [`ref_height_in_window`], verifies the bundle at R with the selection of `Snapshots[R]`
//! ([`verify_tx_bundle`]), and reads `aMint` / `aClaim` — the [`super::bundle_stat`] quantiles
//! `Q_LOW` / `Q_HIGH` under the attestor weights at R — combined with the snapshot's window
//! prices by [`crate::math::price_combine`]. A held rule commits its bundle's facts to the
//! block's [`BundleLogAccumulator`]; the row is `BundleLog[H]`, written before SNAP.

use std::collections::BTreeSet;

use kogany_vault::state::VaultTx;
use kogany_vault::Hash32;

use super::attestation::Attestation;
use super::bundle::{
    bundle_stat, carrier_input, verify_bundle, BundleError, BundleLimits, SigCache,
};
use super::registry::{AttestState, BundleLogRecord, RegistryRead};
use super::seats::{attestor_weight, selected, SelectionBasis};
use crate::codecs::script::CarrierError;
use crate::math::{lower_median, U256};
use crate::params::{MicroUsd, Params};

/// `HALT_NOT_ACTIVE`: only the virtual snapshot below the start height.
pub const HALT_NOT_ACTIVE: u32 = 1 << 0;
/// `HALT_NO_PRICE` (HALT-1).
pub const HALT_NO_PRICE: u32 = 1 << 1;
/// `HALT_PARTICIPATION` (reserved since the vault upgrade).
pub const HALT_PARTICIPATION: u32 = 1 << 2;
/// `HALT_GLOBAL_RATIO` (HALT-2).
pub const HALT_GLOBAL_RATIO: u32 = 1 << 3;
/// `HALT_DIVERGENCE` (HALT-3).
pub const HALT_DIVERGENCE: u32 = 1 << 4;
/// `HALT_ENFORCEMENT` (reserved since the vault upgrade).
pub const HALT_ENFORCEMENT: u32 = 1 << 5;

/// `FEE_PRICE_TRUSTED_HALTS`: the halt bits under which the fee policy still trusts the price
/// (HALT-2 restricts minting only; fees spec §5.1 amendment 2026-10-28, U-27). Any other bit,
/// present or future, withholds it.
pub const FEE_PRICE_TRUSTED_HALTS: u32 = HALT_GLOBAL_RATIO;

/// `FeePriceTrusted`: no halt bit outside [`FEE_PRICE_TRUSTED_HALTS`].
pub const fn fee_price_trusted(halt_mask: u32) -> bool {
    halt_mask & !FEE_PRICE_TRUSTED_HALTS == 0
}

/// The dollar-per-KB network-fee price (D-Q-23 (b), review M-1; `PublishFeePrice`): the highest
/// of the tip snapshot's defined window medians `max(pFast, pMid, pSlow)` when
/// [`fee_price_trusted`], else `None` (the `-pqfeerate` fallback). Node policy only: nothing in
/// block validity reads it. The caller passes `None` for no tip, a tip below the start height, or
/// an unhealthy index.
pub fn attested_fee_price(
    p_fast: Option<MicroUsd>,
    p_mid: Option<MicroUsd>,
    p_slow: Option<MicroUsd>,
    halt_mask: u32,
) -> Option<MicroUsd> {
    if !fee_price_trusted(halt_mask) {
        return None;
    }
    [p_fast, p_mid, p_slow].into_iter().flatten().max()
}

/// A rule's reference height window: `H - REF_WINDOW <= R <= H - 1` and `R >= START_HEIGHT`
/// (NOT-1, MINT-2, RED-1).
pub fn ref_height_in_window(p: &Params, height: i64, r: i64) -> bool {
    height.saturating_sub(i64::from(p.ref_window)) <= r
        && r <= height.saturating_sub(1)
        && r >= i64::from(p.start_height)
}

/// A bundle that passed BUNDLE-1 at R, with its statistic (`BundleVerdict` with `ok`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct VerifiedBundle {
    /// The verified attestations, bundle order.
    pub c: Vec<Attestation>,
    /// `aMint`: the `Q_LOW` weighted quantile; `None` when undefined.
    pub a_mint: Option<MicroUsd>,
    /// `aClaim`: the `Q_HIGH` weighted quantile.
    pub a_claim: Option<MicroUsd>,
}

/// `VerifyTxBundle`: BUNDLE-1 for a transaction with reference height `ref_height`
/// ([`verify_bundle`] with `Selected(R, selector)`, the set's limits, the `Attestors` keys and the
/// index's block hashes), then the bundle statistic under [`attestor_weight`] at R and
/// `Snapshots[R].attest` (a seq without a record weighs 0). `basis` is `Snapshots[R]`'s selection
/// inputs (`None` when missing or virtual); `block_hash_at` is the C++ `BlockHashAt` (the stored,
/// non-virtual snapshot's hash). Returns `selected(R, selector)` too (BundleLog's
/// `selectedSeqs`, the TxLog). Total.
#[allow(clippy::too_many_arguments)]
pub fn verify_tx_bundle(
    tx: &VaultTx,
    p: &Params,
    ref_height: i64,
    selector: &[u8],
    skip_vin0: bool,
    basis: Option<&SelectionBasis>,
    reg: &dyn RegistryRead,
    block_hash_at: &dyn Fn(i64) -> Option<Hash32>,
    cache: Option<&dyn SigCache>,
) -> (Vec<u16>, Result<VerifiedBundle, BundleError>) {
    let sel = selected(basis, reg, p, ref_height, selector);
    let limits = BundleLimits::from_params(p);
    let pubkey_of = |seq: u16| reg.attestor(seq).map(|r| r.attestor_pub_key);
    let verdict = verify_bundle(
        tx,
        p.bundle_carrier,
        skip_vin0,
        &[],
        ref_height,
        &sel,
        &limits,
        Some(&pubkey_of),
        Some(block_hash_at),
        cache,
    );
    let out = verdict.map(|c| {
        let attest = if ref_height >= i64::from(p.start_height) && ref_height >= 0 {
            basis.map(|b| b.attest).unwrap_or_default()
        } else {
            AttestState::default()
        };
        let weights: Vec<U256> = c
            .iter()
            .map(|a| {
                reg.attestor(a.seq).map_or(U256::ZERO, |rec| {
                    attestor_weight(&rec, &attest, p, ref_height)
                })
            })
            .collect();
        let (a_mint, a_claim) =
            bundle_stat(&c, &weights, limits.m_select, p.q_low_bps, p.q_high_bps);
        VerifiedBundle { c, a_mint, a_claim }
    });
    (sel, out)
}

/// What a transaction's bundle contributes to `BundleLog[H]` (R12) and to its TxLog entry
/// (`BundleFacts`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BundleFacts {
    /// Some carrier-shaped input exists (MINT-9's "no bundle" vs "bundle-<reason>").
    pub carrier_present: bool,
    /// `selected(R, selector)`.
    pub selected: Vec<u16>,
    /// The BUNDLE-1 verdict and statistic.
    pub verdict: Result<VerifiedBundle, BundleError>,
}

impl BundleFacts {
    /// BUNDLE-1 held.
    pub fn verified(&self) -> bool {
        self.verdict.is_ok()
    }

    /// The verified seqs in bundle order (the TxLog's `bundleSeqs`); empty unless verified.
    pub fn seqs(&self) -> Vec<u16> {
        self.verdict
            .as_ref()
            .map(|v| v.c.iter().map(|a| a.seq).collect())
            .unwrap_or_default()
    }
}

/// `EvalContext::Bundle`: [`verify_tx_bundle`] plus whether a carrier input is present. Nothing
/// is recorded: the calling rule commits the facts once it holds ([`BundleLogAccumulator::commit`],
/// R12 as hardened, audit 03/M-2).
#[allow(clippy::too_many_arguments)]
pub fn bundle_facts(
    tx: &VaultTx,
    p: &Params,
    ref_height: i64,
    selector: &[u8],
    skip_vin0: bool,
    basis: Option<&SelectionBasis>,
    reg: &dyn RegistryRead,
    block_hash_at: &dyn Fn(i64) -> Option<Hash32>,
    cache: Option<&dyn SigCache>,
) -> BundleFacts {
    let carrier_present = !matches!(carrier_input(tx, skip_vin0), Err(CarrierError::Shape));
    let (selected, verdict) = verify_tx_bundle(
        tx,
        p,
        ref_height,
        selector,
        skip_vin0,
        basis,
        reg,
        block_hash_at,
        cache,
    );
    BundleFacts {
        carrier_present,
        selected,
        verdict,
    }
}

/// The `BundleLog[H]` accumulator of one block evaluation (R12): flushed before SNAP.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BundleLogAccumulator {
    any: bool,
    a_mints: Vec<MicroUsd>,
    a_claims: Vec<MicroUsd>,
    selected: BTreeSet<u16>,
    pairs: BTreeSet<(u16, i64, u32)>,
}

impl BundleLogAccumulator {
    /// An empty accumulator.
    pub fn new() -> BundleLogAccumulator {
        BundleLogAccumulator::default()
    }

    /// `CommitBundle`: a verified bundle of a held MINT, REDEEM or CLAIM_NOTICE enters the row
    /// (a failed one is ignored).
    pub fn commit(&mut self, f: &BundleFacts) {
        let Ok(v) = &f.verdict else {
            return;
        };
        self.any = true;
        self.a_mints.extend(v.a_mint);
        self.a_claims.extend(v.a_claim);
        self.selected.extend(f.selected.iter().copied());
        self.pairs.extend(
            v.c.iter()
                .map(|a| (a.seq, MicroUsd::from(a.price_micro_usd), a.cited_height)),
        );
    }

    /// `BundleRow`: `BundleLog[H]`, `None` when no bundle was committed. `aMint` / `aClaim` are
    /// the lower medians (0 = undefined); the selected union and the `(seq, price, citedHeight)`
    /// union sorted ascending.
    pub fn row(&self) -> Option<BundleLogRecord> {
        if !self.any {
            return None;
        }
        Some(BundleLogRecord {
            a_mint: lower_median(&self.a_mints).unwrap_or(0),
            a_claim: lower_median(&self.a_claims).unwrap_or(0),
            selected_seqs: self.selected.iter().copied().collect(),
            seqs: self.pairs.iter().map(|(s, _, _)| *s).collect(),
            prices: self.pairs.iter().map(|(_, p, _)| *p).collect(),
            cited_heights: self.pairs.iter().map(|(_, _, h)| *h).collect(),
        })
    }
}
