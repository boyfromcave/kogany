// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

//! The module's derived quantities (plan §3.7, v3 plan §3.7, the in-term and quantum plans): the
//! Rust face of ycash6 `src/yellowback/math.h`, function for function and bit for bit.
//!
//! Integer only. Every product the C++ takes in `arith_uint256` is taken in [`U256`] here, with the
//! same wrapping (modulo 2^256) where the C++ could wrap; `int64_t` arithmetic is `i64`/`i128`
//! with `checked_*`, `saturating_*` or `wrapping_*` spelled out. Floor division unless a ceiling
//! is written; "undefined" is `None`. Nothing here reads the chain, the clock or configuration.
//!
//! Where the C++ has undefined behaviour (signed overflow on inputs no caller can produce, such as
//! a debt above `i64::MAX / i32::MAX`), the Rust result is documented on the function; inside the
//! domain the module passes (debts up to `max_mint`, prices in `[PRICE_MIN, PRICE_MAX]`, amounts
//! in `MoneyRange`) every function equals the C++ exactly. `testdata/yellowback/
//! yellowback_math_cases.json`, computed in exact rationals from the spec text, pins that.

mod u256;

pub use u256::U256;

use crate::params::{money_range, Amount, Cents, MicroUsd, Params, COIN, MAX_MONEY};

/// Basis points in one (`BPS`).
pub const BPS: i64 = 10_000;

/// The wallet's collateral rounding (`RequiredCollateralRounded`'s default granularity, §3.5).
pub const DEFAULT_COLLATERAL_GRANULARITY: Amount = 1000;

/// [`U256`] of [`BPS`].
const BPS_U256: U256 = U256::from_u64(BPS as u64); // BPS is the positive constant 10^4
/// [`U256`] of [`COIN`].
const COIN_U256: U256 = U256::from_u64(COIN as u64); // COIN is the positive constant 10^8

/// `ceil(a / b)` as `(a + b - 1) / b` modulo 2^256 (`CeilDiv`); `None` for `b == 0`.
pub fn ceil_div(a: U256, b: U256) -> Option<U256> {
    a.wrapping_add(b).wrapping_sub(U256::ONE).checked_div(b)
}

/// `FitsInt64`: `a.bits() <= 63`.
pub fn fits_i64(a: &U256) -> bool {
    a.bits() <= 63
}

/// The value as an `i64` in `MoneyRange`, else `None`.
fn to_money(a: &U256) -> Option<Amount> {
    a.to_i64().filter(|z| money_range(*z))
}

/// `U256` from a value the caller has checked is non-negative.
fn u(v: i64) -> U256 {
    U256::from_i64(v)
}

// ---------------------------------------------------------------- v2 (§3.7)

/// PRICE-1 `lowerMedian(S)`: the element at index `floor((n - 1) / 2)` of the ascending sort (the
/// smaller middle value for even `n`, M1); `None` if empty.
pub fn lower_median(values: &[MicroUsd]) -> Option<MicroUsd> {
    let mut v = values.to_vec();
    v.sort_unstable();
    let mid = v.len().checked_sub(1)? / 2;
    v.get(mid).copied()
}

/// `IsqrtU256`: the floor square root, bit by bit over bits 127..0 (the root of any 256-bit value
/// is below 2^128, so `t * t` never wraps).
pub fn isqrt_u256(x: U256) -> U256 {
    let mut r = U256::ZERO;
    for bit in (0..128u32).rev() {
        let t = r.bit_or(U256::ONE.wrapping_shl(bit));
        if t.wrapping_mul(t) <= x {
            r = t;
        }
    }
    r
}

/// SIGMA-1 (V17): the volatility multiplier in basis points from the `P_fast` series
/// `s_0..s_n` (`s_0` the newest): `r_k = |s_k - s_{k+1}| * 10^4 / s_{k+1}`,
/// `var = sum r_k^2 / n`, `sigmaAnnualBps = isqrt(var * periodsPerYear)`, result
/// `clamp(sigmaAnnualBps * 10^4 / sigmaRefBps, 10^4, maxBps)`. `sigma_ref_bps <= 0` fixes it at
/// 10^4; an undefined or non-positive sample, or fewer than two, gives `max(max_bps, 10^4)` (K12).
pub fn sigma_mult_bps(
    samples: &[Option<MicroUsd>],
    sigma_ref_bps: i32,
    periods_per_year: i32,
    max_bps: i32,
) -> i32 {
    const ONE_X: i32 = BPS as i32; // 10^4 fits i32
    if sigma_ref_bps <= 0 {
        return ONE_X;
    }
    let max_bps = max_bps.max(ONE_X);
    if samples.len() < 2 {
        return max_bps;
    }
    let mut defined: Vec<MicroUsd> = Vec::with_capacity(samples.len());
    for s in samples {
        match s {
            Some(v) if *v > 0 => defined.push(*v),
            _ => return max_bps,
        }
    }
    let mut sum_sq = U256::ZERO;
    let mut n: u64 = 0;
    for pair in defined.windows(2) {
        let (Some(a), Some(b)) = (pair.first(), pair.get(1)) else {
            continue;
        };
        // a, b > 0, so |a - b| < i64::MAX.
        let diff = u(a.abs_diff(*b) as i64); // abs_diff of two positive i64 fits i64
        let r = diff
            .wrapping_mul(BPS_U256)
            .checked_div(u(*b))
            .unwrap_or(U256::ZERO);
        sum_sq = sum_sq.wrapping_add(r.wrapping_mul(r));
        n = n.wrapping_add(1);
    }
    let var = sum_sq.checked_div(U256::from_u64(n)).unwrap_or(U256::ZERO);
    let ppy = U256::from_u64(u64::try_from(periods_per_year.max(0)).unwrap_or(0));
    let sigma_annual = isqrt_u256(var.wrapping_mul(ppy));
    let sigma_ref = U256::from_u64(u64::try_from(sigma_ref_bps).unwrap_or(1));
    let mult = sigma_annual
        .wrapping_mul(BPS_U256)
        .checked_div(sigma_ref)
        .unwrap_or(U256::ZERO);
    let max_u = U256::from_u64(u64::try_from(max_bps).unwrap_or(0));
    if mult >= max_u {
        return max_bps;
    }
    if mult <= BPS_U256 {
        return ONE_X;
    }
    // 10^4 < mult < max_bps <= i32::MAX
    i32::try_from(mult.low_u64()).unwrap_or(max_bps)
}

/// MINT-5 `minRatioBps = baseRatioBps * sigmaMultBps / 10^4` (floor); 0 for a non-positive input.
/// The quotient is truncated to 32 bits as the C++ `(int)` cast does (unreachable: ratios are
/// below 2^31 / 10^4 times each other in every column).
pub fn min_ratio_bps(base_ratio_bps: i32, sigma_mult_bps: i32) -> i32 {
    if base_ratio_bps <= 0 || sigma_mult_bps <= 0 {
        return 0;
    }
    // Both factors are in (0, 2^31): the product is below 2^62 and cannot overflow.
    let q = i64::from(base_ratio_bps).wrapping_mul(i64::from(sigma_mult_bps)) / BPS;
    q as i32 // the C++ (int) truncation, kept bit for bit
}

/// MINT-5 `requiredZat = ceil(cents * minRatioBps * COIN / pMint)`; `None` when an input is not
/// positive or the result exceeds `MAX_MONEY` (K14).
pub fn required_collateral(cents: Cents, min_ratio_bps: i32, p_mint: MicroUsd) -> Option<Amount> {
    if cents <= 0 || min_ratio_bps <= 0 || p_mint <= 0 {
        return None;
    }
    let num = u(cents)
        .wrapping_mul(u(min_ratio_bps.into()))
        .wrapping_mul(COIN_U256);
    to_money(&ceil_div(num, u(p_mint))?)
}

/// [`required_collateral`] rounded up to a multiple of `granularity` zat (the wallet uses
/// [`DEFAULT_COLLATERAL_GRANULARITY`]); a non-positive granularity returns it unrounded.
pub fn required_collateral_rounded(
    cents: Cents,
    min_ratio_bps: i32,
    p_mint: MicroUsd,
    granularity: Amount,
) -> Option<Amount> {
    let z = required_collateral(cents, min_ratio_bps, p_mint)?;
    if granularity <= 0 {
        return Some(z);
    }
    let rem = z.checked_rem(granularity)?;
    let z = if rem != 0 {
        z.checked_add(granularity.checked_sub(rem)?)?
    } else {
        z
    };
    Some(z).filter(|z| money_range(*z))
}

/// MINT-6 `capCents = issuedZat * pMint / (COIN * 10^4)`: the market capitalisation in cents
/// (D-Q-25); `None` for an undefined price, a negative issuance or a result above `i64::MAX`.
pub fn cap_cents(issued_zat: Amount, p_mint: Option<MicroUsd>) -> Option<Cents> {
    let p = p_mint.filter(|p| *p > 0)?;
    if issued_zat < 0 {
        return None;
    }
    let c = u(issued_zat)
        .wrapping_mul(u(p))
        .checked_div(COIN_U256.wrapping_mul(BPS_U256))?;
    c.to_i64()
}

/// MINT-6 `supplyCapCents = capCents * capBps / 10^4`; `None` for `cap_bps <= 0` (no cap) or an
/// undefined cap.
pub fn supply_cap_cents(
    issued_zat: Amount,
    p_mint: Option<MicroUsd>,
    cap_bps: i32,
) -> Option<Cents> {
    if cap_bps <= 0 {
        return None;
    }
    let cap = cap_cents(issued_zat, p_mint)?;
    u(cap)
        .wrapping_mul(u(cap_bps.into()))
        .checked_div(BPS_U256)?
        .to_i64()
}

/// HALT-2 `globalRatioBps = collateralZat * pMint / (COIN * supplyCents)`; `None` for no supply
/// (never halts), an undefined price, negative collateral or a result above `i64::MAX`. HALT-2
/// passes `Totals.openDebtCents` as `supply_cents` (2026-10-28).
pub fn global_ratio_bps(
    collateral_zat: Amount,
    p_mint: Option<MicroUsd>,
    supply_cents: Cents,
) -> Option<i64> {
    let p = p_mint.filter(|p| *p > 0)?;
    if supply_cents <= 0 || collateral_zat < 0 {
        return None;
    }
    let r = u(collateral_zat)
        .wrapping_mul(u(p))
        .checked_div(COIN_U256.wrapping_mul(u(supply_cents)))?;
    r.to_i64()
}

/// RED-4 claimable: `collateralZat * pClaim < mintedCents * thresholdBps * COIN`; false for an
/// undefined price (M1), no debt or a non-positive threshold. Negative collateral counts as 0.
pub fn is_underwater(
    collateral_zat: Amount,
    p_claim: Option<MicroUsd>,
    minted_cents: Cents,
    threshold_bps: i32,
) -> bool {
    let Some(p) = p_claim.filter(|p| *p > 0) else {
        return false;
    };
    if minted_cents <= 0 || threshold_bps <= 0 {
        return false;
    }
    let lhs = u(collateral_zat.max(0)).wrapping_mul(u(p));
    let rhs = u(minted_cents)
        .wrapping_mul(u(threshold_bps.into()))
        .wrapping_mul(COIN_U256);
    lhs < rhs
}

/// FEE-1′ (D-Q-23, fees spec §1.3): the protocol fee in cent-bps — the sum over the bands of (the
/// debt inside the band) x the band's bps (a negative rate counts as 0), then at least
/// `fee_floor_cents x 10^4`; 0 for no debt. The band walk is the C++ loop's, unusual tables
/// included. Exact for every debt the module passes (at most `max_mint`); the C++ overflows
/// `int64_t` only past ~4 x 10^9 dollars at 10^4 bps, where this saturates at `i64::MAX`.
pub fn protocol_fee_units(debt_cents: Cents, p: &Params) -> i64 {
    if debt_cents <= 0 {
        return 0;
    }
    let debt = i128::from(debt_cents);
    let mut units: i128 = 0;
    let mut lo: i128 = 0;
    for band in &p.fee_bands {
        let hi = i128::from(band.upto_cents); // 0 = unbounded
        let in_band = if hi == 0 { debt } else { debt.min(hi) }.saturating_sub(lo);
        if in_band <= 0 {
            break;
        }
        units = units.saturating_add(in_band.saturating_mul(i128::from(band.bps.max(0))));
        lo = hi;
    }
    let floor = i128::from(p.fee_floor_cents.max(0)).saturating_mul(i128::from(BPS));
    i64::try_from(units.max(floor)).unwrap_or(i64::MAX)
}

/// FEE-1′ for display and RPC: `ceil(units / 10^4)` cents.
pub fn protocol_fee_cents(debt_cents: Cents, p: &Params) -> Cents {
    let units = i128::from(protocol_fee_units(debt_cents, p));
    let cents = units
        .saturating_add(i128::from(BPS).saturating_sub(1))
        .checked_div(i128::from(BPS))
        .unwrap_or(0);
    i64::try_from(cents).unwrap_or(i64::MAX)
}

/// FEE-1′ in zat at the vault's mint price: `ceil(units x COIN / pMint)`; `None` for an undefined
/// price (`p_mint <= 0`); `MAX_MONEY` when the quotient is outside `MoneyRange` (unreachable for a
/// vault that exists, fees spec §1.6).
pub fn protocol_fee_zat(debt_cents: Cents, p_mint: MicroUsd, p: &Params) -> Option<Amount> {
    if p_mint <= 0 {
        return None;
    }
    let units = u(protocol_fee_units(debt_cents, p)); // >= 0
    let f = ceil_div(units.wrapping_mul(COIN_U256), u(p_mint))?;
    Some(to_money(&f).unwrap_or(MAX_MONEY))
}

/// IT-9′ (D-Q-23): the early-redeem fee, `ceil(debt x bps x COIN / pMint)`, no floor; 0 when an
/// input is not positive (the caller tests `height < lockHeight`); `MAX_MONEY` when the quotient is
/// outside `MoneyRange`.
pub fn early_redeem_fee_zat(
    debt_cents: Cents,
    early_redeem_fee_bps: i32,
    p_mint: MicroUsd,
) -> Amount {
    if debt_cents <= 0 || early_redeem_fee_bps <= 0 || p_mint <= 0 {
        return 0;
    }
    let num = u(debt_cents)
        .wrapping_mul(u(early_redeem_fee_bps.into()))
        .wrapping_mul(COIN_U256);
    ceil_div(num, u(p_mint))
        .as_ref()
        .and_then(to_money)
        .unwrap_or(MAX_MONEY)
}

// ---------------------------------------------------------------- v3 (v3 plan §3.7)

/// BUNDLE-1 bond weight `bondZat * clamp(ageBlocks, 0, ageCap)` (R10); 0 for any non-positive input.
pub fn bond_weight(bond_zat: Amount, age_blocks: i64, age_cap: i32) -> U256 {
    if bond_zat <= 0 || age_blocks <= 0 || age_cap <= 0 {
        return U256::ZERO;
    }
    let age = age_blocks.min(i64::from(age_cap));
    u(bond_zat).wrapping_mul(u(age))
}

/// `Log2Q16`: `log2(x)` in Q16 for `x >= 1` (0 for 0), deterministic but not exact — the bit
/// length minus one, then 16 fraction bits from squaring the Q31 mantissa (truncating) in `u64`.
/// The result is `floor(log2(x) x 2^16)` or one below it; every node and the Python model
/// (`seat_age_factor_q16`) compute these same bits.
pub fn log2_q16(x: u64) -> u32 {
    if x == 0 {
        return 0;
    }
    let n: u32 = 63u32.wrapping_sub(x.leading_zeros()); // x != 0: leading_zeros <= 63
    let mut m: u64 = if n <= 31 {
        x.wrapping_shl(31u32.wrapping_sub(n))
    } else {
        x.wrapping_shr(n.wrapping_sub(31))
    };
    let mut frac: u32 = 0;
    for _ in 0..16 {
        // m in [2^31, 2^32): m * m < 2^64.
        m = m.wrapping_mul(m) >> 31;
        frac = frac.wrapping_shl(1);
        if m >= (1u64 << 32) {
            m >>= 1;
            frac |= 1;
        }
    }
    n.wrapping_shl(16) | frac
}

/// The seat-tenure factor in Q16 (2026-10-11): 65,536 at no tenure, rising with log2 to
/// 65,536 + 58,982 (1.9) at `cap`:
/// `65536 + floor(9 x 65536 x (lg(u + a) - lg(u)) / (10 x (lg(u + cap) - lg(u))))`,
/// `a = clamp(ageBlocks, 0, cap)`, `lg` = [`log2_q16`]. 65,536 when `u` or `cap` is not positive.
/// The `uint64_t`/`uint32_t` steps wrap as the C++ unsigned arithmetic does.
pub fn seat_age_factor_q16(age_blocks: i64, u_blocks: i64, cap: i64) -> u32 {
    if u_blocks <= 0 || cap <= 0 {
        return 65_536;
    }
    let a = age_blocks.min(cap).max(0);
    let lu = u64::from(log2_q16(u_blocks as u64)); // u_blocks > 0
                                                   // u + a and u + cap: positive i64 sums; the C++ (uint64_t) cast of the sum is mirrored.
    let num = u64::from(log2_q16(u_blocks.wrapping_add(a) as u64)).wrapping_sub(lu);
    let den = u64::from(log2_q16(u_blocks.wrapping_add(cap) as u64)).wrapping_sub(lu);
    if den == 0 {
        return 65_536;
    }
    let q = 9u64
        .wrapping_mul(65_536)
        .wrapping_mul(num)
        .checked_div(10u64.wrapping_mul(den))
        .unwrap_or(0);
    65_536u32.wrapping_add(q as u32) // the C++ (uint32_t) truncation; q <= 58,982 in range
}

/// The seat weight (2026-10-11): `bondZat x SeatAgeFactorQ16(ageBlocks)`, which ranks seats and
/// picks an eviction victim only (the price statistic and W9 keep [`bond_weight`]); 0 for a bond
/// `<= 0`.
pub fn seat_weight(bond_zat: Amount, age_blocks: i64, u_blocks: i64, cap: i64) -> U256 {
    if bond_zat <= 0 {
        return U256::ZERO;
    }
    u(bond_zat).wrapping_mul(U256::from_u64(
        seat_age_factor_q16(age_blocks, u_blocks, cap).into(),
    ))
}

/// One attestation of a verified bundle as the bundle statistic sees it (`WeightedPrice`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WeightedPrice {
    /// The attested price.
    pub price: MicroUsd,
    /// Its weight ([`bond_weight`]).
    pub weight: U256,
}

impl WeightedPrice {
    /// A weighted price.
    pub fn new(price: MicroUsd, weight: U256) -> WeightedPrice {
        WeightedPrice { price, weight }
    }
}

/// PRICE-2 / BUNDLE-1 bundle statistic: over the entries stable-sorted by price (ties keep the
/// caller's order), the price at which the cumulative weight first reaches
/// `ceil(qBps * total / 10^4)`. `None` for no entries or a threshold above the total
/// (`q_bps > 10^4`); a negative `q_bps` reads as 0; a zero total gives the first price.
pub fn weighted_quantile(entries: &[WeightedPrice], q_bps: i32) -> Option<MicroUsd> {
    if entries.is_empty() {
        return None;
    }
    let q = U256::from_u64(u64::try_from(q_bps.max(0)).unwrap_or(0));
    let mut sorted = entries.to_vec();
    sorted.sort_by_key(|e| e.price); // stable
    let total = sorted
        .iter()
        .fold(U256::ZERO, |acc, e| acc.wrapping_add(e.weight));
    let threshold = ceil_div(total.wrapping_mul(q), BPS_U256)?;
    let mut cumulative = U256::ZERO;
    for e in &sorted {
        cumulative = cumulative.wrapping_add(e.weight);
        if cumulative >= threshold {
            return Some(e.price);
        }
    }
    None
}

/// RED-5 `claimantMaxZat = ceil(mintedCents * marginBps * COIN / price)`: `marginBps` is θ under
/// RED-4(a) at `pClaim`, 10^4 under (b) at `pEmerg`. `None` for a non-positive input or a result
/// above `MAX_MONEY`, which RED-5 reads as residual 0.
pub fn claimant_max_zat(minted_cents: Cents, margin_bps: i32, price: MicroUsd) -> Option<Amount> {
    if minted_cents <= 0 || margin_bps <= 0 || price <= 0 {
        return None;
    }
    let num = u(minted_cents)
        .wrapping_mul(u(margin_bps.into()))
        .wrapping_mul(COIN_U256);
    to_money(&ceil_div(num, u(price))?)
}

/// RED-5′ (D-Q-23a): the residual threshold,
/// `max(residualMinZat, ceil(residualMinCents x 10^4 x COIN / pMint))`; the floor alone for an
/// undefined price, no dollar threshold, or a quotient outside `MoneyRange`.
pub fn residual_min_zat(p_mint: MicroUsd, p: &Params) -> Amount {
    let floor = p.residual_min_zat.max(0);
    if p_mint <= 0 || p.residual_min_cents <= 0 {
        return floor;
    }
    let num = u(p.residual_min_cents)
        .wrapping_mul(BPS_U256)
        .wrapping_mul(COIN_U256);
    match ceil_div(num, u(p_mint)).as_ref().and_then(to_money) {
        Some(z) => floor.max(z),
        None => floor,
    }
}

/// D-Q-30: the attestor bond minimum from the YEC locked in YED vaults,
/// `clamp(ceil(collateralZat x bondShareBps / (10^4 x N_SLOTS)), floor, cap)` with
/// `floor = max(0, bond_min_floor_zat)` and `cap = max(floor, bond_min_cap_zat)`. No price is read.
/// Negative collateral counts as 0; `n_slots <= 0` gives the cap.
pub fn bond_min_from_collateral_zat(collateral_zat: Amount, p: &Params) -> Amount {
    let floor = p.bond_min_floor_zat.max(0);
    let cap = floor.max(p.bond_min_cap_zat);
    if p.n_slots <= 0 {
        return cap;
    }
    let num = u(collateral_zat.max(0)).wrapping_mul(u(p.bond_share_bps.max(0).into()));
    let den = BPS_U256.wrapping_mul(u(p.n_slots.into()));
    match ceil_div(num, den).and_then(|z| z.to_i64()) {
        Some(z) if z <= cap => floor.max(z),
        _ => cap,
    }
}

/// MINT-6b (D-Q-23a): the largest debt one mint may create,
/// `max(capCents x maxVaultShareBps / 10^4, vaultShareFloorCents)` (a negative cap or floor counts
/// as 0; a share above `i64::MAX` is `i64::MAX`); `None` (no limit) for an undefined cap or a
/// share of 0.
pub fn max_vault_cents(
    cap_cents: Option<Cents>,
    max_vault_share_bps: i32,
    vault_share_floor_cents: Cents,
) -> Option<Cents> {
    let cap = cap_cents?;
    if max_vault_share_bps <= 0 {
        return None;
    }
    let s = u(cap.max(0))
        .wrapping_mul(u(max_vault_share_bps.into()))
        .checked_div(BPS_U256)?;
    let share = s.to_i64().unwrap_or(i64::MAX);
    Some(share.max(vault_share_floor_cents.max(0)))
}

/// RED-5 `residualZat = max(0, collateralZat - claimantMaxZat)`; an undefined claimant maximum
/// (above `MAX_MONEY`) leaves nothing. The difference saturates where the C++ would overflow
/// (a negative claimant maximum, which [`claimant_max_zat`] never returns).
pub fn residual_zat(collateral_zat: Amount, claimant_max_zat: Option<Amount>) -> Amount {
    match claimant_max_zat {
        Some(c) if collateral_zat > c => collateral_zat.saturating_sub(c),
        _ => 0,
    }
}

/// AFEE-1′ `attestFeeZat = feeZat * attestFeeBps / 10^4` (floor), out of FEE-1′'s protocol fee
/// (never the early fee); 0 for a non-positive input; `MAX_MONEY` if the quotient does not fit
/// `i64`.
pub fn attest_fee_zat(fee_zat: Amount, attest_fee_bps: i32) -> Amount {
    if fee_zat <= 0 || attest_fee_bps <= 0 {
        return 0;
    }
    u(fee_zat)
        .wrapping_mul(u(attest_fee_bps.into()))
        .checked_div(BPS_U256)
        .and_then(|f| f.to_i64())
        .unwrap_or(MAX_MONEY)
}

/// PRICE-2 (revised) when ARMED: the three per-transaction prices (`CombinedPrices`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CombinedPrices {
    /// `min(xMint, aMint)`.
    pub p_mint: Option<MicroUsd>,
    /// `max(xClaim, aClaim)`.
    pub p_claim: Option<MicroUsd>,
    /// `min(xClaim, aClaim)`.
    pub p_emerg: Option<MicroUsd>,
}

/// PRICE-2 `PriceCombine`: each output is undefined if either of its inputs is. Not ARMED, the
/// caller reads `x` alone.
pub fn price_combine(
    x_mint: Option<MicroUsd>,
    x_claim: Option<MicroUsd>,
    a_mint: Option<MicroUsd>,
    a_claim: Option<MicroUsd>,
) -> CombinedPrices {
    let both = |a: Option<MicroUsd>, b: Option<MicroUsd>| a.zip(b);
    CombinedPrices {
        p_mint: both(x_mint, a_mint).map(|(x, a)| x.min(a)),
        p_claim: both(x_claim, a_claim).map(|(x, a)| x.max(a)),
        p_emerg: both(x_claim, a_claim).map(|(x, a)| x.min(a)),
    }
}
