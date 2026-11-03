// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

//! [`U256`], the unsigned 256-bit integer the module's products are taken in: the Rust face of
//! ycash6 `src/arith_uint256.h` as `src/yellowback/math.h` uses it.
//!
//! `arith_uint256`'s `+`, `-`, `*` and `<<` wrap modulo 2^256 and its division throws on a zero
//! divisor. Here the wrapping operations are spelled out (`wrapping_*`), so the byte-exact
//! behaviour of the C++ type is kept even where a product could wrap, and division is
//! [`U256::checked_div`], `None` for a zero divisor. No operator is overloaded: every
//! arithmetic step is visible at the call site.

use core::cmp::Ordering;

/// Number of 64-bit limbs.
const LIMBS: usize = 4;

/// An unsigned 256-bit integer, four 64-bit limbs, least significant first (`arith_uint256`'s
/// `pn[]` order, 32-bit limbs paired).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct U256([u64; LIMBS]);

impl U256 {
    /// Zero.
    pub const ZERO: U256 = U256([0, 0, 0, 0]);
    /// One.
    pub const ONE: U256 = U256([1, 0, 0, 0]);
    /// 2^256 - 1 (`~arith_uint256(0)`).
    pub const MAX: U256 = U256([u64::MAX, u64::MAX, u64::MAX, u64::MAX]);

    /// From a `u64` (`arith_uint256(uint64_t)`).
    pub const fn from_u64(v: u64) -> U256 {
        U256([v, 0, 0, 0])
    }

    /// From a `u128`.
    pub const fn from_u128(v: u128) -> U256 {
        // The two casts take the low and the high 64 bits: truncation is the intent.
        U256([v as u64, (v >> 64) as u64, 0, 0])
    }

    /// From an `i64` exactly as C++ converts it to the `uint64_t` constructor argument: a
    /// negative value becomes `2^64 + v`. Every caller in this crate passes a value it has
    /// already checked to be non-negative; the conversion is spelled out so that it matches
    /// `arith_uint256(int64_t)` in every case.
    pub const fn from_i64(v: i64) -> U256 {
        U256::from_u64(v as u64) // two's complement reinterpretation, as C++ int64_t -> uint64_t
    }

    /// The limbs, least significant first.
    pub const fn limbs(&self) -> [u64; LIMBS] {
        self.0
    }

    /// From limbs, least significant first.
    pub const fn from_limbs(limbs: [u64; LIMBS]) -> U256 {
        U256(limbs)
    }

    /// The 32 bytes little-endian (`arith_uint256`'s memory order, `ArithToUint256`).
    pub fn to_le_bytes(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        for (chunk, limb) in out.as_chunks_mut::<8>().0.iter_mut().zip(self.0.iter()) {
            *chunk = limb.to_le_bytes();
        }
        out
    }

    /// From 32 bytes little-endian (`UintToArith256`).
    pub fn from_le_bytes(bytes: [u8; 32]) -> U256 {
        let mut limbs = [0u64; LIMBS];
        for (limb, chunk) in limbs.iter_mut().zip(bytes.as_chunks::<8>().0.iter()) {
            *limb = u64::from_le_bytes(*chunk);
        }
        U256(limbs)
    }

    /// True iff zero.
    pub fn is_zero(&self) -> bool {
        self.0 == [0, 0, 0, 0]
    }

    /// The low 64 bits (`GetLow64`).
    pub const fn low_u64(&self) -> u64 {
        self.0[0]
    }

    /// The position of the highest set bit plus one, 0 for zero (`arith_uint256::bits()`).
    pub fn bits(&self) -> u32 {
        let mut bits = 256u32;
        for limb in self.0.iter().rev() {
            if *limb != 0 {
                return bits.saturating_sub(limb.leading_zeros());
            }
            bits = bits.saturating_sub(64);
        }
        0
    }

    /// The value as an `i64` when it fits (`FitsInt64`: `bits() <= 63`).
    pub fn to_i64(&self) -> Option<i64> {
        if self.bits() <= 63 {
            i64::try_from(self.low_u64()).ok()
        } else {
            None
        }
    }

    /// The value as a `u64` when it fits.
    pub fn to_u64(&self) -> Option<u64> {
        if self.bits() <= 64 {
            Some(self.low_u64())
        } else {
            None
        }
    }

    /// `self + rhs` modulo 2^256 (`arith_uint256::operator+`).
    pub fn wrapping_add(self, rhs: U256) -> U256 {
        let mut out = [0u64; LIMBS];
        let mut carry = false;
        for ((o, a), b) in out.iter_mut().zip(self.0.iter()).zip(rhs.0.iter()) {
            let (s1, c1) = a.overflowing_add(*b);
            let (s2, c2) = s1.overflowing_add(u64::from(carry));
            *o = s2;
            carry = c1 || c2;
        }
        U256(out)
    }

    /// `self + rhs`, `None` on overflow past 2^256.
    pub fn checked_add(self, rhs: U256) -> Option<U256> {
        let s = self.wrapping_add(rhs);
        if s < self {
            None
        } else {
            Some(s)
        }
    }

    /// `self - rhs` modulo 2^256 (`arith_uint256::operator-`).
    pub fn wrapping_sub(self, rhs: U256) -> U256 {
        let mut out = [0u64; LIMBS];
        let mut borrow = false;
        for ((o, a), b) in out.iter_mut().zip(self.0.iter()).zip(rhs.0.iter()) {
            let (d1, b1) = a.overflowing_sub(*b);
            let (d2, b2) = d1.overflowing_sub(u64::from(borrow));
            *o = d2;
            borrow = b1 || b2;
        }
        U256(out)
    }

    /// `self - rhs`, `None` when `rhs > self`.
    pub fn checked_sub(self, rhs: U256) -> Option<U256> {
        if rhs > self {
            None
        } else {
            Some(self.wrapping_sub(rhs))
        }
    }

    /// `self * rhs` modulo 2^256 (`arith_uint256::operator*`, schoolbook on the low limbs).
    pub fn wrapping_mul(self, rhs: U256) -> U256 {
        let mut out = [0u64; LIMBS];
        for (i, a) in self.0.iter().enumerate() {
            let mut carry: u128 = 0;
            for (j, b) in rhs.0.iter().enumerate() {
                let k = i.wrapping_add(j);
                let Some(slot) = out.get_mut(k) else { break };
                // a * b + slot + carry < 2^128: (2^64 - 1)^2 + 2 (2^64 - 1) = 2^128 - 1.
                let t = u128::from(*a)
                    .wrapping_mul(u128::from(*b))
                    .wrapping_add(u128::from(*slot))
                    .wrapping_add(carry);
                *slot = t as u64; // the low 64 bits; the high ones carry
                carry = t >> 64;
            }
        }
        U256(out)
    }

    /// `self * rhs`, `None` on overflow past 2^256.
    pub fn checked_mul(self, rhs: U256) -> Option<U256> {
        if self.is_zero() || rhs.is_zero() {
            return Some(U256::ZERO);
        }
        if self.bits().saturating_add(rhs.bits()) > 257 {
            return None;
        }
        let p = self.wrapping_mul(rhs);
        // bits(a) + bits(b) <= 257 leaves at most one bit of doubt: check by dividing back.
        match p.checked_div(rhs) {
            Some(q) if q == self => Some(p),
            _ => None,
        }
    }

    /// `self << shift` modulo 2^256; 0 for `shift >= 256` (`arith_uint256::operator<<`).
    pub fn wrapping_shl(self, shift: u32) -> U256 {
        if shift >= 256 {
            return U256::ZERO;
        }
        let limb_shift = (shift / 64) as usize; // shift < 256: at most 3
        let bit_shift = shift % 64;
        let mut out = [0u64; LIMBS];
        for (i, o) in out.iter_mut().enumerate() {
            let Some(src) = i.checked_sub(limb_shift) else {
                continue;
            };
            let lo = self.0.get(src).copied().unwrap_or(0);
            let carry_in = match src.checked_sub(1) {
                Some(prev) if bit_shift != 0 => {
                    self.0.get(prev).copied().unwrap_or(0) >> 64u32.wrapping_sub(bit_shift)
                }
                _ => 0,
            };
            *o = (lo << bit_shift) | carry_in;
        }
        U256(out)
    }

    /// `self >> shift`; 0 for `shift >= 256` (`arith_uint256::operator>>`).
    pub fn wrapping_shr(self, shift: u32) -> U256 {
        if shift >= 256 {
            return U256::ZERO;
        }
        let limb_shift = (shift / 64) as usize; // shift < 256: at most 3
        let bit_shift = shift % 64;
        let mut out = [0u64; LIMBS];
        for (i, o) in out.iter_mut().enumerate() {
            let src = i.wrapping_add(limb_shift);
            let Some(hi) = self.0.get(src).copied() else {
                continue;
            };
            let carry_in = match self.0.get(src.wrapping_add(1)) {
                Some(next) if bit_shift != 0 => *next << 64u32.wrapping_sub(bit_shift),
                _ => 0,
            };
            *o = (hi >> bit_shift) | carry_in;
        }
        U256(out)
    }

    /// Bitwise or.
    pub fn bit_or(self, rhs: U256) -> U256 {
        U256([
            self.0[0] | rhs.0[0],
            self.0[1] | rhs.0[1],
            self.0[2] | rhs.0[2],
            self.0[3] | rhs.0[3],
        ])
    }

    /// Bitwise not (`arith_uint256::operator~`).
    pub fn bit_not(self) -> U256 {
        U256([!self.0[0], !self.0[1], !self.0[2], !self.0[3]])
    }

    /// Bit `i` (0 = least significant); false for `i >= 256`.
    fn bit(&self, i: u32) -> bool {
        self.0
            .get((i / 64) as usize) // a u32 / 64 fits usize
            .is_some_and(|limb| (limb >> (i % 64)) & 1 == 1)
    }

    /// Quotient and remainder (`arith_uint256::operator/` is the quotient of the same shift-and-
    /// subtract long division); `None` for a zero divisor, where `arith_uint256` throws.
    pub fn checked_div_rem(self, divisor: U256) -> Option<(U256, U256)> {
        if divisor.is_zero() {
            return None;
        }
        if self < divisor {
            return Some((U256::ZERO, self));
        }
        let mut quotient = U256::ZERO;
        let mut rem = U256::ZERO;
        for i in (0..self.bits()).rev() {
            // rem < divisor <= 2^256 - 1, so a shifted-out top bit means rem >= divisor.
            let top = rem.bit(255);
            rem = rem.wrapping_shl(1);
            if self.bit(i) {
                rem = rem.bit_or(U256::ONE);
            }
            if top || rem >= divisor {
                rem = rem.wrapping_sub(divisor);
                quotient = quotient.bit_or(U256::ONE.wrapping_shl(i));
            }
        }
        Some((quotient, rem))
    }

    /// `self / divisor` (floor); `None` for a zero divisor.
    pub fn checked_div(self, divisor: U256) -> Option<U256> {
        self.checked_div_rem(divisor).map(|(q, _)| q)
    }

    /// `self % divisor`; `None` for a zero divisor.
    pub fn checked_rem(self, divisor: U256) -> Option<U256> {
        self.checked_div_rem(divisor).map(|(_, r)| r)
    }
}

impl Ord for U256 {
    fn cmp(&self, other: &U256) -> Ordering {
        for (a, b) in self.0.iter().rev().zip(other.0.iter().rev()) {
            match a.cmp(b) {
                Ordering::Equal => continue,
                unequal => return unequal,
            }
        }
        Ordering::Equal
    }
}

impl PartialOrd for U256 {
    fn partial_cmp(&self, other: &U256) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl From<u64> for U256 {
    fn from(v: u64) -> U256 {
        U256::from_u64(v)
    }
}

impl From<u128> for U256 {
    fn from(v: u128) -> U256 {
        U256::from_u128(v)
    }
}
