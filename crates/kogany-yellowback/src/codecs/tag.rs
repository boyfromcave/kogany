// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

//! The coinbase tag (ycash6 `src/yellowback/tag.{h,cpp}`, plan §3.2, V4, V5): 36 bytes carried in
//! the coinbase scriptSig as one direct push (`0x24 || tag`) somewhere after the BIP34 height
//! push. Little-endian throughout.
//!
//! ```text
//! magic 4 ("YED!") | version 1 | flags 1 | priceMicroUsd 8 | sourceMask 2 | payoutKey 20
//! ```
//!
//! The reader is a byte-level scan, never a script parse: pools write raw extranonce bytes (V4).
//! No property of a tag makes a block invalid (TAG-4).

use kogany_vault::script::Builder;

use crate::params::{
    PRICE_MAX, PRICE_MIN, TAG_MAGIC, TAG_PRICE_SIGNAL_ONLY, TAG_SIZE, TAG_VERSION,
};

/// The scan pattern (TAG-1, P10): the direct-push opcode for 36 bytes, then the magic.
const TAG_PATTERN: [u8; 5] = [0x24, TAG_MAGIC[0], TAG_MAGIC[1], TAG_MAGIC[2], TAG_MAGIC[3]];
/// The bytes after the magic: version and body.
const TAG_BODY_SIZE: usize = 32;

/// A coinbase tag (`CoinbaseTag`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CoinbaseTag {
    /// Bit 0 = activation signal; bits 1-7 reserved, zero in a valid tag (TAG-2).
    pub flags: u8,
    /// The YEC/USD quote in micro-USD; [`TAG_PRICE_SIGNAL_ONLY`] (0) = signal-only (V9).
    pub price_micro_usd: u64,
    /// Informational bitfield of price sources.
    pub source_mask: u16,
    /// Hash160 of the miner's fee key (P2PKH); any 20 bytes (TAG-3).
    pub payout_key: [u8; 20],
}

impl CoinbaseTag {
    /// `Signal`: flag bit 0.
    pub fn signal(&self) -> bool {
        self.flags & 0x01 != 0
    }

    /// `IsQuote` (TAG-3): a price other than signal-only.
    pub fn is_quote(&self) -> bool {
        self.price_micro_usd != TAG_PRICE_SIGNAL_ONLY
    }

    /// `IsValidTag` (TAG-2): reserved flag bits clear, price 0 or in
    /// [`PRICE_MIN`]..=[`PRICE_MAX`]. (The version is the encoding's, checked by [`find_tag`].)
    pub fn is_valid(&self) -> bool {
        if self.flags & 0xFE != 0 {
            return false;
        }
        if self.price_micro_usd == TAG_PRICE_SIGNAL_ONLY {
            return true;
        }
        let (min, max) = (PRICE_MIN.unsigned_abs(), PRICE_MAX.unsigned_abs());
        (min..=max).contains(&self.price_micro_usd)
    }
}

/// `EncodeTag`: the 36 tag bytes (magic, version, body). Any field values serialise.
pub fn encode_tag(tag: &CoinbaseTag) -> [u8; TAG_SIZE] {
    let mut out = Vec::with_capacity(TAG_SIZE);
    out.extend_from_slice(&TAG_MAGIC);
    out.push(TAG_VERSION);
    out.push(tag.flags);
    out.extend_from_slice(&tag.price_micro_usd.to_le_bytes());
    out.extend_from_slice(&tag.source_mask.to_le_bytes());
    out.extend_from_slice(&tag.payout_key);
    // 4 + 1 + 1 + 8 + 2 + 20 = 36 bytes exactly.
    <[u8; TAG_SIZE]>::try_from(out).unwrap_or([0u8; TAG_SIZE])
}

/// `TagPush`: the scriptSig fragment a miner appends, `0x24 || 36 bytes`.
pub fn tag_push(tag: &CoinbaseTag) -> Vec<u8> {
    Builder::new().push(&encode_tag(tag)).into_bytes()
}

/// The BIP34 height prefix `CScript() << nHeight` (the bytes `ContextualCheckBlock` expects).
pub fn height_prefix(height: i32) -> Vec<u8> {
    Builder::new().num(i64::from(height)).into_bytes()
}

/// `FindTag` (TAG-1..5): skip the BIP34 height prefix (no prefix, no tag), find the first
/// occurrence of `24 59 45 44 21` after it, and read the 32 bytes that follow as version and
/// body. Fewer than 32 bytes after the first occurrence, a version other than
/// [`TAG_VERSION`], or a TAG-2 failure is "no tag": the scan never continues past the first
/// occurrence (TAG-5, M2).
pub fn find_tag(script_sig: &[u8], height: i32) -> Option<CoinbaseTag> {
    let rest = script_sig.strip_prefix(height_prefix(height).as_slice())?;
    let at = rest
        .windows(TAG_PATTERN.len())
        .position(|w| w == TAG_PATTERN)?;
    let body = rest.get(at.checked_add(TAG_PATTERN.len())?..)?;
    let body: &[u8; TAG_BODY_SIZE] = body.get(..TAG_BODY_SIZE)?.try_into().ok()?;
    let [version, flags, p0, p1, p2, p3, p4, p5, p6, p7, m0, m1, key @ ..] = *body;
    if version != TAG_VERSION {
        return None;
    }
    let tag = CoinbaseTag {
        flags,
        price_micro_usd: u64::from_le_bytes([p0, p1, p2, p3, p4, p5, p6, p7]),
        source_mask: u16::from_le_bytes([m0, m1]),
        payout_key: key,
    };
    tag.is_valid().then_some(tag)
}
