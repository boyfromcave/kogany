// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

//! The coinbase tag (ycash6 `src/yellowback/tag.{h,cpp}`, plan §3.2, V4, V5): carried in the
//! coinbase scriptSig as one direct push somewhere after the BIP34 height push. Little-endian
//! throughout. Two layouts (docs/plans/beta4/price-feed.md §4.3, D-8, D-10):
//!
//! ```text
//! v1, 36 bytes, pushed as 0x24 || tag (a P2PKH payee):
//!   magic 4 ("YED!") | 0x01 | flags 1 | priceMicroUsd 8 | sourceMask 2 | payoutKey 20
//! v2, 49 bytes, pushed as 0x31 || tag (a post-quantum payee):
//!   magic 4 ("YED!") | 0x02 | flags 1 | priceMicroUsd 8 | sourceMask 2 | payoutScheme 1 | payoutHash 32
//! ```
//!
//! `payoutScheme` is 0x01 (SLH-DSA-SHA2-128s) or 0x02 (FN-DSA-512) and `payoutHash` the
//! `CPQKeyID` hash `SHA256(scheme || pk)`. The tag names a [`Payee`]: v1 a P2PKH key hash, v2 a
//! post-quantum key.
//!
//! The reader is a byte-level scan, never a script parse: pools write raw extranonce bytes (V4).
//! No property of a tag makes a block invalid (TAG-4).

use kogany_vault::script::Builder;
use kogany_vault::template::{
    is_known_pq_scheme, PQ_SCHEME_FN_DSA_512, PQ_SCHEME_SLH_DSA_SHA2_128S,
};
use kogany_vault::{Hash32, PqOwner};

use super::script::{p2pkh_script, pq_key_script};
use crate::params::{
    PRICE_MAX, PRICE_MIN, TAG_MAGIC, TAG_PRICE_SIGNAL_ONLY, TAG_SIZE, TAG_VERSION,
};

/// `TAG_VERSION_V2`: the post-quantum payee's layout.
pub const TAG_VERSION_V2: u8 = 0x02;
/// `TAG_SIZE_V2`: the v2 tag's bytes (magic, version, body).
pub const TAG_SIZE_V2: usize = 49;
/// `PAYEE_P2PKH`: the payee kind of a P2PKH key hash; kinds 0x01 and 0x02 are the post-quantum
/// scheme bytes.
pub const PAYEE_P2PKH: u8 = 0x00;

/// The v1 scan pattern (TAG-1, P10): the direct-push opcode for 36 bytes, then the magic.
const TAG_PATTERN: [u8; 5] = [0x24, TAG_MAGIC[0], TAG_MAGIC[1], TAG_MAGIC[2], TAG_MAGIC[3]];
/// The v2 scan pattern: the direct-push opcode for 49 bytes, then the magic.
const TAG_PATTERN_V2: [u8; 5] = [0x31, TAG_MAGIC[0], TAG_MAGIC[1], TAG_MAGIC[2], TAG_MAGIC[3]];
/// The bytes after the magic: version and body (v1).
const TAG_BODY_SIZE: usize = TAG_SIZE - TAG_MAGIC.len();
/// The bytes after the magic: version and body (v2).
const TAG_BODY_SIZE_V2: usize = TAG_SIZE_V2 - TAG_MAGIC.len();

/// A fee payee (`yellowback::Payee`, beta4 P1 spec §2): kind [`PAYEE_P2PKH`] with a 20-byte
/// Hash160, or kind 1/2 (the post-quantum scheme byte) with the 32-byte `CPQKeyID` hash. Nothing
/// else is a payee.
///
/// Ordered by kind, then by the hash bytes (memcmp; a P2PKH payee's unused tail of `hash` is
/// always zero), so every v1-only ordering is unchanged. Serialised as kind then the 20 or 32
/// raw hash bytes, no length prefix (`SCHEMA_VERSION` 16).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Payee {
    /// [`PAYEE_P2PKH`], or the post-quantum scheme byte.
    pub kind: u8,
    /// Kind 0: bytes `[0, 20)` are the Hash160, `[20, 32)` zero; kind 1/2: the `CPQKeyID` hash.
    pub hash: [u8; 32],
}

impl Payee {
    /// `Payee::FromKeyID`: a P2PKH payee.
    pub fn p2pkh(key_id: &[u8; 20]) -> Payee {
        let mut hash = [0u8; 32];
        for (h, k) in hash.iter_mut().zip(key_id) {
            *h = *k;
        }
        Payee {
            kind: PAYEE_P2PKH,
            hash,
        }
    }

    /// `Payee::FromPQ`: a post-quantum payee; `None` for an unregistered scheme.
    pub fn pq(owner: &PqOwner) -> Option<Payee> {
        is_known_pq_scheme(owner.scheme).then_some(Payee {
            kind: owner.scheme,
            hash: owner.hash.0,
        })
    }

    /// `Payee::FromScript`: the payee a fee output pays, exactly `76 a9 14 <20> 88 ac` or exactly
    /// `GetScriptForPQKey` of a known scheme (`0x20 <32> OP_1|OP_2 OP_CHECKPQSIG`); anything else
    /// is not a payee.
    pub fn from_script(s: &[u8]) -> Option<Payee> {
        if let [0x76, 0xa9, 20, key @ .., 0x88, 0xac] = s {
            return <[u8; 20]>::try_from(key).ok().map(|k| Payee::p2pkh(&k));
        }
        if let [0x20, hash @ .., n @ (0x51 | 0x52), 0xc2] = s {
            let hash = Hash32::from_slice(hash)?;
            return Payee::pq(&PqOwner {
                scheme: n.wrapping_sub(0x50), // OP_1 = 0x51 is scheme 1
                hash,
            });
        }
        None
    }

    /// Kind 0.
    pub fn is_p2pkh(&self) -> bool {
        self.kind == PAYEE_P2PKH
    }

    /// `IsValid`: kind 0, or a registered scheme.
    pub fn is_valid(&self) -> bool {
        self.is_p2pkh() || is_known_pq_scheme(self.kind)
    }

    /// The hash bytes the payee carries: 20 (kind 0) or 32.
    pub fn hash_bytes(&self) -> &[u8] {
        let (key, _) = self.hash.split_at(20);
        if self.is_p2pkh() {
            key
        } else {
            &self.hash
        }
    }

    /// The P2PKH key hash (kind 0 only).
    pub fn key_id(&self) -> Option<[u8; 20]> {
        if !self.is_p2pkh() {
            return None;
        }
        <[u8; 20]>::try_from(self.hash_bytes()).ok()
    }

    /// The post-quantum key (kind 1/2 only).
    pub fn pq_owner(&self) -> Option<PqOwner> {
        (!self.is_p2pkh()).then_some(PqOwner {
            scheme: self.kind,
            hash: Hash32(self.hash),
        })
    }

    /// `Payee::Script`: the 25-byte P2PKH, or `GetScriptForPQKey` (35 bytes); `None` for an
    /// unregistered kind.
    pub fn script(&self) -> Option<Vec<u8>> {
        match (self.key_id(), self.pq_owner()) {
            (Some(k), _) => Some(p2pkh_script(&k)),
            (None, Some(o)) => pq_key_script(&o),
            (None, None) => None,
        }
    }

    /// `Payee::SchemeName`, `yed_gettag.payoutScheme` (rpcversion 11): `"p2pkh"`,
    /// `"slh-dsa-sha2-128s"` or `"fn-dsa-512"`.
    pub fn scheme_name(&self) -> &'static str {
        match self.kind {
            PQ_SCHEME_SLH_DSA_SHA2_128S => "slh-dsa-sha2-128s",
            PQ_SCHEME_FN_DSA_512 => "fn-dsa-512",
            _ => "p2pkh",
        }
    }

    /// The canonical serialisation: kind, then [`Payee::hash_bytes`].
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(33);
        out.push(self.kind);
        out.extend_from_slice(self.hash_bytes());
        out
    }
}

/// A coinbase tag (`CoinbaseTag`). Its version is its payee's layout ([`CoinbaseTag::version`]):
/// v1 for a P2PKH payee, v2 for a post-quantum one.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CoinbaseTag {
    /// Bit 0 = activation signal; bits 1-7 reserved, zero in a valid tag (TAG-2).
    pub flags: u8,
    /// The YEC/USD quote in micro-USD; [`TAG_PRICE_SIGNAL_ONLY`] (0) = signal-only (V9).
    pub price_micro_usd: u64,
    /// Informational bitfield of price sources.
    pub source_mask: u16,
    /// The fee payee: v1 a P2PKH key hash (any 20 bytes, TAG-3), v2 `payoutScheme` /
    /// `payoutHash`.
    pub payee: Payee,
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

    /// The layout version: [`TAG_VERSION`] for a P2PKH payee, [`TAG_VERSION_V2`] otherwise
    /// (`MakeTag`).
    pub fn version(&self) -> u8 {
        if self.payee.is_p2pkh() {
            TAG_VERSION
        } else {
            TAG_VERSION_V2
        }
    }

    /// `IsValidTag` (TAG-2): a P2PKH or a registered post-quantum payee, reserved flag bits
    /// clear, price 0 or in [`PRICE_MIN`]..=[`PRICE_MAX`]. (The version is the encoding's,
    /// checked by [`find_tag`].)
    pub fn is_valid(&self) -> bool {
        if !self.payee.is_valid() || self.flags & 0xFE != 0 {
            return false;
        }
        if self.price_micro_usd == TAG_PRICE_SIGNAL_ONLY {
            return true;
        }
        let (min, max) = (PRICE_MIN.unsigned_abs(), PRICE_MAX.unsigned_abs());
        (min..=max).contains(&self.price_micro_usd)
    }
}

/// `EncodeTag`: the 36 (v1) or 49 (v2) tag bytes (magic, version, body). Any field values
/// serialise.
pub fn encode_tag(tag: &CoinbaseTag) -> Vec<u8> {
    let v1 = tag.payee.is_p2pkh();
    let mut out = Vec::with_capacity(if v1 { TAG_SIZE } else { TAG_SIZE_V2 });
    out.extend_from_slice(&TAG_MAGIC);
    out.push(tag.version());
    out.push(tag.flags);
    out.extend_from_slice(&tag.price_micro_usd.to_le_bytes());
    out.extend_from_slice(&tag.source_mask.to_le_bytes());
    if !v1 {
        out.push(tag.payee.kind);
    }
    out.extend_from_slice(tag.payee.hash_bytes());
    out
}

/// `TagPush`: the scriptSig fragment a miner appends, `0x24 || 36 bytes` or `0x31 || 49 bytes`.
pub fn tag_push(tag: &CoinbaseTag) -> Vec<u8> {
    Builder::new().push(&encode_tag(tag)).into_bytes()
}

/// The BIP34 height prefix `CScript() << nHeight` (the bytes `ContextualCheckBlock` expects).
pub fn height_prefix(height: i32) -> Vec<u8> {
    Builder::new().num(i64::from(height)).into_bytes()
}

/// `FindTag` (TAG-1..5): skip the BIP34 height prefix (no prefix, no tag), find the first
/// occurrence of either `24 59 45 44 21` (v1) or `31 59 45 44 21` (v2) after it, whichever comes
/// first by position, and read the 32 (v1) or 45 (v2) bytes that follow as version and body. A
/// v1 pattern must carry [`TAG_VERSION`] and a v2 pattern [`TAG_VERSION_V2`]. Fewer bytes than
/// the body after the first occurrence, a version mismatch, an unregistered scheme or a TAG-2
/// failure is "no tag": the scan never continues past the first occurrence (TAG-5, M2).
pub fn find_tag(script_sig: &[u8], height: i32) -> Option<CoinbaseTag> {
    let rest = script_sig.strip_prefix(height_prefix(height).as_slice())?;
    let at = rest
        .windows(TAG_PATTERN.len())
        .position(|w| w == TAG_PATTERN || w == TAG_PATTERN_V2)?;
    let v1 = rest.get(at..at.checked_add(TAG_PATTERN.len())?)? == TAG_PATTERN;
    let body = rest.get(at.checked_add(TAG_PATTERN.len())?..)?;
    let (version, payee) = if v1 {
        let key: [u8; 20] = body.get(12..TAG_BODY_SIZE)?.try_into().ok()?;
        (TAG_VERSION, Payee::p2pkh(&key))
    } else {
        let hash: [u8; 32] = body.get(13..TAG_BODY_SIZE_V2)?.try_into().ok()?;
        (
            TAG_VERSION_V2,
            Payee {
                kind: *body.get(12)?,
                hash,
            },
        )
    };
    let [v, flags, p0, p1, p2, p3, p4, p5, p6, p7, m0, m1, ..] = *body else {
        return None;
    };
    if v != version || (!v1 && payee.is_p2pkh()) {
        return None;
    }
    let tag = CoinbaseTag {
        flags,
        price_micro_usd: u64::from_le_bytes([p0, p1, p2, p3, p4, p5, p6, p7]),
        source_mask: u16::from_le_bytes([m0, m1]),
        payee,
    };
    tag.is_valid().then_some(tag)
}
