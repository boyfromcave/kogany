// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

//! Attestation bundles (BUNDLE-1), the cancel co-signature list (`"YC"`), EQV-1's cancel evidence
//! (`"YX"`), carrier extraction, the signature cache contract, `VerifyBundle` in the W8 order and
//! the bundle statistic: ycash6 `src/yellowback/bundle.{h,cpp}` at `65cb4ae0f`.
//!
//! Bundle wire form: `"YA" | version u8 (= 1) | count u8 | count x 74-byte attestation`; six are
//! 448 bytes, inside the 520-byte push (`BUNDLE_MAX = 6`).

use std::collections::BTreeSet;

use kogany_vault::state::VaultTx;
use kogany_vault::{Hash32, OutPoint, PubKeyBytes, RecoverableSig};
use sha2::{Digest, Sha256};

use super::attestation::{
    attest_message, decode_attestation, encode_attestation, verify_compact_sig_key, Attestation,
    ATTESTATION_SIZE,
};
use crate::codecs::script::{find_carrier_input, parse_carrier_script_sig, CarrierError};
use crate::math::{weighted_quantile, WeightedPrice, U256};
use crate::params::{BundleCarrier, MicroUsd, Params, PRICE_MAX, PRICE_MIN};

/// `BUNDLE_VERSION`.
pub const BUNDLE_VERSION: u8 = 1;
/// `BUNDLE_HEADER_SIZE`: magic, version, count.
pub const BUNDLE_HEADER_SIZE: usize = 4;
/// The bundle magic `"YA"`.
pub const BUNDLE_MAGIC: [u8; 2] = *b"YA";
/// The ceiling `DecodeBundle` applies by default (`BUNDLE_MAX`).
pub const DEFAULT_BUNDLE_MAX: usize = 6;
/// The largest count the one-byte field can carry.
pub const MAX_ENCODABLE_COUNT: usize = 255;

/// The cancel co-signature list magic `"YC"`.
pub const COSIGN_MAGIC: [u8; 2] = *b"YC";
/// `CANCEL_COSIGN_VERSION` (also the `"YX"` evidence version).
pub const CANCEL_COSIGN_VERSION: u8 = 1;
/// `CANCEL_COSIGN_ENTRY_SIZE`: price u32 and a 65-byte recoverable signature.
pub const CANCEL_COSIGN_ENTRY_SIZE: usize = 4 + 65;
/// `CANCEL_COSIGN_MAX`: seven entries are 487 bytes, inside one 520-byte push.
pub const CANCEL_COSIGN_MAX: usize = 7;
/// EQV-1's cancel evidence magic `"YX"`.
pub const EVIDENCE_MAGIC: [u8; 2] = *b"YX";
/// `CANCEL_EVIDENCE_SIZE`: `"YX" | version | attestation 74 | txid 32 | n u32 | price u32 | sig 65`.
pub const CANCEL_EVIDENCE_SIZE: usize = 3 + 74 + 32 + 4 + 4 + 65;

/// A decoded bundle (`Bundle`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Bundle {
    /// The version byte (always [`BUNDLE_VERSION`] once decoded).
    pub version: u8,
    /// The attestations, in bundle order.
    pub atts: Vec<Attestation>,
}

impl Default for Bundle {
    fn default() -> Self {
        Bundle {
            version: BUNDLE_VERSION,
            atts: Vec::new(),
        }
    }
}

impl Bundle {
    /// A version-1 bundle of these attestations.
    pub fn of(atts: Vec<Attestation>) -> Bundle {
        Bundle {
            version: BUNDLE_VERSION,
            atts,
        }
    }
}

/// `EncodeBundle`: `"YA" | version | count | attestations`; the count field and the
/// attestations written stop at 255 (the C++ `min(size, 255)`).
pub fn encode_bundle(b: &Bundle) -> Vec<u8> {
    let n = b.atts.len().min(MAX_ENCODABLE_COUNT);
    let mut out = Vec::with_capacity(
        ATTESTATION_SIZE
            .saturating_mul(n)
            .saturating_add(BUNDLE_HEADER_SIZE),
    );
    out.extend_from_slice(&BUNDLE_MAGIC);
    out.push(b.version);
    out.push(u8::try_from(n).unwrap_or(u8::MAX));
    for a in b.atts.iter().take(n) {
        out.extend_from_slice(&encode_attestation(a));
    }
    out
}

/// `DecodeBundle`: `None` unless the magic, version 1, `count <= max_count` and the length is
/// exactly `4 + 74 x count`.
pub fn decode_bundle(data: &[u8], max_count: usize) -> Option<Bundle> {
    let (header, body) = data.split_first_chunk::<BUNDLE_HEADER_SIZE>()?;
    let [m0, m1, version, count] = *header;
    if [m0, m1] != BUNDLE_MAGIC || version != BUNDLE_VERSION {
        return None;
    }
    let count = usize::from(count);
    if count > max_count || body.len() != ATTESTATION_SIZE.checked_mul(count)? {
        return None;
    }
    let atts = body
        .as_chunks::<ATTESTATION_SIZE>()
        .0
        .iter()
        .map(|c| decode_attestation(c))
        .collect::<Option<Vec<_>>>()?;
    Some(Bundle { version, atts })
}

/// One entry of a cancel's `"YC"` list (`CancelCosignEntry`): a member's co-signature of the
/// cancel and its price statement at the claim's `refHeight`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CancelCosignEntry {
    /// The stated price.
    pub price_micro_usd: u32,
    /// The 65-byte recoverable signature over [`super::cancel_cosign_message`].
    pub sig: RecoverableSig,
}

/// `EncodeCancelCosigns`; `None` (the C++ empty vector) for zero or more than
/// [`CANCEL_COSIGN_MAX`] entries.
pub fn encode_cancel_cosigns(entries: &[CancelCosignEntry]) -> Option<Vec<u8>> {
    if entries.is_empty() || entries.len() > CANCEL_COSIGN_MAX {
        return None;
    }
    let mut out = vec![
        COSIGN_MAGIC[0],
        COSIGN_MAGIC[1],
        CANCEL_COSIGN_VERSION,
        u8::try_from(entries.len()).ok()?,
    ];
    for e in entries {
        out.extend_from_slice(&e.price_micro_usd.to_le_bytes());
        out.extend_from_slice(&e.sig.0);
    }
    Some(out)
}

/// `DecodeCancelCosigns`: `None` unless `"YC"`, version 1, `1 <= count <= 7` and exactly
/// `4 + 69 x count` bytes.
pub fn decode_cancel_cosigns(data: &[u8]) -> Option<Vec<CancelCosignEntry>> {
    let (header, body) = data.split_first_chunk::<4>()?;
    let [m0, m1, version, count] = *header;
    if [m0, m1] != COSIGN_MAGIC || version != CANCEL_COSIGN_VERSION {
        return None;
    }
    let count = usize::from(count);
    if !(1..=CANCEL_COSIGN_MAX).contains(&count)
        || body.len() != CANCEL_COSIGN_ENTRY_SIZE.checked_mul(count)?
    {
        return None;
    }
    body.as_chunks::<CANCEL_COSIGN_ENTRY_SIZE>()
        .0
        .iter()
        .map(|c| {
            let (price, sig) = c.split_first_chunk::<4>()?;
            Some(CancelCosignEntry {
                price_micro_usd: u32::from_le_bytes(*price),
                sig: RecoverableSig::from_slice(sig)?,
            })
        })
        .collect()
}

/// The cancel side of EQV-1's second evidence shape (`CancelStatement`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CancelStatement {
    /// The claimant intent whose cancel the statement co-signed.
    pub intent: OutPoint,
    /// The stated price.
    pub price_micro_usd: u32,
    /// The 65-byte recoverable signature.
    pub sig: RecoverableSig,
}

/// `EncodeCancelEvidence`: `"YX" | 1 | attestation | intent txid | n LE32 | price LE32 | sig`
/// (182 bytes); the statement's cited height is the attestation's.
pub fn encode_cancel_evidence(a: &Attestation, s: &CancelStatement) -> Vec<u8> {
    let mut out = Vec::with_capacity(CANCEL_EVIDENCE_SIZE);
    out.extend_from_slice(&EVIDENCE_MAGIC);
    out.push(CANCEL_COSIGN_VERSION);
    out.extend_from_slice(&encode_attestation(a));
    out.extend_from_slice(&s.intent.txid.0);
    out.extend_from_slice(&s.intent.n.to_le_bytes());
    out.extend_from_slice(&s.price_micro_usd.to_le_bytes());
    out.extend_from_slice(&s.sig.0);
    out
}

/// `DecodeCancelEvidence`: `None` unless exactly 182 bytes with the `"YX"` header.
pub fn decode_cancel_evidence(data: &[u8]) -> Option<(Attestation, CancelStatement)> {
    if data.len() != CANCEL_EVIDENCE_SIZE {
        return None;
    }
    let (header, rest) = data.split_first_chunk::<3>()?;
    if *header != [EVIDENCE_MAGIC[0], EVIDENCE_MAGIC[1], CANCEL_COSIGN_VERSION] {
        return None;
    }
    let (att, rest) = rest.split_at_checked(ATTESTATION_SIZE)?;
    let (txid, rest) = rest.split_first_chunk::<32>()?;
    let (n, rest) = rest.split_first_chunk::<4>()?;
    let (price, sig) = rest.split_first_chunk::<4>()?;
    Some((
        decode_attestation(att)?,
        CancelStatement {
            intent: OutPoint {
                txid: Hash32(*txid),
                n: u32::from_le_bytes(*n),
            },
            price_micro_usd: u32::from_le_bytes(*price),
            sig: RecoverableSig::from_slice(sig)?,
        },
    ))
}

/// Where a bundle rode (`BundleSource`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BundleSource {
    /// The first push of the one carrier input's scriptSig.
    ScriptSig,
    /// The payload tail the caller handed in.
    OpReturn,
}

/// BUNDLE-1's first failure (`BundleVerdict::reason`), in check order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum BundleError {
    /// No source, both sources under `EITHER`, or a malformed bundle.
    Shape,
    /// Two or more carrier-shaped inputs.
    TwoCarriers,
    /// The carrier's bundle does not hash to its redeem script's commitment.
    Hash,
    /// Fewer than `mSelect` or more than `bundleMax` attestations.
    Count,
    /// A seq outside the selected set.
    Member,
    /// A seq twice.
    Dup,
    /// A cited height outside `(R - attestMaxAge, R]` or below the start height.
    Stale,
    /// A price outside `[priceMin, priceMax]`.
    Range,
    /// A signature that does not verify, or no key or block hash to verify it under.
    Sig,
}

impl BundleError {
    /// The C++ reason string (`"shape"`, `"two-carriers"`, `"hash"`, `"count"`, `"member"`,
    /// `"dup"`, `"stale"`, `"range"`, `"sig"`); the verdicts `mint9-bundle-<reason>` and
    /// `red1-bundle-<reason>` append it.
    pub const fn reason(self) -> &'static str {
        match self {
            BundleError::Shape => "shape",
            BundleError::TwoCarriers => "two-carriers",
            BundleError::Hash => "hash",
            BundleError::Count => "count",
            BundleError::Member => "member",
            BundleError::Dup => "dup",
            BundleError::Stale => "stale",
            BundleError::Range => "range",
            BundleError::Sig => "sig",
        }
    }
}

impl core::fmt::Display for BundleError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.reason())
    }
}

/// The input scriptSigs of a transaction, in order.
fn script_sigs(tx: &VaultTx) -> Vec<&[u8]> {
    tx.inputs.iter().map(|i| i.script_sig.as_slice()).collect()
}

/// `FindCarrierInput` over a transaction (see [`crate::codecs::script::find_carrier_input`]).
pub fn carrier_input(tx: &VaultTx, skip_vin0: bool) -> Result<usize, CarrierError> {
    find_carrier_input(&script_sigs(tx), skip_vin0)
}

/// `ExtractBundle`: the bundle bytes of a transaction and where they came from, not decoded.
/// `Shape` (no source, or both under `EITHER`), `TwoCarriers`, or `Hash`. `skip_vin0` excludes a
/// REDEEM's vault input.
pub fn extract_bundle(
    tx: &VaultTx,
    mode: BundleCarrier,
    skip_vin0: bool,
    payload_tail: &[u8],
) -> Result<(Vec<u8>, BundleSource), BundleError> {
    let want_script_sig = mode != BundleCarrier::OpReturn;
    let want_op_return = mode != BundleCarrier::ScriptSig;
    let carrier = if want_script_sig {
        match carrier_input(tx, skip_vin0) {
            Ok(i) => Some(i),
            Err(CarrierError::TwoCarriers) => return Err(BundleError::TwoCarriers),
            Err(CarrierError::Shape) => None,
        }
    } else {
        None
    };
    let have_tail = want_op_return && !payload_tail.is_empty();
    match (carrier, have_tail) {
        (Some(_), true) => Err(BundleError::Shape), // EITHER means exactly one
        (Some(i), false) => {
            let spend = tx
                .inputs
                .get(i)
                .and_then(|input| parse_carrier_script_sig(&input.script_sig))
                .ok_or(BundleError::Shape)?; // just parsed by carrier_input; stated for totality
            if Hash32(Sha256::digest(&spend.bundle).into()) != spend.bundle_hash {
                return Err(BundleError::Hash);
            }
            Ok((spend.bundle, BundleSource::ScriptSig))
        }
        (None, true) => Ok((payload_tail.to_vec(), BundleSource::OpReturn)),
        (None, false) => Err(BundleError::Shape),
    }
}

/// The node-local verified-signature cache (W8, R3), keyed by [`sig_cache_key`]. A hit and a cold
/// verification always agree. Shared by the block and mempool paths and the primitive's liveness
/// hook, so it takes `&self`: an implementation locks internally.
pub trait SigCache: Sync {
    /// The cached verdict of a key, if any.
    fn lookup(&self, key: &Hash32) -> Option<bool>;
    /// Records a cold verdict.
    fn insert(&self, key: &Hash32, valid: bool);
}

/// `SigCacheKey`: `SHA256(attestation74 || blockHash(citedHeight) || pubkey33)` — the key binds the
/// block hash and the public key the attestation was verified under.
pub fn sig_cache_key(att: &Attestation, block_hash: &Hash32, pk: &PubKeyBytes) -> Hash32 {
    let mut h = Sha256::new();
    h.update(encode_attestation(att));
    h.update(block_hash.0);
    h.update(pk.0);
    Hash32(h.finalize().into())
}

/// One attestation's signature, through the cache when there is one (the C++
/// `AttestationValid`, and `VerifyBundle`'s step 6): a hit is returned as is, a miss is
/// verified and inserted.
pub fn attestation_valid(
    a: &Attestation,
    pk: &PubKeyBytes,
    block_hash: &Hash32,
    cache: Option<&dyn SigCache>,
) -> bool {
    let key = sig_cache_key(a, block_hash, pk);
    if let Some(hit) = cache.and_then(|c| c.lookup(&key)) {
        return hit;
    }
    let valid = verify_compact_sig_key(
        pk,
        &attest_message(a.seq, a.price_micro_usd, a.cited_height, block_hash),
        &a.sig,
    );
    if let Some(c) = cache {
        c.insert(&key, valid);
    }
    valid
}

/// The bounds BUNDLE-1 reads from the parameter set in force at R (`BundleLimits`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BundleLimits {
    /// `citedHeight` in `(R - attestMaxAge, R]`.
    pub attest_max_age: i32,
    /// `count >= m_select`.
    pub m_select: usize,
    /// `count <= bundle_max`.
    pub bundle_max: usize,
    /// `citedHeight >= start_height`.
    pub start_height: i32,
    /// Price floor.
    pub price_min: MicroUsd,
    /// Price ceiling.
    pub price_max: MicroUsd,
}

impl BundleLimits {
    /// The limits of a parameter set, as `VerifyTxBundle` and `AttestationLiveness` fill them:
    /// negative counts read as 0, prices `[PRICE_MIN, PRICE_MAX]`.
    pub fn from_params(p: &Params) -> BundleLimits {
        BundleLimits {
            attest_max_age: p.attest_max_age,
            m_select: usize::try_from(p.m_select.max(0)).unwrap_or(0),
            bundle_max: usize::try_from(p.bundle_max.max(0)).unwrap_or(0),
            start_height: p.start_height,
            price_min: PRICE_MIN,
            price_max: PRICE_MAX,
        }
    }
}

/// A seq's public key (`pubkeyOf`); `None` = no key, which is `Sig`.
pub type PubkeyOf<'a> = &'a dyn Fn(u16) -> Option<PubKeyBytes>;
/// The index's block hash at a height (`blockHashAt`); `None` = unknown, which is `Sig`.
pub type BlockHashAt<'a> = &'a dyn Fn(i64) -> Option<Hash32>;

/// `VerifyBundle`, BUNDLE-1 in the W8 order: shape → hash → count → membership/uniqueness (per
/// attestation, in order) → freshness/range (per attestation, in order) → signatures (per
/// attestation, in order, through the cache). `selected` is `Selected(R, selector)`, computed by
/// the caller. `None` callbacks (the C++ null `std::function`) make every signature `Sig`. Total:
/// the first failure is returned; on success the verified attestations in bundle order.
#[allow(clippy::too_many_arguments)]
pub fn verify_bundle(
    tx: &VaultTx,
    mode: BundleCarrier,
    skip_vin0: bool,
    payload_tail: &[u8],
    r: i64,
    selected: &[u16],
    limits: &BundleLimits,
    pubkey_of: Option<PubkeyOf<'_>>,
    block_hash_at: Option<BlockHashAt<'_>>,
    cache: Option<&dyn SigCache>,
) -> Result<Vec<Attestation>, BundleError> {
    // 1. shape, 2. hash
    let (bytes, _) = extract_bundle(tx, mode, skip_vin0, payload_tail)?;
    // Well-formed with the encoding's own ceiling; a count above bundle_max is "count".
    let bundle = decode_bundle(&bytes, MAX_ENCODABLE_COUNT).ok_or(BundleError::Shape)?;
    // 3. count
    let count = bundle.atts.len();
    if count < limits.m_select || count > limits.bundle_max {
        return Err(BundleError::Count);
    }
    // 4. membership and uniqueness
    let mut seen = BTreeSet::new();
    for a in &bundle.atts {
        if !selected.contains(&a.seq) {
            return Err(BundleError::Member);
        }
        if !seen.insert(a.seq) {
            return Err(BundleError::Dup);
        }
    }
    // 5. freshness and range
    let oldest_excluded = r.saturating_sub(i64::from(limits.attest_max_age));
    for a in &bundle.atts {
        let h = i64::from(a.cited_height);
        if h > r || h <= oldest_excluded || h < i64::from(limits.start_height) {
            return Err(BundleError::Stale);
        }
        let p = MicroUsd::from(a.price_micro_usd);
        if p < limits.price_min || p > limits.price_max {
            return Err(BundleError::Range);
        }
    }
    // 6. signatures, each through the per-attestation cache
    for a in &bundle.atts {
        let block_hash = block_hash_at
            .and_then(|f| f(i64::from(a.cited_height)))
            .ok_or(BundleError::Sig)?;
        let pk = pubkey_of.and_then(|f| f(a.seq)).ok_or(BundleError::Sig)?; // no key, no cache line
        if !attestation_valid(a, &pk, &block_hash, cache) {
            return Err(BundleError::Sig);
        }
    }
    Ok(bundle.atts)
}

/// `BundleStat` (§3.7): over `c` with parallel `weights`, undefined (`None`, `None`) if `c` is
/// empty, `|c| < m_select`, the lengths differ or a quantile is outside `0..=10^4`; else sort by
/// price (ties by seq), and `aMint` / `aClaim` are [`weighted_quantile`] at `q_low_bps` /
/// `q_high_bps`.
pub fn bundle_stat(
    c: &[Attestation],
    weights: &[U256],
    m_select: usize,
    q_low_bps: i32,
    q_high_bps: i32,
) -> (Option<MicroUsd>, Option<MicroUsd>) {
    if c.is_empty() || c.len() < m_select || weights.len() != c.len() {
        return (None, None);
    }
    if !(0..=10_000).contains(&q_low_bps) || !(0..=10_000).contains(&q_high_bps) {
        return (None, None);
    }
    let mut order: Vec<(&Attestation, &U256)> = c.iter().zip(weights.iter()).collect();
    order.sort_by_key(|(a, _)| (a.price_micro_usd, a.seq));
    // weighted_quantile's stable sort by price keeps the (price, seq) order.
    let sorted: Vec<WeightedPrice> = order
        .iter()
        .map(|(a, w)| WeightedPrice::new(MicroUsd::from(a.price_micro_usd), **w))
        .collect();
    (
        weighted_quantile(&sorted, q_low_bps),
        weighted_quantile(&sorted, q_high_bps),
    )
}
