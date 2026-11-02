// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

//! The 74-byte price attestation, its signed message, the cancel co-sign message and strict
//! compact ECDSA verification: ycash6 `src/yellowback/attest.{h,cpp}` at `65cb4ae0f`.
//!
//! Wire form (74 bytes, fixed-width little-endian): `seq u16 | priceMicroUsd u32 | citedHeight u32
//! | sig 64 (compact r || s)`. Message (R13): `SHA256("YBATTEST1" || seq LE16 || price LE32 ||
//! citedHeight LE32 || blockHash)`, the block hash as its 32 internal bytes, 51 bytes hashed once.

use kogany_vault::{Hash32, PubKeyBytes};
use secp256k1::{ecdsa, Message, PublicKey};
use sha2::{Digest, Sha256};

/// `ATTESTATION_SIZE`.
pub const ATTESTATION_SIZE: usize = 74;

/// The attestation message prefix, 9 ASCII bytes, no length byte.
pub const ATTEST_PREFIX: &[u8; 9] = b"YBATTEST1";

/// The cancel co-sign message prefix (CAN-2 + C4b), 15 ASCII bytes, no length byte.
pub const CANCEL_COSIGN_PREFIX: &[u8; 15] = b"YedCancelCosign";

/// One price attestation (`Attestation`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Attestation {
    /// The attestor's seq (the module's number for one `SET_JOIN` of the attestor set).
    pub seq: u16,
    /// The attested price in micro-dollars per YEC.
    pub price_micro_usd: u32,
    /// The height whose block hash the attestation binds.
    pub cited_height: u32,
    /// The compact signature `r || s`, big-endian, low S.
    pub sig: [u8; 64],
}

impl Default for Attestation {
    fn default() -> Self {
        Attestation {
            seq: 0,
            price_micro_usd: 0,
            cited_height: 0,
            sig: [0u8; 64],
        }
    }
}

/// `AttestMessage`: `SHA256("YBATTEST1" || seq LE16 || price LE32 || citedHeight LE32 ||
/// blockHash)`.
pub fn attest_message(
    seq: u16,
    price_micro_usd: u32,
    cited_height: u32,
    block_hash: &Hash32,
) -> Hash32 {
    let mut h = Sha256::new();
    h.update(ATTEST_PREFIX);
    h.update(seq.to_le_bytes());
    h.update(price_micro_usd.to_le_bytes());
    h.update(cited_height.to_le_bytes());
    h.update(block_hash.0);
    Hash32(h.finalize().into())
}

/// `CancelCosignMessage` (CAN-2 + C4b): `SHA256d("YedCancelCosign" || attestorSetId ||
/// intent txid || intent n LE32 || citedHeight LE32 || priceMicroUsd LE32 ||
/// blockHash(citedHeight))`, 123 bytes hashed twice; every hash as its 32 internal bytes.
pub fn cancel_cosign_message(
    attestor_set_id: &Hash32,
    intent_txid: &Hash32,
    intent_n: u32,
    cited_height: u32,
    price_micro_usd: u32,
    block_hash: &Hash32,
) -> Hash32 {
    let mut h = Sha256::new();
    h.update(CANCEL_COSIGN_PREFIX);
    h.update(attestor_set_id.0);
    h.update(intent_txid.0);
    h.update(intent_n.to_le_bytes());
    h.update(cited_height.to_le_bytes());
    h.update(price_micro_usd.to_le_bytes());
    h.update(block_hash.0);
    Hash32(Sha256::digest(h.finalize()).into())
}

/// `VerifyCompactSig` (W3, R17): parse the 64-byte compact signature (`r` or `s` at or above the
/// group order fails), refuse a high-S encoding outright (never normalised: two encodings of one
/// signature would be two bundle hashes), then verify. False for a key that is not 33 bytes with
/// a `0x02`/`0x03` header, or not on the curve (the C++ `IsValid() && IsCompressed()` and
/// `secp256k1_ec_pubkey_parse`).
pub fn verify_compact_sig(pk: &[u8], msg: &Hash32, sig: &[u8; 64]) -> bool {
    if pk.len() != 33 || !matches!(pk.first(), Some(0x02 | 0x03)) {
        return false;
    }
    let Ok(key) = PublicKey::from_slice(pk) else {
        return false;
    };
    let Ok(parsed) = ecdsa::Signature::from_compact(sig) else {
        return false;
    };
    let mut low = parsed;
    low.normalize_s();
    if low != parsed {
        return false; // secp256k1_ecdsa_signature_normalize returned 1: a rejection, not a repair
    }
    ecdsa::verify(&parsed, Message::from_digest(msg.0), &key).is_ok()
}

/// [`verify_compact_sig`] over the crate's key type.
pub fn verify_compact_sig_key(pk: &PubKeyBytes, msg: &Hash32, sig: &[u8; 64]) -> bool {
    verify_compact_sig(&pk.0, msg, sig)
}

/// `EncodeAttestation`: the 74 bytes.
pub fn encode_attestation(att: &Attestation) -> [u8; ATTESTATION_SIZE] {
    let mut out = [0u8; ATTESTATION_SIZE];
    let (seq, rest) = out.split_at_mut(2);
    seq.copy_from_slice(&att.seq.to_le_bytes());
    let (price, rest) = rest.split_at_mut(4);
    price.copy_from_slice(&att.price_micro_usd.to_le_bytes());
    let (cited, sig) = rest.split_at_mut(4);
    cited.copy_from_slice(&att.cited_height.to_le_bytes());
    sig.copy_from_slice(&att.sig);
    out
}

/// `DecodeAttestation`: `None` unless exactly 74 bytes.
pub fn decode_attestation(data: &[u8]) -> Option<Attestation> {
    let bytes: &[u8; ATTESTATION_SIZE] = data.try_into().ok()?;
    let (seq, rest) = bytes.split_first_chunk::<2>()?;
    let (price, rest) = rest.split_first_chunk::<4>()?;
    let (cited, sig) = rest.split_first_chunk::<4>()?;
    Some(Attestation {
        seq: u16::from_le_bytes(*seq),
        price_micro_usd: u32::from_le_bytes(*price),
        cited_height: u32::from_le_bytes(*cited),
        sig: sig.try_into().ok()?,
    })
}
