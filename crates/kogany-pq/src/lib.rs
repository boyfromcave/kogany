// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

//! Post-quantum signature verification for `OP_CHECKPQSIG` (consensus), the Rust face of
//! ycash6 `src/crypto/pq/scheme.{h,cpp}`.
//!
//! The verifiers are the C++ lines' own C, vendored verify-only under `csrc/` and pinned by
//! `csrc/SHA256SUMS` (plan K-8, mapping M24-25; `README.md` has the provenance and the local
//! patches), so kogany accepts exactly the signatures ycash-dd and ycash6 accept, byte for byte.
//! There is no key generation and no signing: a node only verifies.
//!
//! | byte | scheme | public key | signature (without hashtype) |
//! |---|---|---|---|
//! | `0x01` | SLH-DSA-SHA2-128s (FIPS 205, pure, empty context) | 32 | 7,856 |
//! | `0x02` | FN-DSA-512 / Falcon-512, PQClean padded | 897 | 666 |

mod ffi;

use sha2::{Digest, Sha256};

/// Size of a [`KeyHash`].
pub const KEYHASH_SIZE: usize = 32;

/// Size of the message every [`verify`] call signs: the 32-byte ZIP-243 sighash in memory order,
/// the bytes ECDSA verification is given.
pub const MSG_SIZE: usize = 32;

/// Largest script element; signatures and keys are pushed in chunks of at most this size
/// (`pq::MAX_CHUNK`, equal to `MAX_SCRIPT_ELEMENT_SIZE`).
pub const MAX_CHUNK: usize = 520;

/// Sigop cost of one `OP_CHECKPQSIG` (`pq::SIGOP_COST`).
pub const SIGOP_COST: u32 = 20;

/// `SHA256(scheme ‖ pk)`, the 32 bytes in hash output order (`pq::KeyHash`). The key commitment
/// of a `TX_PQPKH` output.
pub type KeyHash = [u8; KEYHASH_SIZE];

/// A post-quantum signature scheme, by its consensus scheme byte.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum Scheme {
    /// `0x01`: SLH-DSA-SHA2-128s, FIPS 205 pure mode with an empty context.
    SlhDsaSha2_128s = 0x01,
    /// `0x02`: FN-DSA-512 (Falcon-512) in PQClean's padded signature format.
    FnDsa512 = 0x02,
}

/// A scheme byte that names no known [`Scheme`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UnknownScheme(pub u8);

impl std::fmt::Display for UnknownScheme {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "unknown post-quantum scheme byte 0x{:02x}", self.0)
    }
}

impl std::error::Error for UnknownScheme {}

impl Scheme {
    /// The scheme a consensus scheme byte names, if any (`pq::IsKnownScheme`). Whether the
    /// scheme is active is the caller's flag, not this crate's.
    pub const fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0x01 => Some(Self::SlhDsaSha2_128s),
            0x02 => Some(Self::FnDsa512),
            _ => None,
        }
    }

    /// The consensus scheme byte.
    pub const fn byte(self) -> u8 {
        self as u8
    }

    /// Public key size in bytes (`pq::PubKeySize`): 32 or 897.
    pub const fn pubkey_size(self) -> usize {
        match self {
            Self::SlhDsaSha2_128s => 32,
            Self::FnDsa512 => 897,
        }
    }

    /// Signature size in bytes, without the trailing hashtype byte (`pq::SigSize`): 7,856 or 666.
    pub const fn sig_size(self) -> usize {
        match self {
            Self::SlhDsaSha2_128s => 7856,
            Self::FnDsa512 => 666,
        }
    }

    /// [`key_hash`] under this scheme.
    pub fn key_hash(self, pk: &[u8]) -> KeyHash {
        key_hash(self.byte(), pk)
    }

    /// Verifies `sig` (without hashtype) on `msg` under `pk` (`pq::Verify`). False for a public
    /// key or signature of any length but this scheme's.
    pub fn verify(self, pk: &[u8], msg: &[u8; MSG_SIZE], sig: &[u8]) -> bool {
        if pk.len() != self.pubkey_size() || sig.len() != self.sig_size() {
            return false;
        }
        match self {
            Self::SlhDsaSha2_128s => primitive::slh_dsa_sha2_128s_verify(pk, msg, &[], sig),
            Self::FnDsa512 => primitive::falcon512_padded_verify(pk, msg, sig),
        }
    }
}

impl TryFrom<u8> for Scheme {
    type Error = UnknownScheme;

    fn try_from(byte: u8) -> Result<Self, Self::Error> {
        Self::from_byte(byte).ok_or(UnknownScheme(byte))
    }
}

impl From<Scheme> for u8 {
    fn from(scheme: Scheme) -> Self {
        scheme.byte()
    }
}

/// Whether `scheme` is a known scheme byte, `0x01` or `0x02` (`pq::IsKnownScheme`).
pub const fn is_known_scheme(scheme: u8) -> bool {
    Scheme::from_byte(scheme).is_some()
}

/// Public key size for a scheme byte, 0 for an unknown one (`pq::PubKeySize`).
pub const fn pubkey_size(scheme: u8) -> usize {
    match Scheme::from_byte(scheme) {
        Some(s) => s.pubkey_size(),
        None => 0,
    }
}

/// Signature size (without hashtype) for a scheme byte, 0 for an unknown one (`pq::SigSize`).
pub const fn sig_size(scheme: u8) -> usize {
    match Scheme::from_byte(scheme) {
        Some(s) => s.sig_size(),
        None => 0,
    }
}

/// `KeyHash = SHA256(scheme ‖ pk)` for any scheme byte and any key bytes (`pq::KeyHash`, which
/// also hashes unknown schemes): the scheme byte is committed, so one key under two schemes has
/// two key hashes.
pub fn key_hash(scheme: u8, pk: &[u8]) -> KeyHash {
    Sha256::new()
        .chain_update([scheme])
        .chain_update(pk)
        .finalize()
        .into()
}

/// Verifies the post-quantum signature `sig` (without the hashtype byte, which belongs to the
/// script) on the 32-byte sighash `msg` under `pk`, for the scheme byte `scheme`
/// (`pq::Verify(scheme, pk, sig, msg)`, arguments reordered). False for an unknown scheme and
/// for a public key or signature of any length but the scheme's.
pub fn verify(scheme: u8, pk: &[u8], msg: &[u8; MSG_SIZE], sig: &[u8]) -> bool {
    Scheme::from_byte(scheme).is_some_and(|s| s.verify(pk, msg, sig))
}

/// The two verifiers over arbitrary messages, below the registry: the C entry points the C++
/// lines' conformance tests (NIST ACVP, the Falcon KATs) call directly. Consensus code uses
/// [`verify`].
pub mod primitive {
    use crate::ffi;

    /// FIPS 205 Algorithm 24, `slh_verify`: pure SLH-DSA-SHA2-128s with context `ctx` (at most
    /// 255 bytes) on a message of any length. False for a public key that is not 32 bytes or a
    /// signature that is not 7,856.
    pub fn slh_dsa_sha2_128s_verify(pk: &[u8], msg: &[u8], ctx: &[u8], sig: &[u8]) -> bool {
        ffi::slh_dsa_sha2_128s_verify(pk, msg, ctx, sig)
    }

    /// `ycash_falcon512_verify`: Falcon-512 in the padded format on a message of any length.
    /// False unless the signature is exactly 666 bytes and the public key 897 (local patch P2),
    /// so the unpadded compact form is refused.
    pub fn falcon512_padded_verify(pk: &[u8], msg: &[u8], sig: &[u8]) -> bool {
        ffi::falcon512_verify(pk, msg, sig)
    }
}
