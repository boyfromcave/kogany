//! Fixed-size byte types and their canonical byte encodings.
//!
//! These carry no meaning beyond their bytes: ids and hashes are in internal byte order (the
//! C++ `uint256::begin()..end()`), exactly as they are pushed in scripts and written in act
//! bodies. Display (reversed) order is a presentation concern of RPC code, not of this crate.

/// A 32-byte hash or id in internal byte order (the C++ `uint256`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Hash32(pub [u8; 32]);

impl Hash32 {
    /// The all-zero value (the C++ null `uint256`).
    pub const ZERO: Hash32 = Hash32([0u8; 32]);

    /// The 32 bytes from a slice; `None` unless it is exactly 32 bytes long.
    pub fn from_slice(b: &[u8]) -> Option<Hash32> {
        <[u8; 32]>::try_from(b).ok().map(Hash32)
    }

    /// The 32 bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// A set's id: the txid of its `SET_CREATE` transaction, as its 32 internal bytes.
pub type SetId = Hash32;

/// A 4-byte application tag (upgrade plan §3.8).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Tag(pub [u8; 4]);

/// 33 key bytes as carried in a bond redeem script or an act body.
///
/// "Compressed" means a `0x02`/`0x03` header and no curve check (`VAULT_VECTORS.md` A-2): an
/// off-curve key parses, and can never sign or recover.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PubKeyBytes(pub [u8; 33]);

impl PubKeyBytes {
    /// The 33 bytes from a slice; `None` unless it is exactly 33 bytes long.
    pub fn from_slice(b: &[u8]) -> Option<PubKeyBytes> {
        <[u8; 33]>::try_from(b).ok().map(PubKeyBytes)
    }

    /// A `0x02`/`0x03` header (no curve check; the C++ `IsCompressedKeyBytes`).
    pub fn is_compressed(&self) -> bool {
        matches!(self.0.first(), Some(0x02 | 0x03))
    }
}

/// A 65-byte recoverable compact signature: header byte, then `r` and `s` big-endian.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RecoverableSig(pub [u8; 65]);

impl RecoverableSig {
    /// The 65 bytes from a slice; `None` unless it is exactly 65 bytes long.
    pub fn from_slice(b: &[u8]) -> Option<RecoverableSig> {
        <[u8; 65]>::try_from(b).ok().map(RecoverableSig)
    }

    /// The header byte (27..34 in general; the vault primitive accepts 31..34 only).
    pub fn header(&self) -> u8 {
        let [h, ..] = self.0;
        h
    }
}

/// A transparent outpoint. Its canonical encoding is the 36-byte C++ `COutPoint`
/// serialisation: txid (internal order) ‖ n (u32 little-endian).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct OutPoint {
    /// The txid, internal byte order.
    pub txid: Hash32,
    /// The output index.
    pub n: u32,
}

impl OutPoint {
    /// The 36-byte serialisation.
    pub fn to_bytes(&self) -> [u8; 36] {
        let mut out = [0u8; 36];
        let (h, n) = out.split_at_mut(32);
        h.copy_from_slice(&self.txid.0);
        n.copy_from_slice(&self.n.to_le_bytes());
        out
    }

    /// Parses the 36-byte serialisation; `None` unless it is exactly 36 bytes long.
    pub fn from_slice(b: &[u8]) -> Option<OutPoint> {
        if b.len() != 36 {
            return None;
        }
        let (h, n) = b.split_at(32);
        Some(OutPoint {
            txid: Hash32::from_slice(h)?,
            n: u32::from_le_bytes(<[u8; 4]>::try_from(n).ok()?),
        })
    }
}

/// A post-quantum owner key id (the C++ `CPQKeyID`): a scheme byte and the 32-byte key hash.
/// In a template the slot is `<hash:32> OP_<scheme> OP_CHECKPQSIG`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PqOwner {
    /// The scheme id (1 = SLH-DSA-SHA2-128s, 2 = FN-DSA-512).
    pub scheme: u8,
    /// The key hash as pushed (internal order).
    pub hash: Hash32,
}
