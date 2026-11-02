//! The canonical `statehash` (C++ `vault::StateHash`, ycash6 `src/vault/node.cpp:505`), the
//! value `vault_getinfo` reports as `"statehash"`.
//!
//! The preimage is every state entry in key byte order — the C++ iterates the prefixes `'b'`,
//! `'m'`, `'s'`, `'v'` in that order, each in byte order, which is the byte order of all keys —
//! each written as the C++ `CHashWriter << std::string(key) << std::string(value)`:
//! CompactSize(len) ‖ key ‖ CompactSize(len) ‖ value. The digest is SHA256d over the preimage.
//!
//! This is a pure function of the state's canonical entries ([`super::records`]), separate from
//! any storage: a column-family store computes the same value by producing the same entries.

use std::collections::BTreeMap;

use sha2::{Digest, Sha256};

use super::records::write_compact_size;
use crate::bytes::Hash32;

/// SHA256d over the canonical preimage of `entries` (key → value, already canonical bytes).
/// A `BTreeMap` iterates in key byte order, which is the order the C++ digests.
pub fn state_hash_of_entries(entries: &BTreeMap<Vec<u8>, Vec<u8>>) -> Hash32 {
    let mut h = Sha256::new();
    let mut buf = Vec::with_capacity(256);
    for (k, v) in entries {
        buf.clear();
        write_compact_size(&mut buf, k.len());
        buf.extend_from_slice(k);
        write_compact_size(&mut buf, v.len());
        buf.extend_from_slice(v);
        h.update(&buf);
    }
    Hash32(Sha256::digest(h.finalize()).into())
}

/// The C++ `uint256::GetHex()` of a hash (reversed byte order), as RPC prints `statehash`.
pub fn display_hex(h: &Hash32) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(64);
    for b in h.0.iter().rev() {
        for nib in [b >> 4, b & 0x0f] {
            if let Some(c) = HEX.get(usize::from(nib)) {
                s.push(char::from(*c));
            }
        }
    }
    s
}
