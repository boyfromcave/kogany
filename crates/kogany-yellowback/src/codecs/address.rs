// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

//! Yellowback addresses (ycash6 `src/yellowback/address.{h,cpp}`, plan D10, quantum spec §4):
//!
//! - a key hash: `Base58Check(addressVersion || keyId:20)`, versions `0x1FDD` / `0x2007` /
//!   `0x2002`, rendering `yb…` / `yt…` / `yr…` in 35 characters; it decodes to an ordinary P2PKH
//!   destination;
//! - a post-quantum key: `Base58Check(pqAddressVersion || scheme || keyHash:32)`, versions
//!   `0x56AB` / `0x571E` / `0x5710`, the same prefixes in 53 characters; only a registered scheme
//!   encodes or decodes.
//!
//! The version bytes are [`Params::address_version`] / [`Params::pq_address_version`]; a network
//! without them (the C++ empty vector, [`Params::default`]) encodes the bare body and decodes
//! nothing, as the C++ does.

use kogany_vault::template::is_known_pq_scheme;
use kogany_vault::{Hash32, PqOwner};

use super::base58::{decode_base58_check, encode_base58_check};
use super::script::Holder;
use crate::params::Params;

/// `EncodeAddress(CKeyID)`.
pub fn encode_address(key_id: &[u8; 20], p: &Params) -> String {
    let mut data = p.address_version.map(Vec::from).unwrap_or_default();
    data.extend_from_slice(key_id);
    encode_base58_check(&data)
}

/// `version || body` split off a decoded address, if the version is this network's.
fn body_after(data: &[u8], version: Option<[u8; 2]>) -> Option<&[u8]> {
    data.strip_prefix(version?.as_slice())
}

/// `DecodeAddress(CKeyID)`: the key hash of a key-hash Yellowback address of this network.
pub fn decode_address(s: &str, p: &Params) -> Option<[u8; 20]> {
    let data = decode_base58_check(s)?;
    <[u8; 20]>::try_from(body_after(&data, p.address_version)?).ok()
}

/// `IsValidAddress`: [`decode_address`] succeeds.
pub fn is_valid_address(s: &str, p: &Params) -> bool {
    decode_address(s, p).is_some()
}

/// `EncodeAddress(CPQKeyID)`: the 53-character address; `None` for an unregistered scheme.
pub fn encode_pq_address(owner: &PqOwner, p: &Params) -> Option<String> {
    if !is_known_pq_scheme(owner.scheme) {
        return None;
    }
    let mut data = p.pq_address_version.map(Vec::from).unwrap_or_default();
    data.push(owner.scheme);
    data.extend_from_slice(&owner.hash.0);
    Some(encode_base58_check(&data))
}

/// `DecodeAddress(CPQKeyID)`: the key of a post-quantum Yellowback address of this network with a
/// registered scheme.
pub fn decode_pq_address(s: &str, p: &Params) -> Option<PqOwner> {
    let data = decode_base58_check(s)?;
    let (&scheme, hash) = body_after(&data, p.pq_address_version)?.split_first()?;
    let hash = Hash32::from_slice(hash)?;
    is_known_pq_scheme(scheme).then_some(PqOwner { scheme, hash })
}

/// `DecodeAddress(CTxDestination)`: either form, the key-hash form tried first.
pub fn decode_any_address(s: &str, p: &Params) -> Option<Holder> {
    decode_address(s, p)
        .map(Holder::KeyId)
        .or_else(|| decode_pq_address(s, p).map(Holder::Pq))
}
