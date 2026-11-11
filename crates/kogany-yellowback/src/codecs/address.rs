// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

//! Yellowback addresses (ycash6 `src/yellowback/address.{h,cpp}`, plan D10, quantum spec §4) and
//! the plain-YEC post-quantum address (ycash6 `src/key_io.{h,cpp}`, D-Q-20):
//!
//! - a key hash: `Base58Check(addressVersion || keyId:20)`, versions `0x1FDD` / `0x2007` /
//!   `0x2002`, rendering `yb…` / `yt…` / `yr…` in 35 characters; it decodes to an ordinary P2PKH
//!   destination;
//! - a post-quantum key (D-9): `Base58Check(version || keyHash:32)`, 53 characters, with one 3-byte
//!   version per (network, coin, scheme), so the prefix names the scheme: YED `ybf…`/`ybs…`,
//!   `ytf…`/`yts…`, `yrf…`/`yrs…` ([`Params::pq_address_versions`]); plain YEC `sqf…`/`sqs…`,
//!   `tqf…`/`tqs…`, `rqf…`/`rqs…` ([`plain_pq_address_versions`]). One table per network and coin
//!   serves both directions ([`encode_pq`], [`decode_pq_data`]); the pre-D-9 form
//!   (`2-byte version || scheme || keyHash`) is neither produced nor accepted.
//!
//! The version bytes are [`Params::address_version`] / [`Params::pq_address_versions`]; a network
//! without them (the C++ empty vector and map, [`Params::default`]) encodes the bare key-hash body,
//! no post-quantum address, and decodes nothing, as the C++ does.

use kogany_vault::template::{
    is_known_pq_scheme, PQ_SCHEME_FN_DSA_512, PQ_SCHEME_SLH_DSA_SHA2_128S,
};
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

/// A post-quantum address's Base58Check versions (ycash6 `PQAddressVersions`, D-9): one 3-byte
/// version per registered scheme, `(scheme, version)`.
pub type PqAddressVersions = [(u8, [u8; 3]); 2];

/// The plain-YEC post-quantum versions on mainnet: `4ddd04` `sqf…`, `4dde6a` `sqs…`.
pub const PLAIN_PQ_VERSIONS_MAIN: PqAddressVersions = [
    (PQ_SCHEME_FN_DSA_512, [0x4D, 0xDD, 0x04]),
    (PQ_SCHEME_SLH_DSA_SHA2_128S, [0x4D, 0xDE, 0x6A]),
];
/// The plain-YEC post-quantum versions on the testnets: `4f6519` `tqf…`, `4f667f` `tqs…`.
pub const PLAIN_PQ_VERSIONS_TEST: PqAddressVersions = [
    (PQ_SCHEME_FN_DSA_512, [0x4F, 0x65, 0x19]),
    (PQ_SCHEME_SLH_DSA_SHA2_128S, [0x4F, 0x66, 0x7F]),
];
/// The plain-YEC post-quantum versions on regtest: `4c54ef` `rqf…`, `4c5655` `rqs…`.
pub const PLAIN_PQ_VERSIONS_REGTEST: PqAddressVersions = [
    (PQ_SCHEME_FN_DSA_512, [0x4C, 0x54, 0xEF]),
    (PQ_SCHEME_SLH_DSA_SHA2_128S, [0x4C, 0x56, 0x55]),
];

/// `PlainPQAddressVersions` (ycash6 `src/key_io.cpp`): the plain-YEC post-quantum versions of a
/// ycashd network ID (`"main"`, `"test"`, `"regtest"`); `None` for any other.
pub fn plain_pq_address_versions(network: &str) -> Option<&'static PqAddressVersions> {
    match network {
        "main" => Some(&PLAIN_PQ_VERSIONS_MAIN),
        "test" => Some(&PLAIN_PQ_VERSIONS_TEST),
        "regtest" => Some(&PLAIN_PQ_VERSIONS_REGTEST),
        _ => None,
    }
}

/// `EncodePQAddress`: `Base58Check(versions[scheme] || keyHash)`; `None` for a scheme outside the
/// registry or without a version.
pub fn encode_pq(owner: &PqOwner, versions: &PqAddressVersions) -> Option<String> {
    if !is_known_pq_scheme(owner.scheme) {
        return None;
    }
    let (_, version) = versions.iter().find(|(s, _)| *s == owner.scheme)?;
    let mut data = version.to_vec();
    data.extend_from_slice(&owner.hash.0);
    Some(encode_base58_check(&data))
}

/// `DecodePQAddressData`: the key of a decoded Base58Check payload that is `versions[s] ||
/// keyHash:32` for a registered scheme `s`; any other version or length (the pre-D-9 form among
/// them) is `None`.
pub fn decode_pq_data(data: &[u8], versions: &PqAddressVersions) -> Option<PqOwner> {
    let (scheme, hash) = versions.iter().find_map(|(scheme, version)| {
        let hash = data.strip_prefix(version.as_slice())?;
        (hash.len() == 32).then_some((*scheme, hash))
    })?;
    let hash = Hash32::from_slice(hash)?;
    is_known_pq_scheme(scheme).then_some(PqOwner { scheme, hash })
}

/// `DecodePQAddress`: [`decode_pq_data`] of a Base58Check string.
pub fn decode_pq(s: &str, versions: &PqAddressVersions) -> Option<PqOwner> {
    decode_pq_data(&decode_base58_check(s)?, versions)
}

/// `EncodeAddress(CPQKeyID)`: the 53-character YED address; `None` for an unregistered scheme or
/// a network without post-quantum versions.
pub fn encode_pq_address(owner: &PqOwner, p: &Params) -> Option<String> {
    encode_pq(owner, p.pq_address_versions.as_ref()?)
}

/// `DecodeAddress(CPQKeyID)`: the key of a post-quantum Yellowback address of this network with a
/// registered scheme.
pub fn decode_pq_address(s: &str, p: &Params) -> Option<PqOwner> {
    decode_pq(s, p.pq_address_versions.as_ref()?)
}

/// `DecodeAddress(CTxDestination)`: either form, the key-hash form tried first.
pub fn decode_any_address(s: &str, p: &Params) -> Option<Holder> {
    decode_address(s, p)
        .map(Holder::KeyId)
        .or_else(|| decode_pq_address(s, p).map(Holder::Pq))
}
