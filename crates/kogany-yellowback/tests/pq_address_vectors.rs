// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

//! The shared post-quantum address vectors (`testdata/yellowback/pq_address_vectors.json`,
//! byte-identical to ycash6 and ycash-dd `src/test/data/pq_address_vectors.json`; quantum spec §4,
//! D-9), replayed against both codecs: the plain-YEC one ([`plain_pq_address_versions`],
//! ycash6 `PlainPQAddressVersions`) and the YED one ([`Params::pq_address_versions`], ycash6
//! `yellowback::EncodeAddress`/`DecodeAddress`). C++: ycash6 `src/test/pq_address_tests.cpp`.
//!
//! The file is loaded through `load_pinned`, which checks its SHA-256 against
//! `testdata/yellowback/PIN` (the audit's cross-line leg checks that row against ycash6).

mod common;

use common::load_pinned;
use kogany_vault::{Hash32, PqOwner};
use kogany_yellowback::codecs::address::*;
use kogany_yellowback::codecs::base58::{decode_base58_check, encode_base58_check};
use kogany_yellowback::codecs::script::Holder;
use kogany_yellowback::params::{params_for_network, Params};
use serde_json::Value;

const NETWORKS: [&str; 3] = ["main", "test", "regtest"];
const COINS: [&str; 2] = ["yec", "yed"];

fn yed_params(network: &str) -> Params {
    params_for_network(network).expect("a ycashd network id")
}

/// The version table of one (network, coin).
fn versions(network: &str, coin: &str) -> PqAddressVersions {
    match coin {
        "yec" => *plain_pq_address_versions(network).expect("a ycashd network id"),
        "yed" => yed_params(network)
            .pq_address_versions
            .expect("every network has YED versions"),
        other => panic!("unknown coin {other}"),
    }
}

/// The coin's own decoder: the plain-YEC table, or the YED parameters (both forms tried, as
/// `yed_*` does with `DecodeAddress(CTxDestination)`).
fn decode(network: &str, coin: &str, address: &str) -> Option<PqOwner> {
    match coin {
        "yec" => decode_pq(address, &versions(network, coin)),
        _ => {
            let p = yed_params(network);
            let owner = decode_pq_address(address, &p);
            match decode_any_address(address, &p) {
                Some(Holder::Pq(o)) => assert_eq!(Some(o), owner, "{address}"),
                Some(Holder::KeyId(_)) => panic!("{address} decoded as a key-hash YED address"),
                None => assert_eq!(owner, None, "{address}"),
            }
            owner
        }
    }
}

fn encode(network: &str, coin: &str, owner: &PqOwner) -> Option<String> {
    match coin {
        "yec" => encode_pq(owner, &versions(network, coin)),
        _ => encode_pq_address(owner, &yed_params(network)),
    }
}

fn s<'a>(v: &'a Value, key: &str) -> &'a str {
    v[key]
        .as_str()
        .unwrap_or_else(|| panic!("{key} is a string in {v}"))
}

fn vectors() -> Value {
    let v = load_pinned("pq_address_vectors.json");
    assert_eq!(v["format"], "ycash-pq-address-vectors-1");
    assert_eq!(
        v["schemes"],
        serde_json::json!({"1": "slh-dsa-sha2-128s", "2": "fn-dsa-512"})
    );
    v
}

/// Every valid vector: its version is this table's for (network, coin, scheme); it encodes from
/// (scheme, keyhash) to exactly its text and back; and it decodes nowhere else.
#[test]
fn valid_vectors_encode_decode_and_stay_on_their_network_and_coin() {
    let v = vectors();
    let valid = v["valid"].as_array().unwrap();
    assert_eq!(valid.len(), 72);
    let mut seen = std::collections::BTreeSet::new();
    for row in valid {
        let (network, coin, address) = (s(row, "network"), s(row, "coin"), s(row, "address"));
        let scheme = u8::try_from(row["scheme"].as_u64().unwrap()).unwrap();
        let owner = PqOwner {
            scheme,
            hash: Hash32::from_slice(&hex::decode(s(row, "keyhash")).unwrap()).unwrap(),
        };
        seen.insert((network, coin, scheme));
        let table = versions(network, coin);
        let (_, version) = table
            .iter()
            .find(|(sch, _)| *sch == scheme)
            .unwrap_or_else(|| panic!("{network}/{coin} has no version for scheme {scheme}"));
        assert_eq!(hex::encode(version), s(row, "version"), "{address}");
        // The prefix names the scheme: f(alcon) for 2, s(lh) for 1.
        let letter = if scheme == 2 { 'f' } else { 's' };
        assert_eq!(address.chars().nth(2), Some(letter), "{address}");
        assert_eq!(address.len(), 53);
        assert_eq!(
            decode_base58_check(address).map(|d| d.len()),
            Some(35),
            "{address}"
        );
        assert_eq!(
            encode(network, coin, &owner).as_deref(),
            Some(address),
            "encode"
        );
        assert_eq!(decode(network, coin, address), Some(owner), "decode");
        for n in NETWORKS {
            for c in COINS {
                if (n, c) != (network, coin) {
                    assert_eq!(
                        decode(n, c, address),
                        None,
                        "{address} ({network}/{coin}) decodes as {n}/{c}"
                    );
                }
            }
        }
    }
    // Every (network, coin, scheme) is covered.
    assert_eq!(seen.len(), NETWORKS.len() * COINS.len() * 2);
}

/// Every invalid vector is refused on its own network and coin, and so everywhere.
#[test]
fn invalid_vectors_are_refused_everywhere() {
    let v = vectors();
    let invalid = v["invalid"].as_array().unwrap();
    assert_eq!(invalid.len(), 60);
    let mut reasons = std::collections::BTreeSet::new();
    for row in invalid {
        let address = s(row, "address");
        reasons.insert(s(row, "reason"));
        for n in NETWORKS {
            for c in COINS {
                assert_eq!(
                    decode(n, c, address),
                    None,
                    "{address} ({}) decodes as {n}/{c}",
                    s(row, "reason")
                );
            }
        }
    }
    assert_eq!(
        reasons.into_iter().collect::<Vec<_>>(),
        [
            "bad-checksum",
            "extended",
            "old-form",
            "truncated",
            "unknown-version"
        ]
    );
}

/// Round trips over all the tables: every registered scheme's key hash (edge values and a
/// sweep) re-encodes to the text it decodes from; an unregistered scheme encodes nothing.
#[test]
fn round_trips_on_every_table() {
    for n in NETWORKS {
        for c in COINS {
            for scheme in 0..=255u8 {
                for fill in [0u8, 1, 0x7f, 0x80, 0xfe, 0xff] {
                    let owner = PqOwner {
                        scheme,
                        hash: Hash32([fill; 32]),
                    };
                    let Some(a) = encode(n, c, &owner) else {
                        assert!(scheme != 1 && scheme != 2, "{n}/{c} scheme {scheme}");
                        continue;
                    };
                    assert!(scheme == 1 || scheme == 2);
                    assert_eq!(a.len(), 53);
                    assert_eq!(decode(n, c, &a), Some(owner));
                    // The pre-D-9 payload of the same key (the 3-byte version's first two bytes,
                    // then the scheme byte) is refused.
                    let data = decode_base58_check(&a).unwrap();
                    let mut old = data[..2].to_vec();
                    old.push(scheme);
                    old.extend_from_slice(&data[3..]);
                    assert_eq!(decode(n, c, &encode_base58_check(&old)), None);
                }
            }
        }
    }
}
