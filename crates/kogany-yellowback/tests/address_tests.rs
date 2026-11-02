// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

//! ycash6 `src/test/yellowback_address_tests.cpp` (`prefixes_and_roundtrip`, `mainnet_yb_vectors`,
//! `rejects_garbage`), extended to the post-quantum 53-character form (quantum spec §4), the C++
//! Base58 decoder's acceptance (`src/base58.cpp`), and the owners of `pq_wallet_vectors.json`.
//!
//! The PQ and testnet/regtest known answers were computed with ycash6's independent Python
//! implementation, `qa/rpc-tests/test_framework/yellowback_model.py` `base58check_encode` at
//! `65cb4ae0f` (the C++ test has key-hash known answers on mainnet only).

mod common;

use common::{key, load_pinned};
use kogany_vault::template::hash160;
use kogany_vault::{Hash32, PqOwner};
use kogany_yellowback::codecs::address::*;
use kogany_yellowback::codecs::base58::*;
use kogany_yellowback::codecs::script::Holder;
use kogany_yellowback::params::{main_params, regtest_params, test_params, Params};

/// A YED attestor set for the regtest parameters (U-22; addresses do not depend on it).
fn test_set() -> [u8; 32] {
    [0x5e; 32]
}

fn nets() -> [(Params, &'static str); 3] {
    [
        (main_params(), "yb"),
        (test_params(), "yt"),
        (regtest_params(1, 0, 0, test_set()), "yr"),
    ]
}

#[test]
fn prefixes_and_roundtrip() {
    let [(main, _), (test, _), (regtest, _)] = nets();
    let mut ids: Vec<[u8; 20]> = vec![[0; 20], [0xff; 20]];
    ids.extend((1..=20u8).map(|i| hash160(&key(i).0)));
    for id in &ids {
        let m = encode_address(id, &main);
        let t = encode_address(id, &test);
        let r = encode_address(id, &regtest);
        assert_eq!(&m[..2], "yb");
        assert_eq!(&t[..2], "yt");
        assert_eq!(&r[..2], "yr");
        assert_eq!((m.len(), t.len(), r.len()), (35, 35, 35));
        assert_eq!(decode_address(&m, &main), Some(*id));
        assert_eq!(decode_address(&t, &test), Some(*id));
        assert_eq!(decode_address(&r, &regtest), Some(*id));
        // Cross-network rejection.
        assert!(decode_address(&m, &test).is_none());
        assert!(decode_address(&m, &regtest).is_none());
        assert!(decode_address(&t, &main).is_none());
        assert!(decode_address(&r, &main).is_none());
        assert!(!is_valid_address(&t, &regtest));
        // The key-hash form is not a PQ address and the reverse.
        assert!(decode_pq_address(&m, &main).is_none());
        assert_eq!(decode_any_address(&m, &main), Some(Holder::KeyId(*id)));
    }
}

#[test]
fn mainnet_yb_vectors() {
    // D-Q-21: the mainnet prefix is "yb…" (version 0x1FDD); known answers at the extreme payloads.
    let main = main_params();
    assert_eq!(main.address_version, Some([0x1f, 0xdd]));
    assert_eq!(
        encode_address(&[0; 20], &main),
        "ybCxAdkN4XYouwZHde9wgVkDDujbS9ByGQz"
    );
    assert_eq!(
        encode_address(&[0xff; 20], &main),
        "ybcHmcrfMEjGnkzRifaGzysV1YErNnEcqyf"
    );
    assert_eq!(
        encode_address(&[0x33; 20], &main),
        "ybHctRyDvGauHhqv3r3D9PmfadqSpd7iKbS"
    );
    assert_eq!(
        decode_address("ybHctRyDvGauHhqv3r3D9PmfadqSpd7iKbS", &main),
        Some([0x33; 20])
    );
    // The retired "ye…" version 0x1FE4 is no longer a mainnet Yellowback address.
    let mut old = vec![0x1F, 0xE4];
    old.extend_from_slice(&[0x33; 20]);
    assert!(decode_address(&encode_base58_check(&old), &main).is_none());
}

#[test]
fn rejects_garbage() {
    let main = main_params();
    assert!(decode_address("", &main).is_none());
    assert!(decode_address("yb", &main).is_none());
    // A Ycash transparent address (s1…) is not a Yellowback address.
    assert!(decode_address("s1RyNzGjPzkgc7jP6uvjJx8tmv7gY9dvRbP", &main).is_none());
    // Checksum damage.
    let a = encode_address(&hash160(&key(7).0), &main);
    let mut damaged = a.clone();
    let last = damaged.pop().unwrap();
    damaged.push(if last == '1' { '2' } else { '1' });
    assert!(decode_address(&damaged, &main).is_none());
    // Version bytes right but payload wrong length.
    let mut data = main.address_version.unwrap().to_vec();
    data.extend_from_slice(&[0; 19]);
    assert!(decode_address(&encode_base58_check(&data), &main).is_none());
}

/// Known answers from `yellowback_model.py` (see the file header) for both forms on the three
/// networks; the PQ form is 53 characters with the same prefixes.
#[test]
fn pq_addresses_53_characters_known_answers() {
    let slh = Hash32::from_slice(
        &hex::decode("73efa99cd22fe553222b1db6a6a021b3cba29dafd4fb4dfb50be69abcfcf9364").unwrap(),
    )
    .unwrap();
    let rows: [(usize, &str, &str, &str, &str, &str); 3] = [
        (
            0,
            "ybCxAdkN4XYouwZHde9wgVkDDujbS9ByGQz",
            "ybcHmcrfMEjGnkzRifaGzysV1YErNnEcqyf",
            "yb5su7q3DBbMB7Efeo2xRAVJmU8XjTCoZgSjryg4BuiudZk7Cx5EU",
            "yb5wncBW7FJCXZWJpCr7fAPwy1xkxtWDFS221CAMZhiDeLjBHdsWi",
            "yb5tnBGDjRGgh3RWwnhy6Ke5CDyrjDHb885VYHmH3atY3KAiRLbp4",
        ),
        (
            1,
            "yt79VzJtAM8GiHm9Gfmw4s1eGLvR42YuPKp",
            "ytWV6yRBT4Jjb7CHMhCGPM8v3yRfzYuRUN3",
            "yt6ZQsPUfKGhzAkBzPkM7iWBn66dkTKzAQFNrKuu5NkaUwowPfLVW",
            "yt6dJMjwZNyZLd1q9oZWMiQpydvrytdPr9pezYQCTAjtVio7KiffW",
            "yt6aHvpfBYx3W6w3HPRMnsexCqwxkDQmiqt8Xe17w3vCthEWWcSf8",
        ),
        (
            2,
            "yr6TV4mPioDxLCbSqYgGUSPHLCQ8LVNj2v7",
            "yrVo63sh1WQRD22ava6bnvWZ7puPH6iyLcP",
            "yr2Sas8S4s7t4XW1Eegpca4rxc1pcmUBz84f2VZ3kW42X1BDR7x8X",
            "yr2WUMUtxvpjQymeQ4VyrZyWA9r3rCmbfsdwAi3M8J3LXnAGrkb5E",
            "yr2TTvZcb6oDaTgrXeMqHjDdPMs9cXYyYZhQhoeGcBDevkbiDcTX7",
        ),
    ];
    let nets = nets();
    for (i, p00, pff, pq1_00, pq2_ff, pq1_slh) in rows {
        let (p, prefix) = &nets[i];
        assert_eq!(encode_address(&[0; 20], p), p00);
        assert_eq!(encode_address(&[0xff; 20], p), pff);
        let cases = [
            (
                PqOwner {
                    scheme: 1,
                    hash: Hash32::ZERO,
                },
                pq1_00,
            ),
            (
                PqOwner {
                    scheme: 2,
                    hash: Hash32([0xff; 32]),
                },
                pq2_ff,
            ),
            (
                PqOwner {
                    scheme: 1,
                    hash: slh,
                },
                pq1_slh,
            ),
        ];
        for (o, want) in cases {
            let a = encode_pq_address(&o, p).unwrap();
            assert_eq!(a, want);
            assert_eq!(a.len(), 53);
            assert!(a.starts_with(prefix));
            assert_eq!(decode_pq_address(&a, p), Some(o));
            assert_eq!(decode_any_address(&a, p), Some(Holder::Pq(o)));
            assert!(decode_address(&a, p).is_none());
            for (q, _) in nets.iter().filter(|(q, _)| q.network != p.network) {
                assert!(
                    decode_pq_address(&a, q).is_none(),
                    "{a} is not a {} address",
                    q.network
                );
            }
        }
    }
}

#[test]
fn pq_address_registered_schemes_only() {
    let main = main_params();
    for scheme in 0..=255u8 {
        let o = PqOwner {
            scheme,
            hash: Hash32([0x5a; 32]),
        };
        let known = scheme == 1 || scheme == 2;
        assert_eq!(
            encode_pq_address(&o, &main).is_some(),
            known,
            "scheme {scheme}"
        );
        // A well-formed payload with an unregistered scheme does not decode.
        let mut data = main.pq_address_version.unwrap().to_vec();
        data.push(scheme);
        data.extend_from_slice(&[0x5a; 32]);
        assert_eq!(
            decode_pq_address(&encode_base58_check(&data), &main).is_some(),
            known
        );
    }
    // Wrong body length for the PQ form.
    let mut data = main.pq_address_version.unwrap().to_vec();
    data.extend_from_slice(&[1; 32]);
    assert!(decode_pq_address(&encode_base58_check(&data), &main).is_none());
    // A network without version bytes (Params::default, the C++ empty vector) decodes nothing.
    let none = Params::default();
    assert!(decode_address(&encode_address(&[1; 20], &none), &none).is_none());
    assert!(decode_pq_address(
        &encode_pq_address(
            &PqOwner {
                scheme: 1,
                hash: Hash32::ZERO
            },
            &none
        )
        .unwrap(),
        &none
    )
    .is_none());
}

/// `src/base58.cpp`'s acceptance: C-string semantics, leading/trailing C white space, nothing else.
#[test]
fn base58_matches_the_cpp_decoder() {
    let main = main_params();
    let a = "ybHctRyDvGauHhqv3r3D9PmfadqSpd7iKbS";
    for ok in [
        format!(" {a}"),
        format!("\t\n{a} \r\x0b\x0c"),
        format!("{a}\0trailing after the NUL"),
        format!("  {a}  \0x"),
    ] {
        assert_eq!(decode_address(&ok, &main), Some([0x33; 20]), "{ok:?}");
    }
    for bad in [
        format!("{a}x"),
        format!("{} {}", &a[..10], &a[10..]),
        format!("{a}0"),
        format!("{a}\u{a0}"),
        format!("\0{a}"),
    ] {
        assert!(decode_address(&bad, &main).is_none(), "{bad:?}");
    }
    // Leading zero bytes are leading '1's, both ways.
    assert_eq!(encode_base58(&[0, 0, 1]), "112");
    assert_eq!(decode_base58("112"), Some(vec![0, 0, 1]));
    assert_eq!(encode_base58(&[]), "");
    assert_eq!(decode_base58(""), Some(vec![]));
    assert_eq!(decode_base58("   "), Some(vec![]));
    // Bitcoin Core's base58_encode_decode.json rows.
    for (hexs, b58) in [
        ("61", "2g"),
        ("626262", "a3gV"),
        ("636363", "aPEr"),
        (
            "73696d706c792061206c6f6e6720737472696e67",
            "2cFupjhnEsSn59qHXstmK2ffpLv2",
        ),
        (
            "00eb15231dfceb60925886b67d065299925915aeb172c06647",
            "1NS17iag9jJgTHD1VXjvLCEnZuQ3rJDE9L",
        ),
        ("516b6fcd0f", "ABnLTmg"),
        ("bf4f89001e670274dd", "3SEo3LWLoPntC"),
        ("572e4794", "3EFU7m"),
        ("ecac89cad93923c02321", "EJDM8drfXA6uyA"),
        ("10c8511e", "Rt5zm"),
        ("00000000000000000000", "1111111111"),
    ] {
        let b = hex::decode(hexs).unwrap();
        assert_eq!(encode_base58(&b), b58);
        assert_eq!(decode_base58(b58), Some(b));
    }
    // Checksum: a short string fails, a good one strips its 4 bytes.
    assert!(decode_base58_check("2g").is_none());
    assert_eq!(
        decode_base58_check(&encode_base58_check(b"abc")),
        Some(b"abc".to_vec())
    );
}

/// `pq_wallet_vectors.json`: the SLH-DSA owner each wallet line derives (`hdSeed.slh`,
/// `mnemonic.slh`) has `keyhash = key_hash(1, pk)`, and its YED address round-trips on every
/// network. The HKDF seed derivation itself (`derive[]`) is the wallet's (the sidecar, S-track).
#[test]
fn pq_wallet_vectors_owner_addresses() {
    let v = load_pinned("pq_wallet_vectors.json");
    assert_eq!(v["format"], "ycash-pq-wallet-vectors-1");
    for line in ["hdSeed", "mnemonic"] {
        let slh = &v[line]["slh"];
        assert_eq!(slh["index"], 0);
        let pk = hex::decode(slh["pk"].as_str().unwrap()).unwrap();
        let keyhash = hex::decode(slh["keyhash"].as_str().unwrap()).unwrap();
        assert_eq!(kogany_pq::key_hash(1, &pk).to_vec(), keyhash, "{line}");
        let o = PqOwner {
            scheme: 1,
            hash: Hash32::from_slice(&keyhash).unwrap(),
        };
        for (p, prefix) in nets() {
            let a = encode_pq_address(&o, &p).unwrap();
            assert_eq!(a.len(), 53);
            assert!(a.starts_with(prefix));
            assert_eq!(decode_pq_address(&a, &p), Some(o));
        }
    }
}
