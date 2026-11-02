// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

//! ycash6 `src/test/yellowback_attest_tests.cpp` (BUNDLE-1, W3, R13, R17), case for case: the
//! message layout and strict low-S verification against the pinned
//! `yellowback_attest_vectors.json`, the 74-byte codec and the rejections.

mod attest_common;
mod common;

use std::collections::BTreeSet;

use attest_common::{internal32, pubkey, sig64, sign_compact, u256s};
use kogany_vault::Hash32;
use kogany_yellowback::attest::{
    attest_message, decode_attestation, encode_attestation, verify_compact_sig, Attestation,
    ATTESTATION_SIZE,
};
use serde_json::Value;
use sha2::{Digest, Sha256};

fn vectors() -> Value {
    common::load_pinned("yellowback_attest_vectors.json")
}

fn u32of(v: &Value) -> u32 {
    u32::try_from(v.as_i64().unwrap()).unwrap()
}

fn u16of(v: &Value) -> u16 {
    u16::try_from(v.as_i64().unwrap()).unwrap()
}

fn bytes(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().unwrap()).unwrap()
}

fn secret(v: &Value) -> [u8; 32] {
    bytes(v).try_into().unwrap()
}

/// The displayed form of an internal hash (`uint256::GetHex`).
fn display(h: &Hash32) -> String {
    let mut b = h.0;
    b.reverse();
    hex::encode(b)
}

#[test]
fn message_layout() {
    // SHA256("YBATTEST1" || seq LE16 || price LE32 || citedHeight LE32 || blockHash internal bytes)
    let mut bh = [0u8; 32];
    for (i, b) in bh.iter_mut().enumerate() {
        *b = i as u8;
    }
    let bh = Hash32(bh);
    let mut pre = b"YBATTEST1".to_vec();
    pre.extend_from_slice(&[0x34, 0x12, 0x78, 0x56, 0x34, 0x12, 0x21, 0x43, 0x65, 0x07]);
    pre.extend_from_slice(&bh.0);
    assert_eq!(pre.len(), 51);
    let expect = Hash32(Sha256::digest(&pre).into());
    assert_eq!(
        attest_message(0x1234, 0x1234_5678, 0x0765_4321, &bh),
        expect
    );
    // Every field is bound.
    assert_ne!(
        attest_message(0x1235, 0x1234_5678, 0x0765_4321, &bh),
        expect
    );
    assert_ne!(
        attest_message(0x1234, 0x1234_5679, 0x0765_4321, &bh),
        expect
    );
    assert_ne!(
        attest_message(0x1234, 0x1234_5678, 0x0765_4322, &bh),
        expect
    );
    let mut other = bh;
    other.0[0] ^= 1;
    assert_ne!(
        attest_message(0x1234, 0x1234_5678, 0x0765_4321, &other),
        expect
    );
    // The vectors' messages.
    let doc = vectors();
    assert_eq!(doc["prefix"].as_str().unwrap(), "YBATTEST1");
    for v in doc["valid"].as_array().unwrap() {
        let bhi = internal32(v["blockHashInternal"].as_str().unwrap());
        let msg = attest_message(
            u16of(&v["seq"]),
            u32of(&v["priceMicroUsd"]),
            u32of(&v["citedHeight"]),
            &bhi,
        );
        assert_eq!(hex::encode(msg.0), v["message"].as_str().unwrap());
        // The displayed form is the reversed hex of the internal bytes.
        assert_eq!(display(&bhi), v["blockHash"].as_str().unwrap());
    }
}

#[test]
fn vectors_verify() {
    let doc = vectors();
    let valid = doc["valid"].as_array().unwrap();
    let keys = doc["keys"].as_array().unwrap();
    assert_eq!(valid.len(), 8); // seq 0..5 once each, then seq 0 and 1 again
    assert_eq!(keys.len(), 6);
    // The pubkeys are what the secrets derive.
    for k in keys {
        assert_eq!(
            hex::encode(pubkey(&secret(&k["secret"])).0),
            k["pubkey"].as_str().unwrap()
        );
    }
    for v in valid {
        let msg = internal32(v["message"].as_str().unwrap());
        let pk = bytes(&v["pubkey"]);
        let sig = sig64(v["sig"].as_str().unwrap());
        assert!(verify_compact_sig(&pk, &msg, &sig), "seq {}", v["seq"]);
        // libsecp256k1's RFC 6979 signature of the same message re-derives the vector's.
        for k in keys.iter().filter(|k| k["seq"] == v["seq"]) {
            assert_eq!(
                hex::encode(sign_compact(&secret(&k["secret"]), &msg)),
                v["sig"].as_str().unwrap()
            );
        }
        // The 74-byte form in the file is EncodeAttestation of the parts.
        let att = Attestation {
            seq: u16of(&v["seq"]),
            price_micro_usd: u32of(&v["priceMicroUsd"]),
            cited_height: u32of(&v["citedHeight"]),
            sig,
        };
        assert_eq!(
            hex::encode(encode_attestation(&att)),
            v["attestation"].as_str().unwrap()
        );
    }
}

#[test]
fn highs_rejected() {
    // A high-S encoding of a valid signature is invalid, never normalised (R17).
    let doc = vectors();
    let mut seen = 0;
    for v in doc["valid"].as_array().unwrap() {
        let msg = internal32(v["message"].as_str().unwrap());
        let pk = bytes(&v["pubkey"]);
        let low = v["sig"].as_str().unwrap();
        let high = v["sigHighS"].as_str().unwrap();
        assert!(verify_compact_sig(&pk, &msg, &sig64(low)));
        assert!(!verify_compact_sig(&pk, &msg, &sig64(high)));
        assert_ne!(low, high);
        assert_eq!(low[..64], high[..64]); // same r
        seen += 1;
    }
    assert_eq!(seen, 8);
    for v in doc["invalid"].as_array().unwrap() {
        if v["name"] != "high_s" {
            continue;
        }
        let msg = attest_message(
            u16of(&v["seq"]),
            u32of(&v["priceMicroUsd"]),
            u32of(&v["citedHeight"]),
            &internal32(v["blockHashInternal"].as_str().unwrap()),
        );
        assert!(!verify_compact_sig(
            &bytes(&v["pubkey"]),
            &msg,
            &sig64(v["sig"].as_str().unwrap())
        ));
    }
}

#[test]
fn invalid_vectors_rejected() {
    let doc = vectors();
    let mut names = BTreeSet::new();
    for v in doc["invalid"].as_array().unwrap() {
        let msg = attest_message(
            u16of(&v["seq"]),
            u32of(&v["priceMicroUsd"]),
            u32of(&v["citedHeight"]),
            &internal32(v["blockHashInternal"].as_str().unwrap()),
        );
        assert!(
            !verify_compact_sig(
                &bytes(&v["pubkey"]),
                &msg,
                &sig64(v["sig"].as_str().unwrap())
            ),
            "{}",
            v["name"]
        );
        assert!(!v["why"].as_str().unwrap().is_empty());
        names.insert(v["name"].as_str().unwrap().to_owned());
    }
    for n in ["high_s", "wrong_block_hash", "wrong_key"] {
        assert!(names.contains(n), "{n}");
    }
    // Degenerate inputs: an invalid key, an uncompressed key, an all-zero and an all-0xff signature.
    let v0 = &doc["valid"][0];
    let msg = internal32(v0["message"].as_str().unwrap());
    let sig = sig64(v0["sig"].as_str().unwrap());
    let pk0 = bytes(&v0["pubkey"]);
    assert!(!verify_compact_sig(&[], &msg, &sig));
    let unc = {
        let sk = secp256k1::SecretKey::from_secret_bytes([7u8; 32]).unwrap();
        secp256k1::PublicKey::from_secret_key(&sk).serialize_uncompressed()
    };
    assert!(!verify_compact_sig(&unc, &msg, &sig));
    let mut off_curve = pk0.clone();
    off_curve[1] ^= 0xff;
    assert!(!verify_compact_sig(&off_curve, &msg, &sig)); // another point, or none
    assert!(!verify_compact_sig(&pk0, &msg, &[0u8; 64]));
    assert!(!verify_compact_sig(&pk0, &msg, &[0xffu8; 64]));
    // A fresh key's signature verifies; a flipped bit does not.
    let secret = [0x5au8; 32];
    let mut compact = sign_compact(&secret, &msg);
    assert!(verify_compact_sig(&pubkey(&secret).0, &msg, &compact));
    compact[40] ^= 1;
    assert!(!verify_compact_sig(&pubkey(&secret).0, &msg, &compact));
}

#[test]
fn shared_vector_list() {
    // The flat "vectors" list shared with the Python framework: every row decodes, and verifies
    // iff `valid`.
    let doc = vectors();
    let (mut valid, mut invalid, mut regtest) = (0, 0, 0);
    for r in doc["vectors"].as_array().unwrap() {
        let att = decode_attestation(&bytes(&r["attestation"])).unwrap();
        assert_eq!(att.seq, u16of(&r["seq"]));
        assert_eq!(att.price_micro_usd, u32of(&r["price"]));
        assert_eq!(att.cited_height, u32of(&r["citedHeight"]));
        let block_hash = u256s(r["blockHash"].as_str().unwrap()); // the display form, reversed
        let msg = attest_message(att.seq, att.price_micro_usd, att.cited_height, &block_hash);
        let pk = bytes(&r["pubkey"]);
        let ok = verify_compact_sig(&pk, &msg, &att.sig);
        assert_eq!(ok, r["valid"].as_bool().unwrap(), "{}", r["attestation"]);
        if r["valid"].as_bool().unwrap() {
            valid += 1;
            // The secret re-derives the key and, through RFC 6979, the very same signature.
            let s = secret(&r["secret"]);
            assert_eq!(pubkey(&s).0.to_vec(), pk);
            assert_eq!(sign_compact(&s, &msg), att.sig);
        } else {
            invalid += 1;
        }
        if r["name"]
            .as_str()
            .is_some_and(|n| n.starts_with("regtest-attestor-0"))
        {
            regtest += 1;
            assert_eq!(
                r["pubkey"].as_str().unwrap(),
                "0219ce7f2f737be07548a7243c605b76a09e039942f58ef91fe52771bf1f88767b"
            );
            assert_eq!(
                r["blockHash"].as_str().unwrap(),
                format!("{}01", "0".repeat(62))
            );
            assert_eq!(block_hash.0[0], 1); // internal bytes: 01 then 31 zeros
                                            // The framework's attestor secret is sha256("yellowback-regtest-attestor-0").
            let s: [u8; 32] = Sha256::digest(b"yellowback-regtest-attestor-0").into();
            assert_eq!(hex::encode(s), r["secret"].as_str().unwrap());
            assert!(ok);
        }
    }
    assert_eq!(valid, 10);
    assert_eq!(invalid, 5);
    assert_eq!(regtest, 2);
}

#[test]
fn codec() {
    let mut a = Attestation {
        seq: 0xBEEF,
        price_micro_usd: 0x0102_0304,
        cited_height: 0x0A0B_0C0D,
        sig: [0u8; 64],
    };
    for (i, b) in a.sig.iter_mut().enumerate() {
        *b = 0x40 + i as u8;
    }
    let enc = encode_attestation(&a);
    assert_eq!(enc.len(), ATTESTATION_SIZE);
    assert_eq!(ATTESTATION_SIZE, 74);
    assert_eq!(
        enc[..10],
        [0xEF, 0xBE, 0x04, 0x03, 0x02, 0x01, 0x0D, 0x0C, 0x0B, 0x0A]
    );
    assert_eq!(enc[10..], a.sig);
    let d = decode_attestation(&enc).unwrap();
    assert_eq!(d, a);
    assert_eq!(encode_attestation(&d), enc);
    // Any other length is refused.
    assert!(decode_attestation(&[]).is_none());
    assert!(decode_attestation(&enc[..73]).is_none());
    let mut longer = enc.to_vec();
    longer.push(0);
    assert!(decode_attestation(&longer).is_none());
}
