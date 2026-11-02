// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

//! Shared helpers for the attest tests (W5-c): the C++ fixtures' transaction builders, the
//! RFC 6979 compact signer, the `uint256S` reading and a recording signature cache.
#![allow(dead_code, missing_docs)]

pub mod chain;

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

use kogany_vault::state::{VaultTx, VaultTxIn, VaultTxOut};
use kogany_vault::{Hash32, OutPoint, PubKeyBytes};
use kogany_yellowback::attest::{
    attest_message, decode_attestation, encode_bundle, Attestation, Bundle, SigCache,
};
use kogany_yellowback::codecs::script::{carrier_script, carrier_script_sig};
use secp256k1::{ecdsa, Message, SecretKey};
use serde_json::Value;
use sha2::{Digest, Sha256};

/// The C++ `uint256S(hex)`: the hex is the displayed (big-endian) form; the result is the
/// internal (little-endian) bytes. Short strings are left-padded with zeros.
pub fn u256s(hex: &str) -> Hash32 {
    let hex = hex.trim_start_matches("0x");
    let padded = format!("{hex:0>64}");
    let mut b: [u8; 32] = hex::decode(padded).unwrap().try_into().unwrap();
    b.reverse();
    Hash32(b)
}

/// 32 internal bytes from hex in internal order (`uint256(ParseHex(...))`).
pub fn internal32(hex_str: &str) -> Hash32 {
    Hash32(hex::decode(hex_str).unwrap().try_into().unwrap())
}

pub fn sig64(hex_str: &str) -> [u8; 64] {
    hex::decode(hex_str).unwrap().try_into().unwrap()
}

pub fn sha256(b: &[u8]) -> Hash32 {
    Hash32(Sha256::digest(b).into())
}

/// libsecp256k1's own deterministic signature (RFC 6979, no extra data), compact `r || s`: what
/// the C++ `CKey::Sign` produces, and what the generator computes.
pub fn sign_compact(secret: &[u8; 32], msg: &Hash32) -> [u8; 64] {
    let sk = SecretKey::from_secret_bytes(*secret).unwrap();
    ecdsa::sign(Message::from_digest(msg.0), &sk).serialize_compact()
}

pub fn pubkey(secret: &[u8; 32]) -> PubKeyBytes {
    kogany_vault::act::public_key(secret).unwrap()
}

/// An attestation signed by `secret` over `block_hash`.
pub fn signed_att(
    secret: &[u8; 32],
    seq: u16,
    price: u32,
    cited: u32,
    block_hash: &Hash32,
) -> Attestation {
    Attestation {
        seq,
        price_micro_usd: price,
        cited_height: cited,
        sig: sign_compact(secret, &attest_message(seq, price, cited, block_hash)),
    }
}

/// A fixed test key (the C++ `SomeKey()` is random; any valid key will do).
pub fn some_key() -> PubKeyBytes {
    pubkey(&[0x42; 32])
}

pub fn enc(atts: &[Attestation]) -> Vec<u8> {
    encode_bundle(&Bundle::of(atts.to_vec()))
}

/// `CarrierIn`: a carrier input spending with `bundle`, its redeem script committing to `commit`
/// (default `SHA256(bundle)`), prevout `uint256S("aa"):n`.
pub fn carrier_in(bundle: &[u8], commit: Option<Hash32>, n: u32) -> VaultTxIn {
    let redeem = carrier_script(&some_key(), &commit.unwrap_or_else(|| sha256(bundle))).unwrap();
    VaultTxIn {
        prevout: OutPoint {
            txid: u256s("aa"),
            n,
        },
        script_sig: carrier_script_sig(bundle, &[0x30; 71], &redeem),
    }
}

/// `PlainIn`: `<71 x 0x30> <33 x 0x02>`, prevout `uint256S("bb"):n`.
pub fn plain_in(n: u32) -> VaultTxIn {
    let mut s = vec![71u8];
    s.extend_from_slice(&[0x30; 71]);
    s.push(33);
    s.extend_from_slice(&[0x02; 33]);
    VaultTxIn {
        prevout: OutPoint {
            txid: u256s("bb"),
            n,
        },
        script_sig: s,
    }
}

/// `TxWith`: these inputs and one `OP_RETURN` output.
pub fn tx_with(inputs: Vec<VaultTxIn>) -> VaultTx {
    VaultTx {
        txid: Hash32::ZERO,
        coinbase: false,
        inputs,
        outputs: vec![VaultTxOut {
            value: 0,
            script_pubkey: vec![0x6a],
        }],
    }
}

/// The attest vectors' fixture (`yellowback_bundle_tests.cpp` `Fixture`).
pub struct Vectors {
    pub doc: Value,
    /// The first six valid vectors: seq 0..5, one each.
    pub atts: Vec<Attestation>,
    /// The two later re-attestations of seq 0 (at 1002) and seq 1 (at 1003).
    pub extra: Vec<Attestation>,
    pub keys: BTreeMap<u16, PubKeyBytes>,
    pub secrets: BTreeMap<u16, [u8; 32]>,
    pub block_hashes: BTreeMap<i64, Hash32>,
}

impl Vectors {
    pub fn load() -> Vectors {
        let doc = crate::common::load_pinned("yellowback_attest_vectors.json");
        let mut keys = BTreeMap::new();
        let mut secrets = BTreeMap::new();
        for k in doc["keys"].as_array().unwrap() {
            let seq = u16::try_from(k["seq"].as_u64().unwrap()).unwrap();
            keys.insert(
                seq,
                PubKeyBytes::from_slice(&hex::decode(k["pubkey"].as_str().unwrap()).unwrap())
                    .unwrap(),
            );
            secrets.insert(
                seq,
                hex::decode(k["secret"].as_str().unwrap())
                    .unwrap()
                    .try_into()
                    .unwrap(),
            );
        }
        let mut atts = Vec::new();
        let mut extra = Vec::new();
        let mut block_hashes = BTreeMap::new();
        for v in doc["valid"].as_array().unwrap() {
            let a = decode_attestation(&hex::decode(v["attestation"].as_str().unwrap()).unwrap())
                .unwrap();
            if atts.len() < 6 {
                atts.push(a);
            } else {
                extra.push(a);
            }
            block_hashes.insert(
                i64::from(a.cited_height),
                internal32(v["blockHashInternal"].as_str().unwrap()),
            );
        }
        assert_eq!(atts.len(), 6);
        assert_eq!(extra.len(), 2);
        assert_eq!(extra[0].seq, 0);
        assert_eq!(extra[0].cited_height, 1002);
        Vectors {
            doc,
            atts,
            extra,
            keys,
            secrets,
            block_hashes,
        }
    }
}

/// A cache that counts lookups and inserts (`RecordingCache`).
#[derive(Default)]
pub struct RecordingCache {
    pub entries: Mutex<BTreeMap<Hash32, bool>>,
    pub lookups: AtomicUsize,
    pub hits: AtomicUsize,
    pub inserts: AtomicUsize,
}

impl RecordingCache {
    pub fn lookups(&self) -> usize {
        self.lookups.load(Ordering::SeqCst)
    }
    pub fn hits(&self) -> usize {
        self.hits.load(Ordering::SeqCst)
    }
    pub fn inserts(&self) -> usize {
        self.inserts.load(Ordering::SeqCst)
    }
    pub fn get(&self, k: &Hash32) -> Option<bool> {
        self.entries.lock().unwrap().get(k).copied()
    }
    pub fn len(&self) -> usize {
        self.entries.lock().unwrap().len()
    }
}

impl SigCache for RecordingCache {
    fn lookup(&self, key: &Hash32) -> Option<bool> {
        self.lookups.fetch_add(1, Ordering::SeqCst);
        let hit = self.entries.lock().unwrap().get(key).copied();
        if hit.is_some() {
            self.hits.fetch_add(1, Ordering::SeqCst);
        }
        hit
    }
    fn insert(&self, key: &Hash32, valid: bool) {
        self.inserts.fetch_add(1, Ordering::SeqCst);
        self.entries.lock().unwrap().insert(*key, valid);
    }
}
