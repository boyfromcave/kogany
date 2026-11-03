//! Shared helpers for the vector replays: loading the pinned cross-line file and reading hex.
#![allow(dead_code, missing_docs)]

use std::path::PathBuf;

use kogany_vault::{Hash32, OutPoint, PqOwner, PubKeyBytes, RecoverableSig, Tag};
use serde_json::Value;
use sha2::{Digest, Sha256};

/// `testdata/yellowback/` at the kogany root.
pub fn testdata() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata/yellowback")
}

/// Loads a pinned vector file after checking it against `testdata/yellowback/PIN`, so a replay
/// can only run on the bytes the C++ lines test (plan §4.2 rule 4 (i)).
pub fn load_pinned(name: &str) -> Value {
    let dir = testdata();
    let bytes = std::fs::read(dir.join(name)).unwrap();
    let pin = std::fs::read_to_string(dir.join("PIN")).unwrap();
    let want = pin
        .lines()
        .filter(|l| !l.starts_with('#'))
        .find_map(|l| {
            let mut f = l.split_whitespace();
            let sha = f.next()?;
            (f.next()? == format!("testdata/yellowback/{name}")).then(|| sha.to_owned())
        })
        .unwrap_or_else(|| panic!("{name} is not pinned in PIN"));
    assert_eq!(
        hex::encode(Sha256::digest(&bytes)),
        want,
        "{name} differs from its PIN"
    );
    serde_json::from_slice(&bytes).unwrap()
}

/// The pinned `vault_vectors.json`.
pub fn vectors() -> Value {
    load_pinned("vault_vectors.json")
}

/// The hex string at `v[key]`, decoded.
pub fn hx(v: &Value, key: &str) -> Vec<u8> {
    hex::decode(
        v[key]
            .as_str()
            .unwrap_or_else(|| panic!("{key} is a hex string")),
    )
    .unwrap()
}

/// A hex string value, decoded.
pub fn hv(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().expect("a hex string")).unwrap()
}

pub fn s<'a>(v: &'a Value, key: &str) -> &'a str {
    v[key]
        .as_str()
        .unwrap_or_else(|| panic!("{key} is a string"))
}

pub fn int(v: &Value, key: &str) -> i64 {
    v[key]
        .as_i64()
        .unwrap_or_else(|| panic!("{key} is an integer"))
}

pub fn arr<'a>(v: &'a Value, key: &str) -> &'a Vec<Value> {
    v[key]
        .as_array()
        .unwrap_or_else(|| panic!("{key} is an array"))
}

pub fn h32(v: &Value, key: &str) -> Hash32 {
    Hash32::from_slice(&hx(v, key)).unwrap_or_else(|| panic!("{key} is 32 bytes"))
}

pub fn tag(v: &Value, key: &str) -> Tag {
    Tag(hx(v, key).try_into().unwrap())
}

pub fn key(v: &Value, key: &str) -> PubKeyBytes {
    PubKeyBytes::from_slice(&hx(v, key)).unwrap()
}

pub fn sig(v: &Value) -> RecoverableSig {
    RecoverableSig::from_slice(&hv(v)).unwrap()
}

pub fn prevout(v: &Value, key: &str) -> OutPoint {
    OutPoint::from_slice(&hx(v, key)).unwrap()
}

/// `{"scheme": n, "hash": hex32}`.
pub fn owner(v: &Value) -> PqOwner {
    PqOwner {
        scheme: u8::try_from(int(v, "scheme")).unwrap(),
        hash: h32(v, "hash"),
    }
}

/// `pq::KeyHash(scheme, pk) = SHA256(scheme || pk)` (ycash6 `src/crypto/pq/scheme.cpp`).
pub fn pq_key_hash(scheme: u8, pk: &[u8]) -> Hash32 {
    let mut h = Sha256::new();
    h.update([scheme]);
    h.update(pk);
    Hash32(h.finalize().into())
}

/// Reads a Bitcoin compact size at `*pos`.
fn compact_size(b: &[u8], pos: &mut usize) -> usize {
    let first = b[*pos];
    *pos += 1;
    let n = match first {
        0xfd => 2,
        0xfe => 4,
        0xff => 8,
        v => return usize::from(v),
    };
    let mut buf = [0u8; 8];
    buf[..n].copy_from_slice(&b[*pos..*pos + n]);
    *pos += n;
    usize::try_from(u64::from_le_bytes(buf)).unwrap()
}

/// `vin[0]`'s prevout and scriptSig of a serialized Overwinter+ transaction (header,
/// nVersionGroupId, then the inputs). Test-only: the vectors' spends all use input 0.
pub fn first_input(tx: &[u8]) -> (OutPoint, Vec<u8>) {
    let mut pos = 8;
    let n_in = compact_size(tx, &mut pos);
    assert!(n_in >= 1);
    let prevout = OutPoint::from_slice(&tx[pos..pos + 36]).unwrap();
    pos += 36;
    let len = compact_size(tx, &mut pos);
    (prevout, tx[pos..pos + len].to_vec())
}
