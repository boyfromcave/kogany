//! Shared helpers for the vector replays: loading the pinned cross-line files and byte edits.
#![allow(dead_code)]

use std::path::PathBuf;

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

/// The hex string at `v[key]`, decoded.
pub fn hx(v: &Value, key: &str) -> Vec<u8> {
    hex::decode(
        v[key]
            .as_str()
            .unwrap_or_else(|| panic!("{key} is a hex string")),
    )
    .unwrap()
}

/// `v[key]` as an integer.
pub fn int(v: &Value, key: &str) -> u64 {
    v[key]
        .as_u64()
        .unwrap_or_else(|| panic!("{key} is an integer"))
}

/// `v[key]` as an array.
pub fn arr<'a>(v: &'a Value, key: &str) -> &'a Vec<Value> {
    v[key]
        .as_array()
        .unwrap_or_else(|| panic!("{key} is an array"))
}

/// `b` with bit `bit` of byte `byte` flipped (the C++ tests' `Flip`).
pub fn flip(b: &[u8], byte: usize, bit: u32) -> Vec<u8> {
    let mut out = b.to_vec();
    out[byte] ^= 1u8 << bit;
    out
}

/// A 32-byte message from a vector's bytes.
pub fn msg32(b: &[u8]) -> [u8; 32] {
    b.try_into().unwrap()
}
