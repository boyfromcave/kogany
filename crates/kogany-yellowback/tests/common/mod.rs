// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

//! Shared helpers for the codec tests (W5-b): the pinned-vector loader, hex, deterministic keys,
//! and a reader for the transparent half of a v4 transaction (the golden chains' raw txs).
#![allow(dead_code, missing_docs)]

use std::path::PathBuf;

use kogany_vault::{Hash32, PqOwner, PubKeyBytes};
use serde_json::Value;
use sha2::{Digest, Sha256};

/// `testdata/yellowback/` at the kogany root.
pub fn testdata() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata/yellowback")
}

/// Loads a pinned vector file after checking it against `testdata/yellowback/PIN`, so the tests
/// only run on the bytes the C++ lines test (plan §4.2 rule 4 (i)).
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

/// Hex to bytes.
pub fn h(s: &str) -> Vec<u8> {
    hex::decode(s).unwrap_or_else(|e| panic!("hex {s}: {e}"))
}

/// The compressed public key of the secret `[seed; 32]` (a valid curve point).
pub fn key(seed: u8) -> PubKeyBytes {
    kogany_vault::act::public_key(&[seed; 32])
        .expect("[seed; 32] is a valid secret for seed 1..=255")
}

/// A post-quantum owner id: `scheme` and a hash made of `seed` bytes.
pub fn owner(scheme: u8, seed: u8) -> PqOwner {
    PqOwner {
        scheme,
        hash: Hash32([seed; 32]),
    }
}

/// The C++ `uint256S` of a 64-digit display hex: its bytes reversed (internal order).
pub fn uint256_display(s: &str) -> Hash32 {
    let mut b = h(s);
    b.reverse();
    Hash32::from_slice(&b).expect("a 32-byte hash")
}

/// The transparent half of a raw transaction: input scriptSigs and output scripts.
pub struct TxIo {
    pub script_sigs: Vec<Vec<u8>>,
    pub outputs: Vec<Vec<u8>>,
}

fn compact_size(b: &[u8], i: &mut usize) -> usize {
    let first = b[*i];
    *i += 1;
    let n = match first {
        0xfd => 2,
        0xfe => 4,
        0xff => 8,
        x => return usize::from(x),
    };
    let mut v = [0u8; 8];
    v[..n].copy_from_slice(&b[*i..*i + n]);
    *i += n;
    usize::try_from(u64::from_le_bytes(v)).unwrap()
}

/// Reads the header, the inputs and the outputs of a v4 (Sapling-format) transaction; the rest
/// (lock time, expiry, shielded parts) is not needed by the codecs.
pub fn tx_io(raw: &[u8]) -> TxIo {
    assert_eq!(
        &raw[..4],
        &[0x04, 0x00, 0x00, 0x80],
        "a v4 overwintered transaction"
    );
    let mut i = 8;
    let n = compact_size(raw, &mut i);
    let mut script_sigs = Vec::new();
    for _ in 0..n {
        i += 36;
        let l = compact_size(raw, &mut i);
        script_sigs.push(raw[i..i + l].to_vec());
        i += l + 4;
    }
    let n = compact_size(raw, &mut i);
    let mut outputs = Vec::new();
    for _ in 0..n {
        i += 8;
        let l = compact_size(raw, &mut i);
        outputs.push(raw[i..i + l].to_vec());
        i += l;
    }
    TxIo {
        script_sigs,
        outputs,
    }
}
