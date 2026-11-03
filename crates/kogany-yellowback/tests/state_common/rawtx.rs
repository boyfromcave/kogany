// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

//! A reader for the transparent half of a raw v4 (Sapling-format) transaction, as the pinned
//! chains carry them: its inputs and outputs, and its txid (SHA256d of the whole serialisation,
//! internal byte order) — what the state machine's [`VaultTx`] holds.
#![allow(dead_code, missing_docs)]

use kogany_vault::state::{VaultTx, VaultTxIn, VaultTxOut};
use kogany_vault::{Hash32, OutPoint};
use sha2::{Digest, Sha256};

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

/// `SHA256d(raw)`, internal byte order (the C++ `CTransaction::GetHash` of a v4 transaction).
pub fn txid(raw: &[u8]) -> Hash32 {
    Hash32(Sha256::digest(Sha256::digest(raw)).into())
}

/// Parses a raw v4 overwintered transaction's inputs and outputs.
pub fn parse_v4(raw: &[u8]) -> VaultTx {
    assert_eq!(
        &raw[..4],
        &[0x04, 0x00, 0x00, 0x80],
        "a v4 overwintered transaction"
    );
    let mut i = 8;
    let n = compact_size(raw, &mut i);
    let mut inputs = Vec::new();
    for _ in 0..n {
        let prevout = OutPoint::from_slice(&raw[i..i + 36]).unwrap();
        i += 36;
        let l = compact_size(raw, &mut i);
        let script_sig = raw[i..i + l].to_vec();
        i += l + 4; // nSequence
        inputs.push(VaultTxIn {
            prevout,
            script_sig,
        });
    }
    let n = compact_size(raw, &mut i);
    let mut outputs = Vec::new();
    for _ in 0..n {
        let value = i64::from_le_bytes(raw[i..i + 8].try_into().unwrap());
        i += 8;
        let l = compact_size(raw, &mut i);
        outputs.push(VaultTxOut {
            value,
            script_pubkey: raw[i..i + l].to_vec(),
        });
        i += l;
    }
    let coinbase = VaultTx::inputs_are_coinbase(&inputs);
    VaultTx {
        txid: txid(raw),
        coinbase,
        inputs,
        outputs,
    }
}
