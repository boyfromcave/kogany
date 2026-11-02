//! kogany W2-c: the pinned `vault_vectors.json` signature hashes replay through Zakura's native
//! v4 (ZIP-243) sighash under `NetworkUpgrade::Vault` (branch ID `0x6d5b7a31`).
//!
//! The C++ lines compute each `sighash` with `SignatureHash(scriptCode, tx, nIn, hashType, amount,
//! 0x6d5b7a31)` (ycash6 `src/test/vault_vectors_tests.cpp`, `qa/rpc-tests/test_framework/
//! gen_vault_vectors.py`): the set-signed template spends use `SIGHASH_ALL | ANYONECANPAY`
//! (remedial 01/V-2), the post-quantum owner spends `SIGHASH_ALL`. kogany never generates a
//! vector (plan §4.2 rule 4 (iv)); the file is checked against `testdata/yellowback/PIN` first.

use std::{path::PathBuf, sync::Arc};

use serde_json::Value;
use sha2::{Digest, Sha256};

use zakura_chain::{
    amount::{Amount, NonNegative},
    parameters::NetworkUpgrade,
    serialization::ZcashDeserializeInto,
    transaction::{HashType, Transaction},
    transparent,
};

/// Loads `testdata/yellowback/<name>` after checking its SHA-256 against `PIN`.
fn load_pinned(name: &str) -> Value {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata/yellowback");
    let bytes = std::fs::read(dir.join(name)).expect("the pinned vector file is present");
    let pin = std::fs::read_to_string(dir.join("PIN")).expect("PIN is present");
    let want = pin
        .lines()
        .filter(|line| !line.starts_with('#'))
        .find_map(|line| {
            let mut fields = line.split_whitespace();
            let sha = fields.next()?;
            (fields.next()? == format!("testdata/yellowback/{name}")).then(|| sha.to_owned())
        })
        .unwrap_or_else(|| panic!("{name} is pinned in PIN"));
    assert_eq!(
        hex::encode(Sha256::digest(&bytes)),
        want,
        "{name} differs from its PIN"
    );
    serde_json::from_slice(&bytes).expect("the pinned vector file is JSON")
}

fn hex_field(value: &Value, key: &str) -> Vec<u8> {
    hex::decode(
        value[key]
            .as_str()
            .unwrap_or_else(|| panic!("{key} is a hex string")),
    )
    .unwrap_or_else(|_| panic!("{key} is valid hex"))
}

fn int_field(value: &Value, key: &str) -> u64 {
    value[key]
        .as_u64()
        .unwrap_or_else(|| panic!("{key} is an integer"))
}

/// The signature hash of input `nIn` of the vector's transaction under `nu`, with Zakura's
/// native sighash.
fn replay(spend: &Value, nu: NetworkUpgrade, hash_type: HashType) -> [u8; 32] {
    let transaction: Transaction = hex_field(spend, "tx")
        .zcash_deserialize_into()
        .expect("the vector transaction parses as a v4 Sapling transaction");
    assert!(
        matches!(transaction, Transaction::V4 { .. }),
        "vault spends are v4 only (U-26)"
    );
    let input = usize::try_from(int_field(spend, "nIn")).expect("a small input index");
    let amount: Amount<NonNegative> =
        Amount::try_from(int_field(spend, "amount")).expect("the spent amount is a valid amount");
    // A v4 sighash reads only the spent output's value at `input`; the script code is passed
    // explicitly, so the other inputs' outputs are placeholders.
    let previous_outputs: Vec<transparent::Output> = (0..transaction.inputs().len())
        .map(|index| transparent::Output {
            value: if index == input {
                amount
            } else {
                Amount::zero()
            },
            lock_script: transparent::Script::new(&[]),
        })
        .collect();
    transaction
        .sighash(
            nu,
            hash_type,
            Arc::new(previous_outputs),
            Some((input, hex_field(spend, "scriptCode"))),
        )
        .expect("the branch ID converts to the common fork's BranchId")
        .into()
}

#[test]
fn vault_vector_sighashes_replay_under_the_vault_branch_id() {
    let vectors = load_pinned("vault_vectors.json");
    let branch_id = u32::try_from(int_field(&vectors, "branchId")).expect("a u32 branch ID");
    assert_eq!(
        NetworkUpgrade::Vault.branch_id().map(u32::from),
        Some(branch_id),
        "the vectors' branch ID is Zakura's Vault row"
    );

    let mut replayed = 0;
    for (key, hash_type) in [
        ("spends", HashType::ALL_ANYONECANPAY),
        ("ownerSpends", HashType::ALL),
    ] {
        let spends = vectors[key].as_array().expect("an array of spends");
        assert!(!spends.is_empty(), "{key} has spends");
        for spend in spends {
            let name = spend["name"].as_str().unwrap_or("?");
            assert_eq!(
                int_field(spend, "branchId"),
                u64::from(branch_id),
                "{key} {name}"
            );
            let want = hex::encode(hex_field(spend, "sighash"));
            assert_eq!(
                hex::encode(replay(spend, NetworkUpgrade::Vault, hash_type)),
                want,
                "{key} {name}: the Vault sighash replays"
            );
            // The previous epoch's branch ID (Canopy's) gives another digest, so the replay
            // binds 0x6d5b7a31: a spend signed for Canopy does not verify under Vault.
            assert_ne!(
                hex::encode(replay(spend, NetworkUpgrade::Canopy, hash_type)),
                want,
                "{key} {name}"
            );
            replayed += 1;
        }
    }
    assert_eq!(replayed, 6, "two template spends and four owner spends");
}
