//! Beta2 address-interop plan W4.1, W4.2: kogany's transaction verifier on the C++-recorded
//! transactions that mix Sapling spends and outputs with TX_PQPKH inputs and outputs, vault-lock
//! outputs and a vault unlock (`testdata/mixed-shapes/chain.json`, `record.py` there, and
//! `chain2.json`, `record2.py`), and the negative controls: the same transactions before the
//! Vault height, a wrong post-quantum signature, a changed Sapling output, the digest a verifier
//! that left the Sapling parts out of the v4 (ZIP-243) sighash would compute, and the malformed
//! variants `chain2.json` records with both C++ lines' verdicts (beta2 list item 20 (a)).
//!
//! The PQ input signatures were made by the C++ wallets (`signrawtransaction`, `z_sendmany`) over
//! the C++ digest, so each one verifying under kogany's digest (and under no other) is the shared
//! sighash vector: a transaction with Sapling spends or outputs beside an `OP_CHECKPQSIG` input.
//!
//! Copyright (c) 2026 The Ycash developers. Distributed under the MIT software license.

use std::{
    collections::{HashMap, HashSet},
    path::Path,
    sync::Arc,
};

use chrono::{DateTime, Utc};
use tower::{service_fn, ServiceExt};
use zakura_chain::{
    block::{Block, Height},
    parameters::{
        testnet::{ConfiguredActivationHeights, RegtestParameters},
        Network, NetworkUpgrade,
    },
    serialization::{ZcashDeserializeInto, ZcashSerialize},
    transaction::{self, HashType, Transaction},
    transparent,
};

use crate::transaction::{Request, Verifier};

/// The recorded chains: the file, its number of shapes and of PQ inputs among them.
const FIXTURES: [(&str, usize, usize); 2] = [("chain.json", 6, 3), ("chain2.json", 8, 4)];

struct Fixture {
    file: &'static str,
    network: Network,
    vault: Height,
    /// Every transaction of the recorded chain by txid, with its block height.
    txs: HashMap<transaction::Hash, (Arc<Transaction>, Height)>,
    /// (name, txid, height, the PQ inputs' `(nIn, scheme)`)
    shapes: Vec<(String, transaction::Hash, Height, Vec<(usize, u8)>)>,
    /// The recorded malformed variants: (name, the shape it was offered before, the
    /// transaction, ycash6's `sendrawtransaction` message, ycash-dd's).
    rejects: Vec<(String, String, Transaction, String, String)>,
    /// The shapes that spend a vault: their `OP_CHECKSETSIG` reads the set state, which a lone
    /// transaction verifier (`vault_snapshot: None`) has not, so the verifier tests here leave
    /// them out. The block pipeline (`tests/mixed_shapes_chain.rs`) and koganyd's mempool and
    /// miner (`zakurad/tests/kogany_mixed_shapes.rs`) verify them with the set state.
    spends_a_vault: HashSet<String>,
}

/// Every recorded chain.
fn fixtures() -> Vec<Fixture> {
    FIXTURES
        .iter()
        .map(|(file, shapes, _)| fixture(file, *shapes))
        .collect()
}

fn fixture(file: &'static str, expected_shapes: usize) -> Fixture {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata/mixed-shapes")
        .join(file);
    let doc: serde_json::Value =
        serde_json::from_slice(&std::fs::read(path).expect("the fixture is committed"))
            .expect("the fixture is JSON");
    let height = |v: &serde_json::Value| Height(v.as_u64().expect("a height") as u32);
    let vault = height(&doc["vaultActivation"]);
    let network = Network::new_regtest(RegtestParameters::from(ConfiguredActivationHeights {
        overwinter: Some(1),
        sapling: Some(1),
        ycash: Some(1),
        blossom: Some(1),
        heartwood: Some(1),
        canopy: Some(1),
        vault: Some(vault.0),
        pq_falcon: Some(height(&doc["pqFalconHeight"]).0),
        ..Default::default()
    }));

    let mut txs = HashMap::new();
    for (i, b) in doc["blocks"].as_array().expect("blocks").iter().enumerate() {
        let block: Block = hex::decode(b.as_str().expect("block hex"))
            .expect("hex decodes")
            .zcash_deserialize_into()
            .expect("the block parses");
        for tx in &block.transactions {
            txs.insert(tx.hash(), (tx.clone(), Height(i as u32 + 1)));
        }
    }
    let mut shapes: Vec<_> = doc["shapes"]
        .as_object()
        .expect("shapes")
        .iter()
        .map(|(name, s)| {
            let pq = s["pqInputs"]
                .as_array()
                .expect("pqInputs")
                .iter()
                .map(|i| {
                    (
                        i["nIn"].as_u64().expect("nIn") as usize,
                        i["scheme"].as_u64().expect("scheme") as u8,
                    )
                })
                .collect();
            (
                name.clone(),
                s["txid"].as_str().expect("txid").parse().expect("a txid"),
                height(&s["height"]),
                pq,
            )
        })
        .collect();
    shapes.sort_by_key(|s| s.2);
    assert_eq!(shapes.len(), expected_shapes, "{file}: the mixed shapes");
    let text = |v: &serde_json::Value| v.as_str().expect("a string").to_owned();
    let spends_a_vault = doc["shapes"]
        .as_object()
        .expect("shapes")
        .iter()
        .filter(|(_, s)| s["vaultInputs"].as_array().is_some_and(|v| !v.is_empty()))
        .map(|(name, _)| name.clone())
        .collect();
    let rejects = doc["rejects"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|r| {
            (
                text(&r["name"]),
                text(&r["of"]),
                hex::decode(text(&r["hex"]))
                    .expect("hex decodes")
                    .zcash_deserialize_into()
                    .expect("the variant parses"),
                text(&r["cxx"]["ycash6"]["message"]),
                text(&r["cxx"]["ycash-dd"]["message"]),
            )
        })
        .collect();
    Fixture {
        file,
        network,
        vault,
        txs,
        shapes,
        rejects,
        spends_a_vault,
    }
}

impl Fixture {
    /// The outputs `tx` spends, as `known_utxos`, and in input order.
    fn spent(
        &self,
        tx: &Transaction,
    ) -> (
        HashMap<transparent::OutPoint, transparent::OrderedUtxo>,
        Vec<transparent::Output>,
    ) {
        let mut known = HashMap::new();
        let mut outputs = Vec::new();
        for outpoint in tx.inputs().iter().filter_map(|i| i.outpoint()) {
            let (prev, height) = &self.txs[&outpoint.hash];
            let output = prev.outputs()[outpoint.index as usize].clone();
            known.insert(
                outpoint,
                transparent::OrderedUtxo::new(output.clone(), *height, 1),
            );
            outputs.push(output);
        }
        (known, outputs)
    }

    /// The transaction verifier's answer for `tx` in a block at `height`.
    async fn verify(&self, tx: Transaction, height: Height) -> Result<(), String> {
        let (known, _) = self.spent(&tx);
        let state = service_fn(|_| async { unreachable!("every spent output is known") });
        Verifier::new_for_tests(&self.network, state)
            .oneshot(Request::Block {
                transaction_hash: tx.hash(),
                transaction: Arc::new(tx),
                known_utxos: Arc::new(known),
                known_outpoint_hashes: Arc::new(HashSet::new()),
                height,
                time: DateTime::<Utc>::MAX_UTC,
                vault_snapshot: None,
            })
            .await
            .map(|_| ())
            .map_err(|e| format!("{e:?}"))
    }
}

/// Whether a verifier error is `want`.
///
/// Run these tests one per process, as nextest does (CI's `kogany-ycash` profile). Under
/// `cargo test` they share the global batch verifiers with tests on other runtimes, and an
/// answer can come back as `InternalDowncastError` (`ServiceError { inner: Closed }` or a
/// cancelled join) instead of the verdict.
fn refused_with(error: &str, want: &str) -> bool {
    error.contains(want)
}

/// A TX_PQPKH scriptSig `<sig chunks> <s> <pk chunks> <p>`: the signature (its last byte the
/// hash type) and the public key.
fn pq_sig_and_key(script_sig: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let mut pushes: Vec<Vec<u8>> = Vec::new();
    let mut counts = Vec::new();
    let mut at = 0;
    while at < script_sig.len() {
        let op = script_sig[at];
        at += 1;
        let len = match op {
            0x01..=0x4b => op as usize,
            0x4c => {
                at += 1;
                script_sig[at - 1] as usize
            }
            0x4d => {
                at += 2;
                u16::from_le_bytes([script_sig[at - 2], script_sig[at - 1]]) as usize
            }
            0x51..=0x60 => {
                counts.push((op - 0x50) as usize);
                continue;
            }
            _ => panic!("an unexpected opcode {op:#x} in a TX_PQPKH scriptSig"),
        };
        pushes.push(script_sig[at..at + len].to_vec());
        at += len;
    }
    let [s, p] = counts[..] else {
        panic!("two chunk counts")
    };
    assert_eq!(pushes.len(), s + p);
    (pushes[..s].concat(), pushes[s..].concat())
}

/// `tx` with its Sapling parts removed and everything else as it is.
fn without_sapling(tx: &Transaction) -> Transaction {
    match tx.clone() {
        Transaction::V4 {
            inputs,
            outputs,
            lock_time,
            expiry_height,
            joinsplit_data,
            ..
        } => Transaction::V4 {
            inputs,
            outputs,
            lock_time,
            expiry_height,
            joinsplit_data,
            sapling_shielded_data: None,
        },
        _ => panic!("the mixed shapes are v4"),
    }
}

/// `tx` with one byte of its serialization flipped at `offset` from the end.
fn flipped_from_end(tx: &Transaction, offset: usize) -> Transaction {
    let mut bytes = tx.zcash_serialize_to_vec().expect("serializes");
    let at = bytes.len() - offset;
    bytes[at] ^= 0x01;
    bytes.zcash_deserialize_into().expect("still parses")
}

/// `tx` with one byte of input `n`'s scriptSig flipped, inside the first signature chunk.
fn with_bad_pq_signature(tx: &Transaction, n: usize) -> Transaction {
    let Transaction::V4 {
        mut inputs,
        outputs,
        lock_time,
        expiry_height,
        joinsplit_data,
        sapling_shielded_data,
    } = tx.clone()
    else {
        panic!("the mixed shapes are v4")
    };
    if let transparent::Input::PrevOut { unlock_script, .. } = &mut inputs[n] {
        let mut bytes = unlock_script.as_raw_bytes().to_vec();
        bytes[10] ^= 0x01;
        *unlock_script = transparent::Script::new(&bytes);
    }
    Transaction::V4 {
        inputs,
        outputs,
        lock_time,
        expiry_height,
        joinsplit_data,
        sapling_shielded_data,
    }
}

#[tokio::test]
async fn mixed_shapes_verify_at_their_height_and_not_before_vault() {
    let _init_guard = zakura_test::init();
    for f in fixtures() {
        verify_at_height_and_not_before_vault(&f).await;
    }
}

async fn verify_at_height_and_not_before_vault(f: &Fixture) {
    let file = f.file;
    let before = f.vault.previous().expect("Vault is above genesis");
    assert_eq!(
        NetworkUpgrade::current(&f.network, before),
        NetworkUpgrade::Canopy
    );
    for (name, txid, height, _) in &f.shapes {
        if f.spends_a_vault.contains(name) {
            continue;
        }
        let tx = f.txs[txid].0.as_ref().clone();
        assert!(
            tx.has_sapling_shielded_data(),
            "{file} {name} has Sapling parts"
        );
        assert_eq!(
            f.verify(tx.clone(), *height).await,
            Ok(()),
            "{file} {name} verifies at its height"
        );
        // With a transparent input (every one in the shapes spends a TX_PQPKH or a vault) the
        // script check fails first (0xc2 and 0xc0 are no opcodes before Vault); without one,
        // the Sapling signatures (they bind the Vault branch ID).
        let want = if tx.inputs().is_empty() {
            "SaplingVerificationFailed"
        } else {
            "BadOpcode"
        };
        let error = f
            .verify(tx, before)
            .await
            .expect_err("invalid before the Vault height");
        assert!(
            refused_with(&error, want),
            "{file} {name} before the Vault height: {want} expected, got {error}"
        );
    }
}

#[tokio::test]
async fn a_wrong_pq_signature_or_a_changed_sapling_output_is_invalid() {
    let _init_guard = zakura_test::init();
    for f in fixtures() {
        wrong_pq_signature_or_changed_sapling_output_is_invalid(&f).await;
    }
}

async fn wrong_pq_signature_or_changed_sapling_output_is_invalid(f: &Fixture) {
    let file = f.file;
    for (name, txid, height, pq) in &f.shapes {
        if f.spends_a_vault.contains(name) {
            continue;
        }
        let tx = f.txs[txid].0.as_ref().clone();
        for (n, _) in pq {
            let error = f
                .verify(with_bad_pq_signature(&tx, *n), *height)
                .await
                .expect_err("a changed PQ signature fails");
            assert!(
                refused_with(&error, "ScriptInvalid"),
                "{file} {name}: the PQ input fails its script (the Sapling signatures do not \
             cover scriptSigs): {error}"
            );
        }
        // The last Sapling output's outCiphertext (before its 192-byte proof, the JoinSplit
        // count and the 64-byte binding signature): covered by the binding signature, and, with
        // a PQ input, by the PQ signature too.
        let changed = flipped_from_end(&tx, 64 + 1 + 192 + 40);
        assert_ne!(changed.hash(), tx.hash());
        // With a transparent input its script fails first (the PQ signature, and a vault's
        // SIGHASH_ALL|ANYONECANPAY set signature, cover the Sapling outputs); without one, the
        // binding signature.
        let want = if tx.inputs().is_empty() {
            "SaplingVerificationFailed"
        } else {
            "ScriptInvalid"
        };
        let error = f
            .verify(changed, *height)
            .await
            .expect_err("a changed Sapling output is invalid");
        assert!(
            refused_with(&error, want),
            "{file} {name}: a changed Sapling output: {want} expected, got {error}"
        );
    }
}

/// The shared sighash vectors (W4.2): every PQ input's C++-made signature verifies under
/// kogany's v4 digest of the whole transaction, Sapling parts included, for the Vault branch,
/// and under neither the digest without the Sapling parts nor the Canopy branch's.
#[test]
fn pq_signatures_bind_the_sapling_parts() {
    let _init_guard = zakura_test::init();
    for (f, (_, _, pq_inputs)) in fixtures().iter().zip(FIXTURES) {
        assert_eq!(check_pq_signatures(f), pq_inputs, "{}", f.file);
    }
}

/// The number of PQ inputs `f` has, each checked.
fn check_pq_signatures(f: &Fixture) -> usize {
    let file = f.file;
    let mut checked = 0;
    for (name, txid, _, pq) in &f.shapes {
        let tx = f.txs[txid].0.as_ref();
        let (_, spent) = f.spent(tx);
        let spent = Arc::new(spent);
        for (n, scheme) in pq {
            let transparent::Input::PrevOut { unlock_script, .. } = &tx.inputs()[*n] else {
                panic!("a PQ input spends an outpoint")
            };
            let (sig, pk) = pq_sig_and_key(unlock_script.as_raw_bytes());
            let (hash_type, sig) = sig.split_last().expect("a signature");
            assert_eq!(*hash_type, 0x01, "{file} {name}: SIGHASH_ALL");
            let script_code = spent[*n].lock_script.as_raw_bytes().to_vec();
            let digest = |tx: &Transaction, nu: NetworkUpgrade| -> [u8; 32] {
                tx.sighash(
                    nu,
                    HashType::ALL,
                    spent.clone(),
                    Some((*n, script_code.clone())),
                )
                .expect("the branch converts")
                .into()
            };
            let verify = |msg: [u8; 32]| kogany_pq::verify(*scheme, &pk, &msg, sig);
            assert!(
                verify(digest(tx, NetworkUpgrade::Vault)),
                "{file} {name}: the C++ signature verifies under kogany's Vault digest"
            );
            assert!(
                !verify(digest(&without_sapling(tx), NetworkUpgrade::Vault)),
                "{file} {name}: a digest that leaves out the Sapling parts does not verify"
            );
            assert!(
                !verify(digest(tx, NetworkUpgrade::Canopy)),
                "{file} {name}: the Canopy digest does not verify"
            );
            checked += 1;
        }
    }
    checked
}

/// Beta2 list item 20 (a): every malformed variant `chain2.json` recorded (each refused by both
/// C++ mempools) gets the same verdict class from kogany's block verifier at the shape's height:
/// a consensus reject (`16: …`) is invalid in a block, a policy reject (`64: …`, the
/// standardness rules: the C++ nodes ran with `-acceptnonstdtxn=0`) is valid in a block and is
/// the mempool's to refuse (`kogany_mixed_shapes.rs` offers each one to koganyd's mempool).
#[tokio::test]
async fn recorded_rejects_get_the_cxx_verdict_in_a_block() {
    let _init_guard = zakura_test::init();
    let mut offered = 0;
    for f in fixtures() {
        for (name, of, tx, ycash6, ycash_dd) in &f.rejects {
            if f.spends_a_vault.contains(of) {
                // A vault spend's script needs the set state (see `spends_a_vault`): koganyd's
                // mempool test offers this one.
                continue;
            }
            let height = f
                .shapes
                .iter()
                .find(|s| &s.0 == of)
                .expect("the variant's shape is recorded")
                .2;
            let code = |m: &str| m.split(':').next().unwrap_or_default().to_owned();
            assert_eq!(
                code(ycash6),
                code(ycash_dd),
                "{name}: the C++ lines refuse at one stage ({ycash6} / {ycash_dd})"
            );
            let verdict = f.verify(tx.clone(), height).await;
            match code(ycash6).as_str() {
                "16" => assert!(
                    verdict.is_err(),
                    "{name}: consensus-invalid on the C++ lines ({ycash6}), so in a kogany block"
                ),
                "64" => assert_eq!(
                    verdict,
                    Ok(()),
                    "{name}: a policy reject on the C++ lines ({ycash6}) is valid in a block"
                ),
                other => panic!("{name}: an unexpected C++ reject code {other} ({ycash6})"),
            }
            offered += 1;
        }
    }
    assert_eq!(offered, 5, "the recorded variants");
}
