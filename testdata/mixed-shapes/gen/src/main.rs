// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

//! The Sapling half of the mixed-shape fixtures (`testdata/mixed-shapes/record.py`).
//!
//! Reads one JSON request on stdin and writes one JSON answer on stdout. Two requests:
//!
//! - `{"mode": "address", "seed"}`: the default Sapling payment address (43 bytes, hex) of the
//!   fixture key, the ZIP 32 master key of `seed`.
//! - `{"mode": "build", "seed", "params", "branchId", "lockTime", "expiry", "inputs": [{"txid",
//!   "vout", "sequence"}], "outputs": [{"value", "script"}], "saplingOutputs": [{"to": "self" |
//!   hex43, "value"}], "saplingSpends": [{"txid", "output"?}], "saplingChain": [tx hex, ...]}`: a v4
//!   transaction. The transparent inputs keep empty scriptSigs (ycashd's `signrawtransaction`
//!   fills them: none of the signatures below covers a scriptSig). The Sapling spends are notes of
//!   the fixture key, found by trial decryption in `saplingChain`, which lists every transaction
//!   of the chain that has Sapling outputs, in chain order; the anchor is the tree after all of
//!   them, so the caller must pass the chain up to its tip. The spend authorization and binding
//!   signatures sign the ZIP-243 `SIGHASH_ALL` digest of the transaction for `branchId`, computed
//!   here from the bytes this tool writes (not with any node's code).
//!
//! The answer is `{"tx": hex, "anchor": hex | null, "selfAddress": hex43}`.

use std::io::Read;

use blake2b_simd::Params;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use sapling::{
    builder::{Builder, BundleType},
    circuit::{OutputParameters, SpendParameters},
    note::ExtractedNoteCommitment,
    note_encryption::{try_sapling_note_decryption, PreparedIncomingViewingKey, Zip212Enforcement},
    value::{NoteValue, ValueCommitment},
    zip32::ExtendedSpendingKey,
    Anchor, CommitmentTree, IncrementalWitness, Node, PaymentAddress,
};
use serde_json::{json, Value};
use zcash_note_encryption::EphemeralKeyBytes;

const OVERWINTER_FLAG: u32 = 1 << 31;
const SAPLING_VERSION_GROUP_ID: u32 = 0x892f_2085;
const SPEND_SIZE: usize = 384;
const OUTPUT_SIZE: usize = 948;

fn compact(n: usize, out: &mut Vec<u8>) {
    match n {
        0..=0xfc => out.push(n as u8),
        0xfd..=0xffff => {
            out.push(0xfd);
            out.extend_from_slice(&(n as u16).to_le_bytes());
        }
        _ => {
            out.push(0xfe);
            out.extend_from_slice(&(n as u32).to_le_bytes());
        }
    }
}

fn read_compact(b: &[u8], at: &mut usize) -> usize {
    let first = b[*at];
    *at += 1;
    let (len, n) = match first {
        0xfd => (2, u16::from_le_bytes([b[*at], b[*at + 1]]) as usize),
        0xfe => (
            4,
            u32::from_le_bytes(b[*at..*at + 4].try_into().unwrap()) as usize,
        ),
        0xff => panic!("no 8-byte counts in a fixture transaction"),
        n => (0, n as usize),
    };
    *at += len;
    n
}

fn hex_of(v: &Value, key: &str) -> Vec<u8> {
    hex::decode(
        v[key]
            .as_str()
            .unwrap_or_else(|| panic!("{key} is a string")),
    )
    .unwrap_or_else(|_| panic!("{key} is hex"))
}

fn u64_of(v: &Value, key: &str) -> u64 {
    v[key]
        .as_u64()
        .unwrap_or_else(|| panic!("{key} is an integer"))
}

/// A txid in display order to its internal byte order.
fn txid_internal(v: &Value, key: &str) -> [u8; 32] {
    let mut b: [u8; 32] = hex_of(v, key).try_into().expect("a 32-byte txid");
    b.reverse();
    b
}

fn blake2b(personal: &[u8; 16], data: &[u8]) -> [u8; 32] {
    Params::new()
        .hash_length(32)
        .personal(personal)
        .hash(data)
        .as_bytes()
        .try_into()
        .expect("a 32-byte digest")
}

/// The Sapling outputs of a v4 transaction: (cmu, the description's 948 bytes), and its txid.
fn sapling_outputs_of(tx: &[u8]) -> ([u8; 32], Vec<[u8; OUTPUT_SIZE]>) {
    // internal byte order, as `txid_internal` gives the requested ones
    let txid = sha256d(tx);
    let header = u32::from_le_bytes(tx[0..4].try_into().unwrap());
    assert_eq!(header, OVERWINTER_FLAG | 4, "a v4 transaction");
    let mut at = 8;
    for _ in 0..read_compact(tx, &mut at) {
        at += 36;
        let n = read_compact(tx, &mut at);
        at += n + 4;
    }
    for _ in 0..read_compact(tx, &mut at) {
        at += 8;
        let n = read_compact(tx, &mut at);
        at += n;
    }
    at += 4 + 4 + 8;
    let spends = read_compact(tx, &mut at);
    at += spends * SPEND_SIZE;
    let n = read_compact(tx, &mut at);
    let outputs = (0..n)
        .map(|i| {
            tx[at + i * OUTPUT_SIZE..at + (i + 1) * OUTPUT_SIZE]
                .try_into()
                .unwrap()
        })
        .collect();
    (txid, outputs)
}

fn sha256d(b: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    Sha256::digest(Sha256::digest(b)).into()
}

/// The transaction's parts this tool writes.
struct Parts {
    inputs: Vec<([u8; 32], u32, u32)>,
    outputs: Vec<(i64, Vec<u8>)>,
    lock_time: u32,
    expiry: u32,
    value_balance: i64,
    /// cv, anchor, nullifier, rk, zkproof (320 bytes each), and the spendAuthSig.
    spends: Vec<(Vec<u8>, [u8; 64])>,
    outputs_sapling: Vec<[u8; OUTPUT_SIZE]>,
    binding_sig: [u8; 64],
}

impl Parts {
    fn serialize(&self) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&(OVERWINTER_FLAG | 4).to_le_bytes());
        b.extend_from_slice(&SAPLING_VERSION_GROUP_ID.to_le_bytes());
        compact(self.inputs.len(), &mut b);
        for (txid, n, seq) in &self.inputs {
            b.extend_from_slice(txid);
            b.extend_from_slice(&n.to_le_bytes());
            b.push(0);
            b.extend_from_slice(&seq.to_le_bytes());
        }
        compact(self.outputs.len(), &mut b);
        for (value, script) in &self.outputs {
            b.extend_from_slice(&value.to_le_bytes());
            compact(script.len(), &mut b);
            b.extend_from_slice(script);
        }
        b.extend_from_slice(&self.lock_time.to_le_bytes());
        b.extend_from_slice(&self.expiry.to_le_bytes());
        b.extend_from_slice(&self.value_balance.to_le_bytes());
        compact(self.spends.len(), &mut b);
        for (body, sig) in &self.spends {
            b.extend_from_slice(body);
            b.extend_from_slice(sig);
        }
        compact(self.outputs_sapling.len(), &mut b);
        for o in &self.outputs_sapling {
            b.extend_from_slice(o);
        }
        compact(0, &mut b); // no JoinSplits
        if !self.spends.is_empty() || !self.outputs_sapling.is_empty() {
            b.extend_from_slice(&self.binding_sig);
        }
        b
    }

    /// ZIP-243's digest with `SIGHASH_ALL` and no input (the shielded signatures' message).
    fn shielded_sighash(&self, branch_id: u32) -> [u8; 32] {
        let mut prevouts = Vec::new();
        let mut sequences = Vec::new();
        for (txid, n, seq) in &self.inputs {
            prevouts.extend_from_slice(txid);
            prevouts.extend_from_slice(&n.to_le_bytes());
            sequences.extend_from_slice(&seq.to_le_bytes());
        }
        let mut outputs = Vec::new();
        for (value, script) in &self.outputs {
            outputs.extend_from_slice(&value.to_le_bytes());
            compact(script.len(), &mut outputs);
            outputs.extend_from_slice(script);
        }
        // ZIP 243: the transparent digests are taken even over no inputs or outputs (BLAKE2b of
        // the empty string); only the shielded and JoinSplit digests are zero when empty.
        let digest_or_zero = |personal: &[u8; 16], data: &[u8], any: bool| {
            if any {
                blake2b(personal, data)
            } else {
                [0; 32]
            }
        };
        let spends: Vec<u8> = self
            .spends
            .iter()
            .flat_map(|(body, _)| body.clone())
            .collect();
        let shielded_outputs: Vec<u8> = self.outputs_sapling.iter().flatten().copied().collect();

        let mut data = Vec::new();
        data.extend_from_slice(&(OVERWINTER_FLAG | 4).to_le_bytes());
        data.extend_from_slice(&SAPLING_VERSION_GROUP_ID.to_le_bytes());
        data.extend_from_slice(&digest_or_zero(b"ZcashPrevoutHash", &prevouts, true));
        data.extend_from_slice(&digest_or_zero(b"ZcashSequencHash", &sequences, true));
        data.extend_from_slice(&digest_or_zero(b"ZcashOutputsHash", &outputs, true));
        data.extend_from_slice(&[0; 32]); // hashJoinSplits
        data.extend_from_slice(&digest_or_zero(
            b"ZcashSSpendsHash",
            &spends,
            !self.spends.is_empty(),
        ));
        data.extend_from_slice(&digest_or_zero(
            b"ZcashSOutputHash",
            &shielded_outputs,
            !self.outputs_sapling.is_empty(),
        ));
        data.extend_from_slice(&self.lock_time.to_le_bytes());
        data.extend_from_slice(&self.expiry.to_le_bytes());
        data.extend_from_slice(&self.value_balance.to_le_bytes());
        data.extend_from_slice(&1u32.to_le_bytes()); // SIGHASH_ALL
        let mut personal = *b"ZcashSigHash\0\0\0\0";
        personal[12..].copy_from_slice(&branch_id.to_le_bytes());
        blake2b(&personal, &data)
    }
}

fn read_params(dir: &str) -> (SpendParameters, OutputParameters) {
    let spend = std::fs::File::open(format!("{dir}/sapling-spend.params"))
        .expect("sapling-spend.params is in the params directory");
    let output = std::fs::File::open(format!("{dir}/sapling-output.params"))
        .expect("sapling-output.params is in the params directory");
    (
        SpendParameters::read(std::io::BufReader::new(spend), true).expect("spend params read"),
        OutputParameters::read(std::io::BufReader::new(output), true).expect("output params read"),
    )
}

fn build(req: &Value, extsk: &ExtendedSpendingKey) -> Value {
    let branch_id = u64_of(req, "branchId") as u32;
    let mut rng =
        ChaCha20Rng::from_seed(blake2b(b"kogany-mixed-rng", &req.to_string().into_bytes()));
    let dfvk = extsk.to_diversifiable_full_viewing_key();
    let ivk = PreparedIncomingViewingKey::new(&dfvk.to_ivk(zip32::Scope::External));
    let self_address = extsk.default_address().1;

    // The tree and the fixture key's notes, in chain order.
    let mut tree = CommitmentTree::empty();
    let mut witnesses: Vec<(([u8; 32], usize), sapling::Note, IncrementalWitness)> = Vec::new();
    for tx in req["saplingChain"].as_array().expect("saplingChain") {
        let tx = hex::decode(tx.as_str().expect("a tx hex")).expect("tx hex");
        let (txid, outputs) = sapling_outputs_of(&tx);
        for (j, o) in outputs.iter().enumerate() {
            let cmu = ExtractedNoteCommitment::from_bytes(&o[32..64].try_into().unwrap())
                .expect("a valid cmu");
            let node = Node::from_cmu(&cmu);
            tree.append(node).expect("the tree has room");
            for (_, _, w) in witnesses.iter_mut() {
                w.append(node).expect("the witness has room");
            }
            let desc: sapling::bundle::OutputDescription<[u8; 192]> =
                sapling::bundle::OutputDescription::from_parts(
                    ValueCommitment::from_bytes_not_small_order(&o[0..32].try_into().unwrap())
                        .expect("a valid cv"),
                    cmu,
                    EphemeralKeyBytes(o[64..96].try_into().unwrap()),
                    o[96..676].try_into().unwrap(),
                    o[676..756].try_into().unwrap(),
                    o[756..948].try_into().unwrap(),
                );
            if let Some((note, _, _)) =
                try_sapling_note_decryption(&ivk, &desc, Zip212Enforcement::On)
            {
                let w = IncrementalWitness::from_tree(tree.clone()).expect("a non-empty tree");
                witnesses.push(((txid, j), note, w));
            }
        }
    }
    let anchor = Anchor::from(tree.root());

    let spends = req["saplingSpends"].as_array().cloned().unwrap_or_default();
    let mut builder = Builder::new(Zip212Enforcement::On, BundleType::DEFAULT, anchor);
    let mut spent_value = 0u64;
    for s in &spends {
        // `output` names the description; without it, the transaction's one note of the key
        // (the builder shuffles a padded bundle's outputs).
        let txid = txid_internal(s, "txid");
        let output = s["output"].as_u64().map(|n| n as usize);
        let mut found = witnesses
            .iter()
            .filter(|((t, j), _, _)| *t == txid && output.is_none_or(|o| o == *j));
        let (_, note, w) = found
            .next()
            .expect("the spent note is the fixture key's, in saplingChain");
        assert!(
            found.next().is_none(),
            "one note of the key in {}",
            s["txid"]
        );
        spent_value += note.value().inner();
        builder
            .add_spend(
                dfvk.fvk().clone(),
                note.clone(),
                w.path().expect("a witness path"),
            )
            .expect("the spend joins the bundle");
    }
    for o in req["saplingOutputs"]
        .as_array()
        .cloned()
        .unwrap_or_default()
    {
        let to = match o["to"].as_str() {
            Some("self") => self_address,
            _ => PaymentAddress::from_bytes(&hex_of(&o, "to").try_into().expect("43 bytes"))
                .expect("a Sapling payment address"),
        };
        builder
            .add_output(
                Some(dfvk.fvk().ovk),
                to,
                NoteValue::from_raw(u64_of(&o, "value")),
                [0xf6; 512],
            )
            .expect("the output joins the bundle");
    }

    let mut parts = Parts {
        inputs: req["inputs"]
            .as_array()
            .cloned()
            .unwrap_or_default()
            .iter()
            .map(|i| {
                (
                    txid_internal(i, "txid"),
                    u64_of(i, "vout") as u32,
                    u64_of(i, "sequence") as u32,
                )
            })
            .collect(),
        outputs: req["outputs"]
            .as_array()
            .cloned()
            .unwrap_or_default()
            .iter()
            .map(|o| (u64_of(o, "value") as i64, hex_of(o, "script")))
            .collect(),
        lock_time: u64_of(req, "lockTime") as u32,
        expiry: u64_of(req, "expiry") as u32,
        value_balance: 0,
        spends: Vec::new(),
        outputs_sapling: Vec::new(),
        binding_sig: [0; 64],
    };

    let (spend_params, output_params) = read_params(req["params"].as_str().expect("params"));
    let (unproven, _meta) = builder
        .build::<SpendParameters, OutputParameters, _, i64>(std::slice::from_ref(extsk), &mut rng)
        .expect("the bundle builds")
        .expect("the bundle is not empty");
    let proven = unproven.create_proofs(&spend_params, &output_params, &mut rng, ());
    parts.value_balance = *proven.value_balance();
    for s in proven.shielded_spends() {
        let mut body = Vec::with_capacity(320);
        body.extend_from_slice(&s.cv().to_bytes());
        body.extend_from_slice(&s.anchor().to_bytes());
        body.extend_from_slice(&s.nullifier().0);
        body.extend_from_slice(&<[u8; 32]>::from(*s.rk()));
        body.extend_from_slice(s.zkproof());
        parts.spends.push((body, [0; 64]));
    }
    for o in proven.shielded_outputs() {
        let mut b = Vec::with_capacity(OUTPUT_SIZE);
        b.extend_from_slice(&o.cv().to_bytes());
        b.extend_from_slice(&o.cmu().to_bytes());
        b.extend_from_slice(&o.ephemeral_key().0);
        b.extend_from_slice(o.enc_ciphertext());
        b.extend_from_slice(o.out_ciphertext());
        b.extend_from_slice(o.zkproof());
        parts.outputs_sapling.push(b.try_into().unwrap());
    }
    let sighash = parts.shielded_sighash(branch_id);
    eprintln!(
        "mixed-shapes-gen: shielded sighash {}",
        hex::encode(sighash)
    );
    let authorized = proven
        .apply_signatures(&mut rng, sighash, &[extsk.expsk.ask.clone()])
        .expect("the bundle signs");
    for (slot, s) in parts.spends.iter_mut().zip(authorized.shielded_spends()) {
        slot.1 = <[u8; 64]>::from(*s.spend_auth_sig());
    }
    parts.binding_sig = <[u8; 64]>::from(authorized.authorization().binding_sig);
    let mut validator = sapling::BatchValidator::new();
    assert!(
        validator.check_bundle(authorized.clone(), sighash),
        "the bundle passes its own consensus checks"
    );
    assert!(
        validator.validate(
            &spend_params.verifying_key(),
            &output_params.verifying_key(),
            &mut rng
        ),
        "the bundle's proofs and signatures verify"
    );
    eprintln!(
        "mixed-shapes-gen: {} spends ({} zat), {} outputs, valueBalance {}",
        parts.spends.len(),
        spent_value,
        parts.outputs_sapling.len(),
        parts.value_balance
    );
    let mut anchor_display = anchor.to_bytes();
    anchor_display.reverse();
    json!({
        "tx": hex::encode(parts.serialize()),
        "anchor": hex::encode(anchor_display),
        "selfAddress": hex::encode(self_address.to_bytes()),
    })
}

fn main() {
    let mut input = String::new();
    std::io::stdin()
        .read_to_string(&mut input)
        .expect("a request on stdin");
    let req: Value = serde_json::from_str(&input).expect("the request is JSON");
    let extsk = ExtendedSpendingKey::master(&hex_of(&req, "seed"));
    let answer = match req["mode"].as_str() {
        Some("address") => {
            json!({"selfAddress": hex::encode(extsk.default_address().1.to_bytes())})
        }
        Some("build") => build(&req, &extsk),
        other => panic!("unknown mode {other:?}"),
    };
    println!("{answer}");
}
