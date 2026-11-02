// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

//! The codecs over the two pinned cross-line chains, `yellowback_golden.json` (462 blocks) and
//! `yellowback_pq_vectors.json` `chain` (168 blocks), built by ycash6's Python model and
//! replayed by the C++ state tests (`yellowback_state_tests.cpp`). This is the codec layer of
//! that replay; the state machine (W5-d) and the state hash (W5-e/f) consume the same blocks.
//!
//! Every coinbase is read by `find_tag` at its height and every transaction by `find_payload`
//! and `find_carrier_input`: each tag, payload and carrier found re-encodes to its exact bytes;
//! every MINT's YED vault output equals `yed_vault_script` of its owner and reference height
//! under the chain's parameters (`params.attestorSetId` in the C++ `uint256` display order); and
//! the counts of each kind are those of the pinned files.

// Test reporting: a gate run shows what was compared.
#![allow(clippy::print_stderr)]

mod common;

use std::collections::BTreeMap;

use common::{h, load_pinned, tx_io, uint256_display};
use kogany_vault::template::{match_intent, parse_vault};
use kogany_yellowback::codecs::payload::{encode_payload, find_payload, payload_script, Payload};
use kogany_yellowback::codecs::script::{find_carrier_input, yed_vault_script, YED_TAG};
use kogany_yellowback::codecs::tag::{find_tag, tag_push};
use kogany_yellowback::params::{regtest_params_with, BundleCarrier, Params};
use serde_json::Value;
use sha2::{Digest, Sha256};

/// The chain's module parameters (`params`: the seven regtest arguments and the Falcon height).
fn chain_params(v: &Value) -> Params {
    let int = |k: &str| i32::try_from(v[k].as_i64().unwrap()).unwrap();
    let carrier = match v["bundleCarrier"].as_i64().unwrap() {
        0 => BundleCarrier::ScriptSig,
        1 => BundleCarrier::OpReturn,
        _ => BundleCarrier::Either,
    };
    let mut p = regtest_params_with(
        int("startHeight"),
        int("sigmaRefBps"),
        int("supplyCapBps"),
        uint256_display(v["attestorSetId"].as_str().unwrap()).0,
        int("attestArmMin"),
        carrier,
        v["mintRequiresArmed"].as_bool().unwrap(),
    );
    p.pq_falcon_height = int("pqFalconHeight");
    p
}

/// Reads one chain; returns the counts by kind.
fn replay(params: &Params, blocks: &[Value]) -> BTreeMap<String, usize> {
    let mut n: BTreeMap<String, usize> = BTreeMap::new();
    let mut count = |k: &str| *n.entry(k.to_owned()).or_default() += 1;
    for b in blocks {
        let height = i32::try_from(b["height"].as_i64().unwrap()).unwrap();
        for (i, raw) in b["txs"].as_array().unwrap().iter().enumerate() {
            let io = tx_io(&h(raw.as_str().unwrap()));
            if i == 0 {
                count("coinbase");
                if let Some(tag) = find_tag(&io.script_sigs[0], height) {
                    count("tag");
                    let push = tag_push(&tag);
                    assert!(
                        io.script_sigs[0].windows(push.len()).any(|w| w == push),
                        "height {height}: the tag re-encodes to its bytes"
                    );
                }
                continue;
            }
            if let Some(fp) = find_payload(&io.outputs) {
                let t = fp.payload.payload_type().name();
                count(t);
                let data = encode_payload(&fp.payload).unwrap();
                assert_eq!(
                    payload_script(&data),
                    io.outputs[fp.op_return_index],
                    "height {height}: {t} re-encodes"
                );
                if let Payload::Mint(m) = &fp.payload {
                    let want =
                        yed_vault_script(params, &m.owner(), i64::from(m.ref_height)).unwrap();
                    assert!(
                        io.outputs.contains(&want),
                        "height {height}: the MINT's V is yed_vault_script"
                    );
                }
            }
            for s in &io.outputs {
                if let Some(v) = parse_vault(s) {
                    if v.tag == YED_TAG {
                        count("yed-vault-output");
                    }
                } else if match_intent(s)
                    .into_match()
                    .is_some_and(|i| i.tag == YED_TAG)
                {
                    count("yed-intent-output");
                }
            }
            if let Ok(k) = find_carrier_input(&io.script_sigs, false) {
                count("carrier");
                let spend =
                    kogany_yellowback::codecs::script::parse_carrier_script_sig(&io.script_sigs[k])
                        .unwrap();
                let hashed: [u8; 32] = Sha256::digest(&spend.bundle).into();
                count(if hashed == spend.bundle_hash.0 {
                    "carrier-hash-ok"
                } else {
                    "carrier-hash-bad"
                });
            }
        }
    }
    n
}

#[test]
fn golden_chain_codecs() {
    let v = load_pinned("yellowback_golden.json");
    let p = chain_params(&v["params"]);
    let blocks = v["blocks"].as_array().unwrap();
    assert_eq!(blocks.len(), 462);
    let n = replay(&p, blocks);
    eprintln!("yellowback_golden.json: {n:?}");
    // The pinned file's census. 461 coinbases carry the pattern; height 13's tag sets a reserved
    // flag bit (flags 0x03), so TAG-2 makes it no tag.
    let census = [
        ("coinbase", 462),
        ("tag", 460),
        ("mint", 11),
        ("transfer", 4),
        ("redeem", 17),
        ("register", 1),
        ("notice", 3),
        ("equivocation", 2),
        ("cancelcosign", 7),
        ("carrier", 25),
        ("carrier-hash-ok", 25),
        ("yed-vault-output", 23),
        ("yed-intent-output", 21),
    ];
    assert_eq!(n, census.iter().map(|&(k, c)| (k.to_owned(), c)).collect());
    let b13 = &blocks[12];
    assert_eq!(b13["height"], 13);
    let io = tx_io(&h(b13["txs"][0].as_str().unwrap()));
    assert!(io.script_sigs[0].windows(5).any(|w| w == b"\x24YED!"));
    assert_eq!(find_tag(&io.script_sigs[0], 13), None);
}

#[test]
fn pq_chain_codecs() {
    let v = load_pinned("yellowback_pq_vectors.json");
    let p = chain_params(&v["chain"]["params"]);
    let blocks = v["chain"]["blocks"].as_array().unwrap();
    assert_eq!(blocks.len(), 168);
    let n = replay(&p, blocks);
    eprintln!("yellowback_pq_vectors.json chain: {n:?}");
    let census = [
        ("coinbase", 168),
        ("tag", 168),
        ("mint", 12),
        ("transfer", 6),
        ("yed-vault-output", 12),
    ];
    assert_eq!(n, census.iter().map(|&(k, c)| (k.to_owned(), c)).collect());
}
