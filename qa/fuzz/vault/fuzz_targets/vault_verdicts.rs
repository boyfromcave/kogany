// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

//! Every input through kogany's vault, Yellowback and TX_PQPKH parsers in all four verdict
//! formats (each must be total), the round-trip properties ycash6's fuzz targets check, and, for
//! an input ycash6's verdicts were recorded for, the verdict equality the replay test asserts.

#![no_main]

use kogany_vault::act::{decode_act, encode_act};
use kogany_vault::template::{build_intent, build_vault, parse_intent, parse_vault};
use kogany_vault_fuzz::{recorded, verdict};
use libfuzzer_sys::fuzz_target;
use zakura_chain::transparent::{Destination, Script};

fuzz_target!(|data: &[u8]| {
    let mut ours = Vec::new();
    for format in ["Vault", "YellowbackScript", "YellowbackPayload", "YellowbackTag"] {
        ours.push((format, verdict::verdict(format, data).expect("known format")));
    }
    if let Some(expected) = recorded().get(data) {
        for (format, v) in expected {
            let mine = ours.iter().find(|(f, _)| f == format).map(|(_, v)| v);
            assert_eq!(mine, Some(v), "verdict differs from ycash6 ({format})");
        }
    }
    // The ycash6 targets' round trips (vault_fuzz_harness.h -1, -2, -5; standard.cpp).
    if let Some(v) = parse_vault(data) {
        assert_eq!(build_vault(&v).as_deref(), Some(data));
    }
    if let Some(i) = parse_intent(data) {
        assert_eq!(build_intent(&i).as_deref(), Some(data));
    }
    if let Ok(act) = decode_act(data) {
        assert_eq!(encode_act(&act), data);
    }
    let script = Script::new(data);
    if let Some(id) = script.pq_key_id() {
        assert_eq!(data.len(), 35);
        assert_eq!(script.destination(), Some(Destination::PqKeyHash(id)));
    }
});
