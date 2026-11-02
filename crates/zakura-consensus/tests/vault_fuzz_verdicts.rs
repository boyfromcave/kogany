// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

//! Ycash (kogany), W3-e: the vault fuzz verdict replay (qa/fuzz/vault/README.md). Every input of
//! the recorded corpora goes through kogany's parsers and classifiers (script kind with TX_PQPKH,
//! destination, V/I templates, bond redeem, act and payload decode, selector and template spend,
//! the Yellowback scripts, payloads and tags), and the verdict must equal the one recorded once
//! from ycash6 (qa/fuzz/vault/record_verdicts.py).

#![cfg(feature = "ycash")]

#[path = "../../../qa/fuzz/vault/src/verdict.rs"]
mod verdict;

use std::path::PathBuf;

fn verdicts_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../qa/fuzz/vault/verdicts")
}

#[test]
fn vault_fuzz_verdicts_match_ycash6() {
    let mut total = 0;
    let mut mismatches = Vec::new();
    for (corpus, format) in verdict::CORPORA {
        let path = verdicts_dir().join(format!("{corpus}.tsv"));
        let text = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("reading {}: {e}", path.display()));
        let rows = verdict::parse_verdicts(&text).unwrap_or_else(|e| panic!("{corpus}: {e}"));
        assert!(!rows.is_empty(), "{corpus}: no rows");
        for row in rows {
            let ours = verdict::verdict(format, &row.data).expect("known format");
            if ours != row.verdict {
                mismatches.push(format!(
                    "{corpus}/{}\n  ycash6: {}\n  kogany: {ours}",
                    row.name, row.verdict
                ));
            }
            total += 1;
        }
    }
    assert!(
        mismatches.is_empty(),
        "{} of {total} verdicts differ:\n{}",
        mismatches.len(),
        mismatches.join("\n")
    );
}

/// The TX_PQPKH the replay must see: the corpora cover the kind, the destination and the
/// exact-shape boundary (a non-minimal push, a third scheme, a trailing byte).
#[test]
fn pqpkh_kind_and_destination() {
    use zakura_chain::transparent::{Destination, PqKeyId, Script};
    use zakura_consensus::transaction::check::{standard_script_kind, ycash_standard_script_kind};

    let hash = [0x5a; 32];
    let mut s = vec![0x20];
    s.extend_from_slice(&hash);
    s.extend_from_slice(&[0x52, 0xc2]);
    let script = Script::new(&s);
    let id = PqKeyId {
        scheme: 2,
        key_hash: hash,
    };
    assert_eq!(script.pq_key_id(), Some(id));
    assert_eq!(script.destination(), Some(Destination::PqKeyHash(id)));
    assert!(
        standard_script_kind(&script).is_none(),
        "the zcash_script solver has no TX_PQPKH"
    );
    assert_eq!(
        ycash_standard_script_kind(&script).map(|k| k.as_str()),
        Some("pqpubkeyhash")
    );
    for bad in [
        [&[0x4c, 0x20][..], &hash, &[0x52, 0xc2]].concat(),
        [&[0x20][..], &hash, &[0x53, 0xc2]].concat(),
        [&s[..], &[0x00]].concat(),
    ] {
        let script = Script::new(&bad);
        assert_eq!(script.pq_key_id(), None);
        assert_eq!(script.destination(), None);
    }
}
