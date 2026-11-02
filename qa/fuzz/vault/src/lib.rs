// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

//! kogany's vault fuzz package (README.md): the verdicts of kogany's parsers, and the ycash6
//! verdicts recorded once by `record_verdicts.py`.

pub mod verdict;

use std::collections::BTreeMap;
use std::sync::OnceLock;

/// The recorded verdicts files, by corpus, embedded so the fuzz target needs no file system.
const RECORDED: &[(&str, &str)] = &[
    ("Vault", include_str!("../verdicts/Vault.tsv")),
    ("YellowbackScript", include_str!("../verdicts/YellowbackScript.tsv")),
    ("YellowbackPayload", include_str!("../verdicts/YellowbackPayload.tsv")),
    ("YellowbackTag", include_str!("../verdicts/YellowbackTag.tsv")),
    ("PQVectors", include_str!("../verdicts/PQVectors.tsv")),
    ("PQPKH", include_str!("../verdicts/PQPKH.tsv")),
];

/// The recorded ycash6 verdicts of an input, by `(format, verdict)`, keyed by the input bytes.
pub fn recorded() -> &'static BTreeMap<Vec<u8>, Vec<(&'static str, String)>> {
    static MAP: OnceLock<BTreeMap<Vec<u8>, Vec<(&'static str, String)>>> = OnceLock::new();
    MAP.get_or_init(|| {
        let mut map: BTreeMap<Vec<u8>, Vec<(&'static str, String)>> = BTreeMap::new();
        for (corpus, text) in RECORDED {
            let format = verdict::CORPORA
                .iter()
                .find(|(c, _)| c == corpus)
                .map(|(_, f)| *f)
                .expect("every recorded corpus has a format");
            for row in verdict::parse_verdicts(text).expect("recorded verdicts parse") {
                map.entry(row.data).or_default().push((format, row.verdict));
            }
        }
        map
    })
}
