//! The vendored C matches `csrc/SHA256SUMS` (the build checks it too, before compiling).

use std::{collections::BTreeSet, path::PathBuf};

use sha2::{Digest, Sha256};

#[test]
fn vendored_c_matches_its_manifest() {
    let csrc = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("csrc");
    let sums = std::fs::read_to_string(csrc.join("SHA256SUMS")).unwrap();
    let mut listed = BTreeSet::new();
    for line in sums.lines() {
        let (want, file) = line.split_once("  ").unwrap();
        let bytes = std::fs::read(csrc.join(file)).unwrap();
        assert_eq!(hex::encode(Sha256::digest(&bytes)), want, "{file}");
        listed.insert(file.to_owned());
    }
    let mut present = BTreeSet::new();
    for dir in ["falcon", "slhdsa"] {
        for entry in std::fs::read_dir(csrc.join(dir)).unwrap() {
            present.insert(format!(
                "{dir}/{}",
                entry.unwrap().file_name().to_string_lossy()
            ));
        }
    }
    assert_eq!(listed, present);
    assert_eq!(listed.len(), 23);
    // Verify-only: no Falcon keygen/signing/floating-point translation unit is vendored.
    for absent in [
        "keygen.c",
        "sign.c",
        "fft.c",
        "fpr.c",
        "rng.c",
        "ycash_falcon_sign.c",
    ] {
        assert!(!listed.contains(&format!("falcon/{absent}")), "{absent}");
    }
}
