// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

//! Compiles the vendored verify-only post-quantum C (`csrc/`, byte copies of ycash6
//! `src/crypto/pq/{falcon,slhdsa}/`; see `README.md`) with the `cc` crate.
//!
//! Before compiling, every file under `csrc/falcon` and `csrc/slhdsa` is checked against
//! `csrc/SHA256SUMS`: a drifted, missing or extra file fails the build, so the object code can
//! only come from the pinned bytes.
//!
//! Portable C99, no target-feature flags; the optimisation level follows the Cargo profile, so
//! the debug and release test runs exercise differently compiled objects against the same vectors.
//! The global symbols with generic names (`sha2_*`, `shake*`, `slh_*`, …) are renamed
//! `kogany_pq_*` with `-D` defines, so they cannot collide with another C library linked into
//! `zakurad`. A rename only: no byte of a vendored file changes.

use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
};

use sha2::{Digest, Sha256};

/// The translation units the verifiers need. Falcon: PQClean's verify path only (`codec.c`,
/// `common.c`, `vrfy.c`, `fips202.c`) and the Ycash entry point. SLH-DSA: `slh_dsa.c` is one
/// translation unit holding both signing and verification; it is vendored whole (patch P3
/// included) and only `slh_verify` is bound.
const SOURCES: &[&str] = &[
    "falcon/codec.c",
    "falcon/common.c",
    "falcon/fips202.c",
    "falcon/vrfy.c",
    "falcon/ycash_falcon_verify.c",
    "slhdsa/sha2_256.c",
    "slhdsa/sha2_512.c",
    "slhdsa/slh_dsa.c",
    "slhdsa/slh_sha2.c",
];

/// Global symbols of the vendored objects with names another C library might also define.
/// PQClean's own `PQCLEAN_FALCONPADDED512_CLEAN_*` names are already namespaced.
const RENAMED_SYMBOLS: &[&str] = &[
    "sha2_224",
    "sha2_224_init",
    "sha2_256",
    "sha2_256_compress",
    "sha2_256_copy",
    "sha2_256_final_len",
    "sha2_256_final_pad",
    "sha2_256_init",
    "sha2_256_update",
    "sha2_384",
    "sha2_384_init",
    "sha2_512",
    "sha2_512_224",
    "sha2_512_224_init",
    "sha2_512_256",
    "sha2_512_256_init",
    "sha2_512_compress",
    "sha2_512_copy",
    "sha2_512_final_len",
    "sha2_512_final_pad",
    "sha2_512_init",
    "sha2_512_update",
    "sha3_256",
    "sha3_256_inc_absorb",
    "sha3_256_inc_ctx_clone",
    "sha3_256_inc_ctx_release",
    "sha3_256_inc_finalize",
    "sha3_256_inc_init",
    "sha3_384",
    "sha3_384_inc_absorb",
    "sha3_384_inc_ctx_clone",
    "sha3_384_inc_ctx_release",
    "sha3_384_inc_finalize",
    "sha3_384_inc_init",
    "sha3_512",
    "sha3_512_inc_absorb",
    "sha3_512_inc_ctx_clone",
    "sha3_512_inc_ctx_release",
    "sha3_512_inc_finalize",
    "sha3_512_inc_init",
    "shake128",
    "shake128_absorb",
    "shake128_ctx_clone",
    "shake128_ctx_release",
    "shake128_inc_absorb",
    "shake128_inc_ctx_clone",
    "shake128_inc_ctx_release",
    "shake128_inc_finalize",
    "shake128_inc_init",
    "shake128_inc_squeeze",
    "shake128_squeezeblocks",
    "shake256",
    "shake256_absorb",
    "shake256_ctx_clone",
    "shake256_ctx_release",
    "shake256_inc_absorb",
    "shake256_inc_ctx_clone",
    "shake256_inc_ctx_release",
    "shake256_inc_finalize",
    "shake256_inc_init",
    "shake256_inc_squeeze",
    "shake256_squeezeblocks",
    "slh_alg_id",
    "slh_dsa_sha2_128f",
    "slh_dsa_sha2_128s",
    "slh_dsa_sha2_192f",
    "slh_dsa_sha2_192s",
    "slh_dsa_sha2_256f",
    "slh_dsa_sha2_256s",
    "slh_keygen",
    "slh_keygen_internal",
    "slh_pk_sz",
    "slh_sig_sz",
    "slh_sign",
    "slh_sign_internal",
    "slh_sk_sz",
    "slh_verify",
    "slh_verify_internal",
    "ycash_falcon512_verify",
];

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Every vendored file, relative to `csrc/`, sorted.
fn vendored_files(csrc: &Path) -> BTreeSet<String> {
    let mut files = BTreeSet::new();
    for dir in ["falcon", "slhdsa"] {
        let entries = fs::read_dir(csrc.join(dir))
            .unwrap_or_else(|e| panic!("csrc/{dir} must exist in the crate: {e}"));
        for entry in entries {
            let entry = entry.unwrap_or_else(|e| panic!("csrc/{dir} must be readable: {e}"));
            files.insert(format!("{dir}/{}", entry.file_name().to_string_lossy()));
        }
    }
    files
}

/// Fails the build unless `csrc/SHA256SUMS` lists exactly the vendored files with their hashes.
fn check_manifest(csrc: &Path) {
    let sums = fs::read_to_string(csrc.join("SHA256SUMS"))
        .unwrap_or_else(|e| panic!("csrc/SHA256SUMS must exist in the crate: {e}"));
    let mut listed = BTreeSet::new();
    for line in sums.lines() {
        let (want, file) = line
            .split_once("  ")
            .unwrap_or_else(|| panic!("SHA256SUMS line is `<sha256>  <path>`: {line:?}"));
        let bytes = fs::read(csrc.join(file))
            .unwrap_or_else(|e| panic!("csrc/{file} is pinned in SHA256SUMS but unreadable: {e}"));
        let got = hex(&Sha256::digest(&bytes));
        assert_eq!(got, want, "csrc/{file} does not match csrc/SHA256SUMS");
        listed.insert(file.to_owned());
    }
    assert_eq!(
        listed,
        vendored_files(csrc),
        "csrc/SHA256SUMS must list exactly the files in csrc/falcon and csrc/slhdsa"
    );
}

fn main() {
    let csrc = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("csrc");
    println!("cargo:rerun-if-changed={}", csrc.display());
    check_manifest(&csrc);

    let mut build = cc::Build::new();
    build
        .include(csrc.join("falcon"))
        .include(csrc.join("slhdsa"))
        .std("c99")
        .warnings(false);
    for source in SOURCES {
        build.file(csrc.join(source));
    }
    for symbol in RENAMED_SYMBOLS {
        build.define(symbol, Some(format!("kogany_pq_{symbol}").as_str()));
    }
    build.compile("kogany_pq");
}
