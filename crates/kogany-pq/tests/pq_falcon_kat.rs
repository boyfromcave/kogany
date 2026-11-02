//! Replay of `testdata/yellowback/pq_falcon_kat.json` (ycash6 `pq_crypto_tests/pq_falcon_kat`),
//! verify side: the NIST round-3 and PQClean padded known answers through the C++ lines' Falcon
//! entry point.

mod common;

use common::{arr, flip, hx, int, load_pinned};
use kogany_pq::primitive::falcon512_padded_verify;

const SIG: usize = 666;
const NONCE: usize = 40;

/// `r3[]`: `sm = sig_len(2) ‖ nonce(40) ‖ msg ‖ 0x29 ‖ compressed s`. The compressed signature
/// in the padded layout (`0x39 ‖ nonce ‖ s ‖ zeros`) verifies under `pk`, and equals the
/// matching `r3_all` row; the compact form (no padding), which PQClean's own verifier accepts,
/// is refused (local patch P2). `seed`/`sk` drive KeyGen and signing, which are not vendored.
#[test]
fn r3_compressed_signatures_verify_padded() {
    let doc = load_pinned("pq_falcon_kat.json");
    let all = arr(&doc, "r3_all");
    let r3 = arr(&doc, "r3");
    for (i, e) in r3.iter().enumerate() {
        assert_eq!(usize::try_from(int(e, "count")).unwrap(), i);
        let (pk, msg, sm) = (hx(e, "pk"), hx(e, "msg"), hx(e, "sm"));
        let siglen = usize::from(u16::from_be_bytes([sm[0], sm[1]]));
        assert_eq!(sm.len(), 2 + NONCE + msg.len() + siglen);
        let nonce = &sm[2..2 + NONCE];
        assert_eq!(&sm[2 + NONCE..2 + NONCE + msg.len()], msg.as_slice());
        assert_eq!(sm[2 + NONCE + msg.len()], 0x29);
        let comp = &sm[2 + NONCE + msg.len() + 1..];
        assert!(comp.len() < SIG - NONCE);

        let mut padded = vec![0x39];
        padded.extend_from_slice(nonce);
        padded.extend_from_slice(comp);
        let compact = padded.clone();
        padded.resize(SIG, 0);
        assert!(falcon512_padded_verify(&pk, &msg, &padded), "r3 count {i}");
        assert!(compact.len() < SIG);
        assert!(
            !falcon512_padded_verify(&pk, &msg, &compact),
            "r3 compact count {i}"
        );

        assert_eq!(all[i]["pk"], e["pk"]);
        assert_eq!(hx(&all[i], "sig"), padded);
    }
    assert_eq!(r3.len(), 5);
}

/// `r3_all[]`: all 100 round-3 entries as verify-only rows; each verifies, and fails with bit 0
/// of byte `41 + count % 200` of the signature flipped (audit F-6).
#[test]
fn r3_all_verify_and_reject_one_flip() {
    let doc = load_pinned("pq_falcon_kat.json");
    let mut n = 0;
    for e in arr(&doc, "r3_all") {
        assert_eq!(usize::try_from(int(e, "count")).unwrap(), n);
        let (pk, msg, sig) = (hx(e, "pk"), hx(e, "msg"), hx(e, "sig"));
        assert_eq!((pk.len(), sig.len()), (897, SIG));
        assert_eq!(msg.len(), 33 * (n + 1));
        assert!(falcon512_padded_verify(&pk, &msg, &sig), "r3_all count {n}");
        let bad = flip(&sig, 41 + n % 200, 0);
        assert!(
            !falcon512_padded_verify(&pk, &msg, &bad),
            "r3_all flipped count {n}"
        );
        n += 1;
    }
    assert_eq!(n, 100);
}

/// `padded[]`: PQClean's falcon-padded-512 KAT, `sm = signature(666) ‖ msg`; the signature
/// verifies under `pk`.
#[test]
fn pqclean_padded_kat_verifies() {
    let doc = load_pinned("pq_falcon_kat.json");
    let cases = arr(&doc, "padded");
    for e in cases {
        let (pk, msg, sm) = (hx(e, "pk"), hx(e, "msg"), hx(e, "sm"));
        assert_eq!(sm.len(), SIG + msg.len());
        let (sig, tail) = sm.split_at(SIG);
        assert_eq!(tail, msg.as_slice());
        assert_eq!(sig[0], 0x39);
        assert!(falcon512_padded_verify(&pk, &msg, sig));
        assert!(!falcon512_padded_verify(&pk, &msg, &flip(sig, SIG / 2, 0)));
    }
    assert_eq!(cases.len(), 1);
}
