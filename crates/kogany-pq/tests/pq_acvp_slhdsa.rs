//! Replay of `testdata/yellowback/pq_acvp_slhdsa.json` (ycash6 `pq_crypto_tests/pq_slhdsa_acvp`),
//! the NIST ACVP SLH-DSA-SHA2-128s cases, verify side: every sigGen signature verifies under its
//! public key and context, and every sigVer case gets its expected verdict.

mod common;

use common::{arr, hx, int, load_pinned};
use kogany_pq::primitive::slh_dsa_sha2_128s_verify;

/// `keyGen[]`: KeyGen is not vendored (verify-only), so only the shape is checked: FIPS 205
/// `PK = PK.seed ‖ PK.root` and `SK = SK.seed ‖ SK.prf ‖ PK.seed ‖ PK.root`.
#[test]
fn acvp_keygen_shapes() {
    let doc = load_pinned("pq_acvp_slhdsa.json");
    let cases = arr(&doc, "keyGen");
    for tc in cases {
        let (pk, sk) = (hx(tc, "pk"), hx(tc, "sk"));
        assert_eq!(pk.len(), 32);
        assert_eq!(pk[..16], hx(tc, "pkSeed")[..]);
        assert_eq!(sk[..16], hx(tc, "skSeed")[..]);
        assert_eq!(sk[16..32], hx(tc, "skPrf")[..]);
        assert_eq!(sk[32..], pk[..]);
    }
    assert_eq!(cases.len(), 4);
}

/// `sigGen[]`: each expected signature (deterministic and hedged) verifies under `pk` with the
/// vector's `message` and `context`, and fails with the message's first byte flipped.
#[test]
fn acvp_siggen_signatures_verify() {
    let doc = load_pinned("pq_acvp_slhdsa.json");
    let mut n = 0;
    let mut empty_context = 0;
    for tc in arr(&doc, "sigGen") {
        let (pk, m, ctx, sig) = (
            hx(tc, "pk"),
            hx(tc, "message"),
            hx(tc, "context"),
            hx(tc, "signature"),
        );
        assert_eq!(sig.len(), 7856);
        assert!(
            slh_dsa_sha2_128s_verify(&pk, &m, &ctx, &sig),
            "sigGen tcId {}",
            int(tc, "tcId")
        );
        if let Some(first) = m.first() {
            let mut bad = m.clone();
            bad[0] = first ^ 1;
            assert!(!slh_dsa_sha2_128s_verify(&pk, &bad, &ctx, &sig));
        }
        if ctx.is_empty() {
            empty_context += 1;
        }
        n += 1;
    }
    assert_eq!((n, empty_context), (5, 2));
}

/// `sigVer[]`: the verdict equals `testPassed` for every case (two passes, every fail reason).
#[test]
fn acvp_sigver_verdicts() {
    let doc = load_pinned("pq_acvp_slhdsa.json");
    let mut n = 0;
    let mut passed = 0;
    for tc in arr(&doc, "sigVer") {
        let (pk, m, ctx, sig) = (
            hx(tc, "pk"),
            hx(tc, "message"),
            hx(tc, "context"),
            hx(tc, "signature"),
        );
        let want = tc["testPassed"].as_bool().unwrap();
        assert_eq!(
            slh_dsa_sha2_128s_verify(&pk, &m, &ctx, &sig),
            want,
            "sigVer tcId {} ({})",
            int(tc, "tcId"),
            tc["reason"]
        );
        passed += usize::from(want);
        n += 1;
    }
    assert_eq!((n, passed), (9, 2));
}
