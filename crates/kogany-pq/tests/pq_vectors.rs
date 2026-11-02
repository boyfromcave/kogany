//! Replay of `testdata/yellowback/pq_vectors.json` (ycash6 `pq_crypto_tests/pq_golden_vectors`),
//! verify side, and the malformed-encoding cases of `pq_round_trip_and_rejects` and
//! `pq_falcon_padding_is_canonical` run on the vectors' keys and signatures.

mod common;

use common::{arr, flip, hx, int, load_pinned, msg32};
use kogany_pq::{
    is_known_scheme, key_hash, primitive, pubkey_size, sig_size, verify, Scheme, KEYHASH_SIZE,
    MAX_CHUNK, MSG_SIZE, SIGOP_COST,
};
use serde_json::Value;

struct Key {
    scheme: u8,
    pk: Vec<u8>,
    msg: [u8; 32],
    sig: Vec<u8>,
}

fn keys(doc: &Value) -> Vec<Key> {
    arr(doc, "keys")
        .iter()
        .map(|e| Key {
            scheme: u8::try_from(int(e, "scheme")).unwrap(),
            pk: hx(e, "pk"),
            msg: msg32(&hx(e, "msg")),
            sig: hx(e, "sig"),
        })
        .collect()
}

/// `keys[]`: every entry's scheme is known, its key hash is `SHA256(scheme ‖ pk)` as recorded,
/// its key and signature have the registry's sizes, and the signature verifies on `msg`.
#[test]
fn golden_keys_verify_and_hash() {
    let doc = load_pinned("pq_vectors.json");
    assert_eq!(doc["format"], "ycash-pq-vectors-1");
    let mut per_scheme = [0usize; 3];
    for e in arr(&doc, "keys") {
        let scheme = u8::try_from(int(e, "scheme")).unwrap();
        assert!(is_known_scheme(scheme));
        per_scheme[usize::from(scheme)] += 1;
        let pk = hx(e, "pk");
        assert_eq!(pk.len(), pubkey_size(scheme));
        assert_eq!(key_hash(scheme, &pk).to_vec(), hx(e, "keyhash"));
        let msg = hx(e, "msg");
        assert_eq!(msg.len(), MSG_SIZE);
        let sig = hx(e, "sig");
        assert_eq!(sig.len(), sig_size(scheme));
        assert!(verify(scheme, &pk, &msg32(&msg), &sig), "{}", e["name"]);
        // seed/entropy/label/name drive KeyGen and SignWithEntropy, which are not vendored.
        assert_eq!(hx(e, "seed").len(), 48);
        let entropy = hx(e, "entropy").len();
        assert_eq!(entropy, if scheme == 1 { 0 } else { 88 });
    }
    assert!(per_scheme[1] >= 2 && per_scheme[2] >= 2, "{per_scheme:?}");
}

/// Minimal push of one script element (`CScript << vector`): direct below `OP_PUSHDATA1`,
/// `OP_PUSHDATA1` up to 255 bytes, `OP_PUSHDATA2` up to 520.
fn push(out: &mut Vec<u8>, data: &[u8]) {
    let n = data.len();
    if n < 0x4c {
        out.push(u8::try_from(n).unwrap());
    } else if n <= 0xff {
        out.extend([0x4c, u8::try_from(n).unwrap()]);
    } else {
        out.push(0x4d);
        out.extend(u16::try_from(n).unwrap().to_le_bytes());
    }
    out.extend_from_slice(data);
}

/// `<sig_1>..<sig_s> <s> <pk_1>..<pk_p> <p>`, each cut into 520-byte chunks (plan §4.2).
fn chunked_script_sig(sig: &[u8], pk: &[u8]) -> (Vec<u8>, usize, usize) {
    let mut out = Vec::new();
    let s = sig.chunks(MAX_CHUNK).inspect(|c| push(&mut out, c)).count();
    out.push(0x50 + u8::try_from(s).unwrap());
    let p = pk.chunks(MAX_CHUNK).inspect(|c| push(&mut out, c)).count();
    out.push(0x50 + u8::try_from(p).unwrap());
    (out, s, p)
}

/// Parses a push-only script into its elements; `OP_1`..`OP_16` arrive as `Err(n)`.
fn parse_pushes(script: &[u8]) -> Vec<Result<Vec<u8>, u8>> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < script.len() {
        let op = script[i];
        i += 1;
        let n = match op {
            0x01..=0x4b => usize::from(op),
            0x4c => {
                i += 1;
                usize::from(script[i - 1])
            }
            0x4d => {
                i += 2;
                usize::from(u16::from_le_bytes([script[i - 2], script[i - 1]]))
            }
            0x51..=0x60 => {
                out.push(Err(op - 0x50));
                continue;
            }
            _ => panic!("not a push-only scriptSig: opcode 0x{op:02x}"),
        };
        out.push(Ok(script[i..i + n].to_vec()));
        i += n;
    }
    out
}

/// `spends[]`: the `TX_PQPKH` scriptPubKey from the key hash, and the chunked scriptSig of the
/// key's signature ‖ hashtype and key, byte for byte, parsed back; the signature without its
/// hashtype verifies.
#[test]
fn golden_spends_encode_and_verify() {
    let doc = load_pinned("pq_vectors.json");
    let keys_json = arr(&doc, "keys");
    let mut spends = 0;
    for sp in arr(&doc, "spends") {
        let e = &keys_json[usize::try_from(int(sp, "key")).unwrap()];
        let scheme = u8::try_from(int(sp, "scheme")).unwrap();
        assert_eq!(int(sp, "scheme"), int(e, "scheme"));
        let pk = hx(e, "pk");
        let keyhash = hx(e, "keyhash");

        let mut spk = vec![0x20];
        spk.extend_from_slice(&keyhash);
        spk.extend([0x50 + scheme, 0xc2]);
        assert_eq!(spk, hx(sp, "scriptPubKey"));
        assert_eq!(spk.len(), 35);

        let hashtype = u8::try_from(int(sp, "hashtype")).unwrap();
        let mut sig_ht = hx(e, "sig");
        sig_ht.push(hashtype);
        let (script_sig, s, p) = chunked_script_sig(&sig_ht, &pk);
        assert_eq!(script_sig, hx(sp, "scriptSig"));
        assert_eq!(s, usize::try_from(int(sp, "sigChunks")).unwrap());
        assert_eq!(p, usize::try_from(int(sp, "pkChunks")).unwrap());
        assert_eq!(
            script_sig.len(),
            usize::try_from(int(sp, "scriptSigSize")).unwrap()
        );

        let elems = parse_pushes(&hx(sp, "scriptSig"));
        assert_eq!(elems.len(), s + 1 + p + 1);
        assert_eq!(elems[s], Err(u8::try_from(s).unwrap()));
        assert_eq!(elems[s + 1 + p], Err(u8::try_from(p).unwrap()));
        let join = |range: std::ops::Range<usize>| -> Vec<u8> {
            let last = range.end - 1;
            range
                .flat_map(|i| {
                    let c = elems[i].clone().unwrap();
                    assert!(i == last || c.len() == MAX_CHUNK);
                    c
                })
                .collect()
        };
        let sig_out = join(0..s);
        let pk_out = join(s + 1..s + 1 + p);
        assert_eq!(sig_out, sig_ht);
        assert_eq!(pk_out, pk);
        assert_eq!(key_hash(scheme, &pk_out).to_vec(), keyhash);
        let (sig, ht) = sig_out.split_at(sig_out.len() - 1);
        assert_eq!(ht, [hashtype]);
        assert!(verify(scheme, &pk_out, &msg32(&hx(e, "msg")), sig));
        spends += 1;
    }
    assert_eq!(spends, 2);
}

/// `pq_sizes_and_registry`: the scheme bytes, sizes and constants, and every other byte unknown.
#[test]
fn registry_sizes() {
    assert_eq!(Scheme::SlhDsaSha2_128s.byte(), 0x01);
    assert_eq!(Scheme::FnDsa512.byte(), 0x02);
    assert_eq!(KEYHASH_SIZE, 32);
    assert_eq!(MAX_CHUNK, 520);
    assert_eq!(SIGOP_COST, 20);
    assert_eq!((pubkey_size(1), sig_size(1)), (32, 7856));
    assert_eq!((pubkey_size(2), sig_size(2)), (897, 666));
    for b in 0..=u8::MAX {
        let known = b == 1 || b == 2;
        assert_eq!(is_known_scheme(b), known);
        assert_eq!(Scheme::try_from(b).is_ok(), known);
        if let Ok(s) = Scheme::try_from(b) {
            assert_eq!(u8::from(s), b);
        } else {
            assert_eq!((pubkey_size(b), sig_size(b)), (0, 0));
        }
    }
}

/// `pq_keyhash`: SHA256(scheme ‖ pk) for known and unknown scheme bytes and the empty key.
#[test]
fn keyhash_commits_the_scheme() {
    use sha2::{Digest, Sha256};
    let pk: Vec<u8> = (0u8..32).collect();
    for scheme in [1u8, 2, 7] {
        let mut pre = vec![scheme];
        pre.extend_from_slice(&pk);
        assert_eq!(
            key_hash(scheme, &pk),
            <[u8; 32]>::from(Sha256::digest(&pre))
        );
    }
    assert_ne!(key_hash(1, &pk), key_hash(2, &pk));
    assert_eq!(Scheme::FnDsa512.key_hash(&pk), key_hash(2, &pk));
    assert_eq!(key_hash(1, &[]), <[u8; 32]>::from(Sha256::digest([1u8])));
}

/// `pq_round_trip_and_rejects`, on the vectors' keys: wrong message, wrong key, the other scheme
/// byte, unknown scheme bytes, every length but the registry's for the key and the signature
/// (the hashtype byte appended included), and flipped bits in the signature and the key.
#[test]
fn rejects_malformed_and_mismatched() {
    let doc = load_pinned("pq_vectors.json");
    let keys = keys(&doc);
    for (i, k) in keys.iter().enumerate() {
        let (scheme, pk, msg, sig) = (k.scheme, &k.pk, &k.msg, &k.sig);
        assert!(verify(scheme, pk, msg, sig));

        // Wrong message.
        assert!(!verify(scheme, pk, &[0x5a; 32], sig));
        for byte in [0, 17, 31] {
            let mut m = *msg;
            m[byte] ^= 0x01;
            assert!(!verify(scheme, pk, &m, sig));
        }
        // Wrong key: another vector key of the same scheme.
        let other = keys
            .iter()
            .enumerate()
            .find(|(j, o)| *j != i && o.scheme == scheme)
            .unwrap()
            .1;
        assert_ne!(&other.pk, pk);
        assert!(!verify(scheme, &other.pk, msg, sig));
        // The other scheme's byte with these bytes, and unknown scheme bytes.
        assert!(!verify(3 - scheme, pk, msg, sig));
        for u in (0..=u8::MAX).filter(|u| !is_known_scheme(*u)) {
            assert!(!verify(u, pk, msg, sig));
        }

        // Signature lengths: one short, one long, empty, 32 long, the hashtype byte appended.
        let mut bad_sigs = vec![
            sig[..sig.len() - 1].to_vec(),
            [sig.as_slice(), &[0]].concat(),
            Vec::new(),
            [sig.as_slice(), &[0; 32]].concat(),
            [sig.as_slice(), &[0x01]].concat(),
        ];
        // A signature of the other scheme's length.
        bad_sigs.push(vec![0; sig_size(3 - scheme)]);
        for s in &bad_sigs {
            assert!(!verify(scheme, pk, msg, s), "sig len {}", s.len());
        }
        // Key lengths: one short, one long, empty.
        for p in [
            &pk[..pk.len() - 1],
            &[pk.as_slice(), &[0]].concat(),
            &[][..],
        ] {
            assert!(!verify(scheme, p, msg, sig), "pk len {}", p.len());
        }

        // Flipped bits in the signature: the first byte, a sweep, the last byte.
        let mut positions = vec![0, 1, sig.len() / 2, sig.len() - 1];
        positions.extend((0..sig.len()).step_by(sig.len() / 40));
        for pos in positions {
            for bit in [0, 7] {
                assert!(
                    !verify(scheme, pk, msg, &flip(sig, pos, bit)),
                    "{scheme}: sig flip at {pos} bit {bit}"
                );
            }
        }
        // Flipped bits in the public key.
        for pos in [0, 1, pk.len() / 2, pk.len() - 1] {
            assert!(
                !verify(scheme, &flip(pk, pos, 0), msg, sig),
                "{scheme}: pk flip at {pos}"
            );
        }
    }
}

/// Consensus SLH-DSA is pure mode with the empty context: the same signature under any other
/// context fails, and a context over 255 bytes is refused.
#[test]
fn slh_dsa_context_is_empty() {
    let doc = load_pinned("pq_vectors.json");
    for k in keys(&doc).iter().filter(|k| k.scheme == 1) {
        assert!(primitive::slh_dsa_sha2_128s_verify(
            &k.pk,
            &k.msg,
            &[],
            &k.sig
        ));
        assert!(!primitive::slh_dsa_sha2_128s_verify(
            &k.pk,
            &k.msg,
            &[0],
            &k.sig
        ));
        assert!(!primitive::slh_dsa_sha2_128s_verify(
            &k.pk, &k.msg, &[0; 256], &k.sig
        ));
        assert!(!primitive::slh_dsa_sha2_128s_verify(
            &k.pk[..31],
            &k.msg,
            &[],
            &k.sig
        ));
    }
}

/// `pq_falcon_padding_is_canonical`: one (pk, sig) has one accepted encoding. Every non-zero
/// padding byte, every other header, the compact (unpadded) form and inexact key and signature
/// lengths are refused by the registry and by the C entry point itself (local patch P2).
#[test]
fn falcon_padding_is_canonical() {
    let doc = load_pinned("pq_vectors.json");
    let mut padded = 0;
    for k in keys(&doc).iter().filter(|k| k.scheme == 2) {
        let (pk, msg, sig) = (&k.pk, &k.msg, &k.sig);
        assert_eq!(sig[0], 0x39);
        assert_eq!(pk[0], 0x09);
        let end = sig.len() - sig.iter().rev().take_while(|b| **b == 0).count();
        if end < sig.len() {
            padded += 1;
        }
        for i in end..sig.len() {
            for bit in [0, 7] {
                assert!(!verify(2, pk, msg, &flip(sig, i, bit)), "padding byte {i}");
            }
        }
        for h in [0x29, 0x3a, 0x00, 0xb9, 0x38, 0x19] {
            let mut s = sig.clone();
            s[0] = h;
            assert!(!verify(2, pk, msg, &s), "header 0x{h:02x}");
        }
        let compact = &sig[..end];
        assert!(!primitive::falcon512_padded_verify(pk, msg, compact));
        assert!(!verify(2, pk, msg, compact));
        assert!(primitive::falcon512_padded_verify(pk, msg, sig));
        assert!(!primitive::falcon512_padded_verify(
            &pk[..pk.len() - 1],
            msg,
            sig
        ));
        let long_pk = [pk.as_slice(), &[0]].concat();
        assert!(!primitive::falcon512_padded_verify(&long_pk, msg, sig));
        let long_sig = [sig.as_slice(), &[0]].concat();
        assert!(!primitive::falcon512_padded_verify(pk, msg, &long_sig));
    }
    assert!(padded > 0, "no vector signature carries padding");
}

/// Falcon encodings that set high bits the decoders must refuse: a public-key header other than
/// `0x09`; a public-key coefficient at or above q = 12289 (14-bit field `0x3fff` and exactly
/// q); a compressed signature coefficient encoded as "-0", one above 2047 (an unterminated
/// unary high part), and an all-zero or all-one compressed body.
#[test]
fn falcon_rejects_out_of_range_encodings() {
    let doc = load_pinned("pq_vectors.json");
    for k in keys(&doc).iter().filter(|k| k.scheme == 2) {
        let (pk, msg, sig) = (&k.pk, &k.msg, &k.sig);
        for h in [0x89, 0x0a, 0x00, 0x08, 0xff] {
            let mut p = pk.clone();
            p[0] = h;
            assert!(!verify(2, &p, msg, sig), "pk header 0x{h:02x}");
        }
        // First coefficient: the top 14 bits of pk[1..3].
        let with_first_coeff = |w: u16| {
            let mut p = pk.clone();
            p[1] = u8::try_from(w >> 6).unwrap();
            p[2] = (u8::try_from(w & 0x3f).unwrap() << 2) | (pk[2] & 0x03);
            p
        };
        assert!(!verify(2, &with_first_coeff(0x3fff), msg, sig));
        assert!(!verify(2, &with_first_coeff(12289), msg, sig));
        // Last coefficient: the low 14 bits of pk[895..897].
        let mut p = pk.clone();
        p[895] |= 0x3f;
        p[896] = 0xff;
        assert!(!verify(2, &p, msg, sig));

        // Compressed s starts at byte 41 (header 1, nonce 40). "-0": sign 1, low bits 0, stop bit.
        let mut s = sig.clone();
        s[41] = 0x80;
        s[42] |= 0x80;
        assert!(!verify(2, pk, msg, &s), "-0 coefficient");
        // |coefficient| > 2047: low bits 0x7f, then more than 15 zero high bits.
        let mut s = sig.clone();
        s[41] = 0x7f;
        s[42] = 0;
        s[43] = 0;
        assert!(!verify(2, pk, msg, &s), "coefficient over 2047");
        for fill in [0x00, 0xff] {
            let mut s = sig.clone();
            s[41..].fill(fill);
            assert!(!verify(2, pk, msg, &s), "compressed body 0x{fill:02x}");
        }
    }
}

/// `verify` is reentrant: the C keeps its state on its own stack, so threads verify at once.
#[test]
fn verify_is_thread_safe() {
    let doc = load_pinned("pq_vectors.json");
    let keys = keys(&doc);
    std::thread::scope(|scope| {
        for k in &keys {
            scope.spawn(move || {
                for _ in 0..2 {
                    assert!(verify(k.scheme, &k.pk, &k.msg, &k.sig));
                }
            });
        }
    });
}

/// Truncations and cross-scheme lengths the length gate must refuse before any C reads a byte:
/// a signature cut at every script-chunk boundary (a spend missing its last `MAX_CHUNK` pushes),
/// cut to half, to the Falcon header plus nonce, or to the header byte alone; a key of the other
/// scheme's length (zero-padded or cut); and the same refusals at the `primitive` entry points,
/// which are public and carry their own length checks.
#[test]
fn rejects_truncated_and_cross_length_encodings() {
    let doc = load_pinned("pq_vectors.json");
    for k in keys(&doc) {
        let (scheme, pk, msg, sig) = (k.scheme, &k.pk, &k.msg, &k.sig);
        let other = 3 - scheme;

        let mut cuts: Vec<usize> = (1..=sig.len() / MAX_CHUNK).map(|n| n * MAX_CHUNK).collect();
        cuts.extend([1, 41, sig.len() / 2, sig.len() - MAX_CHUNK]);
        for cut in cuts.into_iter().filter(|c| *c < sig.len()) {
            assert!(
                !verify(scheme, pk, msg, &sig[..cut]),
                "{scheme}: sig cut to {cut}"
            );
        }
        // The signature's bytes with the hashtype byte prepended rather than appended, cut to size.
        let shifted = [&[0x01], &sig[..sig.len() - 1]].concat();
        assert!(!verify(scheme, pk, msg, &shifted), "{scheme}: shifted sig");

        let mut padded_pk = pk.clone();
        padded_pk.resize(pubkey_size(other), 0);
        assert!(
            !verify(scheme, &padded_pk, msg, sig),
            "{scheme}: pk at the other scheme's size"
        );
        assert!(
            !verify(other, &padded_pk, msg, sig),
            "{scheme}: pk relabelled"
        );
        // Key and signature swapped.
        assert!(
            !verify(scheme, sig, msg, pk),
            "{scheme}: pk and sig swapped"
        );

        match scheme {
            1 => {
                for s in [
                    &sig[..sig.len() - 1],
                    &[sig.as_slice(), &[0]].concat(),
                    &[][..],
                ] {
                    assert!(
                        !primitive::slh_dsa_sha2_128s_verify(pk, msg, &[], s),
                        "slh primitive sig len {}",
                        s.len()
                    );
                }
                assert!(!primitive::slh_dsa_sha2_128s_verify(
                    &[pk.as_slice(), &[0]].concat(),
                    msg,
                    &[],
                    sig
                ));
                assert!(!primitive::slh_dsa_sha2_128s_verify(&[], msg, &[], sig));
            }
            _ => {
                for s in [&sig[..1], &sig[..41], &[][..], &sig[..sig.len() - 1]] {
                    assert!(
                        !primitive::falcon512_padded_verify(pk, msg, s),
                        "falcon primitive sig len {}",
                        s.len()
                    );
                }
                assert!(!primitive::falcon512_padded_verify(&[], msg, sig));
                // Header and nonce kept, compressed body zeroed: a 666-byte, correctly headed
                // signature that encodes s = 0 is refused (comp_decode needs 512 stop bits).
                let mut s = sig.clone();
                s[41..].fill(0);
                assert!(!primitive::falcon512_padded_verify(pk, msg, &s));
            }
        }
    }
}
