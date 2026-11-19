// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

//! ycash6 `src/test/yellowback_tag_tests.cpp`, case for case (the C++ test names): the coinbase
//! tag reader (plan §3.2, TAG-1..5) against pool-shaped scriptSigs, tag v2 and the payee
//! (docs/plans/beta4/price-feed.md §4.3), and the cross-line tag vectors
//! (`yellowback_tag_vectors.json`, D-T4).

mod common;

use common::{h, load_pinned};
use kogany_yellowback::codecs::tag::*;
use kogany_yellowback::params::{
    PRICE_MAX, PRICE_MIN, TAG_PRICE_SIGNAL_ONLY, TAG_SIZE, TAG_VERSION,
};

fn quote_tag(price: u64, flags: u8) -> CoinbaseTag {
    CoinbaseTag {
        flags,
        price_micro_usd: price,
        source_mask: 0x0007,
        payee: Payee::p2pkh(&[0xAB; 20]),
    }
}

fn quote() -> CoinbaseTag {
    quote_tag(50000, 0x01)
}

/// `CScript() << nHeight`.
fn prefix(height: i32) -> Vec<u8> {
    height_prefix(height)
}

fn cat(parts: &[&[u8]]) -> Vec<u8> {
    parts.concat()
}

/// `CScript() << bytes` (one push).
fn push(b: &[u8]) -> Vec<u8> {
    kogany_vault::script::Builder::new().push(b).into_bytes()
}

// Rule: TAG-1
#[test]
fn tag1_encoding_is_36_bytes_one_direct_push() {
    let t = quote();
    let enc = encode_tag(&t);
    assert_eq!(enc.len(), TAG_SIZE);
    assert_eq!(hex::encode(&enc[..4]), "59454421"); // "YED!"
    assert_eq!(enc[4], TAG_VERSION);
    assert_eq!(enc[5], 0x01);
    assert_eq!(hex::encode(&enc[6..14]), "50c3000000000000"); // 50,000 LE
    assert_eq!(hex::encode(&enc[14..16]), "0700");
    assert_eq!(hex::encode(&enc[16..]), "ab".repeat(20));
    let p = tag_push(&t);
    assert_eq!(p.len(), TAG_SIZE + 1);
    assert_eq!(p[0], 0x24);
    assert_eq!(&p[1..], &enc[..]);
    assert!(t.is_quote());
    assert!(t.signal());
}

// Rule: TAG-1, TAG-2, TAG-3, TAG-5
#[test]
fn tag1_to_5_table() {
    let height = 1234567;
    let pre = prefix(height);
    let q = quote();
    let other = quote_tag(60000, 0x01);
    let signal_only = quote_tag(TAG_PRICE_SIGNAL_ONLY, 0x01);
    let body = encode_tag(&q);
    let extranonce = h("0011223344556677");
    let magic_only = h("59454421");
    let bad = |f: &dyn Fn(&mut Vec<u8>)| {
        let mut b = body.clone();
        f(&mut b);
        push(&b)
    };
    let zero_key = CoinbaseTag {
        payee: Payee::p2pkh(&[0; 20]),
        ..q
    };
    let cases: Vec<(&str, Vec<u8>, Option<CoinbaseTag>)> = vec![
        // TAG-1: right after the height
        ("after_height", cat(&[&pre, &tag_push(&q)]), Some(q)),
        // TAG-1: after an 8-byte raw extranonce
        (
            "after_extranonce",
            cat(&[&pre, &extranonce, &tag_push(&q)]),
            Some(q),
        ),
        // TAG-1: after pool text, then extranonce after the tag
        (
            "after_pool_text",
            cat(&[&pre, b"/YcashPool/", &tag_push(&q), &extranonce]),
            Some(q),
        ),
        // TAG-1: raw 0x24 || tag appended without push encoding is found too
        (
            "raw_push_byte",
            cat(&[&pre, &extranonce, &h("24"), &body]),
            Some(q),
        ),
        // P10: the magic without its push opcode is not a tag
        (
            "magic_without_push_opcode",
            cat(&[&pre, &magic_only, &body[4..]]),
            None,
        ),
        // TAG-5: the first occurrence has too few bytes after it, a later full tag is ignored
        (
            "first_occurrence_short_then_full",
            cat(&[&pre, &h("24"), &magic_only, &h("0100"), &tag_push(&q)]),
            None,
        ),
        // TAG-5: two tags: the first decides
        (
            "two_tags",
            cat(&[&pre, &tag_push(&q), &tag_push(&other)]),
            Some(q),
        ),
        // TAG-5: an invalid first tag is no tag even though a valid one follows
        (
            "invalid_first_then_valid",
            cat(&[&pre, &bad(&|b| b[4] = 2), &tag_push(&q)]),
            None,
        ),
        // TAG-2: version
        ("bad_version", cat(&[&pre, &bad(&|b| b[4] = 0)]), None),
        // TAG-2: reserved flag bits
        (
            "reserved_flag_bit",
            cat(&[&pre, &bad(&|b| b[5] = 0x03)]),
            None,
        ),
        (
            "reserved_flag_bit7",
            cat(&[&pre, &bad(&|b| b[5] = 0x80)]),
            None,
        ),
        // TAG-2: price range
        (
            "price_below_min",
            cat(&[&pre, &tag_push(&quote_tag(PRICE_MIN as u64 - 1, 1))]),
            None,
        ),
        (
            "price_above_max",
            cat(&[&pre, &tag_push(&quote_tag(PRICE_MAX as u64 + 1, 1))]),
            None,
        ),
        (
            "price_at_min",
            cat(&[&pre, &tag_push(&quote_tag(PRICE_MIN as u64, 1))]),
            Some(quote_tag(PRICE_MIN as u64, 1)),
        ),
        (
            "price_at_max",
            cat(&[&pre, &tag_push(&quote_tag(PRICE_MAX as u64, 1))]),
            Some(quote_tag(PRICE_MAX as u64, 1)),
        ),
        // TAG-3: signal-only
        (
            "signal_only",
            cat(&[&pre, &tag_push(&signal_only)]),
            Some(signal_only),
        ),
        // TAG-3: any 20 bytes is a payout key
        (
            "zero_payout_key",
            cat(&[&pre, &tag_push(&zero_key)]),
            Some(zero_key),
        ),
        // TAG-1: the height prefix must be the exact minimal push
        (
            "wrong_height",
            cat(&[&prefix(height + 1), &tag_push(&q)]),
            None,
        ),
        ("no_prefix", tag_push(&q), None),
        ("empty", vec![], None),
        ("prefix_only", pre.clone(), None),
        // TAG-1: 31 bytes after the pattern
        (
            "truncated_by_one",
            cat(&[&pre, &h("24"), &body[..35]]),
            None,
        ),
    ];
    for (name, script_sig, expected) in &cases {
        assert_eq!(&find_tag(script_sig, height), expected, "{name}");
    }
    // TAG-3: kinds
    assert!(q.is_quote());
    assert!(!signal_only.is_quote());
    assert!(signal_only.signal());
    assert!(!quote_tag(50000, 0).signal());
}

// Rule: TAG-1, TAG-5
#[test]
fn tag5_pattern_inside_extranonce_with_too_few_bytes_following() {
    // The extranonce contains 24 59 45 44 21 near the end: fewer than 32 bytes follow, no tag.
    let height = 100;
    let s = cat(&[&prefix(height), &h("aabbccdd24594544210102030405")]);
    assert!(find_tag(&s, height).is_none());
    // Exactly 32 bytes after: version 1, flags 0, price 0 => a signal-only tag from "random" bytes.
    let t = cat(&[
        &prefix(height),
        &h("2459454421"),
        &h("0100"),
        &h("0000000000000000"),
        &h("0000"),
        &[0u8; 20],
    ]);
    assert_eq!(t.len(), prefix(height).len() + 5 + 32);
    let got = find_tag(&t, height).unwrap();
    assert!(!got.is_quote());
}

// Rule: TAG-1, P10
#[test]
fn tag1_magic_without_push_opcode_is_no_tag() {
    let height = 42;
    let body = encode_tag(&quote());
    // OP_PUSHDATA1 (4c 24 59 45 44 21 ...) contains the pattern at offset 1: the scan is
    // byte-level, not a script parse (V4), so a non-minimal push of the tag is still a tag.
    assert!(find_tag(&cat(&[&prefix(height), &h("4c24"), &body]), height).is_some());
    // Raw, no opcode at all.
    assert!(find_tag(&cat(&[&prefix(height), &body]), height).is_none());
    // With the direct push it is.
    assert!(find_tag(&cat(&[&prefix(height), &h("24"), &body]), height).is_some());
}

// Rule: TAG-1
#[test]
fn tag1_byte_budget_at_every_height_push_width() {
    // bad-cb-length: 2 <= scriptSig.size() <= 100; the height push grows from 1 to 5 bytes.
    let heights = [
        (1, 1),
        (16, 1),
        (17, 2),
        (65535, 4),
        (16777215, 5),
        (16777216, 5),
    ];
    let q = quote();
    for (height, width) in heights {
        let pre = prefix(height);
        assert_eq!(pre.len(), width, "height {height} push width");
        let tagged = cat(&[&pre, &tag_push(&q)]);
        assert!(tagged.len() <= 42);
        assert!(100 - tagged.len() >= 58);
        assert!(find_tag(&tagged, height).is_some());
        // A realistic pool coinbase: prefix, 8-byte extranonce, tag, pool text, 100 bytes exactly.
        let mut full = cat(&[&pre, &h("0011223344556677"), &tag_push(&q)]);
        full.resize(100, 0x2F);
        assert_eq!(
            find_tag(&full, height),
            Some(q),
            "height {height} full coinbase"
        );
        // At 101 bytes the block is invalid regardless (consensus); the reader does not judge (TAG-4).
        full.push(0);
        assert!(find_tag(&full, height).is_some());
    }
}

// Rule: TAG-4
#[test]
fn tag4_reader_never_judges_the_block() {
    let height = 7;
    for n in 0..120 {
        let s = cat(&[&prefix(height), &vec![0x24; n]]);
        assert!(find_tag(&s, height).is_none());
    }
    // Any prefix of a valid tagged script is nullopt or the tag itself.
    let tagged = cat(&[&prefix(height), &tag_push(&quote())]);
    for n in 0..=tagged.len() {
        let got = find_tag(&tagged[..n], height);
        assert!(got.is_none() || got == Some(quote()));
        assert_eq!(got.is_some(), n == tagged.len());
    }
}

/// Every height-prefix width the BIP34 push takes, including the negative and zero corners the
/// C++ `CScript << int` encodes (not reachable on a chain, but the encoding is the reader's
/// first gate).
#[test]
fn height_prefix_is_the_cscript_int_push() {
    assert_eq!(height_prefix(0), vec![0x00]);
    assert_eq!(height_prefix(-1), vec![0x4f]);
    assert_eq!(height_prefix(1), vec![0x51]);
    assert_eq!(height_prefix(16), vec![0x60]);
    assert_eq!(height_prefix(17), vec![0x01, 0x11]);
    assert_eq!(height_prefix(128), vec![0x02, 0x80, 0x00]);
    assert_eq!(height_prefix(1234567), vec![0x03, 0x87, 0xd6, 0x12]);
    assert_eq!(height_prefix(i32::MAX), vec![0x04, 0xff, 0xff, 0xff, 0x7f]);
}

// ---------------------------------------------------------------------------------------------
// Tag v2 (docs/plans/beta4/price-feed.md §4.3, beta4 P1 spec §1, §2, §7)

fn v2_tag(scheme: u8) -> CoinbaseTag {
    CoinbaseTag {
        flags: 0x01,
        price_micro_usd: 50000,
        source_mask: 0x0005,
        payee: Payee::pq(&kogany_vault::PqOwner {
            scheme,
            hash: kogany_vault::Hash32([0xCD; 32]),
        })
        .unwrap(),
    }
}

// Rule: TAG-1
#[test]
fn tag_v2_layout_and_roundtrip() {
    let height = 1000;
    for scheme in [1u8, 2] {
        let t = v2_tag(scheme);
        assert_eq!(t.version(), TAG_VERSION_V2);
        let body = encode_tag(&t);
        assert_eq!(body.len(), TAG_SIZE_V2);
        assert_eq!(hex::encode(&body[..5]), "5945442102");
        assert_eq!(body[16], scheme);
        let p = tag_push(&t);
        assert_eq!(p.len(), 50);
        assert_eq!(p[0], 0x31);
        let got = find_tag(&cat(&[&prefix(height), &h("00"), &p]), height);
        assert_eq!(got, Some(t));
        assert!(t.is_valid());
    }
    // v1 for a P2PKH payee, unchanged byte for byte
    assert_eq!(quote().version(), TAG_VERSION);
    assert_eq!(encode_tag(&quote()).len(), TAG_SIZE);
}

// Rule: TAG-2, TAG-5
#[test]
fn tag_v2_bad_scheme_truncation_and_pattern_order() {
    let height = 1000;
    let pre = prefix(height);
    let v2 = encode_tag(&v2_tag(2));
    let mut bad = v2.clone();
    bad[16] = 0x03; // unknown scheme
    assert_eq!(find_tag(&cat(&[&pre, &push(&bad)]), height), None);
    let mut zero = v2.clone();
    zero[16] = 0x00; // P2PKH is not a v2 scheme
    assert_eq!(find_tag(&cat(&[&pre, &push(&zero)]), height), None);
    // truncated: 48 bytes after the 0x31 push opcode
    assert_eq!(find_tag(&cat(&[&pre, &h("31"), &v2[..48]]), height), None);
    // a v2 pattern with version 1, a v1 pattern with version 2
    let mut v2as1 = v2.clone();
    v2as1[4] = 0x01;
    assert_eq!(find_tag(&cat(&[&pre, &push(&v2as1)]), height), None);
    let mut v1as2 = encode_tag(&quote());
    v1as2[4] = 0x02;
    assert_eq!(find_tag(&cat(&[&pre, &push(&v1as2)]), height), None);
    // first by position decides
    let (v1p, v2p) = (tag_push(&quote()), tag_push(&v2_tag(1)));
    assert_eq!(
        find_tag(&cat(&[&pre, &v1p, &v2p]), height).map(|t| t.version()),
        Some(TAG_VERSION)
    );
    assert_eq!(
        find_tag(&cat(&[&pre, &v2p, &v1p]), height).map(|t| t.version()),
        Some(TAG_VERSION_V2)
    );
    assert_eq!(find_tag(&cat(&[&pre, &push(&bad), &v1p]), height), None);
}

// Rule: FEE-2
#[test]
fn payee_script_order_and_serialisation() {
    let p2pkh = quote().payee;
    let (fn_dsa, slh) = (v2_tag(2).payee, v2_tag(1).payee);
    assert_eq!(p2pkh.script().unwrap().len(), 25);
    assert_eq!(fn_dsa.script().unwrap().len(), 35);
    assert_eq!(
        fn_dsa.script(),
        kogany_yellowback::codecs::script::pq_key_script(&fn_dsa.pq_owner().unwrap())
    );
    for p in [p2pkh, fn_dsa, slh] {
        assert_eq!(Payee::from_script(&p.script().unwrap()), Some(p));
        let enc = p.encode();
        assert_eq!(enc.len(), 1 + if p.is_p2pkh() { 20 } else { 32 });
        assert_eq!(enc[0], p.kind);
    }
    // nothing else is a payee: a P2SH, a trailing byte, an unknown scheme
    let p2sh = kogany_yellowback::codecs::script::p2sh_script(&[0x51]);
    assert_eq!(Payee::from_script(&p2sh), None);
    let mut longer = fn_dsa.script().unwrap();
    longer.push(0x00);
    assert_eq!(Payee::from_script(&longer), None);
    let mut scheme3 = fn_dsa.script().unwrap();
    scheme3[33] = 0x53;
    assert_eq!(Payee::from_script(&scheme3), None);
    // order: kind, then the hash bytes
    assert!(p2pkh < slh && slh < fn_dsa);
    assert_eq!(p2pkh.scheme_name(), "p2pkh");
    assert_eq!(slh.scheme_name(), "slh-dsa-sha2-128s");
    assert_eq!(fn_dsa.scheme_name(), "fn-dsa-512");
}

// Rule: TAG-1, TAG-5
#[test]
fn tag_vectors_cross_line() {
    // testdata/yellowback/yellowback_tag_vectors.json (D-T4): ycash-dd's file byte for byte.
    let doc = load_pinned("yellowback_tag_vectors.json");
    let cases = doc["cases"].as_array().unwrap();
    assert!(cases.len() >= 11);
    let mut found = 0;
    for c in cases {
        let name = c["name"].as_str().unwrap();
        let script_sig = h(c["scriptSig"].as_str().unwrap());
        assert_eq!(
            script_sig.len() as u64,
            c["scriptSigSize"].as_u64().unwrap(),
            "{name}"
        );
        let height = i32::try_from(c["height"].as_i64().unwrap()).unwrap();
        let got = find_tag(&script_sig, height);
        assert_eq!(got.is_some(), !c["tag"].is_null(), "{name}");
        assert_eq!(c["payeeScript"].is_null(), c["tag"].is_null(), "{name}");
        let Some(got) = got else { continue };
        found += 1;
        let t = &c["tag"];
        assert_eq!(
            u64::from(got.version()),
            t["version"].as_u64().unwrap(),
            "{name}"
        );
        assert_eq!(u64::from(got.flags), t["flags"].as_u64().unwrap(), "{name}");
        assert_eq!(
            got.price_micro_usd,
            t["priceMicroUsd"].as_u64().unwrap(),
            "{name}"
        );
        assert_eq!(
            u64::from(got.source_mask),
            t["sourceMask"].as_u64().unwrap(),
            "{name}"
        );
        assert_eq!(
            u64::from(got.payee.kind),
            t["payeeKind"].as_u64().unwrap(),
            "{name}"
        );
        assert_eq!(
            got.payee.scheme_name(),
            t["payoutScheme"].as_str().unwrap(),
            "{name}"
        );
        assert_eq!(
            hex::encode(got.payee.hash_bytes()),
            t["payoutHash"].as_str().unwrap(),
            "{name}"
        );
        assert_eq!(
            hex::encode(got.payee.script().unwrap()),
            c["payeeScript"].as_str().unwrap(),
            "{name}: payee script"
        );
        // the push re-encodes to the bytes found
        let p = tag_push(&got);
        assert!(
            script_sig.windows(p.len()).any(|w| w == p.as_slice()),
            "{name}: re-encode"
        );
        // D-6: the 60-byte coinbase at height 8,388,607 is within the consensus 2..=100 range
        assert!((2..=100).contains(&script_sig.len()), "{name}");
    }
    assert_eq!(found, 6);
}
