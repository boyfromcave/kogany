// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

//! ycash6 `src/test/yellowback_tag_tests.cpp`, case for case (the C++ test names): the coinbase
//! tag reader (plan §3.2, TAG-1..5) against pool-shaped scriptSigs.

mod common;

use common::h;
use kogany_yellowback::codecs::tag::*;
use kogany_yellowback::params::{
    PRICE_MAX, PRICE_MIN, TAG_PRICE_SIGNAL_ONLY, TAG_SIZE, TAG_VERSION,
};

fn quote_tag(price: u64, flags: u8) -> CoinbaseTag {
    CoinbaseTag {
        flags,
        price_micro_usd: price,
        source_mask: 0x0007,
        payout_key: [0xAB; 20],
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
    let bad = |f: &dyn Fn(&mut [u8; 36])| {
        let mut b = body;
        f(&mut b);
        push(&b)
    };
    let zero_key = CoinbaseTag {
        payout_key: [0; 20],
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
