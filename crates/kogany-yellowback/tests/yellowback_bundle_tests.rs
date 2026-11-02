// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

//! ycash6 `src/test/yellowback_bundle_tests.cpp` (BUNDLE-1, W2, W8), case for case: the codec and
//! its sizes, extraction from every input position and both carrier modes, `VerifyBundle`'s check
//! order with every reason reachable, the signature cache contract, the bundle statistic, and the
//! cancel co-sign codecs. The attestations are the pinned `yellowback_attest_vectors.json`.

mod attest_common;
mod common;

use std::collections::BTreeMap;

use attest_common::{carrier_in, enc, plain_in, sha256, tx_with, u256s, RecordingCache, Vectors};
use kogany_vault::state::VaultTx;
use kogany_vault::{Hash32, OutPoint, PubKeyBytes};
use kogany_yellowback::attest::bundle::{carrier_input, CANCEL_EVIDENCE_SIZE};
use kogany_yellowback::attest::{
    bundle_stat as stat, cancel_cosign_message, decode_bundle, decode_cancel_cosigns,
    decode_cancel_evidence, encode_attestation, encode_bundle, encode_cancel_cosigns,
    encode_cancel_evidence, extract_bundle, sig_cache_key, verify_bundle, Attestation, Bundle,
    BundleError, BundleLimits, BundleSource, CancelCosignEntry, CancelStatement, SigCache,
};
use kogany_yellowback::codecs::script::CarrierError;
use kogany_yellowback::math::U256;
use kogany_yellowback::params::{BundleCarrier, PRICE_MAX, PRICE_MIN};
use sha2::{Digest, Sha256};

/// The C++ `Fixture`: the vectors, `R = 1003`, the limits and every seq selected.
struct Fixture {
    v: Vectors,
    limits: BundleLimits,
    selected: Vec<u16>,
    r: i64,
    keys: BTreeMap<u16, PubKeyBytes>,
    block_hashes: BTreeMap<i64, Hash32>,
}

impl Fixture {
    fn new() -> Fixture {
        let v = Vectors::load();
        let keys = v.keys.clone();
        let block_hashes = v.block_hashes.clone();
        Fixture {
            v,
            limits: BundleLimits {
                attest_max_age: 8,
                m_select: 2,
                bundle_max: 6,
                start_height: 1000,
                price_min: PRICE_MIN,
                price_max: PRICE_MAX,
            },
            selected: vec![0, 1, 2, 3, 4, 5],
            r: 1003,
            keys,
            block_hashes,
        }
    }

    fn atts(&self) -> &[Attestation] {
        &self.v.atts
    }

    fn a(&self, i: usize) -> Attestation {
        self.v.atts[i]
    }

    fn verify_with(
        &self,
        tx: &VaultTx,
        mode: BundleCarrier,
        skip_vin0: bool,
        tail: &[u8],
        cache: Option<&dyn SigCache>,
    ) -> Result<Vec<Attestation>, BundleError> {
        let pubkey_of = |seq: u16| self.keys.get(&seq).copied();
        let hash_at = |h: i64| self.block_hashes.get(&h).copied();
        verify_bundle(
            tx,
            mode,
            skip_vin0,
            tail,
            self.r,
            &self.selected,
            &self.limits,
            Some(&pubkey_of),
            Some(&hash_at),
            cache,
        )
    }

    fn verify(&self, tx: &VaultTx) -> Result<Vec<Attestation>, BundleError> {
        self.verify_with(tx, BundleCarrier::ScriptSig, false, &[], None)
    }

    fn reason(&self, tx: &VaultTx) -> &'static str {
        match self.verify(tx) {
            Ok(_) => "",
            Err(e) => e.reason(),
        }
    }
}

fn reason_of(r: Result<Vec<Attestation>, BundleError>) -> &'static str {
    match r {
        Ok(_) => "",
        Err(e) => e.reason(),
    }
}

fn ex_reason(r: Result<(Vec<u8>, BundleSource), BundleError>) -> &'static str {
    match r {
        Ok(_) => "",
        Err(e) => e.reason(),
    }
}

fn carrier(b: &[u8]) -> kogany_vault::state::VaultTxIn {
    carrier_in(b, None, 0)
}

#[test]
fn codec_round_trip_and_sizes() {
    let f = Fixture::new();
    // Six attestations are 448 bytes: "YA" 01 06 then 6 x 74.
    let six = enc(f.atts());
    assert_eq!(six.len(), 448);
    assert_eq!(six[..4], [b'Y', b'A', 1, 6]);
    assert!(six.len() <= 520); // MAX_SCRIPT_ELEMENT_SIZE
    let d = decode_bundle(&six, 6).unwrap();
    assert_eq!(d.version, 1);
    assert_eq!(d.atts, f.atts());
    assert_eq!(encode_bundle(&d), six);
    // The vectors file carries the same bytes.
    assert_eq!(hex::encode(&six), f.v.doc["bundle6"].as_str().unwrap());
    for (i, a) in f.atts().iter().enumerate() {
        assert_eq!(usize::from(a.seq), i);
    }
    // Empty bundle: 4 bytes, decodes.
    let zero = enc(&[]);
    assert_eq!(zero.len(), 4);
    assert!(decode_bundle(&zero, 6).unwrap().atts.is_empty());
    // A seventh is refused by the default ceiling (BUNDLE_MAX = 6) and admitted by a larger one.
    let mut seven = f.atts().to_vec();
    seven.push(f.a(0));
    let seven_enc = enc(&seven);
    assert_eq!(seven_enc.len(), 4 + 7 * 74);
    assert!(decode_bundle(&seven_enc, 6).is_none());
    assert!(decode_bundle(&seven_enc, 7).is_some());
    // Malformed: short header, bad magic, version 0 / 2, count-length mismatch, trailing byte.
    assert!(decode_bundle(&[], 6).is_none());
    assert!(decode_bundle(&[b'Y', b'A', 1], 6).is_none());
    for (i, b) in [(1usize, b'B'), (2, 0), (2, 2), (3, 5)] {
        let mut x = six.clone();
        x[i] = b;
        assert!(decode_bundle(&x, 6).is_none(), "byte {i} = {b}");
    }
    assert!(decode_bundle(&six[..six.len() - 1], 6).is_none());
    let mut x = six.clone();
    x.push(0);
    assert!(decode_bundle(&x, 6).is_none());
    assert!(decode_bundle(&[b'Y', b'A', 1, 1], 6).is_none());
    // The encoder's count field stops at 255.
    let many = Bundle::of(vec![f.a(0); 300]);
    let e = encode_bundle(&many);
    assert_eq!(e[3], 255);
    assert_eq!(e.len(), 4 + 255 * 74);
}

#[test]
fn extract_positions_and_modes() {
    let f = Fixture::new();
    let bundle = enc(&[f.a(0), f.a(1)]);
    let ss = BundleCarrier::ScriptSig;
    // Carrier at vin[0].
    {
        let tx = tx_with(vec![carrier(&bundle), plain_in(0)]);
        let (b, src) = extract_bundle(&tx, ss, false, &[]).unwrap();
        assert_eq!(b, bundle);
        assert_eq!(src, BundleSource::ScriptSig);
        assert_eq!(carrier_input(&tx, false), Ok(0));
    }
    // Carrier at vin[2].
    {
        let tx = tx_with(vec![
            plain_in(0),
            plain_in(1),
            carrier(&bundle),
            plain_in(2),
        ]);
        assert_eq!(extract_bundle(&tx, ss, false, &[]).unwrap().0, bundle);
        assert_eq!(carrier_input(&tx, false), Ok(2));
        assert_eq!(carrier_input(&tx, true), Ok(2));
    }
    // Two carriers.
    {
        let tx = tx_with(vec![
            carrier(&bundle),
            plain_in(0),
            carrier_in(&bundle, None, 1),
        ]);
        assert_eq!(
            ex_reason(extract_bundle(&tx, ss, false, &[])),
            "two-carriers"
        );
        assert_eq!(carrier_input(&tx, false), Err(CarrierError::TwoCarriers));
        // ... but with vin[0] skipped there is exactly one.
        assert_eq!(carrier_input(&tx, true), Ok(2));
        assert!(extract_bundle(&tx, ss, true, &[]).is_ok());
        assert_eq!(f.reason(&tx), "two-carriers");
        assert_eq!(
            reason_of(f.verify_with(&tx, BundleCarrier::Either, false, &[], None)),
            "two-carriers"
        );
    }
    // A REDEEM whose vin[0] looks like a carrier: with skip_vin0 the vault input is never considered.
    {
        let tx = tx_with(vec![carrier(&bundle), plain_in(0)]);
        assert_eq!(ex_reason(extract_bundle(&tx, ss, true, &[])), "shape");
        assert_eq!(carrier_input(&tx, true), Err(CarrierError::Shape));
        let tx2 = tx_with(vec![carrier(&bundle), carrier_in(&bundle, None, 1)]);
        assert!(extract_bundle(&tx2, ss, true, &[]).is_ok());
        assert_eq!(carrier_input(&tx2, true), Ok(1));
    }
    // No carrier at all, or no inputs.
    assert_eq!(
        ex_reason(extract_bundle(&tx_with(vec![plain_in(0)]), ss, false, &[])),
        "shape"
    );
    assert_eq!(
        ex_reason(extract_bundle(&tx_with(vec![]), ss, false, &[])),
        "shape"
    );
    assert_eq!(
        ex_reason(extract_bundle(&tx_with(vec![]), ss, true, &[])),
        "shape"
    );
    // Hash mismatch: the redeem script commits to something else (the malleation case, R2).
    {
        let mut other = sha256(&bundle);
        other.0[0] ^= 1;
        let tx = tx_with(vec![plain_in(0), carrier_in(&bundle, Some(other), 0)]);
        assert_eq!(carrier_input(&tx, false), Ok(1)); // shape is fine
        assert_eq!(ex_reason(extract_bundle(&tx, ss, false, &[])), "hash");
        assert_eq!(f.reason(&tx), "hash");
    }
    // OP_RETURN mode reads the tail and ignores carriers; SCRIPTSIG ignores the tail.
    {
        let carrier_tx = tx_with(vec![carrier(&bundle)]);
        let plain_tx = tx_with(vec![plain_in(0)]);
        let op = BundleCarrier::OpReturn;
        let (b, src) = extract_bundle(&plain_tx, op, false, &bundle).unwrap();
        assert_eq!(b, bundle);
        assert_eq!(src, BundleSource::OpReturn);
        assert_eq!(
            ex_reason(extract_bundle(&plain_tx, op, false, &[])),
            "shape"
        );
        assert_eq!(
            extract_bundle(&carrier_tx, op, false, &bundle).unwrap().1,
            BundleSource::OpReturn
        );
        assert_eq!(
            ex_reason(extract_bundle(&plain_tx, ss, false, &bundle)),
            "shape"
        );
        // EITHER: exactly one of the two.
        let either = BundleCarrier::Either;
        assert_eq!(
            extract_bundle(&carrier_tx, either, false, &[]).unwrap().1,
            BundleSource::ScriptSig
        );
        assert_eq!(
            extract_bundle(&plain_tx, either, false, &bundle).unwrap().1,
            BundleSource::OpReturn
        );
        assert_eq!(
            ex_reason(extract_bundle(&carrier_tx, either, false, &bundle)),
            "shape"
        );
        assert_eq!(
            ex_reason(extract_bundle(&plain_tx, either, false, &[])),
            "shape"
        );
        // The extractor does not decode: garbage rides through, VerifyBundle calls it "shape".
        let junk = [1u8, 2, 3];
        assert!(extract_bundle(&tx_with(vec![carrier(&junk)]), ss, false, &[]).is_ok());
        assert_eq!(f.reason(&tx_with(vec![carrier(&junk)])), "shape");
        assert_eq!(
            reason_of(f.verify_with(&plain_tx, op, false, &junk, None)),
            "shape"
        );
    }
}

#[test]
fn verify_order_every_reason() {
    let f = Fixture::new();
    let tx = |b: &[u8]| tx_with(vec![carrier(b)]);
    // The happy path: all six, every seq selected, R = 1003.
    {
        let c = f
            .verify(&tx_with(vec![plain_in(0), carrier(&enc(f.atts()))]))
            .unwrap();
        assert_eq!(c, f.atts());
        assert!(f
            .verify_with(
                &tx_with(vec![plain_in(0)]),
                BundleCarrier::OpReturn,
                false,
                &enc(f.atts()),
                None
            )
            .is_ok());
        assert!(f
            .verify_with(
                &tx_with(vec![plain_in(0), carrier(&enc(f.atts()))]),
                BundleCarrier::Either,
                false,
                &[],
                None
            )
            .is_ok());
        // Exactly mSelect is enough.
        assert!(f.verify(&tx(&enc(&[f.a(0), f.a(1)]))).is_ok());
    }
    // shape: no carrier.
    assert_eq!(f.reason(&tx_with(vec![plain_in(0)])), "shape");
    // shape: a carrier whose bundle is malformed even though it hashes right.
    {
        let mut b = enc(f.atts());
        b[2] = 2;
        assert_eq!(f.reason(&tx(&b)), "shape");
        let mut b = enc(f.atts());
        b.push(0);
        assert_eq!(f.reason(&tx(&b)), "shape");
    }
    // hash, before anything about the content.
    {
        let mut other = sha256(&enc(f.atts()));
        other.0[0] ^= 1;
        assert_eq!(
            f.reason(&tx_with(vec![carrier_in(&enc(f.atts()), Some(other), 0)])),
            "hash"
        );
        // Even a malformed bundle with a wrong hash is "hash": hash precedes decoding.
        assert_eq!(
            f.reason(&tx_with(vec![carrier_in(&[9], Some(other), 0)])),
            "hash"
        );
    }
    // count: below mSelect, zero, above bundleMax.
    assert_eq!(f.reason(&tx(&enc(&[f.a(0)]))), "count");
    assert_eq!(f.reason(&tx(&enc(&[]))), "count");
    {
        let mut seven = f.atts().to_vec();
        seven.push(f.a(0)); // also a dup; count comes first
        assert_eq!(f.reason(&tx(&enc(&seven))), "count");
    }
    // member: seq 5 not selected; precedes dup, stale, sig.
    {
        let mut g = Fixture::new();
        g.selected = vec![0, 1, 2, 3, 4];
        assert_eq!(g.reason(&tx(&enc(&[g.a(0), g.a(1), g.a(5)]))), "member");
        // checks run per attestation in order: the dup of 0 comes before 5
        assert_eq!(g.reason(&tx(&enc(&[g.a(0), g.a(0), g.a(5)]))), "dup");
        assert_eq!(g.reason(&tx(&enc(&[g.a(5), g.a(0), g.a(0)]))), "member");
        let mut s = g.a(5);
        s.sig[5] ^= 1;
        assert_eq!(g.reason(&tx(&enc(&[g.a(0), g.a(1), s]))), "member");
        g.selected = vec![];
        assert_eq!(g.reason(&tx(&enc(&[g.a(0), g.a(1)]))), "member");
    }
    // dup: the same seq twice (two different attestations of one attestor, both valid).
    assert_eq!(f.reason(&tx(&enc(&[f.a(0), f.v.extra[0]]))), "dup");
    assert!(f.verify(&tx(&enc(&[f.a(1), f.v.extra[0]]))).is_ok());
    assert_eq!(f.reason(&tx(&enc(&[f.a(0), f.a(1), f.a(0)]))), "dup");
    // stale: citedHeight > R, <= R - attestMaxAge, < startHeight. Precedes range and sig.
    {
        let mut g = Fixture::new();
        g.r = 1002; // atts[4], [5] cite 1003
        assert_eq!(g.reason(&tx(&enc(&[g.a(0), g.a(4)]))), "stale");
        g.r = 1003;
        g.limits.attest_max_age = 3; // (1000, 1003]
        assert_eq!(g.reason(&tx(&enc(&[g.a(2), g.a(0)]))), "stale");
        assert!(g.verify(&tx(&enc(&[g.a(2), g.a(4)]))).is_ok());
        g.limits.attest_max_age = 8;
        g.limits.start_height = 1001;
        assert_eq!(g.reason(&tx(&enc(&[g.a(2), g.a(0)]))), "stale");
        g.limits.start_height = 1000;
        let mut a = g.a(0);
        a.cited_height = 990;
        a.price_micro_usd = 1;
        assert_eq!(g.reason(&tx(&enc(&[g.a(1), a]))), "stale"); // stale before range
        let mut b = g.a(0);
        b.cited_height = 990;
        assert_eq!(g.reason(&tx(&enc(&[g.a(1), b]))), "stale"); // before sig
    }
    // range: price below priceMin / above priceMax.
    {
        let mut a = f.a(0);
        a.price_micro_usd = u32::try_from(PRICE_MIN - 1).unwrap();
        assert_eq!(f.reason(&tx(&enc(&[f.a(1), a]))), "range");
        // D-Q-22: PRICE_MAX is u32::MAX, so the u32 field cannot exceed it.
        assert_eq!(PRICE_MAX, i64::from(u32::MAX));
        a.price_micro_usd = u32::MAX;
        assert_ne!(f.reason(&tx(&enc(&[f.a(1), a]))), "range");
        let mut g = Fixture::new();
        g.limits.price_min = 100_001; // atts[0] is at 100000
        assert_eq!(g.reason(&tx(&enc(&[g.a(1), g.a(0)]))), "range");
        g.limits.price_min = PRICE_MIN;
        g.limits.price_max = 100_999; // atts[1] is at 101000
        assert_eq!(g.reason(&tx(&enc(&[g.a(0), g.a(1)]))), "range");
    }
    // sig: a flipped bit, a tampered price, an unknown key, an unknown or reorged block hash.
    {
        let mut a = f.a(0);
        a.sig[10] ^= 1;
        assert_eq!(f.reason(&tx(&enc(&[f.a(1), a]))), "sig");
        let mut a = f.a(0);
        a.price_micro_usd += 1;
        assert_eq!(f.reason(&tx(&enc(&[f.a(1), a]))), "sig");
        assert_eq!(f.reason(&tx(&enc(&[f.a(1), f.a(2), a]))), "sig");
        let mut g = Fixture::new();
        g.keys.remove(&2);
        assert_eq!(g.reason(&tx(&enc(&[g.a(0), g.a(2)]))), "sig");
        let mut h = Fixture::new();
        h.block_hashes.remove(&1001);
        assert_eq!(h.reason(&tx(&enc(&[h.a(0), h.a(2)]))), "sig");
        let mut k = Fixture::new();
        k.block_hashes.get_mut(&1001).unwrap().0[0] ^= 1;
        assert_eq!(k.reason(&tx(&enc(&[k.a(0), k.a(2)]))), "sig");
        // Absent callbacks are "sig", never a crash.
        let r = verify_bundle(
            &tx(&enc(&[f.a(0), f.a(1)])),
            BundleCarrier::ScriptSig,
            false,
            &[],
            f.r,
            &f.selected,
            &f.limits,
            None,
            None,
            None,
        );
        assert_eq!(reason_of(r), "sig");
    }
    // A failed verdict carries no attestations (an Err).
    assert!(f.verify(&tx(&enc(&[f.a(0)]))).is_err());
}

#[test]
fn sig_cache_contract() {
    let f = Fixture::new();
    let cache = RecordingCache::default();
    let tx = tx_with(vec![carrier(&enc(f.atts()))]);
    let ss = BundleCarrier::ScriptSig;
    // Cold: six lookups miss, six inserts, all valid.
    assert!(f.verify_with(&tx, ss, false, &[], Some(&cache)).is_ok());
    assert_eq!(cache.lookups(), 6);
    assert_eq!(cache.inserts(), 6);
    assert_eq!(cache.len(), 6);
    assert!(cache.entries.lock().unwrap().values().all(|v| *v));
    // Keys are SHA256(attestation74 || blockHash(citedHeight) || pubkey33).
    for a in f.atts() {
        let bh = f.block_hashes[&i64::from(a.cited_height)];
        let pk = f.keys[&a.seq];
        let mut pre = encode_attestation(a).to_vec();
        pre.extend_from_slice(&bh.0);
        pre.extend_from_slice(&pk.0);
        assert_eq!(
            sig_cache_key(a, &bh, &pk),
            Hash32(Sha256::digest(&pre).into())
        );
        assert!(cache.get(&sig_cache_key(a, &bh, &pk)).is_some());
    }
    // Warm: no verification, no insert, same verdict.
    assert!(f.verify_with(&tx, ss, false, &[], Some(&cache)).is_ok());
    assert_eq!(cache.inserts(), 6);
    assert_eq!(cache.hits(), 6);
    // Without a key for a seq there is no cache line to hit: "sig", nothing inserted.
    let mut no_keys = Fixture::new();
    no_keys.keys.clear();
    assert_eq!(
        reason_of(no_keys.verify_with(&tx, ss, false, &[], Some(&cache))),
        "sig"
    );
    assert_eq!(cache.inserts(), 6);
    // A negative entry is honoured too, and a cold negative is inserted as false.
    let mut bad = f.a(0);
    bad.sig[0] ^= 1;
    let bad_tx = tx_with(vec![carrier(&enc(&[bad, f.a(1)]))]);
    assert_eq!(
        reason_of(f.verify_with(&bad_tx, ss, false, &[], Some(&cache))),
        "sig"
    );
    assert_eq!(cache.inserts(), 7);
    assert_eq!(
        cache.get(&sig_cache_key(
            &bad,
            &f.block_hashes[&1000],
            &f.keys[&bad.seq]
        )),
        Some(false)
    );
    assert_eq!(
        reason_of(f.verify_with(&bad_tx, ss, false, &[], Some(&cache))),
        "sig"
    );
    assert_eq!(cache.inserts(), 7);
    // The key binds the block hash: a reorged hash is a fresh cache line, not a stale hit.
    let mut k = Fixture::new();
    k.block_hashes.get_mut(&1000).unwrap().0[0] ^= 1;
    assert_eq!(
        reason_of(k.verify_with(&tx, ss, false, &[], Some(&cache))),
        "sig"
    );
    assert_eq!(cache.inserts(), 8);
    // The cache is behind the cheap checks: a "count" failure touches it not at all.
    let before = cache.lookups();
    let one = tx_with(vec![carrier(&enc(&[f.a(0)]))]);
    assert_eq!(
        reason_of(f.verify_with(&one, ss, false, &[], Some(&cache))),
        "count"
    );
    assert_eq!(cache.lookups(), before);
}

fn w(ws: &[u64]) -> Vec<U256> {
    ws.iter().map(|x| U256::from_u64(*x)).collect()
}

#[test]
fn bundle_stat() {
    let f = Fixture::new();
    let atts = f.atts();
    // Prices by seq: 0 100000, 1 101000, 2 99500, 3 100500, 4 100000, 5 102000.
    let r = stat(atts, &w(&[1, 1, 1, 1, 1, 1]), 2, 3333, 6667);
    assert_eq!(r, (Some(100_000), Some(101_000)));
    // Undefined below mSelect, on a weights-length mismatch, on empty input, on a bad quantile.
    assert!(stat(atts, &w(&[1, 1, 1, 1, 1, 1]), 7, 3333, 6667)
        .0
        .is_none());
    assert!(stat(atts, &w(&[1, 1]), 2, 3333, 6667).0.is_none());
    assert!(stat(&[], &[], 0, 3333, 6667).0.is_none());
    assert!(stat(atts, &w(&[1, 1, 1, 1, 1, 1]), 2, -1, 6667).0.is_none());
    assert!(stat(atts, &w(&[1, 1, 1, 1, 1, 1]), 2, 3333, 10_001)
        .1
        .is_none());
    // Weighted: one heavy attestor drags the quantile.
    assert_eq!(
        stat(atts, &w(&[1, 1, 100, 1, 1, 1]), 2, 3333, 6667),
        (Some(99_500), Some(99_500))
    );
    // Boundary: cumulative weight exactly at the threshold counts.
    let two = [f.a(2), f.a(1)]; // 99500, 101000
    assert_eq!(
        stat(&two, &w(&[1, 2]), 2, 3333, 3334),
        (Some(99_500), Some(101_000))
    );
    assert_eq!(
        stat(&two, &w(&[1, 1]), 2, 5000, 5001),
        (Some(99_500), Some(101_000))
    );
    // 0 and 10000 bps: the minimum and the maximum.
    assert_eq!(
        stat(atts, &w(&[3, 1, 4, 1, 5, 9]), 2, 0, 10_000),
        (Some(99_500), Some(102_000))
    );
    // Ties in price sort by seq and share the bucket.
    let tie = [f.a(4), f.a(0)];
    assert_eq!(stat(&tie, &w(&[1, 1]), 2, 5000, 10_000).0, Some(100_000));
    // All-zero weights: threshold 0, the lowest price for both.
    assert_eq!(
        stat(&two, &w(&[0, 0]), 2, 3333, 6667),
        (Some(99_500), Some(99_500))
    );
    // Large weights (bondZat * AGE_CAP ~ 4e17 each) do not overflow.
    let big = U256::from_u64(2_000_000_000_000).wrapping_mul(U256::from_u64(207_360));
    assert_eq!(
        stat(atts, &[big; 6], 2, 3333, 6667),
        (Some(100_000), Some(101_000))
    );
}

#[test]
fn cancel_cosign_codecs() {
    let secret = [0x61u8; 32];
    let (set_id, txid, bh) = (u256s("0x5e7"), u256s("0xc1a1"), u256s("0xb10c"));
    let msg = cancel_cosign_message(&set_id, &txid, 2, 950, 50_000, &bh);
    // "YedCancelCosign" | setId | txid | n | citedHeight | price | blockHash, hashed twice.
    let mut pre = b"YedCancelCosign".to_vec();
    pre.extend_from_slice(&set_id.0);
    pre.extend_from_slice(&txid.0);
    for v in [2u32, 950, 50_000] {
        pre.extend_from_slice(&v.to_le_bytes());
    }
    pre.extend_from_slice(&bh.0);
    assert_eq!(pre.len(), 123);
    assert_eq!(msg, Hash32(Sha256::digest(Sha256::digest(&pre)).into()));
    let sig = kogany_vault::act::sign_recoverable(&secret, &msg).unwrap();
    let e = CancelCosignEntry {
        price_micro_usd: 50_000,
        sig,
    };
    let entries = vec![e; 7];
    let blob = encode_cancel_cosigns(&entries).unwrap();
    assert_eq!(blob.len(), 4 + 69 * 7);
    assert!(blob.len() <= 520); // one carrier push
    assert_eq!(decode_cancel_cosigns(&blob).unwrap(), entries);
    assert!(encode_cancel_cosigns(&[]).is_none());
    assert!(encode_cancel_cosigns(&[e; 8]).is_none());
    let mut bad = blob.clone();
    bad.pop();
    assert!(decode_cancel_cosigns(&bad).is_none()); // length
    let mut bad = blob.clone();
    bad[3] = 0;
    assert!(decode_cancel_cosigns(&bad).is_none()); // count 0
    let mut bad = blob.clone();
    bad[2] = 2;
    assert!(decode_cancel_cosigns(&bad).is_none()); // version
    let mut bad = blob.clone();
    bad[1] = b'A';
    assert!(decode_cancel_cosigns(&bad).is_none()); // a price bundle's magic
                                                    // "YX": an attestation and a statement.
    let a = Attestation {
        seq: 4,
        price_micro_usd: 9000,
        cited_height: 950,
        sig: [7u8; 64],
    };
    let st = CancelStatement {
        intent: OutPoint { txid, n: 2 },
        price_micro_usd: 50_000,
        sig,
    };
    let ev = encode_cancel_evidence(&a, &st);
    assert_eq!(ev.len(), CANCEL_EVIDENCE_SIZE);
    assert_eq!(ev.len(), 182);
    assert_eq!(decode_cancel_evidence(&ev).unwrap(), (a, st));
    let mut bad = ev.clone();
    bad.push(0);
    assert!(decode_cancel_evidence(&bad).is_none());
    assert!(decode_cancel_cosigns(&ev).is_none());
    assert!(decode_bundle(&ev, 255).is_none());
}
