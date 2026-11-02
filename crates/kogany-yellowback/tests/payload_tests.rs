// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

//! ycash6 `src/test/yellowback_payload_tests.cpp`, case for case (the test names are the C++
//! ones): the v3 payload codec with the v4 MINT (quantum spec §3.1, C-1), round trips, the
//! fixed-width little-endian layout, every malformed case, the feeVout semantics, the
//! attestation types and the transaction-level rules of `FindPayload`.
//!
//! The C++ "wrong version byte in a `Payload` struct is not encodable" cases are unrepresentable
//! here (the version is derived from the type); the C++ "uncompressed / empty CPubKey is not
//! encodable" cases are unrepresentable too (the keys are 33-byte arrays).

mod common;

use common::{h, key, owner, uint256_display};
use kogany_vault::{Hash32, OutPoint, PubKeyBytes};
use kogany_yellowback::codecs::payload::*;
use kogany_yellowback::params::{FEE_VOUT_NONE, MINT_PAYLOAD_VERSION, PAYLOAD_VERSION};

/// A fixed syntactically valid compressed key, so hex vectors are reproducible.
const KEYHEX: &str = "02cb81cc0269783ebd9e6484b5495343036874a407856f230a8ee0384986759e70";
/// A fixed post-quantum owner, scheme 0x01 || 32 key-hash bytes.
const OWNERHEX: &str = "01cb81cc0269783ebd9e6484b5495343036874a407856f230a8ee0384986759e70";
/// A second key for the bond key of ATTESTOR_REGISTER.
const KEY2HEX: &str = "03a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90";

fn test_sig(seed: u8) -> [u8; COMPACT_SIG_SIZE] {
    let mut s = [0u8; COMPACT_SIG_SIZE];
    for (i, b) in s.iter_mut().enumerate() {
        *b = seed.wrapping_add(i as u8);
    }
    s
}

fn pk(hexs: &str) -> PubKeyBytes {
    PubKeyBytes::from_slice(&h(hexs)).unwrap()
}

fn transfer(a: &[(u8, u32)]) -> Payload {
    Payload::Transfer(a.iter().map(|&(v, c)| Assignment::new(v, c)).collect())
}

fn assigns(a: &[(u8, u32)]) -> Vec<Assignment> {
    a.iter().map(|&(v, c)| Assignment::new(v, c)).collect()
}

fn register(a: PubKeyBytes, b: PubKeyBytes, locktime: u32, flags: u8) -> Payload {
    Payload::AttestorRegister(AttestorRegister {
        attestor_key: a,
        bond_key: b,
        bond_locktime: locktime,
        flags,
    })
}

fn notice(txid: Hash32, vout: u8, ref_height: u32) -> Payload {
    Payload::ClaimNotice(ClaimNotice {
        vault_txid: txid,
        vault_vout: vout,
        ref_height,
    })
}

fn revive(seq: u16, price: u32, cited: u32, sig: [u8; 64]) -> Payload {
    Payload::AttestorRevive(AttestorRevive {
        seq,
        price_micro_usd: price,
        cited_height: cited,
        sig,
    })
}

/// `TxWithOutputs`: `n` outputs of `OP_TRUE`, the one at `idx` replaced by `opret`.
fn tx_with_outputs(n: usize, opret: Vec<u8>, idx: usize) -> Vec<Vec<u8>> {
    let mut v = vec![vec![0x51u8]; n];
    v[idx] = opret;
    v
}

fn enc(p: &Payload) -> Vec<u8> {
    encode_payload(p).unwrap_or_else(|| panic!("encodable: {p:?}"))
}

// Rule: MINT-1, XFER-1, RED-1
#[test]
fn mint1_roundtrip_table() {
    let (o, b) = (key(1), key(2));
    let pq_owner = owner(0x01, 0x11);
    let falcon_owner = owner(0x02, 0x22);
    let unknown_scheme = owner(0x07, 0x33);
    let thirteen: Vec<(u8, u32)> = (0..13u8).map(|i| (i, 100 + u32::from(i))).collect();
    let fifteen: Vec<(u8, u32)> = (0..15u8).map(|i| (i, 100 + u32::from(i))).collect();
    let vault = uint256_display("1122334455667788990011223344556677889900112233445566778899001122");
    let cases: Vec<(Payload, usize)> = vec![
        (
            Payload::mint(0, 10000, 1000, 950, &pq_owner, 3, FEE_VOUT_NONE),
            52,
        ), // attestFeeVout none (AFEE-0)
        (Payload::mint(0, 10000, 1000, 950, &pq_owner, 3, 4), 52),
        (
            Payload::mint(
                2,
                1000000,
                0xFFFFFFFF,
                0,
                &falcon_owner,
                FEE_VOUT_NONE,
                FEE_VOUT_NONE,
            ),
            52,
        ),
        (
            Payload::mint(0xFF, 0, 0, 0xFFFFFFFF, &unknown_scheme, 0, 0),
            52,
        ), // the codec fixes the shape only
        (transfer(&[]), 5),
        (transfer(&[(1, 100)]), 10),
        (transfer(&[(0, 100), (1, 200), (3, 0xFFFFFFFF)]), 20),
        (transfer(&fifteen), 80), // the maximum, 80 bytes exactly
        (Payload::redeem(950, 2, vec![], FEE_VOUT_NONE), 11), // count = 0 allowed (§3.5)
        (Payload::redeem(950, 2, vec![], 3), 11),
        (
            Payload::redeem(950, FEE_VOUT_NONE, assigns(&[(2, 12345)]), 5),
            16,
        ),
        (Payload::redeem(0xFFFFFFFF, 0, assigns(&thirteen), 1), 76), // the maximum count (13)
        (register(o, b, 420480, 0), 75),
        (register(b, o, 0xFFFFFFFF, 0xFF), 75),
        (notice(vault, 1, 950), 41),
        (
            Payload::ClaimNotice(ClaimNotice::from_outpoint(
                &OutPoint { txid: vault, n: 2 },
                0xFFFFFFFF,
            )),
            41,
        ),
        (notice(Hash32::ZERO, 0, 0), 41),
        (Payload::Equivocation, 4),
        (Payload::CancelCosign, 4),
        (revive(0, 0, 0, test_sig(0)), 78),
        (revive(0xFFFF, 0xFFFFFFFF, 0xFFFFFFFF, test_sig(0x80)), 78),
    ];
    for (p, size) in &cases {
        let e = enc(p);
        assert_eq!(e.len(), *size, "{p:?}");
        assert_eq!(e[0], 0x59);
        assert_eq!(e[1], 0x42);
        // C-1: the MINT alone is version 4; every other type stays version 3.
        let mint = p.payload_type() == PayloadType::Mint;
        assert_eq!(
            e[2],
            if mint {
                MINT_PAYLOAD_VERSION
            } else {
                PAYLOAD_VERSION
            }
        );
        assert_eq!(e[2], if mint { 0x04 } else { 0x03 });
        assert_eq!(e[2], p.payload_type().version());
        assert_eq!(e[2], p.version());
        assert_eq!(e[3], p.payload_type().byte());
        let d = decode_payload(&e).unwrap_or_else(|| panic!("decodes: {p:?}"));
        assert_eq!(&d, p);
        assert_eq!(d.version(), p.payload_type().version());
        if let (Payload::Mint(a), Payload::Mint(b)) = (&d, p) {
            assert_eq!(a.owner(), b.owner());
        }
        assert_eq!(d.assigned_cents(), p.assigned_cents());
        assert_eq!(enc(&d), e);
    }
    // The owner accessor reads scheme || hash back.
    let Payload::Mint(m) = Payload::mint(0, 1, 1, 1, &falcon_owner, 0, 0) else {
        unreachable!()
    };
    assert_eq!(m.owner(), falcon_owner);
    // Sums fit int64: 15 x 2^32.
    let big: Vec<(u8, u32)> = (0..15u8).map(|i| (i, 0xFFFFFFFF)).collect();
    assert_eq!(transfer(&big).assigned_cents(), 15 * 0xFFFFFFFFi64);
    // The CLAIM_NOTICE outpoint accessor and the outpoint factory agree.
    let n = ClaimNotice::from_outpoint(&OutPoint { txid: vault, n: 2 }, 7);
    assert_eq!(n.vault_outpoint(), OutPoint { txid: vault, n: 2 });
    assert_eq!(Payload::ClaimNotice(n), notice(vault, 2, 7));
}

// Rule: MINT-1, RED-1
#[test]
fn mint1_fixed_width_little_endian_layout() {
    let (o, b) = (pk(KEYHEX), pk(KEY2HEX));
    // v4 MINT: offset 17 ownerScheme, 18..49 ownerHash (internal bytes, as pushed in V), 50
    // feeVout, 51 attestFeeVout; 52 bytes.
    let ob = h(OWNERHEX);
    let pq_owner = kogany_yellowback::codecs::script::owner_from_bytes(&ob);
    let e = enc(&Payload::mint(
        2, 0x01020304, 0x0A0B0C0D, 0x11223344, &pq_owner, 0x03, 0x04,
    ));
    assert_eq!(e.len(), 52);
    assert_eq!(
        hex::encode(&e),
        format!("5942040102040302010d0c0b0a44332211{OWNERHEX}0304")
    );
    assert_eq!(e[17], 0x01);
    assert_eq!(&e[18..50], &pq_owner.hash.0);
    assert_eq!(e[50], 0x03);
    assert_eq!(e[51], 0x04);
    let e = enc(&Payload::mint(
        2,
        0x01020304,
        0x0A0B0C0D,
        0x11223344,
        &pq_owner,
        0x03,
        FEE_VOUT_NONE,
    ));
    assert_eq!(
        hex::encode(&e),
        format!("5942040102040302010d0c0b0a44332211{OWNERHEX}03ff")
    );
    assert_eq!(
        hex::encode(enc(&transfer(&[(3, 0x0100)]))),
        "59420302010300010000"
    );
    assert_eq!(
        hex::encode(enc(&Payload::redeem(
            0x11223344,
            0xFF,
            assigns(&[(2, 0x0100)]),
            0x05
        ))),
        "5942030344332211ff05010200010000"
    );
    assert_eq!(
        hex::encode(enc(&Payload::redeem(7, 1, vec![], FEE_VOUT_NONE))),
        "594203030700000001ff00"
    );
    let e = enc(&register(o, b, 0x00066a80, 0x01));
    assert_eq!(e.len(), 75);
    assert_eq!(
        hex::encode(&e),
        format!("59420305{KEYHEX}{KEY2HEX}806a060001")
    );
    // The txid is the uint256's internal byte order, not the displayed reversed hex (R13).
    let vault = uint256_display("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff");
    let e = enc(&notice(vault, 0x02, 0x11223344));
    assert_eq!(e.len(), 41);
    assert_eq!(
        hex::encode(&e),
        "59420306ffeeddccbbaa99887766554433221100ffeeddccbbaa998877665544332211000244332211"
    );
    assert_eq!(
        hex::encode(&e),
        format!("59420306{}0244332211", hex::encode(vault.0))
    );
    assert_eq!(hex::encode(enc(&Payload::Equivocation)), "59420307");
    let sig = test_sig(0);
    let e = enc(&revive(0x0102, 0x0000c350, 0x000003b6, sig));
    assert_eq!(e.len(), 78);
    assert_eq!(
        hex::encode(&e),
        format!("59420308020150c30000b6030000{}", hex::encode(sig))
    );
}

// Rule: MINT-1, XFER-1, RED-1
#[test]
fn mint1_malformed_table() {
    let mint_body = format!("0010270000e8030000b6030000{OWNERHEX}ffff"); // 48 bytes
    let sig_hex = "1".repeat(128);
    let txid_hex = "a".repeat(64);
    let o2 = &OWNERHEX[2..];
    let k2 = &KEYHEX[2..];
    let mb = &mint_body;
    let mb_short = &mint_body[..mint_body.len() - 2];
    let cases: Vec<(&str, String, bool)> = vec![
        ("mint_ok", format!("59420401{mb}"), true), // C-1: MINT is version 4
        ("bad_magic_0", format!("58420301{mb}"), false),
        ("bad_magic_1", format!("59430301{mb}"), false),
        ("version_0", format!("59420001{mb}"), false),
        ("version_1", format!("59420101{mb}"), false),
        ("version_2", format!("59420201{mb}"), false), // V23: the v2 header, even over a v3 body
        ("version_2_v2_body", format!("59420201{mb_short}"), false), // a real v2 MINT (51 bytes)
        ("mint_version_3", format!("59420301{mb}"), false), // C-1: a v3 MINT is non-Yellowback
        (
            "mint_version_3_ec",
            format!("594203010010270000e8030000b6030000{KEYHEX}ffff"),
            false,
        ), // the v3 EC-owner MINT
        ("version_5", format!("59420501{mb}"), false),
        ("transfer_version_4", "5942040200".into(), false), // C-1: every other type stays version 3
        ("redeem_version_4", "59420403b6030000ffff00".into(), false),
        (
            "notice_version_4",
            format!("59420406{txid_hex}01b6030000"),
            false,
        ),
        ("equivocation_version_4", "59420407".into(), false),
        ("version_ff", format!("5942ff01{mb}"), false),
        ("unknown_type_04", "5942030401000000".into(), false),
        ("cancel_cosign", "59420309".into(), true), // CAN-2: the empty-bodied marker
        ("cancel_cosign_trailing", "5942030900".into(), false),
        ("cancel_cosign_version_4", "59420409".into(), false),
        ("unknown_type_0a", "5942030a".into(), false),
        ("retired_type_10", "5942031050c3000000000000".into(), false), // the prototype's PRICE
        ("reserved_type_1f", "5942031f00".into(), false),
        ("reserved_type_20", "5942032000".into(), false),
        ("reserved_type_ff", "594203ff00".into(), false),
        ("type_00", "5942030000".into(), false),
        ("empty", "".into(), false),
        ("one_byte", "59".into(), false),
        ("header_only", "594203".into(), false),
        ("header_no_body", "59420401".into(), false),
        ("mint_short_by_one", format!("59420401{mb_short}"), false), // the v2 length
        (
            "mint_no_feevout",
            format!("594204010010270000e8030000b6030000{OWNERHEX}"),
            false,
        ), // the v1 length
        ("mint_trailing", format!("59420401{mb}00"), false),
        // Any 33 bytes decode as the owner, whatever the scheme byte.
        (
            "mint_scheme_02",
            format!("594204010010270000e8030000b603000002{o2}ffff"),
            true,
        ),
        (
            "mint_scheme_00",
            format!("594204010010270000e8030000b603000000{o2}ffff"),
            true,
        ),
        (
            "mint_scheme_03",
            format!("594204010010270000e8030000b603000003{o2}ffff"),
            true,
        ),
        (
            "mint_ec_key_bytes",
            format!("594204010010270000e8030000b6030000{KEYHEX}ffff"),
            true,
        ),
        ("transfer_empty", "5942030200".into(), true),
        ("transfer_short", "594203020101640000".into(), false),
        (
            "transfer_long",
            "59420302010164000000".to_owned() + "00",
            false,
        ),
        ("transfer_count_short", "59420302020164000000".into(), false),
        ("transfer_zero_cents", "59420302010100000000".into(), false),
        (
            "transfer_dup_vout",
            "5942030202016400000001640000".to_owned() + "00",
            false,
        ),
        (
            "transfer_two",
            "594203020201640000000264000000".into(),
            true,
        ),
        ("transfer_trailing", "594203020000".into(), false),
        ("redeem_empty", "59420303b6030000ffff00".into(), true),
        (
            "redeem_one",
            "59420303b603000003040101393000".to_owned() + "00",
            true,
        ),
        ("redeem_v2_head", "59420303b6030000ff00".into(), false), // no attestFeeVout: the v2 head
        ("redeem_head_short", "59420303b6030000ffff".into(), false),
        (
            "redeem_short",
            "59420303b6030000ffff0101393000".into(),
            false,
        ),
        ("redeem_trailing", "59420303b6030000ffff0000".into(), false),
        (
            "redeem_zero_cents",
            "59420303b6030000ffff010100000000".into(),
            false,
        ),
        (
            "redeem_dup_vout",
            "59420303b6030000ffff0201640000000164000000".into(),
            false,
        ),
        // ATTESTOR_REGISTER (75): any 33 + 33 bytes decode (REG-A1 judges the keys).
        (
            "register_ok",
            format!("59420305{KEYHEX}{KEY2HEX}806a060000"),
            true,
        ),
        (
            "register_key_04",
            format!("5942030504{k2}{KEY2HEX}806a060000"),
            true,
        ),
        (
            "register_short",
            format!("59420305{KEYHEX}{KEY2HEX}806a0600"),
            false,
        ),
        (
            "register_trailing",
            format!("59420305{KEYHEX}{KEY2HEX}806a06000000"),
            false,
        ),
        ("register_empty", "59420305".into(), false),
        // CLAIM_NOTICE (41).
        ("notice_ok", format!("59420306{txid_hex}01b6030000"), true),
        ("notice_short", format!("59420306{txid_hex}01b60300"), false),
        (
            "notice_trailing",
            format!("59420306{txid_hex}01b603000000"),
            false,
        ),
        ("notice_empty", "59420306".into(), false),
        // EQUIVOCATION (4): the body is empty, a byte is malformed.
        ("equivocation_ok", "59420307".into(), true),
        ("equivocation_byte", "5942030700".into(), false),
        // ATTESTOR_REVIVE (78).
        (
            "revive_ok",
            format!("59420308010050c30000b6030000{sig_hex}"),
            true,
        ),
        (
            "revive_short",
            format!("59420308010050c30000b6030000{}", &sig_hex[..126]),
            false,
        ),
        (
            "revive_trailing",
            format!("59420308010050c30000b6030000{sig_hex}00"),
            false,
        ),
        (
            "revive_no_sig",
            "59420308010050c30000b6030000".into(),
            false,
        ),
    ];
    for (name, hexs, ok) in &cases {
        assert_eq!(decode_payload(&h(hexs)).is_some(), *ok, "{name}");
    }
    // TRANSFER count 16 = 85 bytes: over MAX_PAYLOAD and the count bound; 15 is the maximum.
    let mut sixteen = h("5942030210");
    for i in 0..16u8 {
        sixteen.extend_from_slice(&[i, 1, 0, 0, 0]);
    }
    assert!(decode_payload(&sixteen).is_none());
    let mut fifteen = h("594203020f");
    for i in 0..15u8 {
        fifteen.extend_from_slice(&[i, 1, 0, 0, 0]);
    }
    assert_eq!(fifteen.len(), 80);
    assert_eq!(decode_payload(&fifteen).unwrap().assignments().len(), 15);
    // REDEEM count 14 = 81 bytes: rejected; 13 = 76 bytes is the maximum.
    let mut fourteen = h("59420303b6030000ffff0e");
    for i in 0..14u8 {
        fourteen.extend_from_slice(&[i, 1, 0, 0, 0]);
    }
    assert_eq!(fourteen.len(), 81);
    assert!(decode_payload(&fourteen).is_none());
    let mut thirteen = h("59420303b6030000ffff0d");
    for i in 0..13u8 {
        thirteen.extend_from_slice(&[i, 1, 0, 0, 0]);
    }
    assert_eq!(thirteen.len(), 76);
    assert_eq!(decode_payload(&thirteen).unwrap().assignments().len(), 13);
    assert_eq!(MAX_REDEEM_ASSIGNMENTS, 13);
    // The encoder refuses 14 for REDEEM but accepts 15 for TRANSFER.
    let mut a: Vec<Assignment> = (0..14u8).map(|i| Assignment::new(i, 1)).collect();
    assert!(encode_payload(&Payload::redeem(1, 0xFF, a.clone(), FEE_VOUT_NONE)).is_none());
    a.push(Assignment::new(14, 1));
    assert_eq!(enc(&Payload::Transfer(a)).len(), 80);
    // 81 bytes never decodes, whatever the header.
    let mut long81 = h("59420302");
    long81.resize(81, 0);
    assert!(decode_payload(&long81).is_none());
    // The encoder refuses what the decoder would refuse.
    assert!(encode_payload(&transfer(&[(1, 0)])).is_none());
    assert!(encode_payload(&transfer(&[(1, 1), (1, 2)])).is_none());
    assert!(encode_payload(&Payload::mint(0, 1, 1, 1, &owner(1, 9), 0xFF, 0xFF)).is_some());
    let good = pk(KEYHEX);
    assert!(encode_payload(&register(good, good, 1, 0)).is_some());
}

// Rule: MINT-8, RED-3, AFEE-0, AFEE-1
// feeVout / attestFeeVout: 0xFF = no such fee output; any other value is carried as is. The
// codec does not range-check either (K11), so FindPayload keeps an out-of-range feeVout.
#[test]
fn mint8_feevout_semantics() {
    let o = owner(1, 0x44);
    for fv in [0u8, 3, 0xFE, FEE_VOUT_NONE] {
        let Some(Payload::Mint(m)) = decode_payload(&enc(&Payload::mint(
            0,
            10000,
            1000,
            950,
            &o,
            fv,
            FEE_VOUT_NONE,
        ))) else {
            panic!("mint")
        };
        assert_eq!((m.fee_vout, m.attest_fee_vout), (fv, FEE_VOUT_NONE));
        let Some(Payload::Redeem(r)) =
            decode_payload(&enc(&Payload::redeem(950, fv, vec![], FEE_VOUT_NONE)))
        else {
            panic!("redeem")
        };
        assert_eq!((r.fee_vout, r.attest_fee_vout), (fv, FEE_VOUT_NONE));
        // attestFeeVout is independent of feeVout and round-trips the same way.
        let Some(Payload::Mint(m)) = decode_payload(&enc(&Payload::mint(
            0,
            10000,
            1000,
            950,
            &o,
            FEE_VOUT_NONE,
            fv,
        ))) else {
            panic!("mint")
        };
        assert_eq!((m.fee_vout, m.attest_fee_vout), (FEE_VOUT_NONE, fv));
        let Some(Payload::Redeem(r)) =
            decode_payload(&enc(&Payload::redeem(950, 2, assigns(&[(3, 1)]), fv)))
        else {
            panic!("redeem")
        };
        assert_eq!((r.fee_vout, r.attest_fee_vout), (2, fv));
    }
    assert_eq!(FEE_VOUT_NONE, 0xFF);
    // An attestFeeVout of 9 in a 3-output transaction still parses (AFEE-1 rejects it).
    let fp = find_payload(&tx_with_outputs(
        3,
        payload_script(&enc(&Payload::mint(0, 10000, 1000, 950, &o, 1, 9))),
        2,
    ))
    .unwrap();
    let Payload::Mint(m) = fp.payload else {
        panic!()
    };
    assert_eq!(m.attest_fee_vout, 9);
    // A MINT with feeVout = 9 in a 3-output transaction still parses (the rule rejects it).
    let fp = find_payload(&tx_with_outputs(
        3,
        payload_script(&enc(&Payload::mint(
            0,
            10000,
            1000,
            950,
            &o,
            9,
            FEE_VOUT_NONE,
        ))),
        2,
    ))
    .unwrap();
    let Payload::Mint(m) = fp.payload else {
        panic!()
    };
    assert_eq!(m.fee_vout, 9);
    assert_eq!(fp.op_return_index, 2);
}

/// `CScript() << OP_RETURN` followed by raw bytes.
fn opret(rest: &[u8]) -> Vec<u8> {
    let mut v = vec![0x6a];
    v.extend_from_slice(rest);
    v
}

/// `CScript() << data` (a minimal push).
fn push(data: &[u8]) -> Vec<u8> {
    kogany_vault::script::Builder::new().push(data).into_bytes()
}

// Rule: TX-0
#[test]
fn tx0_opreturn_shape() {
    let data = enc(&transfer(&[(1, 100)]));
    // Exactly OP_RETURN <push>.
    assert_eq!(
        extract_op_return_data(&payload_script(&data)),
        Some(&data[..])
    );
    // Not OP_RETURN.
    assert!(extract_op_return_data(&push(&data)).is_none());
    assert!(extract_op_return_data(&[]).is_none());
    assert!(extract_op_return_data(&[0x6a]).is_none());
    // Two pushes.
    assert!(extract_op_return_data(&opret(&[push(&data), push(&data)].concat())).is_none());
    // OP_N is not a data push.
    assert!(extract_op_return_data(&[0x6a, 0x51]).is_none());
    assert!(extract_op_return_data(&[0x6a, 0x00]).is_none());
    // Trailing opcode.
    assert!(extract_op_return_data(&opret(&[push(&data), vec![0x75]].concat())).is_none());
    // Length bounds on the push: 3 and 81 out; 4 and 80 in (decoding is separate).
    assert!(extract_op_return_data(&opret(&push(&[1; 3]))).is_none());
    assert!(extract_op_return_data(&opret(&push(&[1; 81]))).is_none());
    assert!(extract_op_return_data(&opret(&push(&[1; 4]))).is_some());
    assert!(extract_op_return_data(&opret(&push(&[1; 80]))).is_some());
    // A non-minimal push (OP_PUSHDATA1 for 10 bytes) is still one push of the bytes.
    let mut s = vec![0x6a, 0x4c, data.len() as u8];
    s.extend_from_slice(&data);
    assert_eq!(extract_op_return_data(&s), Some(&data[..]));
    // Truncated PUSHDATA.
    assert!(extract_op_return_data(&[0x6a, 0x4c, 50, 1]).is_none());
}

// Rule: TX-0, XFER-1
#[test]
fn tx0_find_payload_in_transaction() {
    let o = key(3);
    let pq_owner = owner(1, 0x55);
    let mint = payload_script(&enc(&Payload::mint(
        0,
        10000,
        1000,
        950,
        &pq_owner,
        3,
        FEE_VOUT_NONE,
    )));
    let xfer = payload_script(&enc(&transfer(&[(0, 100), (2, 200)])));

    // Found, with its index.
    let fp = find_payload(&tx_with_outputs(4, mint.clone(), 2)).unwrap();
    assert_eq!(fp.op_return_index, 2);
    assert_eq!(fp.payload.payload_type(), PayloadType::Mint);
    assert_eq!(fp.payload.ref_height(), Some(950));
    // No OP_RETURN.
    let none = tx_with_outputs(2, vec![0x51], 0);
    assert!(find_payload(&none).is_none());
    assert!(find_op_return(&none).is_none());
    // Two OP_RETURNs: non-Yellowback even if one is a good payload.
    let mut two = tx_with_outputs(4, mint.clone(), 2);
    two[3] = opret(&push(&[0; 4]));
    assert!(find_payload(&two).is_none());
    assert!(find_op_return(&two).is_none());
    // A bare OP_RETURN counts as the OP_RETURN output but carries no payload.
    let bare = tx_with_outputs(2, vec![0x6a], 1);
    assert_eq!(find_op_return(&bare), Some(1));
    assert!(find_payload(&bare).is_none());
    // Assigned vout beyond the outputs.
    assert!(find_payload(&tx_with_outputs(2, xfer.clone(), 1)).is_none());
    // Assigned vout is the OP_RETURN itself.
    assert!(find_payload(&tx_with_outputs(3, xfer.clone(), 2)).is_none());
    assert!(find_payload(&tx_with_outputs(4, xfer.clone(), 3)).is_some());
    // A REDEEM with count = 0 has no assignments to check.
    let fp = find_payload(&tx_with_outputs(
        2,
        payload_script(&enc(&Payload::redeem(1, 0xFF, vec![], FEE_VOUT_NONE))),
        1,
    ))
    .unwrap();
    assert_eq!(fp.payload.payload_type(), PayloadType::Redeem);
    assert!(fp.payload.assignments().is_empty());
    // An unknown-type payload is ignored at the transaction level too (V23).
    assert!(find_payload(&tx_with_outputs(
        2,
        payload_script(&h("5942030400000000")),
        1
    ))
    .is_none());
    // The attestation types have no assignments: FindPayload keeps them whatever the outputs.
    let fp = find_payload(&tx_with_outputs(
        1,
        payload_script(&enc(&Payload::Equivocation)),
        0,
    ))
    .unwrap();
    assert_eq!(fp.payload.payload_type(), PayloadType::Equivocation);
    let one = uint256_display(&format!("{:064x}", 1));
    let fp = find_payload(&tx_with_outputs(
        2,
        payload_script(&enc(&notice(one, 200, 950))),
        1,
    ))
    .unwrap();
    let Payload::ClaimNotice(n) = fp.payload else {
        panic!()
    };
    assert_eq!(n.vault_vout, 200); // a vault outpoint index, not one of this transaction's vouts
    assert_eq!(n.ref_height, 950);
    let fp = find_payload(&tx_with_outputs(
        2,
        payload_script(&enc(&register(o, o, 5, 0))),
        1,
    ))
    .unwrap();
    let Payload::AttestorRegister(g) = fp.payload else {
        panic!()
    };
    assert_eq!((g.attestor_key, g.bond_key), (o, o));
    let fp = find_payload(&tx_with_outputs(
        2,
        payload_script(&enc(&revive(3, 50000, 949, test_sig(9)))),
        1,
    ))
    .unwrap();
    assert_eq!(fp.payload, revive(3, 50000, 949, test_sig(9)));
    let names = [
        (PayloadType::Mint, "mint"),
        (PayloadType::Transfer, "transfer"),
        (PayloadType::Redeem, "redeem"),
        (PayloadType::AttestorRegister, "register"),
        (PayloadType::ClaimNotice, "notice"),
        (PayloadType::Equivocation, "equivocation"),
        (PayloadType::AttestorRevive, "revive"),
        (PayloadType::CancelCosign, "cancelcosign"),
    ];
    for (t, n) in names {
        assert_eq!(t.name(), n);
        assert_eq!(PayloadType::from_byte(t.byte()), Some(t));
    }
    for b in [0x00u8, 0x04, 0x0a, 0x10, 0x1f, 0x20, 0xff] {
        assert_eq!(PayloadType::from_byte(b), None, "{b:#x} is reserved");
    }
}

// V23: version 1 (the prototype's layout) and version 2 (the v2 codec) are non-Yellowback.
// Rule: MINT-1, XFER-1, RED-1
#[test]
fn version1_is_non_yellowback() {
    assert!(decode_payload(&h(&format!("594201010010270000e8030000b6030000{KEYHEX}"))).is_none());
    assert!(decode_payload(&h("5942011050c3000000000000")).is_none());
    assert!(decode_payload(&h("59420103010139300000")).is_none());
    assert!(decode_payload(&h("5942031050c3000000000000")).is_none()); // 0x10 under v3: reserved
}

// Rule: MINT-1, XFER-1, RED-1
#[test]
fn version2_is_non_yellowback() {
    // The exact v2 encodings, each well-formed under the v2 codec.
    assert!(decode_payload(&h(&format!("5942020102040302010d0c0b0a44332211{KEYHEX}03"))).is_none()); // v2 MINT
    assert!(decode_payload(&h("59420202010300010000")).is_none()); // v2 TRANSFER
    assert!(decode_payload(&h("5942020344332211ff010200010000")).is_none()); // v2 REDEEM
    assert!(decode_payload(&h("59420203070000000100")).is_none());
    assert!(decode_payload(&h("5942020200")).is_none()); // a v2 empty TRANSFER
                                                         // The same bodies under version 3: TRANSFER decodes; MINT and REDEEM need the extra byte.
    assert!(decode_payload(&h("59420302010300010000")).is_some());
    assert!(decode_payload(&h(&format!("5942030102040302010d0c0b0a44332211{KEYHEX}03"))).is_none());
    assert!(decode_payload(&h(&format!(
        "5942040102040302010d0c0b0a44332211{OWNERHEX}03"
    )))
    .is_none()); // no attestFeeVout
    assert!(decode_payload(&h("5942030344332211ff010200010000")).is_none());
    // A version-2 payload is ignored at the transaction level too.
    assert!(find_payload(&tx_with_outputs(
        2,
        payload_script(&h("59420202010064000000")),
        1
    ))
    .is_none());
    assert!(find_payload(&tx_with_outputs(
        2,
        payload_script(&h("59420302010064000000")),
        1
    ))
    .is_some());
    assert_eq!(PAYLOAD_VERSION, 3);
    assert_eq!(MINT_PAYLOAD_VERSION, 4);
}

// Rule: REG-A1, NOT-1, EQV-1, REV-1
// The four attestation payloads: field-by-field round trips and the sizes 75 / 41 / 4 / 78.
#[test]
fn attestation_types_roundtrip() {
    let (a, b) = (key(4), key(5));
    let e = enc(&register(a, b, 420480, 0x01));
    assert_eq!(e.len(), 75);
    let Some(Payload::AttestorRegister(g)) = decode_payload(&e) else {
        panic!()
    };
    assert_eq!(
        (g.attestor_key, g.bond_key, g.bond_locktime, g.flags),
        (a, b, 420480, 0x01)
    );
    assert_eq!(enc(&Payload::AttestorRegister(g)), e);
    // Any 33 bytes: the keys are carried verbatim (REG-A1 judges).
    let mut bad = e.clone();
    bad[4] = 0x07;
    let Some(Payload::AttestorRegister(g)) = decode_payload(&bad) else {
        panic!()
    };
    assert!(!g.attestor_key.is_compressed());
    assert_eq!(g.attestor_key.0[0], 0x07);
    assert_eq!(g.bond_key, b);
    assert_eq!(enc(&Payload::AttestorRegister(g)), bad);
    // CLAIM_NOTICE
    let vault = uint256_display("deadbeef00000000000000000000000000000000000000000000000000000001");
    let e = enc(&notice(vault, 3, 12345));
    assert_eq!(e.len(), 41);
    let Some(Payload::ClaimNotice(n)) = decode_payload(&e) else {
        panic!()
    };
    assert_eq!(
        (n.vault_txid, n.vault_vout, n.ref_height),
        (vault, 3, 12345)
    );
    assert_eq!(n.vault_outpoint(), OutPoint { txid: vault, n: 3 });
    assert_eq!(enc(&Payload::ClaimNotice(n)), e);
    // The vout byte is the outpoint index: 0xFF is a value, not "none".
    let Some(Payload::ClaimNotice(n)) = decode_payload(&enc(&notice(vault, 0xFF, 1))) else {
        panic!()
    };
    assert_eq!(n.vault_vout, 0xFF);
    // The outpoint factory truncates n to the byte the payload carries.
    assert_eq!(
        Payload::ClaimNotice(ClaimNotice::from_outpoint(
            &OutPoint {
                txid: vault,
                n: 0x102
            },
            1
        )),
        notice(vault, 0x02, 1)
    );
    // EQUIVOCATION
    let e = enc(&Payload::Equivocation);
    assert_eq!(e.len(), 4);
    assert_eq!(decode_payload(&e), Some(Payload::Equivocation));
    // ATTESTOR_REVIVE
    let e = enc(&revive(7, 50000, 9999, test_sig(0x40)));
    assert_eq!(e.len(), 78);
    assert_eq!(
        decode_payload(&e),
        Some(revive(7, 50000, 9999, test_sig(0x40)))
    );
    // seq is a u16 little-endian: 0x0102 encodes as 02 01.
    let e = enc(&revive(0x0102, 1, 1, test_sig(0)));
    assert_eq!((e[4], e[5]), (0x02, 0x01));
    // Inequality across every field.
    assert_ne!(
        revive(7, 50000, 9999, test_sig(0x40)),
        revive(8, 50000, 9999, test_sig(0x40))
    );
    assert_ne!(
        revive(7, 50000, 9999, test_sig(0x40)),
        revive(7, 50000, 9999, test_sig(0x41))
    );
    assert_ne!(notice(vault, 3, 1), notice(vault, 4, 1));
    assert_ne!(register(a, b, 1, 0), register(b, a, 1, 0));
    assert_ne!(register(a, b, 1, 0), register(a, b, 1, 1));
    assert_ne!(Payload::Equivocation, register(a, b, 1, 0));
}
