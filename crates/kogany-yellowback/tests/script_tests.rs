// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

//! The script-shape cases of ycash6 `src/test/yellowback_script_tests.cpp` (the C++ test names):
//! `mint3_vault_script_sizes_sigops_and_parse`, `red1_scriptsig_shapes_and_path_detection`,
//! `bundle1_carrier_script_shape_and_parse`, the shape half of `rega1_bond_script_verifies` and
//! `holderkey_pq_holder_recognition`; and `pqchannel_cross_implementation_vectors` from
//! `src/test/pq_channel_tests.cpp` over `yellowback_pq_vectors.json` `scripts`.
//!
//! Not here: the `VerifyScript` halves (`red1_owner_path_verifies`, `red4_claim_path_verifies`,
//! `bundle1_carrier_spend_verifies_and_malleation_fails`, the spend half of
//! `rega1_bond_script_verifies`) need the interpreter and the ZIP-243 sighash (W3-c); the
//! standardness cases (`*_are_standard_under_*`) are relay policy (W6-a);
//! `transaction_builder_extension` is the wallet's; `pq_falcon_mirror_*` compare with the
//! consensus parameters (W2-b / W5-f).

mod common;

use common::{h, key, load_pinned, owner};
use kogany_vault::script::{op::*, tokenize, Builder};
use kogany_vault::template::{hash160, parse_vault};
use kogany_vault::{Hash32, PqOwner, PubKeyBytes};
use kogany_yellowback::codecs::script::op::*;
use kogany_yellowback::codecs::script::*;
use kogany_yellowback::params::{main_params, regtest_params, LOCKTIME_THRESHOLD};
use sha2::{Digest, Sha256};

/// `GetSigOpCount(true)` for the shapes here: one per CHECKSIG / CHECKSIGVERIFY.
fn sigops(script: &[u8]) -> usize {
    tokenize(script)
        .unwrap()
        .iter()
        .filter(|t| t.op == OP_CHECKSIG || t.op == OP_CHECKSIGVERIFY)
        .count()
}

/// A 65-byte uncompressed-shaped key.
fn uncompressed() -> Vec<u8> {
    let mut k = vec![0x04];
    k.extend_from_slice(&[0x11; 64]);
    k
}

fn b() -> Builder {
    Builder::new()
}

/// The v2 vault built opcode by opcode with any key bytes and any CHECKSIG opcode.
fn v2_by_hand(lock: i64, key: &[u8], checksig: u8, claim: i64) -> Vec<u8> {
    b().op(OP_IF)
        .num(lock)
        .op(OP_CHECKLOCKTIMEVERIFY)
        .op(OP_DROP)
        .push(key)
        .op(checksig)
        .op(OP_ELSE)
        .num(claim)
        .op(OP_CHECKLOCKTIMEVERIFY)
        .op(OP_DROP)
        .op(OP_TRUE)
        .op(OP_ENDIF)
        .into_bytes()
}

// Rule: RED-1, MINT-3
#[test]
fn mint3_vault_script_sizes_sigops_and_parse() {
    let pubk = key(1);
    let grace = u32::try_from(main_params().grace).unwrap(); // 34,560
                                                             // 3-byte height pushes: 51 bytes; 4-byte: 53; mixed: 52.
    let sizes: [(u32, u32, usize); 6] = [
        (120000, 120000 + grace, 51),
        (9000000, 9000000 + grace, 53),
        (8388607, 8388607 + grace, 52), // 0x7FFFFF is 3 bytes, +grace is 4
        (17, 18, 47),                   // 2-byte pushes
        (1, 2, 45),                     // OP_1 / OP_2
        (LOCKTIME_THRESHOLD - 2, LOCKTIME_THRESHOLD - 1, 53),
    ];
    for (lock, claim, size) in sizes {
        let vault = v2_vault_script(lock, &pubk, claim).unwrap_or_else(|| panic!("lock {lock}"));
        assert_eq!(vault.len(), size);
        assert_eq!(sigops(&vault), 1); // one CHECKSIG
                                       // Counted through P2SH the way the block sigop limit sees it.
        let spk = p2sh_script(&vault);
        assert_eq!(spk.len(), 23);
        assert_eq!(&spk[..2], &[OP_HASH160, 20]);
        assert_eq!(spk[22], OP_EQUAL);
        assert_eq!(
            sigops(&extract_redeem_script(&claim_script_sig(&vault)).unwrap()),
            1
        );
        // Round trip.
        let parsed = parse_v2_vault_script(&vault).unwrap();
        assert_eq!(
            (parsed.lock_height, parsed.owner, parsed.claim_height),
            (lock, pubk, claim)
        );
        assert_eq!(
            v2_vault_script(parsed.lock_height, &parsed.owner, parsed.claim_height).unwrap(),
            vault
        );
    }
    // The exact opcode layout of the 51-byte script.
    let vault = v2_vault_script(120000, &pubk, 120000 + grace).unwrap();
    assert_eq!(
        vault,
        v2_by_hand(120000, &pubk.0, OP_CHECKSIG, i64::from(120000 + grace))
    );
    assert_eq!(vault[0], OP_IF);
    assert_eq!(vault[1], 0x03);
    assert_eq!(vault[vault.len() - 1], OP_ENDIF);
    assert_eq!(vault[vault.len() - 2], OP_TRUE);
    assert!(!kogany_vault::script::is_push_only(&vault));
    // Invalid arguments give no script.
    assert!(v2_vault_script(0, &pubk, 100).is_none());
    assert!(v2_vault_script(100, &pubk, 100).is_none()); // claim must exceed lock
    assert!(v2_vault_script(100, &pubk, 99).is_none());
    assert!(v2_vault_script(LOCKTIME_THRESHOLD, &pubk, LOCKTIME_THRESHOLD + 1).is_none());
    assert!(v2_vault_script(100, &pubk, LOCKTIME_THRESHOLD).is_none());
    assert!(v2_vault_script(100, &PubKeyBytes([0x04; 33]), 200).is_none());
    assert!(v2_vault_script(100, &PubKeyBytes([0x00; 33]), 200).is_none());

    // Parser rejections: anything but the exact template with minimal numbers.
    let good = vault.clone();
    let claim = i64::from(120000 + grace);
    let rejects = |s: &[u8], what: &str| assert!(parse_v2_vault_script(s).is_none(), "{what}");
    rejects(&[], "empty");
    rejects(&good[..good.len() - 1], "missing ENDIF");
    rejects(&[&good[..], &[OP_DROP]].concat(), "trailing opcode");
    // Non-minimal lock number (4 bytes for 120000).
    let mut s = vec![OP_IF, 0x04, 0xc0, 0xd4, 0x01, 0x00];
    s.extend(
        b().op(OP_CHECKLOCKTIMEVERIFY)
            .op(OP_DROP)
            .push(&pubk.0)
            .op(OP_CHECKSIG)
            .op(OP_ELSE)
            .num(claim)
            .op(OP_CHECKLOCKTIMEVERIFY)
            .op(OP_DROP)
            .op(OP_TRUE)
            .op(OP_ENDIF)
            .into_bytes(),
    );
    rejects(&s, "non-minimal lock push");
    rejects(
        &v2_by_hand(120000, &pubk.0, OP_CHECKSIG, 120000),
        "claim == lock",
    );
    rejects(
        &v2_by_hand(120000, &pubk.0, OP_CHECKSIGVERIFY, claim),
        "CHECKSIGVERIFY",
    );
    rejects(
        &v2_by_hand(120000, &uncompressed(), OP_CHECKSIG, claim),
        "uncompressed key",
    );
    rejects(
        &v2_by_hand(
            i64::from(LOCKTIME_THRESHOLD),
            &pubk.0,
            OP_CHECKSIG,
            i64::from(LOCKTIME_THRESHOLD) + 1,
        ),
        "time-locked",
    );
    rejects(&v2_by_hand(0, &pubk.0, OP_CHECKSIG, 100), "zero lock");
    // The prototype's multisig-shaped vault is not a v2 vault.
    rejects(
        &b().num(120000)
            .op(OP_CHECKLOCKTIMEVERIFY)
            .op(OP_DROP)
            .push(&pubk.0)
            .op(OP_CHECKSIGVERIFY)
            .op(OP_1)
            .push(&pubk.0)
            .op(OP_1)
            .op(OP_CHECKMULTISIG)
            .into_bytes(),
        "v1 vault",
    );
    rejects(&p2pkh_script(&hash160(&pubk.0)), "P2PKH");
    // The C++ ReadHeightPush accepts a non-minimal *push* of a minimal number (0x01 0x05 = 5).
    let mut s = vec![OP_IF, 0x01, 0x05];
    s.extend(
        b().op(OP_CHECKLOCKTIMEVERIFY)
            .op(OP_DROP)
            .push(&pubk.0)
            .op(OP_CHECKSIG)
            .op(OP_ELSE)
            .num(9)
            .op(OP_CHECKLOCKTIMEVERIFY)
            .op(OP_DROP)
            .op(OP_TRUE)
            .op(OP_ENDIF)
            .into_bytes(),
    );
    assert_eq!(
        parse_v2_vault_script(&s).map(|v| (v.lock_height, v.claim_height)),
        Some((5, 9))
    );
}

// Rule: RED-1, RED-4
#[test]
fn red1_scriptsig_shapes_and_path_detection() {
    let vault = v2_vault_script(120000, &key(1), 120000 + 34560).unwrap();
    let sig = vec![0x30u8; 72];
    // Owner: <sig> OP_1 <script>; claim: OP_0 <script>. Both push-only.
    let owner_sig = owner_script_sig(&sig, &vault);
    let claim_sig = claim_script_sig(&vault);
    assert_eq!(owner_sig.len(), 1 + sig.len() + 1 + 1 + vault.len());
    assert_eq!(claim_sig.len(), 1 + 1 + vault.len());
    assert!(kogany_vault::script::is_push_only(&owner_sig));
    assert!(kogany_vault::script::is_push_only(&claim_sig));
    assert_eq!(owner_sig, b().push(&sig).op(OP_1).push(&vault).into_bytes());
    assert_eq!(claim_sig, b().op(OP_0).push(&vault).into_bytes());
    assert_eq!(owner_sig[1 + sig.len()], OP_1);
    assert_eq!(claim_sig[0], OP_0);
    assert_eq!(extract_redeem_script(&owner_sig), Some(vault.clone()));
    assert_eq!(extract_redeem_script(&claim_sig), Some(vault.clone()));

    // Path detection = CastToBool(selector), exactly as OP_IF evaluates it (K4).
    let with = |parts: Builder| parts.push(&vault).into_bytes();
    let mut truncated = claim_sig.clone();
    truncated.truncate(truncated.len() - 5);
    // (name, scriptSig, present, ownerPath, pushes, hasSig)
    type Case<'a> = (&'a str, Vec<u8>, bool, bool, usize, bool);
    let cases: Vec<Case> = vec![
        ("owner", owner_sig.clone(), true, true, 3, true),
        ("claim", claim_sig.clone(), true, false, 2, false),
        (
            "owner_op2",
            with(b().push(&sig).op(OP_2)),
            true,
            true,
            3,
            true,
        ),
        (
            "owner_op16",
            with(b().push(&sig).op(OP_16)),
            true,
            true,
            3,
            true,
        ),
        (
            "owner_1negate",
            with(b().push(&sig).op(OP_1NEGATE)),
            true,
            true,
            3,
            true,
        ),
        (
            "owner_nonminimal_1",
            {
                let mut s = b().push(&sig).into_bytes();
                s.extend([0x01, 0x01]);
                s.extend(b().push(&vault).into_bytes());
                s
            },
            true,
            true,
            3,
            true,
        ),
        (
            "owner_two_byte_true",
            with(b().push(&sig).push(&[0x00, 0x01])),
            true,
            true,
            3,
            true,
        ),
        (
            "claim_negative_zero",
            with(b().push(&sig).push(&[0x80])),
            true,
            false,
            3,
            true,
        ),
        (
            "claim_zero_byte",
            with(b().push(&sig).push(&[0x00])),
            true,
            false,
            3,
            true,
        ),
        (
            "claim_two_zero_bytes",
            with(b().push(&[0x00, 0x00])),
            true,
            false,
            2,
            false,
        ),
        (
            "claim_neg_zero_long",
            with(b().push(&[0x00, 0x80])),
            true,
            false,
            2,
            false,
        ),
        (
            "claim_with_sig",
            with(b().push(&sig).op(OP_0)),
            true,
            false,
            3,
            true,
        ),
        (
            "claim_extra_op0",
            with(b().op(OP_0).op(OP_0)),
            true,
            false,
            3,
            false,
        ),
        (
            "four_pushes",
            with(b().push(&sig).push(&sig).op(OP_1)),
            true,
            true,
            4,
            true,
        ),
        (
            "one_push",
            b().push(&vault).into_bytes(),
            false,
            false,
            0,
            false,
        ),
        ("empty", vec![], false, false, 0, false),
        (
            "not_push_only",
            b().op(OP_1).push(&vault).op(OP_DROP).into_bytes(),
            false,
            false,
            0,
            false,
        ),
        (
            "opcode_in_middle",
            with(b().push(&sig).op(OP_DUP)),
            false,
            false,
            0,
            false,
        ),
        ("truncated_push", truncated, false, false, 0, false),
    ];
    for (name, script_sig, present, owner_path, pushes, has_sig) in cases {
        let path = parse_vault_spend_path(&script_sig);
        assert_eq!(path.is_some(), present, "{name}: presence");
        let Some(path) = path else { continue };
        assert_eq!(path.owner_path, owner_path, "{name}: path");
        assert_eq!(path.pushes, pushes, "{name}: pushes");
        assert_eq!(!path.owner_sig.is_empty(), has_sig, "{name}: sig");
        assert_eq!(path.vault_script, vault, "{name}: script");
    }
    // The selector of OP_N is the number itself, of OP_0 the empty vector.
    assert_eq!(
        parse_vault_spend_path(&owner_sig).unwrap().selector,
        vec![0x01]
    );
    assert_eq!(
        parse_vault_spend_path(&with(b().push(&sig).op(OP_16)))
            .unwrap()
            .selector,
        vec![0x10]
    );
    assert_eq!(
        parse_vault_spend_path(&with(b().push(&sig).op(OP_1NEGATE)))
            .unwrap()
            .selector,
        vec![0x81]
    );
    assert!(parse_vault_spend_path(&claim_sig)
        .unwrap()
        .selector
        .is_empty());
    assert_eq!(parse_vault_spend_path(&owner_sig).unwrap().owner_sig, sig);
    // The last push need not be a vault script for the path to be read.
    assert!(parse_vault_spend_path(&b().op(OP_1).push(&[9; 3]).into_bytes()).is_some());
}

// Rule: BUNDLE-1
#[test]
fn bundle1_carrier_script_shape_and_parse() {
    let pubk = key(2);
    let bundle = vec![0xABu8; 448];
    let hsh = Hash32(Sha256::digest(&bundle).into());
    let carrier = carrier_script(&pubk, &hsh).unwrap();
    assert_eq!(carrier.len(), 71); // 1 + 1 + (1 + 32) + 1 + (1 + 33) + 1
    assert_eq!(carrier.len(), CARRIER_SCRIPT_SIZE);
    assert_eq!(
        carrier,
        b().op(OP_SWAP)
            .op(OP_SHA256)
            .push(&hsh.0)
            .op(OP_EQUALVERIFY)
            .push(&pubk.0)
            .op(OP_CHECKSIG)
            .into_bytes()
    );
    assert_eq!(
        (
            carrier[0],
            carrier[1],
            carrier[2],
            carrier[35],
            carrier[36],
            carrier[70]
        ),
        (OP_SWAP, OP_SHA256, 32, OP_EQUALVERIFY, 33, OP_CHECKSIG)
    );
    assert_eq!(sigops(&carrier), 1);
    let spk = p2sh_script(&carrier);
    assert_eq!(spk.len(), 23);
    let sig71 = vec![0x30u8; 71];
    let script_sig = carrier_script_sig(&bundle, &sig71, &carrier);
    assert!(kogany_vault::script::is_push_only(&script_sig));
    assert_eq!(script_sig.len(), 3 + 448 + 1 + 71 + 1 + 71); // PUSHDATA2 for 448
    assert!(script_sig.len() <= 1650); // policy's scriptSig ceiling

    assert_eq!(is_carrier_script(&carrier), Some((pubk, hsh)));
    let spend = parse_carrier_script_sig(&script_sig).unwrap();
    assert_eq!(spend.bundle, bundle);
    assert_eq!(spend.sig, sig71);
    assert_eq!(spend.pk, pubk);
    assert_eq!(spend.bundle_hash, hsh);
    assert_eq!(spend.carrier_script, carrier);

    // Not carriers.
    assert!(carrier_script(&PubKeyBytes([0x04; 33]), &hsh).is_none());
    assert!(carrier_script(&PubKeyBytes([0x00; 33]), &hsh).is_none());
    assert!(is_carrier_script(&[]).is_none());
    let shaped = |o1: u8, o2: u8, o3: u8, o4: u8| {
        b().op(o1)
            .op(o2)
            .push(&hsh.0)
            .op(o3)
            .push(&pubk.0)
            .op(o4)
            .into_bytes()
    };
    assert!(is_carrier_script(&shaped(OP_DROP, OP_SHA256, OP_EQUALVERIFY, OP_CHECKSIG)).is_none());
    assert!(is_carrier_script(&shaped(OP_SWAP, OP_HASH256, OP_EQUALVERIFY, OP_CHECKSIG)).is_none());
    assert!(is_carrier_script(&shaped(OP_SWAP, OP_SHA256, OP_EQUAL, OP_CHECKSIG)).is_none());
    assert!(is_carrier_script(&shaped(
        OP_SWAP,
        OP_SHA256,
        OP_EQUALVERIFY,
        OP_CHECKSIGVERIFY
    ))
    .is_none());
    assert!(is_carrier_script(&[&carrier[..], &[OP_NOP]].concat()).is_none());
    assert!(is_carrier_script(&carrier[..70]).is_none());
    let v2 = v2_vault_script(120000, &pubk, 130000).unwrap();
    assert!(is_carrier_script(&v2).is_none());
    assert!(is_carrier_script(&bond_script(&pubk, 120000).unwrap()).is_none());
    assert!(is_carrier_script(&p2pkh_script(&hash160(&pubk.0))).is_none());
    // A 33-byte 02/03 prefix that is not a curve point is still carrier-shaped (IsCompressedKey).
    let mut off_curve = pubk;
    off_curve.0[1..].fill(0xff);
    assert!(carrier_script(&off_curve, &hsh).is_some());
    // Not carrier scriptSigs.
    assert!(parse_carrier_script_sig(&b().push(&bundle).push(&carrier).into_bytes()).is_none());
    assert!(parse_carrier_script_sig(
        &b().push(&bundle)
            .push(&sig71)
            .push(&[1])
            .push(&carrier)
            .into_bytes()
    )
    .is_none());
    assert!(parse_carrier_script_sig(
        &b().push(&bundle)
            .push(&sig71)
            .push(&carrier)
            .op(OP_NOP)
            .into_bytes()
    )
    .is_none());
    assert!(
        parse_carrier_script_sig(&b().push(&bundle).op(OP_DUP).push(&carrier).into_bytes())
            .is_none()
    );
    assert!(parse_carrier_script_sig(
        &b().push(&bundle)
            .push(&sig71)
            .push(&[0x51; 71])
            .into_bytes()
    )
    .is_none());
    assert!(
        parse_carrier_script_sig(&b().op(OP_1).push(&sig71).push(&carrier).into_bytes()).is_none()
    );
    assert!(parse_carrier_script_sig(&owner_script_sig(&sig71, &v2)).is_none());
    assert!(parse_carrier_script_sig(&claim_script_sig(&v2)).is_none());
    assert!(parse_carrier_script_sig(&[]).is_none());
    // An empty bundle push (OP_0) is still carrier-shaped.
    assert!(parse_carrier_script_sig(&carrier_script_sig(&[], &sig71, &carrier)).is_some());

    // FindCarrierInput (BUNDLE-1's "shape" / "two-carriers").
    let other = claim_script_sig(&v2);
    assert_eq!(
        find_carrier_input(&[other.clone(), script_sig.clone()], false),
        Ok(1)
    );
    assert_eq!(
        find_carrier_input(&[script_sig.clone(), other.clone()], true),
        Err(CarrierError::Shape)
    );
    assert_eq!(
        find_carrier_input(&[script_sig.clone(), script_sig.clone()], true),
        Ok(1)
    );
    assert_eq!(
        find_carrier_input(&[script_sig.clone(), script_sig.clone()], false),
        Err(CarrierError::TwoCarriers)
    );
    assert_eq!(
        find_carrier_input::<Vec<u8>>(&[], false),
        Err(CarrierError::Shape)
    );
    assert_eq!(CarrierError::Shape.reason(), "shape");
    assert_eq!(CarrierError::TwoCarriers.reason(), "two-carriers");
}

// Rule: REG-A1 (the script shape; the spend half needs the interpreter, W3-c)
#[test]
fn rega1_bond_script_verifies() {
    let locktime = 420480 + 1000;
    let pubk = key(3);
    let bond = bond_script(&pubk, locktime).unwrap();
    assert_eq!(
        bond,
        b().num(i64::from(locktime))
            .op(OP_CHECKLOCKTIMEVERIFY)
            .op(OP_DROP)
            .push(&pubk.0)
            .op(OP_CHECKSIG)
            .into_bytes()
    );
    assert_eq!(bond.len(), 41); // 3-byte height push
    assert_eq!(bond_script(&pubk, 5).unwrap().len(), 38); // OP_5
    assert_eq!(sigops(&bond), 1);
    assert_eq!(parse_bond_script(&bond), Some((pubk, locktime)));
    assert!(bond_script(&pubk, 0).is_none());
    assert!(bond_script(&pubk, LOCKTIME_THRESHOLD).is_none());
    assert!(bond_script(&PubKeyBytes([0x04; 33]), locktime).is_none());
    assert!(parse_bond_script(&[]).is_none());
    assert!(parse_bond_script(&v2_vault_script(locktime, &pubk, locktime + 10).unwrap()).is_none());
    assert!(parse_bond_script(&carrier_script(&pubk, &Hash32::ZERO).unwrap()).is_none());
    assert!(parse_bond_script(&[&bond[..], &[OP_NOP]].concat()).is_none());
    assert!(parse_bond_script(
        &b().num(i64::from(locktime))
            .op(OP_CHECKLOCKTIMEVERIFY)
            .op(OP_DROP)
            .push(&pubk.0)
            .op(OP_CHECKSIGVERIFY)
            .into_bytes()
    )
    .is_none());
    // Non-minimal 4-byte push of the height.
    let mut s = vec![0x04, 0x78, 0x6e, 0x06, 0x00];
    s.extend(
        b().op(OP_CHECKLOCKTIMEVERIFY)
            .op(OP_DROP)
            .push(&pubk.0)
            .op(OP_CHECKSIG)
            .into_bytes(),
    );
    assert!(parse_bond_script(&s).is_none());
    // The bond is the vault primitive's B shape for the canonical bytes.
    assert_eq!(
        kogany_vault::template::build_bond_redeem(locktime, &pubk),
        Some(bond)
    );
}

// Rule: TOK-PQ
#[test]
fn holderkey_pq_holder_recognition() {
    let key_id = hash160(&key(4).0);
    let hsh = Hash32([0x3c; 32]);
    let slh = PqOwner {
        scheme: 1,
        hash: hsh,
    };
    let falcon = PqOwner {
        scheme: 2,
        hash: hsh,
    };
    let p2pkh = p2pkh_script(&key_id);
    let slh_spk = pq_key_script(&slh).unwrap();
    let falcon_spk = pq_key_script(&falcon).unwrap();
    assert_eq!(slh_spk.len(), 35);
    assert_eq!(
        hex::encode(&slh_spk),
        format!("20{}51c2", hex::encode(hsh.0))
    );
    assert_eq!(
        hex::encode(&falcon_spk),
        format!("20{}52c2", hex::encode(hsh.0))
    );
    assert_eq!(holder_key(&p2pkh), Some(Holder::KeyId(key_id)));
    assert_eq!(holder_key(&slh_spk), Some(Holder::Pq(slh)));
    assert_eq!(holder_key(&falcon_spk), Some(Holder::Pq(falcon)));
    assert!(pq_key_script(&PqOwner {
        scheme: 3,
        hash: hsh
    })
    .is_none());
    assert!(pq_key_script(&PqOwner {
        scheme: 0,
        hash: hsh
    })
    .is_none());
    // Not holders.
    let others: Vec<Vec<u8>> = vec![
        b().push(&hsh.0)
            .push(&[0x01])
            .op(OP_CHECKPQSIG)
            .into_bytes(), // the scheme pushed as data
        b().push(&hsh.0).op(OP_3).op(OP_CHECKPQSIG).into_bytes(), // an unregistered scheme
        b().push(&hsh.0).op(OP_1).op(OP_CHECKSIG).into_bytes(),   // the wrong opcode
        [&slh_spk[..], &[OP_NOP]].concat(),                       // a trailing byte
        slh_spk[..34].to_vec(),                                   // truncated
        p2sh_script(&p2pkh),                                      // P2SH
        b().op(OP_RETURN).push(&[0; 4]).into_bytes(),
        vec![],
    ];
    for s in &others {
        assert_eq!(holder_key(s), None, "{}", hex::encode(s));
    }

    // TOK-PQ: the module's mirror of the consensus Falcon height decides.
    let mut p = regtest_params(1, 0, 0, [0x5e; 32]);
    assert_eq!(p.pq_falcon_height, -1); // never, by default
    for s in [&p2pkh, &slh_spk, &falcon_spk, &others[0], &vec![]] {
        assert!(holder_allowed(&p, 1000000, s));
    }
    p.pq_falcon_height = 100;
    for s in [&p2pkh, &slh_spk, &falcon_spk, &others[0], &vec![]] {
        assert!(holder_allowed(&p, 99, s));
    }
    assert!(holder_allowed(&p, 100, &falcon_spk));
    assert!(holder_allowed(&p, 1000000, &falcon_spk));
    for s in [
        &p2pkh,
        &slh_spk,
        &others[0],
        &others[1],
        &others[3],
        &others[5],
        &vec![],
    ] {
        assert!(!holder_allowed(&p, 100, s));
    }
    p.pq_falcon_height = 0; // -pqfalcon=1
    assert!(!holder_allowed(&p, 0, &p2pkh));
    assert!(holder_allowed(&p, 0, &falcon_spk));

    // A channel's YED is its client's (D-Q-19): allowed iff the client is Falcon.
    let server = key(5);
    for (client, allowed) in [(falcon, true), (slh, false)] {
        let c = PqChannelParams {
            client,
            server,
            refund_height: 1000,
        };
        let spk = pq_channel_script(&c).unwrap();
        assert_eq!(match_pq_channel(&spk), Some(c));
        assert_eq!(holder_key(&spk), Some(Holder::Pq(client)));
        assert_eq!(holder_allowed(&p, 0, &spk), allowed);
    }
}

/// `PQChannelParams` builder and matcher edges (standard.cpp `GetScriptForPQChannel` /
/// `MatchPQChannel`).
#[test]
fn pqchannel_builder_and_matcher_edges() {
    let client = owner(2, 0x77);
    let server = key(6);
    let c = |refund_height| PqChannelParams {
        client,
        server,
        refund_height,
    };
    for r in [
        1i64,
        16,
        17,
        127,
        128,
        0x7fff,
        0x8000,
        0x7fffff,
        0x800000,
        i64::from(LOCKTIME_THRESHOLD) - 1,
    ] {
        let s = pq_channel_script(&c(r)).unwrap();
        assert!(
            (112..=117).contains(&s.len()),
            "refund {r}: {} bytes",
            s.len()
        );
        assert_eq!(match_pq_channel(&s), Some(c(r)));
    }
    assert!(pq_channel_script(&c(0)).is_none());
    assert!(pq_channel_script(&c(i64::from(LOCKTIME_THRESHOLD))).is_none());
    assert!(pq_channel_script(&PqChannelParams {
        client: owner(3, 1),
        server,
        refund_height: 5
    })
    .is_none());
    let mut off = server;
    off.0[1..].fill(0xff); // x = 2^256 - 1 >= p: not on the curve
    assert!(pq_channel_script(&PqChannelParams {
        client,
        server: off,
        refund_height: 5
    })
    .is_none());
    // A non-minimal refund push is not the rebuilt script.
    let s = pq_channel_script(&c(1000)).unwrap();
    let t = tokenize(&s).unwrap();
    assert_eq!(t[8].data, &[0xe8, 0x03]);
    let mut nonmin = s.clone();
    let at = s
        .windows(4)
        .position(|w| w == [0x02, 0xe8, 0x03, OP_CHECKLOCKTIMEVERIFY])
        .unwrap();
    nonmin.splice(at..at + 3, [0x03, 0xe8, 0x03, 0x00]);
    assert!(match_pq_channel(&nonmin).is_none());
    // Different client slots.
    let mut two = s.clone();
    let last_hash = s.len() - 1 - 2 - 32;
    two[last_hash] ^= 1;
    assert!(match_pq_channel(&two).is_none());
}

/// `pqchannel_cross_implementation_vectors` (ycash6 `src/test/pq_channel_tests.cpp`):
/// `yellowback_pq_vectors.json` `scripts` (364 rows, the Python model's verdicts). `type` is
/// Solver's class (TX_PQCHANNEL / TX_PQPKH / other) and `holder` is `HolderKey`'s CPQKeyID as
/// `scheme || hash` hex, `""` for none or a P2PKH.
#[test]
fn pqchannel_cross_implementation_vectors() {
    let v = load_pinned("yellowback_pq_vectors.json");
    let rows = v["scripts"].as_array().unwrap();
    assert_eq!(rows.len(), 364);
    let mut channels = 0;
    for r in rows {
        let name = r["name"].as_str().unwrap();
        let spk = h(r["hex"].as_str().unwrap());
        let got = if match_pq_channel(&spk).is_some() {
            "pqchannel"
        } else if matches!(holder_key(&spk), Some(Holder::Pq(_))) {
            "pqpubkeyhash"
        } else {
            "other"
        };
        assert_eq!(got, r["type"].as_str().unwrap(), "{name}: type");
        let holder = match holder_key(&spk) {
            Some(Holder::Pq(o)) => format!("{:02x}{}", o.scheme, hex::encode(o.hash.0)),
            _ => String::new(),
        };
        assert_eq!(holder, r["holder"].as_str().unwrap(), "{name}: holder");
        if got == "pqchannel" {
            channels += 1;
        }
    }
    assert!(channels > 50);
}

/// The YED vault V (U-23, IT-1): the primitive's template with the module's fields.
#[test]
fn yed_vault_is_the_primitive_v() {
    let set = [0xe7u8; 32];
    let p = regtest_params(1, 0, 0, set);
    let o = owner(2, 0x42);
    let v = yed_vault_params(&p, &o, 950);
    assert_eq!(v.tag, YED_TAG);
    assert_eq!(YED_TAG.0, *b"YED\0");
    assert_eq!((v.set_id, v.cancel_set_id), (Hash32(set), Hash32(set)));
    assert_eq!(v.delay, i64::from(p.claim_delay));
    assert_eq!((v.owner_height, v.app_height), (951, 951));
    assert_eq!(v.owner, o);
    let s = yed_vault_script(&p, &o, 950).unwrap();
    assert_eq!(parse_vault(&s), Some(v));
    assert_eq!(Some(s.clone()), yed_vault_script_at(&p, &o, 951, 951));
    // A pre-IT-1 record's heights.
    let at = yed_vault_params_at(&p, &o, 1000, 1000 + i64::from(p.grace));
    assert_eq!(
        parse_vault(&yed_vault_script_at(&p, &o, 1000, 1000 + i64::from(p.grace)).unwrap()),
        Some(at)
    );
    // No attestor set, no vault; an unregistered owner scheme is out of range.
    assert!(yed_vault_script(&regtest_params(1, 0, 0, [0; 32]), &o, 950).is_none());
    assert!(yed_vault_script(&p, &owner(7, 1), 950).is_none());
    // OwnerFromBytes.
    let mut ob = vec![2u8];
    ob.extend_from_slice(&[0x42; 32]);
    assert_eq!(owner_from_bytes(&ob), o);
    assert_eq!(owner_from_bytes(&ob[..32]), PqOwner::default());
    assert_eq!(
        owner_from_bytes(&[&ob[..], &[0]].concat()),
        PqOwner::default()
    );
}
