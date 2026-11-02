//! Replays `testdata/yellowback/vault_vectors.json` (pinned, byte-identical to ycash6
//! `src/test/data/vault_vectors.json`) against the templates and acts: the Rust face of ycash6
//! `src/test/vault_vectors_tests.cpp`. Key → test map: `testdata/yellowback/CHECKLIST.md`.
#![allow(missing_docs)]

mod common;

use common::*;
use kogany_vault::act::*;
use kogany_vault::script::op;
use kogany_vault::template::*;
use kogany_vault::{Hash32, PqOwner, PubKeyBytes, RecoverableSig};
use secp256k1::ecdsa::{RecoverableSignature, RecoveryId};
use serde_json::Value;

fn vault_of(p: &Value) -> VaultParams {
    VaultParams {
        tag: tag(p, "tag"),
        set_id: h32(p, "setId"),
        cancel_set_id: h32(p, "cancelSetId"),
        delay: int(p, "delay"),
        owner_height: int(p, "ownerHeight"),
        app_height: int(p, "appHeight"),
        owner: owner(&p["owner"]),
    }
}

fn intent_of(p: &Value) -> IntentParams {
    IntentParams {
        tag: tag(p, "tag"),
        recipient_hash: h32(p, "recipientHash"),
        vault_hash: h32(p, "vaultHash"),
        delay: int(p, "delay"),
        cancel_set_id: h32(p, "cancelSetId"),
        set_id: h32(p, "setId"),
        owner: owner(&p["owner"]),
    }
}

#[test]
fn constants() {
    let d = vectors();
    assert_eq!(int(&d, "branchId"), 0x6d5b_7a31);
    let o = &d["opcodes"];
    assert_eq!(
        int(o, "CHECKSEQUENCEVERIFY"),
        i64::from(op::OP_CHECKSEQUENCEVERIFY)
    );
    assert_eq!(int(o, "CHECKSETSIG"), i64::from(op::OP_CHECKSETSIG));
    assert_eq!(int(o, "CHECKSETDORMANT"), i64::from(op::OP_CHECKSETDORMANT));
}

#[test]
fn keys_and_owners() {
    let d = vectors();
    let keys = arr(&d, "keys");
    assert_eq!(keys.len(), 8);
    for k in keys {
        let secret: [u8; 32] = hx(k, "secret").try_into().unwrap();
        assert_eq!(
            public_key(&secret),
            Some(key(k, "pubkey")),
            "{}",
            s(k, "label")
        );
    }
    // The owners are SHA256(scheme || pk) of the vector's PQ keys (KeyGen from the seed is
    // kogany-pq's concern and not vendored, K-8).
    for name in ["pqOwner", "falconOwner"] {
        let o = &d[name];
        let own = owner(&o["owner"]);
        assert_eq!(hx(o, "seed").len(), 48, "{name}");
        assert_eq!(pq_key_hash(own.scheme, &hx(o, "pk")), own.hash, "{name}");
    }
    assert_eq!(
        owner(&d["pqOwner"]["owner"]).scheme,
        PQ_SCHEME_SLH_DSA_SHA2_128S
    );
    assert_eq!(
        owner(&d["falconOwner"]["owner"]).scheme,
        PQ_SCHEME_FN_DSA_512
    );
}

#[test]
fn vault_templates() {
    let d = vectors();
    let ok = arr(&d, "vaults");
    assert_eq!(ok.len(), 12);
    for v in ok {
        let name = s(v, "name");
        let want = vault_of(&v["params"]);
        let spk = hx(v, "script");
        assert_eq!(build_vault(&want), Some(spk.clone()), "build_vault {name}");
        assert_eq!(parse_vault(&spk), Some(want), "parse_vault {name}");
        assert_eq!(match_vault(&spk), Shape::Match(want), "match_vault {name}");
        assert_eq!(parse_intent(&spk), None, "a V is not an I {name}");
        assert_eq!(
            match_intent(&spk),
            Shape::NotTemplate,
            "a V is not I-shaped {name}"
        );
    }
    let bad = arr(&d, "vaultsInvalid");
    assert_eq!(bad.len(), 21);
    for v in bad {
        let name = s(v, "name");
        let spk = hx(v, "script");
        assert_eq!(parse_vault(&spk), None, "parse_vault accepted {name}");
        // A rejected V is either not V-shaped at all or V-shaped and malformed; never a match.
        assert!(!matches!(match_vault(&spk), Shape::Match(_)), "{name}");
    }
    // Out-of-range parameters build nothing (the C++ returns an empty script).
    let mut p = vault_of(&ok[0]["params"]);
    p.delay = 0;
    assert_eq!(build_vault(&p), None);
    p.delay = 144;
    p.owner.scheme = 3;
    assert_eq!(build_vault(&p), None);
}

#[test]
fn vault_invalid_shapes_are_classified() {
    // §15.3: a V-shaped output outside the ranges is Malformed (rule V-1 then rejects it); a
    // different skeleton is NotTemplate. The classes the vector's reasons imply:
    let d = vectors();
    for v in arr(&d, "vaultsInvalid") {
        let name = s(v, "name");
        let got = match_vault(&hx(v, "script"));
        let want_not_template = matches!(
            name,
            "owner-ec-key-checksig" | "trailing-op" | "truncated" | "empty"
        );
        if want_not_template {
            assert_eq!(got, Shape::NotTemplate, "{name}");
        } else {
            assert_eq!(got, Shape::Malformed, "{name}");
        }
    }
}

#[test]
fn intent_templates() {
    let d = vectors();
    let ok = arr(&d, "intents");
    assert_eq!(ok.len(), 4);
    for i in ok {
        let name = s(i, "name");
        let want = intent_of(&i["params"]);
        let spk = hx(i, "script");
        assert_eq!(
            build_intent(&want),
            Some(spk.clone()),
            "build_intent {name}"
        );
        assert_eq!(parse_intent(&spk), Some(want), "parse_intent {name}");
        assert_eq!(parse_vault(&spk), None, "an I is not a V {name}");
        // recipientHash / vaultHash are single SHA256 of the scripts; intent_for reproduces I.
        let vspk = hx(i, "vaultScript");
        let rspk = hx(i, "recipientScript");
        assert_eq!(script_hash256(&rspk), want.recipient_hash, "{name}");
        assert_eq!(script_hash256(&vspk), want.vault_hash, "{name}");
        let vp = parse_vault(&vspk).unwrap();
        assert_eq!(intent_for(&vp, &vspk, &rspk), want, "{name}");
        assert_eq!(
            build_intent(&intent_for(&vp, &vspk, &rspk)),
            Some(spk),
            "{name}"
        );
    }
    let bad = arr(&d, "intentsInvalid");
    assert_eq!(bad.len(), 11);
    for i in bad {
        let spk = hx(i, "script");
        assert_eq!(
            parse_intent(&spk),
            None,
            "parse_intent accepted {}",
            s(i, "name")
        );
        assert!(!matches!(match_intent(&spk), Shape::Match(_)));
    }
}

#[test]
fn bond_templates() {
    let d = vectors();
    let b = arr(&d, "bonds");
    assert_eq!(b.len(), 3);
    for e in b {
        let k = key(e, "memberKey");
        let lt = u32::try_from(int(e, "locktime")).unwrap();
        assert_eq!(build_bond_redeem(lt, &k), Some(hx(e, "redeem")));
        assert_eq!(bond_script_pubkey(lt, &k), Some(hx(e, "spk")));
        assert_eq!(parse_bond_redeem(&hx(e, "redeem")), Some((lt, k)));
    }
    // Out of range or uncompressed: nothing builds, and a non-canonical redeem does not parse.
    let k = key(&b[0], "memberKey");
    assert_eq!(build_bond_redeem(0, &k), None);
    assert_eq!(build_bond_redeem(500_000_000, &k), None);
    let mut k4 = k;
    k4.0[0] = 0x04;
    assert_eq!(build_bond_redeem(16, &k4), None);
    let mut padded = hx(&b[0], "redeem"); // 60 = OP_16; as a data push 01 10 is non-minimal
    padded.splice(0..1, [0x01, 0x10]);
    assert_eq!(parse_bond_redeem(&padded), None);
}

#[test]
fn selectors() {
    let d = vectors();
    // A V and an I to spend: the selector range depends on the kind (V 1..4, I 1..3).
    let vspk = hx(&d["vaults"][0], "script");
    let ispk = hx(&d["intents"][0], "script");
    let ok = arr(&d, "selectors");
    assert_eq!(ok.len(), 7);
    for e in ok {
        let is_v = s(e, "kind") == "V";
        let ts = parse_template_spend(if is_v { &vspk } else { &ispk }, &hx(e, "scriptSig"))
            .unwrap_or_else(|| panic!("selector {}", s(e, "scriptSig")));
        assert_eq!(i64::from(ts.selector), int(e, "selector"));
        assert_eq!(ts.sigs.len(), usize::try_from(int(e, "nArgs")).unwrap());
        assert_eq!(ts.is_vault(), is_v);
    }
    let bad = arr(&d, "selectorsInvalid");
    assert_eq!(bad.len(), 8);
    for e in bad {
        let is_v = s(e, "kind") == "V";
        assert_eq!(
            parse_template_spend(if is_v { &vspk } else { &ispk }, &hx(e, "scriptSig")),
            None,
            "selector accepted: {}",
            s(e, "reason")
        );
    }
    // A non-template coin has no template spend, whatever the scriptSig.
    assert_eq!(
        parse_template_spend(&hx(&d["bonds"][0], "spk"), &[op::OP_1]),
        None
    );
}

#[test]
fn acts() {
    let d = vectors();
    let ok = arr(&d, "acts");
    assert_eq!(ok.len(), 11);
    for a in ok {
        let name = s(a, "name");
        let p = hx(a, "payload");
        let body = decode_payload(&p).unwrap_or_else(|e| panic!("decode_payload {name}: {e:?}"));
        assert_eq!(i64::from(body.act_type()), int(a, "type"), "{name}");
        assert_eq!(encode_payload(&body), p, "encode_payload {name}");
        let pre = prevout(a, "prevout");
        assert_eq!(act_msg(&p, &pre), h32(a, "actMsg"), "act_msg {name}");

        // The full OP_RETURN with its signatures, and each signature's recovered key.
        let script = hx(a, "script");
        assert!(is_act_output(&script), "{name}");
        let full = decode_act(&script).unwrap_or_else(|e| panic!("decode_act {name}: {e:?}"));
        assert_eq!(full.body, body, "{name}");
        assert_eq!(full.sigs.len(), arr(a, "sigs").len(), "{name}");
        assert_eq!(encode_act(&full), script, "encode_act {name}");
        let msg = h32(a, "actMsg");
        assert_eq!(arr(a, "signers").len(), arr(a, "sigs").len(), "{name}");
        for (j, sg) in arr(a, "sigs").iter().enumerate() {
            assert_eq!(full.sigs[j], sig(sg), "{name}");
            let rec = recover_sig(&msg, &sig(sg)).unwrap_or_else(|| panic!("recover {name} {j}"));
            assert_eq!(
                rec,
                PubKeyBytes::from_slice(&hv(&a["recovered"][j])).unwrap()
            );
        }
        assert!(act_fields_valid(&full), "fields {name}");

        let f = &a["fields"];
        assert_eq!(int(f, "type"), int(a, "type"));
        match body {
            ActBody::Create(c) => {
                assert_eq!(i64::from(c.seats), int(f, "seats"));
                assert_eq!(i64::from(c.unlock_threshold), int(f, "unlockThreshold"));
                assert_eq!(i64::from(c.cancel_threshold), int(f, "cancelThreshold"));
                assert_eq!(i64::from(c.slash_threshold), int(f, "slashThreshold"));
                assert_eq!(i64::from(c.flags), int(f, "flags"));
                assert_eq!(c.is_open(), int(f, "flags") & 1 == 1);
                assert_eq!(i64::from(c.rate_limit_bps), int(f, "rateLimitBps"));
                assert_eq!(i64::from(c.rate_window), int(f, "rateWindow"));
                assert_eq!(i64::from(c.liveness_window), int(f, "livenessWindow"));
                assert_eq!(c.bond_min, int(f, "bondMin"));
                assert_eq!(i64::from(c.bond_lock_min), int(f, "bondLockMin"));
                assert_eq!(i64::from(c.maturity), int(f, "maturity"));
                assert_eq!(c.admit_key, key(f, "admitKey"));
                assert!(c.valid(), "{name}");
                assert_eq!(body.target_set(), None);
            }
            ActBody::Join(j) => {
                assert_eq!(j.set_id, h32(f, "setId"));
                assert_eq!(j.member_key, key(f, "memberKey"));
                assert_eq!(i64::from(j.bond_locktime), int(f, "bondLocktime"));
                assert_eq!(i64::from(j.bond_vout), int(f, "bondVout"));
            }
            ActBody::Heartbeat(h) => {
                assert_eq!(h.set_id, h32(f, "setId"));
                assert_eq!(h.member_key, key(f, "memberKey"));
            }
            ActBody::Remove(r) => {
                assert_eq!(r.set_id, h32(f, "setId"));
                assert_eq!(r.member_key, key(f, "memberKey"));
                assert_eq!(i64::from(r.burn), int(f, "burn"));
            }
            ActBody::Equivocation(e) => {
                assert_eq!(e.set_id, h32(f, "setId"));
                assert_eq!(e.prevout, prevout(f, "prevout"));
                assert_eq!(i64::from(e.role_a), int(f, "roleA"));
                assert_eq!(e.sighash_a, h32(f, "sighashA"));
                assert_eq!(e.sig_a, sig(&f["sigA"]));
                assert_eq!(i64::from(e.role_b), int(f, "roleB"));
                assert_eq!(e.sighash_b, h32(f, "sighashB"));
                assert_eq!(e.sig_b, sig(&f["sigB"]));
                // Both signatures recover to the convicted key over their §15.2 messages.
                let convicts = key(a, "convicts");
                let ma = set_sig_msg(&e.set_id, e.role_a, &e.prevout, &e.sighash_a);
                let mb = set_sig_msg(&e.set_id, e.role_b, &e.prevout, &e.sighash_b);
                assert_eq!(recover_sig(&ma, &e.sig_a), Some(convicts));
                assert_eq!(recover_sig(&mb, &e.sig_b), Some(convicts));
            }
            ActBody::WindDown(w) => assert_eq!(w.set_id, h32(f, "setId")),
        }
        if !matches!(body, ActBody::Create(_)) {
            assert_eq!(body.target_set(), Some(h32(f, "setId")), "{name}");
        }
    }
}

#[test]
fn acts_invalid() {
    let d = vectors();
    let bad = arr(&d, "actsInvalid");
    assert_eq!(bad.len(), 29);
    for a in bad {
        let name = s(a, "name");
        let got = decode_payload(&hx(a, "payload"));
        match s(a, "stage") {
            "decode" => {
                let err = got.expect_err(name);
                // The reject class the vector's reason names.
                let want = match s(a, "reason") {
                    "version" => ActError::Version,
                    "type" => ActError::Type,
                    _ => ActError::Malformed,
                };
                assert_eq!(err, want, "{name}");
            }
            "field" => {
                // This decoder, like the C++, applies the field rules at rule time.
                let body = got.unwrap_or_else(|e| panic!("{name} decodes: {e:?}"));
                assert!(!body_fields_valid(&body), "field rule not enforced: {name}");
                assert!(!act_fields_valid(&Act { body, sigs: vec![] }), "{name}");
            }
            other => panic!("unknown stage {other}"),
        }
    }
    let sbad = arr(&d, "actScriptsInvalid");
    assert_eq!(sbad.len(), 4);
    for a in sbad {
        assert!(
            decode_act(&hx(a, "script")).is_err(),
            "decode_act accepted {}",
            s(a, "name")
        );
    }
}

#[test]
fn act_carrier_edges() {
    // Edges the vector does not carry, taken from ycash6 act.cpp's rules.
    let d = vectors();
    let winddown = d["acts"]
        .as_array()
        .unwrap()
        .iter()
        .find(|a| s(a, "name") == "set-winddown")
        .unwrap();
    let script = hx(winddown, "script");
    let act = decode_act(&script).unwrap();
    // More than MAX_ACT_SIGS signatures: bad-vault-act-sigs, before any recovery.
    let mut many = act.clone();
    many.sigs = vec![act.sigs[0]; MAX_ACT_SIGS + 1];
    assert_eq!(decode_act(&encode_act(&many)), Err(ActError::Sigs));
    assert_eq!(ActError::Sigs.reject_reason(), "bad-vault-act-sigs");
    many.sigs.truncate(MAX_ACT_SIGS);
    assert_eq!(decode_act(&encode_act(&many)), Ok(many));
    // Not an OP_RETURN, or an OP_RETURN whose first push is not "YV": not an act.
    assert!(!is_act_output(&script[1..]));
    assert!(!is_act_output(&[op::OP_RETURN, 0x02, 0x59, 0x57]));
    assert!(is_act_output(&[op::OP_RETURN, 0x02, 0x59, 0x56]));
    assert_eq!(
        decode_act(&[op::OP_RETURN, 0x02, 0x59, 0x56]),
        Err(ActError::Malformed)
    );
    assert_eq!(decode_act(&[op::OP_RETURN]), Err(ActError::Malformed));
    // A signature header outside 31..34 decodes but fails the field rules.
    let mut hdr = act.clone();
    hdr.sigs[0].0[0] = 27;
    let back = decode_act(&encode_act(&hdr)).unwrap();
    assert!(!act_fields_valid(&back));
}

#[test]
fn set_sig_messages() {
    let d = vectors();
    let m = arr(&d, "setSigMsgs");
    assert_eq!(m.len(), 3);
    for e in m {
        let role = u8::try_from(int(e, "role")).unwrap();
        let got = set_sig_msg(
            &h32(e, "setId"),
            role,
            &prevout(e, "prevout"),
            &h32(e, "sighash"),
        );
        assert_eq!(got, h32(e, "msg"));
    }
}

/// The stock non-strict recovery (C++ `CPubKey::RecoverCompact`): any header 27..34, recid
/// `(h - 27) & 3`, compressed when `(h - 27) & 4`.
fn recover_non_strict(msg: &Hash32, sig: &RecoverableSig) -> Option<Vec<u8>> {
    let h = sig.0[0].wrapping_sub(27);
    let recid = RecoveryId::from_u8_masked(h & 3);
    let rs = RecoverableSignature::from_compact(&sig.0[1..], recid).ok()?;
    let k = rs
        .recover_ecdsa(secp256k1::Message::from_digest(msg.0))
        .ok()?;
    Some(if h & 4 != 0 {
        k.serialize().to_vec()
    } else {
        k.serialize_uncompressed().to_vec()
    })
}

#[test]
fn recoverable_signatures() {
    let d = vectors();
    let ok = arr(&d, "signatures");
    assert_eq!(ok.len(), 8);
    let mut flipped = 0;
    for e in ok {
        let secret: [u8; 32] = hx(e, "secret").try_into().unwrap();
        assert_eq!(public_key(&secret), Some(key(e, "pubkey")));
        let msg = h32(e, "msg");
        // libsecp256k1's default RFC 6979 nonce: the Python signature byte for byte.
        assert_eq!(
            sign_recoverable(&secret, &msg),
            Some(sig(&e["sig"])),
            "{}",
            s(e, "label")
        );
        assert_eq!(recover_sig(&msg, &sig(&e["sig"])), Some(key(e, "pubkey")));
        if e["lowSFlipped"].as_bool().unwrap() {
            flipped += 1;
        }
    }
    assert!(
        flipped >= 1 && flipped < ok.len(),
        "both low-S branches are covered"
    );
    let bad = arr(&d, "signaturesInvalid");
    assert_eq!(bad.len(), 7);
    for e in bad {
        let msg = h32(e, "msg");
        let sg = sig(&e["sig"]);
        assert_eq!(
            recover_sig(&msg, &sg),
            None,
            "recover_sig accepted {}",
            s(e, "name")
        );
        // The stock non-strict recovery agrees with the vector where it recovers at all.
        match &e["nonStrictRecovers"] {
            Value::Null => {}
            v => assert_eq!(
                recover_non_strict(&msg, &sg),
                Some(hv(v)),
                "{}",
                s(e, "name")
            ),
        }
    }
}

#[test]
fn template_spends() {
    // The set spends' scriptSigs, selectors, setSigMsg and signatures. The ZIP-243 sighash under
    // the Vault branch (`sighash`) is the script crate's (W3) and is taken from the vector here.
    let d = vectors();
    let sp = arr(&d, "spends");
    assert_eq!(sp.len(), 2);
    for e in sp {
        let name = s(e, "name");
        assert_eq!(int(e, "nIn"), 0);
        assert_eq!(int(e, "branchId"), 0x6d5b_7a31);
        let (prevout, script_sig) = first_input(&hx(e, "tx"));
        assert_eq!(script_sig, hx(e, "scriptSig"), "{name}");
        let role = u8::try_from(int(e, "role")).unwrap();
        let msg = set_sig_msg(&h32(e, "setId"), role, &prevout, &h32(e, "sighash"));
        assert_eq!(msg, h32(e, "setSigMsg"), "{name}");
        let code = hx(e, "scriptCode");
        let ts = parse_template_spend(&code, &script_sig).unwrap();
        // UNLOCK = selector 1, role 1 on a V; CANCEL = selector 2, role 2 on an I.
        assert_eq!(ts.selector, role, "{name}");
        match ts.params {
            TemplateParams::Vault(v) => {
                assert_eq!(role, ROLE_UNLOCK);
                assert_eq!(v.set_id, h32(e, "setId"));
            }
            TemplateParams::Intent(i) => {
                assert_eq!(role, ROLE_CANCEL);
                assert_eq!(i.cancel_set_id, h32(e, "setId"));
            }
        }
        assert_eq!(ts.sigs.len(), arr(e, "sigs").len());
        assert_eq!(arr(e, "signers").len(), ts.sigs.len());
        for (j, sg) in ts.sigs.iter().enumerate() {
            assert_eq!(sg, &hv(&e["sigs"][j]), "{name}");
            assert!(recover_sig(&msg, &RecoverableSig::from_slice(sg).unwrap()).is_some());
        }
    }
}

#[test]
fn owner_spends_template_half() {
    // The owner spends: the template parse, the selector and the chunked owner key hashing to
    // the template's owner. pq::Verify of the signature and VerifyScript are W3 (kogany-pq and
    // the script crate) and are not replayed here.
    let d = vectors();
    let sp = arr(&d, "ownerSpends");
    assert!(sp.len() >= 4);
    let (mut falcon, mut released) = (0, 0);
    for e in sp {
        let name = s(e, "name");
        let code = hx(e, "scriptCode");
        let owner: PqOwner = match s(e, "kind") {
            "V" => parse_vault(&code).unwrap().owner,
            _ => parse_intent(&code).unwrap().owner,
        };
        let (_, script_sig) = first_input(&hx(e, "tx"));
        assert_eq!(script_sig, hx(e, "scriptSig"), "{name}");
        let ts = parse_template_spend(&code, &script_sig).unwrap();
        assert_eq!(i64::from(ts.selector), int(e, "selector"), "{name}");
        // <sig_1>..<sig_s> <s> <pk_1>..<pk_p> <p>
        let a = &ts.sigs;
        let p = usize::from(a.last().unwrap()[0]);
        let s_count = usize::from(a[a.len() - 2 - p][0]);
        assert_eq!(a.len(), s_count + p + 2, "{name}");
        let sig: Vec<u8> = a[..s_count].concat();
        let pk: Vec<u8> = a[s_count + 1..s_count + 1 + p].concat();
        assert_eq!(pq_key_hash(owner.scheme, &pk), owner.hash, "{name}");
        assert_eq!(sig.last(), Some(&0x01), "SIGHASH_ALL {name}");
        if owner.scheme == PQ_SCHEME_FN_DSA_512 {
            falcon += 1;
        }
        if s(e, "verify") == "signature" {
            assert_eq!(ts.selector, SEL_RELEASED, "{name}");
            released += 1;
        } else {
            assert_eq!(s(e, "verify"), "script");
            assert_eq!(ts.selector, SEL_OWNER, "{name}");
        }
    }
    assert_eq!(falcon, 1);
    assert_eq!(released, 2);
}

/// A key field whose header is not `0x02`/`0x03` re-encodes as 33 zero bytes (C++ `Writer::key`
/// on an invalid `CPubKey`), so `decode_act`'s round trip refuses it as malformed unless the key
/// bytes are all zero; `decode_payload` alone still decodes it (W3-e verdict replay,
/// qa/fuzz/vault, Vault/fuzz-20261025-10.bin).
#[test]
fn act_key_without_compressed_header_is_malformed() {
    use kogany_vault::act::{decode_act, decode_payload, ActError};
    let heartbeat = |key: [u8; 33]| {
        let mut p = b"YV\x01\x03".to_vec();
        p.extend_from_slice(&[0x11; 32]);
        p.extend_from_slice(&key);
        let mut spk = vec![0x6a, u8::try_from(p.len()).unwrap()];
        spk.extend_from_slice(&p);
        (p, spk)
    };
    let mut good = [0x5a; 33];
    good[0] = 0x02;
    for (key, act_ok) in [
        (good, true),
        ([0; 33], true),
        ([0x04; 33], false),
        (
            {
                let mut k = [0; 33];
                k[32] = 1;
                k
            },
            false,
        ),
    ] {
        let (p, spk) = heartbeat(key);
        assert!(decode_payload(&p).is_ok());
        assert_eq!(
            decode_act(&spk).map(|_| ()),
            if act_ok {
                Ok(())
            } else {
                Err(ActError::Malformed)
            }
        );
    }
}
