//! ycash6 `src/test/vault_policy_tests.cpp` (at `65cb4ae0f`), case by case, under the C++ names
//! (kogany W6-a). The relay policy of the vault primitive and the post-quantum outputs: the V
//! and I templates are standard from Vault, a `YV` act may carry up to 1,200 bytes from Vault,
//! a template input's scriptSig is checked for its exact shape, TX_PQPKH is standard from
//! Vault and scheme 2 only from Falcon, PQ inputs may carry up to 9,000 bytes of scriptSig, PQ
//! dust prices the real spend, and the set-state classification of a template input's error.
//!
//! The C++ `Key(seed)` derives a secp256k1 key; nothing here verifies a signature, so a
//! compressed-looking 33-byte string stands in for it.

use std::collections::BTreeMap;

use kogany_vault::{
    act::{encode_act, Act, ActBody, SetCreateBody, SetHeartbeatBody},
    state::{SetRecord, SetState, StateRead},
    template::{
        build_intent, build_vault, intent_for, match_vault, Shape, VaultParams,
        PQ_SCHEME_FN_DSA_512, PQ_SCHEME_SLH_DSA_SHA2_128S,
    },
    Hash32, PqOwner, PubKeyBytes, RecoverableSig, Tag,
};
use zakura_chain::{
    amount::Amount,
    block::Height,
    parameters::{
        testnet::{self, ConfiguredActivationHeights, RegtestParameters},
        Network,
    },
    transaction::{self, LockTime, Transaction},
    transparent,
};
use zcash_script::interpreter;

use super::*;

const VAULT: u32 = 10;

/// `RegtestVault`: regtest with the Vault upgrade at height 10, Falcon off (regtest's default).
fn regtest_vault() -> Network {
    Network::new_regtest(RegtestParameters::from(ConfiguredActivationHeights {
        vault: Some(VAULT),
        ..Default::default()
    }))
}

/// A configured testnet with Vault at height 10: Falcon follows Vault there (`pqFalconHeight`
/// 0), the kogany stand-in for the C++ `-pqfalcon=1` regtest.
fn testnet_vault_falcon() -> Network {
    let params = testnet::Parameters::build()
        .with_activation_heights(ConfiguredActivationHeights {
            overwinter: Some(1),
            sapling: Some(1),
            vault: Some(VAULT),
            ..Default::default()
        })
        .expect("Vault after Sapling and before NU5 is a valid schedule")
        .to_network()
        .expect("the configured testnet has valid parameters");
    params
}

/// `uint256S("0x<n>")`: the value `n` in internal (little-endian) byte order.
fn u256(n: u8) -> Hash32 {
    let mut h = [0u8; 32];
    h[0] = n;
    Hash32(h)
}

/// A compressed-looking public key for `seed` (the C++ `Key(seed)` shape).
fn key(seed: u8) -> PubKeyBytes {
    let mut k = [0x44u8; 33];
    k[0] = 0x02;
    k[32] = seed;
    PubKeyBytes(k)
}

/// `GetScriptForDestination(Key(seed).GetID())`: a P2PKH script.
fn p2pkh(seed: u8) -> Vec<u8> {
    let mut s = vec![0x76, 0xa9, 0x14];
    s.extend_from_slice(&[seed; 20]);
    s.extend_from_slice(&[0x88, 0xac]);
    s
}

/// `GetScriptForDestination(CScriptID(redeem))`.
fn p2sh_of(redeem: &[u8]) -> Vec<u8> {
    kogany_vault::template::p2sh_script_pubkey(redeem)
}

/// `GetScriptForDestination(CPQKeyID(scheme, hash))`.
fn pqpkh(scheme: u8, hash: Hash32) -> Vec<u8> {
    let mut s = vec![0x20];
    s.extend_from_slice(&hash.0);
    s.push(0x50 + scheme);
    s.push(0xc2);
    s
}

fn params1() -> VaultParams {
    VaultParams {
        tag: Tag(*b"TEST"),
        set_id: u256(0x11),
        cancel_set_id: u256(0x22),
        delay: 5,
        owner_height: 1000,
        owner: PqOwner {
            scheme: PQ_SCHEME_SLH_DSA_SHA2_128S,
            hash: Hash32([0x5c; 32]),
        },
        app_height: 0,
    }
}

fn vault_script(vp: &VaultParams) -> Vec<u8> {
    build_vault(vp).expect("the test vault's fields are in range")
}

fn intent_script(vp: &VaultParams) -> Vec<u8> {
    let v = vault_script(vp);
    build_intent(&intent_for(vp, &v, &p2pkh(3))).expect("the test intent's fields are in range")
}

/// Appends a minimal push of `data` (`CScript << valtype`).
fn push(script: &mut Vec<u8>, data: &[u8]) {
    let n = data.len();
    if n < 0x4c {
        script.push(u8::try_from(n).expect("n < 0x4c"));
    } else if n <= 0xff {
        script.push(0x4c);
        script.push(u8::try_from(n).expect("n <= 0xff"));
    } else {
        script.push(0x4d);
        script.extend_from_slice(&u16::try_from(n).expect("test pushes fit u16").to_le_bytes());
    }
    script.extend_from_slice(data);
}

/// `OP_n` for `1..=16`.
fn op_n(n: usize) -> u8 {
    0x50 + u8::try_from(n).expect("small integer")
}

fn script_of(pushes: &[&[u8]]) -> Vec<u8> {
    let mut s = Vec::new();
    for p in pushes {
        push(&mut s, p);
    }
    s
}

/// `Tx(height)`: a v4 transaction with one input (`<72 bytes> <33 bytes>`, prevout 0x33).
fn tx(inputs: Vec<(Hash32, Vec<u8>)>, outputs: Vec<(u64, Vec<u8>)>) -> Transaction {
    Transaction::V4 {
        inputs: inputs
            .into_iter()
            .map(|(prev, script_sig)| transparent::Input::PrevOut {
                outpoint: transparent::OutPoint {
                    hash: transaction::Hash(prev.0),
                    index: 0,
                },
                unlock_script: transparent::Script::new(&script_sig),
                sequence: u32::MAX,
            })
            .collect(),
        outputs: outputs
            .into_iter()
            .map(|(value, spk)| output(value, &spk))
            .collect(),
        lock_time: LockTime::unlocked(),
        expiry_height: Height(0),
        joinsplit_data: None,
        sapling_shielded_data: None,
    }
}

fn output(value: u64, spk: &[u8]) -> transparent::Output {
    transparent::Output {
        value: Amount::try_from(value).expect("test values are valid amounts"),
        lock_script: transparent::Script::new(spk),
    }
}

fn default_input() -> (Hash32, Vec<u8>) {
    (u256(0x33), script_of(&[&[1u8; 72], &[2u8; 33]]))
}

fn tx_out(outputs: Vec<(u64, Vec<u8>)>) -> Transaction {
    tx(vec![default_input()], outputs)
}

/// `ActScript(sigs)`: a `SET_HEARTBEAT` with `sigs` 65-byte signatures.
fn act_script(sigs: usize) -> Vec<u8> {
    let mut sig = [0x20u8; 65];
    sig[0] = 31;
    encode_act(&Act {
        body: ActBody::Heartbeat(SetHeartbeatBody {
            set_id: u256(0x11),
            member_key: key(2),
        }),
        sigs: vec![RecoverableSig(sig); sigs],
    })
}

/// `PQArgs(scheme, sigLen, extraPushes)`: `<sig chunks> <s> <pk chunks> <p>` with dummy bytes
/// of the scheme's sizes (`sig_len` overrides the signature length).
fn pq_args(scheme: u8, sig_len: Option<usize>, extra_pushes: usize) -> Vec<u8> {
    let sl = sig_len.unwrap_or(kogany_pq::sig_size(scheme) + 1);
    let pl = kogany_pq::pubkey_size(scheme);
    let mut ss = Vec::new();
    let mut s = 0;
    let mut i = 0;
    while i < sl {
        push(&mut ss, &vec![0x5a; (sl - i).min(kogany_pq::MAX_CHUNK)]);
        i += kogany_pq::MAX_CHUNK;
        s += 1;
    }
    ss.push(op_n(s));
    let mut p = 0;
    let mut i = 0;
    while i < pl {
        push(&mut ss, &vec![0x6b; (pl - i).min(kogany_pq::MAX_CHUNK)]);
        i += kogany_pq::MAX_CHUNK;
        p += 1;
    }
    ss.push(op_n(p));
    for _ in 0..extra_pushes {
        push(&mut ss, &[0x07]);
    }
    ss
}

fn reason(result: Result<(), NonStandardReason>) -> &'static str {
    match result {
        Ok(()) => "",
        Err(reason) => reason.as_str(),
    }
}

fn std_tx(tx: &Transaction, network: &Network, height: u32) -> Result<(), NonStandardReason> {
    is_standard_tx(tx, network, Height(height), &RelayPolicy::default())
}

#[test]
fn solver_recognises_templates() {
    let vp = params1();
    let vspk = vault_script(&vp);
    let ispk = intent_script(&vp);
    let v = solver(&transparent::Script::new(&vspk)).expect("V solves");
    assert!(matches!(v, TxOutType::Vault(_)));
    assert_eq!(v.as_str(), "vault");
    let i = solver(&transparent::Script::new(&ispk)).expect("I solves");
    assert!(matches!(i, TxOutType::Intent(_)));
    assert_eq!(i.as_str(), "vaultintent");
    // No destination (ExtractDestination is false for V and I: they are not TX_PQPKH), and
    // ScriptSigArgsExpected is -1.
    assert!(transparent::Script::new(&vspk).pq_key_id().is_none());
    assert!(transparent::Script::new(&ispk).pq_key_id().is_none());
    assert_eq!(script_sig_args_expected(&v), None);
    // A malformed V (a non-minimal delay push) is not a template.
    let mut non_minimal = Vec::new();
    let mut pos = 0;
    let mut index = 0;
    while pos < vspk.len() {
        let (_, _, next) = get_op(&vspk, pos).expect("V parses");
        if index == 2 {
            non_minimal.extend_from_slice(&[0x02, 0x05, 0x00]);
        } else {
            non_minimal.extend_from_slice(&vspk[pos..next]);
        }
        pos = next;
        index += 1;
    }
    assert_ne!(non_minimal, vspk);
    assert!(solver(&transparent::Script::new(&non_minimal)).is_none());
}

#[test]
fn templates_standard_from_activation() {
    let network = regtest_vault();
    let vp = params1();
    for spk in [vault_script(&vp), intent_script(&vp)] {
        let t = tx_out(vec![(100_000, spk)]);
        assert_eq!(reason(std_tx(&t, &network, 9)), "scriptpubkey");
        assert_eq!(reason(std_tx(&t, &network, 10)), "");
    }
}

#[test]
fn act_op_return_size() {
    let network = regtest_vault();
    // A heartbeat with 3 signatures: well above the 83-byte data carrier limit.
    let act = act_script(3);
    assert!(act.len() > MAX_OP_RETURN_RELAY);
    assert!(act.len() <= MAX_VAULT_ACT_BYTES);
    let t = tx_out(vec![(0, act.clone())]);
    // ordinary data before activation
    assert_eq!(reason(std_tx(&t, &network, 9)), "scriptpubkey");
    assert_eq!(reason(std_tx(&t, &network, 10)), "");

    // At most MAX_VAULT_ACT_BYTES (18 signatures do not fit).
    let big = act_script(18);
    assert!(big.len() > MAX_VAULT_ACT_BYTES);
    assert!(std_tx(&tx_out(vec![(0, big)]), &network, 10).is_err());

    // Other OP_RETURNs keep the data carrier limit.
    let mut other = vec![0x6a];
    push(&mut other, &[0x41; 200]);
    assert_eq!(
        reason(std_tx(&tx_out(vec![(0, other)]), &network, 10)),
        "scriptpubkey"
    );

    // An act counts as the transaction's one OP_RETURN.
    let mut small = vec![0x6a];
    push(&mut small, &[0x41; 10]);
    let two = tx_out(vec![(0, act), (0, small)]);
    assert_eq!(reason(std_tx(&two, &network, 10)), "multi-op-return");
}

#[test]
fn template_inputs_standard() {
    let network = regtest_vault();
    let vspk = vault_script(&params1());
    // 15 signatures of 65 bytes and the selector: within the 1,650-byte scriptSig limit.
    let mut ss = Vec::new();
    for _ in 0..15 {
        push(&mut ss, &[0x20; 65]);
    }
    ss.push(op_n(1));
    assert!(ss.len() <= 1650);
    let t = tx(vec![(u256(0x55), ss)], vec![(1000, p2pkh(4))]);
    assert_eq!(reason(std_tx(&t, &network, 12)), "");
    assert!(are_inputs_standard(&t, &[output(100_000, &vspk)], None));
}

#[test]
fn pqpkh_standard_from_activation_and_falcon_gate() {
    let network = regtest_vault();
    let slh = pqpkh(PQ_SCHEME_SLH_DSA_SHA2_128S, u256(0xab));
    let fal = pqpkh(PQ_SCHEME_FN_DSA_512, u256(0xab));
    assert_eq!(slh.len(), 35);
    let kind = solver(&transparent::Script::new(&slh)).expect("TX_PQPKH solves");
    assert!(matches!(kind, TxOutType::PqPubKeyHash(_)));
    let before = tx_out(vec![(100_000, slh.clone())]);
    assert_eq!(reason(std_tx(&before, &network, 9)), "scriptpubkey");
    assert_eq!(reason(std_tx(&before, &network, 10)), "");

    // Scheme 2 (FN-DSA-512) outputs: PQPKH, V and I, refused while Falcon is inactive (A-1),
    // standard once active.
    let mut vp = params1();
    vp.owner.scheme = PQ_SCHEME_FN_DSA_512;
    let fv = vault_script(&vp);
    let fi = intent_script(&vp);
    let scheme = |spk: &[u8]| solver(&transparent::Script::new(spk)).and_then(|k| k.pq_scheme());
    assert_eq!(scheme(&fv), Some(PQ_SCHEME_FN_DSA_512));
    assert_eq!(scheme(&fi), Some(PQ_SCHEME_FN_DSA_512));
    assert_eq!(scheme(&slh), Some(PQ_SCHEME_SLH_DSA_SHA2_128S));
    assert_eq!(scheme(&p2pkh(3)), None);
    assert!(!zakura_script::is_pq_falcon_active(&network, Height(10)));
    for spk in [&fal, &fv, &fi] {
        let t = tx_out(vec![(100_000, spk.clone())]);
        assert_eq!(reason(std_tx(&t, &network, 10)), "scriptpubkey");
    }
    // -pqfalcon=1: kogany has no regtest Falcon parameter (W3-c finding F-1); a configured
    // testnet, where Falcon follows Vault, stands in.
    let falcon = testnet_vault_falcon();
    assert!(zakura_script::is_pq_falcon_active(&falcon, Height(10)));
    for spk in [&fal, &fv, &fi] {
        let t = tx_out(vec![(100_000, spk.clone())]);
        assert_eq!(reason(std_tx(&t, &falcon, 10)), "");
    }
    assert!(!zakura_script::is_pq_falcon_active(&falcon, Height(9)));
}

#[test]
fn pq_scriptsig_limits() {
    let network = regtest_vault();
    let p_pkh = output(100_000, &p2pkh(5));
    let p_slh = output(100_000, &pqpkh(PQ_SCHEME_SLH_DSA_SHA2_128S, u256(0x01)));
    let p_fal = output(100_000, &pqpkh(PQ_SCHEME_FN_DSA_512, u256(0x02)));
    let vspk = vault_script(&params1());
    let p_v = output(100_000, &vspk);
    let p_i = output(100_000, &intent_script(&params1()));

    let spend = |ss: &[u8]| tx(vec![(u256(0x61), ss.to_vec())], vec![(1000, p2pkh(4))]);
    let ais = |ss: &[u8], prev: &transparent::Output| {
        are_inputs_standard(&spend(ss), std::slice::from_ref(prev), None)
    };

    // An SLH-DSA PQPKH spend: 7,938 bytes, 19 pushes (quantum spec §2.1).
    let slh = pq_args(PQ_SCHEME_SLH_DSA_SHA2_128S, None, 0);
    assert_eq!(slh.len(), 7938);
    assert_eq!(reason(std_tx(&spend(&slh), &network, 12)), "");
    assert!(ais(&slh, &p_slh));
    // Before the upgrade the 1,650-byte limit stands (IsStandardTx).
    assert_eq!(reason(std_tx(&spend(&slh), &network, 9)), "scriptsig-size");
    // The exact count per scheme (A-14): one push more or fewer is non-standard.
    assert!(!ais(&pq_args(PQ_SCHEME_SLH_DSA_SHA2_128S, None, 1), &p_slh));
    // a Falcon-shaped stack against an SLH key is the wrong count
    assert!(!ais(&pq_args(PQ_SCHEME_FN_DSA_512, None, 0), &p_slh));
    // A Falcon PQPKH spend: 1,577 bytes, 6 pushes.
    let fal = pq_args(PQ_SCHEME_FN_DSA_512, None, 0);
    assert_eq!(fal.len(), 1577);
    assert!(ais(&fal, &p_fal));
    assert!(!ais(&slh, &p_fal));

    // Above MAX_STANDARD_PQ_SCRIPTSIG: refused by IsStandardTx (and by AreInputsStandard for a
    // PQ prevout).
    let mut huge = slh.clone();
    push(
        &mut huge,
        &vec![0x01; MAX_STANDARD_PQ_SCRIPTSIG - slh.len() + 1 - 3],
    );
    assert!(huge.len() > MAX_STANDARD_PQ_SCRIPTSIG);
    assert_eq!(
        reason(std_tx(&spend(&huge), &network, 12)),
        "scriptsig-size"
    );
    assert!(!ais(&huge, &p_slh));

    // A P2PKH input whose scriptSig passes IsStandardTx's relaxed bound is caught by
    // AreInputsStandard (F-6).
    let fat = script_of(&[&[0x01; 520], &[0x02; 520], &[0x03; 520], &[0x04; 100]]);
    assert!(fat.len() > MAX_STANDARD_SCRIPTSIG && fat.len() <= MAX_STANDARD_PQ_SCRIPTSIG);
    assert_eq!(reason(std_tx(&spend(&fat), &network, 12)), "");
    assert!(!ais(&fat, &p_pkh));

    // V and I owner spends (selector 2 / 3) of 7,939 bytes are standard inputs (F-6: every V/I
    // selector).
    let mut v_owner = slh.clone();
    v_owner.push(op_n(2));
    assert_eq!(v_owner.len(), 7939);
    assert!(ais(&v_owner, &p_v));
    let mut i_owner = slh.clone();
    i_owner.push(op_n(3));
    assert!(ais(&i_owner, &p_i));
    let mut v_huge = huge.clone();
    v_huge.push(op_n(2));
    assert!(!ais(&v_huge, &p_v));

    // P2SH-wrapped PQPKH stays non-standard (quantum spec §2.3): its redeem solves to TX_PQPKH,
    // args -1.
    let redeem = pqpkh(PQ_SCHEME_FN_DSA_512, u256(0x03));
    let p_sh = output(100_000, &p2sh_of(&redeem));
    let mut sh_sig = fal.clone();
    push(&mut sh_sig, &redeem);
    assert!(!ais(&sh_sig, &p_sh));
}

/// The set state of `template_scriptsig_shapes`: unlock threshold 2 on 0x11, cancel threshold
/// 1 on 0x22.
fn two_sets(vp: &VaultParams) -> SetState {
    let body = SetCreateBody {
        seats: 3,
        unlock_threshold: 2,
        cancel_threshold: 1,
        slash_threshold: 1,
        flags: 0,
        rate_limit_bps: 0,
        rate_window: 1,
        liveness_window: 1,
        bond_min: 1,
        bond_lock_min: 0,
        maturity: 0,
        admit_key: key(9),
    };
    let record = SetRecord::new(body, 0);
    SetState {
        sets: BTreeMap::from([(vp.set_id, record), (vp.cancel_set_id, record)]),
        ..SetState::default()
    }
}

#[test]
fn template_scriptsig_shapes() {
    // Audit 01/V-4: a template input's scriptSig carries no more than its selector's branch
    // consumes. The extra pushes are outside every signature (OP_CHECKSETSIG pops exactly k;
    // CLEANSTACK is policy, not consensus): consensus-valid in a block, non-standard for relay.
    // unlock set 0x11, cancel set 0x22, SLH-DSA owner
    let vp = params1();
    let p_v = output(100_000, &vault_script(&vp));
    let p_i = output(100_000, &intent_script(&vp));
    let state = two_sets(&vp);
    let snap: &dyn StateRead = &state;
    assert_eq!(
        snap.threshold(&vp.set_id, kogany_vault::template::ROLE_UNLOCK),
        Some(2)
    );
    let ais = |ss: Vec<u8>, prev: &transparent::Output, st: Option<&dyn StateRead>| {
        let t = tx(vec![(u256(0x71), ss)], vec![(1000, p2pkh(4))]);
        are_inputs_standard(&t, std::slice::from_ref(prev), st)
    };
    let sig = [0x20u8; 65];
    let with = |pushes: &[&[u8]], sel: u8| {
        let mut s = script_of(pushes);
        s.push(op_n(usize::from(sel)));
        s
    };
    // V UNLOCK: k = 2 signatures and OP_1.
    assert!(ais(with(&[&sig, &sig], 1), &p_v, Some(snap)));
    // <junk> <sig> <sig> OP_1: one push more than k (the extra-push malleation) — refused.
    assert!(!ais(with(&[&[0x07], &sig, &sig], 1), &p_v, Some(snap)));
    assert!(!ais(with(&[&sig, &sig, &sig], 1), &p_v, Some(snap)));
    // a non-65-byte push in a set-signed branch, with or without the set state
    assert!(!ais(with(&[&[0x07], &sig], 1), &p_v, None));
    // without the set state only the signature size is checked (k unknown)
    assert!(ais(with(&[&sig, &sig, &sig], 1), &p_v, None));
    // fewer than k fails OP_CHECKSETSIG: left to the script (its reason is the client's)
    assert!(ais(with(&[&sig], 1), &p_v, Some(snap)));
    // V OWNER / OWNER-RELEASED: the SLH-DSA stack (s + p + 2 pushes) and the selector; both
    // selectors standard (2 vs 3 is the owner's choice, not canonicalised); one extra push
    // refused.
    let owner = pq_args(PQ_SCHEME_SLH_DSA_SHA2_128S, None, 0);
    let sel = |mut s: Vec<u8>, n: usize| {
        s.push(op_n(n));
        s
    };
    assert!(ais(sel(owner.clone(), 2), &p_v, Some(snap)));
    assert!(ais(sel(owner.clone(), 3), &p_v, Some(snap)));
    assert!(!ais(
        sel(pq_args(PQ_SCHEME_SLH_DSA_SHA2_128S, None, 1), 2),
        &p_v,
        Some(snap)
    ));
    // V APP: the selector alone.
    assert!(ais(vec![op_n(4)], &p_v, Some(snap)));
    assert!(!ais(with(&[&[0x07]], 4), &p_v, Some(snap)));
    // I RELEASE: the selector alone; I CANCEL: k = 1; I OWNER-RELEASED: the owner stack.
    assert!(ais(vec![op_n(1)], &p_i, Some(snap)));
    assert!(!ais(with(&[&[0x07]], 1), &p_i, Some(snap)));
    assert!(ais(with(&[&sig], 2), &p_i, Some(snap)));
    assert!(!ais(with(&[&sig, &sig], 2), &p_i, Some(snap)));
    assert!(ais(sel(owner.clone(), 3), &p_i, Some(snap)));
    assert!(!ais(
        sel(pq_args(PQ_SCHEME_SLH_DSA_SHA2_128S, None, 1), 3),
        &p_i,
        Some(snap)
    ));
    // OP_4 is not an I selector; no selector at all on a V
    assert!(!ais(vec![op_n(4)], &p_i, Some(snap)));
    assert!(!ais(script_of(&[&sig, &sig]), &p_v, Some(snap)));
}

#[test]
fn pqpkh_dust_uses_the_real_spend_size() {
    // Review A F8: a TX_PQPKH output's dust threshold prices the input that spends it (SLH-DSA
    // 7,938 bytes of scriptSig, Falcon 1,577, plus outpoint, sequence and a 3-byte length), not
    // 148 bytes.
    let network = regtest_vault();
    assert_eq!(
        pq_spend_input_size(PQ_SCHEME_SLH_DSA_SHA2_128S),
        40 + 3 + 7938
    );
    assert_eq!(pq_spend_input_size(PQ_SCHEME_FN_DSA_512), 40 + 3 + 1577);
    assert_eq!(pq_spend_input_size(3), 0);
    // the size agrees with a real chunked scriptSig's serialization in an input: outpoint 36,
    // the scriptSig's compact size (3 above 252 bytes), the scriptSig, sequence 4
    for scheme in [PQ_SCHEME_SLH_DSA_SHA2_128S, PQ_SCHEME_FN_DSA_512] {
        let ss = pq_args(scheme, None, 0);
        assert_eq!(36 + 3 + ss.len() + 4, pq_spend_input_size(scheme));
    }
    // 6.20.0: the dust rate is the fixed ONE_THIRD_DUST_THRESHOLD_RATE.
    for scheme in [PQ_SCHEME_SLH_DSA_SHA2_128S, PQ_SCHEME_FN_DSA_512] {
        let out = output(0, &pqpkh(scheme, u256(0x0a)));
        let want = 3 * fee_at_rate(
            ONE_THIRD_DUST_THRESHOLD_RATE,
            (8 + 1 + 35) + pq_spend_input_size(scheme),
        );
        assert_eq!(pq_dust_threshold(&out), want);
        assert!(pq_dust_threshold(&out) > dust_threshold(&out));
    }
    // other outputs keep CTxOut::GetDustThreshold
    let p = output(0, &p2pkh(9));
    assert_eq!(pq_dust_threshold(&p), dust_threshold(&p));
    // and Zakura's own dust rule agrees with it there
    assert_eq!(dust_threshold(&p), 54);

    // IsStandardTx at the dust rate: one zat below the PQ threshold is dust, the threshold is not
    let slh = pqpkh(PQ_SCHEME_SLH_DSA_SHA2_128S, u256(0x0b));
    let t = pq_dust_threshold(&output(0, &slh));
    assert!(t > dust_threshold(&output(0, &slh)));
    assert_eq!(
        reason(std_tx(&tx_out(vec![(t - 1, slh.clone())]), &network, 10)),
        "dust"
    );
    assert_eq!(reason(std_tx(&tx_out(vec![(t, slh)]), &network, 10)), "");
}

// Audit 07/F-1 and its review: AcceptToMemoryPool checks the one template input of a
// transaction alone first and scores DoS 0 only for its own set-state-dependent errors; every
// other input and error keeps the stock score.
#[test]
fn mempool_set_state_failure_classification() {
    let vp = params1();
    let vspk = vault_script(&vp);
    let ispk = intent_script(&vp);
    let p2 = p2pkh(4);
    let find = |coins: &[Option<&[u8]>]| find_vault_template_input(coins.iter().copied());
    // the template input is found wherever it sits (the stock loop may never reach it)
    assert_eq!(find(&[Some(&p2), Some(&p2)]), None);
    assert_eq!(find(&[Some(&p2), Some(&vspk)]), Some(1));
    assert_eq!(find(&[Some(&ispk), Some(&p2)]), Some(0));
    // missing coin
    assert_eq!(find(&[None]), None);
    // a MALFORMED V-shaped coin (delay 0, out of range) is no template, as in vault::CheckTx's
    // count
    let mut malformed = vspk.clone();
    // <tag:4> <cancelSetId:32> <delay> (OP_5)
    assert_eq!(malformed[38], 0x55);
    malformed[38] = 0x00;
    assert!(matches!(match_vault(&malformed), Shape::Malformed));
    assert_eq!(find(&[Some(&malformed), Some(&p2)]), None);
    assert_eq!(find(&[Some(&malformed), Some(&vspk)]), Some(1));

    // shape only
    let owner_sig = script_of(&[&[7; 64]]);
    let owner_sig = {
        let mut s = owner_sig;
        s.push(op_n(1));
        push(&mut s, &[8; 32]);
        s.push(op_n(1));
        s
    };
    let with_sel = |mut s: Vec<u8>, n: usize| {
        s.push(op_n(n));
        s
    };
    let sel1 = with_sel(script_of(&[&[9; 65]]), 1);
    let sel2 = with_sel(owner_sig.clone(), 2);
    let sel3 = with_sel(owner_sig.clone(), 3);
    let mut sel3data = owner_sig.clone();
    push(&mut sel3data, &[3]);
    // OP_CHECKSETSIG's error: state-dependent whatever the selector
    for ss in [&sel1, &sel2, &sel3] {
        assert!(is_vault_set_state_script_error(
            ss,
            &interpreter::Error::SetSig
        ));
    }
    // OP_VERIFY: only the OWNER-RELEASED branch, whose one OP_VERIFY follows OP_CHECKSETDORMANT
    assert!(is_vault_set_state_script_error(
        &sel3,
        &interpreter::Error::Verify
    ));
    assert!(!is_vault_set_state_script_error(
        &sel1,
        &interpreter::Error::Verify
    ));
    assert!(!is_vault_set_state_script_error(
        &sel2,
        &interpreter::Error::Verify
    ));
    // not a canonical selector
    assert!(!is_vault_set_state_script_error(
        &sel3data,
        &interpreter::Error::Verify
    ));
    // never state-dependent: a template runs one OP_CHECKSETSIG; signatures, sizes, locktimes,
    // stack shape (the forked interpreter has no distinct EQUALVERIFY / CHECKSIGVERIFY codes,
    // and SCRIPT_ERR_EVAL_FALSE / SCRIPT_ERR_OK are not interpreter errors there)
    for e in [
        interpreter::Error::SetSigCount,
        interpreter::Error::PqSize,
        interpreter::Error::UnsatisfiedLockTime,
        interpreter::Error::InvalidStackOperation(None),
        interpreter::Error::PqScheme,
    ] {
        for ss in [&sel1, &sel2, &sel3] {
            assert!(!is_vault_set_state_script_error(ss, &e), "{e:?}");
        }
    }
}

// The isolated check keeps the stock old-consensus-branch-id diagnosis (review of the 07/F-1
// integration): a set-state error that disappears under the previous epoch's branch ID takes the
// stock route (false); the check runs at most twice, and only once for an error that is not
// set-state-dependent.
#[test]
fn mempool_set_state_previous_branch() {
    const CUR: u32 = 0x6d5b_7a31;
    const PREV: u32 = 0xe9ff_75a6;
    let mut sel1 = script_of(&[&[9; 65]]);
    sel1.push(op_n(1));
    let mut sel3 = script_of(&[&[7; 64]]);
    sel3.push(op_n(1));
    push(&mut sel3, &[8; 32]);
    sel3.push(op_n(1));
    sel3.push(op_n(3));

    type Outcome = Result<(), Option<interpreter::Error>>;
    let set_sig: Outcome = Err(Some(interpreter::Error::SetSig));
    let verify: Outcome = Err(Some(interpreter::Error::Verify));
    let eval_false: Outcome = Err(None);

    let check = |ss: &[u8], prev: u32, at_cur: Outcome, at_prev: Outcome| {
        let mut calls = Vec::new();
        let got = vault_template_fails_on_set_state(ss, CUR, prev, |b| {
            calls.push(b);
            if b == CUR {
                at_cur.clone()
            } else {
                at_prev.clone()
            }
        });
        (got, calls)
    };
    // set signatures made for the previous epoch: stock route (old-consensus-branch-id)
    assert_eq!(
        check(&sel1, PREV, set_sig.clone(), Ok(())),
        (false, vec![CUR, PREV])
    );
    // a set-state failure under both branch IDs: DoS 0
    assert_eq!(
        check(&sel1, PREV, set_sig.clone(), set_sig.clone()),
        (true, vec![CUR, PREV])
    );
    assert!(check(&sel3, PREV, verify.clone(), verify.clone()).0);
    // ... whatever else the previous branch ID yields
    assert!(check(&sel1, PREV, set_sig.clone(), eval_false.clone()).0);
    // no previous epoch (prev == cur): one run
    assert_eq!(
        check(&sel1, CUR, set_sig.clone(), Ok(())),
        (true, vec![CUR])
    );
    // success or a state-independent error: one run, stock route
    for e in [
        Ok(()),
        eval_false.clone(),
        Err(Some(interpreter::Error::SetSigCount)),
    ] {
        assert_eq!(check(&sel1, PREV, e, Ok(())), (false, vec![CUR]));
    }
    // VERIFY needs selector 3
    assert_eq!(check(&sel1, PREV, verify, Ok(())), (false, vec![CUR]));
}

/// Pre-Vault ycashd standardness the W6-a port keeps (W1-Y9's `standard` mode cases): the
/// 83-byte carrier, dust at 54 zatoshis for P2PKH, one OP_RETURN, and bare multisig up to
/// x-of-3 (ycashd's `-permitbaremultisig` default, where Zakura refuses every bare multisig).
#[test]
fn pre_vault_standardness_kept() {
    let network = regtest_vault();
    let mut op80 = vec![0x6a];
    push(&mut op80, &[0x5a; 80]);
    assert_eq!(reason(std_tx(&tx_out(vec![(0, op80)]), &network, 5)), "");
    let mut op81 = vec![0x6a];
    push(&mut op81, &[0x5a; 81]);
    assert_eq!(op81.len(), 84);
    assert_eq!(
        reason(std_tx(&tx_out(vec![(0, op81)]), &network, 5)),
        "scriptpubkey"
    );
    assert_eq!(
        reason(std_tx(&tx_out(vec![(53, p2pkh(1))]), &network, 5)),
        "dust"
    );
    assert_eq!(
        reason(std_tx(&tx_out(vec![(54, p2pkh(1))]), &network, 5)),
        ""
    );
    // 1-of-2 bare multisig: standard on ycashd by default
    let mut ms = vec![op_n(1)];
    push(&mut ms, &key(1).0);
    push(&mut ms, &key(2).0);
    ms.extend_from_slice(&[op_n(2), 0xae]);
    assert_eq!(
        reason(std_tx(&tx_out(vec![(10_000, ms.clone())]), &network, 5)),
        ""
    );
    let off = RelayPolicy {
        permit_bare_multisig: false,
        ..RelayPolicy::default()
    };
    assert_eq!(
        is_standard_tx(&tx_out(vec![(10_000, ms)]), &network, Height(5), &off),
        Err(NonStandardReason::BareMultisig)
    );
    // 1-of-4 is not
    let mut ms4 = vec![op_n(1)];
    for k in 1..=4 {
        push(&mut ms4, &key(k).0);
    }
    ms4.extend_from_slice(&[op_n(4), 0xae]);
    assert_eq!(
        reason(std_tx(&tx_out(vec![(10_000, ms4)]), &network, 5)),
        "scriptpubkey"
    );
}

/// `push_only_stack` fails where `EvalScript` fails: a push above 520 bytes and an executed
/// `OP_RESERVED`; a P2PKH scriptSig whose pushes do not evaluate is non-standard.
#[test]
fn push_only_stack_is_eval_script() {
    assert_eq!(
        push_only_stack(&script_of(&[&[1; 520]])).map(|s| s.len()),
        Some(1)
    );
    assert!(push_only_stack(&script_of(&[&[1; 521]])).is_none());
    assert!(push_only_stack(&[0x50]).is_none());
    assert_eq!(
        push_only_stack(&[0x00, 0x4f, 0x51, 0x60]),
        Some(vec![vec![], vec![0x81], vec![1], vec![16]])
    );
    let spend = tx(
        vec![(u256(1), script_of(&[&[1; 521], &[2; 33]]))],
        vec![(1000, p2pkh(4))],
    );
    assert!(!are_inputs_standard(
        &spend,
        &[output(100_000, &p2pkh(5))],
        None
    ));
    // and the P2SH redeem script's OP_CHECKPQSIG costs 20 policy sigops
    let redeem = [0xc2u8];
    let p2sh_spend = tx(
        vec![(u256(1), script_of(&[&redeem]))],
        vec![(1000, p2pkh(4))],
    );
    assert!(!are_inputs_standard(
        &p2sh_spend,
        &[output(100_000, &p2sh_of(&redeem))],
        None
    ));
    assert_eq!(
        pq_sig_op_count(&p2sh_spend, &[output(100_000, &p2sh_of(&redeem))]),
        20
    );
}
