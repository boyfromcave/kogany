//! Tests for the transparent pools by type: the classifier's vectors (the table of ycash6
//! `src/gtest/test_valuepools.cpp` and the pinned `vault_vectors.json`), the record and the seed.

use std::{collections::HashMap, sync::Arc};

use kogany_vault::{
    template::{build_intent, build_vault, IntentParams, VaultParams},
    Hash32, PqOwner, PubKeyBytes, Tag,
};
use kogany_yellowback::codecs::script::{
    pq_channel_script, pq_key_script, PqChannelParams, YED_TAG,
};
use zakura_chain::{
    amount::{Amount, MAX_MONEY},
    block::{Block, Height},
    serialization::ZcashDeserializeInto,
    transaction::{LockTime, Transaction},
    transparent::{Input, OutPoint, Output, Script},
};

use super::*;

const OP_1: u8 = 0x51;
const OP_2: u8 = 0x52;
const OP_3: u8 = 0x53;
const OP_NOP: u8 = 0x61;
const OP_2DROP: u8 = 0x6d;
const OP_CHECKSIG: u8 = 0xac;
const OP_CHECKPQSIG: u8 = 0xc2;

/// The secp256k1 generator, compressed: a valid point (the gtest's `ServerKey`).
fn server_key() -> [u8; 33] {
    hex::decode("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
        .unwrap()
        .try_into()
        .unwrap()
}

const OTHER_TAG: Tag = Tag(*b"WYEC");

fn sample_vault(tag: Tag) -> Vec<u8> {
    build_vault(&VaultParams {
        tag,
        cancel_set_id: Hash32([0x11; 32]),
        set_id: Hash32([0x22; 32]),
        delay: 10,
        owner_height: 500,
        app_height: 500,
        owner: PqOwner {
            scheme: 1,
            hash: Hash32([0x33; 32]),
        },
    })
    .expect("the sample vault builds")
}

fn sample_intent(tag: Tag) -> Vec<u8> {
    build_intent(&IntentParams {
        tag,
        recipient_hash: Hash32([0x44; 32]),
        vault_hash: Hash32([0x55; 32]),
        delay: 10,
        cancel_set_id: Hash32([0x11; 32]),
        set_id: Hash32([0x22; 32]),
        owner: PqOwner {
            scheme: 2,
            hash: Hash32([0x66; 32]),
        },
    })
    .expect("the sample intent builds")
}

fn pq_script(scheme: u8, byte: u8) -> Vec<u8> {
    pq_key_script(&PqOwner {
        scheme,
        hash: Hash32([byte; 32]),
    })
    .expect("a registered scheme")
}

fn channel_script() -> Vec<u8> {
    pq_channel_script(&PqChannelParams {
        client: PqOwner {
            scheme: 2,
            hash: Hash32([0x78; 32]),
        },
        server: PubKeyBytes(server_key()),
        refund_height: 1000,
    })
    .expect("the sample channel builds")
}

fn push(data: &[u8]) -> Vec<u8> {
    let mut script = vec![u8::try_from(data.len()).expect("a direct push")];
    script.extend_from_slice(data);
    script
}

/// The table of ycash6 `test_valuepools.cpp` `Vectors()`: name, script, class, scheme, YED.
fn vectors() -> Vec<(&'static str, Vec<u8>, PoolClass, u8, bool)> {
    use PoolClass::*;

    let key = server_key();
    let key_id = hex::decode("0102030405060708090a0b0c0d0e0f1011121314").unwrap();
    let p2pk = [push(&key), vec![OP_CHECKSIG]].concat();
    let mut v = vec![
        (
            "p2pkh",
            [vec![0x76, 0xa9], push(&key_id), vec![0x88, OP_CHECKSIG]].concat(),
            TransparentEcc,
            0,
            false,
        ),
        ("p2pk", p2pk.clone(), TransparentEcc, 0, false),
        (
            "p2sh",
            [
                vec![0xa9],
                push(&kogany_vault::template::hash160(&p2pk)),
                vec![0x87],
            ]
            .concat(),
            TransparentEcc,
            0,
            false,
        ),
        (
            "multisig",
            [vec![OP_1], push(&key), vec![OP_1, 0xae]].concat(),
            TransparentEcc,
            0,
            false,
        ),
        (
            "op_return",
            [vec![0x6a], push(&[0xde, 0xad, 0xbe, 0xef])].concat(),
            TransparentEcc,
            0,
            false,
        ),
        ("nonstandard", vec![OP_1], TransparentEcc, 0, false),
        ("empty", vec![], TransparentEcc, 0, false),
    ];

    let pq1 = pq_script(1, 0x77);
    let pq2 = pq_script(2, 0x78);
    assert_eq!(pq1.len(), 35);
    v.push(("pqpkh scheme 1", pq1.clone(), TransparentPq, 1, false));
    v.push(("pqpkh scheme 2", pq2, TransparentPq, 2, false));
    // Near misses: 34 and 36 bytes, scheme byte OP_3, a wrong last opcode.
    v.push((
        "pq shape 34 bytes",
        [push(&[0x77; 31]), vec![OP_1, OP_CHECKPQSIG]].concat(),
        TransparentEcc,
        0,
        false,
    ));
    v.push((
        "pq shape 36 bytes",
        [push(&[0x77; 33]), vec![OP_1, OP_CHECKPQSIG]].concat(),
        TransparentEcc,
        0,
        false,
    ));
    let mut scheme_3 = pq1.clone();
    scheme_3[33] = OP_3;
    v.push(("pq scheme OP_3", scheme_3, TransparentEcc, 0, false));
    let mut checksig = pq1;
    checksig[34] = OP_CHECKSIG;
    v.push((
        "pq last opcode CHECKSIG",
        checksig,
        TransparentEcc,
        0,
        false,
    ));

    let channel = channel_script();
    v.push(("pq channel", channel.clone(), PqChannel, 0, false));
    // The same shape with refundHeight 0 (out of range), built by hand: the builder refuses it.
    let client = [push(&[0x78; 32]), vec![OP_2, OP_CHECKPQSIG]].concat();
    v.push((
        "pq channel bad height",
        [
            vec![0x63],
            client.clone(),
            vec![0x69],
            push(&key),
            vec![OP_CHECKSIG, 0x67, 0x00, 0xb1, 0x75],
            client,
            vec![0x68],
        ]
        .concat(),
        TransparentEcc,
        0,
        false,
    ));
    let mut slots_differ = channel;
    slots_differ[5] ^= 0x01;
    v.push((
        "pq channel slots differ",
        slots_differ,
        TransparentEcc,
        0,
        false,
    ));

    let vault_yed = sample_vault(YED_TAG);
    let intent_yed = sample_intent(YED_TAG);
    v.push(("vault YED", vault_yed.clone(), Vault, 0, true));
    v.push(("vault other tag", sample_vault(OTHER_TAG), Vault, 0, false));
    v.push(("intent YED", intent_yed.clone(), VaultIntent, 0, true));
    v.push((
        "intent other tag",
        sample_intent(OTHER_TAG),
        VaultIntent,
        0,
        false,
    ));
    // One byte flipped: an opcode of the skeleton and the owner's scheme byte.
    let mut opcode_flipped = vault_yed.clone();
    let at = opcode_flipped
        .iter()
        .position(|b| *b == OP_2DROP)
        .expect("the vault has an OP_2DROP");
    opcode_flipped[at] = OP_NOP;
    v.push((
        "vault opcode flipped",
        opcode_flipped,
        TransparentEcc,
        0,
        false,
    ));
    let mut owner_scheme = vault_yed.clone();
    let at = owner_scheme
        .windows(2)
        .position(|w| w == [OP_1, OP_CHECKPQSIG])
        .expect("the vault has an owner slot");
    owner_scheme[at] = OP_3;
    v.push((
        "vault owner scheme OP_3",
        owner_scheme,
        TransparentEcc,
        0,
        false,
    ));
    let mut last_flipped = intent_yed;
    *last_flipped.last_mut().unwrap() = OP_NOP;
    v.push((
        "intent last opcode flipped",
        last_flipped,
        TransparentEcc,
        0,
        false,
    ));
    let mut longer = vault_yed;
    longer.push(OP_NOP);
    v.push(("vault one byte longer", longer, TransparentEcc, 0, false));
    v
}

fn classify(script: &[u8]) -> ScriptClass {
    classify_transparent_script(&Script::new(script))
}

#[test]
fn classifier_vectors_shared_with_ycash6() {
    let vectors = vectors();
    assert_eq!(vectors.len(), 24);
    for (name, script, class, pq_scheme, yed) in vectors {
        assert_eq!(
            classify(&script),
            ScriptClass {
                class,
                pq_scheme,
                yed
            },
            "{name}"
        );
    }
}

/// Every single-byte mutation of a template is either the template of the same class again or
/// `transparent_ecc`... or, for a tag or parameter byte, the same class with other fields: the
/// classifier never moves a mutated script to a different template class.
#[test]
fn classifier_keeps_mutations_in_their_class_or_ecc() {
    for (name, script, class, _, _) in vectors() {
        if class == PoolClass::TransparentEcc {
            continue;
        }
        for at in 0..script.len() {
            let mut mutated = script.clone();
            mutated[at] ^= 0x01;
            let got = classify(&mutated).class;
            assert!(
                got == class || got == PoolClass::TransparentEcc,
                "{name}: byte {at} flipped classifies as {got:?}"
            );
        }
    }
}

fn pinned_vault_vectors() -> serde_json::Value {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../testdata/yellowback/vault_vectors.json"
    );
    serde_json::from_slice(&std::fs::read(path).expect("the pinned vectors are committed"))
        .expect("the vectors are JSON")
}

fn script_of(vector: &serde_json::Value, key: &str) -> Vec<u8> {
    hex::decode(vector[key].as_str().expect("a hex string")).expect("hex")
}

/// The pinned vault vectors (byte-identical to ycash6 `src/test/data/vault_vectors.json`): every
/// valid template is its class, with the YED row by its tag; no invalid one is.
#[test]
fn classifier_agrees_with_the_pinned_vault_vectors() {
    let vectors = pinned_vault_vectors();
    let yed = hex::encode(YED_TAG.0);
    let list = |key: &str| vectors[key].as_array().expect("an array").clone();

    for (key, class) in [
        ("vaults", PoolClass::Vault),
        ("intents", PoolClass::VaultIntent),
    ] {
        let valid = list(key);
        assert!(!valid.is_empty());
        for vector in valid {
            let got = classify(&script_of(&vector, "script"));
            assert_eq!(got.class, class, "{key} {}", vector["name"]);
            assert_eq!(
                got.yed,
                vector["params"]["tag"].as_str() == Some(yed.as_str()),
                "{key} {}",
                vector["name"]
            );
            assert_eq!(got.pq_scheme, 0);
        }
        for vector in list(&format!("{key}Invalid")) {
            assert_ne!(
                classify(&script_of(&vector, "script")).class,
                class,
                "{key}Invalid {}",
                vector["name"]
            );
        }
    }
    // An intent's recipient and a bond are ordinary scripts.
    for vector in list("bonds") {
        assert_eq!(
            classify(&script_of(&vector, "spk")).class,
            PoolClass::TransparentEcc
        );
    }
}

fn record(v: [i64; 8]) -> TransparentPools {
    TransparentPools::from_amounts(v)
}

#[test]
fn record_serialization_round_trips_and_refuses_corrupt_rows() {
    let r = record([1_000, 100, 200, 30, 400, 50, 150, 20]);
    assert!(r.is_sane());
    assert_eq!(r.transparent_pq(), 300);
    assert_eq!(r.transparent_ecc(), 220);
    assert_eq!(r.yed(), 170);
    let bytes = r.to_bytes();
    assert_eq!(bytes.len(), TransparentPools::DISK_LEN);
    assert_eq!(TransparentPools::from_bytes(&bytes), Some(r));
    assert_eq!(
        TransparentPools::from_bytes(&TransparentPools::default().to_bytes()),
        Some(TransparentPools::default())
    );

    // An unknown version, a short row, a long row and an empty row are no record.
    let mut unknown = bytes.clone();
    unknown[0] = 2;
    assert_eq!(TransparentPools::from_bytes(&unknown), None);
    assert_eq!(TransparentPools::from_bytes(&bytes[..64]), None);
    assert_eq!(
        TransparentPools::from_bytes(&[bytes.clone(), vec![0]].concat()),
        None
    );
    assert_eq!(TransparentPools::from_bytes(&[]), None);

    // Totals out of range are no record: nothing is computed from them.
    for corrupt in [
        record([-1, 0, 0, 0, 0, 0, 0, 0]),
        record([MAX_MONEY + 1, 0, 0, 0, 0, 0, 0, 0]),
        // The classes exceed the total: a negative transparent_ecc.
        record([100, 60, 60, 0, 0, 0, 0, 0]),
        // The YED part exceeds its class.
        record([100, 0, 0, 0, 10, 0, 11, 0]),
        record([100, 0, 0, 0, 0, 10, 0, 11]),
        record([100, 0, 0, 0, i64::MAX, 0, 0, 0]),
    ] {
        assert!(!corrupt.is_sane(), "{corrupt:?}");
        assert_eq!(TransparentPools::from_bytes(&corrupt.to_bytes()), None);
    }
}

fn output(value: i64, script: &[u8]) -> Output {
    Output {
        value: Amount::try_from(value).expect("a valid amount"),
        lock_script: Script::new(script),
    }
}

fn transaction(inputs: Vec<Input>, outputs: Vec<Output>) -> Arc<Transaction> {
    Arc::new(Transaction::V4 {
        inputs,
        outputs,
        lock_time: LockTime::unlocked(),
        expiry_height: Height(0),
        joinsplit_data: None,
        sapling_shielded_data: None,
    })
}

fn coinbase(outputs: Vec<Output>) -> Arc<Transaction> {
    transaction(
        vec![Input::Coinbase {
            height: Height(1),
            data: vec![],
            sequence: 0,
        }],
        outputs,
    )
}

fn spend(outpoint: OutPoint) -> Input {
    Input::PrevOut {
        outpoint,
        unlock_script: Script::new(&[]),
        sequence: 0,
    }
}

fn block(transactions: Vec<Arc<Transaction>>) -> Block {
    let genesis: Block = zakura_test::vectors::BLOCK_MAINNET_GENESIS_BYTES
        .zcash_deserialize_into()
        .expect("the genesis vector parses");
    Block {
        header: genesis.header,
        transactions,
    }
}

fn outpoint(n: u8) -> OutPoint {
    OutPoint {
        hash: zakura_chain::transaction::Hash([n; 32]),
        index: u32::from(n),
    }
}

#[test]
fn apply_block_sums_every_class_and_needs_every_spent_output() {
    let p2pkh = vectors()[0].1.clone();
    let outputs = vec![
        output(1_000, &p2pkh),
        output(100, &pq_script(1, 0x77)),
        output(200, &pq_script(2, 0x78)),
        output(30, &channel_script()),
        output(400, &sample_vault(YED_TAG)),
        output(40, &sample_vault(OTHER_TAG)),
        output(50, &sample_intent(YED_TAG)),
        output(5, &sample_intent(OTHER_TAG)),
        // An OP_RETURN with value counts, as on ycash6.
        output(7, &[0x6a]),
    ];
    let first = block(vec![coinbase(outputs.clone())]);
    let no_spends = |_: &OutPoint| None;
    let after_first = TransparentPools::default()
        .apply_block(&first, no_spends)
        .expect("a block without inputs needs no spent outputs");
    assert_eq!(after_first, record([1_832, 100, 200, 30, 440, 55, 400, 50]));
    assert_eq!(after_first.transparent_ecc(), 1_007);

    // Spend the scheme-2 output, the YED vault and the other intent; create a P2PKH and an
    // intent in two transactions, the second spending an output of the first.
    let spent: HashMap<OutPoint, Output> = [
        (outpoint(2), outputs[2].clone()),
        (outpoint(4), outputs[4].clone()),
        (outpoint(7), outputs[7].clone()),
        (outpoint(9), output(600, &sample_intent(YED_TAG))),
    ]
    .into();
    let second = block(vec![
        coinbase(vec![output(10, &p2pkh)]),
        transaction(
            vec![spend(outpoint(2)), spend(outpoint(4))],
            vec![output(600, &sample_intent(YED_TAG))],
        ),
        transaction(
            vec![spend(outpoint(9)), spend(outpoint(7))],
            vec![output(605, &p2pkh)],
        ),
    ]);
    let after_second = after_first
        .apply_block(&second, |outpoint| spent.get(outpoint))
        .expect("every spent output is supplied");
    assert_eq!(after_second, record([1_842, 100, 0, 30, 40, 50, 0, 50]));

    // A spent output that is not supplied is an error, never a guess.
    assert_eq!(
        after_first.apply_block(&second, no_spends),
        Err(TransparentPoolsError::MissingSpentOutput(outpoint(2)))
    );
    // Spending more of a class than the chain holds leaves the range.
    let overdraw: HashMap<OutPoint, Output> =
        [(outpoint(1), output(101, &pq_script(1, 0x77)))].into();
    let third = block(vec![transaction(
        vec![spend(outpoint(1))],
        vec![output(101, &p2pkh)],
    )]);
    assert_eq!(
        after_second.apply_block(&third, |outpoint| overdraw.get(outpoint)),
        Err(TransparentPoolsError::TotalOutOfRange)
    );
    // A total above MAX_MONEY leaves the range.
    let rich = block(vec![coinbase(vec![output(MAX_MONEY, &p2pkh)])]);
    assert_eq!(
        after_second.apply_block(&rich, no_spends),
        Err(TransparentPoolsError::TotalOutOfRange)
    );
    // Nothing is computed from a parent that is out of range.
    assert_eq!(
        record([-1, 0, 0, 0, 0, 0, 0, 0]).apply_block(&first, no_spends),
        Err(TransparentPoolsError::ParentOutOfRange)
    );
}

/// The seed is ycash6's mainnet chain-supply checkpoint (`chainparams.cpp:378-384`), the block
/// the C++ line checked (`valuepools.cpp` `SEED_CHECKED_MAX_HEIGHT`).
#[test]
fn compiled_seed_is_the_checked_checkpoint() {
    let seed = compiled_seed().expect("the seed hash parses");
    assert_eq!(seed.height, Height(2_800_000));
    assert_eq!(
        seed.hash.to_string(),
        "000003170414909d5104f4a71708eca4e5b545d231c412c2d3e0e3f33874facb"
    );
    assert_eq!(
        seed.record,
        record([1_053_104_265_390_951, 0, 0, 0, 0, 0, 0, 0])
    );
    assert!(seed.record.is_sane());
    assert_eq!(seed.record.transparent_ecc(), seed.record.transparent);
}
