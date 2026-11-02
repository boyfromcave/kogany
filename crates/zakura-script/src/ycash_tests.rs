//! kogany W3-c: the Ycash script context through the real verifier
//! ([`CachedFfiTransaction::is_valid_in`]).
//!
//! - the height-dependent flags, independent of the transaction version;
//! - `vault_vectors.json` `ownerSpends[]` (post-quantum owner spends, selectors 2 and 3) and
//!   `spends[]` (the set-signed unlock and cancel), with a set-state snapshot built from the
//!   vectors' `SET_CREATE` body and keys (ycash6 `src/test/vault_vectors_tests.cpp`
//!   `pq_owner_spends`, `template_spends`);
//! - `pq_vectors.json` `spends[]` through the Ycash checker and `kogany_pq::verify`;
//! - `OP_CHECKSEQUENCEVERIFY` through the checker from the input's `nSequence`.
//!
//! The vector files are checked against `testdata/yellowback/PIN` first; kogany never edits or
//! generates them (plan §4.2 rule 4).

use std::{path::PathBuf, sync::Arc};

use serde_json::Value;
use sha2::{Digest, Sha256};

use kogany_vault::{
    act::{self, ActBody, SetCreateBody},
    state::{MemberRecord, MemberStatus, SetRecord, SetState},
    Hash32, PubKeyBytes,
};
use zakura_chain::{
    amount::{Amount, NonNegative},
    block::Height,
    parameters::{
        testnet::{self, ConfiguredActivationHeights, RegtestParameters},
        Network, NetworkUpgrade,
    },
    serialization::ZcashDeserializeInto,
    transaction::Transaction,
    transparent,
};
use zcash_script::{
    interpreter::{self, CallbackTransactionSignatureChecker, Flags},
    script,
};

use crate::{
    is_pq_falcon_active, pq_falcon_height, script_flags, CachedFfiTransaction, Error,
    ScriptContext, VaultStateSnapshot, YcashSignatureChecker,
};

/// The Vault height of the test networks.
const VAULT_HEIGHT: u32 = 10;
/// The spending height of the vector spends (above `VAULT_HEIGHT`).
const SPEND_HEIGHT: u32 = 2_000;

// ---- the pinned vectors -------------------------------------------------------------------

/// Loads `testdata/yellowback/<name>` after checking its SHA-256 against `PIN`.
fn load_pinned(name: &str) -> Value {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata/yellowback");
    let bytes = std::fs::read(dir.join(name)).expect("the pinned vector file is present");
    let pin = std::fs::read_to_string(dir.join("PIN")).expect("PIN is present");
    let want = pin
        .lines()
        .filter(|line| !line.starts_with('#'))
        .find_map(|line| {
            let mut fields = line.split_whitespace();
            let sha = fields.next()?;
            (fields.next()? == format!("testdata/yellowback/{name}")).then(|| sha.to_owned())
        })
        .unwrap_or_else(|| panic!("{name} is pinned in PIN"));
    assert_eq!(
        hex::encode(Sha256::digest(&bytes)),
        want,
        "{name} differs from its PIN"
    );
    serde_json::from_slice(&bytes).expect("the pinned vector file is JSON")
}

fn hex_field(value: &Value, key: &str) -> Vec<u8> {
    hex::decode(
        value[key]
            .as_str()
            .unwrap_or_else(|| panic!("{key} is a hex string")),
    )
    .unwrap_or_else(|_| panic!("{key} is valid hex"))
}

fn int_field(value: &Value, key: &str) -> u64 {
    value[key]
        .as_u64()
        .unwrap_or_else(|| panic!("{key} is an integer"))
}

fn name_of(value: &Value) -> &str {
    value["name"].as_str().unwrap_or("?")
}

fn hash32(value: &Value, key: &str) -> Hash32 {
    Hash32::from_slice(&hex_field(value, key)).expect("a 32-byte id")
}

/// The compressed public key of the vectors' key `label`.
fn key(vectors: &Value, label: &str) -> PubKeyBytes {
    let entry = vectors["keys"]
        .as_array()
        .expect("keys is an array")
        .iter()
        .find(|k| k["label"] == label)
        .unwrap_or_else(|| panic!("key {label} is in the vectors"));
    PubKeyBytes::from_slice(&hex_field(entry, "pubkey")).expect("a 33-byte key")
}

/// The vectors' `set-create` act body.
fn set_create_body(vectors: &Value) -> SetCreateBody {
    let create = vectors["acts"]
        .as_array()
        .expect("acts is an array")
        .iter()
        .find(|a| a["name"] == "set-create")
        .expect("the vectors carry a set-create act");
    match act::decode_payload(&hex_field(create, "payload")) {
        Ok(ActBody::Create(body)) => body,
        other => panic!("set-create decodes as a SET_CREATE body: {other:?}"),
    }
}

// ---- networks and contexts ----------------------------------------------------------------

/// A configured (non-regtest) testnet with Vault at `VAULT_HEIGHT`: Falcon follows Vault there,
/// as on Ycash mainnet and testnet (`pqFalconHeight = 0`).
fn vault_testnet() -> Network {
    testnet::Parameters::build()
        .with_activation_heights(ConfiguredActivationHeights {
            before_overwinter: Some(1),
            overwinter: Some(1),
            sapling: Some(1),
            blossom: Some(1),
            heartwood: Some(1),
            canopy: Some(1),
            vault: Some(VAULT_HEIGHT),
            ..Default::default()
        })
        .expect("a valid Vault schedule")
        .clear_funding_streams()
        .to_network()
        .expect("a valid configured testnet")
}

/// A regtest with Vault at `VAULT_HEIGHT`: no Falcon (ycash6's regtest default).
fn vault_regtest() -> Network {
    Network::new_regtest(RegtestParameters::from(ConfiguredActivationHeights {
        vault: Some(VAULT_HEIGHT),
        ..Default::default()
    }))
}

fn context(network: &Network, height: u32, state: Option<SetState>) -> ScriptContext {
    ScriptContext::new(
        network.clone(),
        Height(height),
        state.map(|s| Arc::new(s) as VaultStateSnapshot),
    )
}

/// The vector spend's transaction, prepared as the transaction verifier prepares it: every
/// input's spent output is `(amount, scriptCode)` (the C++ test's `CTxOut(amount, code)`), under
/// the upgrade current at `SPEND_HEIGHT`.
fn prepared(spend: &Value, network: &Network, amount_delta: u64) -> CachedFfiTransaction {
    let transaction: Arc<Transaction> = hex_field(spend, "tx")
        .zcash_deserialize_into()
        .expect("the vector transaction parses");
    let amount: Amount<NonNegative> =
        Amount::try_from(int_field(spend, "amount") + amount_delta).expect("a valid amount");
    let lock_script = transparent::Script::new(&hex_field(spend, "scriptCode"));
    let outputs = (0..transaction.inputs().len())
        .map(|_| transparent::Output {
            value: amount,
            lock_script: lock_script.clone(),
        })
        .collect();
    let nu = NetworkUpgrade::current(network, Height(SPEND_HEIGHT));
    assert_eq!(
        nu,
        NetworkUpgrade::Vault,
        "the spends are verified under Vault"
    );
    CachedFfiTransaction::new(transaction, Arc::new(outputs), nu)
        .expect("a v4 transaction is valid under Vault")
}

fn n_in(spend: &Value) -> usize {
    usize::try_from(int_field(spend, "nIn")).expect("a small input index")
}

/// The interpreter error of a failed verification.
fn interpreter_error(result: Result<(), Error>) -> Option<interpreter::Error> {
    match result {
        Err(Error::Interpreter {
            error: script::Error::Interpreter(_, error),
            ..
        }) => Some(error),
        _ => None,
    }
}

// ---- the set state --------------------------------------------------------------------------

/// A member record that is current and live at `SPEND_HEIGHT`.
fn live_member(join_height: i64) -> MemberRecord {
    MemberRecord {
        join_height,
        last_act: i64::from(SPEND_HEIGHT),
        status: MemberStatus::Active,
        ..Default::default()
    }
}

/// The set state the vector spends were signed against: the unlock set `spends[0].setId` with
/// `member-0` and `member-1` (unlock threshold 2), the cancel set `spends[1].setId` with
/// `member-2` (cancel threshold 1); both from the vectors' `SET_CREATE` body, matured and live
/// at `SPEND_HEIGHT`.
struct VectorSets {
    unlock_set: Hash32,
    cancel_set: Hash32,
    body: SetCreateBody,
    members: [PubKeyBytes; 3],
}

impl VectorSets {
    fn new(vectors: &Value) -> Self {
        let spends = vectors["spends"].as_array().expect("spends is an array");
        let unlock = spends
            .iter()
            .find(|s| s["name"] == "unlock")
            .expect("an unlock spend");
        let cancel = spends
            .iter()
            .find(|s| s["name"] == "cancel")
            .expect("a cancel spend");
        assert_eq!(int_field(unlock, "role"), 1);
        assert_eq!(int_field(cancel, "role"), 2);
        Self {
            unlock_set: hash32(unlock, "setId"),
            cancel_set: hash32(cancel, "setId"),
            body: set_create_body(vectors),
            members: [
                key(vectors, "member-0"),
                key(vectors, "member-1"),
                key(vectors, "member-2"),
            ],
        }
    }

    /// The state, with the unlock threshold `unlock_threshold` and every member joined at
    /// `join_height`.
    fn state_with(&self, unlock_threshold: u8, join_height: i64) -> SetState {
        let mut state = SetState::new();
        let mut unlock = self.body;
        unlock.unlock_threshold = unlock_threshold;
        unlock.cancel_threshold = 1;
        let mut cancel = self.body;
        cancel.unlock_threshold = 1;
        cancel.cancel_threshold = 1;
        state
            .sets
            .insert(self.unlock_set, SetRecord::new(unlock, 0));
        state
            .sets
            .insert(self.cancel_set, SetRecord::new(cancel, 0));
        let [m0, m1, m2] = self.members;
        for m in [m0, m1] {
            state
                .members
                .insert((self.unlock_set, m), live_member(join_height));
        }
        state
            .members
            .insert((self.cancel_set, m2), live_member(join_height));
        state
    }

    fn state(&self) -> SetState {
        self.state_with(2, 0)
    }
}

// ---- flags ----------------------------------------------------------------------------------

#[test]
fn flags_follow_the_height_never_the_version() {
    let base = Flags::P2SH | Flags::CHECKLOCKTIMEVERIFY;
    let vault = base | Flags::CHECKSEQUENCEVERIFY | Flags::Vault;

    // Zcash networks never schedule Vault: upstream's constant at every height.
    for network in [Network::Mainnet, Network::new_regtest(Default::default())] {
        for height in [0, 1, VAULT_HEIGHT, 1_046_400, 3_000_000, Height::MAX.0] {
            assert_eq!(
                script_flags(&network, Height(height)),
                base,
                "{network} {height}"
            );
        }
    }

    // Regtest with Vault: CSV and the vault opcodes from the Vault height, no Falcon.
    let regtest = vault_regtest();
    assert_eq!(pq_falcon_height(&regtest), None);
    assert_eq!(script_flags(&regtest, Height(VAULT_HEIGHT - 1)), base);
    assert_eq!(script_flags(&regtest, Height(VAULT_HEIGHT)), vault);
    assert_eq!(script_flags(&regtest, Height(SPEND_HEIGHT)), vault);
    assert!(!is_pq_falcon_active(&regtest, Height(SPEND_HEIGHT)));

    // Elsewhere Falcon follows Vault exactly (pqFalconHeight 0).
    let testnet = vault_testnet();
    assert_eq!(pq_falcon_height(&testnet), Some(Height(0)));
    assert_eq!(script_flags(&testnet, Height(VAULT_HEIGHT - 1)), base);
    assert!(!is_pq_falcon_active(&testnet, Height(VAULT_HEIGHT - 1)));
    assert_eq!(
        script_flags(&testnet, Height(VAULT_HEIGHT)),
        vault | Flags::PqFalcon
    );

    // The context's flags are the same function: no input of it is the transaction.
    assert_eq!(
        context(&testnet, VAULT_HEIGHT, None).flags(),
        vault | Flags::PqFalcon
    );
}

// ---- ownerSpends[]: post-quantum owners -----------------------------------------------------

#[test]
fn vault_vectors_owner_spends_through_the_verifier() {
    let vectors = load_pinned("vault_vectors.json");
    let sets = VectorSets::new(&vectors);
    let testnet = vault_testnet();
    let regtest = vault_regtest();
    let spends = vectors["ownerSpends"].as_array().expect("ownerSpends");
    let (mut by_script, mut released, mut falcon) = (0, 0, 0);

    for spend in spends {
        let name = name_of(spend);
        let tx = prepared(spend, &testnet, 0);
        let input = n_in(spend);
        let is_falcon = name.contains("falcon");

        match spend["verify"].as_str() {
            // Selector 2, the OWNER branch: OP_CHECKPQSIG over the ZIP-243 SIGHASH_ALL digest.
            Some("script") => {
                by_script += 1;
                for state in [None, Some(SetState::new()), Some(sets.state())] {
                    assert_eq!(
                        tx.is_valid_in(input, &context(&testnet, SPEND_HEIGHT, state)),
                        Ok(()),
                        "{name}: the owner spend verifies"
                    );
                }
                // A different amount changes the digest: the signature no longer verifies.
                let wrong = prepared(spend, &testnet, 1);
                assert!(
                    wrong
                        .is_valid_in(input, &context(&testnet, SPEND_HEIGHT, None))
                        .is_err(),
                    "{name}: the digest commits to the amount"
                );
                if is_falcon {
                    falcon += 1;
                    // Without Falcon (regtest's default) scheme 0x02 is refused.
                    assert_eq!(
                        interpreter_error(
                            tx.is_valid_in(input, &context(&regtest, SPEND_HEIGHT, None))
                        ),
                        Some(interpreter::Error::PqScheme),
                        "{name}"
                    );
                } else {
                    assert_eq!(
                        tx.is_valid_in(input, &context(&regtest, SPEND_HEIGHT, None)),
                        Ok(()),
                        "{name}: SLH-DSA needs no Falcon flag"
                    );
                }
            }
            // Selector 3, OWNER-RELEASED: OP_CHECKSETDORMANT reads the snapshot.
            Some("signature") => {
                released += 1;
                // An unknown set is released (§15.4): the owner may spend.
                assert_eq!(
                    tx.is_valid_in(
                        input,
                        &context(&testnet, SPEND_HEIGHT, Some(SetState::new()))
                    ),
                    Ok(()),
                    "{name}: released when the set is unknown"
                );
                // A live set holds the output.
                assert!(
                    tx.is_valid_in(input, &context(&testnet, SPEND_HEIGHT, Some(sets.state())))
                        .is_err(),
                    "{name}: a live set is not released"
                );
                // A dormant one (no member acted within the liveness window) releases it.
                let dormant_at = i64::from(SPEND_HEIGHT) + i64::from(sets.body.liveness_window) + 1;
                let dormant_height = u32::try_from(dormant_at).expect("a small height");
                assert_eq!(
                    tx.is_valid_in(
                        input,
                        &context(&testnet, dormant_height, Some(sets.state()))
                    ),
                    Ok(()),
                    "{name}: released once the set is dormant"
                );
                // No snapshot: never released (fail closed).
                assert!(
                    tx.is_valid_in(input, &context(&testnet, SPEND_HEIGHT, None))
                        .is_err(),
                    "{name}: no snapshot, not released"
                );
            }
            other => panic!("{name}: unknown verify kind {other:?}"),
        }

        // Before the upgrade (no Vault flag) 0xc0..0xc2 are bad opcodes.
        assert_eq!(
            interpreter_error(tx.is_valid_in(
                input,
                &context(&testnet, VAULT_HEIGHT - 1, Some(SetState::new()))
            )),
            Some(interpreter::Error::BadOpcode),
            "{name}: a bad opcode before Vault"
        );
        // So does upstream's context-free entry point.
        assert!(tx.is_valid(input).is_err(), "{name}");
    }
    assert_eq!(
        (by_script, released, falcon),
        (2, 2, 1),
        "two owner-branch spends (one Falcon) and two released spends"
    );
}

// ---- spends[]: set-signed unlock and cancel -------------------------------------------------

#[test]
fn vault_vectors_set_spends_through_the_verifier() {
    let vectors = load_pinned("vault_vectors.json");
    let sets = VectorSets::new(&vectors);
    let testnet = vault_testnet();
    let regtest = vault_regtest();
    let spends = vectors["spends"].as_array().expect("spends");
    assert_eq!(spends.len(), 2, "an unlock and a cancel");

    for spend in spends {
        let name = name_of(spend);
        let tx = prepared(spend, &testnet, 0);
        let input = n_in(spend);
        let is_unlock = name == "unlock";

        // The vectors' set state: both signatures (or the one) recover to current members.
        for network in [&testnet, &regtest] {
            assert_eq!(
                tx.is_valid_in(input, &context(network, SPEND_HEIGHT, Some(sets.state()))),
                Ok(()),
                "{name}: the set-signed spend verifies"
            );
        }

        let fails = |state: Option<SetState>, height: u32, why: &str| {
            assert_eq!(
                interpreter_error(tx.is_valid_in(input, &context(&testnet, height, state))),
                Some(interpreter::Error::SetSig),
                "{name}: {why}"
            );
        };
        fails(None, SPEND_HEIGHT, "no snapshot: no threshold");
        // The set signature commits to this input's amount (ZIP-243, ALL | ANYONECANPAY).
        assert_eq!(
            interpreter_error(
                prepared(spend, &testnet, 1)
                    .is_valid_in(input, &context(&testnet, SPEND_HEIGHT, Some(sets.state())))
            ),
            Some(interpreter::Error::SetSig),
            "{name}: another amount"
        );
        fails(Some(SetState::new()), SPEND_HEIGHT, "an unknown set");
        // The members joined, but their seats are not matured at the spending height.
        let unmatured = i64::from(SPEND_HEIGHT) - i64::from(sets.body.maturity) + 1;
        fails(
            Some(sets.state_with(2, unmatured)),
            SPEND_HEIGHT,
            "seats not matured",
        );
        // A member that left no longer signs for the set.
        let mut removed = sets.state();
        for record in removed.members.values_mut() {
            record.status = MemberStatus::Removed;
        }
        fails(Some(removed), SPEND_HEIGHT, "members removed");
        if is_unlock {
            // A higher threshold needs more signatures than the stack holds before the
            // selector, or fewer recovered members than required.
            fails(Some(sets.state_with(3, 0)), SPEND_HEIGHT, "threshold 3");
            // A threshold of 1 takes one signature and leaves the other: the second signature
            // alone is checked, and it is by member-1 over the right message, so the spend
            // succeeds with one fewer required signature — the threshold is the set's.
            assert_eq!(
                tx.is_valid_in(
                    input,
                    &context(&testnet, SPEND_HEIGHT, Some(sets.state_with(1, 0)))
                ),
                Ok(()),
                "{name}: threshold 1 consumes the top signature"
            );
        }

        // Before Vault, OP_CHECKSETSIG is a bad opcode.
        assert_eq!(
            interpreter_error(tx.is_valid_in(
                input,
                &context(&testnet, VAULT_HEIGHT - 1, Some(sets.state()))
            )),
            Some(interpreter::Error::BadOpcode),
            "{name}"
        );
    }
}

// ---- pq_vectors.json spends -----------------------------------------------------------------

/// The `pq_vectors` spends sign the key entry's 32-byte `msg`, not a transaction digest, so they
/// run through the Ycash checker with a sighash callback that returns that message (the C++ test
/// does the same with its mock checker). The verification itself is `kogany_pq::verify`.
#[test]
fn pq_vectors_spends_through_the_ycash_checker() {
    let pq = load_pinned("pq_vectors.json");
    let vault = load_pinned("vault_vectors.json");
    // Any transaction with a transparent input: the checker reads only its input's fields.
    let transaction: Transaction = hex_field(&vault["ownerSpends"][0], "tx")
        .zcash_deserialize_into()
        .expect("the vector transaction parses");
    let keys = pq["keys"].as_array().expect("keys");
    let spends = pq["spends"].as_array().expect("spends");
    assert!(!spends.is_empty());
    let testnet = vault_testnet();
    let regtest = vault_regtest();
    let mut schemes = Vec::new();

    for spend in spends {
        let scheme = u8::try_from(int_field(spend, "scheme")).expect("a scheme byte");
        let key = &keys[usize::try_from(int_field(spend, "key")).expect("a key index")];
        let msg: [u8; 32] = hex_field(key, "msg").try_into().expect("a 32-byte message");
        let raw = script::Raw::from_raw_parts(
            hex_field(spend, "scriptSig"),
            hex_field(spend, "scriptPubKey"),
        );
        let eval = |network: &Network, msg: [u8; 32]| {
            let sighash = move |_: &script::Code, _: &zcash_script::signature::HashType| Some(msg);
            let base = CallbackTransactionSignatureChecker {
                sighash: &sighash,
                lock_time: 0,
                is_final: true,
            };
            let ctx = context(network, SPEND_HEIGHT, None);
            let checker = YcashSignatureChecker::new(base, &transaction, 0, &ctx)
                .expect("input 0 spends a prevout");
            raw.eval(ctx.flags(), &checker)
        };

        assert_eq!(eval(&testnet, msg), Ok(true), "scheme {scheme}: verifies");
        let mut other = msg;
        other[0] ^= 1;
        assert_eq!(
            eval(&testnet, other),
            Ok(false),
            "scheme {scheme}: another message pushes false"
        );
        let without_falcon = eval(&regtest, msg);
        if scheme == zcash_script::vault::pq::SCHEME_FN_DSA_512 {
            assert!(
                matches!(
                    without_falcon,
                    Err((
                        _,
                        script::Error::Interpreter(_, interpreter::Error::PqScheme)
                    ))
                ),
                "scheme {scheme}: refused without Falcon: {without_falcon:?}"
            );
        } else {
            assert_eq!(without_falcon, Ok(true), "scheme {scheme}");
        }
        schemes.push(scheme);
    }
    schemes.sort_unstable();
    schemes.dedup();
    assert_eq!(schemes, [1, 2], "both schemes are exercised");
}

// ---- OP_CHECKSEQUENCEVERIFY from nSequence --------------------------------------------------

/// A v4 transaction whose input 0 has `sequence` and an empty scriptSig, spending
/// `<144> OP_CHECKSEQUENCEVERIFY OP_DROP OP_1`.
fn csv_spend(sequence: u32) -> CachedFfiTransaction {
    let vectors = load_pinned("vault_vectors.json");
    let mut transaction: Transaction = hex_field(&vectors["ownerSpends"][0], "tx")
        .zcash_deserialize_into()
        .expect("the vector transaction parses");
    let Transaction::V4 { inputs, .. } = &mut transaction else {
        panic!("a v4 vector transaction");
    };
    let Some(transparent::Input::PrevOut {
        unlock_script,
        sequence: input_sequence,
        ..
    }) = inputs.first_mut()
    else {
        panic!("input 0 spends a prevout");
    };
    *unlock_script = transparent::Script::new(&[]);
    *input_sequence = sequence;
    // 144 = 0x90 0x00 as a minimal script number; 0xb2 0x75 0x51.
    let lock_script = transparent::Script::new(&[0x02, 0x90, 0x00, 0xb2, 0x75, 0x51]);
    let outputs = transaction
        .inputs()
        .iter()
        .map(|_| transparent::Output {
            value: Amount::try_from(1_000).expect("a valid amount"),
            lock_script: lock_script.clone(),
        })
        .collect();
    CachedFfiTransaction::new(
        Arc::new(transaction),
        Arc::new(outputs),
        NetworkUpgrade::Vault,
    )
    .expect("a v4 transaction is valid under Vault")
}

#[test]
fn check_sequence_reads_the_input_sequence() {
    let regtest = vault_regtest();
    let at = |height| context(&regtest, height, None);

    assert_eq!(csv_spend(144).is_valid_in(0, &at(SPEND_HEIGHT)), Ok(()));
    assert_eq!(csv_spend(145).is_valid_in(0, &at(SPEND_HEIGHT)), Ok(()));
    // The upper bits of nSequence beyond the mask do not count.
    assert_eq!(
        csv_spend(144 | 0x0001_0000).is_valid_in(0, &at(SPEND_HEIGHT)),
        Ok(())
    );
    for (sequence, why) in [
        (143, "a shorter relative lock"),
        (0, "no relative lock"),
        (
            144 | interpreter::SEQUENCE_LOCKTIME_DISABLE_FLAG,
            "the input's lock disabled",
        ),
        (
            144 | interpreter::SEQUENCE_LOCKTIME_TYPE_FLAG,
            "a time-based input lock",
        ),
        (u32::MAX, "a final input"),
    ] {
        assert_eq!(
            interpreter_error(csv_spend(sequence).is_valid_in(0, &at(SPEND_HEIGHT))),
            Some(interpreter::Error::UnsatisfiedLockTime),
            "{why}"
        );
    }
    // Before Vault 0xb2 is OP_NOP3: the same v4 transaction passes whatever its sequence.
    for sequence in [0, 143, u32::MAX] {
        assert_eq!(
            csv_spend(sequence).is_valid_in(0, &at(VAULT_HEIGHT - 1)),
            Ok(())
        );
        assert_eq!(csv_spend(sequence).is_valid(0), Ok(()));
    }
}
