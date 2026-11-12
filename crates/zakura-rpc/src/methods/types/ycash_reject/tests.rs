//! The W7-e exit-gate tables: every reason of ycashd's two documented lists, and every reject
//! string the shared regtest scripts match, has a kogany source (or a recorded reason why kogany
//! cannot raise it), and the renderings are ycashd's texts.

use std::{collections::BTreeMap, path::PathBuf};

use kogany_vault::{act::ActError, state::VaultReject};
use kogany_yellowback::state::verdict;
use serde_json::Value;
use zakura_chain::block::Height;
use zakura_consensus::error::TransactionError;
use zakura_state::ValidateContextError;
use zcash_script::{
    interpreter::Error as InterpreterError, op, opcode::PossiblyBad, script::ComponentType,
    script::Error as ScriptError,
};

use super::*;

fn repo_file(path: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(path)
}

fn read_json(path: &str) -> Value {
    let text = std::fs::read_to_string(repo_file(path)).expect("the contract copy is in the tree");
    serde_json::from_str(&text).expect("the contract copy is JSON")
}

fn script(error: InterpreterError, opcode: Option<zcash_script::Opcode>) -> zakura_script::Error {
    zakura_script::Error::Interpreter {
        component: ComponentType::PubKey,
        error: ScriptError::Interpreter(opcode.map(PossiblyBad::Good), error),
    }
}

fn tx_message(reject: CxxReject) -> String {
    reject.rpc_error().expect("a rejection").1
}

fn mempool(error: TransactionError) -> String {
    tx_message(transaction_reject(&error, Context::Mempool))
}

fn block(error: TransactionError) -> String {
    transaction_reject(&error, Context::Block).block_reason()
}

fn context(error: ValidateContextError) -> TransactionError {
    TransactionError::from(error)
}

/// A one-input v4 spend of a coin at height 10 with `sequence`, checked at height 11 on a
/// regtest where Vault is active from height 1 (zakura-state's BIP68 check, W3-d).
fn bip68_error(sequence: u32) -> ValidateContextError {
    use zakura_chain::{
        parameters::{
            testnet::{ConfiguredActivationHeights, RegtestParameters},
            Network,
        },
        transaction::{self, LockTime, Transaction},
        transparent,
    };
    let network = Network::new_regtest(RegtestParameters::from(ConfiguredActivationHeights {
        vault: Some(1),
        ..Default::default()
    }));
    let outpoint = transparent::OutPoint {
        hash: transaction::Hash([1; 32]),
        index: 0,
    };
    let tx = Transaction::V4 {
        inputs: vec![transparent::Input::PrevOut {
            outpoint,
            unlock_script: transparent::Script::new(&[]),
            sequence,
        }],
        outputs: vec![],
        lock_time: LockTime::unlocked(),
        expiry_height: Height(0),
        joinsplit_data: None,
        sapling_shielded_data: None,
    };
    zakura_state::check::transparent_sequence_locks(&network, &tx, Height(11), |_| Some(Height(10)))
        .expect_err("the lock is not satisfied")
}

/// `UnsatisfiedSequenceLock`: a 5-block relative lock on a coin one block old.
fn sequence_lock() -> ValidateContextError {
    let error = bip68_error(5);
    assert!(matches!(
        error,
        ValidateContextError::UnsatisfiedSequenceLock { .. }
    ));
    error
}

/// `VaultTimeLock`: BIP68's type flag (time-based), which Vault makes invalid.
fn vault_time_lock() -> ValidateContextError {
    let error = bip68_error(1 << 22);
    assert!(matches!(error, ValidateContextError::VaultTimeLock { .. }));
    error
}

/// Every [`VaultReject`] variant, with the reason ycash6's `src/vault/state.cpp` writes.
fn vault_rejects() -> Vec<VaultReject> {
    use VaultReject as V;
    vec![
        V::ActMulti,
        V::Malformed,
        V::BondFrozen,
        V::BondLocked,
        V::InputsMissing,
        V::Preactivation,
        V::Multi,
        V::Selector,
        V::Intent,
        V::App,
        V::Covenant,
        V::Amount,
        V::Value,
        V::Rate,
        V::Release,
        V::Cancel,
        V::NoSet,
        V::ActDecode(ActError::Malformed),
        V::ActDecode(ActError::Version),
        V::ActDecode(ActError::Type),
        V::ActCoinbase,
        V::ActNoVin,
        V::ActSigs,
        V::ActParams,
        V::ActNoSet,
        V::ActWindDown,
        V::ActRemove,
        V::ActSig,
        V::ActExists,
        V::ActSeats,
        V::ActJoin,
        V::ActBond,
        V::ActHeartbeat,
        V::ActEquivocation,
    ]
}

fn vault_reason(reason: &str) -> Option<String> {
    vault_rejects()
        .iter()
        .find(|reject| reject.reason() == reason)
        .map(|reject| tx_message(vault_reject(reject)))
}

/// Where a reject string the scripts match comes from in kogany.
enum Source {
    /// kogany produces it today for the scripts' provocation; the rendering.
    Produced(String),
    /// The mapping exists (the rendering), but the provocation needs a chunk that has not
    /// landed: the vault set state in the verifiers (W4-c/d), the YED module (W5-f), the
    /// mempool's policy script flags (W3-c/W6-a).
    Pending(&'static str, String),
    /// kogany never raises it, by design.
    NotReachable(&'static str),
}

/// A mempool storage rejection's text, as `sendrawtransaction` renders it.
fn storage(text: &str) -> String {
    let error: Box<dyn StdError + Send + Sync> = text.into();
    tx_message(mempool_reject(error.as_ref()))
}

fn yed(reason: &str) -> String {
    tx_message(yed_verdict(reason))
}

/// The reject strings the 23 vault_*/yellowback_* scripts match at `sendrawtransaction` ("tx")
/// or `submitblock` ("block") (ycash6 `qa/rpc-tests` at `65cb4ae0f`: `reject`, `block_reject`,
/// `reject_both`, `assert_rpc_error`, `assert_raises_rpc`, `rpc_error`, `rpc_reject`,
/// `assert_mempool_rejects`, `assert_block_rejects` over `sendrawtransaction`/`submitblock`).
fn script_reasons() -> Vec<(&'static str, &'static str, Source)> {
    use Source::*;
    const VAULT: &str = "W6: the mempool's vault checks (kogany_vault::check_tx at the tip); \
                         a block carries them since W4-d (ValidateContextError::VaultRejected)";
    const YED: &str = "W5-f: the YED module registered on the vault primitive";
    let mut rows = vec![
        // Script failures (zakura_script::Error through TransactionError::Script).
        (
            "tx",
            "Locktime requirement not satisfied",
            Produced(mempool(TransactionError::Script(script(
                InterpreterError::UnsatisfiedLockTime,
                None,
            )))),
        ),
        (
            "tx",
            "mandatory-script-verify-flag-failed (Locktime requirement not satisfied)",
            Produced(mempool(TransactionError::Script(script(
                InterpreterError::UnsatisfiedLockTime,
                None,
            )))),
        ),
        (
            "tx",
            "OP_CHECKSETSIG or OP_CHECKSETDORMANT failed",
            Produced(mempool(TransactionError::Script(script(
                InterpreterError::SetSig,
                None,
            )))),
        ),
        (
            "tx",
            "Opcode missing or not understood",
            Produced(mempool(TransactionError::Script(script(
                InterpreterError::BadOpcode,
                None,
            )))),
        ),
        (
            "tx",
            "Script evaluated without error but finished with a false/empty top stack element",
            Produced(mempool(TransactionError::Script(
                zakura_script::Error::ScriptInvalid,
            ))),
        ),
        (
            "tx",
            "Script failed an OP_VERIFY operation",
            Produced(mempool(TransactionError::Script(script(
                InterpreterError::Verify,
                Some(op::VERIFY),
            )))),
        ),
        (
            "tx",
            "mandatory-script-verify-flag-failed",
            Produced(mempool(TransactionError::Script(script(
                InterpreterError::SetSig,
                None,
            )))),
        ),
        (
            "tx",
            "script-verify-flag",
            Produced(mempool(TransactionError::Script(
                zakura_script::Error::ScriptInvalid,
            ))),
        ),
        (
            "tx",
            "non-mandatory-script-verify-flag",
            Produced(storage(
                "transaction scripts fail a standard script verification flag \
                 (non-mandatory-script-verify-flag): input 0: NOPx reserved for soft-fork upgrades",
            )),
        ),
        (
            "tx",
            "old-consensus-branch-id",
            // S5: the mempool retries a failing input under the previous epoch's branch ID
            // (vault_mempool::non_mandatory_script_failure, main.cpp:3060-3075).
            Produced(mempool(TransactionError::OldConsensusBranchId {
                expected: 0x6d5b_7a31,
                found: 0xe9ff_75a6,
            })),
        ),
        (
            "tx",
            "old-consensus-branch-id (Expected %08x, found %08x)*",
            Produced(mempool(TransactionError::OldConsensusBranchId {
                expected: 0x6d5b_7a31,
                found: 0xe9ff_75a6,
            })),
        ),
        // Lock times.
        (
            "tx",
            "non-final",
            Produced(mempool(TransactionError::LockedUntilAfterBlockHeight(
                Height(20),
            ))),
        ),
        (
            "tx",
            "non-BIP68-final",
            Produced(mempool(context(sequence_lock()))),
        ),
        (
            "block",
            "bad-txns-nonfinal",
            Produced(block(context(sequence_lock()))),
        ),
        (
            "tx",
            "bad-txns-vault-timelock",
            Produced(mempool(context(vault_time_lock()))),
        ),
        (
            "block",
            "bad-txns-vault-timelock",
            Produced(block(context(vault_time_lock()))),
        ),
        (
            "tx",
            "expir",
            Produced(
                expiring_soon(12, 10)
                    .expect("an expiry below next + 3 is refused")
                    .1,
            ),
        ),
        // The wallet's YED-burn guard: a wallet check on ycashd, no wallet on kogany (K-3).
        (
            "tx",
            "yed-burn-refused",
            NotReachable(
                "a wallet guard (rawtransaction.cpp:1324-1336): kogany has no wallet (K-3); yewd \
                 applies it in front of kogany (W7-c allowyedburn)",
            ),
        ),
    ];

    // The vault primitive's rejections, through VaultReject::reason.
    for (rpc, reason) in [
        ("block", "bad-txns-vault-app"),
        ("block", "bad-txns-vault-preactivation"),
        ("block", "bad-vault-act-noset"),
        ("block", "bad-vault-act-params"),
        ("block", "bad-vault-bond-frozen"),
        ("tx", "bad-txns-vault-app"),
        ("tx", "bad-txns-vault-cancel"),
        ("tx", "bad-txns-vault-covenant"),
        ("tx", "bad-txns-vault-intent"),
        ("tx", "bad-txns-vault-malformed"),
        ("tx", "bad-txns-vault-multi"),
        ("tx", "bad-txns-vault-noset"),
        ("tx", "bad-txns-vault-preactivation"),
        ("tx", "bad-txns-vault-rate"),
        ("tx", "bad-txns-vault-release"),
        ("tx", "bad-txns-vault-selector"),
        ("tx", "bad-txns-vault-value"),
        ("tx", "bad-vault-act-bond"),
        ("tx", "bad-vault-act-equivocation"),
        ("tx", "bad-vault-act-heartbeat"),
        ("tx", "bad-vault-act-join"),
        ("tx", "bad-vault-act-malformed"),
        ("tx", "bad-vault-act-multi"),
        ("tx", "bad-vault-act-noset"),
        ("tx", "bad-vault-act-params"),
        ("tx", "bad-vault-act-remove"),
        ("tx", "bad-vault-act-seats"),
        ("tx", "bad-vault-act-sig"),
        ("tx", "bad-vault-act-sigs"),
        ("tx", "bad-vault-act-type"),
        ("tx", "bad-vault-act-version"),
        ("tx", "bad-vault-act-winddown"),
        ("tx", "bad-vault-bond-frozen"),
        ("tx", "bad-vault-bond-locked"),
    ] {
        let reject = vault_rejects()
            .into_iter()
            .find(|reject| reject.reason() == reason)
            .unwrap_or_else(|| panic!("no VaultReject for {reason}"));
        if rpc == "block" {
            // W4-d: check::vault renders a block's violation as VaultRejected { reason }.
            rows.push((rpc, reason, Produced(vault_reject(&reject).block_reason())));
        } else {
            rows.push((
                rpc,
                reason,
                Pending(VAULT, tx_message(vault_reject(&reject))),
            ));
        }
    }

    // The YED module's verdicts (bad-yellowback-<verdict>), and the module's set-act refusals,
    // which carry the same prefix.
    for (reason, verdict) in [
        ("bad-yellowback-*", verdict::BAD_MINT_COLLATERAL),
        ("bad-yellowback-bad-mint-amount", verdict::BAD_MINT_AMOUNT),
        (
            "bad-yellowback-bad-mint-collateral",
            verdict::BAD_MINT_COLLATERAL,
        ),
        (
            "bad-yellowback-bad-mint-owner-key",
            verdict::BAD_MINT_OWNER_KEY,
        ),
        (
            "bad-yellowback-bad-mint-vault-script",
            verdict::BAD_MINT_VAULT_SCRIPT,
        ),
        (
            "bad-yellowback-bad-redeem-early-fee",
            verdict::BAD_REDEEM_EARLY_FEE,
        ),
        ("bad-yellowback-bad-yed-holder", verdict::BAD_YED_HOLDER),
        ("bad-yellowback-mempool-expiry", "mempool-expiry"),
        (
            "bad-yellowback-mint-halted-unarmed",
            verdict::MINT_HALTED_UNARMED,
        ),
        (
            "bad-yellowback-vault-claim-not-underwater",
            verdict::VAULT_CLAIM_NOT_UNDERWATER,
        ),
        ("bad-yellowback-vault-spend", verdict::VAULT_SPEND_BAD_FEE),
        ("yellowback-vault-spend", verdict::VAULT_SPEND_BAD_PAYEE),
        ("intent-cancel-cosign", verdict::INTENT_CANCEL_COSIGN),
        ("intent-cancel-no-refund", verdict::INTENT_CANCEL_NO_REFUND),
        ("attestor-bond-below-min", verdict::ATTESTOR_BOND_BELOW_MIN),
        (
            "attestor-register-retired",
            verdict::ATTESTOR_REGISTER_RETIRED,
        ),
        ("attestor-revive-retired", verdict::ATTESTOR_REVIVE_RETIRED),
        ("attestor-set-act", verdict::ATTESTOR_SET_ACT),
    ] {
        rows.push(("tx", reason, Pending(YED, yed(verdict))));
    }
    rows
}

/// A script's pattern matches `message` the way the script does (`reason in message`; a
/// trailing `*` is a printf prefix).
fn matches(pattern: &str, message: &str) -> bool {
    match pattern.split_once('%') {
        Some((head, _)) => message.contains(head),
        None => message.contains(pattern.trim_end_matches('*')),
    }
}

#[test]
fn every_reason_the_scripts_match_has_a_kogany_source() {
    let mut pending = BTreeMap::new();
    for (rpc, pattern, source) in script_reasons() {
        match source {
            Source::Produced(rendered) => assert!(
                matches(pattern, &rendered),
                "{rpc} {pattern:?}: kogany renders {rendered:?}"
            ),
            Source::Pending(chunk, rendered) => {
                assert!(
                    matches(pattern, &rendered),
                    "{rpc} {pattern:?}: the mapping renders {rendered:?}"
                );
                *pending.entry(chunk).or_insert(0) += 1;
            }
            Source::NotReachable(why) => assert!(!why.is_empty()),
        }
    }
    // The vault primitive in the mempool (W6) and the YED module (W5-f).
    assert_eq!(pending.len(), 2, "{pending:?}");
}

#[test]
fn renderings_are_ycashd_texts() {
    assert_eq!(
        mempool(context(vault_time_lock())),
        "16: bad-txns-vault-timelock"
    );
    assert_eq!(mempool(context(sequence_lock())), "64: non-BIP68-final");
    assert_eq!(
        mempool(TransactionError::LockedUntilAfterBlockHeight(Height(20))),
        "64: non-final"
    );
    assert_eq!(
        mempool(TransactionError::Script(script(
            InterpreterError::Verify,
            Some(op::EQUALVERIFY)
        ))),
        "16: mandatory-script-verify-flag-failed (Script failed an OP_EQUALVERIFY operation)"
    );
    assert_eq!(
        mempool(TransactionError::Script(script(
            InterpreterError::DiscourageUpgradableNOPs,
            None
        ))),
        "64: non-mandatory-script-verify-flag (NOPx reserved for soft-fork upgrades)"
    );
    assert_eq!(
        transaction_reject(
            &TransactionError::TransparentInputNotFound,
            Context::Mempool
        )
        .rpc_error(),
        Some((-25, "Missing inputs".to_owned()))
    );
    assert_eq!(
        tx_message(vault_reject(&VaultReject::Rate)),
        "16: bad-txns-vault-rate"
    );
    assert_eq!(
        yed(verdict::BAD_MINT_COLLATERAL),
        "16: bad-yellowback-bad-mint-collateral"
    );
    assert_eq!(
        expiring_soon(12, 10),
        Some((
            -26,
            "tx-expiring-soon: expiryheight is 12 but should be at least 13 to avoid transaction \
             expiring soon"
                .to_owned()
        ))
    );
    assert_eq!(expiring_soon(13, 10), None);
    assert_eq!(expiring_soon(0, 10), None);
    assert_eq!(
        absurd_fee("ab", DEFAULT_TRANSACTION_MAXFEE + 1),
        Some((
            -26,
            "256: absurdly-high-fee, absurdly high fees ab, 10000001 > 10000000".to_owned()
        ))
    );
    assert_eq!(absurd_fee("ab", DEFAULT_TRANSACTION_MAXFEE), None);
}

#[test]
fn mempool_rejections_render_from_the_type_or_the_storage_text() {
    let typed = MempoolRejection::new(
        "failed to validate tx: x, error: …".to_owned(),
        Some(&context(vault_time_lock())),
    );
    let boxed: Box<dyn StdError + Send + Sync> = Box::new(typed);
    assert_eq!(
        mempool_reject(boxed.as_ref()).rpc_error(),
        Some((-26, "16: bad-txns-vault-timelock".to_owned()))
    );

    for (text, expected) in [
        (
            "transaction already exists in mempool",
            CxxReject::InMempool,
        ),
        (
            "failed to validate tx: x, error: transaction is already in state",
            CxxReject::AlreadyInChain,
        ),
        (
            "the transaction will be rejected from the mempool until the next chain tip block: \
             transaction did not pass standard validation: transaction is expiring soon",
            CxxReject::Reject {
                code: REJECT_INVALID,
                reason: "tx-expiring-soon".to_owned(),
            },
        ),
        (
            "transaction rejected because another transaction in the mempool has already spent \
             some of its inputs",
            CxxReject::Reject {
                code: REJECT_CONFLICT,
                reason: "txn-mempool-conflict".to_owned(),
            },
        ),
    ] {
        let error: Box<dyn StdError + Send + Sync> = text.into();
        assert_eq!(mempool_reject(error.as_ref()), expected, "{text}");
    }
    // W6-a's policy-flag failure, with ycashd's ScriptErrorString (zakurad ycash_policy.rs).
    assert_eq!(
        storage(
            "the transaction will be rejected from the mempool until the next chain tip block: \
             transaction did not pass standard validation: transaction scripts fail a standard \
             script verification flag (non-mandatory-script-verify-flag): input 0: Data push \
             larger than necessary"
        ),
        "64: non-mandatory-script-verify-flag (Data push larger than necessary)"
    );
    let in_mempool: Box<dyn StdError + Send + Sync> =
        "transaction already exists in mempool".into();
    assert!(send_raw_transaction_error(in_mempool.as_ref()).is_none());

    // A VaultReject anywhere in the source chain renders without a row.
    #[derive(Debug)]
    struct Wrapper(VaultReject);
    impl std::fmt::Display for Wrapper {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "vault: {}", self.0)
        }
    }
    impl StdError for Wrapper {
        fn source(&self) -> Option<&(dyn StdError + 'static)> {
            Some(&self.0)
        }
    }
    let wrapped: Box<dyn StdError + Send + Sync> = Box::new(Wrapper(VaultReject::ActSigs));
    assert_eq!(
        mempool_reject(wrapped.as_ref()).rpc_error(),
        Some((-26, "16: bad-vault-act-sigs".to_owned()))
    );
}

/// How kogany answers a reason of the C++ lists that is not a transaction rejection.
const NOT_TRANSACTION_REASONS: &[(&str, &str)] = &[
    (
        "is not active at the next block",
        "raised by every act and vault RPC: the wallet RPCs are yewd's; kogany's read RPCs \
         report activation in vault_getinfo",
    ),
    (
        "expiring-too-soon",
        "a YED wallet builder refusal (every builder): yewd",
    ),
    (
        "index-below-start",
        "a YED wallet builder refusal (every builder): yewd",
    ),
    ("wallet-locked", "a wallet refusal: yewd"),
    (
        "yed-locked-outpoint",
        "the stock lockunspent of the Yellowback wallet layer: yewd",
    ),
    (
        "yed-burn-refused",
        "the wallet guard of sendrawtransaction (H7): kogany has no wallet (K-3); yewd",
    ),
    (
        "mempool-check-failed:<verdict>",
        "yed_redeem/yed_claim (wallet): yewd; kogany's mempool answers bad-yellowback-<verdict>",
    ),
];

/// The identifier a contract row names (`mempool-check-failed:<verdict>` stays whole).
fn identifier(message: &str) -> &str {
    message
}

#[test]
fn every_documented_reason_has_a_kogany_source() {
    let openrpc = read_json("doc/kogany-rpc-openrpc.json");
    let served_by: BTreeMap<String, String> = openrpc["methods"]
        .as_array()
        .expect("methods")
        .iter()
        .map(|m| {
            (
                m["name"].as_str().expect("name").to_owned(),
                m["x-kogany-served-by"]
                    .as_str()
                    .expect("served-by")
                    .to_owned(),
            )
        })
        .collect();
    let kogany_sources: String = walk(&repo_file("crates/kogany-rpc/src"));

    let mut rows: Vec<(String, Vec<String>)> = Vec::new();
    let vault = read_json("doc/vault-rpc-contract.json");
    for error in vault["errors"].as_array().expect("vault errors") {
        rows.push((
            error["message"].as_str().expect("message").to_owned(),
            strings(&error["raisedBy"]),
        ));
    }
    let yed = read_json("doc/yellowback-rpc-contract.json");
    for (name, error) in yed["errors"].as_object().expect("yed errors") {
        rows.push((name.clone(), strings(&error["raisedBy"])));
    }
    assert!(rows.len() > 100, "both lists are read: {}", rows.len());

    let mut unexplained = Vec::new();
    let (mut transaction, mut kogany, mut yewd, mut other) = (0, 0, 0, 0);
    for (message, raised_by) in &rows {
        let id = identifier(message);
        if let Some(rendered) = vault_reason(id) {
            // A transaction rejection (set_join / set_sendact relay it from AcceptToMemoryPool).
            assert_eq!(rendered, format!("16: {id}"));
            transaction += 1;
        } else if raised_by.iter().any(|m| {
            served_by.get(m).is_some_and(|s| s == "kogany")
                // `yellowback-unhealthy` gates kogany's yed_* reads as well (W7-b).
                || m == "every gated command"
        }) {
            // A kogany read or node-state RPC raises it (W7-a/b, kogany-rpc).
            assert!(
                kogany_sources.contains(id),
                "{id}: raised by the kogany method(s) {raised_by:?}, absent from kogany-rpc"
            );
            kogany += 1;
        } else if !raised_by.is_empty()
            && raised_by
                .iter()
                .all(|m| served_by.get(m).is_some_and(|s| s == "yewd"))
        {
            // Every raiser is a wallet method yewd serves: not reachable in kogany.
            yewd += 1;
        } else if NOT_TRANSACTION_REASONS.iter().any(|(r, _)| *r == id) {
            other += 1;
        } else {
            unexplained.push((id.to_owned(), raised_by.clone()));
        }
    }
    assert!(unexplained.is_empty(), "no kogany source: {unexplained:#?}");
    assert_eq!(transaction + kogany + yewd + other, rows.len());
    assert!(
        transaction >= 1 && kogany >= 10 && yewd >= 30,
        "{transaction} {kogany} {yewd} {other}"
    );
}

fn strings(value: &Value) -> Vec<String> {
    value
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

fn walk(dir: &std::path::Path) -> String {
    let mut text = String::new();
    for entry in std::fs::read_dir(dir).expect("kogany-rpc is in the tree") {
        let path = entry.expect("a directory entry").path();
        if path.is_dir() {
            text.push_str(&walk(&path));
        } else if path.extension().is_some_and(|e| e == "rs") {
            text.push_str(&std::fs::read_to_string(&path).expect("a source file"));
        }
    }
    text
}

#[test]
fn block_reasons_are_bip22_strings() {
    let error = RouterError::Block {
        source: Box::new(VerifyBlockError::Transaction(context(vault_time_lock()))),
    };
    assert_eq!(block_reject(&error), "bad-txns-vault-timelock");
    let error = RouterError::Block {
        source: Box::new(VerifyBlockError::Block {
            source: BlockError::Transaction(context(sequence_lock())),
        }),
    };
    assert_eq!(block_reject(&error), "bad-txns-nonfinal");
    let error = RouterError::Block {
        source: Box::new(VerifyBlockError::Commit(
            CommitBlockError::ValidateContextError(Box::new(sequence_lock())),
        )),
    };
    assert_eq!(block_reject(&error), "bad-txns-nonfinal");
    // F-S5-4: the YED module's block verdict is its reason, not a bare "rejected".
    let error = RouterError::Block {
        source: Box::new(VerifyBlockError::Commit(
            CommitBlockError::ValidateContextError(Box::new(
                ValidateContextError::yed_rejected_for_test(
                    "bad-yellowback-vault-claim-not-underwater",
                    "vault-claim-not-underwater:00",
                    Height(300),
                ),
            )),
        )),
    };
    assert_eq!(
        block_reject(&error),
        "bad-yellowback-vault-claim-not-underwater"
    );
    assert_eq!(
        CxxReject::Unmapped("x".to_owned()).block_reason(),
        "rejected"
    );
    // ycashd checks a block's scripts in parallel: a failure has no reason.
    assert_eq!(
        block(TransactionError::Script(script(
            InterpreterError::SetSig,
            None
        ))),
        "rejected"
    );
}

#[test]
fn setmocktime_moves_the_template_cur_time() {
    // The pure step: the process clock is not touched, so the other template tests of this
    // binary keep the system clock.
    use zakura_chain::{
        block, serialization::DateTime32, value_balance::ValueBalance,
        work::difficulty::CompactDifficulty,
    };
    let info = zakura_state::GetBlockTemplateChainInfo {
        tip_hash: block::Hash([0; 32]),
        tip_height: Height(100),
        chain_history_root: None,
        expected_difficulty: CompactDifficulty::default(),
        cur_time: DateTime32::from(1_000_000),
        min_time: DateTime32::from(999_000),
        max_time: DateTime32::from(1_005_400),
        value_pools: ValueBalance::zero(),
    };
    // Unset: the state's clock stands.
    assert_eq!(with_cur_time(info.clone(), None).cur_time, info.cur_time);
    assert_eq!(
        with_cur_time(info.clone(), Some(1_001_801)).cur_time,
        DateTime32::from(1_001_801)
    );
    // Within [mintime, maxtime], as the state clamps the system clock.
    assert_eq!(
        with_cur_time(info.clone(), Some(2_000_000)).cur_time,
        info.max_time
    );
    assert_eq!(with_cur_time(info.clone(), Some(1)).cur_time, info.min_time);
}

/// S5 (`vault_primitive`): a signature over the previous epoch's branch ID is ycashd's
/// `old-consensus-branch-id (Expected <current>, found <previous>)`, REJECT_INVALID.
#[test]
fn old_consensus_branch_id_is_ycashds_text() {
    assert_eq!(
        mempool(TransactionError::OldConsensusBranchId {
            expected: 0x6d5b_7a31,
            found: 0xe9ff_75a6,
        }),
        "16: old-consensus-branch-id (Expected 6d5b7a31, found e9ff75a6)"
    );
}

#[test]
fn already_queued_is_waited_for() {
    let queued: Box<dyn std::error::Error> =
        "transaction dropped because it is already queued for download".into();
    assert!(is_already_queued(queued.as_ref()));
    let other: Box<dyn std::error::Error> = "transaction already exists in mempool".into();
    assert!(!is_already_queued(other.as_ref()));
}

/// The three header time rules answer ycashd's reasons: `time-too-old` (not after the
/// median-time-past, ycash6 `src/main.cpp:6138-6142`), `time-too-far-ahead-of-mtp` (more than
/// `MAX_FUTURE_BLOCK_TIME_MTP` past it, `:6149-6153`), `time-too-new` (more than
/// `MAX_FUTURE_BLOCK_TIME_LOCAL` past the local clock, `:6157-6161`).
#[test]
fn header_time_rules_answer_ycashd_reasons() {
    let now = chrono::DateTime::from_timestamp(1_794_297_367, 0).expect("in range");
    let early = ValidateContextError::TimeTooEarly {
        candidate_time: now,
        median_time_past: now,
    };
    let late = ValidateContextError::TimeTooLate {
        candidate_time: now,
        block_time_max: now - chrono::Duration::seconds(1),
    };
    assert_eq!(
        context_reject(&early, Context::Block).block_reason(),
        "time-too-old"
    );
    assert_eq!(
        context_reject(&late, Context::Block).block_reason(),
        "time-too-far-ahead-of-mtp"
    );
}
