// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

//! Ycash (kogany W7-e): ycashd's reject codes and texts at the RPC surface.
//!
//! kogany's verifiers keep Zakura's typed errors (`TransactionError`, `ValidateContextError`,
//! `zakura_script::Error`, the mempool's policy errors) and the vault primitive's
//! [`VaultReject`]; plan §4.2 rule 4 (iii) compares verdicts by class. The wallets and the
//! shared regtest scripts, though, match ycashd's strings: `sendrawtransaction` answers
//! `-26 "<code>: <reason>"` (`ycash6 src/rpc/rawtransaction.cpp:1359`), `-25 "Missing inputs"`
//! (`:1362`), `-27 "transaction already in block chain"` (`:1368`), and `submitblock` answers the
//! BIP 22 reason (`src/rpc/mining.cpp` `BIP22ValidationResult`). This module is the one table
//! from the first to the second ([`CxxReject`]); the two RPCs render through it under the `ycash`
//! feature and nothing else changes. Every reason cites the `ycash6` (`65cb4ae0f`) line that
//! raises it.
//!
//! The match over `TransactionError` names every variant, so a variant added upstream or by a
//! later chunk does not build under `ycash` until it has a row here (`ValidateContextError` is
//! `#[non_exhaustive]`: a new variant renders as [`CxxReject::Unmapped`] until it gets one).

use std::error::Error as StdError;

use kogany_vault::state::VaultReject;
use zakura_consensus::{error::TransactionError, BlockError, RouterError, VerifyBlockError};
use zakura_state::{CommitBlockError, ValidateContextError};
use zcash_script::{
    interpreter::Error as InterpreterError, script::Error as ScriptError,
    signature::Error as SignatureError,
};

#[cfg(test)]
mod tests;

/// `REJECT_INVALID` (`src/consensus/validation.h:35`).
pub const REJECT_INVALID: u16 = 0x10;
/// `REJECT_DUPLICATE` (`validation.h:37`).
pub const REJECT_DUPLICATE: u16 = 0x12;
/// `REJECT_NONSTANDARD` (`validation.h:38`).
pub const REJECT_NONSTANDARD: u16 = 0x40;
/// `REJECT_INSUFFICIENTFEE` (`validation.h:40`).
pub const REJECT_INSUFFICIENTFEE: u16 = 0x42;
/// `REJECT_HIGHFEE` (`src/main.h:759`).
pub const REJECT_HIGHFEE: u16 = 0x100;
/// `REJECT_CONFLICT` (`main.h:763`).
pub const REJECT_CONFLICT: u16 = 0x102;

/// `RPC_TRANSACTION_ERROR` (`src/rpc/protocol.h`).
pub const RPC_TRANSACTION_ERROR: i32 = -25;
/// `RPC_TRANSACTION_REJECTED`.
pub const RPC_TRANSACTION_REJECTED: i32 = -26;
/// `RPC_TRANSACTION_ALREADY_IN_CHAIN`.
pub const RPC_TRANSACTION_ALREADY_IN_CHAIN: i32 = -27;

/// `TX_EXPIRING_SOON_THRESHOLD` (`src/main.h:108`).
pub const TX_EXPIRING_SOON_THRESHOLD: u32 = 3;
/// `DEFAULT_TRANSACTION_MAXFEE`, 0.1 YEC (`src/main.h:77`): `sendrawtransaction` refuses a larger
/// fee unless `allowhighfees`.
pub const DEFAULT_TRANSACTION_MAXFEE: i64 = 10_000_000;

/// The prefix of a mandatory script failure (`src/main.cpp:2233,3092`).
pub const MANDATORY_SCRIPT_FAILED: &str = "mandatory-script-verify-flag-failed";
/// The prefix of a policy-flag script failure (`src/main.cpp:3087`).
pub const NON_MANDATORY_SCRIPT_FAILED: &str = "non-mandatory-script-verify-flag";

/// What ycashd would have answered for a kogany rejection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CxxReject {
    /// `CValidationState::Invalid`/`DoS` with a reject code and reason: `-26 "<code>: <reason>"`
    /// from `sendrawtransaction`, `<reason>` from `submitblock`.
    Reject {
        /// The reject code (`REJECT_*`).
        code: u16,
        /// The reason string.
        reason: String,
    },
    /// The inputs are not in the chain or the mempool: `-25 "Missing inputs"`, and for a block
    /// `bad-txns-inputs-missingorspent` (`src/consensus/tx_verify` `CheckTxInputs`).
    MissingInputs,
    /// The transaction is already mined: `-27 "transaction already in block chain"`.
    AlreadyInChain,
    /// The mempool already holds it: ycashd skips `AcceptToMemoryPool` and answers the txid
    /// (`rawtransaction.cpp:1338-1372`).
    InMempool,
    /// No ycashd counterpart: the error cannot happen on a Ycash network (a Zcash-only rule) or
    /// is node-internal. Rendered as an invalid reject with Zakura's text, so its class stays
    /// reject-consensus.
    Unmapped(String),
}

impl CxxReject {
    fn reject(code: u16, reason: impl Into<String>) -> Self {
        CxxReject::Reject {
            code,
            reason: reason.into(),
        }
    }

    fn invalid(reason: impl Into<String>) -> Self {
        Self::reject(REJECT_INVALID, reason)
    }

    /// The JSON-RPC error code and message of `sendrawtransaction`, `None` for
    /// [`CxxReject::InMempool`] (an accept).
    pub fn rpc_error(&self) -> Option<(i32, String)> {
        Some(match self {
            CxxReject::Reject { code, reason } => {
                (RPC_TRANSACTION_REJECTED, format!("{code}: {reason}"))
            }
            CxxReject::MissingInputs => (RPC_TRANSACTION_ERROR, "Missing inputs".to_owned()),
            CxxReject::AlreadyInChain => (
                RPC_TRANSACTION_ALREADY_IN_CHAIN,
                "transaction already in block chain".to_owned(),
            ),
            CxxReject::InMempool => return None,
            CxxReject::Unmapped(text) => (
                RPC_TRANSACTION_REJECTED,
                format!("{REJECT_INVALID}: {text}"),
            ),
        })
    }

    /// The BIP 22 reason `submitblock` returns for a block this error makes invalid.
    pub fn block_reason(&self) -> String {
        match self {
            CxxReject::Reject { reason, .. } => reason.clone(),
            CxxReject::MissingInputs => "bad-txns-inputs-missingorspent".to_owned(),
            CxxReject::AlreadyInChain | CxxReject::InMempool => "duplicate".to_owned(),
            CxxReject::Unmapped(_) => "rejected".to_owned(),
        }
    }
}

/// Where a rejection was found: ycashd words some rules differently in `AcceptToMemoryPool` and
/// in `ConnectBlock`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Context {
    /// `sendrawtransaction` / `AcceptToMemoryPool`.
    Mempool,
    /// `submitblock` / `ConnectBlock`.
    Block,
}

/// A vault primitive or module rejection: `REJECT_INVALID` and [`VaultReject::reason`], in the
/// mempool (`main.cpp:2204`) and in a block (`main.cpp:4351`). A module's own reason
/// ([`VaultReject::Module`]) passes through as the module wrote it.
pub fn vault_reject(reject: &VaultReject) -> CxxReject {
    CxxReject::invalid(reject.reason())
}

/// A YED module verdict: `REJECT_INVALID` `bad-yellowback-<verdict>`, in the mempool
/// (`main.cpp:2259-2260`) and in a block (`kogany_yellowback::state::BlockEvaluation::verdict`).
pub fn yed_verdict(verdict: &str) -> CxxReject {
    CxxReject::invalid(format!("bad-yellowback-{verdict}"))
}

/// ycashd's `ScriptErrorString` (`src/script/script_error.cpp`) for a script failure, which
/// zakura-script keeps so the verifiers' own refusal texts use it too (S5).
pub use zakura_script::script_error_string;

/// Whether ycashd raises `error` only under `STANDARD_SCRIPT_VERIFY_FLAGS` beyond the mandatory
/// ones (`src/policy/policy.h:57-65`: MINIMALDATA, NULLDUMMY, DISCOURAGE_UPGRADABLE_NOPS,
/// CLEANSTACK, LOW_S): a policy failure, `REJECT_NONSTANDARD` (`main.cpp:3085-3087`).
fn is_policy_script_error(error: &zakura_script::Error) -> bool {
    let zakura_script::Error::Interpreter { error, .. } = error else {
        return false;
    };
    matches!(
        error,
        ScriptError::CleanStack
            | ScriptError::Interpreter(
                _,
                InterpreterError::MinimalData
                    | InterpreterError::SigNullDummy
                    | InterpreterError::DiscourageUpgradableNOPs
                    | InterpreterError::SignatureEncoding(SignatureError::SigHighS)
            )
    )
}

/// A script failure: `16: mandatory-script-verify-flag-failed (<ScriptErrorString>)`, or
/// `64: non-mandatory-script-verify-flag (<…>)` for a policy flag (`main.cpp:3085-3092`).
pub fn script_reject(error: &zakura_script::Error) -> CxxReject {
    let text = script_error_string(error);
    if is_policy_script_error(error) {
        CxxReject::reject(
            REJECT_NONSTANDARD,
            format!("{NON_MANDATORY_SCRIPT_FAILED} ({text})"),
        )
    } else {
        CxxReject::invalid(format!("{MANDATORY_SCRIPT_FAILED} ({text})"))
    }
}

/// A transaction verifier error (mempool or block).
pub fn transaction_reject(error: &TransactionError, context: Context) -> CxxReject {
    use TransactionError as E;
    let mempool = context == Context::Mempool;
    let unmapped = || CxxReject::Unmapped(error.to_string());
    match error {
        // main.cpp:2198-2202 (vault::CheckTx in AcceptToMemoryPool, W4-d follow-up): the reason is ycashd's own.
        E::VaultRejected { reason, .. } => CxxReject::invalid(reason.clone()),
        // main.cpp:2229-2232 (W6-c): a template input failing on the set state, DoS 0.
        E::VaultTemplateSetState { script_error, .. } => {
            CxxReject::invalid(format!("{MANDATORY_SCRIPT_FAILED} ({script_error})"))
        }
        // main.cpp:3085-3087 (W6-c): the mempool retry without the standard-not-mandatory flags.
        E::NonMandatoryScriptFlag { script_error, .. } => CxxReject::reject(
            REJECT_NONSTANDARD,
            format!("{NON_MANDATORY_SCRIPT_FAILED} ({script_error})"),
        ),
        // main.cpp:3060-3075 (S5): a signature made for the previous epoch's branch ID, DoS 10.
        E::OldConsensusBranchId { expected, found } => CxxReject::invalid(format!(
            "old-consensus-branch-id (Expected {expected:08x}, found {found:08x})"
        )),
        // main.cpp:1979-1983 (W6-c): IsStandardTx before vault::CheckTx.
        E::NonStandardTransaction { reason } => {
            CxxReject::reject(REJECT_NONSTANDARD, reason.clone())
        }
        // main.cpp:2259-2260 (W6-c): the YED module's mempool verdict, DoS 0.
        E::YellowbackRejected { reason } => CxxReject::invalid(format!("bad-yellowback-{reason}")),
        // main.cpp:6059-6063, 1975 (a loose coinbase), 1870.
        E::CoinbasePosition | E::NotCoinbase => CxxReject::invalid("bad-cb-missing"),
        E::CoinbaseAfterFirst => CxxReject::invalid("bad-cb-multiple"),
        E::CoinbaseInMempool => CxxReject::invalid("coinbase"),
        E::NonCoinbaseHasCoinbaseInput => CxxReject::invalid("bad-txns-prevout-null"),
        // main.cpp:1836-1861, 1154, 1184.
        E::CoinbaseHasJoinSplit => CxxReject::invalid("bad-cb-has-joinsplits"),
        E::CoinbaseHasSpend => CxxReject::invalid("bad-cb-has-spend-description"),
        E::CoinbaseHasOutputPreHeartwood => CxxReject::invalid("bad-cb-has-output-description"),
        E::CoinbaseHasEnableSpendsOrchard | E::CoinbaseHasOrchardShieldedData => {
            CxxReject::invalid("bad-cb-has-orchard-spend")
        }
        E::CoinbaseOutputsNotDecryptable => CxxReject::invalid("bad-cb-output-desc-invalid-ct"),
        // main.cpp:1986 (mempool, CheckFinalTx) and 6220 (block, ContextualCheckBlock).
        E::LockedUntilAfterBlockHeight { .. } | E::LockedUntilAfterBlockTime { .. } => {
            if mempool {
                CxxReject::reject(REJECT_NONSTANDARD, "non-final")
            } else {
                CxxReject::invalid("bad-txns-nonfinal")
            }
        }
        // main.cpp:1300-1311, 1054.
        E::MaximumExpiryHeight { .. } => CxxReject::invalid("bad-tx-expiry-height-too-high"),
        E::ExpiredTransaction { .. } => CxxReject::invalid("tx-overwinter-expired"),
        E::Subsidy(subsidy) => CxxReject::invalid(subsidy_reason(subsidy)),
        // main.cpp:1557, 1569.
        E::WrongVersion => CxxReject::invalid("bad-txns-version-too-low"),
        E::UnsupportedByNetworkUpgrade { .. } => CxxReject::invalid("bad-tx-version-group-id"),
        // main.cpp:1597, 1612, 1638.
        E::NoInputs => CxxReject::invalid("bad-txns-no-source-of-funds"),
        E::NoOutputs => CxxReject::invalid("bad-txns-no-sink-of-funds"),
        E::BadBalance => CxxReject::invalid("bad-txns-valuebalance-nonzero"),
        // A block's scripts are checked in parallel, whose failure carries no reason
        // (main.cpp:4337-4338, `state.DoS(100, false)`): BIP 22 "rejected".
        E::Script(script) => {
            if mempool {
                script_reject(script)
            } else {
                CxxReject::Unmapped(error.to_string())
            }
        }
        // main.cpp:2295-2298, 1481, 1509.
        E::SaplingVerificationFailed
        | E::Groth16 { .. }
        | E::MalformedGroth16 { .. }
        | E::RedJubjub { .. } => CxxReject::invalid("bad-sapling-bundle-authorization"),
        E::SmallOrder => CxxReject::invalid("bad-txns-sapling-bundle-invalid"),
        E::Halo2VerificationFailed | E::RedPallas { .. } => {
            CxxReject::invalid("bad-orchard-bundle-authorization")
        }
        E::Ed25519 { .. } => CxxReject::invalid("bad-txns-joinsplit-verification-failed"),
        // main.cpp:1731, 1193, 1631-1775, 3003-3006.
        E::BothVPubsNonZero => CxxReject::invalid("bad-txns-vpubs-both-nonzero"),
        E::DisabledAddToSproutPool => CxxReject::invalid("bad-txns-vpub_old-nonzero"),
        E::IncorrectFee => CxxReject::invalid("bad-txns-in-belowout"),
        E::Balance { .. } => CxxReject::invalid("bad-txns-valuebalance-toolarge"),
        E::Amount { .. } => CxxReject::invalid("bad-txns-txouttotal-toolarge"),
        // CheckTransactionWithoutProofVerification: bad-txns-inputs-duplicate; the shielded
        // duplicates (main.cpp:1798-1825).
        E::DuplicateTransparentSpend { .. } => CxxReject::invalid("bad-txns-inputs-duplicate"),
        E::DuplicateSproutNullifier { .. } => {
            CxxReject::invalid("bad-joinsplits-nullifiers-duplicate")
        }
        E::DuplicateSaplingNullifier { .. } => {
            CxxReject::invalid("bad-spend-description-nullifiers-duplicate")
        }
        E::DuplicateOrchardNullifier { .. } => {
            CxxReject::invalid("bad-orchard-nullifiers-duplicate")
        }
        E::NotEnoughFlags => CxxReject::invalid("bad-tx-orchard-flags-disable-actions"),
        // main.cpp:2025-2031: no coins for an input is "Missing inputs" (no reject code).
        E::TransparentInputNotFound => CxxReject::MissingInputs,
        E::ValidateContextError(context_error) => context_reject(context_error, context),
        // main.cpp:2958, 2969.
        E::ImmatureTransparentCoinbaseSpend { .. } => {
            CxxReject::invalid("bad-txns-premature-spend-of-coinbase")
        }
        E::UnshieldedTransparentCoinbaseSpend { .. } => {
            CxxReject::invalid("bad-txns-coinbase-spend-has-transparent-outputs")
        }
        E::Zip317(zip317) => zip317_reject(zip317),
        // policy.cpp:142-146 (IsStandardTx), main.cpp:2071 (AreInputsStandard).
        E::NonStandardScriptSigSize { .. } => {
            CxxReject::reject(REJECT_NONSTANDARD, "scriptsig-size")
        }
        E::NonStandardScriptSigNotPushOnly { .. } => {
            CxxReject::reject(REJECT_NONSTANDARD, "scriptsig-not-pushonly")
        }
        E::NonStandardInputs => {
            CxxReject::reject(REJECT_NONSTANDARD, "bad-txns-nonstandard-inputs")
        }
        // main.cpp:1266, 1276.
        E::WrongConsensusBranchId | E::WrongConsensusBranchIdNu6_3GracePeriod => {
            CxxReject::invalid("bad-tx-consensus-branch-id-mismatch")
        }
        E::MissingConsensusBranchId => CxxReject::invalid("bad-tx-consensus-branch-id-missing"),
        // main.cpp:1663-1675.
        E::SaplingIOsExceedBlockLimit { .. } => {
            CxxReject::invalid("bad-tx-too-many-sapling-spends")
        }
        E::OrchardActionsExceedBlockLimit { .. } => {
            CxxReject::invalid("bad-tx-too-many-orchard-actions")
        }
        // Zcash-only rules (NU5 coinbase expiry, NU6.3 pools, Ironwood, ZIP 234 budgets, proof
        // sizes) that a Ycash network never reaches, and node-internal failures.
        E::CoinbaseExpiryBlockHeight { .. }
        | E::CoinbaseHasEnableSpendsIronwood
        | E::CoinbaseConstruction { .. }
        | E::InternalDowncastError { .. }
        | E::DisabledAddToOrchardPool
        | E::DuplicateIronwoodNullifier { .. }
        | E::NotEnoughIronwoodFlags
        | E::OrchardHasEnableCrossAddress
        | E::ValidateMempoolLockTimeError { .. }
        | E::IronwoodActionsExceedBlockLimit { .. }
        | E::SproutJoinSplitsExceedBlockLimit { .. }
        | E::ShieldedCostExceedsBlockBudget { .. }
        | E::Io { .. }
        | E::TryFromSlice { .. }
        | E::OrchardProofSize
        | E::IronwoodProofSize
        | E::Other { .. } => unmapped(),
    }
}

fn subsidy_reason(error: &zakura_chain::parameters::subsidy::SubsidyError) -> &'static str {
    use zakura_chain::parameters::subsidy::SubsidyError as S;
    match error {
        // main.cpp:6264, 6281.
        S::FoundersRewardNotFound | S::FundingStreamNotFound => "cb-no-founders-reward",
        S::NoCoinbase => "bad-cb-missing",
        // main.cpp:4331.
        _ => "bad-cb-amount",
    }
}

fn zip317_reject(error: &zakura_chain::transaction::zip317::Error) -> CxxReject {
    use zakura_chain::transaction::zip317::Error as Z;
    match error {
        // main.cpp:2161.
        Z::UnpaidActions => {
            CxxReject::reject(REJECT_INSUFFICIENTFEE, "tx unpaid action limit exceeded")
        }
        // main.cpp:2132.
        Z::FeeBelowMinimumRate => {
            CxxReject::reject(REJECT_INSUFFICIENTFEE, "min relay fee not met")
        }
        // main.cpp:2146.
        Z::PerSaplingOutputFee => CxxReject::reject(
            REJECT_INSUFFICIENTFEE,
            "insufficient per-Sapling-output fee",
        ),
        #[allow(unreachable_patterns)]
        _ => CxxReject::Unmapped(error.to_string()),
    }
}

/// A contextual (chain state) error, in a transaction or in a block.
pub fn context_reject(error: &ValidateContextError, context: Context) -> CxxReject {
    use ValidateContextError as E;
    let mempool = context == Context::Mempool;
    match error {
        // main.cpp:905 (fMempool ? 0 : 100, the same reason).
        E::VaultTimeLock { .. } => CxxReject::invalid("bad-txns-vault-timelock"),
        // W4-d: the vault primitive's (or a module's) reason, as ycash6 `src/vault/state.cpp`
        // writes it (main.cpp:4351; in the mempool main.cpp:2204).
        E::VaultRejected { reason, .. } => CxxReject::invalid(reason.clone()),
        // W5-f, F-S5-4: the YED module's block verdict, `bad-yellowback-<verdict>` (DoS 100; the
        // reason ycash6's ConnectBlock gives the block, main.cpp:2260 in the mempool).
        E::YedRejected { reason, .. } => CxxReject::invalid(reason.clone()),
        // main.cpp:907-910.
        E::UnsatisfiedSequenceLock { .. } => {
            if mempool {
                CxxReject::reject(REJECT_NONSTANDARD, "non-BIP68-final")
            } else {
                CxxReject::invalid("bad-txns-nonfinal")
            }
        }
        // main.cpp:2025-2035: a spent input of a known transaction (mempool), or
        // CheckTxInputs in a block.
        E::DuplicateTransparentSpend { .. } => {
            if mempool {
                CxxReject::reject(REJECT_DUPLICATE, "bad-txns-inputs-spent")
            } else {
                CxxReject::invalid("bad-txns-inputs-missingorspent")
            }
        }
        E::MissingTransparentOutput { .. } | E::EarlyTransparentSpend { .. } => {
            CxxReject::MissingInputs
        }
        E::UnshieldedTransparentCoinbaseSpend { .. } => {
            CxxReject::invalid("bad-txns-coinbase-spend-has-transparent-outputs")
        }
        E::ImmatureTransparentCoinbaseSpend { .. } => {
            CxxReject::invalid("bad-txns-premature-spend-of-coinbase")
        }
        E::DuplicateSproutNullifier { .. } => {
            CxxReject::invalid("bad-joinsplits-nullifiers-duplicate")
        }
        E::DuplicateSaplingNullifier { .. } => {
            CxxReject::invalid("bad-spend-description-nullifiers-duplicate")
        }
        E::DuplicateOrchardNullifier { .. } => {
            CxxReject::invalid("bad-orchard-nullifiers-duplicate")
        }
        E::UnknownSproutAnchor { .. } => CxxReject::invalid("bad-txns-sprout-unknown-anchor"),
        E::UnknownSaplingAnchor { .. } => CxxReject::invalid("bad-txns-sapling-unknown-anchor"),
        E::UnknownOrchardAnchor { .. } => CxxReject::invalid("bad-txns-orchard-unknown-anchor"),
        // main.cpp:3003-3006, 1753-1775.
        E::NegativeRemainingTransactionValue { .. } => CxxReject::invalid("bad-txns-in-belowout"),
        E::CalculateRemainingTransactionValue { .. }
        | E::CalculateTransactionValueBalances { .. } => {
            CxxReject::invalid("bad-txns-inputvalues-outofrange")
        }
        // main.cpp:3646-3662, 4181-4187.
        E::CalculateBlockChainValueChange { .. } | E::AddValuePool { .. } => {
            CxxReject::invalid("turnstile-violation-total")
        }
        // main.cpp:4251-4274.
        E::InvalidBlockCommitment { .. } => CxxReject::invalid("bad-heartwood-root-in-block"),
        // main.cpp:6140, 6161, 6132, 6326.
        E::TimeTooEarly { .. } => CxxReject::invalid("time-too-old"),
        E::TimeTooLate { .. } => CxxReject::invalid("time-too-new"),
        E::InvalidDifficultyThreshold { .. } => CxxReject::invalid("bad-diffbits"),
        E::OrphanedBlock { .. } | E::NonSequentialBlock { .. } => CxxReject::invalid("bad-prevblk"),
        // BIP 22 "duplicate-invalid": a block already known to be invalid.
        E::BlockPreviouslyInvalidated { .. }
        | E::InvalidAncestorBlock { .. }
        | E::AncestorBodyRejected { .. } => CxxReject::invalid("duplicate-invalid"),
        E::MissingSproutTipTree { .. }
        | E::NotReadyToBeCommitted { .. }
        | E::VctSuppliedRootUnavailable { .. }
        | E::VctSuppliedRootAwaitingSuccessor { .. }
        | E::VctBlockAuthDataRootMismatch { .. }
        | E::VctSproutHandoffRootMismatch { .. }
        | E::CumulativeWorkOverflow { .. }
        | E::DuplicateIronwoodNullifier { .. }
        | E::NegativeNsmValueBalance { .. }
        | E::NoteCommitmentTreeError { .. }
        | E::HistoryTreeError { .. }
        | E::UnknownIronwoodAnchor { .. } => CxxReject::Unmapped(error.to_string()),
        // The enum is `#[non_exhaustive]`: a variant added later answers with Zakura's text
        // until it gets a row above.
        _ => CxxReject::Unmapped(error.to_string()),
    }
}

/// The first vault primitive rejection in `error`'s source chain, for the chunks that wire
/// [`VaultReject`] into the verifiers (plan W4-c/d, W5-f): an error variant that carries it as its
/// `source` is rendered without a row here.
fn find_vault_reject<'a>(error: &'a (dyn StdError + 'static)) -> Option<&'a VaultReject> {
    let mut next = Some(error);
    while let Some(error) = next {
        if let Some(reject) = error.downcast_ref::<VaultReject>() {
            return Some(reject);
        }
        next = error.source();
    }
    None
}

/// A rejected block's reason (BIP 22, `submitblock`): ycashd's `CValidationState` reason for the
/// first failing rule kogany found; `"rejected"` where it has none (an empty reason in ycashd).
pub fn block_reject(error: &RouterError) -> String {
    if let Some(reject) = find_vault_reject(error) {
        return vault_reject(reject).block_reason();
    }
    let source = match error {
        RouterError::Checkpoint { .. } => return "checkpoint mismatch".to_owned(),
        RouterError::Block { source } => source.as_ref(),
    };
    match source {
        VerifyBlockError::Transaction(error) => {
            transaction_reject(error, Context::Block).block_reason()
        }
        VerifyBlockError::Subsidy(error) => subsidy_reason(error).to_owned(),
        VerifyBlockError::Commit(CommitBlockError::ValidateContextError(error)) => {
            context_reject(error, Context::Block).block_reason()
        }
        VerifyBlockError::Commit(CommitBlockError::Duplicate { .. }) => "duplicate".to_owned(),
        VerifyBlockError::Block { source } => match source {
            BlockError::Transaction(error) => {
                transaction_reject(error, Context::Block).block_reason()
            }
            BlockError::NoTransactions => "bad-cb-missing".to_owned(),
            BlockError::BadMerkleRoot { .. } => "bad-txnmrklroot".to_owned(),
            BlockError::DuplicateTransaction => "bad-txns-duplicate".to_owned(),
            BlockError::AlreadyInChain(..) => "duplicate".to_owned(),
            BlockError::MissingHeight(..) => "bad-cb-height".to_owned(),
            BlockError::InvalidDifficulty(..)
            | BlockError::TargetDifficultyLimit(..)
            | BlockError::DifficultyFilter(..) => "high-hash".to_owned(),
            BlockError::WrongTransactionConsensusBranchId => {
                "bad-tx-consensus-branch-id-mismatch".to_owned()
            }
            BlockError::TooManyTransparentSignatureOperations { .. } => "bad-blk-sigops".to_owned(),
            _ => "rejected".to_owned(),
        },
        VerifyBlockError::Equihash { .. } => "invalid-solution".to_owned(),
        VerifyBlockError::Time(_) => "time-too-new".to_owned(),
        _ => "rejected".to_owned(),
    }
}

/// The rendering of a mempool rejection as it reaches `sendrawtransaction`: a typed
/// [`MempoolRejection`] from the transaction downloader (`zakurad`'s `ycash` hook), a
/// [`VaultReject`] in the error's source chain, or one of the mempool storage's policy errors,
/// whose types live in `zakurad` and are recognised by their (stable, upstream) texts.
pub fn mempool_reject(error: &(dyn StdError + 'static)) -> CxxReject {
    if let Some(rejection) = error.downcast_ref::<MempoolRejection>() {
        return rejection.reject.clone();
    }
    if let Some(reject) = find_vault_reject(error) {
        return vault_reject(reject);
    }
    let mut text = String::new();
    let mut next = Some(error);
    while let Some(error) = next {
        text.push_str(&error.to_string());
        text.push('\n');
        next = error.source();
    }
    storage_text_reject(&text).unwrap_or_else(|| CxxReject::Unmapped(error.to_string()))
}

/// The mempool storage's rejections (`zakurad` `components/mempool/{error,storage}.rs`), by
/// their texts, with ycashd's reason for the same rule.
pub const STORAGE_TEXTS: &[(&str, u16, &str)] = &[
    // MempoolError::InMempool: answered with the txid (`InMempool` below).
    ("transaction already exists in mempool", 0, ""),
    // TransactionDownloadVerifyError::InState, SameEffectsChainRejectionError::Mined.
    ("transaction is already in state", 0, ""),
    ("transaction was committed to the best chain", 0, ""),
    // SameEffectsTipRejectionError::SpendConflict: main.cpp:2006.
    (
        "another transaction in the mempool has already spent some of",
        REJECT_CONFLICT,
        "txn-mempool-conflict",
    ),
    // MissingOutput: an unconfirmed parent that is not there.
    ("spends missing outputs from", 0, ""),
    // Too many ancestors or a too large package: main.cpp:2178.
    (
        "unconfirmed transactions in the mempool",
        REJECT_NONSTANDARD,
        "too-long-mempool-chain",
    ),
    (
        "connected unconfirmed dependency group",
        REJECT_NONSTANDARD,
        "too-long-mempool-chain",
    ),
    // SameEffectsChainRejectionError.
    (
        "best chain tip has reached transaction expiry height",
        REJECT_INVALID,
        "tx-overwinter-expired",
    ),
    (
        "were spent, or nullifiers were revealed, in the best chain",
        REJECT_DUPLICATE,
        "bad-txns-inputs-spent",
    ),
    // ExactTipRejectionError::FailedStandard(NonStandardTransactionError): policy.cpp:142-193,
    // main.cpp:1970, 2071, 2091, 2161, 1118.
    (
        "transaction is expiring soon",
        REJECT_INVALID,
        "tx-expiring-soon",
    ),
    ("transaction is dust", REJECT_NONSTANDARD, "dust"),
    (
        "transaction scriptSig is too large",
        REJECT_NONSTANDARD,
        "scriptsig-size",
    ),
    (
        "transaction scriptSig is not push-only",
        REJECT_NONSTANDARD,
        "scriptsig-not-pushonly",
    ),
    (
        "transaction scriptPubKey is non-standard",
        REJECT_NONSTANDARD,
        "scriptpubkey",
    ),
    (
        "transaction has a bare multisig output",
        REJECT_NONSTANDARD,
        "bare-multisig",
    ),
    (
        "transaction has multiple OP_RETURN outputs",
        REJECT_NONSTANDARD,
        "multi-op-return",
    ),
    (
        "OP_RETURN output that exceeds the size limit",
        REJECT_NONSTANDARD,
        "scriptpubkey",
    ),
    (
        "transaction has too many signature operations",
        REJECT_NONSTANDARD,
        "bad-txns-too-many-sigops",
    ),
    (
        "transaction has non-standard inputs",
        REJECT_NONSTANDARD,
        "bad-txns-nonstandard-inputs",
    ),
    (
        "more unpaid actions than the configured limit",
        REJECT_INSUFFICIENTFEE,
        "tx unpaid action limit exceeded",
    ),
    (
        "exceeding the configured mempool maximum",
        REJECT_INVALID,
        "bad-txns-oversize",
    ),
    // A full mempool: ycashd has no equivalent below its size limit.
    (
        "mempool is full and it pays too low a fee",
        REJECT_INSUFFICIENTFEE,
        "mempool full",
    ),
];

/// The prefix of the mempool storage's policy-flag script failure (W6-a,
/// `NonStandardTransactionError::NonMandatoryScriptVerifyFlag`), followed by `input <n>: ` and
/// ycashd's `ScriptErrorString`.
const STORAGE_NON_MANDATORY: &str = "(non-mandatory-script-verify-flag): input ";

fn storage_text_reject(text: &str) -> Option<CxxReject> {
    // main.cpp:3085-3087: `64: non-mandatory-script-verify-flag (<ScriptErrorString>)`.
    if let Some((_, rest)) = text.split_once(STORAGE_NON_MANDATORY) {
        let script_error = rest
            .split_once(": ")
            .map_or(rest, |(_, error)| error)
            .lines()
            .next()
            .unwrap_or_default();
        return Some(CxxReject::reject(
            REJECT_NONSTANDARD,
            format!("{NON_MANDATORY_SCRIPT_FAILED} ({script_error})"),
        ));
    }
    STORAGE_TEXTS.iter().find_map(|(needle, code, reason)| {
        text.contains(needle).then(|| match (*needle, *code) {
            ("transaction already exists in mempool", _) => CxxReject::InMempool,
            (
                "transaction is already in state" | "transaction was committed to the best chain",
                _,
            ) => CxxReject::AlreadyInChain,
            (_, 0) => CxxReject::MissingInputs,
            _ => CxxReject::reject(*code, *reason),
        })
    })
}

/// The error `zakurad`'s transaction downloader returns to `sendrawtransaction` under the `ycash`
/// feature: its upstream text, and ycashd's answer computed from the typed error before the text
/// was made.
#[derive(Clone, Debug)]
pub struct MempoolRejection {
    message: String,
    /// ycashd's answer.
    pub reject: CxxReject,
}

impl MempoolRejection {
    /// A rejection with the downloader's `message`, rendering `error` (the verifier's error, if
    /// the transaction reached it) or the `message` itself.
    pub fn new(message: String, error: Option<&TransactionError>) -> Self {
        let reject = match error {
            Some(error) => transaction_reject(error, Context::Mempool),
            None => storage_text_reject(&message)
                .unwrap_or_else(|| CxxReject::Unmapped(message.clone())),
        };
        Self { message, reject }
    }
}

impl std::fmt::Display for MempoolRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl StdError for MempoolRejection {}

/// `sendrawtransaction`'s check before `AcceptToMemoryPool` (`rawtransaction.cpp:1306-1317`):
/// from Overwinter, a transaction whose expiry height is set and below `next height + 3` is
/// refused with `-26 "tx-expiring-soon: …"` (no reject code).
pub fn expiring_soon(expiry_height: u32, next_height: u32) -> Option<(i32, String)> {
    let floor = next_height.saturating_add(TX_EXPIRING_SOON_THRESHOLD);
    (expiry_height > 0 && floor > expiry_height).then(|| {
        (
            RPC_TRANSACTION_REJECTED,
            format!(
                "tx-expiring-soon: expiryheight is {expiry_height} but should be at least \
                 {floor} to avoid transaction expiring soon"
            ),
        )
    })
}

/// `sendrawtransaction`'s absurd-fee refusal (`main.cpp:2164-2168`, `rawtransaction.cpp:1348-1357`):
/// `-26 "256: absurdly-high-fee, absurdly high fees <txid>, <fee> > <maxtxfee>"`.
pub fn absurd_fee(txid: &str, fee: i64) -> Option<(i32, String)> {
    (fee > DEFAULT_TRANSACTION_MAXFEE).then(|| {
        (
            RPC_TRANSACTION_REJECTED,
            format!(
                "{REJECT_HIGHFEE}: absurdly-high-fee, absurdly high fees {txid}, {fee} > \
                 {DEFAULT_TRANSACTION_MAXFEE}"
            ),
        )
    })
}

/// `sendrawtransaction`'s answer for a mempool rejection `error` (the queue's or the
/// verifier's): `None` when ycashd would have answered the txid (the mempool already holds it),
/// else ycashd's error.
pub(crate) fn send_raw_transaction_error(
    error: &(dyn StdError + 'static),
) -> Option<crate::server::jsonrpc::ErrorObject> {
    let (code, message) = mempool_reject(error).rpc_error()?;
    Some(crate::server::jsonrpc::ErrorObject::new(code, message))
}

/// `sendrawtransaction`'s refusals before the mempool, in ycashd's order: an expiring-soon
/// transaction (`rawtransaction.cpp:1306-1317`), then, without `allowhighfees`, a fee above
/// [`DEFAULT_TRANSACTION_MAXFEE`] (`main.cpp:2164`, inside `AcceptToMemoryPool` there). The fee
/// is computed from the best chain's unspent outputs; a transaction spending an output the chain
/// does not hold (a mempool parent, or a missing input) skips the fee check and is answered by
/// the mempool.
pub(crate) async fn send_raw_transaction_prechecks<ReadState>(
    read_state: ReadState,
    network: &zakura_chain::parameters::Network,
    tip_height: Option<zakura_chain::block::Height>,
    transaction: &zakura_chain::transaction::Transaction,
    allow_high_fees: bool,
) -> Result<(), crate::server::jsonrpc::ErrorObject>
where
    ReadState: zakura_state::ReadState,
{
    use tower::ServiceExt;
    use zakura_chain::parameters::NetworkUpgrade;

    let next_height = tip_height.map_or(0, |height| height.0.saturating_add(1));
    let overwinter = NetworkUpgrade::Overwinter
        .activation_height(network)
        .is_some_and(|height| height.0 <= next_height);
    if let (true, Some(expiry)) = (overwinter, transaction.expiry_height()) {
        if let Some((code, message)) = expiring_soon(expiry.0, next_height) {
            return Err(crate::server::jsonrpc::ErrorObject::new(code, message));
        }
    }

    if allow_high_fees || transaction.is_coinbase() {
        return Ok(());
    }
    let mut utxos = std::collections::HashMap::new();
    for outpoint in transaction.spent_outpoints() {
        let response = read_state
            .clone()
            .oneshot(zakura_state::ReadRequest::UnspentBestChainUtxo(outpoint))
            .await;
        match response {
            Ok(zakura_state::ReadResponse::UnspentBestChainUtxo(Some(utxo))) => {
                utxos.insert(outpoint, utxo);
            }
            _ => return Ok(()),
        }
    }
    let Ok(fee) = transaction
        .value_balance(&utxos)
        .map_err(|_| ())
        .and_then(|balance| balance.remaining_transaction_value().map_err(|_| ()))
    else {
        return Ok(());
    };
    match absurd_fee(&transaction.hash().to_string(), fee.zatoshis()) {
        Some((code, message)) => Err(crate::server::jsonrpc::ErrorObject::new(code, message)),
        None => Ok(()),
    }
}

/// `submitblock`'s answer for a block that does not decode: ycashd throws
/// `-22 "Block decode failed"` (`src/rpc/mining.cpp` `submitblock`), Zakura answers `rejected`.
pub(crate) fn block_decode_failed() -> crate::server::jsonrpc::ErrorObject {
    crate::server::jsonrpc::ErrorObject::new(-22, "Block decode failed")
}

/// `getblocktemplate`'s `curtime` under `setmocktime` (W7-e): ycashd's
/// `max(MTP + 1, GetAdjustedTime())` reads the mock time (`src/miner.cpp` `UpdateTime`); the
/// state computed `cur_time` from the system clock, so the mock time replaces it, within the
/// template's `[mintime, maxtime]` as the state clamps it.
pub(crate) fn with_mock_cur_time(
    chain_info: zakura_state::GetBlockTemplateChainInfo,
) -> zakura_state::GetBlockTemplateChainInfo {
    with_cur_time(
        chain_info,
        crate::server::kogany_extension::mock_clock::mock_time(),
    )
}

/// `chain_info` with `cur_time` from `mock` (Unix seconds) when it is set.
fn with_cur_time(
    mut chain_info: zakura_state::GetBlockTemplateChainInfo,
    mock: Option<i64>,
) -> zakura_state::GetBlockTemplateChainInfo {
    if let Some(mock) = mock {
        // A mock time outside u32 is clamped to its range, then to the template's.
        let seconds = u32::try_from(mock.max(0)).unwrap_or(u32::MAX);
        chain_info.cur_time = zakura_chain::serialization::DateTime32::from(seconds)
            .clamp(chain_info.min_time, chain_info.max_time);
    }
    chain_info
}
