//! ycashd's `ScriptErrorString` (ycash6 `src/script/script_error.cpp`) for a script failure:
//! the text the Ycash reject reasons carry, `mandatory-script-verify-flag-failed (<text>)`
//! (kogany W7-e; used by zakura-rpc's reject table and the mempool's template-input check, S5).

use zcash_script::{
    interpreter::Error as InterpreterError,
    op,
    opcode::{self, PossiblyBad},
    script::Error as ScriptError,
    signature::Error as SignatureError,
};

use crate::Error;

/// ycashd's `ScriptErrorString` (`src/script/script_error.cpp`) for a script failure.
pub fn script_error_string(error: &Error) -> &'static str {
    match error {
        Error::ScriptInvalid => EVAL_FALSE,
        Error::Interpreter { error, .. } => script_error_text(error),
        Error::TxIndex | Error::TxCoinbase | Error::TxInvalid(_) => "unknown error",
        #[allow(unreachable_patterns)]
        _ => "unknown error",
    }
}

const EVAL_FALSE: &str =
    "Script evaluated without error but finished with a false/empty top stack element";

fn script_error_text(error: &ScriptError) -> &'static str {
    match error {
        ScriptError::ScriptSize(_) => "Script is too big",
        ScriptError::Opcode(opcode::Error::Read { .. }) => "Opcode missing or not understood",
        ScriptError::Opcode(opcode::Error::Disabled(_)) => "Attempted to use a disabled opcode",
        ScriptError::Opcode(opcode::Error::PushSize(_)) => "Push value size limit exceeded",
        ScriptError::SigPushOnly => "Only non-push operators allowed in signatures",
        ScriptError::Interpreter(op, error) => interpreter_error_text(op.as_ref(), error),
        ScriptError::ExternalError(_) => "unknown error",
        ScriptError::UnclosedConditional(_) => "Invalid OP_IF construction",
        // ycashd leaves a P2SH input with an empty stack as a false result.
        ScriptError::MissingRedeemScript => EVAL_FALSE,
        // CLEANSTACK has no ycashd text (Zcash never had the error string).
        ScriptError::CleanStack => "unknown error",
    }
}

fn interpreter_error_text(op: Option<&PossiblyBad>, error: &InterpreterError) -> &'static str {
    let opcode = match op {
        Some(PossiblyBad::Good(opcode)) => Some(opcode.clone()),
        _ => None,
    };
    match error {
        InterpreterError::OpReturn => "OP_RETURN was encountered",
        InterpreterError::OpCount => "Operation limit exceeded",
        InterpreterError::StackSize(_) => "Stack size limit exceeded",
        InterpreterError::SigCount(_) => "Signature count negative or greater than pubkey count",
        InterpreterError::PubKeyCount(_) => "Pubkey count negative or limit exceeded",
        InterpreterError::Verify => match opcode {
            Some(op::EQUALVERIFY) => "Script failed an OP_EQUALVERIFY operation",
            Some(op::NUMEQUALVERIFY) => "Script failed an OP_NUMEQUALVERIFY operation",
            Some(op::CHECKSIGVERIFY) => "Script failed an OP_CHECKSIGVERIFY operation",
            Some(op::CHECKMULTISIGVERIFY) => "Script failed an OP_CHECKMULTISIGVERIFY operation",
            _ => "Script failed an OP_VERIFY operation",
        },
        InterpreterError::BadOpcode => "Opcode missing or not understood",
        InterpreterError::InvalidStackOperation(_) => match opcode {
            Some(op::FROMALTSTACK) => "Operation not valid with the current altstack size",
            _ => "Operation not valid with the current stack size",
        },
        InterpreterError::UnbalancedConditional => "Invalid OP_IF construction",
        InterpreterError::NegativeLockTime => "Negative locktime",
        InterpreterError::UnsatisfiedLockTime => "Locktime requirement not satisfied",
        InterpreterError::SignatureEncoding(SignatureError::SigHashType(_)) => {
            "Signature hash type missing or not understood"
        }
        InterpreterError::SignatureEncoding(SignatureError::SigDER(_)) => {
            "Non-canonical DER signature"
        }
        InterpreterError::SignatureEncoding(SignatureError::SigHighS) => {
            "Non-canonical signature: S value is unnecessarily high"
        }
        InterpreterError::MinimalData => "Data push larger than necessary",
        InterpreterError::SigNullDummy => "Dummy CHECKMULTISIG argument must be zero",
        InterpreterError::PubKeyType => "Public key is neither compressed or uncompressed",
        InterpreterError::DiscourageUpgradableNOPs => "NOPx reserved for soft-fork upgrades",
        InterpreterError::SetSig => "OP_CHECKSETSIG or OP_CHECKSETDORMANT failed",
        InterpreterError::SetSigCount => "More than one OP_CHECKSETSIG in a script evaluation",
        InterpreterError::PqScheme => "OP_CHECKPQSIG scheme unknown or not active",
        InterpreterError::PqChunk => "OP_CHECKPQSIG key or signature chunking not canonical",
        InterpreterError::PqSize => "OP_CHECKPQSIG key, key hash or signature of the wrong size",
        InterpreterError::PqCount => "More than one OP_CHECKPQSIG in a script evaluation",
        InterpreterError::Num(_) => "unknown error",
    }
}

#[cfg(test)]
mod tests {
    use zcash_script::script::ComponentType;

    use super::*;

    /// The interpreter's own `Display` is not ycashd's text (S5 `vault_bridge`: "verify operation
    /// failed" where ycashd says "Script failed an OP_VERIFY operation").
    #[test]
    fn verify_failures_are_ycashds_texts() {
        let verify = |opcode| Error::Interpreter {
            component: ComponentType::PubKey,
            error: ScriptError::Interpreter(opcode, InterpreterError::Verify),
        };
        assert_eq!(
            script_error_string(&verify(None)),
            "Script failed an OP_VERIFY operation"
        );
        assert_eq!(
            script_error_string(&verify(Some(PossiblyBad::Good(op::EQUALVERIFY)))),
            "Script failed an OP_EQUALVERIFY operation"
        );
        assert_eq!(script_error_string(&Error::ScriptInvalid), EVAL_FALSE);
    }
}
