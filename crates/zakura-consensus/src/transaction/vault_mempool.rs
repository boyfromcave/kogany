// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

//! The Vault primitive's and the Yellowback (YED) module's mempool checks for the next block
//! (kogany plan W6-c `tip-recheck`).
//!
//! Ported by meaning from ycashd 6.22 (`ycash6` at `65cb4ae0f`), `src/main.cpp`
//! `AcceptToMemoryPool` and `src/vault/node.cpp`:
//!
//! - [`zakura_state::vault::mempool_vault_check`]: `vault::CheckTx(tx, coins, nextHeight, *vaultSnapshot, ...)`
//!   (`main.cpp:2197-2203`), scored by [`is_byte_level_act_failure`] (`IsByteLevelActFailure`,
//!   `node.cpp:517`): 10 for a malformed act no honest relay produces, else 0;
//! - [`check_template_input`]: the template (V/I) input's script checked alone, first, with the
//!   standard flags and the tip's set state (`main.cpp:2215-2234`): a failure that depends on the
//!   set state is refused at DoS 0 ([`TransactionError::VaultTemplateSetState`]); the standard
//!   script flags of the template input are checked here, where the set state is known (the
//!   mempool storage's standard re-run skips template inputs);
//! - [`yed_mempool_check`]: `MempoolCheckReason` (`main.cpp:2255-2261`), DoS 0.
//!
//! The transaction verifier runs them on every mempool request where the Vault upgrade is active
//! at the next height. The same verifier runs them again when the mempool re-checks a stored
//! transaction after the tip grows (`zakurad` `mempool::tip_recheck`, ycashd's
//! `RemoveInvalidVaultSpends` and `RecheckMempool` in `ConnectTip`).

use std::sync::Arc;

use kogany_vault::{
    act::{decode_act, is_act_output, ActError},
    template::{match_intent, match_vault, Shape},
};
use tower::{timeout::Timeout, Service, ServiceExt};
use zakura_chain::{
    block::Height,
    parameters::{Network, NetworkUpgrade},
    transaction::{self, Transaction},
    transparent,
};
use zakura_script::{CachedFfiTransaction, ScriptContext, VaultStateSnapshot};
use zakura_state as zs;
use zcash_script::interpreter;

use crate::{error::TransactionError, BoxError};

use super::check::ycash_standard::{
    find_vault_template_input, is_standard_tx, require_standard, vault_template_fails_on_set_state,
    RelayPolicy,
};

/// `MAX_OP_RETURN_RELAY` (ycash6 `script/standard.h`): an act output longer than this is what
/// `IsByteLevelActFailure` scores.
pub const MAX_OP_RETURN_RELAY: usize = 83;

/// The reasons `IsByteLevelActFailure` counts as byte-level (`bad-vault-act-sigs` only when
/// `DecodeAct` itself refused the output).
const BYTE_LEVEL_REASONS: [&str; 8] = [
    "bad-vault-act-malformed",
    "bad-vault-act-params",
    "bad-vault-act-type",
    "bad-vault-act-multi",
    "bad-vault-act-coinbase",
    "bad-vault-act-novin",
    "bad-vault-act-sig",
    "bad-txns-vault-malformed",
];

/// `IsByteLevelActFailure(reason, tx)`: is `reason` a byte-level failure no honest
/// pre-upgrade relay produces, with an act output longer than [`MAX_OP_RETURN_RELAY`]?
/// `bad-vault-act-sigs` counts only when `DecodeAct` itself rejected an act output for more
/// than `MAX_ACT_SIGS` signatures; a count mismatch from the set state stays false.
pub fn is_byte_level_act_failure<'a>(
    reason: &str,
    output_scripts: impl IntoIterator<Item = &'a [u8]> + Clone,
) -> bool {
    let byte_level = BYTE_LEVEL_REASONS.contains(&reason)
        || (reason == "bad-vault-act-sigs"
            && output_scripts
                .clone()
                .into_iter()
                .any(|spk| is_act_output(spk) && decode_act(spk) == Err(ActError::Sigs)));
    byte_level
        && output_scripts
            .into_iter()
            .any(|spk| is_act_output(spk) && spk.len() > MAX_OP_RETURN_RELAY)
}

/// Is `spk` V- or I-shaped (`MatchVault` / `MatchIntent` != `NONE`, a malformed shape
/// included)?
pub fn is_template_shaped(spk: &[u8]) -> bool {
    !matches!(match_vault(spk), Shape::NotTemplate)
        || !matches!(match_intent(spk), Shape::NotTemplate)
}

/// `IsVaultRelevant(tx, view)` (ycash6 `src/vault/node.cpp:128`): does `tx` touch the
/// primitive, through an act or a V/I-shaped output, an input spending a V/I-shaped coin
/// (`spent_scripts`, in input order), or an input spending an indexed member bond of `state`?
pub fn is_vault_relevant(
    tx: &Transaction,
    spent_scripts: &[transparent::Output],
    state: &VaultStateSnapshot,
) -> bool {
    if tx.outputs().iter().any(|o| {
        let spk = o.lock_script.as_raw_bytes();
        is_act_output(spk) || is_template_shaped(spk)
    }) {
        return true;
    }
    if tx.is_coinbase() {
        return false;
    }
    spent_scripts
        .iter()
        .any(|o| is_template_shaped(o.lock_script.as_raw_bytes()))
        || tx.inputs().iter().any(|input| {
            input
                .outpoint()
                .is_some_and(|outpoint| state.bond(&zs::vault::vault_outpoint(&outpoint)).is_some())
        })
}

/// ycashd's order for a transaction `zakura_state::vault::mempool_vault_check` refused: `IsStandardTx` (outputs
/// included) runs first where standardness is required, so a non-standard transaction is
/// reported as that (W6-a finding F-3, for the vault pair). The relay knobs are ycashd's
/// defaults (`-datacarriersize` 83; the mempool storage applies the configured ones).
pub fn non_standard_first(
    network: &Network,
    tx: &Transaction,
    height: Height,
) -> Option<TransactionError> {
    if !require_standard(network) {
        return None;
    }
    is_standard_tx(tx, network, height, &RelayPolicy::default())
        .err()
        .map(|reason| TransactionError::NonStandardTransaction {
            reason: reason.as_str().to_owned(),
        })
}

/// The interpreter error inside a script failure, if any.
fn interpreter_error(error: &zakura_script::Error) -> Option<interpreter::Error> {
    match error {
        zakura_script::Error::Interpreter {
            error: zcash_script::script::Error::Interpreter(_, error),
            ..
        } => Some(error.clone()),
        _ => None,
    }
}

/// The text of a template input's script failure (ycashd `ScriptErrorString`, S5:
/// `Script failed an OP_VERIFY operation`, not the interpreter's own `Display`).
fn script_error_text(error: &zakura_script::Error) -> String {
    zakura_script::script_error_string(error).to_owned()
}

/// The upgrade before the one current at `height` (ycashd `PrevEpochBranchId`), when it has a
/// different consensus branch ID.
fn previous_epoch(network: &Network, height: Height) -> Option<NetworkUpgrade> {
    let (current, activation_height) =
        NetworkUpgrade::current_with_activation_height(network, height);
    let previous = NetworkUpgrade::current(network, activation_height.previous().ok()?);
    (previous.branch_id().is_some() && previous.branch_id() != current.branch_id())
        .then_some(previous)
}

/// The template-input check of `AcceptToMemoryPool` (`main.cpp:2215-2234`): the first input
/// spending an exact V or I is run alone, with the standard flags and the set state at the tip
/// (`state`), for the block at `height`.
///
/// - It verifies: `Ok`.
/// - It fails on the set state (`VaultTemplateFailsOnSetState`, retried under the previous
///   epoch's branch ID): [`TransactionError::VaultTemplateSetState`] (DoS 0).
/// - It fails otherwise but passes the consensus flags: [`TransactionError::NonMandatoryScriptFlag`]
///   (ycashd `non-mandatory-script-verify-flag`, DoS 0).
/// - It fails the consensus flags too: `Ok`, and the verifier's own script check refuses the
///   transaction as ycashd's `ContextualCheckInputs` does.
pub fn check_template_input(
    network: &Network,
    tx: &Arc<Transaction>,
    cached: &CachedFfiTransaction,
    height: Height,
    state: &VaultStateSnapshot,
) -> Result<(), TransactionError> {
    if tx.is_coinbase() {
        return Ok(());
    }
    let spent_outputs = cached.all_previous_outputs();
    let Some(input_index) = find_vault_template_input(
        spent_outputs
            .iter()
            .map(|o| Some(o.lock_script.as_raw_bytes())),
    ) else {
        return Ok(());
    };
    let script_sig = match tx.inputs().get(input_index) {
        Some(transparent::Input::PrevOut { unlock_script, .. }) => {
            unlock_script.as_raw_bytes().to_vec()
        }
        _ => return Ok(()),
    };
    let standard =
        ScriptContext::new(network.clone(), height, Some(state.clone())).with_standard_policy();
    let current = NetworkUpgrade::current(network, height);
    let current_branch = current.branch_id().map_or(0, u32::from);
    let previous = previous_epoch(network, height);
    let previous_branch = previous
        .and_then(|nu| nu.branch_id())
        .map_or(current_branch, u32::from);

    let mut first_error = None;
    let fails_on_set_state =
        vault_template_fails_on_set_state(&script_sig, current_branch, previous_branch, |branch| {
            let result = if branch == current_branch {
                cached.is_valid_in(input_index, &standard)
            } else {
                match previous.map(|nu| {
                    CachedFfiTransaction::new(tx.clone(), Arc::new(spent_outputs.clone()), nu)
                }) {
                    Some(Ok(cached_previous)) => {
                        cached_previous.is_valid_in(input_index, &standard)
                    }
                    _ => Err(zakura_script::Error::ScriptInvalid),
                }
            };
            result.map_err(|error| {
                let inner = interpreter_error(&error);
                if branch == current_branch {
                    first_error = Some(error);
                }
                inner
            })
        });
    let Some(error) = first_error else {
        return Ok(());
    };
    if fails_on_set_state {
        return Err(TransactionError::VaultTemplateSetState {
            input_index,
            script_error: script_error_text(&error),
        });
    }
    let consensus = ScriptContext::new(network.clone(), height, Some(state.clone()));
    if cached.is_valid_in(input_index, &consensus).is_ok() {
        return Err(TransactionError::NonMandatoryScriptFlag {
            input_index,
            script_error: script_error_text(&error),
        });
    }
    Ok(())
}

/// ycashd's classification of a mempool script failure (`ContextualCheckInputs`,
/// `main.cpp:3076-3088`, W6-a finding F-4): the first input that fails the consensus flags at
/// `height` is retried with the mempool-mandatory flags
/// ([`ScriptContext::with_mempool_mandatory_flags`]: no `CHECKLOCKTIMEVERIFY`); if it passes
/// there, the failure is [`TransactionError::NonMandatoryScriptFlag`] (policy, DoS 0). `None`:
/// the failure stays the verifier's consensus script error.
pub fn non_mandatory_script_failure(
    network: &Network,
    cached: &CachedFfiTransaction,
    height: Height,
    state: Option<VaultStateSnapshot>,
) -> Option<TransactionError> {
    let consensus = ScriptContext::new(network.clone(), height, state);
    let mandatory = consensus.clone().with_mempool_mandatory_flags();
    let (input_index, error) = (0..cached.inputs().len()).find_map(|input_index| {
        cached
            .is_valid_in(input_index, &consensus)
            .err()
            .map(|error| (input_index, error))
    })?;
    cached
        .is_valid_in(input_index, &mandatory)
        .is_ok()
        .then(|| TransactionError::NonMandatoryScriptFlag {
            input_index,
            script_error: script_error_text(&error),
        })
}

/// `MempoolCheckReason` for the block at `height` (tip + 1): the YED module's verdict over the
/// YED state at the best chain tip. A tip that moved away from `height`'s parent is a retryable
/// error, as the vault snapshot's.
pub async fn yed_mempool_check<ZS>(
    state: Timeout<ZS>,
    tx: &Transaction,
    txid: &transaction::Hash,
    height: Height,
) -> Result<(), TransactionError>
where
    ZS: Service<zs::Request, Response = zs::Response, Error = BoxError> + Send + Clone + 'static,
    ZS::Future: Send + 'static,
{
    let expiry_height = tx.expiry_height().map_or(0, |h| h.0);
    let request =
        zs::Request::BestChainYedMempoolCheck(vec![(zs::vault::vault_tx(tx, txid), expiry_height)]);
    let zs::Response::YedMempoolCheck { tip, reasons } = state
        .oneshot(request)
        .await
        .map_err(|e| TransactionError::Other(e.to_string()))?
    else {
        unreachable!("Request::BestChainYedMempoolCheck always responds with YedMempoolCheck")
    };
    if tip.and_then(|(tip, _)| tip.next().ok()) != Some(height) {
        return Err(TransactionError::Other(format!(
            "the YED state is not at the parent of height {height:?}: the chain tip moved, retry"
        )));
    }
    match reasons.into_iter().next().flatten() {
        Some(reason) => Err(TransactionError::YellowbackRejected { reason }),
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A `YV` act output of `len` bytes: `OP_RETURN OP_PUSHDATA1 <n> "YV" <filler>`.
    fn act_output(len: usize) -> Vec<u8> {
        let pushed = u8::try_from(len - 3).expect("test act outputs are short");
        let mut spk = vec![0x6a, 0x4c, pushed, b'Y', b'V'];
        spk.resize(len, 0);
        assert!(is_act_output(&spk));
        spk
    }

    #[test]
    fn byte_level_act_failures_need_an_oversized_act_output() {
        let long = act_output(120);
        let short = act_output(60);
        assert!(long.len() > MAX_OP_RETURN_RELAY && short.len() <= MAX_OP_RETURN_RELAY);
        for reason in BYTE_LEVEL_REASONS {
            assert!(
                is_byte_level_act_failure(reason, [long.as_slice()]),
                "{reason}"
            );
            assert!(
                !is_byte_level_act_failure(reason, [short.as_slice()]),
                "{reason}"
            );
            assert!(
                !is_byte_level_act_failure(reason, [] as [&[u8]; 0]),
                "{reason}"
            );
        }
        // State-dependent reasons are never byte-level.
        for reason in [
            "bad-vault-act-noset",
            "bad-vault-act-exists",
            "bad-vault-bond-frozen",
            "bad-txns-vault-release",
            "bad-txns-vault-inputs-missing",
        ] {
            assert!(
                !is_byte_level_act_failure(reason, [long.as_slice()]),
                "{reason}"
            );
        }
        // `bad-vault-act-sigs` counts only when the act itself does not decode for that reason.
        assert!(!is_byte_level_act_failure(
            "bad-vault-act-sigs",
            [long.as_slice()]
        ));
    }

    #[test]
    fn the_new_verdicts_score_as_ycashd() {
        let byte_level = TransactionError::VaultRejected {
            reason: "bad-vault-act-malformed".into(),
            height: Height(10),
            byte_level: true,
        };
        assert_eq!(byte_level.mempool_misbehavior_score(), 10);
        for error in [
            TransactionError::VaultRejected {
                reason: "bad-vault-act-noset".into(),
                height: Height(10),
                byte_level: false,
            },
            TransactionError::VaultTemplateSetState {
                input_index: 0,
                script_error: "OP_CHECKSETSIG or OP_CHECKSETDORMANT failed".into(),
            },
            TransactionError::NonMandatoryScriptFlag {
                input_index: 0,
                script_error: "cleanstack".into(),
            },
            TransactionError::YellowbackRejected {
                reason: "mempool-expiry".into(),
            },
        ] {
            assert_eq!(error.mempool_misbehavior_score(), 0, "{error:?}");
        }
        // The texts carry ycashd's reasons, which the harness's verdict map reads.
        assert!(byte_level
            .to_string()
            .ends_with(": bad-vault-act-malformed"));
        assert!(TransactionError::YellowbackRejected {
            reason: "mint-6".into()
        }
        .to_string()
        .contains("bad-yellowback-mint-6"));
    }
}
