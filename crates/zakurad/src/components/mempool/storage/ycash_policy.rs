// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

//! The Ycash mempool policy that depends on the tip or on the node's configuration (kogany
//! W1-Y9 `relay-ycash`, W6-a `standardness`). The network-wide fee rules (the minimum relay
//! fee and the per-Sapling-output floor) run earlier, in the transaction verifier
//! (`zakura_chain::transaction::ycash_relay`), as does the standardness pre-check before script
//! verification (`zakura_consensus::transaction::check::ycash_standard`).
//!
//! Ported by meaning from ycashd 6.22 (`ycash6` at `65cb4ae0f`), `src/main.cpp`
//! `AcceptToMemoryPool`, in its order:
//!
//! - `chainparams.RequireStandard()` gates `IsStandardTx` and `AreInputsStandard`
//!   (`main.cpp:1979,2070`): true on mainnet and testnet, false on regtest unless
//!   `-acceptnonstdtxn=0` (`chainparams.cpp:839,991-994`). From the Vault height both are
//!   ycash6's Vault-era rules (`ycash_standard::{is_standard_tx, are_inputs_standard}`);
//! - `IsExpiringSoonTx` (`main.cpp:1969-1971`);
//! - the sigop limit `MAX_STANDARD_TX_SIGOPS`, `OP_CHECKPQSIG`'s 20 policy sigops included
//!   (`main.cpp:2079-2091`), not gated;
//! - `-txunpaidactionlimit` (`main.cpp:2150-2162`), unlimited by default on Ycash;
//! - `STANDARD_SCRIPT_VERIFY_FLAGS` in every mempool, regtest included (`main.cpp:2234`): a
//!   transaction whose scripts pass the consensus flags but not the standard ones is refused
//!   (`non-mandatory-script-verify-flag`).

use zakura_chain::{
    block::Height,
    parameters::Network,
    transaction::{ycash_relay, VerifiedUnminedTx},
};
use zakura_consensus::transaction::check::ycash_standard::{
    self, NonStandardReason, RelayPolicy, MAX_STANDARD_TX_SIGOPS,
};

use super::{config, NonStandardTransactionError};

/// The resolved Ycash policy of one mempool.
#[derive(Clone, Debug, Default, PartialEq)]
pub(super) struct Policy {
    /// `!RequireStandard()`: skip the standardness checks (regtest only).
    pub(super) accept_non_standard: bool,
    /// `-txunpaidactionlimit`; `None` is ycashd's `SIZE_MAX`.
    pub(super) tx_unpaid_action_limit: Option<u32>,
    /// The network: its Vault and Falcon heights select the standardness rules. `None` (a
    /// storage built without a network) keeps Zakura's own standardness checks.
    network: Option<Network>,
    /// The data carrier limit and the other relay knobs.
    relay: RelayPolicy,
}

impl Policy {
    /// The policy for `network` (`None`: not regtest) from the mempool `config`.
    ///
    /// With a network, it also records the standardness configuration for the transaction
    /// verifier's pre-check (`ycash_standard::configure_relay_policy`).
    pub(super) fn new(config: &config::Config, network: Option<&Network>) -> Self {
        let regtest = network.is_some_and(Network::is_regtest);
        let accept_non_standard = regtest && config.accept_non_standard.unwrap_or(true);
        let relay = RelayPolicy {
            max_datacarrier_bytes: config
                .max_datacarrier_bytes
                .map_or(ycash_standard::MAX_OP_RETURN_RELAY, |n| {
                    usize::try_from(n).unwrap_or(usize::MAX)
                }),
            ..RelayPolicy::default()
        };
        if network.is_some() {
            ycash_standard::configure_relay_policy(
                config.accept_non_standard.unwrap_or(true),
                relay.max_datacarrier_bytes,
            );
        }
        Self {
            accept_non_standard,
            tx_unpaid_action_limit: config.tx_unpaid_action_limit,
            network: network.cloned(),
            relay,
        }
    }

    /// The Ycash standardness rules replace Zakura's `reject_if_non_standard_tx`.
    pub(super) fn replaces_standardness(&self) -> bool {
        self.network.is_some()
    }

    /// The first ycashd rule `tx` breaks at the tip `tip_height`, if any.
    pub(super) fn check(
        &self,
        tx: &VerifiedUnminedTx,
        tip_height: Option<Height>,
    ) -> Result<(), NonStandardTransactionError> {
        let transaction = tx.transaction.transaction().as_ref();
        let next_height = tip_height.and_then(|height| height.next().ok());
        let standard = self.network.as_ref().filter(|_| !self.accept_non_standard);

        if let (Some(network), Some(next_height)) = (standard, next_height) {
            ycash_standard::is_standard_tx(transaction, network, next_height, &self.relay)
                .map_err(non_standard_error)?;
        }

        if let Some(next_height) = next_height {
            if ycash_relay::is_expiring_soon(transaction, next_height) {
                return Err(NonStandardTransactionError::ExpiringSoon);
            }
        }

        if standard.is_some()
            && !ycash_standard::are_inputs_standard(transaction, &tx.spent_outputs, None)
        {
            return Err(NonStandardTransactionError::NonStandardInputs);
        }

        let sigops = tx
            .block_sigop_count()
            .saturating_add(ycash_standard::pq_sig_op_count(
                transaction,
                &tx.spent_outputs,
            ));
        if sigops > MAX_STANDARD_TX_SIGOPS {
            return Err(NonStandardTransactionError::TooManySigops);
        }

        if let Some(limit) = self.tx_unpaid_action_limit {
            if ycash_relay::unpaid_actions(transaction, tx.miner_fee) > limit {
                return Err(NonStandardTransactionError::UnpaidActionLimit);
            }
        }

        if let (Some(network), Some(next_height)) = (self.network.as_ref(), next_height) {
            if !tx.spent_outputs.is_empty() {
                ycash_standard::standard_script_check(
                    tx.transaction.transaction().clone(),
                    tx.spent_outputs.clone(),
                    network,
                    next_height,
                )
                .map_err(|(input_index, error)| {
                    NonStandardTransactionError::NonMandatoryScriptVerifyFlag(format!(
                        "input {input_index}: {error}"
                    ))
                })?;
            }
        }

        Ok(())
    }
}

/// The storage error for an `IsStandardTx` reason.
fn non_standard_error(reason: NonStandardReason) -> NonStandardTransactionError {
    match reason {
        NonStandardReason::ScriptSigSize => NonStandardTransactionError::ScriptSigTooLarge,
        NonStandardReason::ScriptSigNotPushOnly => {
            NonStandardTransactionError::ScriptSigNotPushOnly
        }
        NonStandardReason::ScriptPubKey => NonStandardTransactionError::ScriptPubKeyNonStandard,
        NonStandardReason::DataCarrier => NonStandardTransactionError::DataCarrierTooLarge,
        NonStandardReason::BareMultisig => NonStandardTransactionError::BareMultiSig,
        NonStandardReason::Dust => NonStandardTransactionError::IsDust,
        NonStandardReason::MultiOpReturn => NonStandardTransactionError::MultiOpReturn,
    }
}
