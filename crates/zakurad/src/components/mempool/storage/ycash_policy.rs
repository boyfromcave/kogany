// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

//! The Ycash mempool policy before the Vault upgrade that depends on the tip or on the node's
//! configuration (kogany W1-Y9 `relay-ycash`). The network-wide fee rules (the minimum relay
//! fee and the per-Sapling-output floor) run earlier, in the transaction verifier
//! (`zakura_chain::transaction::ycash_relay`).
//!
//! Ported by meaning from ycashd 6.22 (`ycash6` at `65cb4ae0f`), `src/main.cpp`
//! `AcceptToMemoryPool`:
//!
//! - `chainparams.RequireStandard()` gates `IsStandardTx` and `AreInputsStandard`
//!   (`main.cpp:1979,2070`): true on mainnet and testnet, false on regtest unless
//!   `-acceptnonstdtxn=0` (`chainparams.cpp:839,991-994`). The sigop limit
//!   `MAX_STANDARD_TX_SIGOPS` is not gated (`main.cpp:2079-2091`);
//! - `IsExpiringSoonTx` (`main.cpp:1969-1971`);
//! - `-txunpaidactionlimit` (`main.cpp:2150-2162`), unlimited by default on Ycash.

use zakura_chain::{
    block::Height,
    parameters::Network,
    transaction::{ycash_relay, VerifiedUnminedTx},
};

use super::{config, policy, NonStandardTransactionError};

/// The resolved Ycash policy of one mempool.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(super) struct Policy {
    /// `!RequireStandard()`: skip the standardness checks (regtest only).
    pub(super) accept_non_standard: bool,
    /// `-txunpaidactionlimit`; `None` is ycashd's `SIZE_MAX`.
    pub(super) tx_unpaid_action_limit: Option<u32>,
}

impl Policy {
    /// The policy for `network` (`None`: not regtest) from the mempool `config`.
    pub(super) fn new(config: &config::Config, network: Option<&Network>) -> Self {
        let regtest = network.is_some_and(Network::is_regtest);
        Self {
            accept_non_standard: regtest && config.accept_non_standard.unwrap_or(true),
            tx_unpaid_action_limit: config.tx_unpaid_action_limit,
        }
    }

    /// The first ycashd rule `tx` breaks at the tip `tip_height`, if any.
    pub(super) fn check(
        &self,
        tx: &VerifiedUnminedTx,
        tip_height: Option<Height>,
    ) -> Result<(), NonStandardTransactionError> {
        let transaction = tx.transaction.transaction().as_ref();

        if let Some(next_height) = tip_height.and_then(|height| height.next().ok()) {
            if ycash_relay::is_expiring_soon(transaction, next_height) {
                return Err(NonStandardTransactionError::ExpiringSoon);
            }
        }

        if tx.block_sigop_count() > policy::MAX_STANDARD_TX_SIGOPS {
            return Err(NonStandardTransactionError::TooManySigops);
        }

        if let Some(limit) = self.tx_unpaid_action_limit {
            if ycash_relay::unpaid_actions(transaction, tx.miner_fee) > limit {
                return Err(NonStandardTransactionError::UnpaidActionLimit);
            }
        }

        Ok(())
    }
}
