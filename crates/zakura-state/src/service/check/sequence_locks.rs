//! BIP68 relative lock-times, height-based only, from the Vault upgrade (kogany plan W3-d).
//!
//! Ported by meaning from ycash6 `upgrade/vault` (`src/main.cpp`: `CalculateSequenceLocks`,
//! `EvaluateSequenceLocks`, `ContextualCheckSequenceLocks`) and the upgrade spec
//! (`docs/plans/yellowback-upgrade-plan.md` §15.2, U-11):
//!
//! > for each input whose `nSequence` has bit 31 clear: bit 22 set → transaction invalid
//! > (`bad-txns-vault-timelock`); otherwise the input's coin height + `(nSequence & 0xffff)` must
//! > be ≤ the spending height.
//!
//! The rule applies to every non-coinbase transaction, whatever its version, wherever
//! [`Network::is_vault_active`] holds at the spending height. A block checks it at its own
//! height ([`block_sequence_locks_are_satisfied`], contextual validation); the mempool at the
//! next height, with a mempool parent's coin counted at that height (the transaction verifier).
//! The coin height is [`transparent::Utxo::height`], so the C++ `'v'` replay-height index has
//! nothing to do here.

use std::collections::HashMap;

use zakura_chain::{
    block::Height,
    parameters::Network,
    transaction::Transaction,
    transparent::{self, OrderedUtxo},
};

use crate::{SemanticallyVerifiedBlock, ValidateContextError};

/// `CTxIn::SEQUENCE_LOCKTIME_DISABLE_FLAG`: an input with bit 31 set carries no relative lock.
pub const SEQUENCE_LOCKTIME_DISABLE_FLAG: u32 = 1 << 31;

/// `CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG`: BIP68's time-based lock, invalid on Ycash.
pub const SEQUENCE_LOCKTIME_TYPE_FLAG: u32 = 1 << 22;

/// `CTxIn::SEQUENCE_LOCKTIME_MASK`: the lock's value, in blocks.
pub const SEQUENCE_LOCKTIME_MASK: u32 = 0x0000_ffff;

/// `CalculateSequenceLocks`: the last height at which a block could **not** include a
/// transaction whose inputs have these `(nSequence, coin height)` pairs, or `-1` when no input
/// carries a relative lock. `None` when an enabled input asks for a time-based lock
/// (`bad-txns-vault-timelock`).
///
/// A coin at height `H` with a lock of `n` is spendable from `H + n`, so this is the maximum of
/// `H + n - 1` over the enabled inputs.
pub fn calculate_sequence_locks(inputs: impl IntoIterator<Item = (u32, Height)>) -> Option<i64> {
    let mut min_height: i64 = -1;
    for (sequence, coin_height) in inputs {
        if sequence & SEQUENCE_LOCKTIME_DISABLE_FLAG != 0 {
            continue;
        }
        if sequence & SEQUENCE_LOCKTIME_TYPE_FLAG != 0 {
            return None;
        }
        let lock = i64::from(sequence & SEQUENCE_LOCKTIME_MASK);
        min_height = min_height.max(i64::from(coin_height.0) + lock - 1);
    }
    Some(min_height)
}

/// `EvaluateSequenceLocks`: does a block at `block_height` satisfy `min_height`?
pub fn evaluate_sequence_locks(block_height: Height, min_height: i64) -> bool {
    min_height < i64::from(block_height.0)
}

/// `ContextualCheckSequenceLocks` for one transaction spent at `spend_height`: Ok outside the
/// Vault upgrade and for a coinbase transaction. `coin_height` gives the height of each spent
/// output (a mempool parent at `spend_height`); a spent output it does not know is the caller's
/// spend check's to reject, so this check skips it.
pub fn transparent_sequence_locks(
    network: &Network,
    transaction: &Transaction,
    spend_height: Height,
    coin_height: impl Fn(&transparent::OutPoint) -> Option<Height>,
) -> Result<(), ValidateContextError> {
    if !network.is_vault_active(spend_height) || transaction.is_coinbase() {
        return Ok(());
    }

    let mut inputs = Vec::with_capacity(transaction.inputs().len());
    for (input_index, input) in transaction.inputs().iter().enumerate() {
        let transparent::Input::PrevOut {
            outpoint, sequence, ..
        } = input
        else {
            continue;
        };
        if sequence & SEQUENCE_LOCKTIME_DISABLE_FLAG == 0
            && sequence & SEQUENCE_LOCKTIME_TYPE_FLAG != 0
        {
            return Err(ValidateContextError::VaultTimeLock {
                input_index,
                sequence: *sequence,
            });
        }
        if let Some(height) = coin_height(outpoint) {
            inputs.push((*sequence, height));
        }
    }

    let min_height = calculate_sequence_locks(inputs)
        .expect("time-based locks are rejected above, so only height-based locks remain");
    if evaluate_sequence_locks(spend_height, min_height) {
        Ok(())
    } else {
        Err(ValidateContextError::UnsatisfiedSequenceLock {
            spend_height,
            min_spend_height: Height(
                u32::try_from(min_height + 1).expect("a coin height plus a 16-bit lock fits"),
            ),
        })
    }
}

/// The block-level BIP68 check (contextual validation, `ConnectBlock`'s
/// `ContextualCheckSequenceLocks(.., pindex->nHeight, .., false)`): every transaction of
/// `semantically_verified`, at the block's height, with the coin heights of `spent_utxos` (the
/// UTXOs [`super::utxo::transparent_spend`] returned for this block on its own fork; an output of
/// an earlier transaction of the block is at the block's height).
pub fn block_sequence_locks_are_satisfied(
    network: &Network,
    semantically_verified: &SemanticallyVerifiedBlock,
    spent_utxos: &HashMap<transparent::OutPoint, OrderedUtxo>,
) -> Result<(), ValidateContextError> {
    let height = semantically_verified.height;
    if !network.is_vault_active(height) {
        return Ok(());
    }
    for transaction in &semantically_verified.block.transactions {
        transparent_sequence_locks(network, transaction, height, |outpoint| {
            spent_utxos.get(outpoint).map(|utxo| utxo.utxo.height)
        })?;
    }
    Ok(())
}
