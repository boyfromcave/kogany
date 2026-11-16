// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

//! Ycash (beta3 item 6, kogany): what ycashd's insight explorer names for a transaction input,
//! and the `blockfee` of a block.
//!
//! On a `-insightexplorer` node ycashd's `TxToJSON` (`ycash6 src/rpc/rawtransaction.cpp`) gives
//! every non-coinbase input the `value` and `valueSat` of the output it spends, read from the
//! spent index, and the `address` of that output where the index names one
//! (`SpentInfoDestination`). The index keys an output by `CScript::AddressIndexKey`
//! (`src/script/script.cpp`): a P2PKH or a P2SH by its hash, a bare P2PK folded into the P2PKH
//! of `Hash160(pubkey)`, and a TX_PQPKH `0x20 <keyHash:32> OP_1|OP_2 OP_CHECKPQSIG`, whose address
//! (the D-9 form) ycash6 #128 reads back from the spent output itself. Every other script
//! (a vault, a multisig, a nonstandard script) names no address; its value is still named.
//!
//! kogany has no spent index; on an archive node its transaction index holds every parent, so
//! the spent output is read from the parent (`ReadRequest::Transaction`, or the mempool for an
//! unconfirmed parent) and named by [`spent_output_address`]. The reads are in `methods.rs`
//! (`ycash_name_inputs`); this module is the naming and the fee arithmetic.
//!
//! `blockfee` (`ycash6 src/rpc/blockchain.cpp` `blockToJSON`, `CBlockIndex::nBlockFee`, set in
//! `ConnectBlock` to the sum of every non-coinbase transaction's fee; 0 for genesis) is
//! [`block_fee`]: the fees are the value that leaves the chain's value pools in a block other
//! than through the coinbase, so it needs no input read.

use std::{
    collections::{HashMap, HashSet},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};

use futures::StreamExt;
use tower::ServiceExt;

use zakura_chain::{
    amount::{Amount, NegativeAllowed},
    block::Height,
    parameters::Network,
    transaction::{self, Transaction},
    transparent::{self, Address},
    value_balance::ValueBalance,
};

use super::{transaction::Input, zec::Zec};

/// The parents read during one RPC call, by transaction id (`None`: not found, not read again),
/// so the inputs of a block or a transaction that share a parent read it once (ycash6
/// `SpentInfoDestination`'s `prevTxs`).
pub(crate) type Parents = HashMap<transaction::Hash, Option<Arc<Transaction>>>;

/// How many parent reads one call keeps in flight at most. The read state runs each read on
/// the blocking pool that every other RPC and the syncer share, so a call with thousands of
/// parents takes this many slots, never all of them.
pub(crate) const PARENT_READ_CONCURRENCY: usize = 16;

/// The most distinct parents one call reads; a call whose inputs have more answers without the
/// input fields (logged, [`InsightExplorer::over_cap`]). ycashd has no cap: its spent index
/// answers an input in one lookup. A 2 MB Ycash block holds at most about 13,500 P2PKH inputs
/// (148 bytes each); 5,000 distinct parents is far above the inputs of any block on the Ycash
/// chains so far, and bounds the cost of one unauthenticated call.
pub const MAX_INSIGHT_PARENTS: usize = 5_000;

/// kogany's counterpart of ycashd's `-insightexplorer` for the insight fields of
/// `getrawtransaction 1` and `getblock` (`rpc.insight_explorer`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InsightExplorer {
    /// Whether the input fields and `blockfee` are served (off by default).
    enabled: bool,
    /// The most distinct parents one call reads ([`MAX_INSIGHT_PARENTS`]).
    max_parents: usize,
}

impl Default for InsightExplorer {
    fn default() -> Self {
        Self::new(false)
    }
}

impl InsightExplorer {
    /// The insight fields on (`enabled`) or off, with the default parent cap.
    pub fn new(enabled: bool) -> Self {
        Self {
            enabled,
            max_parents: MAX_INSIGHT_PARENTS,
        }
    }

    /// The same switch with a parent cap of `max_parents` (tests use a small one).
    pub fn with_max_parents(self, max_parents: usize) -> Self {
        Self {
            max_parents,
            ..self
        }
    }

    /// Whether the insight fields are served.
    pub fn enabled(&self) -> bool {
        self.enabled
    }

    /// Whether `parents` distinct parents are more than one call reads; logs it (a warning
    /// the first time in this process, then at debug level).
    pub(crate) fn over_cap(&self, parents: usize) -> bool {
        static WARNED: AtomicBool = AtomicBool::new(false);
        if parents <= self.max_parents {
            return false;
        }
        if WARNED.swap(true, Ordering::Relaxed) {
            tracing::debug!(
                parents,
                cap = self.max_parents,
                "insight explorer: a call's inputs have too many distinct parents; \
                 answering without the input fields"
            );
        } else {
            tracing::warn!(
                parents,
                cap = self.max_parents,
                "insight explorer: a call's inputs have too many distinct parents; \
                 answering without the input fields (logged once, then at debug level)"
            );
        }
        true
    }
}

/// Reads each of `wanted` from the best chain's transaction index (`ReadRequest::Transaction`),
/// [`PARENT_READ_CONCURRENCY`] at a time; a parent the chain does not hold maps to `None`.
pub(crate) async fn read_parents<S>(read_state: S, wanted: HashSet<transaction::Hash>) -> Parents
where
    S: zakura_state::ReadState,
{
    futures::stream::iter(wanted)
        .map(|hash| {
            let read_state = read_state.clone();
            async move {
                let parent = match read_state
                    .oneshot(zakura_state::ReadRequest::Transaction(hash))
                    .await
                {
                    Ok(zakura_state::ReadResponse::Transaction(Some(mined))) => Some(mined.tx),
                    _ => None,
                };
                (hash, parent)
            }
        })
        .buffer_unordered(PARENT_READ_CONCURRENCY)
        .collect()
        .await
}

/// `OP_CHECKSIG`.
const OP_CHECKSIG: u8 = 0xac;

/// The address ycashd's spent index names for an input that spends `output`
/// (`CScript::AddressIndexKey`, then `DestFromAddressHash` or, for a TX_PQPKH,
/// `SpentInfoDestination`), encoded for `network`; `None` where ycashd names none.
pub fn spent_output_address(network: &Network, output: &transparent::Output) -> Option<String> {
    let script = output.lock_script.as_raw_bytes();
    // `CScript::IsPayToPublicKey`: `<33-byte 02|03 key> OP_CHECKSIG` or `<65-byte 04 key>
    // OP_CHECKSIG`, indexed as the P2PKH of Hash160(key).
    let pay_to_pub_key = match script {
        [0x21, key @ .., OP_CHECKSIG] if key.len() == 33 && matches!(key[0], 0x02 | 0x03) => {
            Some(key)
        }
        [0x41, key @ .., OP_CHECKSIG] if key.len() == 65 && key[0] == 0x04 => Some(key),
        _ => None,
    };
    if let Some(key) = pay_to_pub_key {
        return Some(
            Address::from_pub_key_hash(network.t_addr_kind(), kogany_vault::template::hash160(key))
                .to_string(),
        );
    }
    // P2PKH, P2SH (exact byte patterns, `IsPayToPublicKeyHash` / `IsPayToScriptHash`) and the
    // 35-byte TX_PQPKH (`IsPQPKHForIndex`), as `Output::address` matches them; a YED-carrying
    // output is a plain TX_PQPKH and is named in the plain post-quantum form, as on ycashd.
    output.address(network).map(|address| address.to_string())
}

/// Names the spent output on a non-coinbase input: `value`, `valueSat` and, where ycashd names
/// one, `address`. A coinbase input is left as it is.
pub(crate) fn name_input(network: &Network, input: &mut Input, spent: &transparent::Output) {
    if let Input::NonCoinbase {
        value,
        value_zat,
        address,
        ..
    } = input
    {
        *value = Some(Zec::from(spent.value).lossy_zec());
        *value_zat = Some(spent.value.zatoshis());
        *address = spent_output_address(network, spent);
    }
}

/// The output `index` of `parent`, if it has one.
pub(crate) fn spent_output(parent: &Transaction, index: u32) -> Option<&transparent::Output> {
    parent.outputs().get(usize::try_from(index).ok()?)
}

/// ycashd's `blockfee` in zatoshis: the sum of the fees of the block's non-coinbase transactions.
///
/// `delta` is the change of the chain value pools over the block (this block's pools less its
/// parent's), `None` when either side is not known. A transaction's value balance is the value
/// it takes out of the pools; the pools receive the opposite of every transaction's balance,
/// plus the lockbox deposit, which no transaction pays. So over every pool but the lockbox,
/// `delta = -(sum of the fees + the coinbase's value balance)`, and the fees are
/// `-(delta + coinbase balance)`, without reading a single input. 0 for genesis (ycashd does not
/// connect its transactions).
///
/// `None` (no `blockfee` field) wherever a number could be wrong: the pools or the coinbase not
/// known, or an amount out of range.
pub fn block_fee(
    height: Height,
    delta: Option<ValueBalance<NegativeAllowed>>,
    coinbase: Option<&Transaction>,
) -> Option<i64> {
    if height == Height(0) {
        return Some(0);
    }
    let delta = delta?;
    // A coinbase spends no transparent output, so its balance needs no UTXO.
    let balance = coinbase?.value_balance(&HashMap::new()).ok()?;
    let pools = |b: &ValueBalance<NegativeAllowed>| -> Option<Amount<NegativeAllowed>> {
        [
            b.sprout_amount(),
            b.sapling_amount(),
            b.orchard_amount(),
            b.ironwood_amount(),
        ]
        .into_iter()
        .try_fold(b.transparent_amount(), |sum, amount| (sum + amount).ok())
    };
    let sum = (pools(&delta)? + pools(&balance)?).ok()?;
    Some(-sum.zatoshis())
}

#[cfg(test)]
mod tests;
