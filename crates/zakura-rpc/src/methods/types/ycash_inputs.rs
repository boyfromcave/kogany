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

use std::{collections::HashMap, sync::Arc};

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
/// parent's, as `getblock` computes it for `valuePools`). A transaction's value balance is the
/// value it takes out of the pools; the pools receive the opposite of every transaction's
/// balance, plus the lockbox deposit, which no transaction pays. So over every pool but the
/// lockbox, `delta = -(sum of the fees + the coinbase's value balance)`, and the fees are
/// `-(delta + coinbase balance)`, without reading a single input. 0 for genesis (ycashd does not
/// connect its transactions) and where the pools are not known.
pub fn block_fee(
    height: Height,
    delta: Option<ValueBalance<NegativeAllowed>>,
    coinbase: &Transaction,
) -> i64 {
    if height == Height(0) {
        return 0;
    }
    let Some(delta) = delta else {
        return 0;
    };
    // A coinbase spends no transparent output, so its balance needs no UTXO.
    let Ok(balance) = coinbase.value_balance(&HashMap::new()) else {
        return 0;
    };
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
    match (pools(&delta), pools(&balance)) {
        (Some(delta), Some(balance)) => (delta + balance).map_or(0, |sum| -sum.zatoshis()),
        _ => 0,
    }
}

#[cfg(test)]
mod tests;
