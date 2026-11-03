//! The transaction and coin views the state machine reads. The crate depends on no zakura
//! crate, so the node (W4-c/W4-d) converts its own transaction type into a [`VaultTx`] and
//! answers spent coins through a [`CoinAccessor`].

use std::collections::BTreeMap;

use crate::bytes::{Hash32, OutPoint};

/// A transparent input.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct VaultTxIn {
    /// The spent outpoint.
    pub prevout: OutPoint,
    /// The scriptSig.
    pub script_sig: Vec<u8>,
}

/// A transparent output.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct VaultTxOut {
    /// The value in zatoshis (the C++ `CAmount`; the rules range-check it).
    pub value: i64,
    /// The scriptPubKey.
    pub script_pubkey: Vec<u8>,
}

/// What the vault rules read of a transaction: its txid, whether it is a coinbase (the C++
/// `IsCoinBase`: one input with the null prevout), and its transparent inputs and outputs in
/// order. Shielded parts are not the primitive's concern.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct VaultTx {
    /// The txid, internal byte order (a `SET_CREATE`'s set id).
    pub txid: Hash32,
    /// A coinbase transaction.
    pub coinbase: bool,
    /// The transparent inputs.
    pub inputs: Vec<VaultTxIn>,
    /// The transparent outputs.
    pub outputs: Vec<VaultTxOut>,
}

impl VaultTx {
    /// The C++ `CTransaction::IsCoinBase` predicate over `inputs`: exactly one input, whose
    /// prevout is null (zero txid, `n = 0xffffffff`).
    pub fn inputs_are_coinbase(inputs: &[VaultTxIn]) -> bool {
        matches!(inputs, [only] if only.prevout.txid == Hash32::ZERO && only.prevout.n == u32::MAX)
    }
}

/// A coin an input spends (C++ `SpentCoin`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SpentCoin {
    /// Its scriptPubKey.
    pub script_pubkey: Vec<u8>,
    /// Its value.
    pub value: i64,
    /// The height of the block that created it.
    pub height: i64,
}

/// The spent coins of a block's transactions (C++ `CoinAccessor`). Within a block it must also
/// answer outputs created earlier in the same block, at the block's height (the C++
/// `CCoinsViewCache` does). A missing coin rejects the transaction
/// (`bad-txns-vault-inputs-missing`).
pub trait CoinAccessor {
    /// The coin `prevout` spends; `None` if unknown.
    fn spent_coin(&self, prevout: &OutPoint) -> Option<SpentCoin>;
}

impl CoinAccessor for BTreeMap<OutPoint, SpentCoin> {
    fn spent_coin(&self, prevout: &OutPoint) -> Option<SpentCoin> {
        self.get(prevout).cloned()
    }
}
