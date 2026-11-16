//! Extra per-block info tracked in the state.
use crate::{amount::NonNegative, value_balance::ValueBalance};

/// Extra per-block info tracked in the state.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BlockInfo {
    /// The pool balances after the block.
    value_pools: ValueBalance<NonNegative>,
    /// The size of the block in bytes.
    size: u32,
    /// Ycash: the number of transactions in the chain up to and including this block (ycashd's
    /// `nChainTx`), or `None` when it is not known (a row written before the count was stored,
    /// or a block of the non-finalized state, whose count the read path derives).
    #[cfg(feature = "ycash")]
    chain_tx_count: Option<u64>,
}

impl BlockInfo {
    /// Creates a new [`BlockInfo`] with the given value pools.
    pub fn new(value_pools: ValueBalance<NonNegative>, size: u32) -> Self {
        BlockInfo {
            value_pools,
            size,
            #[cfg(feature = "ycash")]
            chain_tx_count: None,
        }
    }

    /// Ycash: returns this block info with the chain transaction count set.
    #[cfg(feature = "ycash")]
    pub fn with_chain_tx_count(mut self, chain_tx_count: Option<u64>) -> Self {
        self.chain_tx_count = chain_tx_count;
        self
    }

    /// Ycash: returns the number of transactions in the chain up to and including this block,
    /// if it is known.
    #[cfg(feature = "ycash")]
    pub fn chain_tx_count(&self) -> Option<u64> {
        self.chain_tx_count
    }

    /// Returns the value pools of this block.
    pub fn value_pools(&self) -> &ValueBalance<NonNegative> {
        &self.value_pools
    }

    /// Returns the size of this block.
    pub fn size(&self) -> u32 {
        self.size
    }
}
