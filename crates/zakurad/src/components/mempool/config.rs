//! User-configurable mempool parameters.

use std::time::Duration;

use serde::{Deserialize, Serialize};

/// Mempool configuration section.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct Config {
    /// The mempool transaction cost limit.
    ///
    /// This limits the total ZIP-401 cost of all transactions in the mempool. When the mempool
    /// is full, it evicts the transactions that pay the lowest fee per unit of cost, but only
    /// for a transaction that pays more.
    ///
    /// Consensus rule:
    /// > There MUST be a configuration option mempooltxcostlimit, which SHOULD default to 80000000.
    ///
    /// This corresponds to `mempooltxcostlimit` from [ZIP-401](https://zips.z.cash/zip-0401#specification).
    pub tx_cost_limit: u64,

    /// Maximum serialized size of an individual transaction accepted into the mempool.
    ///
    /// Transactions exactly at this limit are accepted. Larger transactions are rejected before
    /// semantic and contextual verification. This local policy does not affect block validation.
    pub max_transaction_bytes: u64,

    /// The mempool rejection age limit.
    ///
    /// This limits the maximum amount of time the IDs of expired, mined, and double-spent
    /// transactions stay in the mempool rejection lists. The mempool forgets evicted
    /// transactions at the next block instead, because blocks free mempool space.
    ///
    /// This corresponds to `mempoolevictionmemoryminutes` from
    /// [ZIP-401](https://zips.z.cash/zip-0401#specification).
    #[serde(with = "zakura_chain::serialization::serde_adapters::duration")]
    pub eviction_memory_time: Duration,

    /// If the state's best chain tip has reached this height, always enable the mempool,
    /// regardless of Zebra's sync status.
    ///
    /// Set to `None` by default: Zebra always checks the sync status before enabling the mempool.
    //
    // TODO:
    // - allow the mempool to be enabled before the genesis block is committed?
    //   we could replace `Option` with an enum that has an `AlwaysEnable` variant
    pub debug_enable_at_height: Option<u32>,

    /// Maximum size in bytes of an OP_RETURN script that is considered standard.
    ///
    /// If unset, defaults to [`DEFAULT_MAX_DATACARRIER_BYTES`]. This size includes the OP_RETURN
    /// opcode and pushdata overhead. Matches zcashd's `-datacarriersize` default behavior.
    pub max_datacarrier_bytes: Option<u32>,

    /// Ycash: accept non-standard transactions, ycashd's `-acceptnonstdtxn` (regtest only).
    ///
    /// ycashd checks `IsStandardTx` and `AreInputsStandard` only on networks that require
    /// standard transactions: mainnet and testnet always, regtest only with
    /// `-acceptnonstdtxn=0`. Unset follows the network (accept on regtest only); a value is
    /// honoured on regtest and ignored elsewhere, as ycashd refuses the flag there. The
    /// sigop limit applies either way. (kogany W1-Y9)
    #[cfg(feature = "ycash")]
    pub accept_non_standard: Option<bool>,

    /// Ycash: the ZIP-317 unpaid-action limit, ycashd's `-txunpaidactionlimit`.
    ///
    /// Unset (the Ycash default) applies no limit: ycashd's `DEFAULT_TX_UNPAID_ACTION_LIMIT` is
    /// `SIZE_MAX`. A value rejects a transaction with more unpaid actions, counted at ycashd's
    /// 500-zatoshi marginal fee. (kogany W1-Y9)
    #[cfg(feature = "ycash")]
    pub tx_unpaid_action_limit: Option<u32>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            // [ZIP-401] Consensus rules:
            //
            // > There MUST be a configuration option mempooltxcostlimit,
            // > which SHOULD default to 80000000.
            // >
            // > There MUST be a configuration option mempoolevictionmemoryminutes,
            // > which SHOULD default to 60 [minutes].
            //
            // [ZIP-401]: https://zips.z.cash/zip-0401#specification
            tx_cost_limit: 80_000_000,
            max_transaction_bytes: DEFAULT_MAX_TRANSACTION_BYTES,
            eviction_memory_time: Duration::from_secs(60 * 60),

            debug_enable_at_height: None,

            max_datacarrier_bytes: Some(DEFAULT_MAX_DATACARRIER_BYTES),

            #[cfg(feature = "ycash")]
            accept_non_standard: None,
            #[cfg(feature = "ycash")]
            tx_unpaid_action_limit: None,
        }
    }
}

/// Default maximum serialized size of an individual mempool transaction, in bytes.
#[cfg(not(feature = "ycash"))]
pub const DEFAULT_MAX_TRANSACTION_BYTES: u64 = 250_000;

/// Default maximum serialized size of an individual mempool transaction, in bytes.
///
/// Ycash: ycashd has no standard size limit below the consensus one, `MAX_TX_SIZE_AFTER_SAPLING`
/// = `MAX_BLOCK_SIZE` (ycash6 `consensus/consensus.h:29-34`), so a larger transaction is
/// refused as invalid, not as policy. (kogany W1-Y9)
#[cfg(feature = "ycash")]
pub const DEFAULT_MAX_TRANSACTION_BYTES: u64 = zakura_chain::block::MAX_BLOCK_BYTES;

/// Default maximum size of data carrier scripts (OP_RETURN), in bytes.
///
/// Equivalent to zcashd's `MAX_OP_RETURN_RELAY`:
/// <https://github.com/zcash/zcash/blob/v6.10.0/src/script/standard.h#L22-L26>
pub const DEFAULT_MAX_DATACARRIER_BYTES: u32 = 83;
