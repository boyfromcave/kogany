// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

//! The Ycash mempool fee policy before the Vault upgrade (kogany W1-Y9 `relay-ycash`).
//!
//! On a Ycash network these rules replace Zakura's ZIP-317 relay rules
//! ([`super::zip317::mempool_checks`]); Zcash networks (the feature-off build) keep ZIP-317
//! untouched. They are ported by meaning from ycashd 6.22 (`ycash6` at `65cb4ae0f`),
//! `src/main.cpp` `AcceptToMemoryPool`:
//!
//! - the minimum relay fee: `minRelayTxFee.GetFeeForRelay(nSize)`, 100 zatoshis per 1,000 bytes
//!   (`DEFAULT_MIN_RELAY_TX_FEE`, `main.h:75`), rounded down, at least the rate itself when the
//!   product rounds to zero, and capped at `LEGACY_DEFAULT_FEE` = 1,000 (`amount.cpp:25-37`).
//!   Zakura's ZIP-317 floor is the same rate clamped to 100..=800;
//! - the per-Sapling-output floor `PerSaplingOutputFees` (`policy/policy.cpp:26-46`): 1,000
//!   zatoshis for 1 to 50 Sapling outputs, then 1,000 per output beyond 50. Zakura has none;
//! - no ZIP-317 unpaid-action limit by default: ycash6 sets `DEFAULT_TX_UNPAID_ACTION_LIMIT` to
//!   `SIZE_MAX` (`zip317.h:26-54`), where Zakura's is 0. A node may opt in with
//!   `-txunpaidactionlimit` (the mempool's `tx_unpaid_action_limit`); its count uses ycash6's
//!   500-zatoshi marginal fee ([`MARGINAL_FEE`]), not Zakura's 400;
//! - the expiring-soon rule `IsExpiringSoonTx` (`main.cpp:802-805`, `main.h:108`).

use crate::{
    amount::{Amount, NonNegative},
    block::Height,
    transaction::{Transaction, UnminedTx},
};

use super::zip317;

/// `LEGACY_DEFAULT_FEE` (ycash6 `amount.h:38`): the cap of the size-based relay fee, so a
/// transaction paying 1,000 zatoshis can always be relayed.
pub const LEGACY_DEFAULT_FEE: u64 = 1_000;

/// `DEFAULT_MIN_RELAY_TX_FEE` (ycash6 `main.h:75`), zatoshis per 1,000 bytes.
pub const DEFAULT_MIN_RELAY_TX_FEE: u64 = 100;

/// `DEFAULT_PER_SAPLING_OUTPUT_FEE` (ycash6 `policy/policy.h:27`).
pub const DEFAULT_PER_SAPLING_OUTPUT_FEE: u64 = 1_000;

/// `DEFAULT_EXEMPT_SAPLING_OUTPUTS` (ycash6 `policy/policy.h:28`).
pub const DEFAULT_EXEMPT_SAPLING_OUTPUTS: u64 = 50;

/// ycash6's ZIP-317 marginal fee (`zip317.h:16`), used only to count unpaid actions for an
/// opted-in `-txunpaidactionlimit`.
pub const MARGINAL_FEE: u64 = 500;

/// `TX_EXPIRING_SOON_THRESHOLD` (ycash6 `main.h:108`).
pub const TX_EXPIRING_SOON_THRESHOLD: u32 = 3;

/// The minimum relay fee of a transaction of `size` serialized bytes:
/// `CFeeRate(DEFAULT_MIN_RELAY_TX_FEE).GetFeeForRelay(size)`.
pub fn min_relay_fee(size: usize) -> u64 {
    let size = u64::try_from(size).unwrap_or(u64::MAX);
    let fee = DEFAULT_MIN_RELAY_TX_FEE.saturating_mul(size) / 1_000;
    let fee = if fee == 0 {
        DEFAULT_MIN_RELAY_TX_FEE
    } else {
        fee
    };
    fee.min(LEGACY_DEFAULT_FEE)
}

/// `PerSaplingOutputFees`: the least fee a transaction with Sapling outputs must pay.
pub fn per_sapling_output_fees(transaction: &Transaction) -> u64 {
    let outputs = u64::try_from(transaction.sapling_outputs().count()).unwrap_or(u64::MAX);
    match outputs {
        0 => 0,
        n if n <= DEFAULT_EXEMPT_SAPLING_OUTPUTS => DEFAULT_PER_SAPLING_OUTPUT_FEE,
        n => (n - DEFAULT_EXEMPT_SAPLING_OUTPUTS).saturating_mul(DEFAULT_PER_SAPLING_OUTPUT_FEE),
    }
}

/// `CTxMemPoolEntry::GetUnpaidActionCount` (ycash6 `txmempool.cpp:305-313`): the logical
/// actions, at least the grace actions, less the fee in whole 500-zatoshi marginal fees.
pub fn unpaid_actions(transaction: &Transaction, miner_fee: Amount<NonNegative>) -> u32 {
    let actions = i64::from(zip317::conventional_actions(transaction));
    let paid = i64::try_from(u64::try_from(i64::from(miner_fee)).unwrap_or(0) / MARGINAL_FEE)
        .unwrap_or(i64::MAX);
    u32::try_from(actions.saturating_sub(paid).max(0)).unwrap_or(u32::MAX)
}

/// `IsExpiringSoonTx(tx, next_height)`: the transaction expires within
/// [`TX_EXPIRING_SOON_THRESHOLD`] blocks of the next block (`next_height + 3 > nExpiryHeight`).
pub fn is_expiring_soon(transaction: &Transaction, next_height: Height) -> bool {
    !transaction.is_coinbase()
        && transaction.expiry_height().is_some_and(|expiry| {
            u64::from(next_height.0) + u64::from(TX_EXPIRING_SOON_THRESHOLD) > u64::from(expiry.0)
        })
}

/// The fee rules every Ycash node applies to a mempool transaction, in ycash6's order: the
/// minimum relay fee, then the per-Sapling-output floor. These replace
/// [`zip317::mempool_checks`] on a Ycash network.
pub fn mempool_checks(
    transaction: &UnminedTx,
    miner_fee: Amount<NonNegative>,
) -> Result<(), zip317::Error> {
    let fee = u64::try_from(i64::from(miner_fee)).unwrap_or(0);
    if fee < min_relay_fee(transaction.size) {
        return Err(zip317::Error::FeeBelowMinimumRate);
    }
    if fee < per_sapling_output_fees(&transaction.transaction) {
        return Err(zip317::Error::PerSaplingOutputFee);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn min_relay_fee_matches_get_fee_for_relay() {
        // ycash6 amount.cpp: 100 * size / 1000, the rate when that rounds to 0, at most 1,000.
        assert_eq!(min_relay_fee(0), 100);
        assert_eq!(min_relay_fee(9), 100);
        assert_eq!(min_relay_fee(10), 1);
        assert_eq!(min_relay_fee(244), 24);
        assert_eq!(min_relay_fee(999), 99);
        assert_eq!(min_relay_fee(1_000), 100);
        assert_eq!(min_relay_fee(9_999), 999);
        assert_eq!(min_relay_fee(10_000), 1_000);
        assert_eq!(min_relay_fee(2_000_000), 1_000);
    }

    /// ycash6 `pq_wallet_tests.cpp` `pq_zip317_low_fee_penalty` (audit 04/N-1, W6-b): a
    /// post-quantum spend's conventional fee counts its large scriptSig (500 per 150 bytes of
    /// input), so at ycash-dd's former 1,000-zatoshi wallet fee it has unpaid actions (ycashd's
    /// ZIP-401 eviction weight then carries `LOW_FEE_PENALTY`, and an opted-in
    /// `-txunpaidactionlimit` refuses it), and at the conventional fee none. The relay fee
    /// itself stays the size-capped minimum: the 1,000-zatoshi spend relays by default.
    #[test]
    fn pq_zip317_low_fee_penalty() {
        use crate::{
            block::Height,
            transaction::LockTime,
            transparent::{Input, OutPoint, Output, Script},
        };

        // PQSpendInputSize: SLH-DSA 7,981 bytes (a 7,938-byte scriptSig), Falcon 1,620 (1,577).
        for (input_size, script_sig) in [(7_981u64, 7_938usize), (1_620, 1_577)] {
            let tx = Transaction::V4 {
                inputs: vec![Input::PrevOut {
                    outpoint: OutPoint {
                        hash: crate::transaction::Hash([1; 32]),
                        index: 0,
                    },
                    unlock_script: Script::new(&vec![0u8; script_sig]),
                    sequence: u32::MAX,
                }],
                outputs: vec![Output {
                    value: Amount::try_from(1_000).expect("1,000 zatoshis is a valid amount"),
                    lock_script: Script::new(&[0u8; 25]),
                }],
                lock_time: LockTime::Height(Height(0)),
                expiry_height: Height(0),
                joinsplit_data: None,
                sapling_shielded_data: None,
            };
            let conventional = MARGINAL_FEE * input_size.div_ceil(150);
            assert!(conventional > LEGACY_DEFAULT_FEE);
            assert_eq!(
                u64::from(zip317::conventional_actions(&tx)) * MARGINAL_FEE,
                conventional
            );
            let fee = |z: u64| Amount::try_from(z).expect("a valid amount");
            assert!(unpaid_actions(&tx, fee(LEGACY_DEFAULT_FEE)) > 0);
            assert_eq!(unpaid_actions(&tx, fee(conventional)), 0);
            let unmined = UnminedTx::from(tx);
            assert!(mempool_checks(&unmined, fee(LEGACY_DEFAULT_FEE)).is_ok());
        }
    }
}
