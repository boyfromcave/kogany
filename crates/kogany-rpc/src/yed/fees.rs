// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

//! The node's network-fee policy behind `yed_getinfo.params.fees.network`, `params.pq.feeRateZatPerKB`,
//! `params.feeZat` and `params.refLag` (kogany W6-b; ycash6 `src/rpc/yellowback.cpp:740-787`).
//!
//! ycashd keeps the policy in globals set by `init.cpp` (`attestedFeePolicy`, `pqFeeRate`,
//! `maxTxFee`, `g_yellowbackFee`, `g_yellowbackMintLag`) and the price in the one the index
//! publishes on every tip change (`SetAttestedFeePrice`). kogany installs the configured policy
//! once at start-up ([`install_node_policy`], from `zakurad`'s `[mempool]` section) and reads the
//! price at the tip it answers from: a live [`super::state::YedReadState`] fills
//! [`super::state::NodeInfo`] with [`node_info_fees`] at
//! `zakura_state::yed::YedSnapshot::attested_fee_price()` of the same snapshot, so one answer is
//! taken at one tip.

use std::sync::OnceLock;

pub use kogany_yellowback::fee::{AttestedFeePolicy, FeePolicy};
use kogany_yellowback::{
    fee::NetworkFeeReport,
    params::{MicroUsd, DEFAULT_REF_LAG, MAX_REF_LAG},
};

use super::state::NetworkFees;

/// The node's Yellowback wallet-side policy: the fee policy and `-yellowbackmintlag`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NodeYedPolicy {
    /// The network-fee policy (`-pqfeerate`, `-pqfeeusdperkb`, `-yellowbackfeeusdperkb`,
    /// `-yellowbackmaxtxfeeusd`, `-yellowbackmaxtxfee`, `-maxtxfee`, `-yellowbackfee`).
    pub fee: FeePolicy,
    /// `-yellowbackmintlag` (`g_yellowbackMintLag`): the blocks below the index tip a mint cites.
    pub ref_lag: i32,
}

impl Default for NodeYedPolicy {
    fn default() -> Self {
        NodeYedPolicy {
            fee: FeePolicy::default().with_min_cap(),
            ref_lag: DEFAULT_REF_LAG,
        }
    }
}

impl NodeYedPolicy {
    /// ycashd's init checks of the fee options and of `-yellowbackmintlag` (`0..=MAX_REF_LAG`).
    pub fn validate(&self) -> Result<(), String> {
        self.fee.validate()?;
        if !(0..=MAX_REF_LAG).contains(&self.ref_lag) {
            return Err(format!(
                "-yellowbackmintlag must be between 0 and {MAX_REF_LAG}."
            ));
        }
        Ok(())
    }
}

static NODE_POLICY: OnceLock<NodeYedPolicy> = OnceLock::new();

/// Installs the node's policy, once, before the RPC server starts. A second call keeps the first
/// policy and returns `false` (ycashd parses its arguments once).
pub fn install_node_policy(policy: NodeYedPolicy) -> bool {
    NODE_POLICY.set(policy).is_ok()
}

/// The installed policy, or ycashd's defaults when none was installed.
pub fn node_policy() -> NodeYedPolicy {
    NODE_POLICY.get().copied().unwrap_or_default()
}

impl From<NetworkFeeReport> for NetworkFees {
    fn from(r: NetworkFeeReport) -> Self {
        NetworkFees {
            price_micro_usd: r.price_micro_usd,
            plain_usd_per_kb_micro: r.plain_usd_per_kb_micro,
            plain_zat_per_kb: r.plain_zat_per_kb,
            yed_usd_per_kb_micro: r.yed_usd_per_kb_micro,
            yed_zat_per_kb: r.yed_zat_per_kb,
            yed_max_tx_fee_usd_micro: r.yed_max_tx_fee_usd_micro,
            yed_max_tx_fee_ceiling_zat: r.yed_max_tx_fee_ceiling_zat,
            yed_max_tx_fee_zat: r.yed_max_tx_fee_zat,
            floor_zat_per_kb: r.floor_zat_per_kb,
            fallback_zat_per_kb: r.fallback_zat_per_kb,
            max_tx_fee_zat: r.max_tx_fee_zat,
        }
    }
}

impl NetworkFees {
    /// The `params.fees.network` numbers of `policy` at the published fee `price` (`None`: the
    /// `-pqfeerate` fallback, `priceSource` `"fallback"`).
    pub fn at_price(policy: &FeePolicy, price: Option<MicroUsd>) -> Self {
        policy.network_fee_report(price).into()
    }
}

/// What a live [`super::state::NodeInfo`] takes from the node's policy at the fee `price`:
/// `(network_fees, fee_zat, ref_lag)`.
pub fn node_info_fees(price: Option<MicroUsd>) -> (NetworkFees, i64, i64) {
    let p = node_policy();
    (
        NetworkFees::at_price(&p.fee, price),
        p.fee.yellowback_fee,
        i64::from(p.ref_lag),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The mock fixture's `params.fees.network` (W7-b, $0.40/YEC) is the default policy's.
    #[test]
    fn the_default_policy_at_forty_cents_is_the_fixtures_report() {
        let nf = NetworkFees::at_price(&NodeYedPolicy::default().fee, Some(400_000));
        assert_eq!(
            nf,
            NetworkFees {
                price_micro_usd: Some(400_000),
                plain_usd_per_kb_micro: 20_000,
                plain_zat_per_kb: 5_000_000,
                yed_usd_per_kb_micro: 50_000,
                yed_zat_per_kb: 12_500_000,
                yed_max_tx_fee_usd_micro: 2_000_000,
                yed_max_tx_fee_ceiling_zat: 1_000_000_000,
                yed_max_tx_fee_zat: 500_000_000,
                floor_zat_per_kb: 5000,
                fallback_zat_per_kb: 100,
                max_tx_fee_zat: 10_000_000,
            }
        );
        let (fallback, fee_zat, ref_lag) = node_info_fees(None);
        assert_eq!(fallback.price_micro_usd, None);
        assert_eq!(fallback.plain_zat_per_kb, 100);
        assert_eq!((fee_zat, ref_lag), (1000, 2));
    }
}
