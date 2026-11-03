//! kogany W2-c: ycashd's previous-epoch walk-back at the Vault activation, mapped to the
//! mempool's upgrade grace period.
//!
//! ycashd retries a failed signature under `PrevEpochBranchId(Vault)`, the highest upgrade below
//! Vault with a height (NU5..NU6.2 are never scheduled with Vault), and diagnoses
//! `old-consensus-branch-id` at DoS 10 in the mempool (`ycash6 src/consensus/upgrades.cpp:144-162`,
//! `src/main.cpp:1429-1468`). Zakura re-runs nothing: for `UPGRADE_GRACE_PERIOD_BLOCKS` blocks
//! after an activation, a transaction for the previous upgrade (the one current at H_V − 1) is
//! rejected without a peer cooldown (`upgrade_grace_period`, `transaction_cooldown_peer`). With
//! Vault after Canopy (K-1), that previous upgrade is Canopy on every Ycash network, which is
//! ycashd's walk-back answer. Both nodes reject the transaction (verdict class: reject); the
//! peer handling differs by design (mapping M24-8).

use zakura_chain::{
    block,
    parameters::{testnet::ConfiguredActivationHeights, Network, NetworkUpgrade},
};
use zakura_consensus::error::TransactionError;

use crate::components::mempool::{
    downloads::TransactionDownloadVerifyError, transaction_cooldown_peer, upgrade_grace_period,
};

/// H_V on the test network: far enough above Canopy (height 1) that Canopy's own grace is over.
const VAULT: u32 = 100;

#[test]
fn the_vault_grace_period_names_canopy_as_ycashd_s_previous_epoch() {
    let network = Network::new_regtest(
        ConfiguredActivationHeights {
            vault: Some(VAULT),
            ..Default::default()
        }
        .into(),
    );
    for (height, previous_upgrade) in [
        (VAULT - 1, None),
        (VAULT, Some(NetworkUpgrade::Canopy)),
        (VAULT + 39, Some(NetworkUpgrade::Canopy)),
        (VAULT + 40, None),
    ] {
        assert_eq!(
            upgrade_grace_period(&network, block::Height(height)),
            previous_upgrade,
            "height {height}"
        );
    }

    // A v4 spend signed for Canopy fails its script under Vault's branch ID. Inside the grace
    // period the relaying peer starts no cooldown; after it, it does.
    let peer = zakura_network::PeerSocketAddr::from(([203, 0, 113, 7], 8833));
    let failure = TransactionDownloadVerifyError::Invalid {
        error: TransactionError::SaplingVerificationFailed,
        advertiser_addr: Some(peer),
        tip_height: Some(block::Height(VAULT)),
        transaction_version: 4,
        transaction_network_upgrade: None,
        retried_after_tip_reset: false,
    };
    let tip = Some(block::Height(VAULT));
    assert_eq!(
        transaction_cooldown_peer(
            &failure,
            tip,
            NetworkUpgrade::Vault,
            upgrade_grace_period(&network, block::Height(VAULT)),
        ),
        None
    );
    assert_eq!(
        transaction_cooldown_peer(&failure, tip, NetworkUpgrade::Vault, None),
        Some(peer)
    );
}
