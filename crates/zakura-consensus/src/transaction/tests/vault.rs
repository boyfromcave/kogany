//! The Vault epoch at the transaction layer (kogany plan W2-b, U-26): v4 stays valid, v5 is
//! refused, on a regtest that schedules Vault and, in a `ycash` build, on the Ycash `fast` testnet.

use zakura_chain::{
    block::Height,
    parameters::{
        testnet::{ConfiguredActivationHeights, RegtestParameters},
        Network, NetworkUpgrade,
    },
    transaction::{LockTime, Transaction},
};

use crate::error::TransactionError;

use super::{test_transactions, verify_v4_at, TestVerifier};

/// An empty v5 transaction (the network-upgrade check reads only the version).
fn empty_v5() -> Transaction {
    Transaction::V5 {
        network_upgrade: NetworkUpgrade::Nu5,
        lock_time: LockTime::unlocked(),
        expiry_height: Height(0),
        inputs: Vec::new(),
        outputs: Vec::new(),
        sapling_shielded_data: None,
        orchard_shielded_data: None,
    }
}

/// Networks scheduling Vault, with its activation height.
fn vault_networks() -> Vec<(Network, Height)> {
    let regtest = Network::new_regtest(RegtestParameters::from(ConfiguredActivationHeights {
        vault: Some(10),
        ..Default::default()
    }));
    #[allow(unused_mut)]
    let mut networks = vec![(regtest, Height(10))];
    #[cfg(feature = "ycash")]
    networks.push((
        Network::new_default_testnet(),
        zakura_chain::parameters::ycash::testnet::VAULT_FAST,
    ));
    networks
}

#[test]
fn v4_is_valid_and_v5_is_refused_under_vault() {
    let _init_guard = zakura_test::init();

    let v4 = test_transactions(&Network::Mainnet)
        .map(|(_, transaction)| transaction)
        .find(|transaction| matches!(**transaction, Transaction::V4 { .. }))
        .expect("the test vectors contain a V4 transaction");
    let v5 = empty_v5();

    for (network, vault) in vault_networks() {
        let before = vault.previous().expect("Vault is above height 0");
        let after = vault.next().expect("Vault is below the maximum height");
        assert_eq!(
            NetworkUpgrade::current(&network, before),
            NetworkUpgrade::Canopy
        );
        assert!(!network.is_vault_active(before));

        for height in [before, vault, after] {
            assert!(
                verify_v4_at(&network, &v4, height).is_ok(),
                "{network}: a V4 transaction stays valid at {height:?}"
            );
        }
        for height in [vault, after] {
            let nu = NetworkUpgrade::current(&network, height);
            assert_eq!(nu, NetworkUpgrade::Vault);
            assert!(network.is_vault_active(height));
            assert_eq!(
                TestVerifier::verify_v5_transaction_network_upgrade(&v5, nu),
                Err(TransactionError::UnsupportedByNetworkUpgrade(
                    5,
                    NetworkUpgrade::Vault
                )),
                "{network}: v5 is invalid under Vault at {height:?} (U-26)"
            );
        }
        // Canopy refuses v5 the same way: Vault keeps the Canopy-era rule.
        assert_eq!(
            TestVerifier::verify_v5_transaction_network_upgrade(&v5, NetworkUpgrade::Canopy),
            Err(TransactionError::UnsupportedByNetworkUpgrade(
                5,
                NetworkUpgrade::Canopy
            )),
        );
    }
}
