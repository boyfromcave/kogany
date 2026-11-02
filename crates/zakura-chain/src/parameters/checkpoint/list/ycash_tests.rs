//! kogany: the Ycash checkpoint lists (W1-Y4; K-9; M24-14), checked in a `ycash` build.

use crate::parameters::{ycash, Network, NetworkUpgrade};

use super::*;

/// ycashd's pinned hashes the lists must carry wherever they reach (`ycash6 src/chainparams.cpp`
/// at 65cb4ae0f: `:131-132` fork block, `:252-283` mainnet, `:571-583` testnet).
const MAINNET_PINS: &[(u32, &str)] = &[
    (570_000, ycash::mainnet::YCASH_ACTIVATION_BLOCK_HASH),
    (572_760, "00000008db657f58222e38e354c18ccbb6c74cf525ef4f3a95f0f8a324a3166d"),
    (980_000, "00000510ccc6bae2ddb38b9313ffb9686397f6cd0dee243462baeaf8911d0791"),
    (1_035_353, "00000543378a75f173914390c672838c9fbd9dc86ae647ffae18ed6b626edb30"),
    (1_575_000, "000002b856230b06caa3412058e6490fab256cee9d9d9fb68eae59b4ebd94471"),
    (2_250_000, "000003f98b7497fdcd8a6b6d10a93a887c5d47127e24a9dc3a40cb65754d21e7"),
];
const TESTNET_PINS: &[(u32, &str)] = &[
    (38_000, "001e9a2d2e2892b88e9998cf7b079b41d59dd085423a921fe8386cecc42287b8"),
    (510_247, "0000ec904003d5591290064b0b4d3ccddffe87ef2a3a131284438959bf68fb31"),
];

fn assert_pins(network: &Network, pins: &[(u32, &str)]) {
    let list = network.checkpoint_list();
    assert_eq!(list.hash(block::Height(0)), Some(network.genesis_hash()));
    for (height, hash) in pins {
        let height = block::Height(*height);
        if height > list.max_height() {
            continue;
        }
        assert_eq!(
            list.hash(height),
            Some(hash.parse().expect("hard-coded hash parses")),
            "the list must carry ycashd's pin at {height:?}"
        );
    }
}

/// No list reaches the Vault epoch (M24-14): checkpoints never cover vault or YED state.
fn assert_below_vault(network: &Network) {
    if let Some(vault) = NetworkUpgrade::Vault.activation_height(network) {
        assert!(network.checkpoint_list().max_height() < vault);
    }
}

#[test]
fn ycash_mainnet_list_carries_the_pins() {
    assert_pins(&Network::Mainnet, MAINNET_PINS);
    assert_below_vault(&Network::Mainnet);
}

#[test]
fn ycash_testnet_lists_stop_at_the_shared_history() {
    for network in [
        Network::new_default_testnet(),
        Network::new_ycash_testnet_slow(),
    ] {
        assert_pins(&network, TESTNET_PINS);
        assert_below_vault(&network);
        assert_eq!(
            network.checkpoint_list().max_height(),
            ycash::testnet::LAST_SHARED_HEIGHT,
            "the re-forked testnet's checkpoints above the fork come with its first rc"
        );
        assert!(network.ycash_checkpoint_list_is_partial());
    }
}

#[test]
fn ycash_regtest_list_is_never_partial() {
    assert!(!Network::new_regtest(Default::default()).ycash_checkpoint_list_is_partial());
}
