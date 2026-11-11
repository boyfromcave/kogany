//! kogany: the Ycash checkpoint lists (W1-Y4; K-9; M24-14), checked in a `ycash` build.

use crate::parameters::{ycash, Network};

use super::*;

/// ycashd's pinned hashes the lists must carry wherever they reach (`ycash6 src/chainparams.cpp`
/// at 65cb4ae0f: `:131-132` fork block, `:252-283` mainnet, `:571-583` testnet).
const MAINNET_PINS: &[(u32, &str)] = &[
    (570_000, ycash::mainnet::YCASH_ACTIVATION_BLOCK_HASH),
    (
        572_760,
        "00000008db657f58222e38e354c18ccbb6c74cf525ef4f3a95f0f8a324a3166d",
    ),
    (
        980_000,
        "00000510ccc6bae2ddb38b9313ffb9686397f6cd0dee243462baeaf8911d0791",
    ),
    (
        1_035_353,
        "00000543378a75f173914390c672838c9fbd9dc86ae647ffae18ed6b626edb30",
    ),
    (
        1_575_000,
        "000002b856230b06caa3412058e6490fab256cee9d9d9fb68eae59b4ebd94471",
    ),
    (
        2_250_000,
        "000003f98b7497fdcd8a6b6d10a93a887c5d47127e24a9dc3a40cb65754d21e7",
    ),
];
const TESTNET_PINS: &[(u32, &str)] = &[
    (
        38_000,
        "001e9a2d2e2892b88e9998cf7b079b41d59dd085423a921fe8386cecc42287b8",
    ),
    (
        510_253,
        "0297aad933fdf3f5e07acff13992e138ab4fec56033cdfa3a3815535ff049dbb",
    ),
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
    // Vault's explicit height only (never the fallback), per the is_vault_active rule.
    if let Some(vault) = network.vault_activation_height() {
        assert!(!network.is_vault_active(network.checkpoint_list().max_height()));
        assert!(network.checkpoint_list().max_height() < vault);
    }
}

#[test]
fn ycash_mainnet_list_carries_the_pins() {
    assert_pins(&Network::Mainnet, MAINNET_PINS);
    assert_below_vault(&Network::Mainnet);
}

#[test]
fn ycash_testnet_list_reaches_the_mandatory_checkpoint() {
    let network = Network::new_default_testnet();
    assert_pins(&network, TESTNET_PINS);
    assert_below_vault(&network);
    assert_eq!(
        network.checkpoint_list().max_height(),
        network.mandatory_checkpoint_height(),
        "the re-fork below Canopy is checkpointed; Canopy on is verified semantically"
    );
    assert!(network.checkpoint_list().max_height() > ycash::testnet::LAST_SHARED_HEIGHT);
}

#[test]
fn ycash_shadow_lists_are_mainnet_through_the_split() {
    use crate::parameters::ycash::{
        SHADOW_ACTIVATION_HEIGHT, SHADOW_SPLIT_HASH, SHADOW_SPLIT_HEIGHT,
    };
    let mainnet = Network::Mainnet.checkpoint_list();
    for network in [
        Network::new_ycash_testnet_slow(),
        Network::new_ycash_testnet_legacy(),
    ] {
        let list = network.checkpoint_list();
        assert_eq!(list.hash(block::Height(0)), Some(network.genesis_hash()));
        assert_eq!(network.genesis_hash(), Network::Mainnet.genesis_hash());
        assert_eq!(list.max_height(), block::Height(SHADOW_SPLIT_HEIGHT));
        assert_eq!(
            list.hash(block::Height(SHADOW_SPLIT_HEIGHT)),
            Some(SHADOW_SPLIT_HASH.parse().expect("hash"))
        );
        assert!(!network.ycash_checkpoint_list_is_partial());
        for (height, hash) in mainnet.iter_cloned() {
            if height.0 >= SHADOW_ACTIVATION_HEIGHT.0 {
                assert_eq!(list.hash(height), None, "{height:?}");
            } else if height.0 != SHADOW_SPLIT_HEIGHT {
                assert_eq!(list.hash(height), Some(hash), "{height:?}");
            }
        }
    }
}

#[test]
fn ycash_regtest_list_is_never_partial() {
    assert!(!Network::new_regtest(Default::default()).ycash_checkpoint_list_is_partial());
}
