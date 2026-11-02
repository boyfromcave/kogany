//! Tests of the Ycash network profile: the activation tables and branch IDs against ycashd's.

use crate::{
    block::Height,
    parameters::{ConsensusBranchId, Network, NetworkKind, NetworkUpgrade, NetworkUpgrade::*},
};

use super::{magics, mainnet, ports, testnet};

/// What ycashd's `getblockchaininfo` reports as `consensus.chaintip` (`CurrentEpochBranchId`,
/// `ycash6 src/consensus/upgrades.cpp:141-143`) at the height bands of kogany survey B §3, as
/// `(first height of the band, branch ID)`. `0` is Sprout, which Zakura has no branch ID for.
const MAINNET_BANDS: &[(u32, u32)] = &[
    (0, 0),
    (347_500, 0x5ba81b19),
    (419_200, 0x76b809bb),
    (570_000, 0x374d694f),
    (1_100_000, 0x8e471bd6),
    (1_100_003, 0x66314da3),
    (1_100_006, 0x19bd2d2f),
];

/// As [`MAINNET_BANDS`], for the re-forked Ycash testnet (`ycash6 src/chainparams.cpp:429-459`).
const TESTNET_BANDS: &[(u32, u32)] = &[
    (0, 0),
    (207_500, 0x5ba81b19),
    (280_000, 0x76b809bb),
    (510_248, 0x374d694f),
    (510_250, 0x8e471bd6),
    (510_252, 0x66314da3),
    (510_254, 0x19bd2d2f),
];

fn branch_id_or_sprout(network: &Network, height: u32) -> u32 {
    ConsensusBranchId::current(network, Height(height)).map_or(0, u32::from)
}

/// Checks every band's first and last height, and a height inside it.
fn assert_bands(network: &Network, bands: &[(u32, u32)], tip: u32) {
    for (index, &(start, expected)) in bands.iter().enumerate() {
        let end = bands.get(index + 1).map_or(tip, |&(next, _)| next - 1);
        for height in [start, start + (end - start) / 2, end] {
            assert_eq!(
                branch_id_or_sprout(network, height),
                expected,
                "{network} branch ID at height {height}"
            );
        }
    }
}

#[test]
fn mainnet_branch_ids_match_ycashd_bands() {
    // The tip at the time of writing reported `chaintip: 19bd2d2f` (yecblockexplorer.com
    // Blockbook backend, height 3,086,793, 2026-11-02).
    assert_bands(&Network::Mainnet, MAINNET_BANDS, 3_086_793);
    assert_eq!(
        branch_id_or_sprout(&Network::Mainnet, Height::MAX.0),
        0x19bd2d2f
    );
}

#[test]
fn testnet_profiles_branch_ids_match_ycashd_bands() {
    for network in [
        Network::new_default_testnet(),
        Network::new_ycash_testnet_slow(),
    ] {
        assert_bands(&network, TESTNET_BANDS, 2_000_000);
    }
}

#[test]
fn ycash_heights_and_upgrade_order() {
    let expected = [
        (Height(0), Genesis),
        (mainnet::BEFORE_OVERWINTER, BeforeOverwinter),
        (mainnet::OVERWINTER, Overwinter),
        (mainnet::SAPLING, Sapling),
        (mainnet::YCASH, Ycash),
        (mainnet::BLOSSOM, Blossom),
        (mainnet::HEARTWOOD, Heartwood),
        (mainnet::CANOPY, Canopy),
    ];
    assert_eq!(
        Network::Mainnet
            .activation_list()
            .into_iter()
            .collect::<Vec<_>>(),
        expected
    );
    assert_eq!(
        Ycash.activation_height(&Network::Mainnet),
        Some(Height(570_000))
    );
    assert_eq!(
        Ycash.activation_height(&Network::new_default_testnet()),
        Some(testnet::YCASH)
    );

    // NU5 and later have no height on any Ycash network; `activation_height` falls back to the
    // next upgrade, which has none either.
    for network in [Network::Mainnet, Network::new_default_testnet()] {
        for nu in [Nu5, Nu6, Nu6_1, Nu6_2, Nu6_3, Nu7] {
            assert_eq!(nu.activation_height(&network), None, "{nu:?} on {network}");
        }
        assert!(!NetworkUpgrade::is_nu7_active(&network, Height::MAX));
        assert_eq!(network.temporary_orchard_disabling_soft_fork_height(), None);
        assert!(network.all_funding_streams().is_empty() || network.is_regtest());
        assert!(network.lockbox_disbursements(Height(1_100_006)).is_empty());
    }

    // The mandatory checkpoint is the block before Canopy (Zakura's rule) on each network.
    assert_eq!(
        Network::Mainnet.mandatory_checkpoint_height(),
        Height(1_100_005)
    );
    assert_eq!(
        Network::new_default_testnet().mandatory_checkpoint_height(),
        Height(510_253)
    );
}

#[test]
fn branch_id_table_is_ycashd_network_upgrade_info() {
    // `NetworkUpgradeInfo`, `ycash6 src/consensus/upgrades.cpp:12-99`.
    let expected = [
        (Overwinter, 0x5ba81b19),
        (Sapling, 0x76b809bb),
        (Ycash, 0x374d694f),
        (Blossom, 0x8e471bd6),
        (Heartwood, 0x66314da3),
        (Canopy, 0x19bd2d2f),
        (Nu5, 0xf919a198),
        (Nu6, 0xc8e71055),
        (Nu6_1, 0x4dec4df0),
        (Nu6_2, 0x5437f330),
    ];
    for (nu, id) in expected {
        assert_eq!(nu.branch_id().map(u32::from), Some(id), "{nu:?}");
        assert_eq!(NetworkUpgrade::try_from(id).ok(), Some(nu));
    }
    assert_eq!(Genesis.branch_id(), None);
    assert_eq!(BeforeOverwinter.branch_id(), None);
    // Zcash's post-fork IDs are not Ycash's.
    for zcash_id in [0x2bb40e60_u32, 0xf5b9230b, 0xe9ff75a6, 0xc2d6d0b4] {
        assert!(NetworkUpgrade::try_from(zcash_id).is_err(), "{zcash_id:#x}");
    }
}

#[test]
fn ycash_identity_ports_magics_names() {
    let fast = Network::new_default_testnet();
    let slow = Network::new_ycash_testnet_slow();
    let regtest = Network::new_regtest(Default::default());

    assert_eq!(Network::Mainnet.default_port(), ports::MAINNET);
    assert_eq!(fast.default_port(), ports::TESTNET_FAST);
    assert_eq!(slow.default_port(), ports::TESTNET_SLOW);
    assert_eq!(regtest.default_port(), ports::REGTEST);

    let params = |network: &Network| network.parameters().expect("a testnet");
    assert_eq!(params(&fast).network_magic(), magics::TESTNET_FAST);
    assert_eq!(params(&slow).network_magic(), magics::TESTNET_SLOW);
    assert_eq!(
        params(&regtest).network_magic(),
        crate::parameters::constants::magics::REGTEST
    );

    assert!(fast.is_default_testnet());
    assert!(!slow.is_default_testnet());
    assert_eq!(slow.to_string(), "TestnetSlow");
    assert_eq!(slow.kind(), NetworkKind::Testnet);
    assert_eq!(Network::Mainnet.bip70_network_name(), "main");
    assert_eq!(fast.bip70_network_name(), "test");

    // ZIP 200 maximum block time rule from Blossom + 6 on the testnet (`ycash6
    // src/chainparams.cpp:538`).
    assert!(!fast.is_max_block_time_enforced(Height(510_255)));
    assert!(fast.is_max_block_time_enforced(Height(510_256)));
}

#[test]
fn ycash_spacing_and_window_are_pre_blossom() {
    assert_eq!(Ycash.target_spacing(), Sapling.target_spacing());
    assert_eq!(Ycash.averaging_window(), Sapling.averaging_window());
    assert_eq!(
        NetworkUpgrade::target_spacing_for_height(&Network::Mainnet, Height(1_099_999))
            .num_seconds(),
        150
    );
    assert_eq!(
        NetworkUpgrade::target_spacing_for_height(&Network::Mainnet, Height(1_100_000))
            .num_seconds(),
        75
    );
}
