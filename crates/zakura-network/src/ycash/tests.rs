//! Tests for the Ycash peer-to-peer profile: the version table, the user agent, the inventory
//! filter, the seeds and the P2P stack.

use bytes::BytesMut;
use tokio_util::codec::{Decoder, Encoder};

use zakura_chain::{
    block::{self, Height},
    parameters::{
        testnet::{ConfiguredActivationHeights, RegtestParameters},
        Network, NetworkUpgrade,
    },
    transaction::{self, AuthDigest, WtxId},
};

use crate::{
    constants::CURRENT_NETWORK_PROTOCOL_VERSION,
    protocol::external::{Codec, InventoryHash, Message, Version},
    Config, P2pStack,
};

use super::*;

/// ycashd's `nProtocolVersion` per upgrade, `ycash6 src/chainparams.cpp` at `65cb4ae0f`:
/// (upgrade, mainnet `:115-154`, testnet `:422-463`, regtest `:727-766`).
const YCASHD_PROTOCOL_VERSIONS: &[(NetworkUpgrade, u32, u32, u32)] = &[
    (NetworkUpgrade::Genesis, 170_002, 170_002, 170_002),
    (NetworkUpgrade::BeforeOverwinter, 170_002, 170_002, 170_002),
    (NetworkUpgrade::Overwinter, 170_005, 170_003, 170_003),
    (NetworkUpgrade::Sapling, 170_007, 170_007, 170_006),
    (NetworkUpgrade::Ycash, 270_007, 270_007, 270_007),
    (NetworkUpgrade::Blossom, 270_009, 270_008, 170_008),
    (NetworkUpgrade::Heartwood, 270_011, 270_010, 170_010),
    (NetworkUpgrade::Canopy, 270_013, 270_012, 170_012),
    (NetworkUpgrade::Vault, 270_200, 270_200, 270_200),
    (NetworkUpgrade::Nu5, 270_015, 270_014, 170_050),
    (NetworkUpgrade::Nu6, 270_120, 270_110, 270_110),
    (NetworkUpgrade::Nu6_1, 270_140, 270_130, 270_130),
    (NetworkUpgrade::Nu6_2, 270_150, 270_150, 270_150),
];

/// The protocol versions Zcash nodes advertise: zcashd and Zebra from Overwinter to NU7. Each is
/// below the Ycash floor, so none can complete a handshake with kogany.
const ZCASH_PROTOCOL_VERSIONS: &[u32] = &[
    170_002, 170_005, 170_007, 170_009, 170_011, 170_013, 170_100, 170_120, 170_140, 170_150,
    170_160, 170_180, 170_190,
];

fn regtest() -> Network {
    Network::new_regtest(RegtestParameters {
        activation_heights: ConfiguredActivationHeights {
            ycash: Some(1),
            ..Default::default()
        },
        ..Default::default()
    })
}

#[test]
fn version_table_is_ycashd_n_protocol_version() {
    let networks = [Network::Mainnet, Network::new_default_testnet(), regtest()];

    for &(upgrade, mainnet, testnet, regtest) in YCASHD_PROTOCOL_VERSIONS {
        for (network, expected) in networks.iter().zip([mainnet, testnet, regtest]) {
            assert_eq!(
                min_specified_for_upgrade(network, upgrade),
                Version(expected),
                "{upgrade:?} on {network:?}",
            );
            assert_eq!(
                Version::min_specified_for_upgrade(network, upgrade),
                Version(expected),
                "the upstream table defers to the Ycash one for {upgrade:?} on {network:?}",
            );
        }
    }

    // The slow testnet profile is a testnet like the fast one.
    assert_eq!(
        min_specified_for_upgrade(&Network::new_ycash_testnet_slow(), NetworkUpgrade::Canopy),
        Version(270_012),
    );
}

#[test]
fn upgrades_ycashd_never_schedules_are_unreachable() {
    for upgrade in [NetworkUpgrade::Nu6_3, NetworkUpgrade::Nu7] {
        assert_eq!(
            min_specified_for_upgrade(&Network::Mainnet, upgrade),
            Version(UNREACHABLE_PROTOCOL_VERSION),
        );
        assert!(
            min_specified_for_upgrade(&Network::Mainnet, upgrade)
                > CURRENT_NETWORK_PROTOCOL_VERSION
        );
    }
}

#[test]
fn kogany_advertises_ycash6s_vault_era_version() {
    assert_eq!(CURRENT_NETWORK_PROTOCOL_VERSION, Version(270_200));
    assert_eq!(
        CURRENT_NETWORK_PROTOCOL_VERSION,
        Version(CURRENT_PROTOCOL_VERSION)
    );
    assert!(CURRENT_NETWORK_PROTOCOL_VERSION >= MIN_PEER_PROTO_VERSION);
}

fn vault_regtest(vault: u32) -> Network {
    Network::new_regtest(RegtestParameters {
        activation_heights: ConfiguredActivationHeights {
            overwinter: Some(1),
            sapling: Some(1),
            ycash: Some(1),
            blossom: Some(1),
            heartwood: Some(1),
            canopy: Some(1),
            vault: Some(vault),
            ..Default::default()
        },
        ..Default::default()
    })
}

/// `Version::min_remote_for_height` panics if kogany's own version is below the minimum it
/// demands, so the advertised version must cover every scheduled upgrade on every Ycash network.
#[test]
fn minimum_peer_version_never_exceeds_the_advertised_version() {
    let networks = [
        Network::Mainnet,
        Network::new_default_testnet(),
        Network::new_ycash_testnet_slow(),
        regtest(),
        vault_regtest(1),
        vault_regtest(103),
    ];
    for network in networks {
        let mut heights: Vec<u32> = (0..1_200).collect();
        heights.extend(
            [
                347_500, 419_200, 510_248, 510_254, 570_000, 1_100_000, 1_100_006, 2_275_000,
                3_000_000,
            ]
            .iter()
            .flat_map(|&h| [h - 1, h, h + 1]),
        );
        heights.push(Height::MAX.0);
        for height in heights {
            let minimum = Version::min_remote_for_height(&network, Height(height));
            assert!(
                minimum <= CURRENT_NETWORK_PROTOCOL_VERSION,
                "{minimum:?} above the advertised version at {height} on {network:?}",
            );
            assert!(minimum >= MIN_PEER_PROTO_VERSION);
        }
    }

    // From Vault on, a ycashd 4.5.0-era peer (270013) is refused and ycash6 (270200) is not.
    let network = vault_regtest(103);
    assert_eq!(
        Version::min_remote_for_height(&network, Height(102)),
        MIN_PEER_PROTO_VERSION
    );
    assert_eq!(
        Version::min_remote_for_height(&network, Height(103)),
        Version(270_200)
    );
}

#[test]
fn minimum_peer_version_is_the_ycash_floor_in_every_band() {
    let mainnet_band_starts = [
        0, 1, 347_500, 419_200, 570_000, 1_100_000, 1_100_003, 1_100_006, 3_000_000,
    ];
    for height in mainnet_band_starts {
        assert_eq!(
            Version::min_remote_for_height(&Network::Mainnet, Height(height)),
            MIN_PEER_PROTO_VERSION,
            "mainnet height {height}",
        );
    }

    // Before Vault both testnet profiles hold peers to the floor; the `fast` profile schedules
    // Vault at 510,400 (`zakura_chain::parameters::ycash::testnet::VAULT_FAST`), the `slow` one
    // has no Vault height.
    let testnet_band_starts = [
        0, 207_500, 280_000, 510_248, 510_250, 510_252, 510_254, 510_399,
    ];
    for height in testnet_band_starts.into_iter().chain([510_400, 2_000_000]) {
        assert_eq!(
            Version::min_remote_for_height(&Network::new_ycash_testnet_slow(), Height(height)),
            MIN_PEER_PROTO_VERSION,
            "slow testnet height {height}",
        );
    }
    for height in testnet_band_starts {
        assert_eq!(
            Version::min_remote_for_height(&Network::new_default_testnet(), Height(height)),
            MIN_PEER_PROTO_VERSION,
            "testnet height {height}",
        );
    }
    for height in [510_400, 2_000_000] {
        assert_eq!(
            Version::min_remote_for_height(&Network::new_default_testnet(), Height(height)),
            Version(270_200),
            "testnet height {height}, Vault active",
        );
    }

    for height in [0, 1, 200] {
        assert_eq!(
            Version::min_remote_for_height(&regtest(), Height(height)),
            MIN_PEER_PROTO_VERSION,
            "regtest height {height}",
        );
    }

    assert_eq!(
        Version::min_remote_for_height(&Network::Mainnet, None),
        MIN_PEER_PROTO_VERSION,
        "before the tip is known",
    );
}

#[test]
fn zcash_versions_are_below_the_floor() {
    for &zcash in ZCASH_PROTOCOL_VERSIONS {
        for network in [Network::Mainnet, Network::new_default_testnet(), regtest()] {
            assert!(
                Version(zcash) < Version::min_remote_for_height(&network, None),
                "a Zcash peer advertising {zcash} must be refused on {network:?}",
            );
        }
    }
    // ycashd 4.5.0 and Yolk advertise exactly the floor; ycash6 advertises 270200.
    for ycash in [270_013, 270_200] {
        assert!(
            Version(ycash) >= Version::min_remote_for_height(&Network::Mainnet, Height(3_000_000))
        );
    }
}

#[test]
fn user_agent_is_kogany() {
    assert_eq!(user_agent("1.8.0-rc0"), "/kogany:1.8.0-rc0/");
    // `MAX_SUBVERSION_LENGTH` (ycashd) and `MAX_USER_AGENT_LENGTH` (Zakura) are both 256.
    assert!(user_agent("1.8.0-rc0").len() <= 256);
}

fn wtx() -> InventoryHash {
    InventoryHash::Wtx(WtxId {
        id: transaction::Hash([7; 32]),
        auth_digest: AuthDigest([8; 32]),
    })
}

fn legacy_inventory() -> Vec<InventoryHash> {
    vec![
        InventoryHash::Tx(transaction::Hash([1; 32])),
        InventoryHash::Block(block::Hash([2; 32])),
    ]
}

#[test]
fn inventory_filter_keeps_everything_but_msg_wtx() {
    for inventory in legacy_inventory() {
        assert!(is_ycash_inventory(&inventory));
    }
    assert!(is_ycash_inventory(&InventoryHash::Error));
    assert!(is_ycash_inventory(&InventoryHash::FilteredBlock(
        block::Hash([3; 32])
    )));
    assert!(!is_ycash_inventory(&wtx()));

    let mut mixed = legacy_inventory();
    mixed.insert(1, wtx());
    assert_eq!(outbound_inventory(&mixed), legacy_inventory());
}

fn encode(message: Message) -> BytesMut {
    let mut bytes = BytesMut::new();
    Codec::builder()
        .for_network(&Network::Mainnet)
        .finish()
        .encode(message, &mut bytes)
        .expect("an inventory message within the size limit encodes");
    bytes
}

fn decode(mut bytes: BytesMut) -> Result<Option<Message>, crate::BoxError> {
    Codec::builder()
        .for_network(&Network::Mainnet)
        .finish()
        .decode(&mut bytes)
        .map_err(Into::into)
}

#[test]
fn msg_wtx_is_never_sent() {
    for message in [Message::Inv, Message::GetData, Message::NotFound] {
        let mut with_wtx = legacy_inventory();
        with_wtx.push(wtx());

        let decoded = decode(encode(message(with_wtx)))
            .expect("the filtered message decodes")
            .expect("the whole message was encoded");

        assert_eq!(decoded, message(legacy_inventory()));
    }
}

#[test]
fn msg_wtx_is_refused_on_receipt() {
    // Encode a `MSG_WTX` entry by hand, the way a Zcash NU5 peer would send it.
    let mut entry = Vec::new();
    zakura_chain::serialization::ZcashSerialize::zcash_serialize(
        &vec![InventoryHash::Tx(transaction::Hash([0; 32]))],
        &mut entry,
    )
    .expect("serializing to a Vec does not fail");
    // A one-entry list: the count, then code 1 and 32 bytes. Rewrite it as code 5 with 64 bytes.
    entry[1] = 5;
    entry.extend_from_slice(&[9; 32]);

    let mut ycash_message = encode(Message::Inv(vec![InventoryHash::Tx(transaction::Hash(
        [0; 32],
    ))]));
    // Splice the hand-made body into a correctly framed message: header length and checksum.
    let header_len = 24;
    ycash_message.truncate(header_len);
    ycash_message[16..20].copy_from_slice(&(entry.len() as u32).to_le_bytes()); // a 69-byte body fits u32
    let checksum = zakura_chain::serialization::sha256d::Checksum::from(&entry[..]);
    ycash_message[20..24].copy_from_slice(&checksum.0);
    ycash_message.extend_from_slice(&entry);

    let error = decode(ycash_message).expect_err("MSG_WTX inventory is refused");
    assert!(
        error.to_string().contains(MSG_WTX_REFUSED),
        "unexpected error: {error}",
    );
}

#[test]
fn default_seeds_and_port_are_ycash() {
    let config = Config::default();

    assert_eq!(
        config.initial_mainnet_peers.iter().collect::<Vec<_>>(),
        vec!["seed.ycash.xyz:8833"],
    );
    assert!(config.initial_testnet_peers.is_empty());
    assert_eq!(config.listen_addr.port(), 8833);
    for peer in &config.initial_mainnet_peers {
        assert!(!peer.contains("z.cash") && !peer.contains("zfnd") && !peer.contains(":8233"));
    }
}

#[test]
fn p2p_v2_is_off_on_every_network() {
    for network in [
        Network::Mainnet,
        Network::new_default_testnet(),
        Network::new_ycash_testnet_slow(),
        regtest(),
    ] {
        for stack in [
            P2pStack::Default,
            P2pStack::Legacy,
            P2pStack::Zakura,
            P2pStack::Dual,
        ] {
            assert_eq!(
                stack.resolve(&network),
                P2pStack::Legacy,
                "{stack:?} on {network:?}"
            );

            let config = Config {
                network: network.clone(),
                p2p_stack: stack,
                ..Config::default()
            };
            assert!(config.legacy_p2p());
            assert!(!config.v2_p2p());
        }
    }
}

#[test]
fn configuring_p2p_v2_is_refused() {
    for stack in ["zakura", "dual"] {
        let error = toml::from_str::<Config>(&format!("p2p_stack = \"{stack}\""))
            .expect_err("a v2 stack is refused on Ycash");
        assert!(
            error.to_string().contains("K-11"),
            "unexpected error: {error}"
        );
    }
    for setting in ["v2_p2p = true", "legacy_p2p = false"] {
        let error = toml::from_str::<Config>(setting).expect_err("a v2 stack is refused on Ycash");
        assert!(
            error.to_string().contains("K-11"),
            "unexpected error: {error}"
        );
    }

    for stack in [
        "p2p_stack = \"legacy\"",
        "p2p_stack = \"default\"",
        "v2_p2p = false",
        "",
    ] {
        let config = toml::from_str::<Config>(stack).expect("a legacy stack is accepted");
        assert!(config.legacy_p2p() && !config.v2_p2p());
    }
}
