//! The Ycash network profile (kogany), compiled under the `ycash` cargo feature.
//!
//! In a `ycash` build every network is a Ycash network: [`Network::Mainnet`] is Ycash mainnet,
//! the default [`Network::Testnet`] is the re-forked Ycash testnet's `fast` profile, and Regtest is
//! Ycash regtest. The values here replace Zakura's Zcash tables in place, the way ycashd rewrites
//! zcashd's `CMainParams` (kogany plan §2.3, decision K-5). Every value cites the C++ line it
//! mirrors: `ycash6` at `65cb4ae0f` (`vaults/kogany-compat` = `upgrade/vault`).
//!
//! The Vault upgrade is runtime-gated by its height ([`Network::is_vault_active`], W2-b): this
//! module only carries the heights ycashd compiles in. Ycash mainnet has none (set by the
//! gate-passing release, upgrade plan P8), the `fast` testnet profile has 510,400, the shadow
//! profiles (`slow`, `legacy`) have none until an rc sets slow's, and Regtest takes `Vault`
//! from its configured activation heights.
//!
//! [`Network::is_vault_active`]: super::Network::is_vault_active
//!
//! [`Network::Mainnet`]: super::Network::Mainnet
//! [`Network::Testnet`]: super::Network::Testnet

use crate::block::Height;

use super::{
    network::magic::Magic,
    network_upgrade::{NetworkUpgrade, NetworkUpgrade::*},
};

/// Network upgrade activation heights on Ycash mainnet.
///
/// `ycash6 src/chainparams.cpp:114-160` (`CMainParams`): the shared Zcash history up to
/// Sapling, the Ycash fork at 570,000, then Blossom, Heartwood and Canopy three blocks apart.
/// NU5, NU6, NU6.1, NU6.2 (and NU6.3, NU7, which ycashd does not define) have no height.
pub mod mainnet {
    use crate::block::Height;

    /// The block height at which `BeforeOverwinter` activates on Ycash mainnet.
    pub const BEFORE_OVERWINTER: Height = Height(1);
    /// The block height at which `Overwinter` activates on Ycash mainnet (shared with Zcash).
    pub const OVERWINTER: Height = Height(347_500);
    /// The block height at which `Sapling` activates on Ycash mainnet (shared with Zcash).
    pub const SAPLING: Height = Height(419_200);
    /// The block height of the Ycash fork, `UPGRADE_YCASH` (`ycash6 src/chainparams.cpp:130`).
    pub const YCASH: Height = Height(570_000);
    /// The block height at which `Blossom` activates on Ycash mainnet.
    pub const BLOSSOM: Height = Height(1_100_000);
    /// The block height at which `Heartwood` activates on Ycash mainnet.
    pub const HEARTWOOD: Height = Height(1_100_003);
    /// The block height at which `Canopy` activates on Ycash mainnet.
    pub const CANOPY: Height = Height(1_100_006);

    /// The hash of the Ycash fork block, `UPGRADE_YCASH.hashActivationBlock`
    /// (`ycash6 src/chainparams.cpp:131-132`). Zakura enforces it through the checkpoint list.
    pub const YCASH_ACTIVATION_BLOCK_HASH: &str =
        "0000014fbc5917ba8bcacf3336faf588d86b32443aa3a490a587af5750c77ec5";
}

/// Network upgrade activation heights on the re-forked Ycash testnet, the `fast` profile.
///
/// testnet-yb-slow and testnet-legacy are shadow forks of mainnet (`new_ycash_testnet_slow`,
/// `new_ycash_testnet_legacy`), not this table.
///
/// `ycash6 src/chainparams.cpp:429-459` (`CTestNetParams`): Zcash testnet history through
/// 510,247, the new fork block at 510,248, then Blossom, Heartwood and Canopy two blocks apart.
/// The `fast` profile adds Vault at [`testnet::VAULT_FAST`]; the `slow` profile has no Vault height.
pub mod testnet {
    use crate::block::Height;

    /// The block height at which `BeforeOverwinter` activates on the Ycash testnet.
    pub const BEFORE_OVERWINTER: Height = Height(1);
    /// The block height at which `Overwinter` activates on the Ycash testnet (Zcash testnet's).
    pub const OVERWINTER: Height = Height(207_500);
    /// The block height at which `Sapling` activates on the Ycash testnet (Zcash testnet's).
    pub const SAPLING: Height = Height(280_000);
    /// The block height of the re-forked Ycash testnet's fork block.
    pub const YCASH: Height = Height(510_248);
    /// The block height at which `Blossom` activates on the Ycash testnet.
    pub const BLOSSOM: Height = Height(510_250);
    /// The block height at which `Heartwood` activates on the Ycash testnet.
    pub const HEARTWOOD: Height = Height(510_252);
    /// The block height at which `Canopy` activates on the Ycash testnet.
    pub const CANOPY: Height = Height(510_254);
    /// The block height at which `Vault` activates on the `fast` testnet profile only
    /// (`CTestNetFastParams`, `ycash6 src/chainparams.cpp:640`; H_V, a placeholder until the
    /// testnet's launch ceremony fixes it). The `slow` profile has none until its first rc.
    pub const VAULT_FAST: Height = Height(510_400);

    /// The first height of the maximum block time rule on the Ycash testnet:
    /// `nFutureTimestampSoftForkHeight = Blossom + 6` (`ycash6 src/chainparams.cpp:538`).
    pub const MAX_TIME_START_HEIGHT: Height = Height(510_256);

    /// The highest Zcash testnet height whose checkpoint the Ycash testnet shares: the last block
    /// before the re-fork (`ycash6 src/chainparams.cpp:581-583`, testnet-prefix-v1 manifest).
    pub const LAST_SHARED_HEIGHT: Height = Height(510_247);
}

/// Ycash mainnet activation list, in height order.
pub(super) const MAINNET_ACTIVATION_HEIGHTS: &[(Height, NetworkUpgrade)] = &[
    (Height(0), Genesis),
    (mainnet::BEFORE_OVERWINTER, BeforeOverwinter),
    (mainnet::OVERWINTER, Overwinter),
    (mainnet::SAPLING, Sapling),
    (mainnet::YCASH, Ycash),
    (mainnet::BLOSSOM, Blossom),
    (mainnet::HEARTWOOD, Heartwood),
    (mainnet::CANOPY, Canopy),
];

/// Ycash testnet activation list, in height order: the default (`fast`) profile's.
pub(super) const TESTNET_ACTIVATION_HEIGHTS: &[(Height, NetworkUpgrade)] = &[
    (Height(0), Genesis),
    (testnet::BEFORE_OVERWINTER, BeforeOverwinter),
    (testnet::OVERWINTER, Overwinter),
    (testnet::SAPLING, Sapling),
    (testnet::YCASH, Ycash),
    (testnet::BLOSSOM, Blossom),
    (testnet::HEARTWOOD, Heartwood),
    (testnet::CANOPY, Canopy),
    (testnet::VAULT_FAST, Vault),
];

/// Ycash network magics. Mainnet and Regtest share Zcash's (`ycash6 src/chainparams.cpp:224-227,
/// 820-823`), so Zakura's [`magics::MAINNET`](super::constants::magics::MAINNET) and
/// [`magics::REGTEST`](super::constants::magics::REGTEST) are used unchanged. The re-forked
/// testnet profiles have their own (`ycash6 src/chainparams.cpp:644-647,665-668`).
pub mod magics {
    use super::Magic;

    /// The re-forked Ycash testnet, `fast` profile (`testnet-yb-fast`).
    pub const TESTNET_FAST: Magic = Magic([0xf7, 0x79, 0x62, 0xd3]);
    /// testnet-yb-slow, the shadow fork of mainnet.
    pub const TESTNET_SLOW: Magic = Magic([0xf7, 0x79, 0x62, 0xd4]);
    /// testnet-legacy, the shadow fork of mainnet with no Vault activation.
    pub const TESTNET_LEGACY: Magic = Magic([0xf7, 0x79, 0x62, 0xd5]);
}

/// Default P2P ports (`nDefaultPort`, `ycash6 src/chainparams.cpp:228,648,669,824`).
pub mod ports {
    /// Ycash mainnet.
    pub const MAINNET: u16 = 8833;
    /// Ycash testnet, `fast` profile.
    pub const TESTNET_FAST: u16 = 18833;
    /// Ycash testnet, `slow` profile.
    pub const TESTNET_SLOW: u16 = 18933;
    /// Ycash testnet, `legacy` profile.
    pub const TESTNET_LEGACY: u16 = 19033;
    /// Ycash regtest.
    pub const REGTEST: u16 = 18344;

    /// Default RPC ports (`ycash6 src/chainparamsbase.cpp`), for the RPC configuration (W1-Y6).
    pub mod rpc {
        /// Ycash mainnet.
        pub const MAINNET: u16 = 8832;
        /// Ycash testnet, `fast` profile.
        pub const TESTNET_FAST: u16 = 18832;
        /// Ycash testnet, `slow` profile.
        pub const TESTNET_SLOW: u16 = 18932;
        /// Ycash testnet, `legacy` profile.
        pub const TESTNET_LEGACY: u16 = 19032;
        /// Ycash regtest: the same as the `fast` testnet's, as in ycashd
        /// (`ycash6 src/chainparamsbase.cpp:62,73`; `ref/ycash src/chainparamsbase.cpp:48,62`).
        /// Two such nodes on one host need an explicit `rpc.listen_addr`, as two ycashd do.
        pub const REGTEST: u16 = 18832;
    }
}

/// Seeds, for the network configuration (W1-Y5).
///
/// Mainnet has one DNS seeder (`ycash6 src/chainparams.cpp:241-242`) and no fixed seeds yet
/// (`pnSeed6_main` is empty, `src/chainparamsseeds.h`). The re-forked testnet profiles have fixed
/// seeds only, all empty until the testnet's rc1 (`ycash6 src/chainparams.cpp:560-562`).
pub mod seeds {
    /// Ycash mainnet DNS seeders, with the mainnet port.
    pub const MAINNET_DNS: &[&str] = &["seed.ycash.xyz:8833"];
    /// Ycash testnet DNS seeders: none (fixed seeds only).
    pub const TESTNET_DNS: &[&str] = &[];
}

/// Network names. The names Zakura displays stay `Mainnet`, `Testnet` and `Regtest`, and the
/// BIP70 names `main` / `test` match ycashd's `strNetworkID`. The `slow` testnet profile is a
/// configured testnet with this name (`strTestnetProfile`, `ycash6 src/chainparams.cpp:661`).
pub mod names {
    /// The `slow` Ycash testnet profile.
    pub const TESTNET_SLOW: &str = "TestnetSlow";
    /// The `legacy` Ycash testnet profile.
    pub const TESTNET_LEGACY: &str = "TestnetLegacy";
}

/// Last Ycash mainnet block copied into testnet-yb-slow and testnet-legacy
/// (`ycash6` `TESTNET_SHADOW_SPLIT_HEIGHT`).
pub const SHADOW_SPLIT_HEIGHT: u32 = 3_079_999;

/// `UPGRADE_SHADOW` activates at H_S + 1 on both shadow profiles.
pub const SHADOW_ACTIVATION_HEIGHT: Height = Height(SHADOW_SPLIT_HEIGHT + 1);

/// Block hash of H_S (`ycash6` `TESTNET_SHADOW_SPLIT_HASH`).
pub const SHADOW_SPLIT_HASH: &str =
    "000005030be4763e433447000ef6b98c7ce310a8b0b7bb50f1a6aca3d31e4bef";

/// Ycash mainnet genesis, also the shadow forks' genesis (`ycash6` `CMainParams`).
pub const MAINNET_GENESIS_HASH: &str =
    "00040fe8ec8471911baa1db1266ea15dd06b4a8a5c453883c000b031973dce08";

/// testnet-yb-slow shadow branch id (`SLOW_SHADOW_BRANCH_ID`).
pub const SLOW_SHADOW_BRANCH_ID: u32 = 0x57a2_4d5d;
/// testnet-yb-slow Vault branch id (`SLOW_VAULT_BRANCH_ID`).
pub const SLOW_VAULT_BRANCH_ID: u32 = 0xe1f1_cc08;
/// testnet-legacy shadow branch id (`LEGACY_SHADOW_BRANCH_ID`).
pub const LEGACY_SHADOW_BRANCH_ID: u32 = 0x3570_6728;

/// Whether `network` is testnet-yb-slow or testnet-legacy.
pub fn is_shadow_network(network: &super::Network) -> bool {
    let magic = network.magic();
    magic == magics::TESTNET_SLOW || magic == magics::TESTNET_LEGACY
}

/// Whether `network` is the fast re-fork (`f77962d3`).
pub fn is_fast_network(network: &super::Network) -> bool {
    network.magic() == magics::TESTNET_FAST
}

/// Branch id override for this profile. `None` means the global [`NetworkUpgrade::branch_id`] table.
pub fn profile_branch_id(
    network: &super::Network,
    upgrade: super::NetworkUpgrade,
) -> Option<super::ConsensusBranchId> {
    use super::NetworkUpgrade::*;
    let magic = network.magic();
    if magic == magics::TESTNET_SLOW {
        return match upgrade {
            Shadow => Some(super::ConsensusBranchId(SLOW_SHADOW_BRANCH_ID)),
            Vault => Some(super::ConsensusBranchId(SLOW_VAULT_BRANCH_ID)),
            _ => None,
        };
    }
    if magic == magics::TESTNET_LEGACY {
        return match upgrade {
            Shadow => Some(super::ConsensusBranchId(LEGACY_SHADOW_BRANCH_ID)),
            _ => None,
        };
    }
    None
}

/// Mainnet checkpoints at heights below the shadow activation, plus the H_S pin.
pub fn shadow_checkpoint_pairs() -> Vec<(Height, crate::block::Hash)> {
    let mut items: Vec<(Height, crate::block::Hash)> = super::Network::Mainnet
        .checkpoint_list()
        .iter_cloned()
        .filter(|(height, _)| height.0 < SHADOW_ACTIVATION_HEIGHT.0)
        .collect();
    let split_hash = SHADOW_SPLIT_HASH
        .parse()
        .expect("the H_S checkpoint hash parses");
    if let Some(existing) = items
        .iter_mut()
        .find(|(height, _)| height.0 == SHADOW_SPLIT_HEIGHT)
    {
        existing.1 = split_hash;
    } else {
        items.push((Height(SHADOW_SPLIT_HEIGHT), split_hash));
    }
    items.sort_by_key(|(height, _)| height.0);
    items
}

/// kogany's default file-system names (the identity table: `parameters/ycash/identity_tests.rs`).
///
/// A `ycash` build never uses Zakura's: a kogany node and a Zcash `zakurad` on one host would
/// otherwise share the state database, the peer cache (`network/mainnet.peers`, which would mix
/// Zcash and Ycash peers), the RPC cookie and the config file. ycashd itself uses `~/.ycash`
/// (`Ycash` on macOS and Windows) and `ycash.conf` (`ycash6 src/util/system.cpp:83,234-257`);
/// kogany's state is a different database, so it takes names of its own rather than ycashd's.
pub mod dirs {
    /// The node's directory in the platform cache directory (`~/.cache/kogany` on Linux,
    /// `~/Library/Caches/kogany` on macOS): state, peer cache and RPC cookie.
    pub const CACHE_DIR_NAME: &str = "kogany";
    /// The config file in the platform preference directory (`~/.config/kogany.toml` on Linux,
    /// `~/Library/Preferences/kogany.toml` on macOS).
    pub const CONFIG_FILE: &str = "kogany.toml";
    /// The directory, relative to the home directory, of the long-term network identity secrets
    /// (the Zakura P2P v2 key; v2 is off on Ycash, decision K-11, but the path stays separate).
    pub const NETWORK_IDENTITY_DIR: &str = ".kogany";
}

/// The default P2P port of a Ycash testnet or regtest network: Regtest's, then the `slow`
/// profile's for its magic, and the `fast` profile's otherwise (configured testnets included).
pub(super) fn testnet_default_port(params: &super::testnet::Parameters) -> u16 {
    if params.is_regtest() {
        ports::REGTEST
    } else if params.network_magic() == magics::TESTNET_SLOW {
        ports::TESTNET_SLOW
    } else if params.network_magic() == magics::TESTNET_LEGACY {
        ports::TESTNET_LEGACY
    } else {
        ports::TESTNET_FAST
    }
}

impl super::Network {
    /// testnet-yb-slow: mainnet through H_S, then `UPGRADE_SHADOW` under `0x57a24d5d`.
    /// Vault has no height until slow's rc (`CTestNetSlowParams`).
    pub fn new_ycash_testnet_slow() -> Self {
        Self::new_ycash_shadow(names::TESTNET_SLOW, magics::TESTNET_SLOW)
    }

    /// testnet-legacy: the same shadow fork under `0x35706728`, Vault never scheduled
    /// (`CTestNetLegacyParams`).
    pub fn new_ycash_testnet_legacy() -> Self {
        Self::new_ycash_shadow(names::TESTNET_LEGACY, magics::TESTNET_LEGACY)
    }

    fn new_ycash_shadow(name: &str, magic: super::network::magic::Magic) -> Self {
        use super::testnet::ConfiguredCheckpoints;
        use super::NetworkUpgrade::*;
        use crate::work::difficulty::ParameterDifficulty as _;
        let mut heights: std::collections::BTreeMap<_, _> =
            MAINNET_ACTIVATION_HEIGHTS.iter().copied().collect();
        heights.insert(SHADOW_ACTIVATION_HEIGHT, Shadow);
        let configured = super::testnet::ConfiguredActivationHeights::from(heights);
        let limit = Self::Mainnet.target_difficulty_limit();
        super::testnet::Parameters::build()
            .with_network_name(name)
            .and_then(|builder| builder.with_network_magic(magic))
            .and_then(|builder| builder.with_genesis_hash(MAINNET_GENESIS_HASH))
            .and_then(|builder| builder.with_activation_heights(configured))
            .and_then(|builder| builder.with_target_difficulty_limit(limit))
            .and_then(|builder| Ok(builder.with_max_block_time_start_height(Height(2))))
            .and_then(|builder| {
                builder.with_checkpoints(ConfiguredCheckpoints::HeightsAndHashes(
                    shadow_checkpoint_pairs(),
                ))
            })
            .and_then(|builder| builder.to_network())
            .expect("the hard-coded shadow testnet profile is a valid configured testnet")
    }
}

pub mod ydf;

#[cfg(test)]
mod identity_tests;
#[cfg(test)]
mod tests;
