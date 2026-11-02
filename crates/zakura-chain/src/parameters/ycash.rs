//! The Ycash network profile (kogany), compiled under the `ycash` cargo feature.
//!
//! In a `ycash` build every network is a Ycash network: [`Network::Mainnet`] is Ycash mainnet,
//! the default [`Network::Testnet`] is the re-forked Ycash testnet's `fast` profile, and Regtest is
//! Ycash regtest. The values here replace Zakura's Zcash tables in place, the way ycashd rewrites
//! zcashd's `CMainParams` (kogany plan §2.3, decision K-5). Every value cites the C++ line it
//! mirrors: `ycash6` at `65cb4ae0f` (`vaults/kogany-compat` = `upgrade/vault`).
//!
//! The Vault upgrade is not part of this module: it is runtime-gated by its height (W2-b).
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

/// Network upgrade activation heights on the re-forked Ycash testnet, shared by its `fast` and
/// `slow` profiles (decision K-10; the legacy testnet3 profile is dropped).
///
/// `ycash6 src/chainparams.cpp:429-459` (`CTestNetParams`): Zcash testnet history through
/// 510,247, the new fork block at 510,248, then Blossom, Heartwood and Canopy two blocks apart.
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

/// Ycash testnet activation list, in height order (both profiles).
pub(super) const TESTNET_ACTIVATION_HEIGHTS: &[(Height, NetworkUpgrade)] = &[
    (Height(0), Genesis),
    (testnet::BEFORE_OVERWINTER, BeforeOverwinter),
    (testnet::OVERWINTER, Overwinter),
    (testnet::SAPLING, Sapling),
    (testnet::YCASH, Ycash),
    (testnet::BLOSSOM, Blossom),
    (testnet::HEARTWOOD, Heartwood),
    (testnet::CANOPY, Canopy),
];

/// Ycash network magics. Mainnet and Regtest share Zcash's (`ycash6 src/chainparams.cpp:224-227,
/// 820-823`), so Zakura's [`magics::MAINNET`](super::constants::magics::MAINNET) and
/// [`magics::REGTEST`](super::constants::magics::REGTEST) are used unchanged. The re-forked
/// testnet profiles have their own (`ycash6 src/chainparams.cpp:644-647,665-668`).
pub mod magics {
    use super::Magic;

    /// The re-forked Ycash testnet, `fast` profile (`testnet-yb-fast`).
    pub const TESTNET_FAST: Magic = Magic([0xf7, 0x79, 0x62, 0xd3]);
    /// The re-forked Ycash testnet, `slow` profile (`testnet-yb-slow`).
    pub const TESTNET_SLOW: Magic = Magic([0xf7, 0x79, 0x62, 0xd4]);
}

/// Default P2P ports (`nDefaultPort`, `ycash6 src/chainparams.cpp:228,648,669,824`).
pub mod ports {
    /// Ycash mainnet.
    pub const MAINNET: u16 = 8833;
    /// Ycash testnet, `fast` profile.
    pub const TESTNET_FAST: u16 = 18833;
    /// Ycash testnet, `slow` profile.
    pub const TESTNET_SLOW: u16 = 18933;
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
        /// Ycash regtest.
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
}

/// The default P2P port of a Ycash testnet or regtest network: Regtest's, then the `slow`
/// profile's for its magic, and the `fast` profile's otherwise (configured testnets included).
pub(super) fn testnet_default_port(params: &super::testnet::Parameters) -> u16 {
    if params.is_regtest() {
        ports::REGTEST
    } else if params.network_magic() == magics::TESTNET_SLOW {
        ports::TESTNET_SLOW
    } else {
        ports::TESTNET_FAST
    }
}

impl super::Network {
    /// Creates the re-forked Ycash testnet's `slow` profile: the `fast` profile's consensus
    /// values with the `slow` profile's magic and name (`CTestNetSlowParams`,
    /// `ycash6 src/chainparams.cpp:658-672`). The two profiles differ only in Vault parameters,
    /// which W2-b adds.
    pub fn new_ycash_testnet_slow() -> Self {
        super::testnet::Parameters::build()
            .with_network_name(names::TESTNET_SLOW)
            .and_then(|builder| builder.with_network_magic(magics::TESTNET_SLOW))
            .and_then(|builder| builder.to_network())
            .expect("the hard-coded slow testnet profile is a valid configured testnet")
    }
}

#[cfg(test)]
mod tests;
