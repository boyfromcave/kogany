//! The Ycash peer-to-peer profile (kogany), compiled under the `ycash` cargo feature.
//!
//! Ycash shares Zcash's genesis block and its mainnet and regtest network magics, so a Ycash node
//! tells the two networks apart at the P2P layer by its port, its seeds and, above all, its
//! protocol version: every live Ycash node (ycashd 4.5.0, ycash6, Yolk) advertises at least
//! 270013, and every Zcash node advertises 170_xxx. This module holds the values that replace
//! Zakura's Zcash ones in a `ycash` build (kogany plan W1-Y5; lane B survey traps T5 and T6):
//!
//! - the protocol version table: ycashd's per-upgrade `nProtocolVersion` values and its
//!   `MIN_PEER_PROTO_VERSION` floor of 270013, so a Zcash peer is refused at the handshake;
//! - the version kogany advertises, ycash6's Vault-era 270200;
//! - the user agent, `/koganyd:<version>/`;
//! - the inventory filter: `MSG_WTX` (ZIP 239) is never sent and is refused on receipt, as
//!   ycash6 pins `CINV_WTX_VERSION` to an unreachable sentinel;
//! - the default seeds and listen port;
//! - the Zakura P2P v2 overlay, which is off (decision K-11).
//!
//! Every value cites the C++ line it mirrors: `ycash6` at `65cb4ae0f`
//! (`vaults/kogany-compat` = `upgrade/vault`).

use zakura_chain::parameters::{
    ycash as profile,
    Network::{self, *},
    NetworkUpgrade::{self, *},
};

use crate::protocol::external::{InventoryHash, Version};

/// The lowest protocol version kogany accepts from a peer, on every Ycash network.
///
/// ycashd's `MIN_PEER_PROTO_VERSION` and `MIN_TESTNET_PEER_PROTO_VERSION`, both 270013
/// (`ycash6 src/version.h:26,55`; `ref/ycash src/version.h` at v4.5.0 has the same floor). It is
/// above every Zcash protocol version, so a Zcash peer with the shared magic is refused.
pub const MIN_PEER_PROTO_VERSION: Version = Version(270_013);

/// The protocol version kogany advertises in its `version` message: ycash6's `PROTOCOL_VERSION`,
/// the Vault-era 270200 (`ycash6 src/version.h:14-22`).
///
/// It must be at least the version of every upgrade kogany schedules
/// ([`min_specified_for_upgrade`]): Zakura refuses to run below its own minimum, and ycashd
/// disconnects a peer below the current epoch's version, so after Vault activates a node that
/// advertised the Canopy-era 270013 (ycashd 4.5.0's) would lose every ycash6 peer. Before Vault
/// activates it gates nobody: peers are held to the [`MIN_PEER_PROTO_VERSION`] floor, as ycash6
/// holds them.
pub const CURRENT_PROTOCOL_VERSION: u32 = 270_200;

/// The version ycashd gives an upgrade it never schedules (`UPGRADE_ZFUTURE.nProtocolVersion`,
/// `ycash6 src/chainparams.cpp:161`): kogany refuses to run past such an upgrade.
const UNREACHABLE_PROTOCOL_VERSION: u32 = 0x7FFF_FFFF;

/// The name kogany advertises in its BIP 14 user agent, `/koganyd:<version>/`.
///
/// ycashd (`/YcashCpp:<version>/`, `ycash6 src/clientversion.cpp:23`) sanitizes a peer's user
/// agent and never filters on it (`ycash6 src/main.cpp:8378-8379`).
pub const USER_AGENT_NAME: &str = "koganyd";

/// Returns kogany's BIP 14 user agent for `release_version`: `/koganyd:<release_version>/`.
pub fn user_agent(release_version: impl std::fmt::Display) -> String {
    format!("/{USER_AGENT_NAME}:{release_version}/")
}

/// Returns ycashd's `nProtocolVersion` for `network_upgrade` on `network`: the minimum version
/// a peer must advertise once that upgrade is the current epoch.
///
/// `ycash6 src/chainparams.cpp:115-161` (mainnet), `:422-468` (testnet, both re-forked profiles),
/// `:727-770` (regtest). ycashd disconnects a peer below the current epoch's version
/// (`ycash6 src/main.cpp:8352-8366,8516-8530`); the [`MIN_PEER_PROTO_VERSION`] floor applies
/// on top of it.
///
/// NU6.3 and NU7 do not exist on ycashd; like `UPGRADE_ZFUTURE` they get an unreachable version,
/// so a build that ever schedules them refuses to run instead of talking to the wrong peers.
pub(crate) fn min_specified_for_upgrade(
    network: &Network,
    network_upgrade: NetworkUpgrade,
) -> Version {
    let is_regtest = matches!(network, Testnet(params) if params.is_regtest());

    Version(match (network, network_upgrade) {
        (_, Genesis) | (_, BeforeOverwinter) => 170_002,
        (Mainnet, Overwinter) => 170_005,
        (Testnet(_), Overwinter) => 170_003,
        (Testnet(_), Sapling) if is_regtest => 170_006,
        (_, Sapling) => 170_007,
        (_, Ycash) => 270_007,
        (Mainnet, Blossom) => 270_009,
        (Testnet(_), Blossom) if is_regtest => 170_008,
        (Testnet(_), Blossom) => 270_008,
        (Mainnet, Heartwood) => 270_011,
        (Testnet(_), Heartwood) if is_regtest => 170_010,
        (Testnet(_), Heartwood) => 270_010,
        (Mainnet, Canopy) => 270_013,
        (Testnet(_), Canopy) if is_regtest => 170_012,
        (Testnet(_), Canopy) => 270_012,
        (Mainnet, Nu5) => 270_015,
        (Testnet(_), Nu5) if is_regtest => 170_050,
        (Testnet(_), Nu5) => 270_014,
        (Mainnet, Nu6) => 270_120,
        (Testnet(_), Nu6) => 270_110,
        (Mainnet, Nu6_1) => 270_140,
        (Testnet(_), Nu6_1) => 270_130,
        (_, Nu6_2) => 270_150,
        // `UPGRADE_VAULT.nProtocolVersion` on every network (`ycash6 src/chainparams.cpp:154,463,
        // 766`), as the W2-b row of the upstream table says.
        (_, Vault) => 270_200,
        (_, Nu6_3) | (_, Nu7) => UNREACHABLE_PROTOCOL_VERSION,

        #[cfg(zcash_unstable = "zfuture")]
        (_, ZFuture) => UNREACHABLE_PROTOCOL_VERSION,
    })
}

/// Returns `true` if `inventory` may cross the wire on Ycash.
///
/// `MSG_WTX` (ZIP 239) carries meaning only for v5 transactions, which need NU5, inactive on
/// Ycash. ycashd 4.5.0 and Yolk do not parse it, and ycash6 pins `CINV_WTX_VERSION` to an
/// unreachable sentinel so it is never sent and a received one is rejected at deserialization
/// (`ycash6 src/version.h:39-51`). kogany does the same.
pub fn is_ycash_inventory(inventory: &InventoryHash) -> bool {
    !matches!(inventory, InventoryHash::Wtx(_))
}

/// Returns `hashes` without the inventory Ycash peers cannot parse ([`is_ycash_inventory`]), for
/// an outbound `inv`, `getdata` or `notfound` message.
pub(crate) fn outbound_inventory(hashes: &[InventoryHash]) -> Vec<InventoryHash> {
    let kept: Vec<InventoryHash> = hashes.iter().copied().filter(is_ycash_inventory).collect();

    if kept.len() != hashes.len() {
        tracing::debug!(
            dropped = hashes.len() - kept.len(),
            "dropped MSG_WTX inventory from an outbound message: Ycash does not use MSG_WTX",
        );
    }

    kept
}

/// The error a received `MSG_WTX` inventory entry is refused with.
pub(crate) const MSG_WTX_REFUSED: &str = "MSG_WTX inventory is not used on Ycash";

/// The default listen address: every interface, on the Ycash mainnet port
/// (`nDefaultPort`, `ycash6 src/chainparams.cpp:228`).
pub(crate) fn default_listen_addr() -> std::net::SocketAddr {
    std::net::SocketAddr::from((std::net::Ipv6Addr::UNSPECIFIED, profile::ports::MAINNET))
}

/// The default P2P ports of the Ycash networks kogany runs: mainnet, the `fast` and `slow` testnet
/// profiles and regtest (`nDefaultPort`, `ycash6 src/chainparams.cpp:228,648,669,822`). A peer
/// on one of them is preferred, as Zakura prefers Zcash's ports; one on another Ycash network's
/// port is refused, as Zakura refuses the other Zcash network's.
pub const P2P_PORTS: [u16; 4] = [
    profile::ports::MAINNET,
    profile::ports::TESTNET_FAST,
    profile::ports::TESTNET_SLOW,
    profile::ports::REGTEST,
];

/// Zcash's default P2P and RPC ports (`zcashd` `src/chainparams.cpp`, `chainparamsbase.cpp`;
/// Zakura's `Network::default_port` and RPC documentation): mainnet 8233/8232, testnet
/// 18233/18232.
pub const ZCASH_PORTS: [u16; 4] = [8233, 8232, 18233, 18232];

/// Returns why a peer on `port` is refused because the port is Zcash's, or `None`.
///
/// Ycash shares Zcash's mainnet and regtest magics, so a Zcash node at a gossiped address
/// completes the version exchange's framing and is refused only by its protocol version
/// ([`MIN_PEER_PROTO_VERSION`]). Zakura refuses ZClassic and Flux by port for the same reason
/// (`peer/priority.rs`); kogany refuses Zcash's ports the same way, so it never spends an
/// outbound slot on one.
pub fn zcash_port_refusal(port: u16) -> Option<&'static str> {
    ZCASH_PORTS
        .contains(&port)
        .then_some("invalid peer port: port is for Zcash, which shares Ycash's network magic")
}

/// The default initial mainnet peers: ycashd's DNS seeders (`vSeeds`,
/// `ycash6 src/chainparams.cpp:241-242`). ycashd's fixed seeds (`pnSeed6_main`) are empty.
///
/// Fixed seed IPs need no Zakura extension: an `IP:port` literal in `initial_mainnet_peers` or
/// `initial_testnet_peers` is dialled as is (decision K-11, the open question it left to W1-Y5).
pub(crate) fn default_initial_mainnet_peers() -> indexmap::IndexSet<String> {
    profile::seeds::MAINNET_DNS
        .iter()
        .map(|&seed| String::from(seed))
        .collect()
}

/// The default initial testnet peers: none. The re-forked Ycash testnet has fixed seeds only,
/// all empty until its rc1 (`ycash6 src/chainparams.cpp:560-562`).
pub(crate) fn default_initial_testnet_peers() -> indexmap::IndexSet<String> {
    profile::seeds::TESTNET_DNS
        .iter()
        .map(|&seed| String::from(seed))
        .collect()
}

/// The error a configuration that asks for the Zakura P2P v2 overlay is refused with.
///
/// The overlay identifies a chain by its genesis hash, which Ycash shares with Zcash
/// (`zakura/handshake.rs`), so a kogany node and a Zakura Zcash node would look like one chain.
/// Decision K-11: legacy TCP only until a Ycash `chain_id` is designed.
pub(crate) const P2P_V2_REFUSED: &str = "the Zakura P2P v2 stack is off on Ycash (kogany plan \
     decision K-11): set network.p2p_stack = \"legacy\" or leave it unset";

#[cfg(test)]
mod tests;
