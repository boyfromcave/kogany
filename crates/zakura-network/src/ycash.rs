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
//! - the user agent, `/koganyd:<version>/`, where a release build cut at a
//!   `v<X.Y.Z>-ycash.<beta|rc><n>` tag advertises the tag without its `v` (`/koganyd:1.8.0-ycash.beta1/`);
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

/// Returns the release name of a kogany release tag, `v<X.Y.Z>-ycash.<beta|rc><n>` without its
/// leading `v`, or `None` if `tag` is not of that shape.
///
/// The name holds only `[0-9a-z.-]`, all of them in ycashd's `SAFE_CHARS_SUBVERSION`
/// (`ycash6 src/util/strencodings.cpp:25`), so a ycashd peer shows it unchanged.
pub fn release_name(tag: &str) -> Option<&str> {
    let name = tag.strip_prefix('v')?;
    let (version, stage) = name.split_once("-ycash.")?;
    let numbers: Vec<&str> = version.split('.').collect();
    let digits = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
    if numbers.len() != 3 || !numbers.iter().all(|n| digits(n)) {
        return None;
    }
    let n = stage
        .strip_prefix("beta")
        .or_else(|| stage.strip_prefix("rc"))?;
    digits(n).then_some(name)
}

/// Returns kogany's BIP 14 user agent: `/koganyd:<release name>/` if `release_tag` is a kogany
/// release tag ([`release_name`]), otherwise `/koganyd:<crate_version>/` ([`user_agent`]).
pub fn user_agent_for_release(
    release_tag: Option<&str>,
    crate_version: impl std::fmt::Display,
) -> String {
    match release_tag.and_then(release_name) {
        Some(name) => user_agent(name),
        None => user_agent(crate_version),
    }
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
    // Shadow forks inherit mainnet's per-upgrade versions (`CTestNetShadowParams : CMainParams`).
    let version_network = if profile::is_shadow_network(network) {
        &Mainnet
    } else {
        network
    };

    Version(match (version_network, network_upgrade) {
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
        // `UPGRADE_SHADOW.nProtocolVersion` (`ycash6 src/chainparams.cpp`, CTestNetShadowParams).
        (_, Shadow) => 270_013,
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

/// The default P2P ports of the Ycash networks kogany runs: mainnet, the `fast`, `slow` and
/// `legacy` testnet profiles and regtest (`nDefaultPort`, `ycash6 src/chainparams.cpp`). A peer
/// on one of them is preferred, as Zakura prefers Zcash's ports; one on another Ycash network's
/// port is refused, as Zakura refuses the other Zcash network's.
pub const P2P_PORTS: [u16; 5] = [
    profile::ports::MAINNET,
    profile::ports::TESTNET_FAST,
    profile::ports::TESTNET_SLOW,
    profile::ports::TESTNET_LEGACY,
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

/// ycashd's `CNetAddr::IsLocal` (`ycash6 src/netbase.cpp:798-810`): IPv4 `127.0.0.0/8` and `0.0.0.0/8`, and
/// IPv6 `::1`. A misbehaving local peer is never banned (`src/main.cpp:9508`).
pub fn is_local(ip: std::net::IpAddr) -> bool {
    use std::net::IpAddr;

    match ip.to_canonical() {
        IpAddr::V4(ip) => matches!(ip.octets()[0], 0 | 127),
        IpAddr::V6(ip) => ip.is_loopback(),
    }
}

/// Returns `true` if `ip` is routable in ycashd's sense (`CNetAddr::IsRoutable`,
/// `ycash6 src/netbase.cpp:798-810,854-857`): valid, and none of the loopback and `0/8` hosts,
/// the RFC 1918, 2544, 3927, 4862, 6598, 5737, 4193 and 4843 ranges, or the RFC 3849 IPv6
/// documentation range (`IsValid`).
///
/// ycashd's address manager keeps only routable addresses (`CAddrMan::Add_`,
/// `ycash6 src/addrman.cpp:244-247`), so a gossiped loopback or private address is never dialled:
/// on a regtest network, where every node listens on `127.0.0.1`, a node connects only to the
/// nodes `addnode` names. kogany drops such a gossiped address the same way (finding F-S5-6: the
/// harness's split halves met again through gossiped addresses). An operator's address
/// (`addnode`, the initial peers, the disk cache) is kept whatever its range.
pub fn is_routable(ip: std::net::IpAddr) -> bool {
    use std::net::IpAddr;

    match ip.to_canonical() {
        IpAddr::V4(ip) => {
            let [a, b, c, _] = ip.octets();
            !(a == 0
                || a == 127
                || ip.is_broadcast()
                || a == 10
                || (a == 172 && (16..=31).contains(&b))
                || (a == 192 && b == 168)
                || (a == 198 && (b == 18 || b == 19))
                || (a == 169 && b == 254)
                || (a == 100 && (64..=127).contains(&b))
                || (a == 192 && b == 0 && c == 2)
                || (a == 198 && b == 51 && c == 100)
                || (a == 203 && b == 0 && c == 113))
        }
        IpAddr::V6(ip) => {
            let s = ip.segments();
            !(ip.is_unspecified()
                || ip.is_loopback()
                || (s[0] == 0x2001 && s[1] == 0x0db8)
                || (s[0] & 0xfe00) == 0xfc00
                || (s[0] == 0xfe80 && s[1] == 0 && s[2] == 0 && s[3] == 0)
                || (s[0] == 0x2001 && (s[1] & 0xfff0) == 0x0010))
        }
    }
}

/// ycashd's `MAX_REJECT_MESSAGE_LENGTH` (`ycash6 src/main.h:145`): the reason is cut to it.
pub const MAX_REJECT_MESSAGE_LENGTH: usize = 111;

/// ycashd's `REJECT_INTERNAL` (`ycash6 src/consensus/validation.h`): codes from it up are
/// `AcceptToMemoryPool`'s own and never go over P2P.
pub const REJECT_INTERNAL: u16 = 0x100;

/// The `reject` ycashd sends the peer that relayed a transaction `AcceptToMemoryPool` refused
/// (`ycash6 src/main.cpp:8937-8945`): `reject "tx" <code> <reason, cut to 111 bytes> <txid>`.
/// `None` for an internal code (at or above [`REJECT_INTERNAL`]), which ycashd never sends.
pub fn transaction_reject_message(
    code: u16,
    reason: &str,
    txid: [u8; 32],
) -> Option<crate::protocol::external::Message> {
    use crate::protocol::external::RejectReason;
    let ccode = match u8::try_from(code).ok().filter(|_| code < REJECT_INTERNAL)? {
        0x01 => RejectReason::Malformed,
        0x10 => RejectReason::Invalid,
        0x11 => RejectReason::Obsolete,
        0x12 => RejectReason::Duplicate,
        0x40 => RejectReason::Nonstandard,
        0x41 => RejectReason::Dust,
        0x42 => RejectReason::InsufficientFee,
        0x43 => RejectReason::Checkpoint,
        _ => RejectReason::Other,
    };
    let mut end = reason.len().min(MAX_REJECT_MESSAGE_LENGTH);
    while !reason.is_char_boundary(end) {
        end -= 1;
    }
    Some(crate::protocol::external::Message::Reject {
        message: "tx".to_owned(),
        ccode,
        reason: reason[..end].to_owned(),
        data: Some(txid),
    })
}

/// Sends ycashd's transaction `reject` to a legacy peer (kogany S5), through the address book's
/// peer registry. A default handle sends nothing.
#[derive(Clone, Debug, Default)]
pub struct LegacyRejectSender {
    registry: Option<crate::peer_registry::PeerRegistry>,
}

impl LegacyRejectSender {
    pub(crate) fn new(registry: Option<crate::peer_registry::PeerRegistry>) -> Self {
        Self { registry }
    }

    /// Queues [`transaction_reject_message`] on every legacy connection to `peer`; returns the
    /// number of connections it was queued on.
    pub fn reject_transaction(
        &self,
        peer: crate::PeerSocketAddr,
        code: u16,
        reason: &str,
        txid: [u8; 32],
    ) -> usize {
        match (
            &self.registry,
            transaction_reject_message(code, reason, txid),
        ) {
            (Some(registry), Some(message)) => registry.send_legacy(peer, &message),
            _ => 0,
        }
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod user_agent_tests {
    use super::{release_name, user_agent_for_release};

    #[test]
    fn release_tag_names_the_user_agent() {
        assert_eq!(
            user_agent_for_release(Some("v1.8.0-ycash.beta1"), "1.8.0-rc1"),
            "/koganyd:1.8.0-ycash.beta1/"
        );
        assert_eq!(
            user_agent_for_release(Some("v1.8.0-ycash.rc12"), "1.8.0-rc1"),
            "/koganyd:1.8.0-ycash.rc12/"
        );
    }

    #[test]
    fn no_or_foreign_tag_keeps_the_crate_version() {
        assert_eq!(
            user_agent_for_release(None, "1.8.0-rc1"),
            "/koganyd:1.8.0-rc1/"
        );
        for tag in [
            "v1.8.0",
            "v1.8.0-rc1",
            "1.8.0-ycash.beta1",
            "v1.8.0-ycash.1",
            "v1.8-ycash.beta1",
            "v1.8.0-ycash.beta",
            "v1.8.0-ycash.beta1-dirty",
            "kogany-ycash-baseline",
        ] {
            assert_eq!(release_name(tag), None, "{tag}");
            assert_eq!(
                user_agent_for_release(Some(tag), "1.8.0-rc1"),
                "/koganyd:1.8.0-rc1/"
            );
        }
    }
}
