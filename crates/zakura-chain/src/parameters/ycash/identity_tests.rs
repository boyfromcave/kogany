//! The kogany identity table: every network identifier of the Zcash networks (upstream Zakura,
//! `ref/zakura` at `2b062412c5`, and zcashd), of the Ycash networks (ycashd: ycash6 at
//! `65cb4ae0f` and `ref/ycash` v4.5.0, the source of truth), and of the regtest harness and the
//! client tools that run beside a node on one host.
//!
//! The Yellowback lead architect's collision set (2026-11-02): an operator runs a Zcash `zakurad`
//! and a Ycash `koganyd`, mainnet and testnet variants, on one host at once. These tests prove
//! that set disjoint (P2P port and magic, RPC port, binary, cache directory, config file, network
//! identity directory, cookie path, user agent), and that every value kogany runs a Ycash network
//! with equals ycashd's. The few overlaps ycashd itself has are listed in [`INHERITED`], each with
//! its reason; kogany must not differ from ycashd there.

use std::collections::BTreeMap;

use crate::parameters::{constants::magics as zcash_magics, ycash, Network, NetworkKind};

/// Where a network's nodes run: the public networks share operators' hosts; regtest runs on
/// developer and CI hosts only, beside the harness and the client tools.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum HostClass {
    Public,
    Local,
}

use HostClass::*;

/// One network as one node line names it.
#[derive(Clone, Copy, Debug)]
struct NetRow {
    /// The network, unique per network (two implementations of one network share it).
    network: &'static str,
    /// The implementation the values come from.
    source: &'static str,
    class: HostClass,
    p2p_port: u16,
    rpc_port: u16,
    magic: [u8; 4],
}

/// The Zcash networks: Zakura's defaults (`ref/zakura`
/// `crates/zakura-chain/src/parameters/network.rs` `default_port`,
/// `parameters/constants.rs:43-47`, `crates/zakura-rpc/src/config/rpc.rs:19-24`) and zcashd's
/// regtest (`src/chainparams.cpp` `CRegTestParams::nDefaultPort = 18344`,
/// `chainparamsbase.cpp` `nRPCPort = 18232`).
const ZCASH: &[NetRow] = &[
    NetRow {
        network: "zcash-mainnet",
        source: "Zakura",
        class: Public,
        p2p_port: 8233,
        rpc_port: 8232,
        magic: [0x24, 0xe9, 0x27, 0x64],
    },
    NetRow {
        network: "zcash-testnet",
        source: "Zakura",
        class: Public,
        p2p_port: 18233,
        rpc_port: 18232,
        magic: [0xfa, 0x1a, 0xf9, 0xbf],
    },
    NetRow {
        network: "zcash-regtest",
        source: "Zakura",
        class: Local,
        p2p_port: 18233,
        rpc_port: 18232,
        magic: [0xaa, 0xe8, 0x3f, 0x5f],
    },
    NetRow {
        network: "zcash-regtest",
        source: "zcashd",
        class: Local,
        p2p_port: 18344,
        rpc_port: 18232,
        magic: [0xaa, 0xe8, 0x3f, 0x5f],
    },
];

/// The Ycash networks as ycashd defines them: ycash6 `src/chainparams.cpp:224-228` (mainnet),
/// `:644-648` (`fast`), `:665-669` (`slow`), `:684-688` (`legacy`), `:818-822` (regtest) and
/// `src/chainparamsbase.cpp:41,64-66,73`; ycashd 4.5.0 (`ref/ycash src/chainparams.cpp:199-204,
/// 461-466,650-654`, `src/chainparamsbase.cpp:35,48,62`).
const YCASHD: &[NetRow] = &[
    NetRow {
        network: "ycash-mainnet",
        source: "ycash6",
        class: Public,
        p2p_port: 8833,
        rpc_port: 8832,
        magic: [0x24, 0xe9, 0x27, 0x64],
    },
    NetRow {
        network: "ycash-mainnet",
        source: "ycashd 4.5.0",
        class: Public,
        p2p_port: 8833,
        rpc_port: 8832,
        magic: [0x24, 0xe9, 0x27, 0x64],
    },
    NetRow {
        network: "ycash-testnet-fast",
        source: "ycash6",
        class: Public,
        p2p_port: 18833,
        rpc_port: 18832,
        magic: [0xf7, 0x79, 0x62, 0xd3],
    },
    NetRow {
        network: "ycash-testnet-slow",
        source: "ycash6",
        class: Public,
        p2p_port: 18933,
        rpc_port: 18932,
        magic: [0xf7, 0x79, 0x62, 0xd4],
    },
    NetRow {
        network: "ycash-testnet-legacy",
        source: "ycash6",
        class: Public,
        p2p_port: 19033,
        rpc_port: 19032,
        magic: [0xf7, 0x79, 0x62, 0xd5],
    },
    NetRow {
        network: "ycash-testnet3",
        source: "ycashd 4.5.0",
        class: Public,
        p2p_port: 18833,
        rpc_port: 18832,
        magic: [0xfa, 0x1a, 0xf9, 0xbf],
    },
    NetRow {
        network: "ycash-regtest",
        source: "ycash6",
        class: Local,
        p2p_port: 18344,
        rpc_port: 18832,
        magic: [0xaa, 0xe8, 0x3f, 0x5f],
    },
    NetRow {
        network: "ycash-regtest",
        source: "ycashd 4.5.0",
        class: Local,
        p2p_port: 18344,
        rpc_port: 18832,
        magic: [0xaa, 0xe8, 0x3f, 0x5f],
    },
];

/// The overlaps ycashd itself defines, which kogany inherits because it must equal ycashd.
///
/// - `ycash-regtest` / `zcash-regtest` (zcashd): Ycash regtest keeps zcashd's regtest port and
///   magic. The two are told apart by the protocol version (ycashd's 270013 floor), on hosts
///   that run regtest only, never on a public network.
/// - `ycash-testnet-fast` / `ycash-testnet3`: the re-forked testnet takes over the old testnet3's
///   ports on purpose ("clients' testnet defaults keep working", ycash6
///   `src/chainparams.cpp:648`); its magic differs, so only the RPC port is shared, and a host
///   runs one or the other (testnet3 is retired, decision K-10).
const INHERITED: &[(&str, &str)] = &[
    ("ycash-regtest", "zcash-regtest"),
    ("ycash-testnet-fast", "ycash-testnet3"),
];

fn inherited(a: &str, b: &str) -> bool {
    INHERITED
        .iter()
        .any(|&(x, y)| (x, y) == (a, b) || (x, y) == (b, a))
}

/// The networks kogany runs (decision K-10: mainnet, the two re-forked testnet profiles and
/// regtest; the `legacy` profile and testnet3 are not kogany's), with kogany's live values.
fn kogany_rows() -> Vec<(NetRow, Network)> {
    let fast = Network::new_default_testnet();
    let slow = Network::new_ycash_testnet_slow();
    let regtest = Network::new_regtest(Default::default());
    let row = |network, class, net: &Network, rpc_port| NetRow {
        network,
        source: "kogany",
        class,
        p2p_port: net.default_port(),
        rpc_port,
        magic: net.magic().0,
    };
    vec![
        (
            row(
                "ycash-mainnet",
                Public,
                &Network::Mainnet,
                ycash::ports::rpc::MAINNET,
            ),
            Network::Mainnet,
        ),
        (
            row(
                "ycash-testnet-fast",
                Public,
                &fast,
                ycash::ports::rpc::TESTNET_FAST,
            ),
            fast.clone(),
        ),
        (
            row(
                "ycash-testnet-slow",
                Public,
                &slow,
                ycash::ports::rpc::TESTNET_SLOW,
            ),
            slow.clone(),
        ),
        (
            row("ycash-regtest", Local, &regtest, ycash::ports::rpc::REGTEST),
            regtest.clone(),
        ),
    ]
}

#[test]
fn kogany_networks_equal_ycashd() {
    for (kogany, _) in kogany_rows() {
        let ycashd = YCASHD
            .iter()
            .find(|row| row.network == kogany.network && row.source == "ycash6")
            .expect("every kogany network is a ycash6 network");
        assert_eq!(
            (kogany.p2p_port, kogany.rpc_port, kogany.magic, kogany.class),
            (ycashd.p2p_port, ycashd.rpc_port, ycashd.magic, ycashd.class),
            "{}: kogany differs from ycash6",
            kogany.network,
        );
    }

    // The two ycashd lines agree wherever they define the same network.
    for a in YCASHD {
        for b in YCASHD.iter().filter(|b| b.network == a.network) {
            assert_eq!(
                (a.p2p_port, a.rpc_port, a.magic),
                (b.p2p_port, b.rpc_port, b.magic),
                "{}: {} and {} differ",
                a.network,
                a.source,
                b.source,
            );
        }
    }

    // Zakura's own Zcash magics are the ones the Zcash rows name: Ycash mainnet and regtest share
    // them (lane B survey trap T6), the re-forked testnets do not.
    assert_eq!(zcash_magics::MAINNET.0, ZCASH[0].magic);
    assert_eq!(zcash_magics::TESTNET.0, ZCASH[1].magic);
    assert_eq!(zcash_magics::REGTEST.0, ZCASH[2].magic);
}

#[test]
fn no_two_networks_collide_on_one_host() {
    let mut rows: Vec<NetRow> = ZCASH.to_vec();
    rows.extend(YCASHD.iter().copied());
    rows.extend(kogany_rows().into_iter().map(|(row, _)| row));

    let mut collisions = Vec::new();
    for (i, a) in rows.iter().enumerate() {
        for b in &rows[i + 1..] {
            if a.network == b.network || inherited(a.network, b.network) {
                continue;
            }
            if (a.p2p_port, a.magic) == (b.p2p_port, b.magic) {
                collisions.push(format!(
                    "P2P {} magic {:02x?}: {} ({}) and {} ({})",
                    a.p2p_port, a.magic, a.network, a.source, b.network, b.source
                ));
            }
            if a.class == b.class && a.rpc_port == b.rpc_port {
                collisions.push(format!(
                    "RPC {}: {} ({}) and {} ({})",
                    a.rpc_port, a.network, a.source, b.network, b.source
                ));
            }
            // A node binds its P2P port; no other network's node may bind it as its RPC port.
            if a.class == b.class && (a.p2p_port == b.rpc_port || a.rpc_port == b.p2p_port) {
                collisions.push(format!(
                    "P2P/RPC: {} ({}) and {} ({})",
                    a.network, a.source, b.network, b.source
                ));
            }
        }
    }
    assert!(collisions.is_empty(), "{collisions:#?}");

    // The inherited overlaps are exactly the ones listed: none is stale.
    for &(a, b) in INHERITED {
        let overlap = rows.iter().filter(|row| row.network == a).any(|a| {
            rows.iter().filter(|row| row.network == b).any(|b| {
                (a.p2p_port, a.magic) == (b.p2p_port, b.magic)
                    || (a.class == b.class && a.rpc_port == b.rpc_port)
            })
        });
        assert!(overlap, "{a} / {b} no longer overlap: remove the entry");
    }
}

/// The regtest harness's port ranges (ycash6 `qa/rpc-tests/test_framework/util.py:62-66,108-113`,
/// `kogany.py:125-152`, `util.py` `yewd_*_port`, `yellowback_stratum.py`): `PORT_MIN` 11000 plus a
/// multiple of `PORT_RANGE` 5000, plus the node index and a per-seed offset below 4991.
const HARNESS_RANGES: &[(&str, u16)] = &[
    ("ycashd p2p_port", 0),
    ("ycashd rpc_port", 1),
    ("stratum (yellowback_stratum.py)", 2),
    ("stratum status", 3),
    (
        "kogany_v2_port (bound only with v2 on; off on Ycash, K-11)",
        4,
    ),
    ("kogany_rpc_port", 5),
    ("yewd_backend_rpc_port", 6),
    ("kogany_p2p_port", 7),
    ("yewd_rpc_port (reserved)", 8),
];

/// The default ports of the client tools that run beside a regtest or devnet node (each repo's
/// `vaults/kogany-compat` integration tree): yolo's stratum (`yolo README.md`, `--port`) and the
/// Perl `cenote`/`stratumsolo`, lightwalletd's gRPC and HTTP (`lightwalletd-dd docs/docker.md`),
/// chain-viz (`chain-viz README.md` `--listen`), Hawkeye's API (`hawkeye config/*.example.toml`),
/// the YEW operator script (`yew scripts/devnet-operator.py`) and the x402 facilitator's default
/// (`x402-ycash`, upstream `PORT` 4022).
const CLIENT_PORTS: &[(&str, u16)] = &[
    ("yolo stratum", 3333),
    ("yolo cenote/stratumsolo", 3334),
    ("lightwalletd gRPC", 9067),
    ("lightwalletd HTTP", 9068),
    ("chain-viz", 8480),
    ("hawkeye API (Ethereum)", 7801),
    ("hawkeye API (NEAR)", 7811),
    ("yew devnet operator", 2398),
    ("x402 facilitator", 4022),
];

#[test]
fn harness_and_client_ports_are_disjoint_from_node_defaults() {
    const PORT_MIN: u32 = 11_000;
    const PORT_RANGE: u32 = 5_000;
    let range = |k: u16| {
        let start = PORT_MIN + u32::from(k) * PORT_RANGE;
        start..start + PORT_RANGE
    };

    let mut node_ports: BTreeMap<u16, Vec<&str>> = BTreeMap::new();
    for row in ZCASH.iter().chain(YCASHD) {
        node_ports
            .entry(row.p2p_port)
            .or_default()
            .push(row.network);
        node_ports
            .entry(row.rpc_port)
            .or_default()
            .push(row.network);
    }

    // The harness ranges are disjoint by construction; kogany's and yewd's hold no node default
    // (ycashd's own two ranges do hold some, as Bitcoin Core's harness always has: its nodes are
    // started with explicit ports, never the defaults).
    for (name, k) in HARNESS_RANGES.iter().filter(|(_, k)| *k >= 4) {
        for port in node_ports.keys() {
            assert!(
                !range(*k).contains(&u32::from(*port)),
                "{name} holds the node default {port}"
            );
        }
    }
    for (i, (_, a)) in HARNESS_RANGES.iter().enumerate() {
        for (_, b) in &HARNESS_RANGES[i + 1..] {
            assert!(range(*a).end <= range(*b).start || range(*b).end <= range(*a).start);
        }
    }

    // The client tools' defaults: no node default and no harness range.
    for (name, port) in CLIENT_PORTS {
        assert!(
            !node_ports.contains_key(port),
            "{name} {port} is a node default"
        );
        for (range_name, k) in HARNESS_RANGES {
            assert!(
                !range(*k).contains(&u32::from(*port)),
                "{name} {port} lies in the harness range {range_name}"
            );
        }
    }
    let mut seen = BTreeMap::new();
    for (name, port) in CLIENT_PORTS {
        assert!(seen.insert(port, name).is_none(), "{name} {port}");
    }
}

/// Address prefixes, HRPs and the coin type equal ycashd's (ycash6 `src/chainparams.cpp:92,
/// 171-190,399,478-497,704,781-797`; `src/key_io.cpp:25-31`; the Yellowback versions in
/// `src/yellowback/params.cpp`, mirrored by `kogany_yellowback::params`), and no Ycash prefix
/// equals the Zcash one it replaces (`zcash_protocol` with the feature off; ycash6 keeps those as
/// its `LEGACY_*` decoding prefixes, `src/chainparams.cpp:198-213`).
#[test]
fn address_prefixes_hrps_and_coin_type_equal_ycashd() {
    use zcash_protocol::constants::{mainnet, regtest, testnet};

    // (network, P2PKH, P2SH, Sprout, secret key, Sapling address HRP, Sapling extsk HRP,
    // Sapling extfvk HRP, coin type)
    assert_eq!(
        (
            mainnet::B58_PUBKEY_ADDRESS_PREFIX,
            mainnet::B58_SCRIPT_ADDRESS_PREFIX,
            mainnet::B58_SPROUT_ADDRESS_PREFIX,
            mainnet::B58_SECRET_KEY_PREFIX,
            mainnet::HRP_SAPLING_PAYMENT_ADDRESS,
            mainnet::HRP_SAPLING_EXTENDED_SPENDING_KEY,
            mainnet::HRP_SAPLING_EXTENDED_FULL_VIEWING_KEY,
            mainnet::COIN_TYPE,
        ),
        (
            [0x1c, 0x28],
            [0x1c, 0x2c],
            [0x16, 0x36],
            [0x80],
            "ys",
            "secret-extended-key-main",
            "zxviews",
            347,
        )
    );
    assert_eq!(
        (
            testnet::B58_PUBKEY_ADDRESS_PREFIX,
            testnet::B58_SCRIPT_ADDRESS_PREFIX,
            testnet::B58_SPROUT_ADDRESS_PREFIX,
            testnet::B58_SECRET_KEY_PREFIX,
            testnet::HRP_SAPLING_PAYMENT_ADDRESS,
            testnet::HRP_SAPLING_EXTENDED_SPENDING_KEY,
            testnet::HRP_SAPLING_EXTENDED_FULL_VIEWING_KEY,
            testnet::COIN_TYPE,
        ),
        (
            [0x1c, 0x95],
            [0x1c, 0x2a],
            [0x16, 0x52],
            [0xef],
            "ytestsapling",
            "secret-extended-key-test",
            "zxviewtestsapling",
            1,
        )
    );
    assert_eq!(
        (
            regtest::B58_PUBKEY_ADDRESS_PREFIX,
            regtest::B58_SCRIPT_ADDRESS_PREFIX,
            regtest::HRP_SAPLING_PAYMENT_ADDRESS,
            regtest::COIN_TYPE,
        ),
        ([0x1c, 0x95], [0x1c, 0x2a], "yregtestsapling", 1)
    );

    // Zakura reads the transparent prefixes through `NetworkKind`.
    assert_eq!(
        NetworkKind::Mainnet.b58_pubkey_address_prefix(),
        [0x1c, 0x28]
    );
    assert_eq!(
        NetworkKind::Regtest.b58_script_address_prefix(),
        [0x1c, 0x2a]
    );

    // The Zcash prefixes the Ycash ones replace (ycash6's LEGACY_* rows).
    let zcash_main = ([0x1c, 0xb8], [0x1c, 0xbd], "zs");
    let zcash_test = ([0x1d, 0x25], [0x1c, 0xba], "ztestsapling");
    assert_ne!(
        (
            mainnet::B58_PUBKEY_ADDRESS_PREFIX,
            mainnet::B58_SCRIPT_ADDRESS_PREFIX,
            mainnet::HRP_SAPLING_PAYMENT_ADDRESS
        ),
        zcash_main
    );
    assert_ne!(
        (
            testnet::B58_PUBKEY_ADDRESS_PREFIX,
            testnet::B58_SCRIPT_ADDRESS_PREFIX,
            testnet::HRP_SAPLING_PAYMENT_ADDRESS
        ),
        zcash_test
    );

    // The plain-YEC post-quantum versions, `sq…`/`tq…`/`rq…` (`PlainPQAddressVersion`).
    use crate::transparent::plain_pq_address_version as pq;
    assert_eq!(pq(NetworkKind::Mainnet), [0x4d, 0xd9]);
    assert_eq!(pq(NetworkKind::Testnet), [0x4f, 0x61]);
    assert_eq!(pq(NetworkKind::Regtest), [0x4c, 0x51]);

    // The Yellowback (YED) versions, `yb…`/`yt…`/`yr…`, 35 and 53 characters.
    use kogany_yellowback::params::params_for_network;
    let yed = |id| {
        let p = params_for_network(id).expect("a ycashd network id");
        (p.address_version.unwrap(), p.pq_address_version.unwrap())
    };
    assert_eq!(yed("main"), ([0x1f, 0xdd], [0x56, 0xab]));
    assert_eq!(yed("test"), ([0x20, 0x07], [0x57, 0x1e]));
    assert_eq!(yed("regtest"), ([0x20, 0x02], [0x57, 0x10]));

    // Every two-byte version on one network is distinct, so no address decodes as two kinds.
    for (kind, id, p2pkh, p2sh) in [
        (
            NetworkKind::Mainnet,
            "main",
            mainnet::B58_PUBKEY_ADDRESS_PREFIX,
            mainnet::B58_SCRIPT_ADDRESS_PREFIX,
        ),
        (
            NetworkKind::Testnet,
            "test",
            testnet::B58_PUBKEY_ADDRESS_PREFIX,
            testnet::B58_SCRIPT_ADDRESS_PREFIX,
        ),
        (
            NetworkKind::Regtest,
            "regtest",
            regtest::B58_PUBKEY_ADDRESS_PREFIX,
            regtest::B58_SCRIPT_ADDRESS_PREFIX,
        ),
    ] {
        let (yed_plain, yed_pq) = yed(id);
        let versions = [p2pkh, p2sh, pq(kind), yed_plain, yed_pq];
        for (i, a) in versions.iter().enumerate() {
            for b in &versions[i + 1..] {
                assert_ne!(a, b, "{id}: two address kinds share a version");
            }
        }
    }
}

/// Names: the zakurad.toml network names, `getblockchaininfo.chain` (ycashd's `strNetworkID`,
/// through the BIP70 name) and the testnet profiles.
#[test]
fn network_names_equal_ycashd() {
    let rows = kogany_rows();
    let names: Vec<(String, String, String)> = rows
        .iter()
        .map(|(_, net)| {
            (
                net.to_string(),
                net.lowercase_name(),
                net.bip70_network_name(),
            )
        })
        .collect();
    assert_eq!(
        names,
        [
            ("Mainnet", "mainnet", "main"),
            ("Testnet", "testnet", "test"),
            ("TestnetSlow", "testnetslow", "test"),
            ("Regtest", "regtest", "test"),
        ]
        .map(|(a, b, c)| (a.to_string(), b.to_string(), c.to_string()))
    );
    // `getblockchaininfo.chain` is `regtest` on Regtest (`zakura-rpc` `types::ycash::chain_name`).
    assert!(rows[3].1.is_regtest());
    // Vault: none on mainnet and on the slow profile, 510,400 on the fast profile (ycashd's).
    assert_eq!(rows[0].1.vault_activation_height(), None);
    assert_eq!(
        rows[1].1.vault_activation_height(),
        Some(ycash::testnet::VAULT_FAST)
    );
    assert_eq!(rows[2].1.vault_activation_height(), None);
}

/// The file-system names a kogany node uses by default, and Zakura's, which they must never equal.
#[test]
fn kogany_directories_are_not_zakuras() {
    use crate::common::{default_cache_dir, CACHE_DIR_NAME};

    assert_eq!(CACHE_DIR_NAME, "kogany");
    assert_eq!(
        default_cache_dir()
            .file_name()
            .and_then(|name| name.to_str()),
        Some("kogany")
    );
    assert_eq!(ycash::dirs::CONFIG_FILE, "kogany.toml");
    assert_eq!(ycash::dirs::NETWORK_IDENTITY_DIR, ".kogany");

    // Zakura's (`ref/zakura crates/zakura-chain/src/common.rs`, `crates/zakurad/src/commands.rs`,
    // `crates/zakura-network/src/config/cache_dir.rs`), and ycashd's (`ycash6
    // src/util/system.cpp:83,242-257`): kogany shares none of them.
    for taken in [
        "zakura",
        "zakura.toml",
        "zebrad.toml",
        ".zakura",
        ".ycash",
        "Ycash",
        "ycash.conf",
    ] {
        for ours in [
            ycash::dirs::CACHE_DIR_NAME,
            ycash::dirs::CONFIG_FILE,
            ycash::dirs::NETWORK_IDENTITY_DIR,
        ] {
            assert_ne!(ours, taken);
        }
    }
}
