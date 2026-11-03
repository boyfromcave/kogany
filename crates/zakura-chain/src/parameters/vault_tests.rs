//! The Vault epoch (kogany plan W2-b): the `is_vault_active` predicate, the U-26 schedule
//! refusals, the Canopy behaviour of every exhaustive match, and the grep guard.
//!
//! Runs in both builds. In a Zcash (feature-off) build every network is a Zcash network and Vault
//! is dormant; in a `ycash` build the default Testnet is the `fast` profile with Vault at 510,400.

use std::{fs, path::Path};

use crate::{
    block::{self, Height},
    parameters::{
        testnet::{self, ConfiguredActivationHeights, RegtestParameters},
        ConsensusBranchId, Network, NetworkUpgrade,
        NetworkUpgrade::*,
    },
    serialization::{ZcashDeserializeInto, ZcashSerialize},
    transaction::{LockTime, Transaction},
};

/// ycashd's Vault branch ID, as the vectors and `-nuparams=6d5b7a31:<h>` spell it.
const VAULT_BRANCH_ID: u32 = 0x6d5b_7a31;

/// `ParametersBuilderError::VaultWithoutSapling` (the error type is private to the crate's
/// `network` module, so the tests compare its message).
/// ycashd's `InitError` text (`ycash6 src/init.cpp:1559`), byte for byte.
const WITHOUT_SAPLING: &str = "The Vault upgrade requires Sapling active at or below its height (quantum spec R-A3: the vault opcodes are defined for v4 transactions only)";
/// `ParametersBuilderError::VaultWithNu5OrLater`.
/// ycashd's `InitError` text (`ycash6 src/init.cpp:1563`), byte for byte.
const WITH_NU5_OR_LATER: &str = "NU5..NU6.2 cannot be scheduled together with the Vault upgrade (quantum spec R-A3; this node builds V1 history-tree leaves in the Vault epoch)";
/// `ParametersBuilderError::OutOfOrderUpgrades`.
const OUT_OF_ORDER: &str = "network upgrades must be activated in order specified by the protocol";

/// A regtest network with Vault at `vault` (and the regtest back-fill below it).
fn regtest_with_vault(vault: u32) -> Network {
    Network::new_regtest(RegtestParameters::from(ConfiguredActivationHeights {
        vault: Some(vault),
        ..Default::default()
    }))
}

/// Every height at, just below and just above an activation height of `network`, plus the ends.
fn boundary_heights(network: &Network) -> Vec<Height> {
    let mut heights = vec![Height(0), Height(1), Height::MAX];
    for (height, _) in network.full_activation_list() {
        heights.extend(
            [height.previous().ok(), Some(height), height.next().ok()]
                .into_iter()
                .flatten(),
        );
    }
    // NU5..NU7 on Zcash's public networks, even where the list omits an upgrade.
    for nu in [Nu5, Nu6, Nu6_1, Nu6_2, Nu6_3, Nu7] {
        if let Some(height) = nu.activation_height(network) {
            heights.extend(
                [height.previous().ok(), Some(height), height.next().ok()]
                    .into_iter()
                    .flatten(),
            );
        }
    }
    heights
}

/// The networks a Zcash build knows, all with Vault dormant; in a `ycash` build, Ycash mainnet,
/// the `slow` testnet profile and the default Regtest (none of them schedules Vault).
fn networks_without_vault() -> Vec<Network> {
    let mut networks = vec![Network::Mainnet, Network::new_regtest(Default::default())];
    #[cfg(not(feature = "ycash"))]
    {
        networks.push(Network::new_default_testnet());
        // Regtest with every Zcash upgrade, through NU7, scheduled.
        networks.push(Network::new_regtest(RegtestParameters::from(
            ConfiguredActivationHeights {
                nu5: Some(10),
                nu6: Some(20),
                nu6_1: Some(30),
                nu6_2: Some(40),
                nu6_3: Some(50),
                nu7: Some(60),
                ..Default::default()
            },
        )));
    }
    #[cfg(feature = "ycash")]
    networks.push(Network::new_ycash_testnet_slow());
    networks
}

#[test]
fn is_vault_active_is_false_where_vault_is_not_scheduled() {
    for network in networks_without_vault() {
        assert_eq!(network.vault_activation_height(), None, "{network}");
        assert!(!network.activation_list().values().any(|nu| *nu == Vault));
        for height in boundary_heights(&network) {
            assert!(
                !network.is_vault_active(height),
                "{network}: Vault must be dormant at {height:?}"
            );
            assert_ne!(NetworkUpgrade::current(&network, height), Vault);
            assert_ne!(
                ConsensusBranchId::current(&network, height).map(u32::from),
                Some(VAULT_BRANCH_ID)
            );
        }
        // Not listed in getblockchaininfo's upgrades, and librustzcash sees no height either.
        assert!(!network
            .full_activation_list()
            .iter()
            .any(|(_, nu)| *nu == Vault));
        assert_eq!(
            zcash_protocol::consensus::Parameters::activation_height(
                &network,
                zcash_protocol::consensus::NetworkUpgrade::Vault
            ),
            None,
            "{network}"
        );
    }
}

/// The trap the predicate exists for (mapping M24-2): `activation_height` falls back to the next
/// upgrade's height, so on a network with NU5 it would read Vault as active from NU5's height.
#[cfg(not(feature = "ycash"))]
#[test]
fn vault_activation_height_fallback_is_never_the_predicate() {
    let network = Network::Mainnet;
    assert_eq!(
        Vault.activation_height(&network),
        Nu5.activation_height(&network)
    );
    assert_eq!(network.vault_activation_height(), None);
    assert!(!network.is_vault_active(Height::MAX));
}

#[test]
fn is_vault_active_follows_explicit_membership() {
    let network = regtest_with_vault(10);
    assert_eq!(network.vault_activation_height(), Some(Height(10)));
    assert!(!network.is_vault_active(Height(9)));
    assert!(network.is_vault_active(Height(10)));
    assert!(network.is_vault_active(Height(11)));
    assert!(network.is_vault_active(Height::MAX));

    assert_eq!(NetworkUpgrade::current(&network, Height(9)), Canopy);
    assert_eq!(NetworkUpgrade::current(&network, Height(10)), Vault);
    assert_eq!(
        ConsensusBranchId::current(&network, Height(10)).map(u32::from),
        Some(VAULT_BRANCH_ID)
    );
    // librustzcash (the common fork) sees the same height, so sighashes and the coinbase builder
    // use BranchId::Vault from H_V.
    assert_eq!(
        zcash_protocol::consensus::Parameters::activation_height(
            &network,
            zcash_protocol::consensus::NetworkUpgrade::Vault
        ),
        Some(zcash_protocol::consensus::BlockHeight::from_u32(10))
    );
    assert_eq!(
        zcash_protocol::consensus::BranchId::for_height(
            &network,
            zcash_protocol::consensus::BlockHeight::from_u32(10)
        ),
        zcash_protocol::consensus::BranchId::Vault
    );
    assert_eq!(
        network.full_activation_list().last().copied(),
        Some((Height(10), Vault))
    );
}

/// Vault at Canopy's height (and the mixed-regtest shape: everything at 1) wins the collapse.
#[test]
fn vault_at_a_shared_height_wins_the_collapse() {
    let network = regtest_with_vault(1);
    assert_eq!(network.vault_activation_height(), Some(Height(1)));
    assert!(network.is_vault_active(Height(1)));
    assert_eq!(NetworkUpgrade::current(&network, Height(1)), Vault);
    // Canopy and the upgrades below it are still active there: they fall back to Vault's height.
    assert_eq!(Canopy.activation_height(&network), Some(Height(1)));
    assert_eq!(Heartwood.activation_height(&network), Some(Height(1)));
}

/// ycashd's start-up check (`ycash6 src/init.cpp:1541-1565`, `qa/rpc-tests/vault_upgrade.py`
/// R-A3 cases, `src/test/testnet_params_tests.cpp` `testnet_upgrade_schedule`): the accept/refuse
/// table, row for row.
#[test]
fn vault_schedule_accept_refuse_table_equals_ycashd() {
    let sapling_to_canopy = |h| ConfiguredActivationHeights {
        before_overwinter: Some(1),
        overwinter: Some(h),
        sapling: Some(h),
        blossom: Some(h),
        heartwood: Some(h),
        canopy: Some(h),
        ..Default::default()
    };
    #[derive(Debug, PartialEq)]
    enum Want {
        Accept,
        WithoutSapling,
        WithNu5OrLater,
    }
    use Want::*;
    let rows: Vec<(&str, ConfiguredActivationHeights, Want)> = vec![
        ("no Vault", sapling_to_canopy(5), Accept),
        (
            "Vault above Canopy",
            ConfiguredActivationHeights {
                vault: Some(10),
                ..sapling_to_canopy(5)
            },
            Accept,
        ),
        (
            "Vault at Canopy",
            ConfiguredActivationHeights {
                vault: Some(5),
                ..sapling_to_canopy(5)
            },
            Accept,
        ),
        (
            "Vault at Sapling, Canopy-era chain at 1",
            ConfiguredActivationHeights {
                vault: Some(1),
                ..sapling_to_canopy(1)
            },
            Accept,
        ),
        // R-A3 (a): Vault alone, no Sapling at all (`assert_vault_alone_refused`).
        (
            "Vault alone",
            ConfiguredActivationHeights {
                vault: Some(10),
                ..Default::default()
            },
            WithoutSapling,
        ),
        // R-A3 (a): Sapling above Vault (`-nuparams=76b809bb:20` with Vault at 10).
        (
            "Sapling above Vault",
            ConfiguredActivationHeights {
                before_overwinter: Some(1),
                overwinter: Some(5),
                sapling: Some(20),
                vault: Some(10),
                ..Default::default()
            },
            WithoutSapling,
        ),
        // Sapling implicit from a later Sapling-era upgrade at or below Vault (ycashd back-fills it).
        (
            "Sapling implicit from Canopy",
            ConfiguredActivationHeights {
                before_overwinter: Some(1),
                overwinter: Some(1),
                canopy: Some(5),
                vault: Some(10),
                ..Default::default()
            },
            Accept,
        ),
        // R-A3 (b): any of NU5..NU6.2 with Vault, below it (`f919a198:5`) or above it (`5437f330:12`).
        (
            "NU5 below Vault",
            ConfiguredActivationHeights {
                nu5: Some(5),
                vault: Some(10),
                ..sapling_to_canopy(1)
            },
            WithNu5OrLater,
        ),
        (
            "NU6.2 above Vault",
            ConfiguredActivationHeights {
                nu6_2: Some(12),
                vault: Some(10),
                ..sapling_to_canopy(1)
            },
            WithNu5OrLater,
        ),
        (
            "NU6 with Vault",
            ConfiguredActivationHeights {
                nu6: Some(20),
                vault: Some(10),
                ..sapling_to_canopy(1)
            },
            WithNu5OrLater,
        ),
        (
            "NU6.1 with Vault",
            ConfiguredActivationHeights {
                nu6_1: Some(20),
                vault: Some(10),
                ..sapling_to_canopy(1)
            },
            WithNu5OrLater,
        ),
        // kogany's tail beyond ycashd's enum (NU6.3, NU7): refused the same way (plan §2.2), so
        // Vault can never be collapsed into a later upgrade at its height.
        (
            "NU6.3 with Vault",
            ConfiguredActivationHeights {
                nu6_3: Some(20),
                vault: Some(10),
                ..sapling_to_canopy(1)
            },
            WithNu5OrLater,
        ),
        (
            "NU7 at Vault",
            ConfiguredActivationHeights {
                nu7: Some(10),
                vault: Some(10),
                ..sapling_to_canopy(1)
            },
            WithNu5OrLater,
        ),
        // NU5..NU7 without Vault stay Zakura's business.
        (
            "NU5 without Vault",
            ConfiguredActivationHeights {
                nu5: Some(10),
                ..sapling_to_canopy(1)
            },
            Accept,
        ),
    ];
    for (name, heights, want) in rows {
        let got = match testnet::Parameters::build().with_activation_heights(heights) {
            Ok(_) => Accept,
            Err(error) if error.to_string() == WITHOUT_SAPLING => WithoutSapling,
            Err(error) if error.to_string() == WITH_NU5_OR_LATER => WithNu5OrLater,
            Err(other) => panic!("{name}: unexpected refusal {other}"),
        };
        assert_eq!(got, want, "{name}");
    }

    // A configured testnet overlay refuses Vault on top of a schedule with NU5 or later.
    #[cfg(not(feature = "ycash"))]
    assert_eq!(
        testnet::Parameters::build()
            .with_activation_height_overlay(ConfiguredActivationHeights {
                vault: Some(4_000_000),
                ..Default::default()
            })
            .err()
            .map(|error| error.to_string()),
        Some(WITH_NU5_OR_LATER.to_string())
    );
    // Regtest back-fills Sapling to 1, so `vault` alone is a valid Regtest (ycashd's start_node
    // always passes Overwinter and Sapling); NU5 with Vault is refused there too.
    assert!(testnet::Parameters::new_regtest(RegtestParameters::from(
        ConfiguredActivationHeights {
            vault: Some(10),
            ..Default::default()
        }
    ))
    .is_ok());
    assert!(testnet::Parameters::new_regtest(RegtestParameters::from(
        ConfiguredActivationHeights {
            vault: Some(10),
            nu5: Some(20),
            ..Default::default()
        }
    ))
    .is_err());
}

/// kogany refuses Vault below an earlier upgrade (the builder's order check); ycashd accepts that
/// schedule and makes Vault current from its height (finding W2-b/1; no network uses it).
#[test]
fn vault_below_canopy_is_out_of_order() {
    let heights = ConfiguredActivationHeights {
        before_overwinter: Some(1),
        overwinter: Some(1),
        sapling: Some(1),
        canopy: Some(10),
        vault: Some(5),
        ..Default::default()
    };
    assert_eq!(
        testnet::Parameters::build()
            .with_activation_heights(heights)
            .err()
            .map(|error| error.to_string()),
        Some(OUT_OF_ORDER.to_string())
    );
}

#[test]
fn configured_vault_height_round_trips() {
    let heights: ConfiguredActivationHeights =
        serde_json::from_str(r#"{"Canopy": 1, "Vault": 7}"#).expect("Vault is a configured key");
    assert_eq!(heights.vault, Some(7));
    let network = Network::new_regtest(RegtestParameters::from(heights));
    assert_eq!(network.vault_activation_height(), Some(Height(7)));
    // ConfiguredActivationHeights from an activation list keeps Vault.
    let back = ConfiguredActivationHeights::from(network.activation_list());
    assert_eq!(back.vault, Some(7));
    // Unset Vault is not serialized, so upstream's configuration files are unchanged.
    let json = serde_json::to_string(&ConfiguredActivationHeights::default()).expect("serializes");
    assert!(!json.contains("Vault"), "{json}");
}

/// kogany (W3-c finding F-1): the Falcon height is `pq_falcon_height` in the activation heights,
/// not a network upgrade: it takes 0, never enters the activation list, and is unset by default.
#[test]
fn configured_pq_falcon_height() {
    let heights: ConfiguredActivationHeights =
        serde_json::from_str(r#"{"Canopy": 1, "Vault": 7, "pq_falcon_height": 0}"#)
            .expect("pq_falcon_height is a configured key");
    assert_eq!(heights.pq_falcon, Some(0));
    let json = serde_json::to_string(&ConfiguredActivationHeights::default()).expect("serializes");
    assert!(!json.contains("pq_falcon"), "{json}");

    let regtest = Network::new_regtest(RegtestParameters::default());
    assert_eq!(
        regtest.pq_falcon_height(),
        None,
        "Regtest has none by default"
    );

    #[cfg(feature = "ycash")]
    {
        let network = Network::new_regtest(RegtestParameters::from(heights));
        assert!(network.is_regtest());
        assert_eq!(network.pq_falcon_height(), Some(Height(0)));
        assert_eq!(
            network.activation_list().len(),
            regtest_with_vault(7).activation_list().len(),
            "the Falcon height is not an activation"
        );
        let later = Network::new_regtest(RegtestParameters::from(ConfiguredActivationHeights {
            vault: Some(7),
            pq_falcon: Some(12),
            ..Default::default()
        }));
        assert_eq!(later.pq_falcon_height(), Some(Height(12)));
        // Mainnet and the testnets: 0 (quantum plan D-Q-2), unless a configured testnet sets it.
        assert_eq!(Network::Mainnet.pq_falcon_height(), Some(Height(0)));
        assert_eq!(
            Network::new_default_testnet().pq_falcon_height(),
            Some(Height(0))
        );
        let configured = testnet::Parameters::build()
            .with_activation_height_overlay(ConfiguredActivationHeights {
                pq_falcon: Some(20),
                ..Default::default()
            })
            .expect("a Falcon height alone is valid")
            .to_network()
            .expect("valid parameters");
        assert_eq!(configured.pq_falcon_height(), Some(Height(20)));
    }

    // A Zcash build has no Falcon height anywhere and refuses one.
    #[cfg(not(feature = "ycash"))]
    {
        assert_eq!(Network::Mainnet.pq_falcon_height(), None);
        assert_eq!(Network::new_default_testnet().pq_falcon_height(), None);
        assert!(testnet::Parameters::new_regtest(RegtestParameters::from(heights)).is_err());
    }
}

/// The Canopy behaviour of every exhaustive match (kogany plan §2.1), and the `_ =>` audit:
/// one assertion per arm a Vault height can reach.
#[test]
fn vault_takes_canopy_behaviour_in_every_match() {
    // network_upgrade.rs: spacing and averaging window.
    assert_eq!(Vault.target_spacing(), Canopy.target_spacing());
    assert_eq!(Vault.averaging_window(), Canopy.averaging_window());
    assert_eq!(Vault.next_upgrade(), Some(Nu5));
    assert_eq!(Canopy.next_upgrade(), Some(Vault));
    assert_eq!(
        NetworkUpgrade::from(zcash_protocol::consensus::NetworkUpgrade::Vault),
        Vault
    );
    assert!(!NetworkUpgrade::is_nu7_active(
        &regtest_with_vault(10),
        Height::MAX
    ));
    // Ordinal gates read Vault as Canopy-era (K-1).
    assert!(Vault > Canopy && Vault < Nu5);

    // history_tree.rs `_ if branch_id().is_none()` (both trees) and header-chain
    // `preparation.rs` `_ => u32::MAX`: Vault has a branch ID, so neither wildcard is reached.
    assert_eq!(Vault.branch_id().map(u32::from), Some(VAULT_BRANCH_ID));
    assert_eq!(NetworkUpgrade::try_from(VAULT_BRANCH_ID).ok(), Some(Vault));
    assert_eq!(
        zcash_protocol::consensus::BranchId::try_from(Vault.branch_id().expect("has one")).ok(),
        Some(zcash_protocol::consensus::BranchId::Vault)
    );

    // block/commitment.rs: Vault's header commits to the ZIP-221 chain history root, and at
    // Heartwood's activation height to the reserved value, as Canopy.
    let mut header = header_with_commitment([7; 32]);
    let network = regtest_with_vault(10);
    for height in [Height(9), Height(10), Height(11)] {
        assert!(matches!(
            header.commitment(&network, height),
            Ok(block::Commitment::ChainHistoryRoot(_))
        ));
    }
    let collapsed = regtest_with_vault(1);
    assert!(header.commitment(&collapsed, Height(1)).is_err());
    header = header_with_commitment(block::CHAIN_HISTORY_ACTIVATION_RESERVED);
    assert!(matches!(
        header.commitment(&collapsed, Height(1)),
        Ok(block::Commitment::ChainHistoryActivationReserved)
    ));
}

/// Zcash mainnet block 1's header with `commitment` in its commitment field.
fn header_with_commitment(commitment: [u8; 32]) -> block::Header {
    let block: block::Block = zakura_test::vectors::BLOCK_MAINNET_1_BYTES
        .zcash_deserialize_into()
        .expect("block 1 is a valid test vector");
    let mut header = *block.header;
    header.commitment_bytes = commitment.into();
    header
}

/// U-26 at the transaction layer: a v5 transaction with the Vault branch ID does not parse (the
/// `< Nu5` gate in `transaction/serialize.rs`), and v4 is the only version the fork's builder
/// suggests for Vault.
#[test]
fn v5_with_the_vault_branch_id_is_refused() {
    // An empty NU5 v5 transaction, its consensus branch ID (after the header and the version
    // group ID) swapped for Vault's.
    let v5 = Transaction::V5 {
        network_upgrade: Nu5,
        lock_time: LockTime::min_lock_time_timestamp(),
        expiry_height: Height(0),
        inputs: Vec::new(),
        outputs: Vec::new(),
        sapling_shielded_data: None,
        orchard_shielded_data: None,
    };
    let mut bytes = v5
        .zcash_serialize_to_vec()
        .expect("an empty v5 transaction serializes");
    assert!(bytes.zcash_deserialize_into::<Transaction>().is_ok());
    bytes[8..12].copy_from_slice(&VAULT_BRANCH_ID.to_le_bytes());
    let parsed: Result<Transaction, _> = bytes.zcash_deserialize_into();
    let error = parsed.expect_err("v5 under Vault is refused");
    assert!(
        error
            .to_string()
            .contains("NU5 or later consensus branch ID"),
        "{error}"
    );
    assert_eq!(
        zcash_primitives::transaction::TxVersion::suggested_for_branch(
            zcash_protocol::consensus::BranchId::Vault
        ),
        zcash_primitives::transaction::TxVersion::V4
    );
}

/// The grep guard (kogany plan §2.2): the only way code asks "is Vault on" is
/// `Network::is_vault_active`. Rejects an ordinal comparison with `Vault` and
/// `Vault.activation_height(..)` outside the predicate's own module.
#[test]
fn only_is_vault_active_asks_whether_vault_is_on() {
    let crates = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crates directory");
    // An ordinal comparison with `Vault`, on either side, or `Vault.activation_height`.
    let forbidden = |code: &str| {
        let code = code.replace("NetworkUpgrade::Vault", "Vault");
        code.match_indices("Vault").any(|(at, _)| {
            let before = &code[..at];
            let after = &code[at + "Vault".len()..];
            let is_word = !before.ends_with(|c: char| c.is_alphanumeric() || c == '_' || c == ':')
                && !after.starts_with(|c: char| c.is_alphanumeric() || c == '_');
            is_word
                // rustfmt spaces a comparison, never a generic bracket (`Vec<Vault>`).
                && ((before.ends_with(char::is_whitespace)
                    && is_ordinal_operator(before.trim_end(), true))
                    || (after.starts_with(char::is_whitespace)
                        && is_ordinal_operator(after.trim_start(), false))
                    || after.trim_start().trim_start_matches(')').starts_with(".activation_height"))
        })
    };
    let allowed = [
        crates.join("zakura-chain/src/parameters/network_upgrade.rs"),
        crates.join("zakura-chain/src/parameters/vault_tests.rs"),
    ];
    let mut hits = Vec::new();
    let mut stack = vec![crates.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in fs::read_dir(&dir).expect("readable directory") {
            let path = entry.expect("directory entry").path();
            if path.is_dir() {
                if path.file_name().is_some_and(|name| name == "target") {
                    continue;
                }
                stack.push(path);
            } else if path.extension().is_some_and(|ext| ext == "rs") && !allowed.contains(&path) {
                let text = fs::read_to_string(&path).expect("utf-8 source");
                for (index, line) in text.lines().enumerate() {
                    let code = line.split("//").next().unwrap_or_default();
                    if forbidden(code) {
                        hits.push(format!("{}:{}: {}", path.display(), index + 1, line.trim()));
                    }
                }
            }
        }
    }
    assert!(
        hits.is_empty(),
        "ask Network::is_vault_active instead:\n{}",
        hits.join("\n")
    );
}

/// Whether `text` ends (`before`) or starts (`!before`) with `<`, `<=`, `>` or `>=` used as a
/// comparison, not as part of `=>`, `->`, `<<`, `>>` or a generic bracket next to a word.
fn is_ordinal_operator(text: &str, before: bool) -> bool {
    let chars: Vec<char> = if before {
        text.chars().rev().take(3).collect()
    } else {
        text.chars().take(3).collect()
    };
    // `chars[0]` is the character next to `Vault`.
    match chars.as_slice() {
        ['=', c, ..] if before => matches!(c, '<' | '>') && chars.get(2) != Some(c),
        ['<' | '>', ..] => {
            let next = chars.get(1).copied();
            if before {
                // `x < Vault`, but not `-> Vault`, `=> Vault`, `Vec<Vault` or `<< Vault`.
                !matches!(next, Some('-' | '=' | '<' | '>'))
                    && next.is_some_and(char::is_whitespace)
            } else {
                // `Vault > x` or `Vault >= x`, but not `Vault>` closing a generic or `Vault =>`.
                matches!(next, Some('=')) || next.is_some_and(char::is_whitespace)
            }
        }
        _ => false,
    }
}

/// The Ycash profile's compiled-in Vault heights (`ycash6 src/chainparams.cpp`): none on mainnet,
/// 510,400 on the `fast` testnet, none on the `slow` testnet.
#[cfg(feature = "ycash")]
#[test]
fn ycash_profile_vault_heights_equal_ycashd() {
    use crate::parameters::ycash::testnet::VAULT_FAST;

    assert_eq!(Network::Mainnet.vault_activation_height(), None);
    let fast = Network::new_default_testnet();
    assert_eq!(VAULT_FAST, Height(510_400));
    assert_eq!(fast.vault_activation_height(), Some(VAULT_FAST));
    assert!(!fast.is_vault_active(Height(510_399)));
    assert!(fast.is_vault_active(Height(510_400)));
    assert_eq!(
        Network::new_ycash_testnet_slow().vault_activation_height(),
        None
    );
    assert_eq!(
        Network::new_regtest(Default::default()).vault_activation_height(),
        None
    );
}

/// Plan §2.3/§2.5: an upgrade a network does not schedule is not observable there. Neither
/// `Ycash` (in a Zcash build) nor `Vault` appears in `full_activation_list` (getblockchaininfo's
/// `upgrades`) or in librustzcash's `activation_height`, even on a configured testnet whose
/// later upgrades give them a fallback height (the `nu6testnet` snapshot's shape: Sapling 584,000
/// and NU6 set), so Zcash-network RPC output stays byte-identical to upstream.
#[cfg(not(feature = "ycash"))]
#[test]
fn unscheduled_kogany_upgrades_are_not_observable() {
    let configured = testnet::Parameters::build()
        .with_activation_heights(ConfiguredActivationHeights {
            before_overwinter: Some(1),
            overwinter: Some(207_500),
            sapling: Some(584_000),
            blossom: Some(584_001),
            heartwood: Some(584_002),
            canopy: Some(584_003),
            nu5: Some(584_004),
            nu6: Some(2_976_000),
            ..Default::default()
        })
        .expect("a valid configured testnet")
        .clear_funding_streams()
        .to_network()
        .expect("a valid configured testnet");
    let mut networks = networks_without_vault();
    networks.push(configured);
    for network in networks {
        for nu in [Ycash, Vault] {
            assert!(!network.is_kogany_upgrade_scheduled(nu), "{network} {nu:?}");
            assert!(
                !network
                    .full_activation_list()
                    .iter()
                    .any(|(_, listed)| *listed == nu),
                "{network}: {nu:?} is listed without a height"
            );
            assert!(
                !network
                    .full_activation_list()
                    .iter()
                    .any(|(_, listed)| listed.branch_id() == nu.branch_id()),
                "{network}: {nu:?}'s branch ID is reported"
            );
            assert_eq!(
                zcash_protocol::consensus::Parameters::activation_height(
                    &network,
                    match nu {
                        Ycash => zcash_protocol::consensus::NetworkUpgrade::Ycash,
                        _ => zcash_protocol::consensus::NetworkUpgrade::Vault,
                    }
                ),
                None,
                "{network} {nu:?}"
            );
        }
    }
    // Scheduled, Vault is listed at its own height, with its branch ID.
    let network = regtest_with_vault(10);
    assert!(network
        .full_activation_list()
        .contains(&(Height(10), Vault)));
}
