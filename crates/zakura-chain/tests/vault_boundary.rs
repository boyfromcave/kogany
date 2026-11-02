//! kogany W2-d: the Vault activation boundary on a regtest that schedules Vault (a Ycash regtest
//! in a `ycash` build), at H_V − 1, H_V and H_V + 1.
//!
//! What ycashd reports there, and kogany must equal:
//! - `getblockchaininfo.consensus.chaintip` / `nextblock`: Canopy's branch ID below H_V, `6d5b7a31`
//!   from H_V (`CurrentEpochBranchId`, `ycash6 src/consensus/upgrades.cpp:141-143`);
//! - `getblockchaininfo.upgrades["6d5b7a31"]`: `activationheight` H_V, `pending` while the tip is
//!   below it, `active` from a tip at H_V;
//! - `hashBlockCommitments` (the ZIP-221 `hashLightClientRoot` field, pre-NU5): block H commits to
//!   the history tree of its epoch through H − 1, and a new epoch starts a new tree, so block H_V
//!   commits to the Canopy-epoch tree through H_V − 1, and block H_V + 1 to a one-leaf Vault tree
//!   (`history_tree.rs` `push_from_parts`: a new upgrade replaces the tree). Vault's leaves are V1,
//!   as Canopy's (ycash6's history-tree dispatcher, plan §2.1).

use zakura_chain::{
    block::{self, Height},
    history_tree::{HistoryTreeBlockParts, NonEmptyHistoryTree},
    ironwood, orchard,
    parameters::{
        testnet::{ConfiguredActivationHeights, RegtestParameters},
        ConsensusBranchId, Network, NetworkUpgrade,
    },
    sapling,
    serialization::ZcashDeserializeInto,
};

/// H_V on the test network.
const VAULT: u32 = 10;

fn network() -> Network {
    Network::new_regtest(RegtestParameters::from(ConfiguredActivationHeights {
        vault: Some(VAULT),
        ..Default::default()
    }))
}

/// Zcash mainnet block 1's header, used as every leaf's header (the leaf commits to its hash,
/// time, target and the parts below; the boundary behaviour does not depend on them).
fn header() -> block::Header {
    let block: block::Block = zakura_test::vectors::BLOCK_MAINNET_1_BYTES
        .zcash_deserialize_into()
        .expect("block 1 is a valid test vector");
    *block.header
}

/// The tree after pushing heights `first..=last`, each leaf with a distinct Sapling root.
fn tree_through(
    network: &Network,
    header: &block::Header,
    roots: &[sapling::tree::Root],
    last: u32,
) -> NonEmptyHistoryTree {
    let orchard = orchard::tree::Root::default();
    let ironwood = ironwood::tree::Root::default();
    let parts = |height: u32| HistoryTreeBlockParts {
        header,
        height: Height(height),
        sapling_root: &roots[height as usize],
        orchard_root: &orchard,
        ironwood_root: &ironwood,
        sapling_tx: 0,
        orchard_tx: 0,
        ironwood_tx: 0,
    };
    let heartwood = NetworkUpgrade::Heartwood
        .activation_height(network)
        .expect("regtest schedules Heartwood")
        .0;
    let mut tree =
        NonEmptyHistoryTree::from_parts(network, parts(heartwood)).expect("a Heartwood-era leaf");
    for height in heartwood + 1..=last {
        tree.push_from_parts(parts(height))
            .expect("each next height appends");
    }
    tree
}

#[test]
fn branch_id_and_upgrade_info_across_the_vault_boundary() {
    let network = network();
    let canopy = NetworkUpgrade::Canopy.branch_id();
    let vault = NetworkUpgrade::Vault.branch_id();
    assert_eq!(vault.map(u32::from), Some(0x6d5b_7a31));

    // consensus.chaintip at each tip, and consensus.nextblock for the block after it.
    for (tip, chaintip, nextblock) in [
        (VAULT - 1, canopy, vault),
        (VAULT, vault, vault),
        (VAULT + 1, vault, vault),
    ] {
        assert_eq!(
            ConsensusBranchId::current(&network, Height(tip)),
            chaintip,
            "tip {tip}"
        );
        assert_eq!(
            ConsensusBranchId::current(&network, Height(tip + 1)),
            nextblock,
            "next block after {tip}"
        );
        assert_eq!(network.is_vault_active(Height(tip)), tip >= VAULT);
    }

    // upgrades: what getblockchaininfo lists (`full_activation_list`, keyed by branch ID).
    let listed: Vec<_> = network
        .full_activation_list()
        .into_iter()
        .filter(|(_, nu)| nu.branch_id() == vault)
        .collect();
    assert_eq!(listed, vec![(Height(VAULT), NetworkUpgrade::Vault)]);
    for (tip, active) in [(VAULT - 1, false), (VAULT, true), (VAULT + 1, true)] {
        assert_eq!(Height(tip) >= listed[0].0, active, "status at tip {tip}");
    }
}

#[test]
fn history_tree_resets_at_the_vault_activation() {
    let network = network();
    let header = header();
    let roots: Vec<sapling::tree::Root> = (0..=VAULT + 1)
        .map(|height| {
            let mut bytes = [0; 32];
            bytes[..4].copy_from_slice(&height.to_le_bytes());
            sapling::tree::Root::try_from(bytes).expect("a small field element")
        })
        .collect();

    // The header field is a chain history root at all three heights (Canopy's interpretation).
    for height in [VAULT - 1, VAULT, VAULT + 1] {
        let mut header = header;
        header.commitment_bytes = [3; 32].into();
        assert!(matches!(
            header.commitment(&network, Height(height)),
            Ok(block::Commitment::ChainHistoryRoot(_))
        ));
    }

    let canopy_epoch = tree_through(&network, &header, &roots, VAULT - 1);
    let at_vault = tree_through(&network, &header, &roots, VAULT);
    let after_vault = tree_through(&network, &header, &roots, VAULT + 1);

    // Block H_V commits to the Canopy epoch's tree through H_V - 1: a multi-leaf tree.
    assert!(canopy_epoch.size() > 1);
    assert_eq!(canopy_epoch.current_height(), Height(VAULT - 1));

    // Pushing H_V starts a new tree holding only the activation block.
    assert_eq!(at_vault.size(), 1, "the history tree resets at H_V");
    assert_eq!(at_vault.current_height(), Height(VAULT));
    let orchard = orchard::tree::Root::default();
    let ironwood = ironwood::tree::Root::default();
    let fresh = NonEmptyHistoryTree::from_parts(
        &network,
        HistoryTreeBlockParts {
            header: &header,
            height: Height(VAULT),
            sapling_root: &roots[VAULT as usize],
            orchard_root: &orchard,
            ironwood_root: &ironwood,
            sapling_tx: 0,
            orchard_tx: 0,
            ironwood_tx: 0,
        },
    )
    .expect("a Vault-era leaf");
    assert_eq!(
        at_vault.hash(),
        fresh.hash(),
        "block H_V + 1 commits to the one-leaf Vault tree"
    );
    assert_ne!(at_vault.hash(), canopy_epoch.hash());

    // H_V + 1 appends to the Vault tree: two leaves, three nodes.
    assert_eq!(after_vault.size(), 3);
    assert_ne!(after_vault.hash(), at_vault.hash());

    // A network without Vault keeps one Canopy tree across the same heights.
    let no_vault = Network::new_regtest(RegtestParameters::default());
    let continuous = tree_through(&no_vault, &header, &roots, VAULT);
    assert!(continuous.size() > 1);
}
