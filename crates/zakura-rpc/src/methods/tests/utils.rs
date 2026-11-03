//! Utility functions for RPC method tests.

use std::sync::Arc;
use zakura_chain::{
    block::Block,
    history_tree::{HistoryTree, NonEmptyHistoryTree},
    parameters::Network,
    sapling::tree::Root,
    serialization::ZcashDeserialize,
};

/// Create a history tree with one single block for a network by using Zebra test vectors.
pub fn fake_history_tree(network: &Network) -> Arc<HistoryTree> {
    let (block, sapling_root) = network.test_block_sapling_roots(1046400, 1116000).unwrap();

    let block = Arc::<Block>::zcash_deserialize(block).expect("block should deserialize");
    let first_sapling_root = Root::try_from(sapling_root).unwrap();

    // kogany: the vector is Zcash Mainnet block 1,046,400 (Zcash Heartwood), which precedes Ycash
    // Mainnet Heartwood (1,100,003); with `ycash` the tree is built on the Ycash testnet, where
    // that height is past Heartwood. The callers only carry the root into a template.
    #[cfg(not(feature = "ycash"))]
    let tree_network = Network::Mainnet;
    #[cfg(feature = "ycash")]
    let tree_network = Network::new_default_testnet();

    let history_tree = NonEmptyHistoryTree::from_block(
        &tree_network,
        block,
        &first_sapling_root,
        &Default::default(),
        &Default::default(),
    )
    .unwrap();

    Arc::new(HistoryTree::from(history_tree))
}

/// The tip height the template-worker tests build on: Zcash's NU5 activation height, or with
/// `ycash` (kogany), which has no NU5, the network's Canopy activation height. The tests exercise
/// the worker, the long poll and the rejection paths, which do not depend on the upgrade.
pub fn template_tip_height(network: &Network) -> zakura_chain::block::Height {
    #[cfg(not(feature = "ycash"))]
    let upgrade = zakura_chain::parameters::NetworkUpgrade::Nu5;
    #[cfg(feature = "ycash")]
    let upgrade = zakura_chain::parameters::NetworkUpgrade::Canopy;
    upgrade
        .activation_height(network)
        .expect("the template test upgrade activates on the network")
}
