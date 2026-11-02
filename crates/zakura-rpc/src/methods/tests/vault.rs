//! kogany: block templates across the Vault activation (W2-b, the `proposal.rs` `_ =>` audit).
//!
//! `proposal_block_from_template` maps the current upgrade to the header's commitment field with
//! a wildcard error arm for pre-Canopy upgrades. Vault keeps Canopy's ZIP-221 chain history root,
//! and the coinbase is v4 (the common fork's `suggested_for_branch(Vault)`).

use zcash_address::{ToAddress, ZcashAddress};
use zcash_protocol::consensus::NetworkType;

use zakura_chain::{
    block::{ChainHistoryMmrRootHash, Height},
    parameters::{
        testnet::{ConfiguredActivationHeights, RegtestParameters},
        Network, NetworkUpgrade,
    },
    serialization::BytesInDisplayOrder,
    transaction::Transaction,
    work::difficulty::{CompactDifficulty, ExpandedDifficulty, U256},
};
use zakura_state::GetBlockTemplateChainInfo;

use crate::config::mining;
use crate::methods::{
    types::{
        get_block_template::{
            proposal::proposal_block_from_template, BlockTemplateResponse, MinerParams,
        },
        long_poll::LongPollInput,
    },
};

/// The chain history root the test state reports. A distinct fixed value rather than
/// `fake_history_tree(&Network::Mainnet)`: that tree is built from Zcash Mainnet block 1,046,400,
/// which precedes Ycash Mainnet Heartwood (1,100,003), so it cannot be built with `ycash`; and the
/// test is on regtest, where only the value the template carries into the header matters.
const CHAIN_HISTORY_ROOT: [u8; 32] = [0x5a; 32];

/// A template for the block after `tip` on `network`.
fn template_after(network: &Network, tip: Height) -> BlockTemplateResponse {
    let miner_params = MinerParams::new(
        network,
        mining::Config {
            miner_address: Some(ZcashAddress::from_transparent_p2pkh(
                NetworkType::Regtest,
                [0x7e; 20],
            )),
            ..Default::default()
        },
    )
    .expect("the test miner address is valid");
    let chain_info = GetBlockTemplateChainInfo {
        expected_difficulty: CompactDifficulty::from(ExpandedDifficulty::from(U256::one())),
        tip_height: tip,
        tip_hash: zakura_chain::block::Hash([1; 32]),
        cur_time: 1654008617.into(),
        min_time: 1654008606.into(),
        max_time: 1654008728.into(),
        chain_history_root: Some(ChainHistoryMmrRootHash::from(CHAIN_HISTORY_ROOT)),
        value_pools: Default::default(),
    };
    let long_poll_id = LongPollInput::new(
        chain_info.tip_height,
        chain_info.tip_hash,
        chain_info.max_time,
        vec![],
    )
    .generate_id();
    BlockTemplateResponse::new_internal(
        network,
        None,
        &miner_params,
        &chain_info,
        long_poll_id,
        vec![],
        None,
    )
    .expect("the test template is valid")
}

#[test]
fn templates_across_the_vault_activation_commit_to_the_chain_history_root() {
    let _init_guard = zakura_test::init();
    let network = Network::new_regtest(RegtestParameters::from(ConfiguredActivationHeights {
        vault: Some(10),
        ..Default::default()
    }));

    for (tip, upgrade) in [
        (Height(8), NetworkUpgrade::Canopy),
        (Height(9), NetworkUpgrade::Vault),
        (Height(10), NetworkUpgrade::Vault),
    ] {
        let template = template_after(&network, tip);
        let height = Height(template.height);
        assert_eq!(NetworkUpgrade::current(&network, height), upgrade);

        let block = proposal_block_from_template(&template, None, &network)
            .expect("Zakura generates Canopy and Vault templates");
        let chain_history_root = template
            .default_roots
            .chain_history_root
            .bytes_in_serialized_order();
        assert_eq!(chain_history_root, CHAIN_HISTORY_ROOT, "{height:?}");
        assert_eq!(
            *block.header.commitment_bytes, chain_history_root,
            "{height:?}"
        );
        assert!(
            matches!(*block.transactions[0], Transaction::V4 { .. }),
            "{height:?}: the coinbase is v4 under {upgrade:?}"
        );
    }
}
