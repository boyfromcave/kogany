//! The Vault upgrade's contextual block rules (kogany plan W4-d, `check::vault`), over the ycash6
//! regtest chain `kogany-vault` recorded (`crates/kogany-vault/tests/data/`): on the recorded
//! chain the strict check accepts every block with the total transition's delta; a block whose
//! acts and template rules fail against its parent fork's set state is rejected as
//! `ValidateContextError::VaultRejected` (ycash6 `ConnectBlock`: DoS 100), where the total
//! transition of the write path would only skip the failing transactions.

use std::{collections::HashMap, path::Path, sync::Arc};

use tempfile::TempDir;
use zakura_chain::{
    amount::NonNegative,
    block::{Block, Height},
    parameters::{testnet::ConfiguredActivationHeights, Network},
    serialization::ZcashDeserializeInto,
    transaction, transparent,
    value_balance::ValueBalance,
};

use crate::{
    config::Config,
    constants::{state_database_format_version_in_code, STATE_DATABASE_KIND},
    service::{
        check::vault::block_vault_delta,
        finalized_state::{
            vault::{register_vault_params_for_test, VaultNetworkParams},
            ZakuraDb, STATE_COLUMN_FAMILIES_IN_CODE,
        },
        non_finalized_state::Chain,
        vault::{block_vault_delta_for_chain, mempool_vault_check},
    },
    CheckpointVerifiedBlock, ContextuallyVerifiedBlock, SemanticallyVerifiedBlock,
    ValidateContextError,
};

const FIXTURE: &str = "ycash6_statehash_vault_rpc.json";

struct Recorded {
    height: Height,
    block: Arc<Block>,
    tx_hashes: Arc<[transaction::Hash]>,
}

fn fixture() -> (VaultNetworkParams, Vec<Recorded>) {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../kogany-vault/tests/data")
        .join(FIXTURE);
    let doc: serde_json::Value =
        serde_json::from_slice(&std::fs::read(path).expect("the fixture is committed"))
            .expect("the fixture is JSON");
    let params = VaultNetworkParams {
        activation_height: Height(doc["vaultActivation"].as_u64().unwrap() as u32),
        min_set_maturity: doc["minSetMaturity"].as_u64().unwrap() as u32,
    };
    let blocks = doc["blocks"]
        .as_array()
        .unwrap()
        .iter()
        .map(|b| {
            let bytes = hex::decode(b["hex"].as_str().unwrap()).unwrap();
            let block: Arc<Block> = Arc::new(bytes.zcash_deserialize_into().unwrap());
            let tx_hashes = block.transactions.iter().map(|tx| tx.hash()).collect();
            Recorded {
                height: Height(b["height"].as_u64().unwrap() as u32),
                block,
                tx_hashes,
            }
        })
        .collect();
    (params, blocks)
}

fn empty_chain(network: &Network) -> Chain {
    Chain::new(
        network,
        Height(0),
        Default::default(),
        Default::default(),
        Default::default(),
        Default::default(),
        Default::default(),
        ValueBalance::<NonNegative>::zero(),
    )
}

/// The block as contextual validation sees it, with the coins it spends from `coins` (every
/// output created so far, the block's own included).
fn contextual(
    network: &Network,
    coins: &mut HashMap<transparent::OutPoint, transparent::OrderedUtxo>,
    b: &Recorded,
) -> ContextuallyVerifiedBlock {
    coins.extend(transparent::new_ordered_outputs_with_height(
        &b.block,
        b.height,
        &b.tx_hashes,
    ));
    let spent = b
        .block
        .transactions
        .iter()
        .flat_map(|tx| tx.inputs().iter().filter_map(|i| i.outpoint()))
        .map(|op| (op, coins[&op].clone()))
        .collect();
    let semantic = SemanticallyVerifiedBlock::from(CheckpointVerifiedBlock::from(b.block.clone()));
    ContextuallyVerifiedBlock::with_block_and_spent_utxos(network, semantic, spent)
        .expect("the recorded value balances are valid")
}

#[test]
fn check_vault_accepts_the_recorded_chain_and_rejects_acts_out_of_order() {
    let _init_guard = zakura_test::init();
    let (params, blocks) = fixture();
    let network = Network::new_regtest(ConfiguredActivationHeights::default().into());
    register_vault_params_for_test(&network, params);
    let dir = TempDir::new().unwrap();
    let db = ZakuraDb::new(
        &Config {
            cache_dir: dir.path().to_path_buf(),
            ephemeral: false,
            ..Config::default()
        },
        STATE_DATABASE_KIND,
        &state_database_format_version_in_code(),
        &network,
        true,
        STATE_COLUMN_FAMILIES_IN_CODE
            .iter()
            .map(ToString::to_string),
        false,
    )
    .expect("the state database opens");

    // The recorded chain: the strict check accepts every block, with the total delta.
    let mut coins = HashMap::new();
    let mut chain = empty_chain(&network);
    let mut chains = vec![chain.clone()];
    let mut writers = Vec::new();
    let mut deltas = Vec::new();
    for (i, b) in blocks.iter().enumerate() {
        let mut cv = contextual(&network, &mut coins, b);
        let strict = block_vault_delta(&network, &chain, &db, &cv)
            .unwrap_or_else(|e| panic!("recorded block {:?} passes check::vault: {e}", b.height));
        assert_eq!(
            strict,
            block_vault_delta_for_chain(&network, &chain, &db, &cv),
            "the strict and total transitions agree on a valid block"
        );
        if !strict.is_empty() {
            writers.push(i);
        }
        deltas.push(strict.clone());
        cv.vault_delta = Arc::new(strict);
        chain = chain.push(cv).expect("the recorded block pushes");
        chains.push(chain.clone());
    }
    assert!(writers.len() >= 10, "the chain carries vault acts");

    // Every later vault-writing block, pushed instead onto the fork just before the first one
    // (before any set exists): its acts and template rules fail, the block is rejected, and the
    // total transition would have skipped the failing transactions.
    let first = writers[0];
    let base = &chains[first];
    let mut rejected = 0;
    for &i in &writers[1..] {
        let mut coins_now = HashMap::new();
        for b in &blocks[..=i] {
            coins_now.extend(transparent::new_ordered_outputs_with_height(
                &b.block,
                b.height,
                &b.tx_hashes,
            ));
        }
        let cv = contextual(&network, &mut coins_now, &blocks[i]);
        match block_vault_delta(&network, base, &db, &cv) {
            Err(ValidateContextError::VaultRejected {
                reason,
                height,
                hash,
            }) => {
                assert!(reason.starts_with("bad-"), "a ycash6 reject reason: {reason}");
                assert_eq!((height, hash), (cv.height, cv.hash));
                let total = block_vault_delta_for_chain(&network, base, &db, &cv);
                assert_ne!(total, deltas[i], "the total transition skipped something");
                rejected += 1;
            }
            Err(other) => panic!("only a vault rejection: {other}"),
            Ok(_) => {}
        }
    }
    assert!(rejected >= 5, "out-of-order acts are rejected ({rejected})");

    // The mempool check (ycash6 `vault::CheckTx`): over the parent's state, a vault-writing
    // block's first non-coinbase transaction passes at the block's height; over the state
    // before the first act, some transaction of every rejected block fails with a C++ reason.
    let all_coins: HashMap<_, _> = blocks
        .iter()
        .flat_map(|b| {
            transparent::new_ordered_outputs_with_height(&b.block, b.height, &b.tx_hashes)
        })
        .map(|(op, u)| (op, u.utxo))
        .collect();
    let mut mempool_rejected = 0;
    for &i in &writers {
        let b = &blocks[i];
        let parent_state = chains[i].vault_view(&db).set_state();
        let base_state = base.vault_view(&db).set_state();
        let mut first = true;
        let mut any_failed = false;
        for (tx, txid) in b.block.transactions.iter().zip(b.tx_hashes.iter()) {
            if tx.is_coinbase() {
                continue;
            }
            if first {
                mempool_vault_check(&network, &parent_state, None, tx, txid, b.height, &all_coins)
                    .unwrap_or_else(|r| panic!("block {:?}'s first tx passes: {r}", b.height));
                first = false;
            }
            if let Err(reason) =
                mempool_vault_check(&network, &base_state, None, tx, txid, b.height, &all_coins)
            {
                assert!(reason.starts_with("bad-"), "a ycash6 reason: {reason}");
                any_failed = true;
            }
        }
        mempool_rejected += usize::from(any_failed);
    }
    assert!(mempool_rejected >= 5, "the mempool rejects them too ({mempool_rejected})");

    // Before the activation height nothing is checked.
    let mut pre = contextual(&network, &mut HashMap::new(), &blocks[0]);
    pre.height = Height(params.activation_height.0 - 1);
    assert!(block_vault_delta(&network, base, &db, &pre)
        .expect("before Vault nothing is checked")
        .is_empty());
}

/// The Vault parameters come from the network (W2-b's `Network::vault_activation_height`, never
/// a later upgrade's height) without any test registration: a Vault regtest answers its height
/// and regtest's set maturity 2; a network without Vault answers none (mainnet's 16,128
/// maturity is `kogany_vault::state::MIN_SET_MATURITY`).
#[test]
fn vault_network_params_follow_the_network() {
    use crate::service::finalized_state::vault::{vault_min_set_maturity, vault_network_params};

    let _init_guard = zakura_test::init();
    let vault_regtest = Network::new_regtest(
        ConfiguredActivationHeights {
            canopy: Some(1),
            vault: Some(200),
            ..Default::default()
        }
        .into(),
    );
    assert_eq!(
        vault_network_params(&vault_regtest),
        Some(VaultNetworkParams {
            activation_height: Height(200),
            min_set_maturity: 2,
        })
    );
    let plain_regtest = Network::new_regtest(ConfiguredActivationHeights::default().into());
    assert_eq!(vault_network_params(&plain_regtest), None);
    assert_eq!(
        vault_min_set_maturity(&Network::Mainnet),
        kogany_vault::state::MIN_SET_MATURITY
    );
    assert_eq!(kogany_vault::state::MIN_SET_MATURITY, 16_128);
}
