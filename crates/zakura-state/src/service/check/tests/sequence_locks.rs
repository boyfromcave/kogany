//! BIP68 relative lock-times from the Vault upgrade (kogany plan W3-d), re-expressed from ycash6
//! `upgrade/vault` `src/test/vault_script_tests.cpp` (`vault_bip68_calculate`,
//! `vault_bip68_contextual`), plus the reorg case and the inactive-before-Vault cases.

use std::{collections::HashMap, sync::Arc};

use zakura_chain::{
    amount::Amount,
    block::{Block, Height},
    parameters::{
        testnet::{ConfiguredActivationHeights, RegtestParameters},
        Network, NetworkUpgrade,
    },
    serialization::ZcashDeserializeInto,
    transaction::{self, LockTime, Transaction},
    transparent::{self, OrderedUtxo},
};

use crate::{
    config::Config,
    service::{
        check::{
            sequence_locks::{
                block_sequence_locks_are_satisfied, calculate_sequence_locks,
                evaluate_sequence_locks, transparent_sequence_locks,
                SEQUENCE_LOCKTIME_DISABLE_FLAG, SEQUENCE_LOCKTIME_TYPE_FLAG,
            },
            utxo::transparent_spend,
        },
        finalized_state::FinalizedState,
        non_finalized_state::CreatedUtxos,
    },
    SemanticallyVerifiedBlock, ValidateContextError,
};

/// `CTxIn::SEQUENCE_FINAL`.
const SEQUENCE_FINAL: u32 = 0xffff_ffff;

/// The regtest Vault activation height these tests use.
const VAULT: u32 = 10;

fn regtest_with_vault(vault: u32) -> Network {
    Network::new_regtest(RegtestParameters::from(ConfiguredActivationHeights {
        vault: Some(vault),
        ..Default::default()
    }))
}

/// `CalculateSequenceLocks` over `(nSequence, coin height)` pairs.
fn calc(seqs: &[u32], heights: &[u32]) -> Option<i64> {
    assert_eq!(seqs.len(), heights.len());
    calculate_sequence_locks(seqs.iter().copied().zip(heights.iter().copied().map(Height)))
}

fn outpoint(byte: u8, index: u32) -> transparent::OutPoint {
    transparent::OutPoint {
        hash: transaction::Hash([byte; 32]),
        index,
    }
}

fn input(outpoint: transparent::OutPoint, sequence: u32) -> transparent::Input {
    transparent::Input::PrevOut {
        outpoint,
        unlock_script: transparent::Script::new(&[]),
        sequence,
    }
}

fn output(value: u64) -> transparent::Output {
    transparent::Output {
        value: Amount::try_from(value).expect("a valid test amount"),
        lock_script: transparent::Script::new(&[0x51]),
    }
}

/// A non-coinbase v4 transaction with these inputs and outputs.
fn v4(inputs: Vec<transparent::Input>, outputs: Vec<transparent::Output>) -> Transaction {
    Transaction::V4 {
        inputs,
        outputs,
        lock_time: LockTime::unlocked(),
        expiry_height: Height(0),
        joinsplit_data: None,
        sapling_shielded_data: None,
    }
}

/// ycash6 `SeqTx`-style spends: one input per `(outpoint, nSequence)`.
fn spend(inputs: &[(transparent::OutPoint, u32)]) -> Transaction {
    v4(
        inputs.iter().map(|&(o, s)| input(o, s)).collect(),
        Vec::new(),
    )
}

/// `ContextualCheckSequenceLocks` with a coin-height table (a mempool parent is entered at the
/// height checked, as the transaction verifier enters it).
fn contextual(
    network: &Network,
    tx: &Transaction,
    spend_height: u32,
    coins: &HashMap<transparent::OutPoint, Height>,
) -> Result<(), ValidateContextError> {
    transparent_sequence_locks(network, tx, Height(spend_height), |o| coins.get(o).copied())
}

#[test]
fn vault_bip68_calculate() {
    let _init_guard = zakura_test::init();

    // Disabled inputs carry no lock.
    assert_eq!(calc(&[SEQUENCE_FINAL], &[100]), Some(-1));
    assert_eq!(calc(&[0xffff_fffe], &[100]), Some(-1));
    // A coin at height 100 with a lock of 5 is spendable from height 105.
    let m = calc(&[5], &[100]).unwrap();
    assert_eq!(m, 104);
    assert!(!evaluate_sequence_locks(Height(104), m));
    assert!(evaluate_sequence_locks(Height(105), m));
    // Lock 0 and 1: the same block and the next block.
    assert!(evaluate_sequence_locks(Height(100), calc(&[0], &[100]).unwrap()));
    assert!(!evaluate_sequence_locks(Height(100), calc(&[1], &[100]).unwrap()));
    assert!(evaluate_sequence_locks(Height(101), calc(&[1], &[100]).unwrap()));
    // Only the low 16 bits count.
    assert_eq!(calc(&[0x3fbf_0005], &[100]), Some(104));
    assert_eq!(calc(&[0xffff], &[0]), Some(65534));
    // The maximum over inputs.
    assert_eq!(calc(&[5, SEQUENCE_FINAL, 3], &[100, 1, 110]), Some(112));
    // A time-based lock makes the transaction invalid; with the disable flag it is ignored.
    assert_eq!(calc(&[SEQUENCE_LOCKTIME_TYPE_FLAG | 5], &[100]), None);
    assert_eq!(calc(&[5, SEQUENCE_LOCKTIME_TYPE_FLAG], &[100, 100]), None);
    assert_eq!(
        calc(
            &[SEQUENCE_LOCKTIME_DISABLE_FLAG | SEQUENCE_LOCKTIME_TYPE_FLAG | 5],
            &[100]
        ),
        Some(-1)
    );
    // No inputs, no lock; the far end of the height range does not overflow.
    assert_eq!(calc(&[], &[]), Some(-1));
    assert_eq!(
        calc(&[0xffff], &[Height::MAX.0]),
        Some(i64::from(Height::MAX.0) + 0xffff - 1)
    );
    assert!(!evaluate_sequence_locks(Height::MAX, calc(&[0xffff], &[Height::MAX.0]).unwrap()));
}

#[test]
fn vault_bip68_contextual() {
    let _init_guard = zakura_test::init();
    let network = regtest_with_vault(VAULT);

    // Coin `a` confirmed at 100; coin `b` is a mempool parent, entered at the height checked.
    let a = outpoint(0xaa, 0);
    let b = outpoint(0xbb, 0);
    let mut coins = HashMap::from([(a, Height(100))]);

    assert_eq!(contextual(&network, &spend(&[(a, 5)]), 105, &coins), Ok(()));
    let nonfinal = contextual(&network, &spend(&[(a, 5)]), 104, &coins).unwrap_err();
    assert_eq!(
        nonfinal,
        ValidateContextError::UnsatisfiedSequenceLock {
            spend_height: Height(104),
            min_spend_height: Height(105),
        }
    );

    let timelock = contextual(
        &network,
        &spend(&[(a, SEQUENCE_LOCKTIME_TYPE_FLAG | 1)]),
        1000,
        &coins,
    )
    .unwrap_err();
    assert_eq!(
        timelock,
        ValidateContextError::VaultTimeLock {
            input_index: 0,
            sequence: SEQUENCE_LOCKTIME_TYPE_FLAG | 1,
        }
    );
    // The time-type flag is invalid on any enabled input, wherever it is and whatever the others.
    assert!(matches!(
        contextual(
            &network,
            &spend(&[(a, SEQUENCE_FINAL), (a, 0), (a, SEQUENCE_LOCKTIME_TYPE_FLAG)]),
            1000,
            &coins
        ),
        Err(ValidateContextError::VaultTimeLock { input_index: 2, .. })
    ));

    // A mempool parent counts as confirming in the block checked: lock 0 passes, lock 1 waits.
    coins.insert(b, Height(200));
    assert_eq!(contextual(&network, &spend(&[(b, 0)]), 200, &coins), Ok(()));
    assert!(matches!(
        contextual(&network, &spend(&[(b, 1)]), 200, &coins),
        Err(ValidateContextError::UnsatisfiedSequenceLock { .. })
    ));
    assert_eq!(
        contextual(&network, &spend(&[(b, SEQUENCE_FINAL)]), 200, &coins),
        Ok(())
    );
}

/// The rule is independent of the transaction version (ycash6 checks every `CTransaction`) and
/// exempts the coinbase.
#[test]
fn vault_bip68_every_version_and_not_the_coinbase() {
    let _init_guard = zakura_test::init();
    let network = regtest_with_vault(VAULT);
    let a = outpoint(0xaa, 0);
    let coins = HashMap::from([(a, Height(100))]);

    let inputs = vec![input(a, 5)];
    let versions = [
        Transaction::V1 {
            inputs: inputs.clone(),
            outputs: Vec::new(),
            lock_time: LockTime::unlocked(),
        },
        Transaction::V2 {
            inputs: inputs.clone(),
            outputs: Vec::new(),
            lock_time: LockTime::unlocked(),
            joinsplit_data: None,
        },
        Transaction::V3 {
            inputs: inputs.clone(),
            outputs: Vec::new(),
            lock_time: LockTime::unlocked(),
            expiry_height: Height(0),
            joinsplit_data: None,
        },
        v4(inputs, Vec::new()),
    ];
    for tx in &versions {
        assert!(
            matches!(
                contextual(&network, tx, 104, &coins),
                Err(ValidateContextError::UnsatisfiedSequenceLock { .. })
            ),
            "{tx:?}"
        );
        assert_eq!(contextual(&network, tx, 105, &coins), Ok(()));
    }

    // A coinbase input's sequence is no relative lock.
    let coinbase = v4(
        vec![transparent::Input::Coinbase {
            height: Height(104),
            data: vec![0],
            sequence: SEQUENCE_LOCKTIME_TYPE_FLAG | 5,
        }],
        vec![output(0)],
    );
    assert!(coinbase.is_coinbase());
    assert_eq!(contextual(&network, &coinbase, 104, &coins), Ok(()));
}

/// Inactive before Vault: below the activation height on a Vault regtest, and at every height on
/// every network that does not schedule Vault (every Zcash network).
#[test]
fn vault_bip68_inactive_before_vault() {
    let _init_guard = zakura_test::init();
    let a = outpoint(0xaa, 0);
    let unsatisfied = |h: u32| (spend(&[(a, 0xffff)]), HashMap::from([(a, Height(h))]));
    let timelocked = spend(&[(a, SEQUENCE_LOCKTIME_TYPE_FLAG | 1)]);

    let network = regtest_with_vault(VAULT);
    let below = VAULT - 1;
    let (tx, coins) = unsatisfied(below);
    assert_eq!(contextual(&network, &tx, below, &coins), Ok(()));
    assert_eq!(contextual(&network, &timelocked, below, &coins), Ok(()));
    let (tx, coins) = unsatisfied(VAULT);
    assert!(contextual(&network, &tx, VAULT, &coins).is_err());
    assert!(contextual(&network, &timelocked, VAULT, &coins).is_err());

    // Every network a build knows. zakura-state has no `ycash` feature of its own (zakura-chain's
    // is unified in), so the build is told apart at run time: in a Zcash build none of these
    // schedules Vault; in a `ycash` build the default Testnet is the `fast` profile, which does,
    // and is then checked below and at its activation height. zakura-consensus's
    // `vault_bip68_inactive_on_every_zcash_network` adds the NU5..NU7 regtest per build.
    for network in [
        Network::Mainnet,
        Network::new_default_testnet(),
        Network::new_regtest(Default::default()),
    ] {
        let mut heights = vec![0, 1, Height::MAX.0];
        for (height, _) in network.full_activation_list() {
            heights.extend([height.0.saturating_sub(1), height.0, height.0.saturating_add(1)]);
        }
        for nu in [NetworkUpgrade::Nu5, NetworkUpgrade::Nu6, NetworkUpgrade::Nu7] {
            if let Some(height) = nu.activation_height(&network) {
                heights.extend([height.0.saturating_sub(1), height.0, height.0.saturating_add(1)]);
            }
        }
        let vault = network.vault_activation_height();
        for height in heights {
            let (tx, coins) = unsatisfied(height);
            let active = vault.is_some_and(|vault| Height(height) >= vault);
            assert_eq!(
                contextual(&network, &tx, height, &coins).is_err(),
                active,
                "{network:?} {height}"
            );
            assert_eq!(
                contextual(&network, &timelocked, height, &coins).is_err(),
                active,
                "{network:?} {height}"
            );
        }
    }
}

/// A block at `height` whose transactions follow its coinbase.
fn block_at(height: u32, transactions: Vec<Transaction>) -> SemanticallyVerifiedBlock {
    let mut block = zakura_test::vectors::BLOCK_MAINNET_1_BYTES
        .zcash_deserialize_into::<Block>()
        .expect("block should deserialize");
    let coinbase = v4(
        vec![transparent::Input::Coinbase {
            height: Height(height),
            data: vec![0],
            sequence: SEQUENCE_FINAL,
        }],
        Vec::new(),
    );
    block.transactions = std::iter::once(coinbase)
        .chain(transactions)
        .map(Arc::new)
        .collect();
    Arc::new(block).into()
}

/// A fork's created UTXOs: the parent output, mined at `height` on this fork.
fn fork_with_parent(parent: transparent::OutPoint, height: u32) -> CreatedUtxos {
    let mut created = CreatedUtxos::default();
    created.insert(
        parent,
        Arc::new(OrderedUtxo::new(output(10), Height(height), 1)),
    );
    created
}

/// The block-level check through the spend lookup `validate_and_commit` uses, on one fork.
fn check_block_on_fork(
    network: &Network,
    finalized: &FinalizedState,
    fork: &CreatedUtxos,
    block: &SemanticallyVerifiedBlock,
) -> Result<(), ValidateContextError> {
    let spent: HashMap<transparent::OutPoint, OrderedUtxo> =
        transparent_spend(block, fork, &Default::default(), &finalized.db)?;
    block_sequence_locks_are_satisfied(network, block, &spent)
}

/// The reorg case: the same spending block, at the same height, satisfies its lock on the fork
/// where the parent was mined early and fails it on the fork where the parent was mined late.
/// The coin height comes from each fork's own UTXO set (`Utxo.height`), never from a global
/// index, so a reorg needs no undo for this rule.
#[test]
fn vault_bip68_reorg_lock_satisfied_on_one_fork_only() {
    let _init_guard = zakura_test::init();
    let network = regtest_with_vault(VAULT);
    let finalized = FinalizedState::new_with_debug(&Config::ephemeral(), &network, true, false)
        .expect("opening an ephemeral database should succeed");

    let parent = outpoint(0xcc, 0);
    let block = block_at(20, vec![spend(&[(parent, 4)])]);

    // Fork A mined the parent at 16: 16 + 4 <= 20.
    let fork_a = fork_with_parent(parent, 16);
    assert_eq!(check_block_on_fork(&network, &finalized, &fork_a, &block), Ok(()));

    // Fork B mined the same parent at 17: 17 + 4 > 20.
    let fork_b = fork_with_parent(parent, 17);
    let error = check_block_on_fork(&network, &finalized, &fork_b, &block).unwrap_err();
    assert_eq!(
        error,
        ValidateContextError::UnsatisfiedSequenceLock {
            spend_height: Height(20),
            min_spend_height: Height(21),
        }
    );
    // A block that proves its own invalidity: the supplier is scored.
    assert_eq!(
        crate::CommitBlockError::ValidateContextError(Box::new(error)).misbehavior_score(),
        100
    );

    // On fork B the block one height later is valid again.
    let later = block_at(21, vec![spend(&[(parent, 4)])]);
    assert_eq!(check_block_on_fork(&network, &finalized, &fork_b, &later), Ok(()));
}

/// An output of an earlier transaction of the same block is at the block's height: lock 0 is
/// satisfied there, lock 1 is not (ycash6 `ConnectBlock`, whose view holds it at
/// `pindex->nHeight`).
#[test]
fn vault_bip68_parent_in_the_same_block() {
    let _init_guard = zakura_test::init();
    let network = regtest_with_vault(VAULT);
    let finalized = FinalizedState::new_with_debug(&Config::ephemeral(), &network, true, false)
        .expect("opening an ephemeral database should succeed");

    let funding = outpoint(0xdd, 0);
    let fork = fork_with_parent(funding, 12);
    let parent_tx = spend(&[(funding, SEQUENCE_FINAL)]);
    let parent_tx = v4(parent_tx.inputs().to_vec(), vec![output(5)]);
    let child_output = transparent::OutPoint {
        hash: parent_tx.hash(),
        index: 0,
    };

    for (lock, ok) in [(0, true), (1, false), (SEQUENCE_FINAL, true)] {
        let block = block_at(
            30,
            vec![parent_tx.clone(), spend(&[(child_output, lock)])],
        );
        assert_eq!(
            check_block_on_fork(&network, &finalized, &fork, &block).is_ok(),
            ok,
            "lock {lock:#x}"
        );
    }

    // A time-based lock in a block is a consensus failure scored 100.
    let block = block_at(
        30,
        vec![spend(&[(funding, SEQUENCE_LOCKTIME_TYPE_FLAG | 1)])],
    );
    let error = check_block_on_fork(&network, &finalized, &fork, &block).unwrap_err();
    assert!(matches!(error, ValidateContextError::VaultTimeLock { .. }));
    assert_eq!(
        crate::CommitBlockError::ValidateContextError(Box::new(error)).misbehavior_score(),
        100
    );

    // Before Vault the same blocks pass.
    let network = regtest_with_vault(1_000);
    let block = block_at(30, vec![parent_tx, spend(&[(child_output, 1)])]);
    assert_eq!(check_block_on_fork(&network, &finalized, &fork, &block), Ok(()));
}
