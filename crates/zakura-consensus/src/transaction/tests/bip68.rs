//! BIP68 relative lock-times in the transaction verifier (kogany plan W3-d): a mempool
//! transaction is evaluated at the next block's height (ycash6 `AcceptToMemoryPool`'s
//! `ContextualCheckSequenceLocks(.., nextBlockHeight, .., true)`), a mempool parent counts at
//! that height, and the rule is off wherever Vault is not active. The block rule is zakura-state's
//! contextual validation (`check::sequence_locks`).

use std::collections::HashMap;

use tower::ServiceExt;
use zakura_chain::{
    amount::Amount,
    block::Height,
    parameters::{
        testnet::{ConfiguredActivationHeights, RegtestParameters},
        Network,
    },
    serialization::DateTime32,
    transaction::{LockTime, Transaction},
    transparent,
};
use zakura_state::{
    check::sequence_locks::{SEQUENCE_LOCKTIME_MASK, SEQUENCE_LOCKTIME_TYPE_FLAG},
    ValidateContextError,
};
use zakura_test::mock_service::MockService;

use crate::error::TransactionError;

use super::{check, mock_transparent_transfer, Request, Verifier};

const VAULT: u32 = 10;

fn regtest_with_vault() -> Network {
    Network::new_regtest(RegtestParameters::from(ConfiguredActivationHeights {
        vault: Some(VAULT),
        ..Default::default()
    }))
}

/// A one-input v4 spend of a coin at `coin_height` with `sequence`, and the coin.
fn spend(
    coin_height: Height,
    sequence: u32,
) -> (Transaction, transparent::OutPoint, transparent::Utxo) {
    let (mut input, output, known_utxos) =
        mock_transparent_transfer(coin_height, true, 0, Amount::try_from(10001).unwrap());
    let transparent::Input::PrevOut {
        outpoint,
        sequence: input_sequence,
        ..
    } = &mut input
    else {
        unreachable!("mock_transparent_transfer returns a prevout input")
    };
    *input_sequence = sequence;
    let outpoint = *outpoint;
    let utxo = known_utxos[&outpoint].utxo.clone();
    let tx = Transaction::V4 {
        inputs: vec![input],
        outputs: vec![output],
        lock_time: LockTime::min_lock_time_timestamp(),
        expiry_height: Height(0),
        joinsplit_data: None,
        sapling_shielded_data: None,
    };
    (tx, outpoint, utxo)
}

/// Runs a mempool request at `height` through the verifier, the coin at its own height in the
/// best chain.
async fn mempool_verify(
    network: &Network,
    tx: Transaction,
    outpoint: transparent::OutPoint,
    utxo: transparent::Utxo,
    height: Height,
) -> Result<(), TransactionError> {
    let mut state: MockService<_, _, _, _> = MockService::build().for_prop_tests();
    let verifier = Verifier::new_for_tests(network, state.clone());
    // kogany (W4-d): from Vault the verifier reads the tip's set state for the scripts.
    let vault_active = network.is_vault_active(height);

    tokio::spawn(async move {
        state
            .expect_request(zakura_state::Request::BestChainNextMedianTimePast)
            .await
            .expect("the verifier asks the state")
            .respond(zakura_state::Response::BestChainNextMedianTimePast(
                DateTime32::MAX,
            ));
        state
            .expect_request(zakura_state::Request::UnspentBestChainUtxo(outpoint))
            .await
            .expect("the verifier asks the state")
            .respond(zakura_state::Response::UnspentBestChainUtxo(Some(utxo)));
        if vault_active {
            let tip = height.previous().expect("a mempool height is above genesis");
            state
                .expect_request(zakura_state::Request::BestChainVaultSnapshot)
                .await
                .expect("the verifier asks the state")
                .respond(zakura_state::Response::VaultSnapshot(Some(
                    zakura_state::vault::VaultSnapshot {
                        tip: Some((tip, zakura_chain::block::Hash([0; 32]))),
                        state: Default::default(),
                    },
                )));
        }
        state
            .expect_request_that(|req| {
                matches!(
                    req,
                    zakura_state::Request::CheckBestChainTipNullifiersAndAnchors(_)
                )
            })
            .await
            .expect("the verifier asks the state")
            .respond(zakura_state::Response::ValidBestChainTipNullifiersAndAnchors);
        // kogany (W6-c): from Vault the verifier asks the YED module last.
        #[cfg(feature = "ycash")]
        if vault_active {
            let tip = height.previous().expect("a mempool height is above genesis");
            state
                .expect_request_that(|req| {
                    matches!(req, zakura_state::Request::BestChainYedMempoolCheck(_))
                })
                .await
                .expect("the verifier asks the state")
                .respond(zakura_state::Response::YedMempoolCheck {
                    tip: Some((tip, zakura_chain::block::Hash([0; 32]))),
                    reasons: vec![None],
                });
        }
    });

    verifier
        .oneshot(Request::Mempool {
            transaction: tx.into(),
            height,
        })
        .await
        .map(|_| ())
}

/// A coin at H with a lock of 5: the mempool request for height H + 4 (tip H + 3) waits, the
/// one for H + 5 (tip H + 4) is accepted. The block at H + 5 is checked at H + 5 by contextual
/// validation, so the mempool admits exactly what the next block may include.
#[tokio::test]
async fn vault_bip68_mempool_evaluates_at_the_next_height() {
    let _init_guard = zakura_test::init();

    // The Vault regtest and, in a `ycash` build, the Ycash `fast` testnet.
    #[allow(unused_mut)]
    let mut networks = vec![(regtest_with_vault(), 100)];
    #[cfg(feature = "ycash")]
    networks.push((
        Network::new_default_testnet(),
        zakura_chain::parameters::ycash::testnet::VAULT_FAST.0 + 100,
    ));

    for (network, coin) in networks {
        let (tx, outpoint, utxo) = spend(Height(coin), 5);
        let error = mempool_verify(
            &network,
            tx.clone(),
            outpoint,
            utxo.clone(),
            Height(coin + 4),
        )
        .await
        .expect_err("the lock is not satisfied by the next block at coin + 4");
        let TransactionError::ValidateContextError(context) = &error else {
            panic!("a contextual rejection, got {error:?}")
        };
        assert!(
            matches!(
                **context,
                ValidateContextError::UnsatisfiedSequenceLock {
                    spend_height,
                    min_spend_height,
                    ..
                } if spend_height == Height(coin + 4) && min_spend_height == Height(coin + 5)
            ),
            "{network:?}: {context:?}"
        );
        // non-BIP68-final: never scored in the mempool (ycash6 DoS 0).
        assert_eq!(error.mempool_misbehavior_score(), 0);

        mempool_verify(&network, tx, outpoint, utxo, Height(coin + 5))
            .await
            .expect("the lock is satisfied by the next block at coin + 5");
    }
}

/// A time-based relative lock is `bad-txns-vault-timelock`, unscored in the mempool (ycash6
/// DoS 0 there, 100 in a block).
#[tokio::test]
async fn vault_bip68_mempool_rejects_a_time_based_lock() {
    let _init_guard = zakura_test::init();
    let network = regtest_with_vault();

    let (tx, outpoint, utxo) = spend(Height(100), SEQUENCE_LOCKTIME_TYPE_FLAG | 1);
    let error = mempool_verify(&network, tx, outpoint, utxo, Height(1000))
        .await
        .expect_err("a time-based relative lock is invalid under Vault");
    let TransactionError::ValidateContextError(context) = &error else {
        panic!("a contextual rejection, got {error:?}")
    };
    assert!(matches!(
        **context,
        ValidateContextError::VaultTimeLock {
            input_index: 0,
            sequence,
            ..
        } if sequence == SEQUENCE_LOCKTIME_TYPE_FLAG | 1
    ));
    assert_eq!(error.mempool_misbehavior_score(), 0);
}

/// Before Vault the verifier does not look at sequence numbers.
#[tokio::test]
async fn vault_bip68_mempool_ignores_sequences_before_vault() {
    let _init_guard = zakura_test::init();
    let network = regtest_with_vault();
    let below = Height(VAULT - 1);

    for sequence in [SEQUENCE_LOCKTIME_MASK, SEQUENCE_LOCKTIME_TYPE_FLAG | 1] {
        let (tx, outpoint, utxo) = spend(Height(VAULT - 2), sequence);
        mempool_verify(&network, tx, outpoint, utxo, below)
            .await
            .expect("BIP68 is not active before Vault");
    }
}

/// A mempool parent's output is entered at the request height (`spent_utxos`), so it counts as
/// confirming in the next block: lock 0 passes, lock 1 waits (ycash6's `MEMPOOL_HEIGHT` coin).
#[test]
fn vault_bip68_mempool_parent_counts_at_the_next_height() {
    let _init_guard = zakura_test::init();
    let network = regtest_with_vault();
    let next = Height(200);

    for (sequence, ok) in [(0, true), (1, false), (u32::MAX, true)] {
        let (tx, outpoint, mut utxo) = spend(next, sequence);
        // As `Verifier::spent_utxos` builds a mempool parent: `Utxo::new(output, req.height())`.
        utxo = transparent::Utxo::new(utxo.output, next, false);
        let spent = HashMap::from([(outpoint, utxo)]);
        assert_eq!(
            check::tx_transparent_sequence_locks(&network, &tx, next, &spent).is_ok(),
            ok,
            "sequence {sequence:#x}"
        );
    }
}

/// Every network that does not schedule Vault, at every activation boundary: every Zcash
/// network in a Zcash build; Ycash mainnet, the `slow` testnet and the default regtest in a
/// `ycash` build.
#[test]
fn vault_bip68_inactive_on_every_zcash_network() {
    let _init_guard = zakura_test::init();

    #[allow(unused_mut)]
    let mut networks = vec![Network::Mainnet, Network::new_regtest(Default::default())];
    #[cfg(not(feature = "ycash"))]
    {
        networks.push(Network::new_default_testnet());
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

    for network in networks {
        assert_eq!(network.vault_activation_height(), None, "{network:?}");
        let mut heights = vec![Height(0), Height(1), Height::MAX];
        for (height, _) in network.full_activation_list() {
            heights.extend(
                [height.previous().ok(), Some(height), height.next().ok()]
                    .into_iter()
                    .flatten(),
            );
        }
        for height in heights {
            for sequence in [SEQUENCE_LOCKTIME_MASK, SEQUENCE_LOCKTIME_TYPE_FLAG | 1] {
                let (tx, outpoint, utxo) = spend(height, sequence);
                let spent = HashMap::from([(outpoint, utxo)]);
                assert_eq!(
                    check::tx_transparent_sequence_locks(&network, &tx, height, &spent),
                    Ok(()),
                    "{network:?} {height:?} {sequence:#x}"
                );
            }
        }
    }
}
