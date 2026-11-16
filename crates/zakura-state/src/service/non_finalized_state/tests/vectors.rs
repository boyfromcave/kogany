//! Fixed test vectors for the non-finalized state.
// kogany: the Zcash-fixture tests are not built with `ycash`, leaving their helpers unused.
#![cfg_attr(feature = "ycash", allow(unused_imports, dead_code))]

use std::{sync::Arc, time::Duration};

use zakura_chain::{
    amount::NonNegative,
    block::{self, Block, Height},
    history_tree::NonEmptyHistoryTree,
    ironwood, orchard,
    parameters::{Network, NetworkUpgrade},
    serialization::ZcashDeserializeInto,
    subtree::NoteCommitmentSubtree,
    value_balance::ValueBalance,
};
use zakura_test::prelude::*;

use crate::{
    arbitrary::Prepare,
    constants::{MAX_INVALIDATED_BLOCKS, MAX_NON_FINALIZED_CHAIN_FORKS},
    error::{PreciousError, ReconsiderError},
    service::{
        finalized_state::FinalizedState,
        non_finalized_state::{Chain, NonFinalizedState, MIN_DURATION_BETWEEN_BACKUP_UPDATES},
    },
    tests::FakeChainHelper,
    Config,
};

#[test]
fn construct_single() -> Result<()> {
    let _init_guard = zakura_test::init();
    let block: Arc<Block> =
        zakura_test::vectors::BLOCK_MAINNET_434873_BYTES.zcash_deserialize_into()?;

    let mut chain = Chain::new(
        &Network::Mainnet,
        Height(0),
        Default::default(),
        Default::default(),
        Default::default(),
        Default::default(),
        Default::default(),
        ValueBalance::fake_populated_pool(),
    );

    chain = chain.push(block.prepare().test_with_zero_spent_utxos())?;

    assert_eq!(1, chain.blocks.len());

    Ok(())
}

#[test]
fn construct_many() -> Result<()> {
    let _init_guard = zakura_test::init();

    let mut block: Arc<Block> =
        zakura_test::vectors::BLOCK_MAINNET_434873_BYTES.zcash_deserialize_into()?;
    let initial_height = block
        .coinbase_height()
        .expect("Block 434873 should have its height in its coinbase tx.");
    let mut blocks = vec![];

    while blocks.len() < 100 {
        let next_block = block.make_fake_child();
        blocks.push(block);
        block = next_block;
    }

    let mut chain = Chain::new(
        &Network::Mainnet,
        (initial_height - 1).expect("Initial height should be at least 1."),
        Default::default(),
        Default::default(),
        Default::default(),
        Default::default(),
        Default::default(),
        ValueBalance::fake_populated_pool(),
    );

    for block in blocks {
        chain = chain.push(block.prepare().test_with_zero_spent_utxos())?;
    }

    assert_eq!(100, chain.blocks.len());

    Ok(())
}

#[test]
fn ord_matches_work() -> Result<()> {
    let _init_guard = zakura_test::init();
    let less_block = zakura_test::vectors::BLOCK_MAINNET_434873_BYTES
        .zcash_deserialize_into::<Arc<Block>>()?
        .set_work(1);
    let more_block = less_block.clone().set_work(10);

    let mut lesser_chain = Chain::new(
        &Network::Mainnet,
        Height(0),
        Default::default(),
        Default::default(),
        Default::default(),
        Default::default(),
        Default::default(),
        ValueBalance::fake_populated_pool(),
    );
    lesser_chain = lesser_chain.push(less_block.prepare().test_with_zero_spent_utxos())?;

    let mut bigger_chain = Chain::new(
        &Network::Mainnet,
        Height(0),
        Default::default(),
        Default::default(),
        Default::default(),
        Default::default(),
        Default::default(),
        ValueBalance::zero(),
    );
    bigger_chain = bigger_chain.push(more_block.prepare().test_with_zero_spent_utxos())?;

    assert!(bigger_chain > lesser_chain);

    Ok(())
}

#[test]
// kogany: Zcash Mainnet and Testnet block vectors (NU5 branch IDs, Zcash Heartwood and NU5
// heights); not run on Ycash.
#[cfg(not(feature = "ycash"))]
fn best_chain_wins() -> Result<()> {
    let _init_guard = zakura_test::init();

    for network in Network::iter() {
        best_chain_wins_for_network(network)?;
    }

    Ok(())
}

fn best_chain_wins_for_network(network: Network) -> Result<()> {
    // Since the brand new FinalizedState below will pass a None history tree
    // to the NonFinalizedState, we must use pre-Heartwood blocks since
    // they won't trigger the history tree update in the NonFinalizedState.
    let block1: Arc<Block> = Arc::new(network.test_block(653599, 583999).unwrap());

    let block2 = block1.make_fake_child().set_work(10);
    let child = block1.make_fake_child().set_work(1);

    let expected_hash = block2.hash();

    let mut state = NonFinalizedState::new(&network);
    let finalized_state = FinalizedState::new(&Config::ephemeral(), &network)
        .expect("opening an ephemeral database should succeed");

    state.commit_new_chain(block2.prepare(), &finalized_state)?;
    state.commit_new_chain(child.prepare(), &finalized_state)?;

    let best_chain = state.best_chain().unwrap();
    assert!(best_chain.height_by_hash.contains_key(&expected_hash));

    Ok(())
}

#[test]
// kogany: Zcash Mainnet and Testnet block vectors (NU5 branch IDs, Zcash Heartwood and NU5
// heights); not run on Ycash.
#[cfg(not(feature = "ycash"))]
fn finalize_pops_from_best_chain() -> Result<()> {
    let _init_guard = zakura_test::init();

    for network in Network::iter() {
        finalize_pops_from_best_chain_for_network(network)?;
    }

    Ok(())
}

fn finalize_pops_from_best_chain_for_network(network: Network) -> Result<()> {
    // Since the brand new FinalizedState below will pass a None history tree
    // to the NonFinalizedState, we must use pre-Heartwood blocks since
    // they won't trigger the history tree update in the NonFinalizedState.
    let block1: Arc<Block> = Arc::new(network.test_block(653599, 583999).unwrap());

    let block2 = block1.make_fake_child().set_work(10);
    let child = block1.make_fake_child().set_work(1);

    let mut state = NonFinalizedState::new(&network);
    let finalized_state = FinalizedState::new(&Config::ephemeral(), &network)
        .expect("opening an ephemeral database should succeed");

    let fake_value_pool = ValueBalance::<NonNegative>::fake_populated_pool();
    finalized_state.set_finalized_value_pool(fake_value_pool);

    state.commit_new_chain(block1.clone().prepare(), &finalized_state)?;
    state.commit_block(block2.clone().prepare(), &finalized_state)?;
    state.commit_block(child.prepare(), &finalized_state)?;

    let finalized = state.finalize().inner_block();

    assert_eq!(block1, finalized);

    let finalized = state.finalize().inner_block();
    assert_eq!(block2, finalized);

    assert!(state.best_chain().is_none());

    Ok(())
}

/// Finalizing a shared root drops a side chain that contains only that root.
#[test]
// kogany: Zcash Mainnet and Testnet block vectors (NU5 branch IDs, Zcash Heartwood and NU5
// heights); not run on Ycash.
#[cfg(not(feature = "ycash"))]
fn finalize_drops_empty_side_chain() -> Result<()> {
    let _init_guard = zakura_test::init();

    for network in Network::iter() {
        finalize_drops_empty_side_chain_for_network(network)?;
    }

    Ok(())
}

fn finalize_drops_empty_side_chain_for_network(network: Network) -> Result<()> {
    let root: Arc<Block> = Arc::new(network.test_block(653599, 583999).unwrap());
    let child = root.make_fake_child().set_work(10);

    let root_chain = Chain::new(
        &network,
        Height(0),
        Default::default(),
        Default::default(),
        Default::default(),
        Default::default(),
        Default::default(),
        ValueBalance::fake_populated_pool(),
    )
    .push(root.clone().prepare().test_with_zero_spent_utxos())?;
    let best_chain = root_chain
        .clone()
        .push(child.clone().prepare().test_with_zero_spent_utxos())?;

    let mut state = NonFinalizedState::new(&network);
    state.insert(Arc::new(root_chain));
    state.insert(Arc::new(best_chain));
    assert_eq!(state.chain_count(), 2);

    let finalized = state.finalize().inner_block();

    assert_eq!(root, finalized);
    assert_eq!(state.chain_count(), 1);
    assert_eq!(state.best_chain_len(), Some(1));
    assert_eq!(
        state.best_tip().map(|(_height, hash)| hash),
        Some(child.hash())
    );

    Ok(())
}

#[test]
// kogany: Zcash Mainnet and Testnet block vectors (NU5 branch IDs, Zcash Heartwood and NU5
// heights); not run on Ycash.
#[cfg(not(feature = "ycash"))]
fn invalidate_block_removes_block_and_descendants_from_chain() -> Result<()> {
    let _init_guard = zakura_test::init();

    for network in Network::iter() {
        invalidate_block_removes_block_and_descendants_from_chain_for_network(network)?;
    }

    Ok(())
}

fn invalidate_block_removes_block_and_descendants_from_chain_for_network(
    network: Network,
) -> Result<()> {
    let block1: Arc<Block> = Arc::new(network.test_block(653599, 583999).unwrap());
    let block2 = block1.make_fake_child().set_work(10);
    let block3 = block2.make_fake_child().set_work(1);

    let mut state = NonFinalizedState::new(&network);
    let finalized_state = FinalizedState::new(&Config::ephemeral(), &network)
        .expect("opening an ephemeral database should succeed");

    let fake_value_pool = ValueBalance::<NonNegative>::fake_populated_pool();
    finalized_state.set_finalized_value_pool(fake_value_pool);

    state.commit_new_chain(block1.clone().prepare(), &finalized_state)?;
    state.commit_block(block2.clone().prepare(), &finalized_state)?;
    state.commit_block(block3.clone().prepare(), &finalized_state)?;

    assert_eq!(
        state
            .best_chain()
            .unwrap_or(&Arc::new(Chain::default()))
            .blocks
            .len(),
        3
    );

    let _ = state.invalidate_block(block2.hash());

    let post_invalidated_chain = state.best_chain().unwrap();

    assert_eq!(post_invalidated_chain.blocks.len(), 1);
    assert!(
        post_invalidated_chain.contains_block_hash(block1.hash()),
        "the new modified chain should contain block1"
    );

    assert!(
        !post_invalidated_chain.contains_block_hash(block2.hash()),
        "the new modified chain should not contain block2"
    );
    assert!(
        !post_invalidated_chain.contains_block_hash(block3.hash()),
        "the new modified chain should not contain block3"
    );

    let invalidated_blocks_state = &state.invalidated_blocks;

    // Find an entry in the IndexMap that contains block2 hash
    let (_, invalidated_blocks_state_descendants) = invalidated_blocks_state
        .iter()
        .find_map(|(height, blocks)| {
            assert!(
                blocks.iter().any(|block| block.hash == block2.hash()),
                "invalidated_blocks should reference the hash of block2"
            );

            if blocks.iter().any(|block| block.hash == block2.hash()) {
                Some((height, blocks))
            } else {
                None
            }
        })
        .unwrap();

    match network {
        Network::Mainnet => assert!(
            invalidated_blocks_state_descendants
                .iter()
                .any(|block| block.height == block::Height(653601)),
            "invalidated descendants should contain block3"
        ),
        Network::Testnet(_parameters) => assert!(
            invalidated_blocks_state_descendants
                .iter()
                .any(|block| block.height == block::Height(584001)),
            "invalidated descendants should contain block3"
        ),
    }

    Ok(())
}

/// Regression test for https://github.com/ZcashFoundation/zebra/issues/10586.
///
/// Build an empty `NonFinalizedState` and an ephemeral `FinalizedState` with a
/// populated value pool — the shared setup for the invalidate/reconsider
/// regression tests below.
fn new_invalidate_test_state(network: &Network) -> (NonFinalizedState, FinalizedState) {
    let state = NonFinalizedState::new(network);
    let finalized_state = FinalizedState::new(&Config::ephemeral(), network)
        .expect("opening an ephemeral finalized state succeeds");
    finalized_state.set_finalized_value_pool(ValueBalance::<NonNegative>::fake_populated_pool());
    (state, finalized_state)
}

/// Invalidating the non-finalized root of a tracked chain previously called
/// `BTreeSet::remove(&chain)`, which compared the stored chain against
/// itself via `Chain::cmp` and reached an `unreachable!()` for matching tip
/// hashes. The root branch now retains chains that do not contain the root
/// hash, so the call returns successfully without panicking.
#[test]
fn invalidating_non_finalized_root_does_not_panic() {
    let _init_guard = zakura_test::init();

    let network = Network::Mainnet;
    let block1: Arc<Block> = Arc::new(network.test_block(653599, 583999).unwrap());
    let block2 = block1.make_fake_child().set_work(10);

    let (mut state, finalized_state) = new_invalidate_test_state(&network);

    state
        .commit_new_chain(block1.clone().prepare(), &finalized_state)
        .expect("fake root block should commit to an empty non-finalized state");
    state
        .commit_block(block2.prepare(), &finalized_state)
        .expect("fake child block should extend the fake root chain");

    state
        .invalidate_block(block1.hash())
        .expect("invalidating the chain root should not panic");

    assert!(
        state.best_chain().is_none(),
        "invalidating the root should leave no live non-finalized chain"
    );
}

/// A non-finalized root can be shared by multiple sibling forks. Invalidating
/// that root must remove every live fork containing it, not only the best fork
/// selected to populate the invalidation record.
#[test]
fn invalidating_shared_non_finalized_root_removes_all_forks() {
    let _init_guard = zakura_test::init();

    let network = Network::Mainnet;
    let block1: Arc<Block> = Arc::new(network.test_block(653599, 583999).unwrap());
    let block2a = block1.make_fake_child().set_work(10);
    let block2b = block1.make_fake_child().set_work(11);

    let (mut state, finalized_state) = new_invalidate_test_state(&network);

    state
        .commit_new_chain(block1.clone().prepare(), &finalized_state)
        .expect("fake root block should commit to an empty non-finalized state");
    state
        .commit_block(block2a.clone().prepare(), &finalized_state)
        .expect("first fork tip should extend the root chain");
    state
        .commit_block(block2b.clone().prepare(), &finalized_state)
        .expect("second fork tip should fork from the root chain");

    state
        .invalidate_block(block1.hash())
        .expect("invalidating a shared root should remove every descendant fork");

    assert!(
        state.best_chain().is_none(),
        "invalidating a shared root should leave no live non-finalized chain"
    );
    assert!(!state.any_chain_contains(&block1.hash()));
    assert!(!state.any_chain_contains(&block2a.hash()));
    assert!(!state.any_chain_contains(&block2b.hash()));
}

/// Regression test for https://github.com/ZcashFoundation/zebra/issues/10586.
///
/// Sequentially invalidating two same-height sibling fork tips with the same
/// parent previously panicked. The second invalidation produced a shortened
/// parent chain whose tip hash matched an existing entry, and `BTreeSet::insert`
/// reached `Chain::cmp`'s `unreachable!()`. After the fix, `Chain::cmp` returns
/// `Equal` for matching tip hashes, so the duplicate insert is a no-op and the
/// pre-existing parent chain is retained.
#[test]
fn invalidating_same_height_fork_tips_is_idempotent() {
    let _init_guard = zakura_test::init();

    let network = Network::Mainnet;
    let block1: Arc<Block> = Arc::new(network.test_block(653599, 583999).unwrap());
    let block2a = block1.make_fake_child().set_work(10);
    let block2b = block1.make_fake_child().set_work(11);

    let (mut state, finalized_state) = new_invalidate_test_state(&network);

    state
        .commit_new_chain(block1.clone().prepare(), &finalized_state)
        .expect("fake root block should commit to an empty non-finalized state");
    state
        .commit_block(block2a.clone().prepare(), &finalized_state)
        .expect("first fork tip should extend the root chain");
    state
        .commit_block(block2b.clone().prepare(), &finalized_state)
        .expect("second fork tip should fork from the root chain");

    state
        .invalidate_block(block2a.hash())
        .expect("first fork tip should invalidate cleanly");
    state
        .invalidate_block(block2b.hash())
        .expect("second sibling fork tip should not panic on collapse to shared parent");

    let best_chain = state
        .best_chain()
        .expect("the parent chain should remain after both sibling tips are invalidated");
    assert!(best_chain.contains_block_hash(block1.hash()));
    assert!(!best_chain.contains_block_hash(block2a.hash()));
    assert!(!best_chain.contains_block_hash(block2b.hash()));
}

/// Regression test for https://github.com/ZcashFoundation/zebra/issues/10586.
///
/// `reconsider_block` previously removed the invalidation record from a clone
/// of `invalidated_blocks` rather than from the live map. A second
/// `reconsider_block` for the same hash then replayed the same chain suffix
/// into a chain set that already contained the restored tip, panicking in
/// `Chain::cmp`'s duplicate-tip check. After the fix, the live entry is
/// removed and the second call returns `MissingInvalidatedBlock`.
#[test]
fn reconsider_block_removes_live_entry_and_second_call_returns_missing() {
    let _init_guard = zakura_test::init();

    let network = Network::Mainnet;
    let block1: Arc<Block> = Arc::new(network.test_block(653599, 583999).unwrap());
    let block2 = block1.make_fake_child().set_work(10);
    let block3 = block2.make_fake_child().set_work(1);

    let (mut state, finalized_state) = new_invalidate_test_state(&network);

    state
        .commit_new_chain(block1.prepare(), &finalized_state)
        .expect("fake root block should commit");
    state
        .commit_block(block2.clone().prepare(), &finalized_state)
        .expect("fake child should extend the root chain");
    state
        .commit_block(block3.prepare(), &finalized_state)
        .expect("fake grandchild should extend the child chain");

    state
        .invalidate_block(block2.hash())
        .expect("invalidating the child should succeed");

    state
        .reconsider_block(block2.hash(), &finalized_state.db)
        .expect("first reconsider should restore the invalidated chain");

    assert!(
        state.invalidated_blocks().values().all(|blocks| {
            blocks
                .first()
                .map(|block| block.hash != block2.hash())
                .unwrap_or(true)
        }),
        "first reconsider should remove the invalidated entry from the live map"
    );

    let second = state.reconsider_block(block2.hash(), &finalized_state.db);
    assert!(
        matches!(second, Err(ReconsiderError::MissingInvalidatedBlock(_))),
        "a second reconsider for the same hash should return MissingInvalidatedBlock; got {second:?}"
    );
}

/// Regression test for https://github.com/ZcashFoundation/zebra/issues/10586.
///
/// `reconsider_block` must not destroy the invalidation record when a fallible
/// step fails. We invalidate child `B` (which has a grandchild), then invalidate
/// its parent/root `A`. Calling `reconsider_block(B)` now must fail with
/// `ParentChainNotFound` (because `A` is no longer in the non-finalized state)
/// without removing `B`'s record. A subsequent `reconsider_block(A)` must
/// restore `A`, after which the original `B` record remains available for a
/// later reconsider.
#[test]
fn reconsider_block_preserves_record_when_parent_chain_missing() {
    let _init_guard = zakura_test::init();

    let network = Network::Mainnet;
    let block1: Arc<Block> = Arc::new(network.test_block(653599, 583999).unwrap());
    let block2 = block1.make_fake_child().set_work(10);
    let block3 = block2.make_fake_child().set_work(1);

    let (mut state, finalized_state) = new_invalidate_test_state(&network);

    state
        .commit_new_chain(block1.clone().prepare(), &finalized_state)
        .expect("fake root should commit");
    state
        .commit_block(block2.clone().prepare(), &finalized_state)
        .expect("fake child should extend the root chain");
    state
        .commit_block(block3.prepare(), &finalized_state)
        .expect("fake grandchild should extend the child chain");

    state
        .invalidate_block(block2.hash())
        .expect("invalidating the child should succeed");
    state
        .invalidate_block(block1.hash())
        .expect("invalidating the root should not panic and should succeed");

    // Now block2's parent (block1) is no longer in the non-finalized state, so
    // reconsidering block2 must fail. The record for block2 must survive the
    // failure so a later reconsider can still restore it.
    let result = state.reconsider_block(block2.hash(), &finalized_state.db);
    assert!(
        matches!(result, Err(ReconsiderError::ParentChainNotFound(_))),
        "reconsider with missing parent chain should fail, got {result:?}"
    );

    assert!(
        state.invalidated_blocks().values().any(|blocks| {
            blocks
                .first()
                .map(|block| block.hash == block2.hash())
                .unwrap_or(false)
        }),
        "a failed reconsider must not destroy the invalidation record"
    );
}

#[test]
// kogany: Zcash Mainnet and Testnet block vectors (NU5 branch IDs, Zcash Heartwood and NU5
// heights); not run on Ycash.
#[cfg(not(feature = "ycash"))]
fn invalidate_root_block_removes_entire_chain() -> Result<()> {
    let _init_guard = zakura_test::init();

    for network in Network::iter() {
        invalidate_root_block_removes_entire_chain_for_network(network)?;
    }

    Ok(())
}

fn invalidate_root_block_removes_entire_chain_for_network(network: Network) -> Result<()> {
    let block1: Arc<Block> = Arc::new(network.test_block(653599, 583999).unwrap());
    let block2 = block1.make_fake_child().set_work(10);
    let block3 = block2.make_fake_child().set_work(1);

    let mut state = NonFinalizedState::new(&network);
    let finalized_state = FinalizedState::new(&Config::ephemeral(), &network)
        .expect("opening an ephemeral database should succeed");

    let fake_value_pool = ValueBalance::<NonNegative>::fake_populated_pool();
    finalized_state.set_finalized_value_pool(fake_value_pool);

    state.commit_new_chain(block1.clone().prepare(), &finalized_state)?;
    state.commit_block(block2.clone().prepare(), &finalized_state)?;
    state.commit_block(block3.clone().prepare(), &finalized_state)?;

    state.invalidate_block(block1.hash())?;

    assert!(
        state.best_chain().is_none(),
        "invalidating the non-finalized root should remove the whole chain"
    );

    let invalidated_blocks = state
        .invalidated_blocks
        .get(&block1.hash())
        .expect("invalidated root block should be tracked");

    assert!(
        invalidated_blocks
            .iter()
            .any(|block| block.hash == block1.hash()),
        "invalidated blocks should contain block1"
    );
    assert!(
        invalidated_blocks
            .iter()
            .any(|block| block.hash == block2.hash()),
        "invalidated blocks should contain block2"
    );
    assert!(
        invalidated_blocks
            .iter()
            .any(|block| block.hash == block3.hash()),
        "invalidated blocks should contain block3"
    );

    Ok(())
}

#[test]
// kogany: Zcash Mainnet and Testnet block vectors (NU5 branch IDs, Zcash Heartwood and NU5
// heights); not run on Ycash.
#[cfg(not(feature = "ycash"))]
fn reconsider_block_and_reconsider_chain_correctly_reconsiders_blocks_and_descendants() -> Result<()>
{
    let _init_guard = zakura_test::init();

    for network in Network::iter() {
        reconsider_block_inserts_block_and_descendants_into_chain_for_network(network.clone())?;
    }

    Ok(())
}

fn reconsider_block_inserts_block_and_descendants_into_chain_for_network(
    network: Network,
) -> Result<()> {
    let block1: Arc<Block> = Arc::new(network.test_block(653599, 583999).unwrap());
    let block2 = block1.make_fake_child().set_work(10);
    let block3 = block2.make_fake_child().set_work(1);

    let mut state = NonFinalizedState::new(&network);
    let finalized_state = FinalizedState::new(&Config::ephemeral(), &network)
        .expect("opening an ephemeral database should succeed");

    let fake_value_pool = ValueBalance::<NonNegative>::fake_populated_pool();
    finalized_state.set_finalized_value_pool(fake_value_pool);

    state.commit_new_chain(block1.clone().prepare(), &finalized_state)?;
    state.commit_block(block2.clone().prepare(), &finalized_state)?;
    state.commit_block(block3.clone().prepare(), &finalized_state)?;

    assert_eq!(
        state
            .best_chain()
            .unwrap_or(&Arc::new(Chain::default()))
            .blocks
            .len(),
        3
    );

    // Invalidate block2 to update the invalidated_blocks NonFinalizedState
    let _ = state.invalidate_block(block2.hash());

    // Perform checks to ensure the invalidated_block and descendants were added to the invalidated_block
    // state
    let post_invalidated_chain = state.best_chain().unwrap();

    assert_eq!(post_invalidated_chain.blocks.len(), 1);
    assert!(
        post_invalidated_chain.contains_block_hash(block1.hash()),
        "the new modified chain should contain block1"
    );

    assert!(
        !post_invalidated_chain.contains_block_hash(block2.hash()),
        "the new modified chain should not contain block2"
    );
    assert!(
        !post_invalidated_chain.contains_block_hash(block3.hash()),
        "the new modified chain should not contain block3"
    );

    // Reconsider block2 and check that both block2 and block3 were `reconsidered` into the
    // best chain
    state.reconsider_block(block2.hash(), &finalized_state.db)?;

    let best_chain = state.best_chain().unwrap();

    assert!(
        best_chain.contains_block_hash(block2.hash()),
        "the best chain should again contain block2"
    );
    assert!(
        best_chain.contains_block_hash(block3.hash()),
        "the best chain should again contain block3"
    );

    let result = state.reconsider_block(block2.hash(), &finalized_state.db);

    assert!(
        matches!(
            result,
            Err(ReconsiderError::MissingInvalidatedBlock(hash)) if hash == block2.hash()
        ),
        "reconsidering the same block twice should fail without changing the chain"
    );

    Ok(())
}

#[test]
// kogany: Zcash Mainnet and Testnet block vectors (NU5 branch IDs, Zcash Heartwood and NU5
// heights); not run on Ycash.
#[cfg(not(feature = "ycash"))]
// This test gives full coverage for `take_chain_if`
fn commit_block_extending_best_chain_doesnt_drop_worst_chains() -> Result<()> {
    let _init_guard = zakura_test::init();

    for network in Network::iter() {
        commit_block_extending_best_chain_doesnt_drop_worst_chains_for_network(network)?;
    }

    Ok(())
}

fn commit_block_extending_best_chain_doesnt_drop_worst_chains_for_network(
    network: Network,
) -> Result<()> {
    // Since the brand new FinalizedState below will pass a None history tree
    // to the NonFinalizedState, we must use pre-Heartwood blocks since
    // they won't trigger the history tree update in the NonFinalizedState.
    let block1: Arc<Block> = Arc::new(network.test_block(653599, 583999).unwrap());

    let block2 = block1.make_fake_child().set_work(10);
    let child1 = block1.make_fake_child().set_work(1);
    let child2 = block2.make_fake_child().set_work(1);

    let mut state = NonFinalizedState::new(&network);
    let finalized_state = FinalizedState::new(&Config::ephemeral(), &network)
        .expect("opening an ephemeral database should succeed");

    let fake_value_pool = ValueBalance::<NonNegative>::fake_populated_pool();
    finalized_state.set_finalized_value_pool(fake_value_pool);

    assert_eq!(0, state.chain_set.len());
    state.commit_new_chain(block1.prepare(), &finalized_state)?;
    assert_eq!(1, state.chain_set.len());
    state.commit_block(block2.prepare(), &finalized_state)?;
    assert_eq!(1, state.chain_set.len());
    state.commit_block(child1.prepare(), &finalized_state)?;
    assert_eq!(2, state.chain_set.len());
    state.commit_block(child2.prepare(), &finalized_state)?;
    assert_eq!(2, state.chain_set.len());

    Ok(())
}

#[test]
// kogany: Zcash Mainnet and Testnet block vectors (NU5 branch IDs, Zcash Heartwood and NU5
// heights); not run on Ycash.
#[cfg(not(feature = "ycash"))]
fn shorter_chain_can_be_best_chain() -> Result<()> {
    let _init_guard = zakura_test::init();
    for network in Network::iter() {
        shorter_chain_can_be_best_chain_for_network(network)?;
    }
    Ok(())
}

fn shorter_chain_can_be_best_chain_for_network(network: Network) -> Result<()> {
    // Since the brand new FinalizedState below will pass a None history tree
    // to the NonFinalizedState, we must use pre-Heartwood blocks since
    // they won't trigger the history tree update in the NonFinalizedState.
    let block1: Arc<Block> = Arc::new(network.test_block(653599, 583999).unwrap());

    let long_chain_block1 = block1.make_fake_child().set_work(1);
    let long_chain_block2 = long_chain_block1.make_fake_child().set_work(1);

    let short_chain_block = block1.make_fake_child().set_work(3);

    let mut state = NonFinalizedState::new(&network);
    let finalized_state = FinalizedState::new(&Config::ephemeral(), &network)
        .expect("opening an ephemeral database should succeed");

    let fake_value_pool = ValueBalance::<NonNegative>::fake_populated_pool();
    finalized_state.set_finalized_value_pool(fake_value_pool);

    state.commit_new_chain(block1.prepare(), &finalized_state)?;
    state.commit_block(long_chain_block1.prepare(), &finalized_state)?;
    state.commit_block(long_chain_block2.prepare(), &finalized_state)?;
    state.commit_block(short_chain_block.prepare(), &finalized_state)?;
    assert_eq!(2, state.chain_set.len());

    assert_eq!(Some(2), state.best_chain_len());

    Ok(())
}

#[test]
// kogany: Zcash Mainnet and Testnet block vectors (NU5 branch IDs, Zcash Heartwood and NU5
// heights); not run on Ycash.
#[cfg(not(feature = "ycash"))]
fn longer_chain_with_more_work_wins() -> Result<()> {
    let _init_guard = zakura_test::init();
    for network in Network::iter() {
        longer_chain_with_more_work_wins_for_network(network)?;
    }

    Ok(())
}

fn longer_chain_with_more_work_wins_for_network(network: Network) -> Result<()> {
    // Since the brand new FinalizedState below will pass a None history tree
    // to the NonFinalizedState, we must use pre-Heartwood blocks since
    // they won't trigger the history tree update in the NonFinalizedState.
    let block1: Arc<Block> = Arc::new(network.test_block(653599, 583999).unwrap());

    let long_chain_block1 = block1.make_fake_child().set_work(1);
    let long_chain_block2 = long_chain_block1.make_fake_child().set_work(1);
    let long_chain_block3 = long_chain_block2.make_fake_child().set_work(1);
    let long_chain_block4 = long_chain_block3.make_fake_child().set_work(1);

    let short_chain_block = block1.make_fake_child().set_work(3);

    let mut state = NonFinalizedState::new(&network);
    let finalized_state = FinalizedState::new(&Config::ephemeral(), &network)
        .expect("opening an ephemeral database should succeed");

    let fake_value_pool = ValueBalance::<NonNegative>::fake_populated_pool();
    finalized_state.set_finalized_value_pool(fake_value_pool);

    state.commit_new_chain(block1.prepare(), &finalized_state)?;
    state.commit_block(long_chain_block1.prepare(), &finalized_state)?;
    state.commit_block(long_chain_block2.prepare(), &finalized_state)?;
    state.commit_block(long_chain_block3.prepare(), &finalized_state)?;
    state.commit_block(long_chain_block4.prepare(), &finalized_state)?;
    state.commit_block(short_chain_block.prepare(), &finalized_state)?;
    assert_eq!(2, state.chain_set.len());

    assert_eq!(Some(5), state.best_chain_len());

    Ok(())
}

#[test]
// kogany: Zcash Mainnet and Testnet block vectors (NU5 branch IDs, Zcash Heartwood and NU5
// heights); not run on Ycash.
#[cfg(not(feature = "ycash"))]
fn equal_length_goes_to_more_work() -> Result<()> {
    let _init_guard = zakura_test::init();

    for network in Network::iter() {
        equal_length_goes_to_more_work_for_network(network)?;
    }

    Ok(())
}
fn equal_length_goes_to_more_work_for_network(network: Network) -> Result<()> {
    // Since the brand new FinalizedState below will pass a None history tree
    // to the NonFinalizedState, we must use pre-Heartwood blocks since
    // they won't trigger the history tree update in the NonFinalizedState.
    let block1: Arc<Block> = Arc::new(network.test_block(653599, 583999).unwrap());

    let less_work_child = block1.make_fake_child().set_work(1);
    let more_work_child = block1.make_fake_child().set_work(3);
    let expected_hash = more_work_child.hash();

    let mut state = NonFinalizedState::new(&network);
    let finalized_state = FinalizedState::new(&Config::ephemeral(), &network)
        .expect("opening an ephemeral database should succeed");

    let fake_value_pool = ValueBalance::<NonNegative>::fake_populated_pool();
    finalized_state.set_finalized_value_pool(fake_value_pool);

    state.commit_new_chain(block1.prepare(), &finalized_state)?;
    state.commit_block(less_work_child.prepare(), &finalized_state)?;
    state.commit_block(more_work_child.prepare(), &finalized_state)?;
    assert_eq!(2, state.chain_set.len());

    let tip_hash = state.best_tip().unwrap().1;
    assert_eq!(expected_hash, tip_hash);

    Ok(())
}

#[test]
// kogany: Zcash Mainnet and Testnet block vectors (NU5 branch IDs, Zcash Heartwood and NU5
// heights); not run on Ycash.
#[cfg(not(feature = "ycash"))]
fn history_tree_is_updated() -> Result<()> {
    for network in Network::iter() {
        history_tree_is_updated_for_network_upgrade(network, NetworkUpgrade::Heartwood)?;
    }
    // TODO: we can't test other upgrades until we have a method for creating a FinalizedState
    // with a HistoryTree.
    Ok(())
}

fn history_tree_is_updated_for_network_upgrade(
    network: Network,
    network_upgrade: NetworkUpgrade,
) -> Result<()> {
    let blocks = network.block_map();

    let height = network_upgrade.activation_height(&network).unwrap().0;

    let prev_block = Arc::new(
        blocks
            .get(&(height - 1))
            .expect("test vector exists")
            .zcash_deserialize_into::<Block>()
            .expect("block is structurally valid"),
    );

    let mut state = NonFinalizedState::new(&network);
    let finalized_state = FinalizedState::new(&Config::ephemeral(), &network)
        .expect("opening an ephemeral database should succeed");

    state
        .commit_new_chain(prev_block.clone().prepare(), &finalized_state)
        .unwrap();

    let chain = state.best_chain().unwrap();
    if network_upgrade == NetworkUpgrade::Heartwood {
        assert!(
            chain.history_block_commitment_tree().as_ref().is_none(),
            "history tree must not exist yet"
        );
    } else {
        assert!(
            chain.history_block_commitment_tree().as_ref().is_some(),
            "history tree must already exist"
        );
    }

    // The Heartwood activation block has an all-zero commitment
    let activation_block = prev_block.make_fake_child().set_block_commitment([0u8; 32]);

    state
        .commit_block(activation_block.clone().prepare(), &finalized_state)
        .unwrap();

    let chain = state.best_chain().unwrap();
    assert!(
        chain.history_block_commitment_tree().as_ref().is_some(),
        "history tree must have been (re)created"
    );
    assert_eq!(
        chain
            .history_block_commitment_tree()
            .as_ref()
            .as_ref()
            .unwrap()
            .size(),
        1,
        "history tree must have a single node"
    );

    // To fix the commitment in the next block we must recreate the history tree
    let tree = NonEmptyHistoryTree::from_block(
        &Network::Mainnet,
        activation_block.clone(),
        &chain.sapling_note_commitment_tree_for_tip().root(),
        &chain.orchard_note_commitment_tree_for_tip().root(),
        &chain.ironwood_note_commitment_tree_for_tip().root(),
    )
    .unwrap();

    let next_block = activation_block
        .make_fake_child()
        .set_block_commitment(tree.hash().into());

    state
        .commit_block(next_block.prepare(), &finalized_state)
        .unwrap();

    assert!(
        state
            .best_chain()
            .unwrap()
            .history_block_commitment_tree()
            .as_ref()
            .is_some(),
        "history tree must still exist"
    );

    Ok(())
}

#[test]
// kogany: Zcash Mainnet and Testnet block vectors (NU5 branch IDs, Zcash Heartwood and NU5
// heights); not run on Ycash.
#[cfg(not(feature = "ycash"))]
fn commitment_is_validated() {
    for network in Network::iter() {
        commitment_is_validated_for_network_upgrade(network, NetworkUpgrade::Heartwood);
    }
    // TODO: we can't test other upgrades until we have a method for creating a FinalizedState
    // with a HistoryTree.
}

fn commitment_is_validated_for_network_upgrade(network: Network, network_upgrade: NetworkUpgrade) {
    let blocks = network.block_map();
    let height = network_upgrade.activation_height(&network).unwrap().0;

    let prev_block = Arc::new(
        blocks
            .get(&(height - 1))
            .expect("test vector exists")
            .zcash_deserialize_into::<Block>()
            .expect("block is structurally valid"),
    );

    let mut state = NonFinalizedState::new(&network);
    let finalized_state = FinalizedState::new(&Config::ephemeral(), &network)
        .expect("opening an ephemeral database should succeed");

    state
        .commit_new_chain(prev_block.clone().prepare(), &finalized_state)
        .unwrap();

    // The Heartwood activation block must have an all-zero commitment.
    // Test error return when committing the block with the wrong commitment
    let activation_block = prev_block.make_fake_child();
    let err = state
        .commit_block(activation_block.clone().prepare(), &finalized_state)
        .unwrap_err();
    match err {
        crate::ValidateContextError::InvalidBlockCommitment(
            zakura_chain::block::CommitmentError::InvalidChainHistoryActivationReserved { .. },
        ) => {},
        _ => panic!("Error must be InvalidBlockCommitment::InvalidChainHistoryActivationReserved instead of {err:?}"),
    };

    // Test committing the Heartwood activation block with the correct commitment
    let activation_block = activation_block.set_block_commitment([0u8; 32]);
    state
        .commit_block(activation_block.clone().prepare(), &finalized_state)
        .unwrap();

    // To fix the commitment in the next block we must recreate the history tree
    let chain = state.best_chain().unwrap();
    let tree = NonEmptyHistoryTree::from_block(
        &Network::Mainnet,
        activation_block.clone(),
        &chain.sapling_note_commitment_tree_for_tip().root(),
        &chain.orchard_note_commitment_tree_for_tip().root(),
        &chain.ironwood_note_commitment_tree_for_tip().root(),
    )
    .unwrap();

    // Test committing the next block with the wrong commitment
    let next_block = activation_block.make_fake_child();
    let err = state
        .commit_block(next_block.clone().prepare(), &finalized_state)
        .unwrap_err();
    match err {
        crate::ValidateContextError::InvalidBlockCommitment(
            zakura_chain::block::CommitmentError::InvalidChainHistoryRoot { .. },
        ) => {}
        _ => panic!(
            "Error must be InvalidBlockCommitment::InvalidChainHistoryRoot instead of {err:?}"
        ),
    };

    // Test committing the next block with the correct commitment
    let next_block = next_block.set_block_commitment(tree.hash().into());
    state
        .commit_block(next_block.prepare(), &finalized_state)
        .unwrap();
}

#[tokio::test]
// kogany: Zcash Mainnet and Testnet block vectors (NU5 branch IDs, Zcash Heartwood and NU5
// heights); not run on Ycash.
#[cfg(not(feature = "ycash"))]
async fn non_finalized_state_writes_blocks_to_and_restores_blocks_from_backup_cache() {
    let network = Network::Mainnet;

    let finalized_state = FinalizedState::new(&Config::ephemeral(), &network)
        .expect("opening an ephemeral database should succeed");

    let backup_dir_path = tempfile::Builder::new()
        .prefix("zebra-non-finalized-state-backup-cache")
        .tempdir()
        .expect("temporary directory is created successfully")
        .keep();

    let (mut non_finalized_state, non_finalized_state_sender, _receiver) =
        NonFinalizedState::new(&network)
            .with_backup(
                Some(backup_dir_path.clone()),
                &finalized_state.db,
                false,
                false,
            )
            .await;

    let blocks = network.block_map();
    let height = NetworkUpgrade::Heartwood
        .activation_height(&network)
        .unwrap()
        .0;
    let block = Arc::new(
        blocks
            .get(&(height - 1))
            .expect("test vector exists")
            .zcash_deserialize_into::<Block>()
            .expect("block is structurally valid"),
    );

    non_finalized_state
        .commit_new_chain(block.into(), &finalized_state.db)
        .expect("committing test block should succeed");

    non_finalized_state_sender
        .send(non_finalized_state.clone())
        .expect("backup task should have a receiver, channel should be open");

    // Wait for the minimum update time
    tokio::time::sleep(Duration::from_secs(1) + MIN_DURATION_BETWEEN_BACKUP_UPDATES).await;

    let (non_finalized_state, _sender, _receiver) = NonFinalizedState::new(&network)
        .with_backup(Some(backup_dir_path), &finalized_state.db, true, false)
        .await;

    assert_eq!(
        non_finalized_state.best_chain_len(),
        Some(1),
        "non-finalized state should have restored the block committed \
        to the previous non-finalized state"
    );
}

/// Regression test for
/// [GHSA-2gf8-q9rr-jq3h](https://github.com/ZcashFoundation/zebra/security/advisories/GHSA-2gf8-q9rr-jq3h).
///
/// `Chain::pop_tip` used to leave entries in `sapling_subtrees`, `orchard_subtrees`,
/// and `ironwood_subtrees`, so a chain forked below a subtree boundary inherited stale subtrees from the
/// abandoned branch. Forking should drop any subtree whose `end_height` is above the
/// new tip.
#[test]
fn fork_drops_subtrees_above_fork_point() -> Result<()> {
    let _init_guard = zakura_test::init();

    let network = Network::Mainnet;
    let block1: Arc<Block> = Arc::new(network.test_block(653599, 583999).unwrap());
    let block2 = block1.make_fake_child().set_work(10);
    let block3 = block2.make_fake_child().set_work(1);

    let mut chain = Chain::new(
        &network,
        (block1.coinbase_height().unwrap() - 1).unwrap(),
        Default::default(),
        Default::default(),
        Default::default(),
        Default::default(),
        Default::default(),
        ValueBalance::fake_populated_pool(),
    );
    chain = chain.push(block1.clone().prepare().test_with_zero_spent_utxos())?;
    chain = chain.push(block2.clone().prepare().test_with_zero_spent_utxos())?;
    chain = chain.push(block3.clone().prepare().test_with_zero_spent_utxos())?;

    // Inject Sapling, Orchard, and Ironwood subtrees whose `end_height` is the chain's tip.
    // The block-push pipeline above doesn't complete subtrees on its own for these
    // fixture blocks, so we install them directly via the test-only helpers.
    let tip_height = block3.coinbase_height().unwrap();
    let sapling_node = sapling_crypto::Node::from_bytes([0; 32]).unwrap();
    chain.insert_sapling_subtree(NoteCommitmentSubtree::new(0u16, tip_height, sapling_node));
    let orchard_node = orchard::tree::Node::default();
    chain.insert_orchard_subtree(NoteCommitmentSubtree::new(0u16, tip_height, orchard_node));
    let ironwood_node = ironwood::tree::Node::default();
    chain.insert_ironwood_subtree(NoteCommitmentSubtree::new(0u16, tip_height, ironwood_node));

    assert_eq!(chain.sapling_subtrees.len(), 1);
    assert_eq!(chain.orchard_subtrees.len(), 1);
    assert_eq!(chain.ironwood_subtrees.len(), 1);

    // Fork at `block1`, so `pop_tip` runs twice (for block3 then block2). The
    // subtree at block3's height must be removed; without the fix, it would survive
    // into the forked chain.
    let forked = chain.fork(block1.hash()).expect("block1 is in the chain");

    assert_eq!(forked.non_finalized_tip_hash(), block1.hash());
    assert!(
        forked.sapling_subtrees.is_empty(),
        "fork should have dropped the Sapling subtree completed above the fork point"
    );
    assert!(
        forked.orchard_subtrees.is_empty(),
        "fork should have dropped the Orchard subtree completed above the fork point"
    );
    assert!(
        forked.ironwood_subtrees.is_empty(),
        "fork should have dropped the Ironwood subtree completed above the fork point"
    );

    Ok(())
}

/// Commits `root` and two equal-work children, returning the state, the finalized state, and
/// the children ordered as `(hash_loser, hash_winner)`.
fn precious_test_state(
    network: &Network,
) -> (NonFinalizedState, FinalizedState, Arc<Block>, Arc<Block>) {
    let root = Arc::new(network.test_block(653599, 583999).unwrap());
    let a = root
        .make_fake_child()
        .set_work(10)
        .set_block_commitment([1; 32]);
    let b = root
        .make_fake_child()
        .set_work(10)
        .set_block_commitment([2; 32]);
    let (mut state, finalized) = new_invalidate_test_state(network);
    state
        .commit_new_chain(root.prepare(), &finalized.db)
        .unwrap();
    for block in [&a, &b] {
        state
            .commit_block(block.clone().prepare(), &finalized.db)
            .unwrap();
    }
    let (low, high) = if a.hash().0 < b.hash().0 {
        (a, b)
    } else {
        (b, a)
    };
    assert_eq!(state.best_tip().unwrap().1, high.hash());
    (state, finalized, low, high)
}

/// Commits `block` to `state`.
fn commit_test_block(
    state: &mut NonFinalizedState,
    finalized: &FinalizedState,
    block: &Arc<Block>,
) {
    state
        .commit_block(block.clone().prepare(), &finalized.db)
        .unwrap();
}

/// A precious tip beats the hash tie-break, and a later call wins.
#[test]
// kogany: Zcash Mainnet and Testnet block vectors (NU5 branch IDs, Zcash Heartwood and NU5
// heights); not run on Ycash.
#[cfg(not(feature = "ycash"))]
fn precious_block_overrides_hash_order_and_later_calls_win() {
    let _init_guard = zakura_test::init();
    for network in Network::iter() {
        let (mut state, finalized, low, high) = precious_test_state(&network);

        state.precious_block(low.hash(), &finalized.db).unwrap();
        assert_eq!(state.best_tip().unwrap().1, low.hash());
        assert_eq!(state.chain_count(), 2);

        state.precious_block(high.hash(), &finalized.db).unwrap();
        assert_eq!(state.best_tip().unwrap().1, high.hash());

        // Repeating a call on the best tip keeps it best.
        state.precious_block(high.hash(), &finalized.db).unwrap();
        assert_eq!(state.best_tip().unwrap().1, high.hash());
    }
}

/// Greater work still wins, and only unknown hashes are errors, not lower-work or invalidated blocks.
#[test]
fn precious_block_ignores_known_blocks_and_rejects_unknown_hashes() {
    let _init_guard = zakura_test::init();
    let network = Network::Mainnet;
    let (mut state, finalized, low, high) = precious_test_state(&network);
    let child = low.make_fake_child().set_work(1);
    commit_test_block(&mut state, &finalized, &child);
    assert_eq!(state.best_tip().unwrap().1, child.hash());

    // A lower-work tip and a block below the best tip leave the state unchanged.
    for hash in [high.hash(), low.hash()] {
        let before = state.clone();
        state.precious_block(hash, &finalized.db).unwrap();
        assert!(state.eq_internal_state(&before));
        assert_eq!(state.best_tip().unwrap().1, child.hash());
    }

    // An invalidated block is known, so the request succeeds without changing the state.
    state.invalidate_block(high.hash()).unwrap();
    let before = state.clone();
    state.precious_block(high.hash(), &finalized.db).unwrap();
    assert!(state.eq_internal_state(&before));
    assert_eq!(state.best_tip().unwrap().1, child.hash());

    let unknown = high.make_fake_child().set_work(1).hash();
    assert!(matches!(
        state.precious_block(unknown, &finalized.db),
        Err(PreciousError::BlockNotFound(hash)) if hash == unknown
    ));
    assert_eq!(state.best_tip().unwrap().1, child.hash());
}

/// The preference applies to the precious tip only: later equal-work tips do not displace it,
/// descendants do not inherit it, and reverting to the tip restores it.
#[test]
fn precious_block_follows_the_preferred_tip() {
    let _init_guard = zakura_test::init();
    let network = Network::Mainnet;
    let (mut state, finalized, low, high) = precious_test_state(&network);
    state.precious_block(low.hash(), &finalized.db).unwrap();
    assert_eq!(state.best_tip().unwrap().1, low.hash());

    // Equal-work siblings arriving later do not displace the precious tip, whatever their hash.
    let root_hash = low.header.previous_block_hash;
    let root = state
        .best_chain()
        .unwrap()
        .block(root_hash.into())
        .unwrap()
        .block
        .clone();
    for commitment in [3, 4, 5] {
        let sibling = root
            .make_fake_child()
            .set_work(10)
            .set_block_commitment([commitment; 32]);
        commit_test_block(&mut state, &finalized, &sibling);
        assert_eq!(state.best_tip().unwrap().1, low.hash());
    }

    // Children with equal work fall back to the hash tie-break.
    let low_child = low.make_fake_child().set_work(1);
    let high_child = high.make_fake_child().set_work(1);
    commit_test_block(&mut state, &finalized, &low_child);
    assert_eq!(state.best_tip().unwrap().1, low_child.hash());
    commit_test_block(&mut state, &finalized, &high_child);
    let hash_winner = std::cmp::max_by_key(low_child.hash(), high_child.hash(), |hash| hash.0);
    assert_eq!(state.best_tip().unwrap().1, hash_winner);

    // Reverting both children restores the precious tip.
    state.invalidate_block(low_child.hash()).unwrap();
    state.invalidate_block(high_child.hash()).unwrap();
    assert_eq!(state.best_tip().unwrap().1, low.hash());
}

/// Preferences are independent between clones.
#[test]
fn precious_block_changes_only_the_cloned_state() {
    let _init_guard = zakura_test::init();
    let network = Network::Mainnet;
    let (state, finalized, low, high) = precious_test_state(&network);
    let mut staged = state.clone();
    staged.precious_block(low.hash(), &finalized.db).unwrap();
    assert_eq!(staged.best_tip().unwrap().1, low.hash());
    assert_eq!(state.best_tip().unwrap().1, high.hash());
}

/// A preference belongs to its block, so preferring a descendant does not erase it, and
/// reverting to the block restores it.
#[test]
fn precious_block_survives_a_later_call_on_a_descendant() {
    let _init_guard = zakura_test::init();
    let network = Network::Mainnet;
    let (mut state, finalized, low, high) = precious_test_state(&network);
    state.precious_block(low.hash(), &finalized.db).unwrap();
    let low_child = low.make_fake_child().set_work(1);
    commit_test_block(&mut state, &finalized, &low_child);
    state
        .precious_block(low_child.hash(), &finalized.db)
        .unwrap();
    assert_eq!(state.best_tip().unwrap().1, low_child.hash());

    state.invalidate_block(low_child.hash()).unwrap();
    assert_eq!(state.best_tip().unwrap().1, low.hash());
    assert!(state
        .chain_iter()
        .any(|chain| chain.non_finalized_tip_hash() == high.hash()));

    // Invalidation keeps the preference for reconsideration, like Bitcoin Core's block index.
    state.invalidate_block(low.hash()).unwrap();
    assert_eq!(state.best_tip().unwrap().1, high.hash());
    state.reconsider_block(low.hash(), &finalized.db).unwrap();
    assert_eq!(state.best_tip().unwrap().1, low.hash());

    // Finalizing the shared root keeps preferences only for retained or invalidated blocks.
    state.finalize();
    assert!(state
        .precious_blocks
        .keys()
        .all(|hash| state.any_chain_contains(hash) || state.is_invalidated(hash)));
    assert_eq!(state.best_tip().unwrap().1, low.hash());
}

/// Commits `count` children of `parent` with the same `work` and distinct hashes.
fn commit_test_siblings(
    state: &mut NonFinalizedState,
    finalized: &FinalizedState,
    parent: &Arc<Block>,
    work: u128,
    count: u8,
) {
    for commitment in 0..count {
        let child = parent
            .make_fake_child()
            .set_work(work)
            .set_block_commitment([commitment.saturating_add(100); 32]);
        commit_test_block(state, finalized, &child);
    }
}

/// A fork-limit eviction forgets the evicted tip's preference, so the same body downloaded
/// again competes on work and hash only.
#[test]
fn precious_block_preference_is_dropped_with_an_evicted_tip() {
    let _init_guard = zakura_test::init();
    let network = Network::Mainnet;
    let (mut state, finalized, low, high) = precious_test_state(&network);
    state.precious_block(low.hash(), &finalized.db).unwrap();
    let high_child = high.make_fake_child().set_work(1);
    commit_test_block(&mut state, &finalized, &high_child);
    assert!(state.precious_blocks.contains_key(&low.hash()));

    // Fill the fork limit with a branch whose tips all have more work than `low`, so `low` is
    // the lowest chain when the last fork arrives. Their shared parent stays in the state.
    let root_hash = low.header.previous_block_hash;
    let root = state
        .best_chain()
        .unwrap()
        .block(root_hash.into())
        .unwrap()
        .block
        .clone();
    let branch = root
        .make_fake_child()
        .set_work(1)
        .set_block_commitment([3; 32]);
    commit_test_block(&mut state, &finalized, &branch);
    let forks = u8::try_from(MAX_NON_FINALIZED_CHAIN_FORKS - 1).unwrap();
    commit_test_siblings(&mut state, &finalized, &branch, 10, forks);
    assert_eq!(state.chain_count(), MAX_NON_FINALIZED_CHAIN_FORKS);
    assert!(!state.any_chain_contains(&low.hash()));
    assert!(state.any_chain_contains(&root_hash));
    // The commit that evicted the tip forgets its preference, before any invalidation runs.
    assert!(!state.precious_blocks.contains_key(&low.hash()));

    // Remove every tip with more work, then download the evicted body again.
    state.invalidate_block(branch.hash()).unwrap();
    state.invalidate_block(high_child.hash()).unwrap();
    commit_test_block(&mut state, &finalized, &low);

    assert_eq!(
        state.best_tip().unwrap().1,
        high.hash(),
        "an evicted tip must not keep its operator preference"
    );
    assert!(!state.precious_blocks.contains_key(&low.hash()));
}

/// Commits and reverts keep the preferences of blocks still in a chain or in an invalidation
/// record.
#[test]
fn precious_block_preference_survives_commits_invalidation_and_reconsideration() {
    let _init_guard = zakura_test::init();
    let network = Network::Mainnet;
    let (mut state, finalized, low, high) = precious_test_state(&network);
    state.precious_block(low.hash(), &finalized.db).unwrap();
    let sequence = state.precious_blocks[&low.hash()];

    // A child commit keeps the preference of its live ancestor, and a rollback restores it.
    let low_child = low.make_fake_child().set_work(1);
    commit_test_block(&mut state, &finalized, &low_child);
    assert_eq!(state.precious_blocks.get(&low.hash()), Some(&sequence));
    state.invalidate_block(low_child.hash()).unwrap();
    assert_eq!(state.best_tip().unwrap().1, low.hash());

    // An invalidation record keeps the preference, and reconsideration restores it.
    state.invalidate_block(low.hash()).unwrap();
    assert_eq!(state.best_tip().unwrap().1, high.hash());
    assert_eq!(state.precious_blocks.get(&low.hash()), Some(&sequence));
    state.reconsider_block(low.hash(), &finalized.db).unwrap();
    assert_eq!(state.best_tip().unwrap().1, low.hash());
    assert_eq!(state.precious_blocks.get(&low.hash()), Some(&sequence));
}

/// Dropping the oldest invalidation record at the record limit also drops its preferences.
#[test]
fn precious_block_preference_is_dropped_with_its_invalidation_record() {
    let _init_guard = zakura_test::init();
    let network = Network::Mainnet;
    let (mut state, finalized, low, high) = precious_test_state(&network);
    state.precious_block(low.hash(), &finalized.db).unwrap();
    state.invalidate_block(low.hash()).unwrap();

    // Each invalidated tip of this chain gets its own record.
    let mut descendants = vec![high.clone()];
    for _ in 0..MAX_INVALIDATED_BLOCKS {
        let child = descendants.last().unwrap().make_fake_child().set_work(1);
        commit_test_block(&mut state, &finalized, &child);
        descendants.push(child);
    }
    for (count, descendant) in descendants[1..].iter().rev().enumerate() {
        assert!(state.precious_blocks.contains_key(&low.hash()));
        state.invalidate_block(descendant.hash()).unwrap();
        assert_eq!(
            state.is_invalidated(&low.hash()),
            count + 1 < MAX_INVALIDATED_BLOCKS
        );
    }
    assert!(!state.precious_blocks.contains_key(&low.hash()));

    // The dropped block can be downloaded again, and then has no preference.
    commit_test_block(&mut state, &finalized, &low);
    assert_eq!(state.best_tip().unwrap().1, high.hash());
}

/// Finalization keeps the preference of a side chain that survives it.
#[test]
fn precious_block_preference_survives_finalization_of_a_shared_root() {
    let _init_guard = zakura_test::init();
    let network = Network::Mainnet;
    let (mut state, finalized, low, high) = precious_test_state(&network);
    state.precious_block(low.hash(), &finalized.db).unwrap();
    let sequence = state.precious_blocks[&low.hash()];
    let high_child = high.make_fake_child().set_work(1);
    commit_test_block(&mut state, &finalized, &high_child);

    // The best chain is rebuilt before the side chain holding the preferred tip.
    state.finalize();
    assert_eq!(state.precious_blocks.get(&low.hash()), Some(&sequence));
    state.invalidate_block(high_child.hash()).unwrap();
    assert_eq!(state.best_tip().unwrap().1, low.hash());
}

/// Chains reverted to the same tip compare equal, so the chain set keeps one chain per tip.
#[test]
fn precious_block_keeps_one_chain_per_tip() {
    let _init_guard = zakura_test::init();
    let network = Network::Mainnet;
    let (mut state, finalized, low, high) = precious_test_state(&network);
    state.precious_block(low.hash(), &finalized.db).unwrap();

    // Extend the preferred tip, then fork from it, so both chains carry the old preference.
    let extension = low.make_fake_child().set_work(1);
    let fork = low
        .make_fake_child()
        .set_work(1)
        .set_block_commitment([9; 32]);
    commit_test_block(&mut state, &finalized, &extension);
    commit_test_block(&mut state, &finalized, &fork);
    assert_eq!(state.chain_count(), 3);

    // Revert one chain, prefer the tip again, then revert the other chain to the same tip.
    state.invalidate_block(extension.hash()).unwrap();
    state.precious_block(low.hash(), &finalized.db).unwrap();
    state.invalidate_block(fork.hash()).unwrap();

    let tips: Vec<_> = state
        .chain_iter()
        .map(|chain| chain.non_finalized_tip_hash())
        .collect();
    assert_eq!(tips, vec![low.hash(), high.hash()]);
}

/// Receipt order is independent of commit scheduling, hash order, and replay.
#[test]
// kogany: Zcash Mainnet and Testnet block vectors (NU5 branch IDs, Zcash Heartwood and NU5
// heights); not run on Ycash.
#[cfg(not(feature = "ycash"))]
fn equal_work_prefers_first_receipt_through_forks_and_reconsideration() {
    let _init_guard = zakura_test::init();
    for network in Network::iter() {
        let root = Arc::new(network.test_block(653599, 583999).unwrap());
        let a = root
            .make_fake_child()
            .set_work(10)
            .set_block_commitment([1; 32]);
        let b = root
            .make_fake_child()
            .set_work(10)
            .set_block_commitment([2; 32]);
        for (early, late) in [(&a, &b), (&b, &a)] {
            for reverse_completion in [false, true] {
                let (mut state, finalized) = new_invalidate_test_state(&network);
                state
                    .commit_new_chain(root.clone().prepare(), &finalized.db)
                    .unwrap();
                let mut early_block = early.clone().prepare();
                early_block.receipt_order = Some(1);
                let mut late_block = late.clone().prepare();
                late_block.receipt_order = Some(2);
                let commits = if reverse_completion {
                    [late_block, early_block]
                } else {
                    [early_block, late_block]
                };
                for block in commits {
                    state.commit_block(block, &finalized.db).unwrap();
                }
                assert_eq!(state.best_tip().unwrap().1, early.hash());
                assert_eq!(state.chain_set.len(), 2);
                let mut duplicate = early.clone().prepare();
                duplicate.receipt_order = Some(99);
                state.commit_block(duplicate, &finalized.db).unwrap();
                assert_eq!(state.chain_set.len(), 2);
                assert_eq!(state.best_tip().unwrap().1, early.hash());
                state.invalidate_block(early.hash()).unwrap();
                assert_eq!(state.best_tip().unwrap().1, late.hash());
                state.reconsider_block(early.hash(), &finalized.db).unwrap();
                assert_eq!(state.best_tip().unwrap().1, early.hash());
                let child = late.make_fake_child().set_work(1);
                let mut prepared = child.clone().prepare();
                prepared.receipt_order = Some(3);
                state.commit_block(prepared, &finalized.db).unwrap();
                assert_eq!(state.best_tip().unwrap().1, child.hash());
                state.invalidate_block(child.hash()).unwrap();
                assert_eq!(state.best_tip().unwrap().1, early.hash());
                state.precious_block(late.hash(), &finalized.db).unwrap();
                assert_eq!(state.best_tip().unwrap().1, late.hash());
                state.invalidate_block(late.hash()).unwrap();
                assert_eq!(state.best_tip().unwrap().1, early.hash());
                state.reconsider_block(late.hash(), &finalized.db).unwrap();
                assert_eq!(state.best_tip().unwrap().1, late.hash());
                state.precious_block(early.hash(), &finalized.db).unwrap();
                assert_eq!(state.best_tip().unwrap().1, early.hash());
                state.finalize();
                assert_eq!(state.best_tip().unwrap().1, early.hash());
            }
        }
    }
}

#[test]
fn receipt_fallback_and_backup_restore_ignore_replay_order() {
    let _init_guard = zakura_test::init();
    let network = Network::Mainnet;
    let root = Arc::new(network.test_block(653599, 583999).unwrap());
    let a = root
        .make_fake_child()
        .set_work(10)
        .set_block_commitment([1; 32]);
    let b = root
        .make_fake_child()
        .set_work(10)
        .set_block_commitment([2; 32]);
    let (low, high) = if a.hash().0 < b.hash().0 {
        (a, b)
    } else {
        (b, a)
    };
    for (low_order, high_order, expected) in [
        (None, None, high.hash()),
        (Some(1), Some(1), high.hash()),
        (None, Some(1), low.hash()),
        (Some(1), None, high.hash()),
        (Some(1), Some(2), low.hash()),
    ] {
        let (mut state, finalized) = new_invalidate_test_state(&network);
        state
            .commit_new_chain(root.clone().prepare(), &finalized.db)
            .unwrap();
        for (block, order) in [(&high, high_order), (&low, low_order)] {
            let mut prepared = block.clone().prepare();
            prepared.receipt_order = order;
            state.commit_block(prepared, &finalized.db).unwrap();
        }
        assert_eq!(state.best_tip().unwrap().1, expected);
        let backup = tempfile::tempdir().unwrap();
        state.write_to_backup(backup.path());
        let restored = super::super::backup::restore_backup(
            NonFinalizedState::new(&network),
            backup.path(),
            &finalized.db,
        );
        // kogany (beta3 R1): the Ycash build keeps the best tip with the backup, so the restored
        // best chain is the one the state had, not the one the tip hash picks.
        #[cfg(not(feature = "ycash"))]
        assert_eq!(restored.best_tip().unwrap().1, high.hash());
        #[cfg(feature = "ycash")]
        {
            use crate::service::non_finalized_state::reorg_guard::best_tip_path;

            assert_eq!(restored.best_tip().unwrap().1, expected);
            std::fs::remove_file(best_tip_path(backup.path())).unwrap();
        }
        assert!(restored.chain_iter().all(|chain| chain
            .tip_block()
            .unwrap()
            .receipt_order
            .is_none()));
    }
}

/// kogany (S5, `vault_pq_reorg` case C): two blocks invalidated at one height are both recorded,
/// keyed by hash, and each can be reconsidered; keyed by height the second record overwrote the
/// first, so `reconsiderblock` of the first found nothing. ycashd keeps a failure flag per block.
#[test]
fn ycash_invalidations_at_one_height_are_kept_by_hash() -> Result<()> {
    let _init_guard = zakura_test::init();

    // Mainnet and a pre-Heartwood testnet: the vector blocks need no history tree there.
    for network in [Network::Mainnet, crate::tests::testnet_with_zcash_heights()] {
        let block1: Arc<Block> = Arc::new(network.test_block(653599, 583999).unwrap());
        let first = block1.make_fake_child().set_work(10);
        let second = block1.make_fake_child().set_work(5);
        assert_ne!(first.hash(), second.hash());

        let mut state = NonFinalizedState::new(&network);
        let finalized_state = FinalizedState::new(&Config::ephemeral(), &network)
            .expect("opening an ephemeral database should succeed");
        finalized_state
            .set_finalized_value_pool(ValueBalance::<NonNegative>::fake_populated_pool());

        state.commit_new_chain(block1.clone().prepare(), &finalized_state)?;
        state.commit_block(first.clone().prepare(), &finalized_state)?;
        state.commit_block(second.clone().prepare(), &finalized_state)?;

        state.invalidate_block(first.hash())?;
        state.invalidate_block(second.hash())?;
        assert_eq!(state.invalidated_blocks().len(), 2, "both records are kept");

        state
            .reconsider_block(first.hash(), &finalized_state.db)
            .expect("the first invalidated block is reconsidered");
        assert!(state.any_chain_contains(&first.hash()));
        state
            .reconsider_block(second.hash(), &finalized_state.db)
            .expect("the second invalidated block is reconsidered");
        assert!(state.any_chain_contains(&second.hash()));
        assert!(state.invalidated_blocks().is_empty());
    }

    Ok(())
}

/// kogany (S5, F-S5-19): `getblock` of a block off the best chain. A side-chain block and an
/// invalidated block are found with their heights; a best-chain block and an unknown one are
/// not (the best chain answers those).
#[test]
fn off_chain_blocks_are_found_by_hash() -> Result<()> {
    let _init_guard = zakura_test::init();

    // kogany: on Ycash the default testnet is past Heartwood at the vector height, so the vector
    // blocks go on a pre-Heartwood testnet with Zcash Testnet's heights.
    #[cfg(feature = "ycash")]
    let networks = [Network::Mainnet, crate::tests::testnet_with_zcash_heights()];
    #[cfg(not(feature = "ycash"))]
    let networks = Network::iter();
    for network in networks {
        let block1: Arc<Block> = Arc::new(network.test_block(653599, 583999).unwrap());
        let best = block1.make_fake_child().set_work(10);
        let side = block1.make_fake_child().set_work(5);
        let doomed = best.make_fake_child().set_work(10);

        let mut state = NonFinalizedState::new(&network);
        let finalized_state = FinalizedState::new(&Config::ephemeral(), &network)
            .expect("opening an ephemeral database should succeed");
        finalized_state
            .set_finalized_value_pool(ValueBalance::<NonNegative>::fake_populated_pool());

        state.commit_new_chain(block1.clone().prepare(), &finalized_state)?;
        state.commit_block(best.clone().prepare(), &finalized_state)?;
        state.commit_block(side.clone().prepare(), &finalized_state)?;
        state.commit_block(doomed.clone().prepare(), &finalized_state)?;
        state.invalidate_block(doomed.hash())?;

        let height1 = block1.coinbase_height().unwrap();
        let (found, height) = state
            .off_chain_block(&side.hash())
            .expect("the side-chain block is found");
        assert_eq!(
            (found.hash(), height),
            (side.hash(), (height1 + 1).unwrap())
        );
        let (found, height) = state
            .off_chain_block(&doomed.hash())
            .expect("the invalidated block is found");
        assert_eq!(
            (found.hash(), height),
            (doomed.hash(), (height1 + 2).unwrap())
        );
        assert!(state.off_chain_block(&best.hash()).is_none());
        assert!(state.off_chain_block(&block1.hash()).is_none());
        assert!(state.off_chain_block(&block::Hash([7; 32])).is_none());
    }

    Ok(())
}

/// kogany (beta3 R1, decision note `reorg-parity.md` T1): the reorganisation guard counts the
/// blocks a change of best chain disconnects as ycashd does, the old tip's height minus the fork
/// point's (ycash6 `src/main.cpp:5004`): 99 pass, 100 and more are refused (`MAX_REORG_LENGTH`,
/// `src/main.h:69`). The non-finalized state itself follows the heavier branch at any depth, with
/// the feature on and off, and its window stays 1,000 blocks: the guard is the writer's, and the
/// writer exists only in the Ycash build.
#[test]
fn reorg_guard_counts_rolled_back_blocks_as_ycashd() -> Result<()> {
    let _init_guard = zakura_test::init();

    assert_eq!(crate::constants::MAX_BLOCK_REORG_HEIGHT, 1_000);

    let network = Network::Mainnet;
    let root: Arc<Block> = Arc::new(network.test_block(653599, 583999).unwrap());
    let finalized_state = FinalizedState::new(&Config::ephemeral(), &network)
        .expect("opening an ephemeral database should succeed");
    finalized_state.set_finalized_value_pool(ValueBalance::<NonNegative>::fake_populated_pool());

    // `(depth, fork_is_finalized_tip)`: the blocks of the old best chain above the fork point,
    // and whether the two branches share the non-finalized root or fork below it.
    for (depth, fork_is_finalized_tip) in [
        (1_u32, false),
        (99, false),
        (100, false),
        (101, false),
        (99, true),
        (100, true),
    ] {
        let mut state = NonFinalizedState::new(&network);
        let (mut old_tip, mut new_tip) = if fork_is_finalized_tip {
            // Two roots: the fork point is the finalized tip, and the old root is rolled back.
            let old_root = root.clone().set_block_commitment([1; 32]);
            let new_root = root.clone().set_block_commitment([2; 32]);
            state.commit_new_chain(old_root.clone().prepare(), &finalized_state)?;
            state.commit_new_chain(new_root.clone().prepare(), &finalized_state)?;
            (old_root, new_root)
        } else {
            state.commit_new_chain(root.clone().prepare(), &finalized_state)?;
            let old_child = root
                .make_fake_child()
                .set_work(10)
                .set_block_commitment([1; 32]);
            let new_child = root
                .make_fake_child()
                .set_work(9)
                .set_block_commitment([2; 32]);
            state.commit_block(old_child.clone().prepare(), &finalized_state)?;
            state.commit_block(new_child.clone().prepare(), &finalized_state)?;
            (old_child, new_child)
        };
        // The two roots tie on work: the old best chain is the one the tie-break prefers.
        if state.best_tip().unwrap().1 != old_tip.hash() {
            std::mem::swap(&mut old_tip, &mut new_tip);
        }

        // Each block of the old best chain has more work than its rival, so the chain stays best
        // while the other branch is stored beside it.
        for _ in 1..depth {
            old_tip = old_tip.make_fake_child().set_work(10);
            state.commit_block(old_tip.clone().prepare(), &finalized_state)?;
            #[cfg(feature = "ycash")]
            let before = state.clone();
            new_tip = new_tip.make_fake_child().set_work(9);
            state.commit_block(new_tip.clone().prepare(), &finalized_state)?;
            assert_eq!(state.best_tip().unwrap().1, old_tip.hash());
            // A block stored off the best chain rolls nothing back.
            #[cfg(feature = "ycash")]
            assert_eq!(before.refused_reorg(&state), None);
        }
        let old_height = old_tip.coinbase_height().unwrap();
        let fork = if fork_is_finalized_tip {
            (
                (root.coinbase_height().unwrap() - 1).unwrap(),
                root.header.previous_block_hash,
            )
        } else {
            (root.coinbase_height().unwrap(), root.hash())
        };
        assert_eq!(old_height.0 - fork.0 .0, depth);

        // The block that gives the other branch more work.
        let before = state.clone();
        new_tip = new_tip
            .make_fake_child()
            .set_work(10 * u128::from(depth) + 100);
        state.commit_block(new_tip.clone().prepare(), &finalized_state)?;
        assert_eq!(
            state.best_tip().unwrap().1,
            new_tip.hash(),
            "the non-finalized state follows the heavier branch {depth} blocks back"
        );
        assert_eq!(before.best_tip().unwrap().1, old_tip.hash());

        #[cfg(feature = "ycash")]
        {
            use crate::service::non_finalized_state::reorg_guard::{
                RefusedReorg, MAX_REORG_LENGTH,
            };

            assert_eq!(MAX_REORG_LENGTH, 99);
            let refused = before.refused_reorg(&state);
            if depth <= 99 {
                assert_eq!(refused, None, "{depth} blocks are rolled back");
            } else {
                let expected = RefusedReorg {
                    rollback: depth,
                    old_tip: (old_height, old_tip.hash()),
                    new_tip: (new_tip.coinbase_height().unwrap(), new_tip.hash()),
                    fork,
                };
                assert_eq!(refused, Some(expected), "{depth} blocks are refused");
                let message = expected.to_string();
                // ycash6 `src/main.cpp:5008-5009`, the sentence `reorg_limit.py` matches.
                assert!(message.starts_with(&format!(
                    "A block chain reorganization has been detected that would roll back {depth} \
                     blocks! This is larger than the maximum of 99 blocks, and so the node is \
                     shutting down for your safety.\n\nReorganization details:\n"
                )));
                assert!(message.ends_with("\n\nPlease help, human!"));
            }

            // The new best chain, extended: nothing is rolled back.
            let before = state.clone();
            let extended = new_tip.make_fake_child().set_work(10);
            state.commit_block(extended.prepare(), &finalized_state)?;
            assert_eq!(before.refused_reorg(&state), None);
            // And an unchanged state.
            assert_eq!(state.refused_reorg(&state), None);
        }
    }

    Ok(())
}

/// kogany (beta3 R1): `invalidateblock` is asked the depth as ycashd asks it. `InvalidateBlock`
/// disconnects down to the parent of the invalidated block unasked (ycash6
/// `src/main.cpp:5245-5267`), and the `ActivateBestChain` that follows
/// (`src/rpc/blockchain.cpp:2175`) measures from that parent (`src/main.cpp:5004-5008`): a
/// branch that forks 99 blocks below the parent is followed, 100 is refused, and the blocks at
/// and above the invalidated one are not counted. An invalidation that leaves the node on a
/// chain that holds the parent is never refused.
#[cfg(feature = "ycash")]
#[test]
fn reorg_guard_asks_an_invalidation_from_the_parent_as_ycashd() -> Result<()> {
    use crate::service::non_finalized_state::reorg_guard::RefusedReorg;

    let _init_guard = zakura_test::init();

    let network = Network::Mainnet;
    let root: Arc<Block> = Arc::new(network.test_block(653599, 583999).unwrap());
    let root_id = (root.coinbase_height().unwrap(), root.hash());
    let finalized_state = FinalizedState::new(&Config::ephemeral(), &network)
        .expect("opening an ephemeral database should succeed");
    finalized_state.set_finalized_value_pool(ValueBalance::<NonNegative>::fake_populated_pool());

    // `(depth, side_is_heavier)`: the blocks between the fork point (the root) and the parent of
    // the invalidated block, and whether the side branch has more work than the best chain cut
    // at that parent.
    for (depth, side_is_heavier) in [(99_u32, true), (100, true), (100, false), (250, true)] {
        let mut state = NonFinalizedState::new(&network);
        state.commit_new_chain(root.clone().prepare(), &finalized_state)?;

        // The best chain: `depth` blocks up to the parent, the invalidated block, and a tip.
        let mut old = vec![root.clone()];
        for _ in 0..depth + 2 {
            let child = old.last().unwrap().make_fake_child().set_work(10);
            state.commit_block(child.clone().prepare(), &finalized_state)?;
            old.push(child);
        }
        let parent = &old[usize::try_from(depth).unwrap()];
        let invalidated = &old[usize::try_from(depth).unwrap() + 1];
        let old_tip = old.last().unwrap();

        // One block on the root: less work than the best chain (`10 * depth + 20`), and more or
        // less than the best chain cut at the parent (`10 * depth`).
        let side_work = 10 * u128::from(depth) + 5 - if side_is_heavier { 0 } else { 10 };
        let side = root
            .make_fake_child()
            .set_work(side_work)
            .set_block_commitment([2; 32]);
        state.commit_block(side.clone().prepare(), &finalized_state)?;
        assert_eq!(state.best_tip().unwrap().1, old_tip.hash());
        let before = state.clone();

        // The tip: the node stays on the parent of the tip, which the cut chain holds.
        assert_eq!(state.refused_invalidation(old_tip.hash()), None);
        // A block of the side branch, an unknown block, and the first non-finalized block,
        // whose parent is the finalized tip.
        assert_eq!(state.refused_invalidation(side.hash()), None);
        assert_eq!(state.refused_invalidation(block::Hash([7; 32])), None);
        assert_eq!(state.refused_invalidation(root.hash()), None);

        let refused = state.refused_invalidation(invalidated.hash());
        // What the invalidation does when it is made: the guard reads the same change.
        let mut after = state.clone();
        after.invalidate_block(invalidated.hash())?;
        if !side_is_heavier {
            assert_eq!(after.best_tip().unwrap().1, parent.hash());
            assert_eq!(refused, None, "the node stays on the parent");
        } else {
            assert_eq!(after.best_tip().unwrap().1, side.hash());
            if depth <= 99 {
                assert_eq!(
                    refused, None,
                    "{depth} blocks below the parent are rolled back"
                );
            } else {
                let expected = RefusedReorg {
                    rollback: depth,
                    old_tip: (parent.coinbase_height().unwrap(), parent.hash()),
                    new_tip: (side.coinbase_height().unwrap(), side.hash()),
                    fork: root_id,
                };
                assert_eq!(refused, Some(expected), "{depth} blocks are refused");
                assert!(expected.to_string().starts_with(&format!(
                    "A block chain reorganization has been detected that would roll back {depth} \
                     blocks! This is larger than the maximum of 99 blocks"
                )));
            }
        }

        // Asking changes nothing.
        assert_eq!(state.best_tip(), before.best_tip());
        assert_eq!(state.chain_count(), before.chain_count());
    }

    Ok(())
}

/// kogany (beta3 R1): a refusal whose message cannot be written is still recorded. The file is
/// made without a message, which keeps the node down like any record, and a record that is
/// there is left as it is. Only when no file can be made is there an error.
#[cfg(feature = "ycash")]
#[test]
fn reorg_refusal_is_recorded_when_its_message_cannot_be_written() {
    use crate::service::non_finalized_state::reorg_guard::{record, recorded, refusal_path};

    let _init_guard = zakura_test::init();
    let db_dir = tempfile::tempdir().expect("a temporary directory");
    let path = refusal_path(db_dir.path());

    // The temporary file the message is written to cannot be created: a directory has its name.
    std::fs::create_dir(db_dir.path().join("ycash-reorg-refused.tmp")).unwrap();
    assert_eq!(recorded(db_dir.path()), None);
    assert_eq!(
        record(db_dir.path(), "refused").expect("the refusal is recorded without its message"),
        path
    );
    assert_eq!(std::fs::read(&path).unwrap(), b"");
    let message = recorded(db_dir.path()).expect("an empty record counts");
    assert!(
        message.contains("is empty") && message.contains("more than 99 blocks"),
        "{message}"
    );

    // A record with a message is not emptied by a later refusal that cannot write its own.
    std::fs::write(&path, "the first refusal").unwrap();
    record(db_dir.path(), "refused again").expect("the record stays");
    assert_eq!(
        recorded(db_dir.path()).as_deref(),
        Some("the first refusal")
    );

    // No directory: nothing can be recorded, and the caller is told.
    let missing = db_dir.path().join("missing");
    record(&missing, "refused").expect_err("there is no directory to record in");
    assert_eq!(recorded(&missing), None);
}

/// kogany (beta3 R1): the record of a refused reorganisation is a file beside the state
/// database, so it does not depend on the non-finalized backup.
#[cfg(feature = "ycash")]
#[test]
fn reorg_refusal_is_recorded_beside_the_state_database() {
    use crate::service::non_finalized_state::reorg_guard::{record, recorded, refusal_path};

    let _init_guard = zakura_test::init();
    let db_dir = tempfile::tempdir().expect("a temporary directory");

    assert_eq!(recorded(db_dir.path()), None);
    let path = record(db_dir.path(), "refused").expect("the record is written");
    assert_eq!(path, refusal_path(db_dir.path()));
    assert_eq!(path, db_dir.path().join("ycash-reorg-refused"));
    assert_eq!(recorded(db_dir.path()).as_deref(), Some("refused"));
    // The record is renamed into place from a temporary file: only the record is left.
    let names: Vec<_> = std::fs::read_dir(db_dir.path())
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    assert_eq!(names, ["ycash-reorg-refused"]);
    // A second refusal replaces the first.
    record(db_dir.path(), "refused again").expect("the record is replaced");
    assert_eq!(recorded(db_dir.path()).as_deref(), Some("refused again"));

    // A record with no message still keeps the node down, and says what to do.
    for contents in [&b""[..], b" \n", &[0xff, 0xfe][..]] {
        std::fs::write(&path, contents).unwrap();
        let message = recorded(db_dir.path()).expect("the record still counts");
        assert!(
            message.contains(&path.display().to_string())
                && message.contains("more than 99 blocks")
                && message.contains("remove the file"),
            "{message}"
        );
    }
    // A half-written temporary file is not a record.
    std::fs::remove_file(&path).expect("the operator removes the record");
    std::fs::write(db_dir.path().join("ycash-reorg-refused.tmp"), "refu").unwrap();
    assert_eq!(recorded(db_dir.path()), None);
}

/// kogany (beta3 R1): a restart does not undo the guard. Restored blocks have no receipt order,
/// so two restored chains with the same work are ordered by tip hash; the best tip kept with
/// the backup makes the restored best chain the one the node was on, and a restore that would
/// roll back more than 99 blocks from that tip is refused and recorded as at run time.
#[cfg(feature = "ycash")]
#[test]
fn restored_best_chain_is_the_one_the_node_was_on() -> Result<()> {
    use crate::service::non_finalized_state::{
        backup::restore_backup,
        reorg_guard::{best_tip_path, persisted_best_tip, recorded, refusal_path},
    };

    let _init_guard = zakura_test::init();
    let network = Network::Mainnet;
    let root: Arc<Block> = Arc::new(network.test_block(653599, 583999).unwrap());
    let scratch = tempfile::tempdir().expect("a temporary directory");

    // Two branches of `depth` blocks from `root`; every block has the same work, except the
    // last of the second branch when it is `heavier`. Returns the state and the two tips.
    let branches = |depth: u32, heavier: bool, finalized_state: &FinalizedState| {
        let mut state = NonFinalizedState::new(&network);
        state
            .commit_new_chain(root.clone().prepare(), finalized_state)
            .unwrap();
        let mut tips = [root.clone(), root.clone()];
        for height in 1..=depth {
            for (branch, tip) in tips.iter_mut().enumerate() {
                let work = if heavier && branch == 1 && height == depth {
                    20
                } else {
                    10
                };
                *tip = tip
                    .make_fake_child()
                    .set_work(work)
                    .set_block_commitment([u8::try_from(branch).unwrap() + 1; 32]);
                let mut prepared = tip.clone().prepare();
                // The first branch is received first.
                prepared.receipt_order =
                    Some(u64::from(height) * 2 + u64::try_from(branch).unwrap());
                state.commit_block(prepared, finalized_state).unwrap();
            }
        }
        (state, tips)
    };
    let new_finalized_state = || {
        let finalized_state = FinalizedState::new(&Config::ephemeral(), &network)
            .expect("opening an ephemeral database should succeed");
        finalized_state
            .set_finalized_value_pool(ValueBalance::<NonNegative>::fake_populated_pool());
        finalized_state
    };
    let backup_dir = |name: &str| {
        let dir = scratch.path().join(name);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    };
    let restore = |dir: &std::path::Path, finalized_state: &FinalizedState| {
        restore_backup(NonFinalizedState::new(&network), dir, &finalized_state.db)
    };

    // A tie 100 blocks deep: the node was on the branch it received first.
    let finalized_state = new_finalized_state();
    let (state, [first, second]) = branches(100, false, &finalized_state);
    let old_tip = state.best_tip().unwrap();
    assert_eq!(old_tip.1, first.hash());
    let by_hash = if first.hash().0 > second.hash().0 {
        first.hash()
    } else {
        second.hash()
    };
    // Each branch in turn is the one the node was on, so one of the two is the branch the tip
    // hash would not pick.
    for preferred in [&first, &second] {
        let mut state = state.clone();
        state
            .precious_block(preferred.hash(), &finalized_state.db)
            .unwrap();
        let old_tip = state.best_tip().unwrap();
        assert_eq!(old_tip.1, preferred.hash());

        let dir = backup_dir(&format!("tie-{}", preferred.hash()));
        state.write_to_backup(&dir);
        assert_eq!(persisted_best_tip(&dir), Some(old_tip));
        assert_eq!(
            std::fs::read_to_string(best_tip_path(&dir)).unwrap(),
            format!("{} {}\n", old_tip.0 .0, old_tip.1)
        );
        let restored = restore(&dir, &finalized_state);
        assert_eq!(restored.chain_count(), 2);
        assert_eq!(restored.best_tip(), Some(old_tip), "the node's own tip");
        assert_eq!(recorded(finalized_state.db.path()), None);
        // Restored again, as at the next restart: the same tip.
        assert_eq!(restore(&dir, &finalized_state).best_tip(), Some(old_tip));

        // Without the kept tip (a backup written before this guard) the tip hash decides, and
        // the tip is kept from then on.
        std::fs::remove_file(best_tip_path(&dir)).unwrap();
        let restored = restore(&dir, &finalized_state);
        assert_eq!(restored.best_tip().unwrap().1, by_hash);
        assert_eq!(persisted_best_tip(&dir), restored.best_tip());

        // A kept tip that names no restored block: the same, and it is replaced.
        std::fs::write(
            best_tip_path(&dir),
            format!("{} {}\n", old_tip.0 .0, block::Hash([7; 32])),
        )
        .unwrap();
        let restored = restore(&dir, &finalized_state);
        assert_eq!(restored.best_tip().unwrap().1, by_hash);
        assert_eq!(persisted_best_tip(&dir), restored.best_tip());

        // A file that is not a height and a hash is no tip.
        std::fs::write(best_tip_path(&dir), "not a tip").unwrap();
        assert_eq!(persisted_best_tip(&dir), None);
        assert_eq!(
            restore(&dir, &finalized_state).best_tip().unwrap().1,
            by_hash
        );
    }

    // One chain needs no tip: the file goes when the other branch does.
    let dir = backup_dir("one-chain");
    state.write_to_backup(&dir);
    assert!(best_tip_path(&dir).exists());
    let mut one_chain = NonFinalizedState::new(&network);
    one_chain
        .commit_new_chain(root.clone().prepare(), &finalized_state)
        .unwrap();
    let child = root.make_fake_child().set_work(10);
    one_chain
        .commit_block(child.clone().prepare(), &finalized_state)
        .unwrap();
    assert_eq!(one_chain.chain_count(), 1);
    one_chain.write_to_backup(&dir);
    assert!(!best_tip_path(&dir).exists());
    assert_eq!(
        restore(&dir, &finalized_state).best_tip().unwrap().1,
        child.hash()
    );
    assert!(!best_tip_path(&dir).exists());

    // More work on the other branch, and a kept tip on the first: a reorganisation from the
    // node's tip. 99 blocks back it is followed; 100 back it is refused and recorded, and the
    // node starts with no restored block, so the writer stops it before a reader sees one.
    for depth in [99_u32, 100] {
        let finalized_state = new_finalized_state();
        let (state, [first, second]) = branches(depth, true, &finalized_state);
        assert_eq!(state.best_tip().unwrap().1, second.hash());
        let dir = backup_dir(&format!("heavier-{depth}"));
        state.write_to_backup(&dir);
        let first_height = first.coinbase_height().unwrap();
        std::fs::write(
            best_tip_path(&dir),
            format!("{} {}\n", first_height.0, first.hash()),
        )
        .unwrap();

        let restored = restore(&dir, &finalized_state);
        let record = recorded(finalized_state.db.path());
        if depth <= 99 {
            assert_eq!(restored.best_tip().unwrap().1, second.hash());
            assert_eq!(record, None);
            assert_eq!(persisted_best_tip(&dir), restored.best_tip());
        } else {
            assert_eq!(restored.chain_count(), 0, "no restored block is shown");
            let record = record.expect("the refusal is recorded");
            assert!(
                record.starts_with(
                    "A block chain reorganization has been detected that would roll back 100 \
                     blocks! This is larger than the maximum of 99 blocks"
                ),
                "{record}"
            );
            assert!(record.contains(&format!(
                "- Current tip: {}, height {}",
                first.hash(),
                first_height.0
            )));
            assert!(record.contains(&format!("- New tip:     {}", second.hash())));
            assert!(record.contains(&format!("- Fork point:  {}", root.hash())));
            // The backup and its tip are left for the operator.
            assert_eq!(persisted_best_tip(&dir), Some((first_height, first.hash())));
            std::fs::remove_file(refusal_path(finalized_state.db.path())).unwrap();
        }
    }

    Ok(())
}
