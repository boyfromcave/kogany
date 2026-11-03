//! The Vault upgrade's contextual block rules (kogany plan W4-d, mapping M24-15).
//!
//! ycash6 `ConnectBlock` applies a block's vault acts and template rules sequentially on one
//! overlay over the set state after the parent (`VaultState::ApplyBlock`, `src/main.cpp:4344-4351`)
//! and rejects the block at DoS 100, `REJECT_INVALID`, with the rule's reason. Zakura verifies a
//! block's transactions concurrently (`zakura-consensus`), so the sequential rules run here, in
//! contextual validation, when the block is pushed onto its parent fork: the same transition as
//! the finalized write path's (`block_vault_delta_total`), except that a reject **rejects the
//! block** instead of being skipped. On a block this accepts, the delta equals the total
//! transition's, so the finalized state computes the same records when the block finalizes.
//!
//! The module table has `YED\0` registered where Yellowback is configured (W5-f,
//! `crate::service::yed::module`), so the YED module's `validate_create` / `validate_spend` /
//! `check_block` verdicts reject the block here too.
//!
//! The module ejection effect (U-25) is inside the transition: `VaultOverlay::apply_tx` runs each
//! registered module's ejection and liveness hooks after the transaction's own rules and act
//! (`kogany_vault::state::eject_and_freeze`, C++ `ApplyEjectionsOf`), so the block's delta carries
//! the ejected member and the frozen bond, and a reorg pops them with the block.

use kogany_vault::state::apply_block;
use zakura_chain::parameters::Network;

use crate::{
    service::{
        finalized_state::{
            vault::{vault_network_params, vault_txs, OrderedUtxoCoins},
            ZakuraDb,
        },
        non_finalized_state::{Chain, VaultDelta},
        yed::module::{chain_block_hash_at, with_vault_rules},
    },
    ContextuallyVerifiedBlock, ValidateContextError,
};

/// The vault delta of `block` pushed onto `parent_chain` (the parent fork, or an empty chain at
/// the finalized tip): every transaction applied in block order over the set state at the
/// parent's tip, then each registered module's `check_block`.
///
/// Empty where the Vault upgrade is not active at the block's height. A rule violation is
/// [`ValidateContextError::VaultRejected`] (ycash6 DoS 100).
pub fn block_vault_delta(
    network: &Network,
    parent_chain: &Chain,
    db: &ZakuraDb,
    block: &ContextuallyVerifiedBlock,
) -> Result<VaultDelta, ValidateContextError> {
    let Some(params) = vault_network_params(network).filter(|p| p.is_active(block.height)) else {
        return Ok(VaultDelta::default());
    };
    let txs = vault_txs(&block.block, &block.transaction_hashes);
    // kogany (W5-f): YED\0 registered where Yellowback is configured, with the parent fork's
    // ancestor hashes for the module hooks (ycash6 `SetBlockHashes(AncestorHashes(pprev))`).
    let block_hash_at = |h: i64| chain_block_hash_at(parent_chain, db, h);
    with_vault_rules(
        &params,
        network,
        &db.config().yellowback,
        Some(&block_hash_at),
        |rules| {
            apply_block(
                &parent_chain.vault_view(db),
                &txs,
                i64::from(block.height.0),
                &OrderedUtxoCoins(&block.spent_outputs),
                rules,
            )
        },
    )
    .map_err(|reject| ValidateContextError::VaultRejected {
        reason: reject.reason().to_owned(),
        height: block.height,
        hash: block.hash,
    })
}
