//! The Ycash Yellowback (YED) module's block verdict as a contextual rule (kogany plan W5-f,
//! U-21, mapping M24-15).
//!
//! ycash6 `ConnectBlock` asks the index whether the module judges the block valid
//! (`YellowbackIndex::CheckConnect`, `src/main.cpp:4355-4359`) and rejects it at DoS 100,
//! `REJECT_INVALID`, `bad-yellowback-<verdict>`, wherever `UPGRADE_VAULT` is active and the YED
//! attestor set is configured; an index that cannot evaluate the block stops the node. Zakura's
//! contextual validation computes the block's [`YedBlockEffect`] over the parent fork's index
//! state when the block is pushed (W5-e); this turns its verdict into
//! [`ValidateContextError::YedRejected`]. A block below the start height, or on a node where
//! Yellowback is off, has an empty effect and passes.

use zakura_chain::parameters::Network;

use crate::{
    service::{
        finalized_state::ZakuraDb,
        non_finalized_state::Chain,
        yed::{block_yed_effect_for_chain, YedBlockEffect},
    },
    ContextuallyVerifiedBlock, ValidateContextError,
};

/// The YED effect of `block` pushed onto `parent_chain` (see
/// [`block_yed_effect_for_chain`]: stops the node when the index cannot evaluate the block), or
/// [`ValidateContextError::YedRejected`] (DoS 100) when the module judges the block invalid.
pub fn block_yed_effect(
    network: &Network,
    parent_chain: &Chain,
    db: &ZakuraDb,
    block: &ContextuallyVerifiedBlock,
) -> Result<YedBlockEffect, ValidateContextError> {
    yed_verdict(
        block_yed_effect_for_chain(network, parent_chain, db, block),
        block,
    )
}

/// `effect`, or its verdict as the rejection of `block`.
pub fn yed_verdict(
    effect: YedBlockEffect,
    block: &ContextuallyVerifiedBlock,
) -> Result<YedBlockEffect, ValidateContextError> {
    match &effect.invalid {
        None => Ok(effect),
        Some(invalid) => Err(ValidateContextError::YedRejected {
            reason: invalid.reject_reason(),
            detail: invalid.reason.clone(),
            height: block.height,
            hash: block.hash,
        }),
    }
}
