//! kogany (W9-a finding F-6): tip-state-dependent mempool failures are retried, never left
//! cached as "did not pass consensus".
//!
//! ycashd keeps a transaction whose inputs are missing in its orphan pool and tries it again when a
//! parent arrives (`mapOrphanTransactions`, `AcceptToMemoryPool`'s `fMissingInputs`); every other
//! state rejection (the vault and YED checks, sequence locks: DoS 0) holds only for the tip it ran
//! at (`recentRejects` is reset when the tip moves). Zakura caches every verification failure as an
//! [`ExactTipRejectionError::FailedVerification`](super::ExactTipRejectionError) until the next
//! block, with two gaps a lagging node falls into:
//!
//! - a failure computed at an old tip (the verification waited, up to
//!   `MEMPOOL_OUTPUT_LOOKUP_TIMEOUT`, for a parent that then arrived in a block) is cached for the
//!   new tip, so the transaction is refused until the block after;
//! - a transaction relayed before this node has the parent it spends is dropped: the relaying peer
//!   never announces it again.
//!
//! So, for the errors [`is_tip_state_dependent`] names:
//!
//! - a verdict from an old tip is not cached: the transaction is verified again at the current tip
//!   (as upstream already does for a success from an old tip);
//! - a missing-input failure keeps the transaction here, as ycashd's orphan pool does, and it is
//!   verified again when a transaction it spends from enters the mempool, and when the tip grows or
//!   resets, at most [`MAX_RETRIES`] times; at most [`MAX_ORPHANS`] are kept (ycashd's
//!   `DEFAULT_MAX_ORPHAN_TRANSACTIONS`).
//!
//! A failure that does not depend on the tip is cached as upstream does.

use std::collections::{HashMap, HashSet, VecDeque};

use zakura_chain::{
    block::Height,
    transaction::{self, UnminedTx, UnminedTxId},
    transparent,
};
use zakura_consensus::error::TransactionError;
use zakura_node_services::mempool::QueueSource;
use zakura_state::ValidateContextError as ContextError;

/// ycashd's `DEFAULT_MAX_ORPHAN_TRANSACTIONS`.
pub const MAX_ORPHANS: usize = 100;

/// How many times one transaction is verified again before it is dropped.
pub const MAX_RETRIES: u8 = 10;

/// Returns true if `error` depends on this node's tip (or mempool) state rather than on the
/// transaction: the verdict can change when a block or a parent transaction arrives.
pub fn is_tip_state_dependent(error: &TransactionError) -> bool {
    use TransactionError::*;
    match error {
        VaultRejected { byte_level, .. } => !byte_level,
        VaultTemplateSetState { .. } | YellowbackRejected { .. } => true,
        ValidateContextError(error) => matches!(
            **error,
            ContextError::UnsatisfiedSequenceLock { .. }
                | ContextError::MissingTransparentOutput { .. }
        ),
        _ => is_missing_input(error),
    }
}

/// Returns true if `error` is a missing input: a parent this node does not have yet (ycashd's
/// orphan, `fMissingInputs`).
pub fn is_missing_input(error: &TransactionError) -> bool {
    match error {
        TransactionError::TransparentInputNotFound => true,
        TransactionError::ValidateContextError(error) => {
            matches!(**error, ContextError::MissingTransparentOutput { .. })
        }
        _ => false,
    }
}

/// Returns true if a failure with `error`, verified with the best tip at `verified_tip`, is a
/// verdict from an old tip that must be verified again at `best_tip`.
pub fn is_stale(
    error: &TransactionError,
    verified_tip: Option<Height>,
    best_tip: Option<Height>,
) -> bool {
    verified_tip != best_tip && is_tip_state_dependent(error)
}

/// A transaction to verify again, and the peer that relayed it.
pub type Retry = (UnminedTx, Option<QueueSource>);

/// The transactions kept for another verification.
#[derive(Debug, Default)]
pub struct StateRetries {
    /// The bytes of each recent tip-state-dependent failure, delivered by the downloader before its
    /// result. Taken by [`Self::take_failed`] when the failure is handled.
    failed: HashMap<UnminedTxId, Retry>,

    /// The kept missing-input transactions (ycashd's orphans), oldest first.
    orphans: VecDeque<UnminedTxId>,

    /// The orphans' transactions and the parents they spend from.
    orphan_entries: HashMap<UnminedTxId, (Retry, HashSet<transaction::Hash>)>,

    /// How many times each transaction was verified again.
    attempts: HashMap<UnminedTxId, u8>,
}

impl StateRetries {
    /// Records the bytes of a tip-state-dependent failure (from the downloader).
    pub fn record_failed(&mut self, failures: impl IntoIterator<Item = Retry>) {
        for (tx, source) in failures {
            self.failed.insert(tx.id(), (tx, source));
        }
        // Bounded like the orphans: a failure whose result never arrives (cancelled) is dropped.
        if self.failed.len() > MAX_ORPHANS {
            self.failed.clear();
        }
    }

    /// Takes the bytes of the failure of `txid`, if recorded.
    pub fn take_failed(&mut self, txid: &UnminedTxId) -> Option<Retry> {
        self.failed.remove(txid)
    }

    /// Counts one more verification of `txid`. Returns false if it was verified again too often.
    pub fn count_attempt(&mut self, txid: UnminedTxId) -> bool {
        if self.attempts.len() > MAX_ORPHANS * usize::from(MAX_RETRIES) {
            self.attempts.clear();
        }
        let attempts = self.attempts.entry(txid).or_insert(0);
        *attempts = attempts.saturating_add(1);
        *attempts <= MAX_RETRIES
    }

    /// Keeps `retry` as an orphan, dropping the oldest orphan beyond [`MAX_ORPHANS`].
    pub fn keep_orphan(&mut self, retry: Retry) {
        let txid = retry.0.id();
        let parents = retry
            .0
            .transaction()
            .inputs()
            .iter()
            .filter_map(transparent::Input::outpoint)
            .map(|outpoint| outpoint.hash)
            .collect();
        if self.orphan_entries.insert(txid, (retry, parents)).is_none() {
            self.orphans.push_back(txid);
        }
        while self.orphans.len() > MAX_ORPHANS {
            if let Some(oldest) = self.orphans.pop_front() {
                self.orphan_entries.remove(&oldest);
                self.attempts.remove(&oldest);
            }
        }
    }

    /// Takes every orphan (the tip grew or reset).
    pub fn take_orphans(&mut self) -> Vec<Retry> {
        self.orphans
            .drain(..)
            .filter_map(|txid| self.orphan_entries.remove(&txid))
            .map(|(retry, _parents)| retry)
            .collect()
    }

    /// Takes the orphans that spend from one of `parents` (they entered the mempool).
    pub fn take_children_of(&mut self, parents: &HashSet<transaction::Hash>) -> Vec<Retry> {
        if parents.is_empty() || self.orphans.is_empty() {
            return Vec::new();
        }
        let children: Vec<UnminedTxId> = self
            .orphans
            .iter()
            .filter(|txid| {
                self.orphan_entries
                    .get(txid)
                    .is_some_and(|(_retry, spends)| !spends.is_disjoint(parents))
            })
            .copied()
            .collect();
        self.orphans.retain(|txid| !children.contains(txid));
        children
            .iter()
            .filter_map(|txid| self.orphan_entries.remove(txid))
            .map(|(retry, _parents)| retry)
            .collect()
    }

    /// Forgets `txid`: it entered the mempool.
    pub fn accepted(&mut self, txid: &UnminedTxId) {
        self.attempts.remove(txid);
        self.failed.remove(txid);
    }

    /// The number of kept orphans.
    #[cfg(test)]
    pub fn orphan_count(&self) -> usize {
        self.orphans.len()
    }
}

#[cfg(test)]
mod tests {
    use zakura_chain::block::Height;
    use zakura_consensus::error::TransactionError;

    use super::*;

    #[test]
    fn the_tip_state_errors_are_named() {
        // `ValidateContextError::MissingTransparentOutput` is non-exhaustive outside its crate; it
        // is matched like `TransparentInputNotFound`.
        let error = TransactionError::TransparentInputNotFound;
        assert!(is_tip_state_dependent(&error), "{error}");
        assert!(is_missing_input(&error), "{error}");
        for error in [
            TransactionError::VaultRejected {
                reason: "set-unknown".into(),
                height: Height(10),
                byte_level: false,
            },
            TransactionError::YellowbackRejected {
                reason: "mint".into(),
            },
            TransactionError::VaultTemplateSetState {
                input_index: 0,
                script_error: "SetSig".into(),
            },
        ] {
            assert!(is_tip_state_dependent(&error), "{error}");
            assert!(!is_missing_input(&error), "{error}");
        }
        // A malformed act, a bad balance, a failing script: the transaction's own fault.
        for error in [
            TransactionError::VaultRejected {
                reason: "bad-act".into(),
                height: Height(10),
                byte_level: true,
            },
            TransactionError::BadBalance,
            TransactionError::Script(zakura_script::Error::ScriptInvalid),
        ] {
            assert!(!is_tip_state_dependent(&error), "{error}");
        }

        // Stale: verified at another tip than the best one.
        let missing = TransactionError::TransparentInputNotFound;
        assert!(is_stale(&missing, Some(Height(5)), Some(Height(6))));
        assert!(!is_stale(&missing, Some(Height(6)), Some(Height(6))));
        assert!(!is_stale(
            &TransactionError::BadBalance,
            Some(Height(5)),
            Some(Height(6))
        ));
    }

    /// The vectors' non-coinbase transactions.
    fn transactions() -> impl Iterator<Item = UnminedTx> {
        zakura_chain::parameters::Network::Mainnet
            .unmined_transactions_in_blocks(..)
            .map(|tx| tx.transaction)
            .filter(|tx| !tx.transaction().is_coinbase())
    }

    /// `transaction` with its first input spending output 0 of `parent`.
    fn spending(transaction: &UnminedTx, parent: &UnminedTx) -> UnminedTx {
        let mut transaction = (**transaction.transaction()).clone();
        if let Some(transparent::Input::PrevOut { outpoint, .. }) = transaction
            .inputs_mut()
            .iter_mut()
            .find(|input| input.outpoint().is_some())
        {
            *outpoint = transparent::OutPoint::from_usize(parent.id().mined_id(), 0);
        }
        transaction.into()
    }

    /// ycashd's orphan processing: an orphan is verified again when a transaction it spends from
    /// enters the mempool, and only then; every orphan when the tip changes.
    #[test]
    fn orphans_follow_their_parents() {
        let mut txs = transactions();
        let (parent, a, b) = (
            txs.next().unwrap(),
            txs.next().unwrap(),
            txs.next().unwrap(),
        );
        let child = spending(&a, &parent);
        let mut retries = StateRetries::default();
        retries.keep_orphan((child.clone(), None));
        retries.keep_orphan((b.clone(), None));
        assert_eq!(retries.orphan_count(), 2);

        let unrelated: HashSet<_> = [b.id().mined_id()].into();
        assert!(retries.take_children_of(&unrelated).is_empty());
        let parents: HashSet<_> = [parent.id().mined_id()].into();
        let children = retries.take_children_of(&parents);
        assert_eq!(
            children.iter().map(|(tx, _)| tx.id()).collect::<Vec<_>>(),
            [child.id()]
        );
        assert_eq!(retries.orphan_count(), 1);

        assert_eq!(
            retries
                .take_orphans()
                .iter()
                .map(|(tx, _)| tx.id())
                .collect::<Vec<_>>(),
            [b.id()]
        );
        assert_eq!(retries.orphan_count(), 0);
    }

    #[test]
    fn attempts_and_orphans_are_bounded() {
        let mut retries = StateRetries::default();
        let txid = UnminedTxId::Legacy(transaction::Hash([7; 32]));
        for _ in 0..MAX_RETRIES {
            assert!(retries.count_attempt(txid));
        }
        assert!(!retries.count_attempt(txid));
        retries.accepted(&txid);
        assert!(retries.count_attempt(txid));

        // At most MAX_ORPHANS, the oldest dropped first.
        let tx = transactions().next().unwrap();
        for index in 0..=MAX_ORPHANS {
            let parent = transactions().next().unwrap();
            let mut orphan = (**tx.transaction()).clone();
            if let Some(transparent::Input::PrevOut { outpoint, .. }) =
                orphan.inputs_mut().first_mut()
            {
                *outpoint = transparent::OutPoint::from_usize(parent.id().mined_id(), index);
            }
            retries.keep_orphan((orphan.into(), None));
        }
        assert_eq!(retries.orphan_count(), MAX_ORPHANS);
    }
}
