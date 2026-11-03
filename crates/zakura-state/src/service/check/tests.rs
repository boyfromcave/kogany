//! Tests for state contextual validation checks.

#![allow(clippy::unwrap_in_result)]

mod anchors;
mod nullifier;
// kogany (W3-d): BIP68 relative lock-times.
mod sequence_locks;
mod utxo;
// kogany (W4-d): the Vault upgrade's sequential act and template rules.
mod vault;
mod vectors;
