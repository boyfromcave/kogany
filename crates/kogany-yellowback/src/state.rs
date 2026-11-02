// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

//! The YED state machine (chunks W5-d1, W5-d2): a port by meaning of ycash6
//! `src/yellowback/{view,state}.{h,cpp}` at `65cb4ae0f` over this crate's [`crate::math`],
//! [`crate::params`], [`crate::codecs`] and [`crate::attest`] layers.
//!
//! | module | ycash6 source | what |
//! |---|---|---|
//! | [`records`] | `view.h` | Tip, Tags, Judgements, Vaults, Tokens, TxLog, Totals, Notices, Intents, Snapshots, Params and their canonical encodings |
//! | [`keys`] | `view.cpp` `keys::*` | the typed key space ([`YedKey`], canonical byte order) and [`YedRecord`] |
//! | [`view`] | `view.{h,cpp}` | [`YedRead`], [`YedState`], [`YedOverlay`], [`YedDelta`], the state hash |
//! | [`lookups`] | `state.cpp` | `SnapshotAt`, `TagAt`, `BlockHashAt`, `EligiblePayees`, `BondMinZat`, `CancelsRequired`, … |
//! | [`verdict`] | `state.cpp` | the §4.2a verdict strings |
//! | `mint` | `state.cpp` | MINT-1..10, AFEE-1′ |
//! | `transfer` | `state.cpp` | XFER-1..3, TOK-PQ |
//! | `redeem` | `state.cpp` | RED-1..5 over an ACTIVE vault: the owner's redeem (IT-9′) and the claim into intents (U-23) |
//! | `intent` | `state.cpp` | an intent's release and cancel: CAN-1/2/3, C4b |
//! | [`tx`] | `state.cpp` `ProcessTxImpl` | [`process_tx`]: IN-1..3, the mirror's set acts, NOT-1, EQV-1, liveness, U-23's output rule |
//! | [`block`] | `state.cpp` `EvaluateBlock`, `ComputeSnapshot` | [`evaluate_block`]: TAG, BLK-1, BundleLog, SNAP (REG-4, PIN, seating, PRICE-1, SIGMA-1, HALT-1..3, S15) |
//! | [`policy`] | `state.cpp`, `view.cpp` | REG-1..3 and FEE-W (`Registered`, `Penalized`, `AccuracyBps`, `PayeePolicy`, `DefaultPayee`), `OpenDebtInvariantViolation`, `HaltMaskNames` |
//! | [`mempool`] | `index.cpp` `MempoolCheckInner` | [`mempool_check_reason`]: the mempool-time check and its reasons (K7, MP-1) |
//!
//! **State and delta model** (mirroring `kogany_vault::state`): state is a `BTreeMap` from
//! [`YedKey`] to [`YedRecord`]; [`evaluate_block`] evaluates a block over a read-only
//! `&dyn YedRead` base — each transaction on its own overlay ([`process_tx`]), merged into the
//! block overlay only when it passes — and returns the block's [`YedDelta`] (every written key
//! with its value before and after). [`YedState::apply`] moves a state forward by it and
//! [`YedState::revert`] back byte for byte (the C++ `UndoBlock`). The node's store (W5-e)
//! implements [`YedRead`] over its column families and writes [`YedDelta::canonical_entries`];
//! [`state_hash`] is the `yed_getstatehash` digest over any [`YedRead`].
//!
//! Every function is total (K1, M1): no input makes one panic, a lookup that misses makes the
//! rule reading it false. Nothing reads a clock, the network, a wallet or configuration.

pub mod block;
pub(crate) mod codec;
pub(crate) mod eval;
mod intent;
pub mod keys;
pub mod lookups;
pub mod mempool;
mod mint;
pub mod policy;
pub mod records;
mod redeem;
mod transfer;
pub mod tx;
pub mod verdict;
pub mod view;

pub use block::{compute_snapshot, display_hex, evaluate_block, BlockEvaluation};
pub use keys::{Table, YedKey, YedRecord};
pub use lookups::{
    armed_at, block_hash_at, bond_min_zat, cancel_q, cancels_required, eligible_payees,
    judgement_at, p2pkh_key, selection_basis, snapshot_at, tag_at, RegistryView,
};
pub use mempool::{mempool_check_reason, MEMPOOL_EXPIRY, UNHEALTHY};
pub use policy::{
    accuracy_bps, default_payee, halt_mask_names, open_debt_invariant_violation, penalized,
    registered, PayeePolicy,
};
pub use records::{
    is_null_outpoint, AssignedOutput, IntentRecord, IntentRole, Judgement, NoticeRecord,
    ParamsRecord, Snapshot, TagRecord, TipRecord, TokenRecord, Totals, TxLogRecord, TxLogType,
    VaultRecord, VaultStatus, NULL_OUTPOINT, SCHEMA_VERSION,
};
pub use tx::{process_tx, TxEffect, TxOutcome};
pub use view::{
    canonical_entries_of, state_hash, state_hash_preimage, CanonicalChange, Change, Writes,
    YedDelta, YedOverlay, YedRead, YedState,
};
