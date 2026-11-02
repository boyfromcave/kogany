//! The Vault network upgrade's lock/unlock primitive for kogany (plan W4-a).
//!
//! A byte-exact port, by meaning, of ycash6 `upgrade/vault` `src/vault/template.{h,cpp}` and
//! `src/vault/act.{h,cpp}` (docs/plans/yellowback-upgrade-plan.md §15.2, §15.3, §15.5):
//!
//! - [`template`]: the vault V and intent I (bare scriptPubKeys) and the member bond B (a P2SH
//!   redeem script); builders emit the exact byte shapes with minimal pushes, parsers accept
//!   only those shapes (parse, rebuild, compare bytes); the template-input selector (the
//!   scriptSig's last push, `OP_1..OP_4`).
//! - [`act`]: the `YV` OP_RETURN act codec, the two signed messages (`actMsg`, `setSigMsg`)
//!   and strict recoverable-signature recovery.
//! - [`bytes`]: the crate's own fixed-size byte types and their canonical encodings.
//! - [`state`]: the boundary reserved for the set state machine (W4-b); empty here.
//!
//! The crate depends on no zakura crate: it reads and writes bytes only, so it can be checked
//! against the pinned cross-line vectors (`testdata/yellowback/vault_vectors.json`) on its own.

#![deny(
    clippy::arithmetic_side_effects,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::float_arithmetic,
    clippy::panic,
    clippy::disallowed_types
)]

pub mod act;
pub mod bytes;
pub mod script;
pub mod state;
pub mod template;

pub use bytes::{Hash32, OutPoint, PqOwner, PubKeyBytes, RecoverableSig, SetId, Tag};
