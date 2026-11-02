//! The set state machine (plan W4-b `set-state`): a port by meaning of ycash6
//! `src/vault/state.{h,cpp}`, the canonical `statehash` of `src/vault/node.cpp` and the module
//! table of `src/vault/module.{h,cpp}` (docs/plans/yellowback-upgrade-plan.md §15.4–§15.7).
//!
//! - [`records`]: the four record kinds (`SetRecord`, `MemberRecord`, `BondRecord`,
//!   `TemplateOutRecord`), their canonical keys and byte encodings.
//! - [`view`]: [`StateRead`] (the read interface and the §15.4 snapshot queries script
//!   evaluation needs: [`StateRead::threshold`], [`StateRead::check_set_sigs`],
//!   [`StateRead::is_released`]), the in-memory [`SetState`] and the per-block [`Delta`].
//! - [`overlay`]: the rules — [`apply_block`], [`check_tx`], the write overlay
//!   [`VaultOverlay`] (`ApplyTx` / `ApplyBlock` / `ApplyAct`), [`Rules`].
//! - [`module`]: the [`Module`] trait and the compile-time table, `YED\0` registered inert.
//! - [`hash`]: the canonical `statehash` preimage and digest, separate from any storage.
//! - [`audit`]: the locked-value invariant audit (C++ `AuditLockedValue`).
//!
//! State is held in `BTreeMap` / `BTreeSet` only. The rules consume this crate's
//! [`crate::template`] and [`crate::act`] parsers and never re-parse scripts themselves.
//!
//! **Delta model** (for W4-c): `apply_block(&parent, txs, height, coins, rules)` returns the
//! block's [`Delta`] — every changed entry with its value before and after — without touching
//! `parent`. [`SetState::apply`] moves a state forward by a delta and [`SetState::revert`] moves
//! it back byte for byte (a reorg), and [`SetState::with`] is the copying form. A store that is
//! not a `SetState` implements [`StateRead`] and writes [`Delta::canonical_entries`] (or the
//! typed maps) itself.

pub mod audit;
pub mod hash;
pub mod module;
pub mod overlay;
pub mod records;
mod reject;
pub mod tx;
pub mod view;

pub use audit::{audit_locked_value, SetValueAudit};
pub use hash::{display_hex, state_hash_of_entries};
pub use module::{
    find_module, registered_modules, BlockHashFn, InertModule, Module, ModuleContext, ModuleEntry,
    YED_TAG,
};
pub use overlay::{apply_block, check_tx, eject_and_freeze, Rules, VaultOverlay, MIN_SET_MATURITY};
pub use records::{
    BondRecord, MemberRecord, MemberStatus, SetRecord, TemplateOutKind, TemplateOutRecord,
};
pub use reject::VaultReject;
pub use tx::{CoinAccessor, SpentCoin, VaultTx, VaultTxIn, VaultTxOut};
pub use view::{
    count_active, count_current, is_current, is_dormant, is_released, money_range, rate_cap,
    Change, Delta, MemberList, SetState, StateRead,
};
