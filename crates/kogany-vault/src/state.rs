//! The set state machine's boundary (plan W4-b `set-state`; not implemented in W4-a).
//!
//! W4-b fills this module with the port of ycash6 `src/vault/state.{h,cpp}` and the canonical
//! `statehash` preimage of `src/vault/node.cpp` (`SERIALISATION.md`): `ApplyTx` / `ApplyBlock`
//! over members, seats, maturity, liveness, dormancy and release, the rate limit, the bond and
//! template-output indexes, and the module table with `YED\0` inert.
//!
//! Rules for what lands here:
//!
//! - State is held in `BTreeMap` / `BTreeSet` only (the crate's `clippy.toml` disallows the
//!   hashed collections).
//! - The canonical `statehash` encoder is a pure function of the state and stays separate from
//!   anything storage-shaped (column families and DB formats belong to W4-c in zakura-state).
//! - The state machine consumes this crate's [`crate::template`] and [`crate::act`] parsers;
//!   it never re-parses scripts itself.
