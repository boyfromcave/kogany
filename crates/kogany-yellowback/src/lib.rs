// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

//! Ycash Yellowback (YED): the rule module of the vault network upgrade, rewritten in Rust for
//! kogany (plan K-4 (a)) from ycash6 `src/yellowback/`.
//!
//! The module is built bottom up in the order of the plan's §1.6 (`math.h` → `params` →
//! `payload/script/address/tag` → `attest/bundle` → `view/state` → `index` → registration), one
//! chunk per layer:
//!
//! | module | ycash6 source | chunk | status |
//! |---|---|---|---|
//! | [`math`] | `src/yellowback/math.h`, `src/arith_uint256.h` | W5-a | done |
//! | [`params`] | `src/yellowback/params.{h,cpp}`, `src/amount.h` | W5-a | done |
//! | [`codecs`] | `payload`, `script`, `address`, `tag` | W5-b | stub |
//! | [`attest`] | `attest`, `bundle` | W5-c | stub |
//! | [`state`] | `view`, `state` | W5-d1/d2 | stub |
//!
//! Every layer is pure: no chain, clock, network, configuration or floating point, and no
//! dependency on the `zakura-*` crates (the hook chunks W5-e/f wire it into the node). Consensus
//! equality with the C++ lines is checked by the pinned cross-line vectors in
//! `testdata/yellowback/` (plan §4.2 rule 4) and, for the parameters, by parsing ycash6's
//! `params.cpp` (`tests/params_cpp.rs`).
//!
//! Naming (workspace rule 6): Yellowback is the system, YED is the unit.

#![forbid(unsafe_code)]
// Determinism disciplines (plan §4.2 rule 6); `clippy.toml` lists the disallowed types.
#![deny(clippy::arithmetic_side_effects)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::indexing_slicing)]
#![deny(clippy::panic)]
#![deny(clippy::float_arithmetic)]
#![deny(clippy::float_cmp)]
#![deny(clippy::disallowed_types)]
#![deny(clippy::disallowed_methods)]
#![deny(missing_docs)]

pub mod attest;
pub mod codecs;
pub mod math;
pub mod params;
pub mod state;
