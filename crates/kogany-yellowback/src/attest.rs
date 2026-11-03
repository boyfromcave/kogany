// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

//! Price attestation (chunk W5-c): the 74-byte attestations, bundles, the attestor registry
//! mirrored from `attestorSetId`'s set acts, EQV-1 by key trial, liveness by attestation, seats
//! and selection, and the reference price a bundle yields. A port by meaning of ycash6
//! `src/yellowback/{attest,bundle}.{h,cpp}` and the attestor parts of `state.cpp`, `view.h` and
//! `module.cpp` at `65cb4ae0f`, checked by `testdata/yellowback/yellowback_attest_vectors.json`.
//!
//! | module | ycash6 source | what |
//! |---|---|---|
//! | [`attestation`] | `attest.{h,cpp}` | the 74-byte form, `AttestMessage`, `CancelCosignMessage`, strict low-S verification |
//! | [`bundle`] | `bundle.{h,cpp}` | `"YA"` bundles, `"YC"` co-signatures, `"YX"` evidence, `ExtractBundle`, the signature cache, `VerifyBundle`, `BundleStat` |
//! | [`registry`] | `view.{h,cpp}` | `Attestors`, `AttestorSet`, `Attest`, `BundleLog` records, keys, encodings; the store traits |
//! | [`seats`] | `state.cpp` | weights, seat rank, eviction, `Seated`, `SelectAttestors`/`Selected`, the SNAP attestor passes |
//! | [`mirror`] | `state.cpp` | the set acts on the mirror, the bond spend, EQV-1 on the mirror, the liveness credit |
//! | [`equivocation`] | `state.cpp` | `EquivocationEvidence`, `EquivocatedBy` |
//! | [`liveness`] | `state.cpp` | `AttestationLiveness` |
//! | [`hooks`] | `module.cpp` | the primitive-side hooks over [`kogany_vault::state::StateRead`] |
//! | [`price`] | `state.cpp`, `index.{h,cpp}` | `VerifyTxBundle`, the bundle log, the fee price |
//!
//! Everything is pure: no chain, clock, network or configuration. The chain enters as closures
//! (`blockHashAt`, `BondMinZat`) and store traits, so the state machine (W5-d), the index (W5-e)
//! and the module registration (W5-f) wire it in.

pub mod attestation;
pub mod bundle;
pub mod equivocation;
pub mod hooks;
pub mod liveness;
pub mod mirror;
pub mod price;
pub mod registry;
pub mod seats;

pub use attestation::{
    attest_message, cancel_cosign_message, decode_attestation, encode_attestation,
    verify_compact_sig, verify_compact_sig_key, Attestation, ATTESTATION_SIZE,
};
pub use bundle::{
    attestation_valid, bundle_stat, decode_bundle, decode_cancel_cosigns, decode_cancel_evidence,
    encode_bundle, encode_cancel_cosigns, encode_cancel_evidence, extract_bundle, sig_cache_key,
    verify_bundle, Bundle, BundleError, BundleLimits, BundleSource, CancelCosignEntry,
    CancelStatement, SigCache,
};
pub use equivocation::{equivocated_by, equivocation_evidence, Equivocation};
pub use liveness::attestation_liveness;
pub use registry::{
    AttestState, AttestStatus, AttestorRecord, AttestorSetRecord, AttestorStatus, BundleLogRecord,
    Registry, RegistryRead, RegistryWrite,
};
pub use seats::{
    age_origin, attestor_weight, default_attest_payee, eviction_victim, outpoint_selector,
    seat_rank, seated, select_attestors, selected, SeatCandidate, SelectionBasis,
};
