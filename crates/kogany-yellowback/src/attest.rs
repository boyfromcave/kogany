// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

//! Price attestation (chunk W5-c, not yet implemented): the 74-byte attestations, bundles, the
//! attestor registry mirrored from `attestorSetId`'s set acts, and EQV-1 by key trial — ycash6
//! `src/yellowback/{attest,bundle}.{h,cpp}`, checked by `testdata/yellowback/
//! yellowback_attest_vectors.json`. The bundle statistic itself is
//! [`crate::math::weighted_quantile`] over [`crate::math::bond_weight`].
