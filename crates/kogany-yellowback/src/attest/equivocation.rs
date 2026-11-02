// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

//! EQV-1, equivocation by key trial: two signed prices at one cited height by one key — two
//! attestations of one seq (a `"YA"` bundle of two), or (C4b) an attestation and a cancel
//! statement (`"YX"`) — eject the member and freeze its bond. ycash6 `src/yellowback/state.cpp`
//! `EquivocationEvidence`, `EquivocatedBy` at `65cb4ae0f`.
//!
//! The evidence carries no key: whoever applies it tries the candidate keys (the primitive's
//! members of the attestor set in key order, [`super::hooks::yed_ejections`]; the mirror's
//! newest records in seq order, [`super::mirror::apply_equivocation`]). Never through the
//! signature cache: it is keyed by the key it was verified under, which is what is being found.

use kogany_vault::act::recover_sig;
use kogany_vault::state::VaultTx;
use kogany_vault::{Hash32, PubKeyBytes};

use super::attestation::{
    attest_message, cancel_cosign_message, verify_compact_sig_key, Attestation,
};
use super::bundle::{
    decode_bundle, decode_cancel_evidence, extract_bundle, CancelStatement, MAX_ENCODABLE_COUNT,
};
use crate::codecs::payload::{find_payload, PayloadType};
use crate::params::Params;

/// EQV-1's evidence (`Equivocation`): `a` and either a second attestation `b` or a cancel
/// statement `s`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Equivocation {
    /// Two attestations of one seq at one cited height with different prices.
    Attestations(Attestation, Attestation),
    /// An attestation and a cancel statement at its cited height with a different price.
    CancelStatement(Attestation, CancelStatement),
}

impl Equivocation {
    /// The regular attestation (`e.a`): its seq and cited height name the evidence.
    pub fn attestation(&self) -> &Attestation {
        match self {
            Equivocation::Attestations(a, _) | Equivocation::CancelStatement(a, _) => a,
        }
    }
}

/// The output scripts of a transaction, in order.
pub(crate) fn output_scripts(tx: &VaultTx) -> Vec<&[u8]> {
    tx.outputs
        .iter()
        .map(|o| o.script_pubkey.as_slice())
        .collect()
}

/// `EquivocationEvidence` (structure only): an EQUIVOCATION payload whose carrier (under
/// `BUNDLE_CARRIER`, vin 0 not skipped, no payload tail) holds two attestations sharing a seq and
/// a cited height with different prices, or one attestation and one cancel statement whose price
/// differs; `citedHeight >= START_HEIGHT`. No key, block hash or state is read.
pub fn equivocation_evidence(tx: &VaultTx, p: &Params) -> Option<Equivocation> {
    let fp = find_payload(&output_scripts(tx))?;
    if fp.payload.payload_type() != PayloadType::Equivocation {
        return None;
    }
    let (bytes, _) = extract_bundle(tx, p.bundle_carrier, false, &[]).ok()?;
    let e = if let Some(bundle) = decode_bundle(&bytes, MAX_ENCODABLE_COUNT) {
        let [a, b] = bundle.atts.as_slice() else {
            return None;
        };
        if a.seq != b.seq
            || a.cited_height != b.cited_height
            || a.price_micro_usd == b.price_micro_usd
        {
            return None;
        }
        Equivocation::Attestations(*a, *b)
    } else {
        let (a, s) = decode_cancel_evidence(&bytes)?;
        if a.price_micro_usd == s.price_micro_usd {
            return None;
        }
        Equivocation::CancelStatement(a, s)
    };
    (i64::from(e.attestation().cited_height) >= i64::from(p.start_height)).then_some(e)
}

/// `EquivocatedBy`: both sides verify under `key` over `block_hash` (the hash at the cited
/// height); a cancel statement's message names `attestor_set_id` and its signature must recover
/// to `key`.
pub fn equivocated_by(
    e: &Equivocation,
    key: &PubKeyBytes,
    block_hash: &Hash32,
    attestor_set_id: &Hash32,
) -> bool {
    let a = e.attestation();
    let signed = |x: &Attestation| {
        verify_compact_sig_key(
            key,
            &attest_message(x.seq, x.price_micro_usd, x.cited_height, block_hash),
            &x.sig,
        )
    };
    if !signed(a) {
        return false;
    }
    match e {
        Equivocation::Attestations(_, b) => signed(b),
        Equivocation::CancelStatement(_, s) => {
            let msg = cancel_cosign_message(
                attestor_set_id,
                &s.intent.txid,
                s.intent.n,
                a.cited_height,
                s.price_micro_usd,
                block_hash,
            );
            recover_sig(&msg, &s.sig).is_some_and(|signer| signer == *key)
        }
    }
}
