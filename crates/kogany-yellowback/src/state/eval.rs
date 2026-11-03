// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

//! One transaction's evaluation context (the C++ `EvalContext` of `state.cpp`): the
//! transaction's own write overlay over the running block state, the parameters, the height, the
//! signature cache, and the bundles its held rules committed (R12: they reach the block's
//! [`crate::attest::price::BundleLogAccumulator`] only when the whole transaction passes; a
//! failing transaction makes the block invalid anyway).

use std::collections::BTreeSet;

use kogany_vault::state::VaultTx;

use super::lookups::{block_hash_at, eligible_payees, p2pkh_key, selection_basis, snapshot_at};
use super::records::{Snapshot, TxLogRecord};
use super::view::{YedOverlay, YedRead};
use crate::attest::bundle::SigCache;
use crate::attest::price::{bundle_facts, BundleFacts};
use crate::attest::registry::RegistryRead;
use crate::params::{Amount, Params};

/// The evaluation of one transaction at `height` over `st`.
pub(crate) struct Eval<'a, 'p> {
    /// The transaction's overlay over the running block state.
    pub(crate) st: YedOverlay<'a>,
    pub(crate) p: &'p Params,
    pub(crate) h: i64,
    pub(crate) cache: Option<&'p dyn SigCache>,
    /// `CommitBundle`'s facts, in commit order.
    pub(crate) commits: Vec<BundleFacts>,
}

impl<'a, 'p> Eval<'a, 'p> {
    pub(crate) fn new(
        base: &'a dyn YedRead,
        p: &'p Params,
        h: i64,
        cache: Option<&'p dyn SigCache>,
    ) -> Eval<'a, 'p> {
        Eval {
            st: YedOverlay::new(base),
            p,
            h,
            cache,
            commits: Vec::new(),
        }
    }

    /// `ctx.Snap(h)`.
    pub(crate) fn snap(&self, h: i64) -> Option<Snapshot> {
        snapshot_at(&self.st, self.p, h)
    }

    /// `ctx.Armed(R)`: ARMED at R (W15 folded in).
    pub(crate) fn armed(&self, r: i64) -> bool {
        self.snap(r)
            .is_some_and(|s| self.p.is_armed(s.attest.is_armed()))
    }

    /// `ctx.Eligible(R)`.
    pub(crate) fn eligible(&self, r: i64) -> Vec<[u8; 20]> {
        eligible_payees(&self.st, self.p, r)
    }

    /// `ctx.Bundle`: BUNDLE-1 at R for `tx`, nothing recorded.
    pub(crate) fn bundle(
        &self,
        tx: &VaultTx,
        r: i64,
        selector: &[u8],
        skip_vin0: bool,
    ) -> BundleFacts {
        let basis = selection_basis(&self.st, self.p, r);
        let hash_at = |h: i64| block_hash_at(&self.st, self.p, h);
        bundle_facts(
            tx,
            self.p,
            r,
            selector,
            skip_vin0,
            basis.as_ref(),
            &self.st,
            &hash_at,
            self.cache,
        )
    }

    /// `ctx.CommitBundle`: a held rule's verified bundle enters BundleLog[H] (R12, 03/M-2).
    pub(crate) fn commit_bundle(&mut self, f: &BundleFacts) {
        if f.verified() {
            self.commits.push(f.clone());
        }
    }

    /// AFEE-1 (the attestor-fee clause of MINT-8 / RED-3): `vout[attestFeeVout]` is
    /// `P2PKH(bondPubKey(s))` for some `s` in `a`, pays at least `fee` and is none of
    /// `excluded`. The payee's seq.
    pub(crate) fn attest_fee_ok(
        &self,
        tx: &VaultTx,
        attest_fee_vout: u8,
        a: &[u16],
        excluded: &BTreeSet<usize>,
        fee: Amount,
    ) -> Option<u16> {
        let v = usize::from(attest_fee_vout);
        if attest_fee_vout == crate::params::FEE_VOUT_NONE || excluded.contains(&v) {
            return None;
        }
        let out = tx.outputs.get(v)?;
        let key = p2pkh_key(&out.script_pubkey)?;
        if out.value < fee {
            return None;
        }
        a.iter().copied().find(|seq| {
            self.st.attestor(*seq).is_some_and(|rec| {
                rec.bond_pub_key.is_compressed()
                    && kogany_vault::template::hash160(&rec.bond_pub_key.0) == key
            })
        })
    }
}

/// `LogBundle`: the TxLog fields a verified bundle fills.
pub(crate) fn log_bundle(log: &mut TxLogRecord, f: Option<&BundleFacts>) {
    let Some(f) = f else {
        return;
    };
    let Ok(v) = &f.verdict else {
        return;
    };
    log.a_mint = v.a_mint.unwrap_or(0);
    log.a_claim = v.a_claim.unwrap_or(0);
    log.bundle_seqs = f.seqs();
}
