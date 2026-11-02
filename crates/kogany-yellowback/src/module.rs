// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

//! The YED rule module as the vault primitive sees it (plan W5-f): ycash6
//! `src/yellowback/module.{h,cpp}` at `65cb4ae0f`, `yellowback::Module`, registered for the tag
//! `YED\0`, and `src/yellowback/index.h` `LruSigCache`, the node-local signature cache the module
//! and the index share.
//!
//! The module's rules are split by what they read, as on the C++ lines:
//!
//! - [`YedModule::validate_create`] / [`YedModule::validate_spend`] need only the network's YED
//!   parameters: a YED vault names the attestor set as both its sets, `CLAIM_DELAY` as its delay
//!   and `lockHeight + GRACE` as its `appHeight` bound (U-23, IT-1); a YED vault is never unlocked
//!   by the set (selector 1) and a YED intent is never taken by its owner on set release
//!   (selector 3).
//! - Everything that reads the module's own state is [`crate::state::evaluate_block`], which the
//!   node's index runs as a consensus rejection (DoS 100, `bad-yellowback-<verdict>`, U-21);
//!   [`YedModule::check_block`] holds only the structural attestor-set rule.
//! - The hooks on the primitive's set state (ejection, displacement, liveness) are
//!   [`crate::attest::hooks`].
//!
//! ycash6 configures one global instance at init (`SetModuleParams`); an unconfigured module
//! accepts everything (the YED tag is then governed by the primitive alone, §5.4). Here the node
//! builds a [`YedModule`] from the network's parameters ([`YedModule::new`] is `None` for an
//! unconfigured set, which leaves the primitive's inert entry in place) and passes the table
//! [`YedModule::table`] to the primitive's rules: the same compile-time table — exactly one
//! entry, `YED\0` — with the parameters bound per network instead of through a global.

use std::collections::BTreeMap;
use std::sync::Mutex;

use kogany_vault::act::SetJoinBody;
use kogany_vault::state::{Module, ModuleContext, ModuleEntry, VaultReject, VaultTx, YED_TAG};
use kogany_vault::template::{
    TemplateParams, TemplateSpend, VaultParams, SEL_RELEASED, SEL_UNLOCK,
};
use kogany_vault::{Hash32, PubKeyBytes, SetId};

use crate::attest::bundle::SigCache;
use crate::attest::hooks::{yed_check_block, yed_displace, yed_ejections, yed_liveness};
use crate::attest::mirror::attestor_set_id;
use crate::params::Params;

/// `bad-yellowback-vault-set`: a YED vault names another set than the attestor set.
pub const BAD_VAULT_SET: &str = "bad-yellowback-vault-set";
/// `bad-yellowback-vault-delay`: a YED vault's delay is not `CLAIM_DELAY`.
pub const BAD_VAULT_DELAY: &str = "bad-yellowback-vault-delay";
/// `bad-yellowback-vault-height`: a YED vault's `appHeight` is outside `[1, ownerHeight + GRACE]`.
pub const BAD_VAULT_HEIGHT: &str = "bad-yellowback-vault-height";
/// `bad-yellowback-vault-unlock`: a YED vault spent by the set's unlock branch.
pub const BAD_VAULT_UNLOCK: &str = "bad-yellowback-vault-unlock";
/// `bad-yellowback-intent-owner`: a YED intent taken by its owner on set release.
pub const BAD_INTENT_OWNER: &str = "bad-yellowback-intent-owner";

/// `yellowback::Module` configured with one network's YED parameters, and the signature cache
/// its liveness hook reads (C++ `ModuleContext::moduleCache`, the index's `LruSigCache`).
#[derive(Clone, Copy)]
pub struct YedModule<'c> {
    params: Params,
    cache: Option<&'c dyn SigCache>,
}

impl<'c> YedModule<'c> {
    /// The module for a configured parameter set (`SetModuleParams`), `None` when the set is not
    /// configured (no attestor set or no start height: the module is off, the primitive's inert
    /// entry stays).
    pub fn new(params: Params, cache: Option<&'c dyn SigCache>) -> Option<YedModule<'c>> {
        (params.is_configured() && attestor_set_id(&params).is_some())
            .then_some(YedModule { params, cache })
    }

    /// The parameters the module was configured with.
    pub fn params(&self) -> &Params {
        &self.params
    }

    /// The primitive's module table with this module in `YED\0`'s entry (C++ `vault::Modules()`
    /// once `SetModuleParams` has run).
    pub fn table(&self) -> [ModuleEntry<'_>; 1] {
        [(YED_TAG, self as &dyn Module)]
    }
}

impl std::fmt::Debug for YedModule<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("YedModule")
            .field("attestor_set_id", &Hash32(self.params.attestor_set_id))
            .field("start_height", &self.params.start_height)
            .field("cache", &self.cache.is_some())
            .finish()
    }
}

fn reject(reason: &str) -> Result<(), VaultReject> {
    Err(VaultReject::Module(reason.to_owned()))
}

impl Module for YedModule<'_> {
    fn validate_create(
        &self,
        _tx: &VaultTx,
        _vout: usize,
        v: &VaultParams,
        _ctx: &ModuleContext<'_>,
    ) -> Result<(), VaultReject> {
        let p = &self.params;
        let set: SetId = Hash32(p.attestor_set_id);
        // U-23: the only shape a YED vault has.
        if v.set_id != set || v.cancel_set_id != set {
            return reject(BAD_VAULT_SET);
        }
        if v.delay != i64::from(p.claim_delay) {
            return reject(BAD_VAULT_DELAY);
        }
        // IT-1: the APP branch is open (appHeight >= 1) and no later than lockHeight + GRACE.
        if v.app_height < 1 || v.app_height > v.owner_height.saturating_add(i64::from(p.grace)) {
            return reject(BAD_VAULT_HEIGHT);
        }
        Ok(())
    }

    fn validate_spend(
        &self,
        _tx: &VaultTx,
        _vin: usize,
        spend: &TemplateSpend,
        _ctx: &ModuleContext<'_>,
    ) -> Result<(), VaultReject> {
        match spend.params {
            TemplateParams::Vault(_) if spend.selector == SEL_UNLOCK => reject(BAD_VAULT_UNLOCK),
            TemplateParams::Intent(_) if spend.selector == SEL_RELEASED => reject(BAD_INTENT_OWNER),
            _ => Ok(()),
        }
    }

    fn check_block(&self, txs: &[VaultTx], _ctx: &ModuleContext<'_>) -> Result<(), VaultReject> {
        yed_check_block(&self.params, txs)
    }

    fn governed_set(&self) -> Option<SetId> {
        attestor_set_id(&self.params)
    }

    fn ejections(&self, tx: &VaultTx, ctx: &ModuleContext<'_>) -> Vec<PubKeyBytes> {
        yed_ejections(&self.params, tx, ctx)
    }

    fn displace(
        &self,
        tx: &VaultTx,
        join: &SetJoinBody,
        ctx: &ModuleContext<'_>,
    ) -> Option<PubKeyBytes> {
        yed_displace(&self.params, tx, join, ctx)
    }

    fn liveness(&self, tx: &VaultTx, ctx: &ModuleContext<'_>) -> Vec<(PubKeyBytes, i64)> {
        // ParamsAtHeight: the node holds one parameter set, so the set in force is this one.
        yed_liveness(&self.params, tx, ctx, self.cache)
    }
}

// ---- the signature cache ----------------------------------------------------------------

/// ycash6 `SIG_CACHE_ENTRIES`.
pub const SIG_CACHE_ENTRIES: usize = 16_384;

#[derive(Default)]
struct LruInner {
    /// key → (verdict, last-use tick).
    entries: BTreeMap<Hash32, (bool, u64)>,
    /// last-use tick → key (the oldest first).
    order: BTreeMap<u64, Hash32>,
    tick: u64,
    hits: u64,
    misses: u64,
}

impl LruInner {
    fn touch(&mut self, key: &Hash32) -> Option<bool> {
        let tick = self.tick.wrapping_add(1);
        let (valid, old) = self.entries.get(key).copied()?;
        self.tick = tick;
        self.order.remove(&old);
        self.order.insert(tick, *key);
        self.entries.insert(*key, (valid, tick));
        Some(valid)
    }
}

/// `LruSigCache`: the [`SigCache`] the node's index and the module's liveness hook share, keyed
/// by [`crate::attest::bundle::sig_cache_key`]. Node-local, never state: a hit and a cold
/// verification always agree, because the key covers every input of the verification. An
/// internal mutex guards it (a leaf lock).
pub struct LruSigCache {
    capacity: usize,
    inner: Mutex<LruInner>,
}

impl Default for LruSigCache {
    fn default() -> Self {
        LruSigCache::new(SIG_CACHE_ENTRIES)
    }
}

impl LruSigCache {
    /// A cache holding at most `capacity` verdicts (at least one).
    pub fn new(capacity: usize) -> LruSigCache {
        LruSigCache {
            capacity: capacity.max(1),
            inner: Mutex::new(LruInner::default()),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, LruInner> {
        // A poisoned leaf lock still holds a consistent map (no method panics while holding it).
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// The number of cached verdicts.
    pub fn len(&self) -> usize {
        self.lock().entries.len()
    }

    /// No verdict is cached.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The capacity.
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// `(hits, misses)` since start.
    pub fn stats(&self) -> (u64, u64) {
        let g = self.lock();
        (g.hits, g.misses)
    }

    /// Drops every verdict.
    pub fn clear(&self) {
        let mut g = self.lock();
        g.entries.clear();
        g.order.clear();
    }
}

impl SigCache for LruSigCache {
    fn lookup(&self, key: &Hash32) -> Option<bool> {
        let mut g = self.lock();
        let hit = g.touch(key);
        if hit.is_some() {
            g.hits = g.hits.saturating_add(1);
        } else {
            g.misses = g.misses.saturating_add(1);
        }
        hit
    }

    fn insert(&self, key: &Hash32, valid: bool) {
        let mut g = self.lock();
        if g.touch(key).is_some() {
            if let Some(e) = g.entries.get_mut(key) {
                e.0 = valid;
            }
            return;
        }
        while g.entries.len() >= self.capacity {
            let Some((&oldest, &k)) = g.order.iter().next() else {
                break;
            };
            g.order.remove(&oldest);
            g.entries.remove(&k);
        }
        let tick = g.tick.wrapping_add(1);
        g.tick = tick;
        g.order.insert(tick, *key);
        g.entries.insert(*key, (valid, tick));
    }
}
