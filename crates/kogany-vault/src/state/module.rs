//! Application modules (upgrade plan §3.8, §15.7; C++ `src/vault/module.{h,cpp}`).
//!
//! Registration is a compile-time table, not a transaction: adding a module is a network
//! upgrade. A module runs after the primitive's rules for a template input or V output whose
//! tag it owns, and can only reject; through its hooks it can also name members of the one set
//! it governs for ejection, displacement or liveness credit. `YED\0` is registered — inert in
//! this crate ([`InertModule`]) until the YED rule module replays `yellowback_golden.json` and
//! takes its entry (plan W5-f); `WYEC` is never registered.

use super::tx::VaultTx;
use super::view::StateRead;
use super::VaultReject;
use crate::act::SetJoinBody;
use crate::bytes::{Hash32, PubKeyBytes, SetId, Tag};
use crate::template::{TemplateSpend, VaultParams};

/// The hash of the block at a height below the one being validated, on the chain being
/// validated (the block's own ancestors; the tip's in the mempool and the miner), or `None`
/// (C++ `BlockHashFn`).
pub type BlockHashFn<'a> = &'a (dyn Fn(i64) -> Option<Hash32> + Sync);

/// What a module is told about the validation it runs inside (C++ `ModuleContext`).
#[derive(Clone, Copy)]
pub struct ModuleContext<'a> {
    /// The block height being validated (tip + 1 in the mempool).
    pub height: i64,
    /// The running set state, including the effects of earlier transactions in the block.
    pub state: &'a dyn StateRead,
    /// Ancestor block hashes; `None` when the caller has none (a module then finds nothing
    /// that needs them).
    pub block_hash_at: Option<BlockHashFn<'a>>,
}

/// An application module (C++ `vault::Module`). Every method has the inert default.
pub trait Module: Sync {
    /// After the primitive's rules, for every V output whose tag this module owns.
    fn validate_create(
        &self,
        _tx: &VaultTx,
        _vout: usize,
        _params: &VaultParams,
        _ctx: &ModuleContext<'_>,
    ) -> Result<(), VaultReject> {
        Ok(())
    }

    /// After the primitive's rules, for the template input whose tag this module owns.
    fn validate_spend(
        &self,
        _tx: &VaultTx,
        _vin: usize,
        _spend: &TemplateSpend,
        _ctx: &ModuleContext<'_>,
    ) -> Result<(), VaultReject> {
        Ok(())
    }

    /// After every transaction of the block has applied.
    fn check_block(&self, _txs: &[VaultTx], _ctx: &ModuleContext<'_>) -> Result<(), VaultReject> {
        Ok(())
    }

    /// The one signer set this module governs, if any (the ejection, displacement and
    /// liveness hooks act only on it).
    fn governed_set(&self) -> Option<SetId> {
        None
    }

    /// The ejection hook (U-25): members of the governed set the transaction proves broke a
    /// rule of the module. Each one that is a member with an unspent, unfrozen bond is EJECTED
    /// and its bond frozen; any other key is ignored.
    fn ejections(&self, _tx: &VaultTx, _ctx: &ModuleContext<'_>) -> Vec<PubKeyBytes> {
        Vec::new()
    }

    /// The displacement hook: for a `SET_JOIN` into the full governed set, the ACTIVE member
    /// to make room (set REMOVED, its bond in the exit delay). `None` refuses the join.
    fn displace(
        &self,
        _tx: &VaultTx,
        _join: &SetJoinBody,
        _ctx: &ModuleContext<'_>,
    ) -> Option<PubKeyBytes> {
        None
    }

    /// The liveness hook: `(key, height)` pairs the transaction proves the key signed for the
    /// module at `height`; an ACTIVE member of the governed set with an unspent, unfrozen bond
    /// and `last_act < height < block height` gets `last_act = height`.
    fn liveness(&self, _tx: &VaultTx, _ctx: &ModuleContext<'_>) -> Vec<(PubKeyBytes, i64)> {
        Vec::new()
    }
}

/// One entry of a module table: a tag and the module that owns it.
pub type ModuleEntry<'a> = (Tag, &'a dyn Module);

/// The YED rule module's tag, `"YED\0"`.
pub const YED_TAG: Tag = Tag(*b"YED\0");

/// A module that accepts everything and names nobody: every default of [`Module`]. `YED\0`'s
/// entry until the YED rule module is registered (plan §1.6: safe only on regtest).
#[derive(Clone, Copy, Debug, Default)]
pub struct InertModule;

impl Module for InertModule {}

static INERT_YED: InertModule = InertModule;

static REGISTERED: [ModuleEntry<'static>; 1] = [(YED_TAG, &INERT_YED)];

/// The compile-time module table (C++ `vault::Modules()`): exactly `YED\0`, inert here.
pub fn registered_modules() -> &'static [ModuleEntry<'static>] {
    &REGISTERED
}

/// The module that owns `tag` in `table`, if any (C++ `FindModule`).
pub fn find_module<'a>(table: &[ModuleEntry<'a>], tag: &Tag) -> Option<&'a dyn Module> {
    table.iter().find(|(t, _)| t == tag).map(|(_, m)| *m)
}
