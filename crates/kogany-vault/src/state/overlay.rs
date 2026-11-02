//! The rules that move the set state (C++ `VaultState::ApplyTx` / `ApplyBlock` / `ApplyAct`,
//! ycash6 `src/vault/state.cpp`): §15.5 acts, §15.6 template rules, bond spends, the
//! template-output index, module dispatch and the module hooks (U-16..U-20, U-25, S-0).
//!
//! [`VaultOverlay`] is the write overlay of the C++ `VaultState`: it applies transactions in
//! block order over a read-only base, each transaction on a child overlay that is merged only
//! when the transaction passes (a failing transaction changes nothing). Every read goes through
//! the overlay, so the order of reads and writes inside a transaction is the C++ order.

use std::collections::{BTreeMap, BTreeSet};

use super::module::{find_module, BlockHashFn, ModuleContext, ModuleEntry};
use super::records::{
    BondRecord, MemberRecord, MemberStatus, SetRecord, TemplateOutKind, TemplateOutRecord,
};
use super::tx::{CoinAccessor, SpentCoin, VaultTx};
use super::view::{
    count_active, count_current, is_current, member_range, money_range, rate_cap, Change, Delta,
    MemberList, StateRead,
};
use super::VaultReject;
use crate::act::{
    act_fields_valid, act_msg, decode_act, encode_payload, is_act_output, recover_sig, set_sig_msg,
    Act, ActBody, SetEquivocationBody, SetHeartbeatBody, SetJoinBody, SetRemoveBody,
    SetWindDownBody,
};
use crate::bytes::{OutPoint, PubKeyBytes, SetId};
use crate::template::{
    bond_script_pubkey, match_intent, match_vault, parse_intent, parse_selector, parse_vault,
    script_hash256, IntentParams, Shape, TemplateParams, TemplateSpend, VaultParams, ROLE_CANCEL,
    ROLE_UNLOCK, SEL_APP, SEL_OWNER, SEL_UNLOCK,
};

/// D-Q-31: every signer set has at least a 14-day exit window on mainnet (16,128 blocks). The
/// network's value is [`Rules::min_set_maturity`] (testnet-yb-fast 48, regtest 2).
pub const MIN_SET_MATURITY: u32 = 16_128;

/// The network- and chain-dependent inputs of the rules: what the C++ takes from globals
/// (`MinSetMaturity`, the module table) and from setters (`SetActivationHeight`,
/// `SetBlockHashes`). The rules apply only where the caller has established that
/// `UPGRADE_VAULT` is active at the height.
#[derive(Clone, Copy)]
pub struct Rules<'a> {
    /// S-0: `UPGRADE_VAULT`'s activation height. A template input whose coin was created below
    /// it is invalid. 0 = no floor (unit tests that build chains from height 0).
    pub activation_height: i64,
    /// D-Q-31: the smallest `SET_CREATE` maturity (`Consensus::Params::nVaultMinSetMaturity`).
    pub min_set_maturity: u32,
    /// The module table, normally [`super::registered_modules`].
    pub modules: &'a [ModuleEntry<'a>],
    /// Ancestor block hashes for the module hooks; `None` = unknown.
    pub block_hashes: Option<BlockHashFn<'a>>,
}

impl<'a> Rules<'a> {
    /// Rules over the registered module table, with no block-hash provider.
    pub fn new(activation_height: i64, min_set_maturity: u32) -> Rules<'static> {
        Rules {
            activation_height,
            min_set_maturity,
            modules: super::registered_modules(),
            block_hashes: None,
        }
    }
}

/// The write overlay (C++ `VaultState`): `base` plus this overlay's own writes (`None` =
/// erased). Implements [`StateRead`] with the writes visible.
pub struct VaultOverlay<'a> {
    base: &'a dyn StateRead,
    sets: BTreeMap<SetId, Option<SetRecord>>,
    members: BTreeMap<(SetId, PubKeyBytes), Option<MemberRecord>>,
    bonds: BTreeMap<OutPoint, Option<BondRecord>>,
    template_outs: BTreeMap<OutPoint, Option<TemplateOutRecord>>,
}

/// The writes of one overlay, moved out of a child into its parent.
#[derive(Default)]
struct Writes {
    sets: BTreeMap<SetId, Option<SetRecord>>,
    members: BTreeMap<(SetId, PubKeyBytes), Option<MemberRecord>>,
    bonds: BTreeMap<OutPoint, Option<BondRecord>>,
    template_outs: BTreeMap<OutPoint, Option<TemplateOutRecord>>,
}

impl StateRead for VaultOverlay<'_> {
    fn set(&self, set_id: &SetId) -> Option<SetRecord> {
        match self.sets.get(set_id) {
            Some(v) => *v,
            None => self.base.set(set_id),
        }
    }
    fn member(&self, set_id: &SetId, key: &PubKeyBytes) -> Option<MemberRecord> {
        match self.members.get(&(*set_id, *key)) {
            Some(v) => *v,
            None => self.base.member(set_id, key),
        }
    }
    fn members(&self, set_id: &SetId) -> MemberList {
        let mut merged: BTreeMap<PubKeyBytes, MemberRecord> =
            self.base.members(set_id).into_iter().collect();
        for ((_, k), v) in self.members.range(member_range(set_id)) {
            match v {
                Some(m) => {
                    merged.insert(*k, *m);
                }
                None => {
                    merged.remove(k);
                }
            }
        }
        merged.into_iter().collect()
    }
    fn bond(&self, outpoint: &OutPoint) -> Option<BondRecord> {
        match self.bonds.get(outpoint) {
            Some(v) => *v,
            None => self.base.bond(outpoint),
        }
    }
    fn template_out(&self, outpoint: &OutPoint) -> Option<TemplateOutRecord> {
        match self.template_outs.get(outpoint) {
            Some(v) => v.clone(),
            None => self.base.template_out(outpoint),
        }
    }
}

/// Roll the rate epoch (U-20) before any change to `locked_value` or use of the epoch fields.
fn roll_epoch(s: &mut SetRecord, h: i64) {
    let e = h.checked_div(i64::from(s.params.rate_window)).unwrap_or(0);
    if e != s.epoch {
        s.epoch = e;
        s.epoch_basis = s.locked_value;
        s.epoch_used = 0;
    }
}

#[derive(Clone, Copy)]
enum OutClass {
    Other,
    Vault(VaultParams),
    Intent(IntentParams),
    Act,
}

impl<'a> VaultOverlay<'a> {
    /// An empty overlay over `base`.
    pub fn new(base: &'a dyn StateRead) -> VaultOverlay<'a> {
        VaultOverlay {
            base,
            sets: BTreeMap::new(),
            members: BTreeMap::new(),
            bonds: BTreeMap::new(),
            template_outs: BTreeMap::new(),
        }
    }

    /// No write yet.
    pub fn is_empty(&self) -> bool {
        self.sets.is_empty()
            && self.members.is_empty()
            && self.bonds.is_empty()
            && self.template_outs.is_empty()
    }

    fn put_set(&mut self, id: SetId, r: SetRecord) {
        self.sets.insert(id, Some(r));
    }
    fn put_member(&mut self, id: SetId, k: PubKeyBytes, r: MemberRecord) {
        self.members.insert((id, k), Some(r));
    }
    fn put_bond(&mut self, op: OutPoint, r: BondRecord) {
        self.bonds.insert(op, Some(r));
    }

    fn take_writes(self) -> Writes {
        Writes {
            sets: self.sets,
            members: self.members,
            bonds: self.bonds,
            template_outs: self.template_outs,
        }
    }

    fn merge(&mut self, w: Writes) {
        self.sets.extend(w.sets);
        self.members.extend(w.members);
        self.bonds.extend(w.bonds);
        self.template_outs.extend(w.template_outs);
    }

    /// The overlay's writes with the base's prior values: the block's [`Delta`] (C++
    /// `Changes()` + `MakeUndo()`).
    pub fn delta(&self) -> Delta {
        let mut d = Delta::default();
        for (k, v) in &self.sets {
            d.sets.insert(
                *k,
                Change {
                    before: self.base.set(k),
                    after: *v,
                },
            );
        }
        for ((id, key), v) in &self.members {
            d.members.insert(
                (*id, *key),
                Change {
                    before: self.base.member(id, key),
                    after: *v,
                },
            );
        }
        for (k, v) in &self.bonds {
            d.bonds.insert(
                *k,
                Change {
                    before: self.base.bond(k),
                    after: *v,
                },
            );
        }
        for (k, v) in &self.template_outs {
            d.template_outs.insert(
                *k,
                Change {
                    before: self.base.template_out(k),
                    after: v.clone(),
                },
            );
        }
        d
    }

    /// Applies one transaction at `height` (C++ `VaultState::ApplyTx`). On failure the reject
    /// reason and no change to this overlay.
    pub fn apply_tx(
        &mut self,
        tx: &VaultTx,
        height: i64,
        coins: &dyn CoinAccessor,
        rules: &Rules<'_>,
    ) -> Result<(), VaultReject> {
        let writes = {
            let mut child = VaultOverlay::new(&*self);
            child.apply_tx_inner(tx, height, coins, rules)?;
            child.take_writes()
        };
        self.merge(writes);
        Ok(())
    }

    /// Applies every transaction of a block in order, then each module's `check_block`
    /// (C++ `VaultState::ApplyBlock`). On failure the overlay must be discarded.
    pub fn apply_block(
        &mut self,
        txs: &[VaultTx],
        height: i64,
        coins: &dyn CoinAccessor,
        rules: &Rules<'_>,
    ) -> Result<(), VaultReject> {
        for tx in txs {
            self.apply_tx(tx, height, coins, rules)?;
        }
        for (_, module) in rules.modules {
            let ctx = ModuleContext {
                height,
                state: &*self,
                block_hash_at: rules.block_hashes,
            };
            module.check_block(txs, &ctx)?;
        }
        Ok(())
    }

    fn ctx<'s>(&'s self, height: i64, rules: &Rules<'s>) -> ModuleContext<'s> {
        ModuleContext {
            height,
            state: self,
            block_hash_at: rules.block_hashes,
        }
    }

    fn apply_tx_inner(
        &mut self,
        tx: &VaultTx,
        h: i64,
        coins: &dyn CoinAccessor,
        rules: &Rules<'_>,
    ) -> Result<(), VaultReject> {
        let txid = tx.txid;

        // ---- outputs: classify (malformed template shapes are invalid: §15.3, V-1) ----
        let mut outs = Vec::with_capacity(tx.outputs.len());
        let mut act_index: Option<usize> = None;
        for (o, out) in tx.outputs.iter().enumerate() {
            let spk = &out.script_pubkey;
            if is_act_output(spk) {
                if act_index.is_some() {
                    return Err(VaultReject::ActMulti);
                }
                act_index = Some(o);
                outs.push(OutClass::Act);
                continue;
            }
            match match_vault(spk) {
                Shape::Malformed => return Err(VaultReject::Malformed),
                Shape::Match(v) => {
                    outs.push(OutClass::Vault(v));
                    continue;
                }
                Shape::NotTemplate => {}
            }
            match match_intent(spk) {
                Shape::Malformed => return Err(VaultReject::Malformed),
                Shape::Match(i) => outs.push(OutClass::Intent(i)),
                Shape::NotTemplate => outs.push(OutClass::Other),
            }
        }

        // ---- inputs: bond spends, the template input (S-1) ----
        let mut tin: Option<(usize, TemplateSpend, SpentCoin)> = None;
        if !tx.coinbase {
            for (i, input) in tx.inputs.iter().enumerate() {
                let prevout = input.prevout;
                if let Some(bond) = self.bond(&prevout) {
                    if bond.frozen {
                        return Err(VaultReject::BondFrozen);
                    }
                    // The bond exit delay: spendable only once its member has left without a
                    // freeze and the set's maturity has passed since.
                    let bset = self.set(&bond.set_id);
                    let locked = match bset {
                        Some(s) => {
                            bond.exit_height == 0
                                || h < bond.exit_height.wrapping_add(i64::from(s.params.maturity))
                        }
                        None => true,
                    };
                    if locked {
                        return Err(VaultReject::BondLocked);
                    }
                    if let Some(mut m) = self.member(&bond.set_id, &bond.member_key) {
                        if m.status == MemberStatus::Active && m.bond_outpoint == prevout {
                            m.status = MemberStatus::Withdrawn;
                            self.put_member(bond.set_id, bond.member_key, m);
                        }
                    }
                    self.bonds.insert(prevout, None);
                }
                let Some(c) = coins.spent_coin(&prevout) else {
                    return Err(VaultReject::InputsMissing);
                };
                let params = if let Some(v) = parse_vault(&c.script_pubkey) {
                    TemplateParams::Vault(v)
                } else if let Some(ip) = parse_intent(&c.script_pubkey) {
                    TemplateParams::Intent(ip)
                } else {
                    continue;
                };
                // S-0: a template input's coin was created at or above the activation height.
                if c.height < rules.activation_height {
                    return Err(VaultReject::Preactivation);
                }
                if tin.is_some() {
                    return Err(VaultReject::Multi);
                }
                let Some((selector, sigs)) = parse_selector(&input.script_sig) else {
                    return Err(VaultReject::Selector);
                };
                if matches!(params, TemplateParams::Intent(_)) && selector == SEL_APP {
                    return Err(VaultReject::Selector);
                }
                tin = Some((
                    i,
                    TemplateSpend {
                        params,
                        selector,
                        sigs,
                    },
                    c,
                ));
            }
        }

        let unlock_spend = matches!(
            &tin,
            Some((_, TemplateSpend { params: TemplateParams::Vault(_), selector, .. }, _))
                if *selector == SEL_UNLOCK || *selector == SEL_APP
        );

        // ---- I-0: intents only from an UNLOCK/APP spend ----
        if !unlock_spend && outs.iter().any(|o| matches!(o, OutClass::Intent(_))) {
            return Err(VaultReject::Intent);
        }

        // ---- template input rules ----
        if let Some((_, spend, tcoin)) = &tin {
            match &spend.params {
                TemplateParams::Vault(v) => {
                    if spend.selector == SEL_APP && v.app_height == 0 {
                        return Err(VaultReject::App); // S-4
                    }
                    let mut set = self.set(&v.set_id);
                    if let Some(s) = set.as_mut() {
                        roll_epoch(s, h);
                    }
                    if unlock_spend {
                        // S-2: the vault's value never leaves to ordinary outputs.
                        let vault_hash = script_hash256(&tcoin.script_pubkey);
                        let mut sum_i: i64 = 0;
                        let mut sum_relock: i64 = 0;
                        for (oc, out) in outs.iter().zip(&tx.outputs) {
                            let value = out.value;
                            match oc {
                                OutClass::Intent(ip) => {
                                    if ip.tag != v.tag
                                        || ip.set_id != v.set_id
                                        || ip.cancel_set_id != v.cancel_set_id
                                        || ip.delay != v.delay
                                        || ip.owner != v.owner
                                        || ip.vault_hash != vault_hash
                                    {
                                        return Err(VaultReject::Covenant);
                                    }
                                    sum_i = sum_i.wrapping_add(value);
                                    if !money_range(value) || !money_range(sum_i) {
                                        return Err(VaultReject::Amount);
                                    }
                                }
                                OutClass::Vault(_) => {
                                    if out.script_pubkey != tcoin.script_pubkey {
                                        return Err(VaultReject::Covenant);
                                    }
                                    sum_relock = sum_relock.wrapping_add(value);
                                    if !money_range(value) || !money_range(sum_relock) {
                                        return Err(VaultReject::Amount);
                                    }
                                }
                                OutClass::Other | OutClass::Act => {}
                            }
                        }
                        let total = sum_i.wrapping_add(sum_relock);
                        if !money_range(total) || total < tcoin.value {
                            return Err(VaultReject::Value);
                        }
                        // S-3: the set's rate limit over the current epoch (U-20).
                        if let Some(s) = set.as_mut() {
                            if s.params.rate_limit_bps != 0 {
                                let cap = rate_cap(s.epoch_basis, s.params.rate_limit_bps);
                                if s.epoch_used.wrapping_add(sum_i) > cap {
                                    return Err(VaultReject::Rate);
                                }
                            }
                            s.epoch_used = s.epoch_used.wrapping_add(sum_i);
                        }
                    }
                    // S-3 / S-4: the spent vault leaves the set's locked value (every selector).
                    if let Some(mut s) = set {
                        s.locked_value = if s.locked_value > tcoin.value {
                            s.locked_value.wrapping_sub(tcoin.value)
                        } else {
                            0
                        };
                        self.put_set(v.set_id, s);
                    }
                }
                TemplateParams::Intent(ip) => {
                    if spend.selector == SEL_UNLOCK {
                        // I-1 RELEASE
                        let paid = tx.outputs.iter().any(|out| {
                            out.value >= tcoin.value
                                && script_hash256(&out.script_pubkey) == ip.recipient_hash
                        });
                        if !paid {
                            return Err(VaultReject::Release);
                        }
                    } else if spend.selector == SEL_OWNER {
                        // I-2 CANCEL
                        if h.wrapping_sub(tcoin.height) >= ip.delay {
                            return Err(VaultReject::Cancel);
                        }
                        let back = tx.outputs.iter().any(|out| {
                            out.value >= tcoin.value
                                && script_hash256(&out.script_pubkey) == ip.vault_hash
                        });
                        if !back {
                            return Err(VaultReject::Cancel);
                        }
                    }
                    // I-3 (selector 3): script only.
                }
            }
        }

        // ---- V-1: vault outputs ----
        for (oc, out) in outs.iter().zip(&tx.outputs) {
            let OutClass::Vault(v) = oc else {
                continue;
            };
            // V-1: the APP branch (selector 4) exists for a module to govern.
            if v.app_height != 0 && find_module(rules.modules, &v.tag).is_none() {
                return Err(VaultReject::App);
            }
            let Some(mut set) = self.set(&v.set_id).filter(|s| s.create_height < h) else {
                return Err(VaultReject::NoSet);
            };
            if self
                .set(&v.cancel_set_id)
                .filter(|s| s.create_height < h)
                .is_none()
            {
                return Err(VaultReject::NoSet);
            }
            roll_epoch(&mut set, h);
            set.locked_value = set.locked_value.wrapping_add(out.value);
            if !money_range(out.value) || !money_range(set.locked_value) {
                return Err(VaultReject::Amount);
            }
            self.put_set(v.set_id, set);
        }

        // ---- the template-output index (vault_list; an intent's height for replay) ----
        if let Some((i, _, _)) = &tin {
            if let Some(input) = tx.inputs.get(*i) {
                self.template_outs.insert(input.prevout, None);
            }
        }
        for (o, (oc, out)) in outs.iter().zip(&tx.outputs).enumerate() {
            let kind = match oc {
                OutClass::Vault(_) => TemplateOutKind::Vault,
                OutClass::Intent(_) => TemplateOutKind::Intent,
                OutClass::Other | OutClass::Act => continue,
            };
            let origin = match (kind, &tin) {
                (TemplateOutKind::Intent, Some((_, _, tcoin))) => tcoin.script_pubkey.clone(),
                _ => Vec::new(),
            };
            let n = u32::try_from(o).map_err(|_| VaultReject::Malformed)?;
            self.template_outs.insert(
                OutPoint { txid, n },
                Some(TemplateOutRecord {
                    kind,
                    height: h,
                    value: out.value,
                    script_pubkey: out.script_pubkey.clone(),
                    origin,
                }),
            );
        }

        // ---- module dispatch (after the primitive rules; a module can only reject) ----
        if let Some((i, spend, _)) = &tin {
            let tag = match &spend.params {
                TemplateParams::Vault(v) => v.tag,
                TemplateParams::Intent(ip) => ip.tag,
            };
            if let Some(module) = find_module(rules.modules, &tag) {
                module.validate_spend(tx, *i, spend, &self.ctx(h, rules))?;
            }
        }
        for (o, oc) in outs.iter().enumerate() {
            if let OutClass::Vault(v) = oc {
                if let Some(module) = find_module(rules.modules, &v.tag) {
                    module.validate_create(tx, o, v, &self.ctx(h, rules))?;
                }
            }
        }

        // ---- the act ----
        if let Some(a) = act_index {
            let spk = tx
                .outputs
                .get(a)
                .map(|o| o.script_pubkey.as_slice())
                .unwrap_or_default();
            let act = decode_act(spk).map_err(VaultReject::ActDecode)?;
            self.apply_act(tx, &act, h, rules)?;
        }

        // ---- the module ejection hook (U-25): after the transaction's own rules and act ----
        if !tx.coinbase {
            for (_, module) in rules.modules {
                self.apply_ejections_of(*module, tx, h, rules);
            }
        }
        Ok(())
    }

    /// The module ejection and liveness hooks for one module (C++ `ApplyEjectionsOf`): what
    /// `apply_tx` runs for each registered module after the transaction's own rules and act.
    /// Public so a test can drive the hooks with a module outside the table.
    pub fn apply_ejections_of(
        &mut self,
        module: &dyn super::Module,
        tx: &VaultTx,
        h: i64,
        rules: &Rules<'_>,
    ) {
        let Some(governed) = module.governed_set() else {
            return;
        };
        if self.set(&governed).is_none() {
            return;
        }
        let ejected = module.ejections(tx, &self.ctx(h, rules));
        for key in ejected {
            eject_and_freeze(self, &governed, &key);
        }
        // The module liveness hook: a member's proven act at height raises its last_act to it.
        let credits = module.liveness(tx, &self.ctx(h, rules));
        for (key, at) in credits {
            let Some(mut m) = self.member(&governed, &key) else {
                continue;
            };
            if m.status != MemberStatus::Active || m.bond_frozen || at >= h || at <= m.last_act {
                continue;
            }
            match self.bond(&m.bond_outpoint) {
                Some(b) if !b.frozen => {}
                _ => continue,
            }
            m.last_act = at;
            self.put_member(governed, key, m);
        }
    }

    fn apply_act(
        &mut self,
        tx: &VaultTx,
        act: &Act,
        h: i64,
        rules: &Rules<'_>,
    ) -> Result<(), VaultReject> {
        if tx.coinbase {
            return Err(VaultReject::ActCoinbase);
        }
        let Some(vin0) = tx.inputs.first() else {
            return Err(VaultReject::ActNoVin);
        };

        // A SET_CREATE carrying signatures is a count error, reported as such.
        if matches!(act.body, ActBody::Create(_)) && !act.sigs.is_empty() {
            return Err(VaultReject::ActSigs);
        }
        if !act_fields_valid(act) {
            return Err(VaultReject::ActParams);
        }

        // The count each type demands, compared before any recovery (W3-V-2).
        self.sig_count(act, h)?;

        let msg = act_msg(&encode_payload(&act.body), &vin0.prevout);
        let mut keys = Vec::with_capacity(act.sigs.len());
        for sig in &act.sigs {
            keys.push(recover_sig(&msg, sig).ok_or(VaultReject::ActSig)?);
        }

        match &act.body {
            ActBody::Create(c) => {
                if !act.sigs.is_empty() {
                    return Err(VaultReject::ActSigs);
                }
                if !c.valid() || c.maturity < rules.min_set_maturity {
                    return Err(VaultReject::ActParams);
                }
                let set_id = tx.txid;
                if self.set(&set_id).is_some() {
                    return Err(VaultReject::ActExists);
                }
                self.put_set(set_id, SetRecord::new(*c, h));
                Ok(())
            }
            ActBody::Join(j) => self.act_join(tx, j, &keys, h, rules),
            ActBody::Heartbeat(hb) => self.act_heartbeat(hb, &keys, h),
            ActBody::Remove(r) => self.act_remove(r, &keys, h),
            ActBody::Equivocation(e) => {
                if !act.sigs.is_empty() {
                    return Err(VaultReject::ActSigs);
                }
                self.act_equivocation(e)
            }
            ActBody::WindDown(w) => self.act_winddown(w, &keys, h),
        }
    }

    /// The signature count each act type demands (C++ `sigCount`), with the state reasons that
    /// do not read the signatures first, in the order the act cases use.
    fn sig_count(&self, act: &Act, h: i64) -> Result<(), VaultReject> {
        let n = act.sigs.len();
        match &act.body {
            ActBody::Create(_) => Ok(()),
            ActBody::Equivocation(e) => {
                if self.set(&e.set_id).is_none() {
                    return Err(VaultReject::ActNoSet);
                }
                if n != 0 {
                    return Err(VaultReject::ActSigs);
                }
                Ok(())
            }
            ActBody::Heartbeat(hb) => {
                if self.set(&hb.set_id).is_none() {
                    return Err(VaultReject::ActNoSet);
                }
                if n != 1 {
                    return Err(VaultReject::ActSigs);
                }
                Ok(())
            }
            ActBody::Join(j) => {
                let Some(s) = self.set(&j.set_id).filter(|s| s.create_height < h) else {
                    return Err(VaultReject::ActNoSet);
                };
                if s.wind_down_height != 0 {
                    return Err(VaultReject::ActWindDown);
                }
                let expected = if s.params.is_open() {
                    1
                } else if count_current(&s, &self.members(&j.set_id), h)
                    >= usize::from(s.params.slash_threshold)
                {
                    usize::from(s.params.slash_threshold).saturating_add(1)
                } else {
                    2
                };
                if n != expected {
                    return Err(VaultReject::ActSigs);
                }
                Ok(())
            }
            ActBody::Remove(r) => {
                let Some(s) = self.set(&r.set_id) else {
                    return Err(VaultReject::ActNoSet);
                };
                let Some(m) = self.member(&r.set_id, &r.member_key) else {
                    return Err(VaultReject::ActRemove);
                };
                if m.status != MemberStatus::Active {
                    // Not a slash of a bond still in its exit delay: the case returns remove
                    // before it looks at the count.
                    if !self.slashable_after_exit(r, &m) {
                        return Err(VaultReject::ActRemove);
                    }
                    if n != usize::from(s.params.slash_threshold) {
                        return Err(VaultReject::ActSigs);
                    }
                    return Ok(());
                }
                // Voluntary exit is one signature and burn 0; every other shape needs
                // slashThreshold signatures.
                let expected = if n == 1 && r.burn == 0 {
                    1
                } else {
                    usize::from(s.params.slash_threshold)
                };
                if n != expected {
                    return Err(VaultReject::ActSigs);
                }
                Ok(())
            }
            ActBody::WindDown(w) => {
                let Some(s) = self.set(&w.set_id) else {
                    return Err(VaultReject::ActNoSet);
                };
                if s.wind_down_height != 0 {
                    return Err(VaultReject::ActWindDown);
                }
                if n != usize::from(s.params.slash_threshold) {
                    return Err(VaultReject::ActSigs);
                }
                Ok(())
            }
        }
    }

    /// A REMOVED member whose bond is in its exit delay (unspent, unfrozen, its own), reached
    /// by a cosigned `SET_REMOVE` with burn (review A1).
    fn slashable_after_exit(&self, r: &SetRemoveBody, m: &MemberRecord) -> bool {
        if m.status != MemberStatus::Removed || r.burn != 1 {
            return false;
        }
        matches!(
            self.bond(&m.bond_outpoint),
            Some(b) if !b.frozen && b.exit_height != 0 && b.set_id == r.set_id && b.member_key == r.member_key
        )
    }

    fn act_join(
        &mut self,
        tx: &VaultTx,
        j: &SetJoinBody,
        keys: &[PubKeyBytes],
        h: i64,
        rules: &Rules<'_>,
    ) -> Result<(), VaultReject> {
        let Some(mut s) = self.set(&j.set_id).filter(|s| s.create_height < h) else {
            return Err(VaultReject::ActNoSet);
        };
        if s.wind_down_height != 0 {
            return Err(VaultReject::ActWindDown);
        }
        if !j.member_key.is_compressed() {
            return Err(VaultReject::ActParams);
        }
        if keys.first() != Some(&j.member_key) {
            return Err(VaultReject::ActSig);
        }
        let members = self.members(&j.set_id);
        if s.params.is_open() {
            if keys.len() != 1 {
                return Err(VaultReject::ActSigs);
            }
        } else if count_current(&s, &members, h) >= usize::from(s.params.slash_threshold) {
            if !cosigners(
                &s,
                &members,
                keys,
                1,
                usize::from(s.params.slash_threshold),
                None,
                h,
            ) {
                return Err(VaultReject::ActSigs);
            }
        } else if keys.len() != 2 || keys.get(1) != Some(&s.params.admit_key) {
            return Err(VaultReject::ActSigs);
        }
        // A full set refuses the join, unless the module governing the set names a member to
        // displace: an ACTIVE member, not the joining key, with an unspent, unfrozen bond.
        let mut displaced: Option<PubKeyBytes> = None;
        if count_active(&members) >= usize::from(s.params.seats) {
            for (_, module) in rules.modules {
                if module.governed_set() != Some(j.set_id) {
                    continue;
                }
                displaced = module.displace(tx, j, &self.ctx(h, rules));
                break;
            }
            let room = match displaced {
                Some(d) if d != j.member_key => match self.member(&j.set_id, &d) {
                    Some(dm) => {
                        dm.status == MemberStatus::Active
                            && !dm.bond_frozen
                            && matches!(
                                self.bond(&dm.bond_outpoint),
                                Some(db) if !db.frozen && db.set_id == j.set_id && db.member_key == d
                            )
                    }
                    None => false,
                },
                _ => false,
            };
            if !room {
                return Err(VaultReject::ActSeats);
            }
        }
        let existing = self.member(&j.set_id, &j.member_key);
        if let Some(e) = &existing {
            if e.status == MemberStatus::Active {
                return Err(VaultReject::ActJoin);
            }
            // One unspent bond per (set, key) (review B1).
            if self.bond(&e.bond_outpoint).is_some() {
                return Err(VaultReject::ActJoin);
            }
        }
        let Some(bond) = tx.outputs.get(usize::from(j.bond_vout)) else {
            return Err(VaultReject::ActBond);
        };
        match bond_script_pubkey(j.bond_locktime, &j.member_key) {
            Some(spk) if spk == bond.script_pubkey => {}
            _ => return Err(VaultReject::ActBond),
        }
        if !money_range(bond.value) || bond.value < s.params.bond_min {
            return Err(VaultReject::ActBond);
        }
        if i64::from(j.bond_locktime) < h.wrapping_add(i64::from(s.params.bond_lock_min))
            || j.bond_locktime >= 500_000_000
        {
            return Err(VaultReject::ActBond);
        }
        if let Some(d) = displaced {
            if let Some(mut dm) = self.member(&j.set_id, &d) {
                dm.status = MemberStatus::Removed;
                self.put_member(j.set_id, d, dm);
                if let Some(mut db) = self.bond(&dm.bond_outpoint) {
                    db.exit_height = h; // the bond exit delay starts
                    self.put_bond(dm.bond_outpoint, db);
                }
            }
        }
        s.join_count = s.join_count.wrapping_add(1);
        self.put_set(j.set_id, s);
        let bond_outpoint = OutPoint {
            txid: tx.txid,
            n: u32::from(j.bond_vout),
        };
        let m = MemberRecord {
            bond_outpoint,
            bond_value: bond.value,
            bond_locktime: j.bond_locktime,
            join_height: h,
            last_act: h.wrapping_add(i64::from(s.params.maturity)),
            status: MemberStatus::Active,
            bond_frozen: false,
            join_ordinal: s.join_count,
        };
        self.put_member(j.set_id, j.member_key, m);
        self.put_bond(
            bond_outpoint,
            BondRecord {
                set_id: j.set_id,
                member_key: j.member_key,
                frozen: false,
                exit_height: 0,
            },
        );
        Ok(())
    }

    fn act_heartbeat(
        &mut self,
        hb: &SetHeartbeatBody,
        keys: &[PubKeyBytes],
        h: i64,
    ) -> Result<(), VaultReject> {
        let Some(s) = self.set(&hb.set_id) else {
            return Err(VaultReject::ActNoSet);
        };
        let [key] = keys else {
            return Err(VaultReject::ActSigs);
        };
        if *key != hb.member_key {
            return Err(VaultReject::ActSig);
        }
        let Some(mut m) = self
            .member(&hb.set_id, &hb.member_key)
            .filter(|m| is_current(&s, m, h))
        else {
            return Err(VaultReject::ActHeartbeat);
        };
        m.last_act = h;
        self.put_member(hb.set_id, hb.member_key, m);
        Ok(())
    }

    fn act_remove(
        &mut self,
        r: &SetRemoveBody,
        keys: &[PubKeyBytes],
        h: i64,
    ) -> Result<(), VaultReject> {
        if r.burn > 1 {
            return Err(VaultReject::ActParams);
        }
        let Some(s) = self.set(&r.set_id) else {
            return Err(VaultReject::ActNoSet);
        };
        let Some(mut m) = self.member(&r.set_id, &r.member_key) else {
            return Err(VaultReject::ActRemove);
        };
        let members = self.members(&r.set_id);
        let slash = usize::from(s.params.slash_threshold);
        if m.status != MemberStatus::Active {
            // A slash after the exit (review A1): a cosigned SET_REMOVE with burn of a member
            // that already left, whose bond is in its exit delay, freezes that bond.
            if !self.slashable_after_exit(r, &m) {
                return Err(VaultReject::ActRemove);
            }
            if !cosigners(&s, &members, keys, 0, slash, Some(&r.member_key), h) {
                return Err(VaultReject::ActSigs);
            }
            m.bond_frozen = true;
            if let Some(mut b) = self.bond(&m.bond_outpoint) {
                b.frozen = true;
                self.put_bond(m.bond_outpoint, b);
            }
            self.put_member(r.set_id, r.member_key, m);
            return Ok(());
        }
        // A member's voluntary exit: the SET_REMOVE of itself, signed by itself alone, no burn.
        let own_exit = matches!(keys, [k] if *k == r.member_key) && r.burn == 0;
        if !own_exit && !cosigners(&s, &members, keys, 0, slash, Some(&r.member_key), h) {
            return Err(VaultReject::ActSigs);
        }
        m.status = MemberStatus::Removed;
        if r.burn != 0 {
            m.bond_frozen = true;
            if let Some(mut b) = self.bond(&m.bond_outpoint) {
                b.frozen = true;
                self.put_bond(m.bond_outpoint, b);
            }
        } else if let Some(mut b) = self.bond(&m.bond_outpoint) {
            b.exit_height = h; // the bond exit delay starts
            self.put_bond(m.bond_outpoint, b);
        }
        self.put_member(r.set_id, r.member_key, m);
        Ok(())
    }

    fn act_equivocation(&mut self, e: &SetEquivocationBody) -> Result<(), VaultReject> {
        let role_ok = |r: u8| r == ROLE_UNLOCK || r == ROLE_CANCEL;
        if !role_ok(e.role_a) || !role_ok(e.role_b) {
            return Err(VaultReject::ActParams);
        }
        if e.role_a == e.role_b && e.sighash_a == e.sighash_b {
            return Err(VaultReject::ActEquivocation);
        }
        if self.set(&e.set_id).is_none() {
            return Err(VaultReject::ActNoSet);
        }
        let ka = recover_sig(
            &set_sig_msg(&e.set_id, e.role_a, &e.prevout, &e.sighash_a),
            &e.sig_a,
        );
        let kb = recover_sig(
            &set_sig_msg(&e.set_id, e.role_b, &e.prevout, &e.sighash_b),
            &e.sig_b,
        );
        let key = match (ka, kb) {
            (Some(a), Some(b)) if a == b => a,
            _ => return Err(VaultReject::ActEquivocation),
        };
        let Some(mut m) = self.member(&e.set_id, &key) else {
            return Err(VaultReject::ActEquivocation);
        };
        let Some(mut b) = self
            .bond(&m.bond_outpoint)
            .filter(|b| !b.frozen && b.set_id == e.set_id && b.member_key == key)
        else {
            return Err(VaultReject::ActEquivocation);
        };
        m.status = MemberStatus::Ejected;
        m.bond_frozen = true;
        b.frozen = true;
        self.put_member(e.set_id, key, m);
        self.put_bond(m.bond_outpoint, b);
        Ok(())
    }

    fn act_winddown(
        &mut self,
        w: &SetWindDownBody,
        keys: &[PubKeyBytes],
        h: i64,
    ) -> Result<(), VaultReject> {
        let Some(mut s) = self.set(&w.set_id) else {
            return Err(VaultReject::ActNoSet);
        };
        if s.wind_down_height != 0 {
            return Err(VaultReject::ActWindDown);
        }
        let members = self.members(&w.set_id);
        if !cosigners(
            &s,
            &members,
            keys,
            0,
            usize::from(s.params.slash_threshold),
            None,
            h,
        ) {
            return Err(VaultReject::ActSigs);
        }
        s.wind_down_height = h;
        self.put_set(w.set_id, s);
        Ok(())
    }
}

/// `count` distinct current members of the set among `keys[from..]`, none equal to `exclude`,
/// and nothing else (C++ `cosigners`).
fn cosigners(
    s: &SetRecord,
    members: &[(PubKeyBytes, MemberRecord)],
    keys: &[PubKeyBytes],
    from: usize,
    count: usize,
    exclude: Option<&PubKeyBytes>,
    h: i64,
) -> bool {
    if keys.len() != from.saturating_add(count) {
        return false;
    }
    let mut seen = BTreeSet::new();
    for k in keys.iter().skip(from) {
        if exclude == Some(k) {
            return false;
        }
        if !seen.insert(*k) {
            return false;
        }
        let current = members
            .iter()
            .find(|(mk, _)| mk == k)
            .is_some_and(|(_, m)| is_current(s, m, h));
        if !current {
            return false;
        }
    }
    true
}

/// Ejects a member and freezes its bond (`SET_EQUIVOCATION`'s effect; the module ejection
/// hook's, U-25; C++ `EjectAndFreeze`): only a member of `set_id` whose bond is unspent
/// (indexed), unfrozen and its own. Returns false and changes nothing otherwise.
pub fn eject_and_freeze(st: &mut VaultOverlay<'_>, set_id: &SetId, key: &PubKeyBytes) -> bool {
    let Some(mut m) = st.member(set_id, key) else {
        return false;
    };
    let Some(mut b) = st
        .bond(&m.bond_outpoint)
        .filter(|b| !b.frozen && b.set_id == *set_id && b.member_key == *key)
    else {
        return false;
    };
    m.status = MemberStatus::Ejected;
    m.bond_frozen = true;
    b.frozen = true;
    st.put_member(*set_id, *key, m);
    st.put_bond(m.bond_outpoint, b);
    true
}

/// Applies a block over `base` (C++ `VaultState::ApplyBlock` on a fresh overlay): every
/// transaction in order, then each module's `check_block`. The result is the block's
/// [`Delta`] against `base`; on failure the block is invalid and `base` is unchanged.
pub fn apply_block(
    base: &dyn StateRead,
    txs: &[VaultTx],
    height: i64,
    coins: &dyn CoinAccessor,
    rules: &Rules<'_>,
) -> Result<Delta, VaultReject> {
    let mut st = VaultOverlay::new(base);
    st.apply_block(txs, height, coins, rules)?;
    Ok(st.delta())
}

/// The mempool check (C++ `vault::CheckTx`): would `tx` apply at `height` (tip + 1) over
/// `base` (the tip's state)? Returns the transaction's delta on success.
pub fn check_tx(
    base: &dyn StateRead,
    tx: &VaultTx,
    height: i64,
    coins: &dyn CoinAccessor,
    rules: &Rules<'_>,
) -> Result<Delta, VaultReject> {
    let mut st = VaultOverlay::new(base);
    st.apply_tx(tx, height, coins, rules)?;
    Ok(st.delta())
}
