//! The read boundary between the vault RPCs and the node's vault state.
//!
//! The RPC layer formats; it computes nothing a block could change. Everything the set state
//! machine decides (membership, liveness, dormancy, release, the rate-limit cap, the state hash)
//! comes from a [`VaultStateView`], which plan W4-d implements over zakura-state's vault column
//! families (W4-c) and W4-b's state machine. This crate ships two implementations for the
//! prototype: [`crate::mock::MockVaultState`] (a fixed fixture) and
//! [`crate::mock::UnavailableVaultState`] (no vault database).
//!
//! Byte conventions follow `kogany_vault::bytes`: ids, hashes and outpoint txids are in internal
//! byte order; the RPC layer reverses them for display.
//!
//! One call reads one [`VaultSnapshot`], so every field of one answer is taken at one tip, as
//! ycash6 reads one `SetSnapshot` under `cs_main` (`src/rpc/vault.cpp`, `Snapshot()`).

use std::sync::Arc;

use async_trait::async_trait;
use kogany_vault::{act::SetCreateBody, Hash32, OutPoint, PubKeyBytes, SetId};

/// The node's vault state, as the read RPCs see it.
#[async_trait]
pub trait VaultReadState: Send + Sync + 'static {
    /// The vault state at the current best tip.
    ///
    /// An `Err` is answered as RPC error `-32603` with its text; ycash6 answers
    /// `"the vault database is not available"` there.
    async fn snapshot(&self) -> Result<VaultSnapshot, String>;
}

#[async_trait]
impl<S: VaultReadState + ?Sized> VaultReadState for Arc<S> {
    async fn snapshot(&self) -> Result<VaultSnapshot, String> {
        (**self).snapshot().await
    }
}

/// The vault state at one tip.
#[derive(Clone)]
pub struct VaultSnapshot {
    /// The chain and upgrade facts at this tip.
    pub upgrade: VaultUpgradeInfo,
    /// The set-state database at this tip, `None` when it is not open (ycash6: `g_vaultdb`
    /// null). `vault_getinfo` then omits its counts and `statehash`; the other reads fail.
    pub db: Option<Arc<dyn VaultStateView>>,
}

/// The chain and upgrade facts every read needs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VaultUpgradeInfo {
    /// The best tip's height.
    pub tip_height: i64,
    /// The Vault upgrade's activation height on this network, `None` when it is not scheduled.
    pub activation_height: Option<i64>,
    /// Whether the upgrade is active at the next block (`tip_height + 1`).
    pub active_at_next: bool,
    /// The set the registered module (YED) governs on this node, `None` when it governs none.
    pub attestor_set_id: Option<SetId>,
}

/// The set-state database at one tip.
///
/// Every method answers from the same state. Lists are in the database's key order, which is
/// the order ycash6 lists them in (`ListSets`, `ListTemplateOuts`).
pub trait VaultStateView: Send + Sync {
    /// The block the set state is at, `None` before the first active block.
    fn db_tip(&self) -> Option<DbTip>;

    /// The canonical state hash (ycash6 `StateHash`, `src/vault/node.cpp`), internal order.
    fn state_hash(&self) -> Hash32;

    /// Every set id, in key order.
    fn set_ids(&self) -> Vec<SetId>;

    /// The set `id` with its predicates evaluated at `at_height` over this state, `None` for
    /// an unknown set.
    fn set(&self, id: &SetId, at_height: i64) -> Option<SetView>;

    /// The unspent vault and intent outputs (the template-output index), in key order.
    fn template_outputs(&self) -> Vec<TemplateOutRecord>;
}

/// A block hash (internal order) and height.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DbTip {
    /// The block hash.
    pub hash: Hash32,
    /// The block height.
    pub height: i64,
}

/// One set, evaluated at a height (ycash6 `SetJSON`'s inputs, with the state machine's
/// predicates already applied).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SetView {
    /// The set id.
    pub id: SetId,
    /// The `SET_CREATE` parameters.
    pub params: SetCreateBody,
    /// The height the set was created at.
    pub create_height: i64,
    /// The wind-down height, 0 for none.
    pub winddown_height: i64,
    /// The value the set's vaults hold, zatoshi.
    pub locked_value: i64,
    /// The stored rate-limit epoch.
    pub epoch: i64,
    /// The stored epoch basis, zatoshi.
    pub epoch_basis: i64,
    /// The stored epoch use, zatoshi.
    pub epoch_used: i64,
    /// What may still be unlocked in the epoch of the evaluation height, zatoshi; `None` when
    /// the set is not rate limited.
    pub unlock_available: Option<i64>,
    /// Members with `active` status.
    pub active: i64,
    /// Current members at the evaluation height.
    pub current: i64,
    /// The dormancy predicate (upgrade plan §15.4).
    pub dormant: bool,
    /// The release predicate (upgrade plan §15.4).
    pub released: bool,
    /// Every member, in key order.
    pub members: Vec<MemberView>,
}

/// A member's status (ycash6 `MEMBER_*`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MemberStatus {
    /// `active`
    Active,
    /// `removed`
    Removed,
    /// `ejected`
    Ejected,
    /// `withdrawn`
    Withdrawn,
}

impl MemberStatus {
    /// The RPC name.
    pub fn name(self) -> &'static str {
        match self {
            MemberStatus::Active => "active",
            MemberStatus::Removed => "removed",
            MemberStatus::Ejected => "ejected",
            MemberStatus::Withdrawn => "withdrawn",
        }
    }
}

/// One member, evaluated at the set's evaluation height.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemberView {
    /// The member key.
    pub key: PubKeyBytes,
    /// The status.
    pub status: MemberStatus,
    /// Whether the member is current.
    pub current: bool,
    /// Whether the member is current and acted within the liveness window.
    pub live: bool,
    /// The join height.
    pub join_height: i64,
    /// The height of the member's last act.
    pub last_act: i64,
    /// The bond output.
    pub bond_outpoint: OutPoint,
    /// The bond value, zatoshi.
    pub bond_value: i64,
    /// The bond's CLTV locktime.
    pub bond_locktime: u32,
    /// Whether the bond is frozen.
    pub bond_frozen: bool,
    /// The bond's exit height, while the member has left and its bond is unspent.
    pub exit_height: Option<i64>,
}

/// Whether a template output is a vault or an intent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TemplateKind {
    /// A vault V output.
    Vault,
    /// An intent I output.
    Intent,
}

/// One entry of the template-output index (ycash6 `TemplateOutRecord`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TemplateOutRecord {
    /// The output.
    pub outpoint: OutPoint,
    /// Vault or intent.
    pub kind: TemplateKind,
    /// The value, zatoshi.
    pub value: i64,
    /// The height it was confirmed at.
    pub height: i64,
    /// Its scriptPubKey.
    pub script: Vec<u8>,
    /// For an intent, the scriptPubKey of the vault it was unlocked from; empty for a vault.
    pub origin: Vec<u8>,
}
