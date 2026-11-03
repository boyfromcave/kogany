//! Prototype [`VaultReadState`]s, until plan W4-d reads the real vault state.
//!
//! - [`UnavailableVaultState`]: the chain tip, no Vault upgrade scheduled, no vault database.
//!   `vault_getinfo` answers without counts; the other reads answer `-32603 "the vault database
//!   is not available"`, ycash6's answer when `g_vaultdb` is not open. `zakurad` serves this by
//!   default.
//! - [`MockVaultState`]: the chain tip and a fixed set-state fixture (two sets, three members,
//!   a vault and the intent unlocked from it), every script built with `kogany_vault`'s
//!   template builders. `zakurad` serves it when `KOGANY_VAULT_RPC_MOCK=1` is set, so the RPC
//!   shapes can be checked against `ycash6/doc/vault-rpc-contract.json` before W4-d.

use std::sync::Arc;

use async_trait::async_trait;
use kogany_vault::{
    act::SetCreateBody,
    template::{build_intent, build_vault, intent_for, VaultParams},
    Hash32, OutPoint, PqOwner, PubKeyBytes, SetId, Tag,
};
use zakura_chain::chain_tip::ChainTip;

use crate::state::{
    DbTip, MemberStatus, MemberView, SetView, TemplateKind, TemplateOutRecord, VaultReadState,
    VaultSnapshot, VaultStateView, VaultUpgradeInfo,
};

/// The environment variable that makes `zakurad` serve [`MockVaultState`].
pub const MOCK_ENV: &str = "KOGANY_VAULT_RPC_MOCK";

/// The best tip's height and hash (internal order); height -1 before genesis, as ycashd's
/// `chainActive.Height()`.
fn tip_of<T: ChainTip>(tip: &T) -> (i64, Hash32) {
    match tip.best_tip_height_and_hash() {
        Some((height, hash)) => (i64::from(height.0), Hash32(hash.0)),
        None => (-1, Hash32::ZERO),
    }
}

fn upgrade_at(tip_height: i64) -> VaultUpgradeInfo {
    VaultUpgradeInfo {
        tip_height,
        activation_height: None,
        active_at_next: false,
        attestor_set_id: None,
    }
}

/// The chain tip with no vault database (see the module documentation).
#[derive(Clone)]
pub struct UnavailableVaultState<T> {
    tip: T,
}

impl<T> UnavailableVaultState<T> {
    /// No vault state, at `tip`.
    pub fn new(tip: T) -> Self {
        Self { tip }
    }
}

#[async_trait]
impl<T: ChainTip + Send + Sync + 'static> VaultReadState for UnavailableVaultState<T> {
    async fn snapshot(&self) -> Result<VaultSnapshot, String> {
        let (height, _) = tip_of(&self.tip);
        Ok(VaultSnapshot {
            upgrade: upgrade_at(height),
            db: None,
        })
    }
}

/// The chain tip with the fixture database (see the module documentation).
#[derive(Clone)]
pub struct MockVaultState<T> {
    tip: T,
}

impl<T> MockVaultState<T> {
    /// The fixture, at `tip`.
    pub fn new(tip: T) -> Self {
        Self { tip }
    }
}

#[async_trait]
impl<T: ChainTip + Send + Sync + 'static> VaultReadState for MockVaultState<T> {
    async fn snapshot(&self) -> Result<VaultSnapshot, String> {
        let (height, hash) = tip_of(&self.tip);
        Ok(VaultSnapshot {
            upgrade: upgrade_at(height),
            db: Some(Arc::new(Fixture::new(DbTip { hash, height }))),
        })
    }
}

/// A fixed set state.
#[derive(Clone, Debug)]
pub struct Fixture {
    tip: DbTip,
    sets: Vec<SetView>,
    outputs: Vec<TemplateOutRecord>,
}

fn filled(byte: u8) -> Hash32 {
    Hash32([byte; 32])
}

fn key(byte: u8) -> PubKeyBytes {
    let mut k = [byte; 33];
    k[0] = 0x02;
    PubKeyBytes(k)
}

impl Fixture {
    /// The first set's id.
    pub const SET_A: SetId = Hash32([0x5a; 32]);
    /// The second (rate-limited, memberless) set's id.
    pub const SET_B: SetId = Hash32([0x5b; 32]);
    /// The vault owner.
    pub const OWNER: PqOwner = PqOwner {
        scheme: 1,
        hash: Hash32([0x0c; 32]),
    };

    /// The fixture at `tip` (its heights are fixed, whatever the tip).
    pub fn new(tip: DbTip) -> Self {
        let params = |seats, rate_limit_bps| SetCreateBody {
            seats,
            unlock_threshold: 1,
            cancel_threshold: 1,
            slash_threshold: 1,
            flags: 0,
            rate_limit_bps,
            rate_window: 10,
            liveness_window: 100,
            bond_min: 50_000_000,
            bond_lock_min: 0,
            maturity: 2,
            admit_key: key(0xad),
        };
        let member = |byte, status, current, exit_height| MemberView {
            key: key(byte),
            status,
            current,
            live: current,
            join_height: 207,
            last_act: 209,
            bond_outpoint: OutPoint {
                txid: filled(byte),
                n: 1,
            },
            bond_value: 100_000_000,
            bond_locktime: 705,
            bond_frozen: false,
            exit_height,
        };
        let set_a = SetView {
            id: Self::SET_A,
            params: params(2, 0),
            create_height: 206,
            winddown_height: 0,
            locked_value: 500_000_000,
            epoch: 0,
            epoch_basis: 0,
            epoch_used: 0,
            unlock_available: None,
            active: 1,
            current: 1,
            dormant: false,
            released: false,
            members: vec![
                member(0x11, MemberStatus::Active, true, None),
                member(0x22, MemberStatus::Withdrawn, false, Some(212)),
            ],
        };
        let set_b = SetView {
            id: Self::SET_B,
            params: params(2, 5000),
            create_height: 206,
            winddown_height: 0,
            locked_value: 0,
            epoch: 20,
            epoch_basis: 0,
            epoch_used: 0,
            unlock_available: Some(0),
            active: 0,
            current: 0,
            dormant: false,
            released: false,
            members: vec![],
        };

        let vault = VaultParams {
            tag: Tag(*b"TEST"),
            cancel_set_id: Self::SET_A,
            delay: 3,
            set_id: Self::SET_A,
            owner_height: 410,
            owner: Self::OWNER,
            app_height: 0,
        };
        // The builders accept these in-range parameters, so the scripts are never empty.
        let vault_script = build_vault(&vault).unwrap_or_default();
        let recipient = [0x76, 0xa9, 0x14, 0x33];
        let intent_script =
            build_intent(&intent_for(&vault, &vault_script, &recipient)).unwrap_or_default();
        let outputs = vec![
            TemplateOutRecord {
                outpoint: OutPoint {
                    txid: filled(0x71),
                    n: 0,
                },
                kind: TemplateKind::Vault,
                value: 500_000_000,
                height: 210,
                script: vault_script.clone(),
                origin: vec![],
            },
            TemplateOutRecord {
                outpoint: OutPoint {
                    txid: filled(0x72),
                    n: 0,
                },
                kind: TemplateKind::Intent,
                value: 200_000_000,
                height: 211,
                script: intent_script,
                origin: vault_script,
            },
        ];

        Self {
            tip,
            sets: vec![set_a, set_b],
            outputs,
        }
    }
}

impl VaultStateView for Fixture {
    fn db_tip(&self) -> Option<DbTip> {
        Some(self.tip)
    }

    fn state_hash(&self) -> Hash32 {
        filled(0x5e)
    }

    fn set_ids(&self) -> Vec<SetId> {
        self.sets.iter().map(|s| s.id).collect()
    }

    fn set(&self, id: &SetId, _at_height: i64) -> Option<SetView> {
        self.sets.iter().find(|s| s.id == *id).cloned()
    }

    fn template_outputs(&self) -> Vec<TemplateOutRecord> {
        self.outputs.clone()
    }
}
