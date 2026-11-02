//! The vault read RPCs over the node's real set state (kogany plan W4-d): a [`VaultReadState`]
//! that reads `zakura_state`'s best-chain vault snapshot (`ReadRequest::BestChainVaultSnapshot`)
//! and evaluates the §15.4 predicates with `kogany_vault::state`, as ycash6's `src/rpc/vault.cpp`
//! reads one `SetSnapshot` under `cs_main` and evaluates them in `SetJSON`.

use std::sync::Arc;

use async_trait::async_trait;
use kogany_vault::{
    state::{
        count_active, count_current, is_current, is_dormant, is_released, rate_cap,
        records::key_template_out, SetState, StateRead,
    },
    Hash32, SetId,
};
use tower::{Service, ServiceExt};
use zakura_chain::{block::Height, parameters::Network};
use zakura_state::{BoxError, ReadRequest, ReadResponse};

use crate::state::{
    DbTip, MemberStatus, MemberView, SetView, TemplateKind, TemplateOutRecord, VaultReadState,
    VaultSnapshot, VaultStateView, VaultUpgradeInfo,
};

/// The vault state of a running node: the best chain tip's set state from the read state
/// service `read_state`, on `network`.
#[derive(Clone)]
pub struct LiveVaultState<R> {
    network: Network,
    read_state: R,
}

impl<R> LiveVaultState<R> {
    /// The live state of `read_state` on `network`.
    pub fn new(network: Network, read_state: R) -> Self {
        Self {
            network,
            read_state,
        }
    }
}

#[async_trait]
impl<R> VaultReadState for LiveVaultState<R>
where
    R: Service<ReadRequest, Response = ReadResponse, Error = BoxError>
        + Clone
        + Send
        + Sync
        + 'static,
    R::Future: Send,
{
    async fn snapshot(&self) -> Result<VaultSnapshot, String> {
        let response = self
            .read_state
            .clone()
            .oneshot(ReadRequest::BestChainVaultSnapshot)
            .await
            .map_err(|e| e.to_string())?;
        let ReadResponse::VaultSnapshot(Some(snapshot)) = response else {
            return Err("the vault database is not available".to_owned());
        };
        Ok(snapshot_at(&self.network, snapshot))
    }
}

/// The RPC view of one state snapshot on `network`.
pub fn snapshot_at(network: &Network, snapshot: zakura_state::vault::VaultSnapshot) -> VaultSnapshot {
    // A height fits in an i64; -1 before genesis, as ycashd's `chainActive.Height()`.
    let tip_height = snapshot.tip.map_or(-1, |(height, _)| i64::from(height.0));
    let next = snapshot
        .tip
        .map_or(Some(Height(0)), |(height, _)| height.next().ok());
    let upgrade = VaultUpgradeInfo {
        tip_height,
        activation_height: network
            .vault_activation_height()
            .map(|height| i64::from(height.0)),
        active_at_next: next.is_some_and(|height| network.is_vault_active(height)),
        // No module governs a set until plan W5-f registers YED.
        attestor_set_id: None,
    };
    // ycash6 writes the vault database's tip marker in the blocks it connects from activation
    // (and wipes it when the activation block is disconnected).
    let db_tip = snapshot
        .tip
        .filter(|(height, _)| network.is_vault_active(*height))
        .map(|(height, hash)| DbTip {
            hash: Hash32(hash.0),
            height: i64::from(height.0),
        });
    VaultSnapshot {
        upgrade,
        db: Some(Arc::new(LiveView {
            tip: db_tip,
            state: snapshot.state,
        })),
    }
}

/// One snapshot's set state, read by the RPCs.
struct LiveView {
    tip: Option<DbTip>,
    state: Arc<SetState>,
}

fn member_status(status: kogany_vault::state::MemberStatus) -> MemberStatus {
    use kogany_vault::state::MemberStatus as S;
    match status {
        S::Active => MemberStatus::Active,
        S::Removed => MemberStatus::Removed,
        S::Ejected => MemberStatus::Ejected,
        S::Withdrawn => MemberStatus::Withdrawn,
    }
}

impl VaultStateView for LiveView {
    fn db_tip(&self) -> Option<DbTip> {
        self.tip
    }

    fn state_hash(&self) -> Hash32 {
        self.state.state_hash()
    }

    fn set_ids(&self) -> Vec<SetId> {
        self.state.set_ids()
    }

    fn set(&self, id: &SetId, h: i64) -> Option<SetView> {
        let s = self.state.set(id)?;
        let members = self.state.members(id);
        // The epoch fields as they stand at h (U-20 rolls them lazily on the next change).
        let e = h.checked_div(i64::from(s.params.rate_window)).unwrap_or(0);
        let (basis, used) = if e == s.epoch {
            (s.epoch_basis, s.epoch_used)
        } else {
            (s.locked_value, 0)
        };
        let unlock_available = (s.params.rate_limit_bps != 0).then(|| {
            let cap = rate_cap(basis, s.params.rate_limit_bps);
            if cap > used {
                cap.saturating_sub(used)
            } else {
                0
            }
        });
        let since = h.saturating_sub(i64::from(s.params.liveness_window));
        let member_views = members
            .iter()
            .map(|(key, m)| {
                let current = is_current(&s, m, h);
                MemberView {
                    key: *key,
                    status: member_status(m.status),
                    current,
                    live: current && m.last_act >= since,
                    join_height: m.join_height,
                    last_act: m.last_act,
                    bond_outpoint: m.bond_outpoint,
                    bond_value: m.bond_value,
                    bond_locktime: m.bond_locktime,
                    bond_frozen: m.bond_frozen,
                    exit_height: self
                        .state
                        .bond(&m.bond_outpoint)
                        .map(|b| b.exit_height)
                        .filter(|&exit| exit != 0),
                }
            })
            .collect();
        Some(SetView {
            id: *id,
            params: s.params,
            create_height: s.create_height,
            winddown_height: s.wind_down_height,
            locked_value: s.locked_value,
            epoch: s.epoch,
            epoch_basis: s.epoch_basis,
            epoch_used: s.epoch_used,
            unlock_available,
            // A member count fits in an i64.
            active: count_active(&members) as i64,
            current: count_current(&s, &members, h) as i64,
            dormant: is_dormant(&s, &members, h),
            released: is_released(Some(&s), &members, h),
            members: member_views,
        })
    }

    fn template_outputs(&self) -> Vec<TemplateOutRecord> {
        // The database's key order: 'v' || txid || n (little-endian).
        let mut outputs: Vec<_> = self.state.template_outs.iter().collect();
        outputs.sort_by_key(|(outpoint, _)| key_template_out(outpoint));
        outputs
            .into_iter()
            .map(|(outpoint, record)| TemplateOutRecord {
                outpoint: *outpoint,
                kind: match record.kind {
                    kogany_vault::state::TemplateOutKind::Vault => TemplateKind::Vault,
                    kogany_vault::state::TemplateOutKind::Intent => TemplateKind::Intent,
                },
                value: record.value,
                height: record.height,
                script: record.script_pubkey.clone(),
                origin: record.origin.clone(),
            })
            .collect()
    }
}
