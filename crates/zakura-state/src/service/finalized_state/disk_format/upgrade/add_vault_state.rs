//! Add the Vault upgrade's set-state column families (kogany plan W4-c).
//!
//! The four vault column families (`vault_set`, `vault_member`, `vault_bond`,
//! `vault_template_out`) are created empty when an older database is opened. That is the right
//! state for every block below the network's Vault activation height, which is every block an
//! older database can hold on a network where the upgrade is not yet scheduled.
//!
//! A database whose finalized tip is already at or above the activation height was written by
//! code that did not compute the vault transition. ycash6 rebuilds its vault database by replaying
//! acts from undo on `-reindex`; Zakura has no per-block undo for finalized blocks, so this
//! migration refuses such a database and asks for a resync (K-14).

use semver::Version;
use std::sync::mpsc::TryRecvError;
use zakura_chain::block::Height;

use crate::service::finalized_state::{zakura_db::vault::vault_network_params, ZakuraDb};

use super::{CancelFormatChange, CancelReceiver, DiskFormatUpgrade, FormatChangeError};

/// Implements [`DiskFormatUpgrade`] for adding the vault column families.
pub struct Upgrade;

impl DiskFormatUpgrade for Upgrade {
    fn version(&self) -> Version {
        Version::new(30, 1, 0)
    }

    fn description(&self) -> &'static str {
        "add the Vault upgrade's set-state column families"
    }

    fn run(
        &self,
        initial_finalized_tip_height: Option<Height>,
        db: &ZakuraDb,
        cancel_receiver: &CancelReceiver,
    ) -> Result<(), FormatChangeError> {
        check_cancelled(cancel_receiver)?;
        match missing_vault_epoch(initial_finalized_tip_height, db) {
            Some(message) => Err(FormatChangeError::ResyncRequired(message)),
            None => Ok(()),
        }
    }

    fn validate(
        &self,
        db: &ZakuraDb,
        cancel_receiver: &CancelReceiver,
    ) -> Result<Result<(), String>, FormatChangeError> {
        check_cancelled(cancel_receiver)?;
        let below_activation = match (
            db.finalized_tip_height(),
            vault_network_params(&db.network()),
        ) {
            (None, _) | (_, None) => true,
            (Some(tip), Some(params)) => !params.is_active(tip),
        };
        if below_activation && db.has_vault_state() {
            return Ok(Err(
                "vault state is stored but the finalized tip is below the Vault activation height"
                    .to_string(),
            ));
        }
        Ok(Ok(()))
    }
}

/// `Some(reason)` when the database holds Vault-epoch blocks without their vault state.
fn missing_vault_epoch(tip: Option<Height>, db: &ZakuraDb) -> Option<String> {
    let tip = tip?;
    let params = vault_network_params(&db.network())?;
    (params.is_active(tip) && !db.has_vault_state()).then(|| {
        format!(
            "the finalized tip {tip:?} is at or above the Vault activation height {:?}, \
             but the database has no vault state",
            params.activation_height
        )
    })
}

fn check_cancelled(cancel_receiver: &CancelReceiver) -> Result<(), CancelFormatChange> {
    match cancel_receiver.try_recv() {
        Err(TryRecvError::Empty) => Ok(()),
        _ => Err(CancelFormatChange),
    }
}
