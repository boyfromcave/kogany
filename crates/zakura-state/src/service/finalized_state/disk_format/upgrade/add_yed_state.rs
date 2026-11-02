//! Add the Ycash Yellowback (YED) index column families (kogany plan W5-e).
//!
//! The nineteen YED column families (`yed_<table>` for the seventeen tables, the undo `yed_undo`
//! and the rules stamp `yed_rules`) are created empty when an older database is opened. That is
//! the right state for every block below the YED start height (the Vault activation height with
//! a YED attestor set), which is every block an older database can hold where Yellowback is
//! configured.
//!
//! A database whose finalized tip is already at or above the start height was written by code
//! that did not evaluate the module. ycash6 rebuilds its index from the block files
//! (`SyncToChain`); kogany has no in-place rebuild, so this migration refuses such a database and
//! asks for a resync (as the vault state's migration does, K-14).

use semver::Version;
use std::sync::mpsc::TryRecvError;
use zakura_chain::block::Height;

use crate::service::finalized_state::{zakura_db::yed::yed_params_for_db, ZakuraDb};

use super::{CancelFormatChange, CancelReceiver, DiskFormatUpgrade, FormatChangeError};

/// Implements [`DiskFormatUpgrade`] for adding the YED index column families.
pub struct Upgrade;

impl DiskFormatUpgrade for Upgrade {
    fn version(&self) -> Version {
        Version::new(30, 2, 0)
    }

    fn description(&self) -> &'static str {
        "add the Yellowback (YED) index column families"
    }

    fn run(
        &self,
        initial_finalized_tip_height: Option<Height>,
        db: &ZakuraDb,
        cancel_receiver: &CancelReceiver,
    ) -> Result<(), FormatChangeError> {
        check_cancelled(cancel_receiver)?;
        match missing_yed_epoch(initial_finalized_tip_height, db) {
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
        let below_start = match (db.finalized_tip_height(), yed_params_for_db(db)) {
            (Some(tip), Ok(Some(p))) => i64::from(tip.0) < i64::from(p.start_height),
            _ => true,
        };
        if below_start && db.yed_tip().is_some() {
            return Ok(Err(
                "a YED index tip is stored but the finalized tip is below the YED start height, \
                 or Yellowback is not configured"
                    .to_string(),
            ));
        }
        Ok(Ok(()))
    }
}

/// `Some(reason)` when the database holds YED-epoch blocks without their index.
pub(crate) fn missing_yed_epoch(tip: Option<Height>, db: &ZakuraDb) -> Option<String> {
    let tip = tip?;
    let p = yed_params_for_db(db).ok()??;
    (i64::from(tip.0) >= i64::from(p.start_height) && db.yed_tip().is_none()).then(|| {
        format!(
            "the finalized tip {tip:?} is at or above the Yellowback start height {}, but the \
             database has no YED index",
            p.start_height
        )
    })
}

fn check_cancelled(cancel_receiver: &CancelReceiver) -> Result<(), CancelFormatChange> {
    match cancel_receiver.try_recv() {
        Err(TryRecvError::Empty) => Ok(()),
        _ => Err(CancelFormatChange),
    }
}
