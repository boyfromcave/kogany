//! kogany (beta3 R1): ycashd's reorganisation guard (Ycash build only).
//!
//! ycashd refuses to roll back more than `MAX_REORG_LENGTH = COINBASE_MATURITY - 1` = 99 blocks
//! (ycash6 `src/main.h:69`). In `ActivateBestChainStep` the depth is the old tip's height minus
//! the fork point's (`src/main.cpp:5004`); above 99 (`:5006`), before any block is disconnected,
//! it logs and shows the message below (`:5007-5018`), calls `StartShutdown()` and returns
//! (`:5021-5022`). Nothing is marked invalid: every block on both branches stays valid, the node
//! stops on its old tip. Zakura follows any branch that forks at or above its finalized tip,
//! up to `MAX_BLOCK_REORG_HEIGHT` = 1,000 blocks back, and that window is unchanged here.
//!
//! This is fork choice, not block validity: the guard never rejects a block, it stops the node
//! before the best chain changes.
//!
//! The state writer asks [`NonFinalizedState::refused_reorg`] before it publishes a commit. On a
//! refusal it records the message beside the state database ([`record`]), and exits; the node
//! shuts down on the writer's failure. While the record exists the node refuses to start
//! ([`recorded_for`]) and the writer exits at once ([`recorded`]), whether or not the
//! non-finalized backup is on, so a restarted node cannot adopt the branch because it lost the
//! tip it would have compared with.

use std::{
    fmt, fs, io,
    path::{Path, PathBuf},
};

use zakura_chain::{
    block::{self, Height},
    parameters::Network,
    transparent::MIN_TRANSPARENT_COINBASE_MATURITY,
};

use crate::{
    constants::{state_database_format_version_in_code, STATE_DATABASE_KIND},
    Config,
};

use super::{Chain, NonFinalizedState};

/// The most blocks a reorganisation may roll back: ycashd's `MAX_REORG_LENGTH`,
/// `COINBASE_MATURITY - 1` (ycash6 `src/main.h:69`).
pub(crate) const MAX_REORG_LENGTH: u32 = MIN_TRANSPARENT_COINBASE_MATURITY - 1;

/// The file, in the state database's directory, that records a refused reorganisation.
pub(crate) const REFUSAL_FILE_NAME: &str = "ycash-reorg-refused";

/// A change of best chain the guard refuses.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RefusedReorg {
    /// The blocks the change would disconnect: the old tip's height minus the fork point's.
    pub(crate) rollback: u32,
    /// The best tip before the change.
    pub(crate) old_tip: (Height, block::Hash),
    /// The best tip after the change.
    pub(crate) new_tip: (Height, block::Hash),
    /// The last block the two chains share.
    pub(crate) fork: (Height, block::Hash),
}

impl fmt::Display for RefusedReorg {
    /// ycashd's message, word for word (ycash6 `src/main.cpp:5007-5018`), without the two
    /// `work` fields: a non-finalized chain holds its work above the finalized tip only.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "A block chain reorganization has been detected that would roll back {} blocks! \
             This is larger than the maximum of {} blocks, and so the node is shutting down for \
             your safety.\n\n\
             Reorganization details:\n\
             - Current tip: {}, height {}\n\
             - New tip:     {}, height {}\n\
             - Fork point:  {}, height {}\n\n\
             Please help, human!",
            self.rollback,
            MAX_REORG_LENGTH,
            self.old_tip.1,
            self.old_tip.0 .0,
            self.new_tip.1,
            self.new_tip.0 .0,
            self.fork.1,
            self.fork.0 .0,
        )
    }
}

/// The last block `old` and `new` share, and how many blocks of `old` are above it.
///
/// Every non-finalized chain starts at the child of the finalized tip, so two chains share a
/// prefix: the fork point is the last height at which both hold the same block, or the finalized
/// tip if they share none.
fn rollback(old: &Chain, new: &Chain) -> (u32, (Height, block::Hash)) {
    let root = old
        .blocks
        .values()
        .next()
        .expect("non-finalized chains contain a block");
    let mut fork = (
        Height(root.height.0.saturating_sub(1)),
        root.block.header.previous_block_hash,
    );
    for (height, block) in &old.blocks {
        if new.hash_by_height(*height) != Some(block.hash) {
            break;
        }
        fork = (*height, block.hash);
    }

    (
        old.non_finalized_tip_height().0.saturating_sub(fork.0 .0),
        fork,
    )
}

impl NonFinalizedState {
    /// Returns the refusal if replacing `self` with `after` rolls back more than
    /// [`MAX_REORG_LENGTH`] blocks of the best chain: 99 pass, 100 stop, as on ycashd.
    ///
    /// `None` when the best tip is unchanged or extended (nothing is rolled back), and when
    /// `self` has no non-finalized block (the tip is the finalized tip, which every chain keeps).
    pub(crate) fn refused_reorg(&self, after: &NonFinalizedState) -> Option<RefusedReorg> {
        let old = self.best_chain()?;
        let new = after.best_chain()?;
        let old_tip = old.non_finalized_tip();
        if new.contains_block_hash(old_tip.1) {
            return None;
        }

        let (rollback, fork) = rollback(old, new);
        (rollback > MAX_REORG_LENGTH).then(|| RefusedReorg {
            rollback,
            old_tip,
            new_tip: new.non_finalized_tip(),
            fork,
        })
    }
}

/// The path of the refusal record for the state database at `db_path`.
pub(crate) fn refusal_path(db_path: &Path) -> PathBuf {
    db_path.join(REFUSAL_FILE_NAME)
}

/// Records `message` beside the state database at `db_path`, and returns the record's path.
///
/// The record does not depend on the non-finalized backup. An ephemeral database is deleted with
/// its directory when the node stops, and the record with it: its next start is a new node at
/// genesis, which has no tip to roll back.
pub(crate) fn record(db_path: &Path, message: &str) -> io::Result<PathBuf> {
    let path = refusal_path(db_path);
    fs::write(&path, message)?;
    fs::File::open(&path)?.sync_all()?;
    Ok(path)
}

/// The recorded refusal for the state database at `db_path`, if there is one.
///
/// A record that exists but cannot be read still counts: the node stays down until an operator
/// removes the file.
pub(crate) fn recorded(db_path: &Path) -> Option<String> {
    let path = refusal_path(db_path);
    match fs::read_to_string(&path) {
        Ok(message) => Some(message),
        Err(error) if error.kind() == io::ErrorKind::NotFound => None,
        Err(error) => Some(format!(
            "a refused block chain reorganization is recorded in {} ({error})",
            path.display()
        )),
    }
}

/// The refusal on record for the state that `config` opens on `network`, with the record's path:
/// what the node checks before it starts.
///
/// `None` for an ephemeral state, which starts empty.
pub fn recorded_for(config: &Config, network: &Network) -> Option<(PathBuf, String)> {
    if config.ephemeral {
        return None;
    }
    let db_path = config.db_path(
        STATE_DATABASE_KIND,
        state_database_format_version_in_code().major,
        network,
    );
    recorded(&db_path).map(|message| (refusal_path(&db_path), message))
}
