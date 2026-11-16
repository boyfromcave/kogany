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
//! The state writer asks [`NonFinalizedState::refused_reorg`] before it publishes a commit or a
//! reconsideration, and [`NonFinalizedState::refused_invalidation`] before an invalidation. On a
//! refusal it records the message beside the state database ([`record`]), and exits; the node
//! shuts down on the writer's failure. While the record exists the node refuses to start
//! ([`recorded_for`]) and the writer exits at once ([`recorded`]), whether or not the
//! non-finalized backup is on, so a restarted node cannot adopt the branch because it lost the
//! tip it would have compared with.
//!
//! A restart must not undo the guard either. Blocks restored from the non-finalized backup carry
//! no receipt order, so two restored chains with exactly the same work are ordered by tip hash
//! (`Chain::cmp`), and a stored branch that ties the node's chain could become the best chain
//! 100 or more blocks back with no message. So the backup keeps the best tip it was written for
//! ([`persist_best_tip`]), and a restore puts the chain that holds that tip first, or refuses as
//! the running node does ([`after_restore`]).

use std::{
    ffi::OsString,
    fmt, fs,
    io::{self, Write},
    path::{Path, PathBuf},
};

use zakura_chain::{
    block::{self, Height},
    parameters::Network,
    transparent::MIN_TRANSPARENT_COINBASE_MATURITY,
};

use crate::{
    constants::{state_database_format_version_in_code, STATE_DATABASE_KIND},
    Config, ZakuraDb,
};

use super::{Chain, NonFinalizedState};

/// The most blocks a reorganisation may roll back: ycashd's `MAX_REORG_LENGTH`,
/// `COINBASE_MATURITY - 1` (ycash6 `src/main.h:69`).
pub(crate) const MAX_REORG_LENGTH: u32 = MIN_TRANSPARENT_COINBASE_MATURITY - 1;

/// The file, in the state database's directory, that records a refused reorganisation.
pub(crate) const REFUSAL_FILE_NAME: &str = "ycash-reorg-refused";

/// What is added to the non-finalized backup directory's name to name the file that keeps the
/// best tip the backup was written for. The file is beside the directory, not in it: the backup
/// deletes every file in its directory that is not named by a block hash.
pub(crate) const BEST_TIP_FILE_SUFFIX: &str = ".ycash-best-tip";

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

    /// Returns the refusal if invalidating `hash` moves the node to a branch that forks more
    /// than [`MAX_REORG_LENGTH`] blocks below the parent of `hash`.
    ///
    /// ycashd's `invalidateblock` disconnects the best chain down to that parent without asking
    /// the depth (`InvalidateBlock`, ycash6 `src/main.cpp:5245-5267`), then calls
    /// `ActivateBestChain` (`src/rpc/blockchain.cpp:2171-2175`), whose guard measures from the
    /// tip it finds, the parent (`src/main.cpp:5004-5008`). So the blocks at and above `hash`
    /// are not counted, and a branch that holds the parent rolls nothing back.
    ///
    /// `None` when `hash` is not in the best chain (the best chain keeps its tip), when it is
    /// the first non-finalized block (the parent is the finalized tip, which every chain
    /// keeps), and when the best chain after the invalidation holds the parent.
    pub(crate) fn refused_invalidation(&self, hash: block::Hash) -> Option<RefusedReorg> {
        let old = self.best_chain()?;
        let parent_height = Height(old.height_by_hash(hash)?.0.checked_sub(1)?);
        let parent = (parent_height, old.hash_by_height(parent_height)?);

        let mut after = self.clone();
        after.invalidate_block(hash).ok()?;
        let new = after.best_chain()?;
        if new.contains_block_hash(parent.1) {
            return None;
        }

        let (_, fork) = rollback(old, new);
        let rollback = parent.0 .0.saturating_sub(fork.0 .0);
        (rollback > MAX_REORG_LENGTH).then(|| RefusedReorg {
            rollback,
            old_tip: parent,
            new_tip: new.non_finalized_tip(),
            fork,
        })
    }
}

/// The path of the refusal record for the state database at `db_path`.
pub(crate) fn refusal_path(db_path: &Path) -> PathBuf {
    db_path.join(REFUSAL_FILE_NAME)
}

/// Writes `contents` to `path` so that a crash leaves the old file or the new one, never a part
/// of one: a temporary file beside it is written and synced, renamed over `path`, and the
/// directory is synced.
fn write_durably(path: &Path, contents: &[u8]) -> io::Result<()> {
    let mut temporary_name = path
        .file_name()
        .map(OsString::from)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "the path names no file"))?;
    temporary_name.push(".tmp");
    let temporary = path.with_file_name(temporary_name);

    let mut file = fs::File::create(&temporary)?;
    file.write_all(contents)?;
    file.sync_all()?;
    drop(file);
    fs::rename(&temporary, path)?;
    sync_parent_dir(path)
}

/// Syncs the directory that holds `path`, so a rename or a removal in it survives a crash.
fn sync_parent_dir(path: &Path) -> io::Result<()> {
    // A directory cannot be opened as a file on Windows; the rename itself is what it offers.
    #[cfg(unix)]
    if let Some(dir) = path.parent() {
        fs::File::open(dir)?.sync_all()?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

/// Records `message` beside the state database at `db_path`, and returns the record's path.
///
/// The record does not depend on the non-finalized backup. An ephemeral database is deleted with
/// its directory when the node stops, and the record with it: its next start is a new node at
/// genesis, which has no tip to roll back.
///
/// If the message cannot be written (a full disk), the file is still made, empty and without
/// touching a record that is there: [`recorded`] counts a file with no message, so the node
/// stays down either way. An error means there is no record at all.
pub(crate) fn record(db_path: &Path, message: &str) -> io::Result<PathBuf> {
    let path = refusal_path(db_path);
    if let Err(error) = write_durably(&path, message.as_bytes()) {
        tracing::error!(
            ?error,
            ?path,
            "could not write the refused reorganization's message: recording the refusal \
             without it"
        );
        fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)?
            .sync_all()?;
        sync_parent_dir(&path)?;
    }
    Ok(path)
}

/// What the node says when the record exists but holds no message it can show.
fn unreadable_record(path: &Path, why: &str) -> String {
    format!(
        "A refused block chain reorganization is recorded in {}, but the record {why}. The node \
         refused a reorganization that would roll back more than {MAX_REORG_LENGTH} blocks, and \
         it stops at every start while this file exists. Its log from the time of the refusal \
         names both tips and the fork point. To start the node again, follow \"Deep \
         reorganisations\" in docs/kogany.md: decide which chain to keep, then remove the file.",
        path.display()
    )
}

/// The recorded refusal for the state database at `db_path`, if there is one.
///
/// A record that exists but is empty or cannot be read still counts: the node stays down until
/// an operator removes the file, and the message says so.
pub(crate) fn recorded(db_path: &Path) -> Option<String> {
    let path = refusal_path(db_path);
    match fs::read_to_string(&path) {
        Ok(message) if message.trim().is_empty() => Some(unreadable_record(&path, "is empty")),
        Ok(message) => Some(message),
        Err(error) if error.kind() == io::ErrorKind::NotFound => None,
        Err(error) => Some(unreadable_record(
            &path,
            &format!("cannot be read ({error})"),
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

/// The path of the best-tip file for the non-finalized backup directory at `backup_dir_path`.
pub(crate) fn best_tip_path(backup_dir_path: &Path) -> PathBuf {
    let mut name = backup_dir_path
        .file_name()
        .map(OsString::from)
        .unwrap_or_default();
    name.push(BEST_TIP_FILE_SUFFIX);
    backup_dir_path.with_file_name(name)
}

/// The best tip the backup at `backup_dir_path` was written for, if it keeps one.
///
/// A file that cannot be read or parsed is no tip: it is written whole or not at all
/// ([`write_durably`]), so that is a damaged disk or another program's file.
pub(crate) fn persisted_best_tip(backup_dir_path: &Path) -> Option<(Height, block::Hash)> {
    let path = best_tip_path(backup_dir_path);
    let contents = match fs::read_to_string(&path) {
        Ok(contents) => contents,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return None,
        Err(error) => {
            tracing::warn!(?error, ?path, "could not read the backup's best tip");
            return None;
        }
    };
    let mut fields = contents.split_whitespace();
    let tip = match (fields.next(), fields.next(), fields.next()) {
        (Some(height), Some(hash), None) => height.parse().ok().map(Height).zip(hash.parse().ok()),
        _ => None,
    };
    if tip.is_none() {
        tracing::warn!(
            ?path,
            "the backup's best tip is not a height and a block hash"
        );
    }
    tip
}

/// Keeps `state`'s best tip beside the non-finalized backup at `backup_dir_path`, which was just
/// written from `state`.
///
/// The tip decides between restored chains only, so it is kept while the state holds more than
/// one chain, and written when it changes. With one chain or none the file is removed. A node
/// that follows one chain, as during its first sync, writes nothing here.
pub(crate) fn persist_best_tip(backup_dir_path: &Path, state: &NonFinalizedState) {
    let path = best_tip_path(backup_dir_path);
    let result = match state.best_tip().filter(|_| state.chain_count() > 1) {
        Some(tip) if persisted_best_tip(backup_dir_path) == Some(tip) => Ok(()),
        Some((height, hash)) => write_durably(&path, format!("{} {hash}\n", height.0).as_bytes()),
        None => match fs::remove_file(&path) {
            Ok(()) => sync_parent_dir(&path),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error),
        },
    };
    if let Err(error) = result {
        tracing::error!(
            ?error,
            ?path,
            "could not keep the best tip beside the non-finalized backup: after a restart, \
             chains with the same work are ordered by tip hash"
        );
    }
}

impl NonFinalizedState {
    /// Makes the best chain of this restored state the one that holds `persisted`, the best tip
    /// the backup was written for, or returns the refusal.
    ///
    /// - The best chain holds the tip: nothing to do.
    /// - Another chain holds it, with the same work as the best chain: that chain is preferred,
    ///   as if its tip had been received first. This is the order the running node had; only
    ///   the tie-break by tip hash is replaced.
    /// - Another chain holds it, with less work: switching to the best chain is a reorganisation
    ///   from the node's tip, refused above [`MAX_REORG_LENGTH`] blocks as at run time, and
    ///   followed otherwise.
    /// - No chain holds it: the restored order stands. The file is written after every block of
    ///   its state is in the backup, and a block leaves the backup only when the node's state
    ///   has left it (finalized, pruned, or invalidated by the operator), so the node was no
    ///   longer on that tip, or a block file was lost and the tip's chain cannot be named.
    fn settle_restored_best_chain(
        &mut self,
        persisted: (Height, block::Hash),
        finalized_state: &ZakuraDb,
    ) -> Option<RefusedReorg> {
        let best = self.best_chain()?.clone();
        if best.contains_block_hash(persisted.1) {
            return None;
        }
        let Some(old) = self
            .chain_iter()
            .find(|chain| chain.contains_block_hash(persisted.1))
            .cloned()
        else {
            tracing::warn!(
                ?persisted,
                restored_best_tip = ?best.non_finalized_tip(),
                "the best tip kept with the non-finalized backup is not among the restored \
                 blocks: the restored chains are ordered by work, then by tip hash"
            );
            return None;
        };

        if old.partial_cumulative_work == best.partial_cumulative_work {
            let old_tip = old.non_finalized_tip();
            tracing::info!(
                ?old_tip,
                other_tip = ?best.non_finalized_tip(),
                "two restored chains have the same work: keeping the chain the node was on"
            );
            self.precious_block(old_tip.1, finalized_state)
                .expect("the preferred block is the tip of a chain in this state");
            return None;
        }

        let (rollback, fork) = rollback(&old, &best);
        (rollback > MAX_REORG_LENGTH).then(|| RefusedReorg {
            rollback,
            old_tip: old.non_finalized_tip(),
            new_tip: best.non_finalized_tip(),
            fork,
        })
    }
}

/// Settles the best chain of `restored`, the state just read from the non-finalized backup at
/// `backup_dir_path`, against the best tip kept with that backup, and returns the state the
/// node starts with.
///
/// Without a kept tip (the first start with this guard, or a backup that held one chain) the
/// restored order stands, and the tip is kept from here on. On a refusal the message is
/// recorded beside the state database and `empty`, the state before the restore, is returned:
/// the writer finds the record when it starts and stops the node, and no reader is shown the
/// other branch in between. The backup is left as it is.
///
/// # Panics
///
/// If a refusal cannot be recorded: the node must not start as if nothing had happened.
pub(super) fn after_restore(
    mut restored: NonFinalizedState,
    empty: NonFinalizedState,
    backup_dir_path: &Path,
    finalized_state: &ZakuraDb,
) -> NonFinalizedState {
    let refused = persisted_best_tip(backup_dir_path)
        .and_then(|persisted| restored.settle_restored_best_chain(persisted, finalized_state));
    let Some(refused) = refused else {
        persist_best_tip(backup_dir_path, &restored);
        return restored;
    };

    let message = refused.to_string();
    tracing::error!("*** {message}");
    let path = record(finalized_state.path(), &message).unwrap_or_else(|error| {
        panic!(
            "could not record the refused reorganization beside the state database \
             ({error}): {message}"
        )
    });
    tracing::error!(
        ?path,
        "the blocks restored from the non-finalized backup would roll back the node's tip: \
         the refusal is recorded, and the node stops"
    );
    empty
}
