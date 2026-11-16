//! Chain data serialization formats for finalized data.
//!
//! # Correctness
//!
//! [`crate::constants::state_database_format_version_in_code()`] must be incremented
//! each time the database format (column, serialization, etc) changes.

use std::collections::BTreeMap;

use thiserror::Error;

use zakura_chain::{
    amount::NonNegative,
    block::Height,
    block_info::BlockInfo,
    history_tree::{HistoryTreeError, NonEmptyHistoryTree},
    parameters::{Network, NetworkKind},
    primitives::zcash_history,
    serialization::bincode_format::{self, BincodeError},
    value_balance::ValueBalance,
};

use crate::service::finalized_state::disk_format::{FromDisk, IntoDisk};

/// An error decoding a persisted history-tree snapshot.
#[derive(Debug, Error)]
pub enum HistoryTreeDecodeError {
    /// The snapshot does not use either supported serialization format.
    #[error(
        "history tree snapshot is neither the current nor legacy format: \
         current format error: {current}; legacy format error: {legacy}"
    )]
    InvalidEncoding {
        /// The current-width decoding error.
        current: BincodeError,
        /// The legacy-width decoding error.
        legacy: BincodeError,
    },

    /// The snapshot was created for a different network kind.
    #[error(
        "history tree snapshot network kind {stored:?} does not match configured network kind {configured:?}"
    )]
    NetworkMismatch {
        /// The network kind stored in the snapshot.
        stored: NetworkKind,
        /// The configured network kind.
        configured: NetworkKind,
    },

    /// The decoded snapshot does not contain a valid history tree.
    #[error("invalid history tree snapshot: {0}")]
    HistoryTree(#[from] HistoryTreeError),
}

impl IntoDisk for ValueBalance<NonNegative> {
    type Bytes = [u8; 56];

    fn as_bytes(&self) -> Self::Bytes {
        self.to_bytes()
    }
}

impl FromDisk for ValueBalance<NonNegative> {
    fn from_bytes(bytes: impl AsRef<[u8]>) -> Self {
        ValueBalance::from_bytes(bytes.as_ref()).expect("ValueBalance should be parsable")
    }
}

// The following implementations for history trees use `serde` and
// the `bincode` 1.3 format. `serde` serializations depend on the inner structure of the type.
// They should not be used in new code. (This is an issue for any derived serialization format.)
//
// The format rejects trailing bytes, like `bincode::DefaultOptions`; see
// [`bincode_format`].

#[derive(serde::Serialize, serde::Deserialize)]
pub struct HistoryTreeParts {
    network_kind: NetworkKind,
    size: u32,
    peaks: BTreeMap<u32, zcash_history::Entry>,
    current_height: Height,
}

impl HistoryTreeParts {
    /// Decodes current-width or legacy-width history-tree snapshot bytes.
    pub(crate) fn try_from_bytes(bytes: impl AsRef<[u8]>) -> Result<Self, HistoryTreeDecodeError> {
        let bytes = bytes.as_ref();
        // Try the current entry width first. Databases written before NU6.3 widened
        // `zcash_history::Entry` store narrower entries that fail to parse at the current width,
        // so fall back to the legacy width and zero-pad each entry up to the current width.
        //
        // Legacy-width rows can fail the current-width decoder with errors other than
        // `UnexpectedEof`, because the wider entry can read into the next legacy entry and
        // interpret arbitrary entry bytes as bincode control bytes.
        match bincode_format::deserialize::<HistoryTreeParts>(bytes) {
            Ok(parts) => Ok(parts),
            Err(current) => bincode_format::deserialize::<LegacyHistoryTreeParts>(bytes)
                .map(HistoryTreeParts::from)
                .map_err(|legacy| HistoryTreeDecodeError::InvalidEncoding { current, legacy }),
        }
    }

    /// Converts [`HistoryTreeParts`] to a [`NonEmptyHistoryTree`].
    pub(crate) fn with_network(
        self,
        network: &Network,
    ) -> Result<NonEmptyHistoryTree, HistoryTreeDecodeError> {
        let configured = network.kind();
        if self.network_kind != configured {
            return Err(HistoryTreeDecodeError::NetworkMismatch {
                stored: self.network_kind,
                configured,
            });
        }

        Ok(NonEmptyHistoryTree::from_cache(
            network,
            self.size,
            self.peaks,
            self.current_height,
        )?)
    }
}

impl From<&NonEmptyHistoryTree> for HistoryTreeParts {
    fn from(history_tree: &NonEmptyHistoryTree) -> Self {
        HistoryTreeParts {
            network_kind: history_tree.network().kind(),
            size: history_tree.size(),
            peaks: history_tree.peaks().clone(),
            current_height: history_tree.current_height(),
        }
    }
}

impl IntoDisk for HistoryTreeParts {
    type Bytes = Vec<u8>;

    fn as_bytes(&self) -> Self::Bytes {
        bincode_format::serialize(self).expect("history tree parts have known lengths")
    }
}

/// The width of a history-tree [`zcash_history::Entry`] as serialized by database formats written
/// before NU6.3 widened `zcash_history::NodeData`.
const LEGACY_MAX_ENTRY_SIZE: usize = 253;

/// A mirror of [`HistoryTreeParts`] using the pre-NU6.3 [`zcash_history::Entry`] width.
#[derive(serde::Serialize, serde::Deserialize)]
struct LegacyHistoryTreeParts {
    network_kind: NetworkKind,
    size: u32,
    peaks: BTreeMap<u32, LegacyEntry>,
    current_height: Height,
}

/// A history-tree entry serialized at the pre-NU6.3 [`LEGACY_MAX_ENTRY_SIZE`] width.
#[derive(serde::Serialize, serde::Deserialize)]
struct LegacyEntry {
    #[serde(with = "zakura_chain::serialization::serde_adapters::bytes")]
    inner: [u8; LEGACY_MAX_ENTRY_SIZE],
}

impl From<LegacyHistoryTreeParts> for HistoryTreeParts {
    fn from(legacy: LegacyHistoryTreeParts) -> Self {
        HistoryTreeParts {
            network_kind: legacy.network_kind,
            size: legacy.size,
            peaks: legacy
                .peaks
                .into_iter()
                .map(|(index, entry)| {
                    (
                        index,
                        zcash_history::Entry::from_raw_bytes_padded(&entry.inner),
                    )
                })
                .collect(),
            current_height: legacy.current_height,
        }
    }
}

impl FromDisk for HistoryTreeParts {
    fn from_bytes(bytes: impl AsRef<[u8]>) -> Self {
        HistoryTreeParts::try_from_bytes(bytes)
            .expect("deserialization format should match the serialization format used by IntoDisk")
    }
}

impl IntoDisk for BlockInfo {
    type Bytes = Vec<u8>;

    #[cfg_attr(not(feature = "ycash"), allow(clippy::let_and_return))]
    fn as_bytes(&self) -> Self::Bytes {
        let bytes: Vec<u8> = self
            .value_pools()
            .as_bytes()
            .iter()
            .copied()
            .chain(self.size().to_le_bytes().iter().copied())
            .collect();
        // Ycash: a known chain transaction count is appended to the full-length row only.
        #[cfg(feature = "ycash")]
        let bytes = ycash_append_chain_tx_count(bytes, self.chain_tx_count());
        bytes
    }
}

/// Ycash: the length of a full NU7-layout `BlockInfo` row, the only row the chain transaction
/// count is appended to.
///
/// [`FromDisk`] for [`BlockInfo`] chooses the pool layout by the row length (44, 52 or 60
/// bytes), so a count appended to a shorter row would be read as a longer pool layout.
///
/// # Upstream syncs: READ THIS BEFORE MERGING ANY UPSTREAM CHANGE TO `BlockInfo`'S LAYOUT
///
/// Upstream's value-pool layout has grown 8 bytes at a time (40, 48, 56 bytes of pools, so
/// 44, 52, 60-byte rows). Its next growth would make upstream's row 68 bytes: the same length
/// as kogany's 60-byte row with the count appended. The length-dispatched reader below would
/// then read every existing counted row's count as pool data, and consensus reads the pools
/// (`AwaitBlockInfo`). Such a merge needs a kogany format step that moves the count first.
/// The procedure is `.github/README-kogany.md`, "Before merging an upstream change to
/// BlockInfo's on-disk layout"; the tripwire is the test
/// `ycash_upstream_block_info_row_is_still_60_bytes` in `chain/tests.rs`.
#[cfg(feature = "ycash")]
const YCASH_FULL_BLOCK_INFO_LEN: usize = 60;

/// Ycash: the length of the appended chain transaction count (`u64`, little-endian).
#[cfg(feature = "ycash")]
const YCASH_CHAIN_TX_COUNT_LEN: usize = 8;

/// Ycash: appends a known chain transaction count to a full-length row.
#[cfg(feature = "ycash")]
fn ycash_append_chain_tx_count(mut bytes: Vec<u8>, chain_tx_count: Option<u64>) -> Vec<u8> {
    if let (Some(chain_tx_count), YCASH_FULL_BLOCK_INFO_LEN) = (chain_tx_count, bytes.len()) {
        bytes.extend_from_slice(&chain_tx_count.to_le_bytes());
    }
    bytes
}

/// Ycash: a `BlockInfo` row with `chain_tx_count` as its count, for the format upgrade: `None`
/// unless `row` is a full-length row, with or without a count.
#[cfg(feature = "ycash")]
pub(crate) fn ycash_block_info_row_with_count(row: &[u8], chain_tx_count: u64) -> Option<Vec<u8>> {
    let full = [
        YCASH_FULL_BLOCK_INFO_LEN,
        YCASH_FULL_BLOCK_INFO_LEN + YCASH_CHAIN_TX_COUNT_LEN,
    ];
    full.contains(&row.len()).then(|| {
        ycash_append_chain_tx_count(
            row[..YCASH_FULL_BLOCK_INFO_LEN].to_vec(),
            Some(chain_tx_count),
        )
    })
}

/// Ycash: the chain transaction count of a `BlockInfo` row, if the row holds one.
#[cfg(feature = "ycash")]
pub(crate) fn ycash_chain_tx_count_from_row(bytes: &[u8]) -> Option<u64> {
    let count = bytes
        .get(YCASH_FULL_BLOCK_INFO_LEN..YCASH_FULL_BLOCK_INFO_LEN + YCASH_CHAIN_TX_COUNT_LEN)?;
    (bytes.len() == YCASH_FULL_BLOCK_INFO_LEN + YCASH_CHAIN_TX_COUNT_LEN)
        .then(|| u64::from_le_bytes(count.try_into().expect("the slice is 8 bytes long")))
}

impl FromDisk for BlockInfo {
    #[cfg_attr(not(feature = "ycash"), allow(clippy::let_and_return))]
    fn from_bytes(bytes: impl AsRef<[u8]>) -> Self {
        // We have three different DB formats: NU6_1 (Lockbox), Ironwood, and the ZIP 234
        // NSM value balance.
        const NU6_1_VALUE_BALANCE_LEN: usize = 40;
        const IRONWOOD_VALUE_BALANCE_LEN: usize = 48;
        const NU7_VALUE_BALANCE_LEN: usize = 56;
        const BLOCK_SIZE_LEN: usize = 4;
        const NU6_1_BLOCK_INFO_LEN: usize = NU6_1_VALUE_BALANCE_LEN + BLOCK_SIZE_LEN;
        const IRONWOOD_BLOCK_INFO_LEN: usize = IRONWOOD_VALUE_BALANCE_LEN + BLOCK_SIZE_LEN;
        const NU7_BLOCK_INFO_LEN: usize = NU7_VALUE_BALANCE_LEN + BLOCK_SIZE_LEN;

        let bytes = bytes.as_ref();

        // We want to be forward-compatible, so this must work even if the
        // size of the buffer is larger than expected.
        //
        // Ycash: UPSTREAM-SYNC HAZARD. A kogany row with the chain transaction count is 68
        // bytes and is read here by its first 60. If an upstream merge adds a longer pool layout
        // (a 64-byte value balance makes a 68-byte row), the count would be read as pool data.
        // Do not merge such a change without the procedure in `.github/README-kogany.md`,
        // "Before merging an upstream change to BlockInfo's on-disk layout"
        // (`YCASH_FULL_BLOCK_INFO_LEN`, `ycash_upstream_block_info_row_is_still_60_bytes`).
        let block_info = match bytes.len() {
            NU7_BLOCK_INFO_LEN.. => {
                let value_pools =
                    ValueBalance::<NonNegative>::from_bytes(&bytes[..NU7_VALUE_BALANCE_LEN])
                        .expect("must work for 56 bytes");
                let size = u32::from_le_bytes(
                    bytes[NU7_VALUE_BALANCE_LEN..NU7_VALUE_BALANCE_LEN + BLOCK_SIZE_LEN]
                        .try_into()
                        .expect("must be 4 bytes"),
                );
                BlockInfo::new(value_pools, size)
            }
            IRONWOOD_BLOCK_INFO_LEN.. => {
                let value_pools =
                    ValueBalance::<NonNegative>::from_bytes(&bytes[..IRONWOOD_VALUE_BALANCE_LEN])
                        .expect("must work for 48 bytes");
                let size = u32::from_le_bytes(
                    bytes[IRONWOOD_VALUE_BALANCE_LEN..IRONWOOD_VALUE_BALANCE_LEN + BLOCK_SIZE_LEN]
                        .try_into()
                        .expect("must be 4 bytes"),
                );
                BlockInfo::new(value_pools, size)
            }
            NU6_1_BLOCK_INFO_LEN.. => {
                let value_pools =
                    ValueBalance::<NonNegative>::from_bytes(&bytes[..NU6_1_VALUE_BALANCE_LEN])
                        .expect("must work for 40 bytes");
                let size = u32::from_le_bytes(
                    bytes[NU6_1_VALUE_BALANCE_LEN..NU6_1_VALUE_BALANCE_LEN + BLOCK_SIZE_LEN]
                        .try_into()
                        .expect("must be 4 bytes"),
                );
                BlockInfo::new(value_pools, size)
            }
            _ => panic!("invalid format"),
        };
        // Ycash: the count after a full-length row; the pools and size are read as upstream
        // reads them.
        #[cfg(feature = "ycash")]
        let block_info = block_info.with_chain_tx_count(ycash_chain_tx_count_from_row(bytes));
        block_info
    }
}

#[cfg(test)]
mod tests;
