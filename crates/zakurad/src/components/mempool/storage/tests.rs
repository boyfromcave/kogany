//! Tests for mempool storage.

// kogany: the Ycash build evicts by ycashd's ZIP-401 random weighted draw (`make_room`), so
// upstream's fee-ranked eviction tests describe the Zcash build only.
#[cfg(not(feature = "ycash"))]
mod eviction;
mod prop;
mod vectors;
