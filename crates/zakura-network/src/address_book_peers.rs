//! A AddressBookPeers trait for getting the [`MetaAddr`] of recently live peers.

use chrono::Utc;

use crate::{meta_addr::MetaAddr, ConnectedPeer, PeerSocketAddr};

#[cfg(any(test, feature = "proptest-impl"))]
pub mod mock;

#[cfg(any(test, feature = "proptest-impl"))]
pub use mock::MockAddressBookPeers;

/// Method signatures for getting [`MetaAddr`]s of recently live peers.
pub trait AddressBookPeers {
    /// Return an Vec of peers we've seen recently, in reconnection attempt order.
    fn recently_live_peers(&self, now: chrono::DateTime<Utc>) -> Vec<MetaAddr>;

    /// Return active connection metadata when this implementation has a live-peer registry.
    fn connected_peers(&self) -> Option<Vec<ConnectedPeer>> {
        None
    }

    /// Add a peer to the address book.
    fn add_peer(&mut self, peer: PeerSocketAddr) -> bool;

    /// Close the connections to `peer` and keep its address out of the book until
    /// [`Self::add_peer`] adds it again (`disconnectnode`, kogany F-S5-6). Returns `false` when
    /// no connection to `peer` is open.
    fn disconnect_peer(&mut self, _peer: PeerSocketAddr) -> bool {
        false
    }

    /// Make `peer` ready for an outbound connection attempt now, adding it if it is missing
    /// (`addnode "onetry"`, kogany F-S5-6). Returns `false` when the address cannot be used.
    fn try_peer_now(&mut self, peer: PeerSocketAddr) -> bool {
        self.add_peer(peer)
    }
}
