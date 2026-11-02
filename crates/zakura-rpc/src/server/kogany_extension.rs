//! kogany's hook: a second set of JSON-RPC methods, dispatched beside [`RpcServer`]'s own.
//!
//! Copyright (c) 2026 The Ycash developers. Distributed under the MIT software license.
//!
//! Zakura's server is generic over one [`RpcMethods`] type, the one `rpc_trait!` generates for
//! `RpcServer`'s `RpcImpl` (`methods.rs`). That macro's `RpcMethods` implementation is a blanket
//! `impl<T: Trait> RpcMethods for T`, so a second `rpc_trait!` trait can implement it neither in
//! this crate (the two blanket implementations overlap) nor in another crate (the orphan rule
//! forbids a foreign trait on an uncovered `T`). kogany's methods (`vault_*`, `set_*`, `yed_*`)
//! therefore live in their own crate, `kogany-rpc`, whose macro implements [`RpcMethods`] for a
//! local wrapper type, and reach the server through this module:
//!
//! - [`RpcExtension`]: one or more [`RpcMethods`] sets with an access class for every method
//!   name, checked at startup the way `RPC_METHOD_ACCESS` is checked for `RpcServer` (fail closed:
//!   an unclassified, duplicate or `RpcServer`-shadowing name stops the server).
//! - [`ExtendedMethods`]: the [`RpcMethods`] the server runs, which sends an extension method
//!   name to its extension and every other name to `RpcServer`.
//! - [`RpcServer::start_with_extension`], [`RpcServer::start_admin_with_extension`] and the
//!   non-generic [`start_node_server`] / [`start_node_admin_server`] for `zakurad`.
//!
//! The upstream lines this hook touches are the `pub mod` line and the extension argument of
//! `start_inner` in `server.rs`; nothing else in Zakura changes. The extension's methods are not
//! in `rpc.discover`'s OpenRPC document (plan W7-d).

use std::{collections::BTreeSet, future::Future, pin::Pin, sync::Arc};

use futures::{future::BoxFuture, FutureExt};
use tokio::task::JoinHandle;
use tower::BoxError;

use zakura_chain::{chain_sync_status::ChainSyncStatus, chain_tip::ChainTip};
use zakura_consensus::router::service_trait::BlockVerifierService;
use zakura_network::AddressBookPeers;
use zakura_node_services::mempool::MempoolService;
use zakura_state::{ReadState as ReadStateService, State as StateService};

use crate::{
    config,
    methods::{RpcImpl, RpcSurface},
    node::NodeRpcImpl,
    server::{
        jsonrpc::{Id, MethodResponse, Params},
        rpc_service::RpcMethods,
        RpcServer, ServerTask, OPENED_ADMIN_RPC_ENDPOINT_MSG, OPENED_RPC_ENDPOINT_MSG,
    },
};

/// The access class of an extension method, with the meaning of Zakura's `RpcAccess`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExtensionAccess {
    /// Available on restricted unauthenticated Mainnet and Testnet RPC listeners.
    Unauthenticated,
    /// Available only on authenticated listeners, except on Regtest.
    Admin,
    /// A Regtest control method retained on the full RPC surface.
    Test,
}

/// A method set as the extension holds it: [`RpcMethods`] without its associated constant, so
/// that sets of different types can be held together.
trait DynRpcMethods: Send + Sync + 'static {
    fn call<'a>(
        &'a self,
        method: &str,
        params: Params<'a>,
        id: Id<'a>,
        max_response_size: usize,
    ) -> Option<Pin<Box<dyn Future<Output = MethodResponse> + Send + 'a>>>;
}

impl<M: RpcMethods> DynRpcMethods for M {
    fn call<'a>(
        &'a self,
        method: &str,
        params: Params<'a>,
        id: Id<'a>,
        max_response_size: usize,
    ) -> Option<Pin<Box<dyn Future<Output = MethodResponse> + Send + 'a>>> {
        RpcMethods::call(self, method, params, id, max_response_size)
    }
}

/// One method set of an extension.
#[derive(Clone)]
struct ExtensionSet {
    methods: Arc<dyn DynRpcMethods>,
    names: &'static [&'static str],
    access: &'static [(&'static str, ExtensionAccess)],
}

/// RPC methods served beside `RpcServer`'s, with an access class for each.
///
/// [`RpcExtension::none`] is the empty extension: a server started with it is Zakura's.
#[derive(Clone, Default)]
pub struct RpcExtension {
    sets: Vec<ExtensionSet>,
}

impl RpcExtension {
    /// The empty extension.
    pub fn none() -> Self {
        Self::default()
    }

    /// An extension of the method set `methods`, whose methods have the classes in `access`.
    ///
    /// Every name in `M::METHOD_NAMES` must appear exactly once in `access`, and nothing else;
    /// the server checks this when it starts.
    pub fn new<M: RpcMethods>(
        methods: M,
        access: &'static [(&'static str, ExtensionAccess)],
    ) -> Self {
        Self {
            sets: vec![ExtensionSet {
                methods: Arc::new(methods),
                names: M::METHOD_NAMES,
                access,
            }],
        }
    }

    /// This extension and `other` together.
    pub fn and(mut self, other: RpcExtension) -> Self {
        self.sets.extend(other.sets);
        self
    }

    /// Every method name of the extension, in registration order.
    pub fn method_names(&self) -> impl Iterator<Item = &'static str> + '_ {
        self.sets.iter().flat_map(|set| set.names.iter().copied())
    }

    /// The access class of the extension method `name`.
    pub fn access(&self, name: &str) -> Option<ExtensionAccess> {
        self.sets
            .iter()
            .flat_map(|set| set.access.iter())
            .find_map(|(method, access)| (*method == name).then_some(*access))
    }

    fn set_of(&self, name: &str) -> Option<&ExtensionSet> {
        self.sets.iter().find(|set| set.names.contains(&name))
    }

    /// Checks the extension against `RpcServer`'s `registered` methods, and returns the
    /// extension methods available on `surface`.
    pub(crate) fn enabled_methods(
        &self,
        registered: &[&'static str],
        surface: RpcSurface,
    ) -> Result<Vec<&'static str>, std::io::Error> {
        let registered: BTreeSet<_> = registered.iter().copied().collect();
        let mut names = BTreeSet::new();
        let mut enabled = Vec::new();

        for set in &self.sets {
            let classified: BTreeSet<_> = set.access.iter().map(|(name, _)| *name).collect();
            let declared: BTreeSet<_> = set.names.iter().copied().collect();
            if classified.len() != set.access.len() || declared.len() != set.names.len() {
                return Err(std::io::Error::other(
                    "RPC extension method names or access classifications contain duplicates",
                ));
            }
            if classified != declared {
                let unclassified: Vec<_> = declared.difference(&classified).copied().collect();
                let unregistered: Vec<_> = classified.difference(&declared).copied().collect();
                return Err(std::io::Error::other(format!(
                    "RPC extension access classification mismatch; unclassified methods: {unclassified:?}; classified but unregistered methods: {unregistered:?}"
                )));
            }
            for (name, access) in set.access {
                if registered.contains(name) || !names.insert(*name) {
                    return Err(std::io::Error::other(format!(
                        "RPC extension method {name:?} is already registered"
                    )));
                }
                if surface != RpcSurface::Restricted || *access == ExtensionAccess::Unauthenticated
                {
                    enabled.push(*name);
                }
            }
        }

        Ok(enabled)
    }
}

/// `RpcServer`'s methods `M` and an extension's, as one method set.
#[derive(Clone)]
pub struct ExtendedMethods<M> {
    primary: M,
    extension: RpcExtension,
}

impl<M> ExtendedMethods<M> {
    /// `primary`'s methods, then `extension`'s.
    pub fn new(primary: M, extension: RpcExtension) -> Self {
        Self { primary, extension }
    }
}

impl<M: RpcMethods> RpcMethods for ExtendedMethods<M> {
    /// `RpcServer`'s names only: the extension's are known at runtime, and the server reads them
    /// from the extension ([`RpcExtension::enabled_methods`]).
    const METHOD_NAMES: &'static [&'static str] = M::METHOD_NAMES;

    fn call<'a>(
        &'a self,
        method: &str,
        params: Params<'a>,
        id: Id<'a>,
        max_response_size: usize,
    ) -> Option<Pin<Box<dyn Future<Output = MethodResponse> + Send + 'a>>> {
        match self.extension.set_of(method) {
            Some(set) => set.methods.call(method, params, id, max_response_size),
            None => self.primary.call(method, params, id, max_response_size),
        }
    }
}

impl RpcServer {
    /// [`RpcServer::start`], with `extension`'s methods served beside `rpc`'s.
    #[allow(clippy::too_many_arguments)]
    pub async fn start_with_extension<
        Mempool,
        State,
        ReadState,
        Tip,
        BlockVerifierRouter,
        SyncStatus,
        AddressBook,
    >(
        rpc: RpcImpl<Mempool, State, ReadState, Tip, AddressBook, BlockVerifierRouter, SyncStatus>,
        extension: RpcExtension,
        conf: config::rpc::Config,
    ) -> Result<ServerTask, tower::BoxError>
    where
        Mempool: MempoolService,
        State: StateService,
        ReadState: ReadStateService,
        Tip: ChainTip + Clone + Send + Sync + 'static,
        AddressBook: AddressBookPeers + Clone + Send + Sync + 'static,
        BlockVerifierRouter: BlockVerifierService,
        SyncStatus: ChainSyncStatus + Clone + Send + Sync + 'static,
    {
        // Keep in step with `RpcServer::start` (server.rs).
        conf.validate().map_err(std::io::Error::other)?;

        let surface = super::primary_rpc_surface(rpc.network(), conf.enable_cookie_auth);

        Self::start_inner(rpc, conf, surface, OPENED_RPC_ENDPOINT_MSG, extension).await
    }

    /// [`RpcServer::start_admin`], with `extension`'s methods served beside `rpc`'s.
    pub async fn start_admin_with_extension<
        Mempool,
        State,
        ReadState,
        Tip,
        BlockVerifierRouter,
        SyncStatus,
        AddressBook,
    >(
        rpc: RpcImpl<Mempool, State, ReadState, Tip, AddressBook, BlockVerifierRouter, SyncStatus>,
        extension: RpcExtension,
        mut conf: config::rpc::Config,
    ) -> Result<ServerTask, tower::BoxError>
    where
        Mempool: MempoolService,
        State: StateService,
        ReadState: ReadStateService,
        Tip: ChainTip + Clone + Send + Sync + 'static,
        AddressBook: AddressBookPeers + Clone + Send + Sync + 'static,
        BlockVerifierRouter: BlockVerifierService,
        SyncStatus: ChainSyncStatus + Clone + Send + Sync + 'static,
    {
        // Keep in step with `RpcServer::start_admin` (server.rs).
        conf.validate().map_err(std::io::Error::other)?;

        conf.listen_addr = Some(
            conf.admin_listen_addr
                .expect("caller should make sure admin_listen_addr is set"),
        );
        conf.admin_listen_addr = None;
        conf.enable_cookie_auth = true;
        conf.tls = None;

        Self::start_inner(
            rpc,
            conf,
            RpcSurface::Full,
            OPENED_ADMIN_RPC_ENDPOINT_MSG,
            extension,
        )
        .await
    }
}

/// Starts the node's public RPC server with `extension`. See [`crate::node::start_server`].
pub fn start_node_server(
    rpc: &NodeRpcImpl,
    extension: RpcExtension,
    conf: config::rpc::Config,
) -> BoxFuture<'static, Result<JoinHandle<Result<(), BoxError>>, BoxError>> {
    RpcServer::start_with_extension(rpc.clone(), extension, conf).boxed()
}

/// Starts the node's admin RPC server with `extension`. See [`crate::node::start_admin_server`].
pub fn start_node_admin_server(
    rpc: &NodeRpcImpl,
    extension: RpcExtension,
    conf: config::rpc::Config,
) -> BoxFuture<'static, Result<JoinHandle<Result<(), BoxError>>, BoxError>> {
    RpcServer::start_admin_with_extension(rpc.clone(), extension, conf).boxed()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone)]
    struct Two;

    impl RpcMethods for Two {
        const METHOD_NAMES: &'static [&'static str] = &["kogany_a", "kogany_b"];

        fn call<'a>(
            &'a self,
            _method: &str,
            _params: Params<'a>,
            _id: Id<'a>,
            _max_response_size: usize,
        ) -> Option<Pin<Box<dyn Future<Output = MethodResponse> + Send + 'a>>> {
            None
        }
    }

    #[test]
    fn extension_methods_are_classified_and_filtered() {
        let ok = RpcExtension::new(
            Two,
            &[
                ("kogany_a", ExtensionAccess::Unauthenticated),
                ("kogany_b", ExtensionAccess::Admin),
            ],
        );
        assert_eq!(
            ok.enabled_methods(&["getinfo"], RpcSurface::Full).unwrap(),
            ["kogany_a", "kogany_b"]
        );
        assert_eq!(
            ok.enabled_methods(&["getinfo"], RpcSurface::Restricted)
                .unwrap(),
            ["kogany_a"]
        );
        // A name RpcServer already has is refused.
        assert!(ok.enabled_methods(&["kogany_b"], RpcSurface::Full).is_err());
        // Two extensions with one name are refused.
        assert!(ok
            .clone()
            .and(ok.clone())
            .enabled_methods(&[], RpcSurface::Full)
            .is_err());
        // An unclassified method is refused.
        let unclassified =
            RpcExtension::new(Two, &[("kogany_a", ExtensionAccess::Unauthenticated)]);
        assert!(unclassified.enabled_methods(&[], RpcSurface::Full).is_err());
        // The empty extension adds nothing.
        assert!(RpcExtension::none()
            .enabled_methods(&["getinfo"], RpcSurface::Full)
            .unwrap()
            .is_empty());
    }
}
