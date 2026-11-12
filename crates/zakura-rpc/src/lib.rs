//! The Zakura node's Remote Procedure Call (RPC) interface

#![doc(html_favicon_url = "https://zakura.com/assets/rustdoc/zakura-favicon-128.png")]
#![doc(html_logo_url = "https://zakura.com/assets/rustdoc/zakura-icon.png")]
#![doc(html_root_url = "https://docs.rs/zakura_rpc")]
// Long Tower service and future types are routine in this crate, and factoring
// them into type aliases would not make the code clearer.
#![allow(clippy::type_complexity)]

pub mod client;
pub mod config;
#[cfg(feature = "indexer-rpc")]
pub mod indexer;
pub mod methods;
pub mod node;
pub mod queue;
pub mod server;
#[cfg(feature = "indexer-rpc")]
pub mod sync;

#[cfg(test)]
mod tests;

pub use methods::types::{
    get_block_template::{
        fetch_chain_info, proposal::proposal_block_from_template, MinerAddress, MinerParams,
    },
    submit_block::{
        MinedBlockEvent, MinedBlockSubmission, PendingBlockRegistration, PendingBlockRegistry,
        PendingBlockSignal, SubmitBlockChannel,
    },
};

// kogany W8: the Ycash `getblocktemplate` hooks the node installs (`RpcImpl::with_ycash_mining`).
#[cfg(feature = "ycash")]
pub use methods::types::get_block_template::ycash as ycash_mining;
// kogany W7-b: ycashd's `ScriptErrorString` text for `yed_validaterawtransaction`.
#[cfg(feature = "ycash")]
pub use methods::types::ycash_reject::script_error_string as ycash_script_error_string;
// kogany S5: the insight reads' address parameter, YED forms included.
#[cfg(feature = "ycash")]
pub use methods::types::ycash::insight_address as ycash_insight_address;
#[cfg(feature = "ycash")]
pub use methods::types::ycash::insight_address_on as ycash_insight_address_on;
