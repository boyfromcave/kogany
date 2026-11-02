//! kogany's regtest control RPCs beside Zakura's `generate` (plan W7-e, decision K-26):
//! `setmocktime` (`ycash6 src/rpc/misc.cpp:518-552` `setmocktime`), which the shared regtest scripts
//! (`yellowback_mining`, `_quote`, `_stratum`) and the parity sidecar's façade call.
//!
//! The clock is zakura-rpc's [`mock_clock`]: `getblocktemplate`'s `curtime` and the YED miner
//! quote's age read it. Like `generate` (`RpcAccess::Test`), the method is on the full RPC
//! surface only and refuses outside regtest with ycashd's message.

use zakura_chain::parameters::Network;
use zakura_rpc::server::{
    jsonrpc::{ErrorObject, RpcResult},
    kogany_extension::mock_clock,
};

crate::kogany_rpc_trait! {
    /// kogany's regtest control RPCs.
    pub trait RegtestRpc {
        /// Sets the node's clock to `timestamp` (Unix seconds); `0` goes back to the system
        /// clock (`setmocktime timestamp`). Regtest only.
        #[method(name = "setmocktime", access = Test)]
        async fn setmocktime(&self, timestamp: i64) -> RpcResult<()>;
    }
    dispatch = RegtestRpcDispatch;
}

/// [`RegtestRpc`] for a network.
#[derive(Clone, Debug)]
pub struct RegtestRpcImpl {
    network: Network,
}

impl RegtestRpcImpl {
    /// The regtest control RPCs on `network`.
    pub fn new(network: Network) -> Self {
        Self { network }
    }

    /// These methods as a server extension.
    pub fn into_extension(self) -> zakura_rpc::server::kogany_extension::RpcExtension {
        RegtestRpcDispatch(self).into_extension()
    }
}

#[async_trait::async_trait]
impl RegtestRpc for RegtestRpcImpl {
    async fn setmocktime(&self, timestamp: i64) -> RpcResult<()> {
        if !self.network.is_regtest() {
            // ycashd: `throw runtime_error(...)`, answered as RPC_MISC_ERROR (-1).
            return Err(ErrorObject::new(
                -1,
                "setmocktime: for regression testing (-regtest mode) only",
            ));
        }
        mock_clock::set_mock_time(timestamp);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn setmocktime_is_regtest_only_and_sets_the_clock() {
        let mainnet = RegtestRpcImpl::new(Network::Mainnet);
        let error = mainnet.setmocktime(1).await.expect_err("mainnet refuses");
        assert_eq!(error.code(), -1);
        assert_eq!(mock_clock::mock_time(), None);

        let regtest = RegtestRpcImpl::new(Network::new_regtest(Default::default()));
        regtest
            .setmocktime(2_000_000_000)
            .await
            .expect("regtest takes it");
        assert_eq!(mock_clock::mock_time(), Some(2_000_000_000));
        assert_eq!(mock_clock::now(), 2_000_000_000);
        regtest.setmocktime(0).await.expect("0 clears it");
        assert_eq!(mock_clock::mock_time(), None);
        assert!(mock_clock::now() > 2_000_000_000 - 10 * 365 * 86_400);
    }
}
