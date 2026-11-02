//! `setmocktime` (plan W7-e): regtest only, and it sets the process clock that
//! `getblocktemplate.curtime` and the YED quote age read. Its own test binary, since the clock is
//! one value per process.

use kogany_rpc::regtest::{RegtestRpc, RegtestRpcImpl};
use zakura_chain::parameters::Network;
use zakura_rpc::server::kogany_extension::mock_clock;

#[tokio::test]
async fn setmocktime_is_regtest_only_and_sets_the_clock() {
    let mainnet = RegtestRpcImpl::new(Network::Mainnet);
    let error = mainnet.setmocktime(1).await.expect_err("mainnet refuses");
    assert_eq!(error.code(), -1);
    assert_eq!(
        error.message(),
        "setmocktime: for regression testing (-regtest mode) only"
    );
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
    assert!(mock_clock::now() > 1_700_000_000);
}
