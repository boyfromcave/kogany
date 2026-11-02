//! A Zcash (feature-off) build never parses or accepts the 400-byte Ycash solution.

use crate::{
    block::Height,
    parameters::Network,
    work::equihash::{Solution, YCASH_SOLUTION_SIZE},
};

#[test]
fn a_zcash_build_rejects_ycash_solutions() {
    assert!(Solution::from_bytes(&[0; YCASH_SOLUTION_SIZE]).is_err());

    let ycash = Solution::Ycash([0; YCASH_SOLUTION_SIZE]);
    for network in [Network::Mainnet, Network::new_default_testnet()] {
        for height in [Height(1), Height(570_000), Height(3_000_000)] {
            assert!(ycash.validate_shape(&network, height).is_err());
        }
    }
    assert_eq!(
        Solution::for_proposal_for_network(&Network::Mainnet),
        Solution::for_proposal()
    );
}
