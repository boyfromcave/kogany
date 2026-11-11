use chrono::{DateTime, Duration};
use zakura_chain::{
    block,
    parameters::testnet::Parameters,
    work::difficulty::{ExpandedDifficulty, ParameterDifficulty as _, U256},
};

use super::super::{AdjustedDifficulty, POW_ADJUSTMENT_BLOCK_SPAN};
use zakura_chain::parameters::POW_AVERAGING_WINDOW;

#[test]
fn custom_target_scaling_clamps_before_overflowing_u256() {
    let candidate_time =
        DateTime::from_timestamp(2_000_000_000, 0).expect("test timestamp is in range");
    let compact = ExpandedDifficulty::from(U256::MAX).to_compact();
    let network = Parameters::build()
        .with_target_difficulty_limit(U256::MAX)
        .expect("the maximum compact-representable target is valid")
        .to_network()
        .expect("the custom network parameters are valid");
    let mut context = vec![(compact, candidate_time - Duration::seconds(1)); POW_AVERAGING_WINDOW];
    context.extend(vec![
        (compact, candidate_time - Duration::seconds(100_000));
        POW_ADJUSTMENT_BLOCK_SPAN - POW_AVERAGING_WINDOW
    ]);
    let adjustment = AdjustedDifficulty::new_from_header_time(
        candidate_time,
        block::Height(699_999),
        &network,
        context,
    )
    .expect("the complete context is accepted");

    assert_eq!(
        adjustment.expected_difficulty_threshold(),
        network.target_difficulty_limit().to_compact()
    );
}

/// The fast re-fork and the shadow split reset one averaging window to the PoW limit
/// (`ycash6` `src/pow.cpp`).
#[cfg(feature = "ycash")]
#[test]
fn ycash_fork_windows_reset_to_the_pow_limit() {
    use zakura_chain::parameters::Network;

    let hard = ExpandedDifficulty::from(U256::from(1u64)).to_compact();
    let time = DateTime::from_timestamp(1_700_000_000, 0).expect("timestamp");
    let context = vec![(hard, time); POW_ADJUSTMENT_BLOCK_SPAN];
    let expect_limit = |network: &Network, previous: u32| {
        let adjustment = AdjustedDifficulty::new_from_header_time(
            time + Duration::seconds(75),
            block::Height(previous),
            network,
            context.clone(),
        )
        .expect("context");
        assert_eq!(
            adjustment.expected_difficulty_threshold(),
            network.target_difficulty_limit().to_compact(),
            "{network} at {}",
            previous + 1
        );
    };
    let fast = Network::new_default_testnet();
    expect_limit(&fast, 510_247);
    expect_limit(&Network::new_ycash_testnet_slow(), 3_079_999);
    expect_limit(&Network::new_ycash_testnet_legacy(), 3_079_999);
}
