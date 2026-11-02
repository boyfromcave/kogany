//! The `Ycash` upgrade is inert in a Zcash (feature-off) build (kogany plan §2.3, §2.5).

use crate::{
    block::Height,
    parameters::{
        testnet::{self, ConfiguredActivationHeights, RegtestParameters},
        ConsensusBranchId, Network, NetworkUpgrade,
    },
};

#[test]
fn ycash_is_never_scheduled_on_zcash_networks() {
    for network in [
        Network::Mainnet,
        Network::new_default_testnet(),
        Network::new_regtest(Default::default()),
    ] {
        assert!(
            !network
                .activation_list()
                .values()
                .any(|nu| *nu == NetworkUpgrade::Ycash),
            "{network}"
        );
        for height in [0, 419_200, 570_000, 653_600, 1_046_400, 3_000_000] {
            assert_ne!(
                NetworkUpgrade::current(&network, Height(height)),
                NetworkUpgrade::Ycash
            );
            assert_ne!(
                ConsensusBranchId::current(&network, Height(height)),
                NetworkUpgrade::Ycash.branch_id()
            );
        }
    }
}

#[test]
fn ycash_branch_id_row_is_inert_data() {
    assert_eq!(
        NetworkUpgrade::Ycash.branch_id().map(u32::from),
        Some(0x374d694f)
    );
    // Zcash's own IDs are unchanged.
    assert_eq!(
        NetworkUpgrade::Canopy.branch_id().map(u32::from),
        Some(0xe9ff75a6)
    );
}

#[test]
fn a_zcash_build_refuses_a_ycash_height() {
    let heights = ConfiguredActivationHeights {
        ycash: Some(5),
        ..Default::default()
    };
    let error = testnet::Parameters::build()
        .with_activation_heights(heights)
        .err()
        .expect("a Zcash build refuses a Ycash activation height");
    assert!(error.to_string().contains("`ycash` build"), "{error}");
    assert!(testnet::Parameters::new_regtest(RegtestParameters::from(heights)).is_err());
}
