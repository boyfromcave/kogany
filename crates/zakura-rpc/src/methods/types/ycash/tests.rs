//! The Ycash RPC answers against ycashd's values (W1-Y6).

use zakura_chain::{
    amount::{Amount, NonNegative},
    block::Height,
    parameters::{subsidy::block_subsidy, ycash::ydf, Network},
    work::difficulty::ParameterDifficulty,
};

use super::*;

fn zat(value: i64) -> Amount<NonNegative> {
    Amount::try_from(value).expect("test amounts are valid")
}

fn subsidy(network: &Network, height: u32) -> Amount<NonNegative> {
    block_subsidy(Height(height), network, None).expect("a valid subsidy")
}

/// Regtest, every upgrade through Canopy at 1 (the `-nuparams` set the ycash6 suites pass):
/// the mandatory YDF below 5, the optional 5 % from 5, ycashd's `getblocksubsidy` and template.
#[test]
fn regtest_ydf_shares_match_ycashd() {
    let regtest = Network::new_regtest(Default::default());
    let s = subsidy(&regtest, 1);
    assert_eq!(s, zat(625_000_000));

    for height in 1..5 {
        let h = Height(height);
        assert_eq!(founders_share(&regtest, h, s), zat(31_250_000));
        assert_eq!(optional_ydf_share(&regtest, h, s), zat(0));
        assert_eq!(
            template_founders_reward(&regtest, h, s),
            Some(zat(31_250_000))
        );
        let (amount, address) = ydf_output(&regtest, h, s).expect("mandatory YDF output");
        assert_eq!(amount, zat(31_250_000));
        assert_eq!(address.to_string(), ydf::TESTNET_YDF_ADDRESSES[0]);
    }

    // After the mandate: ycashd's default `-ydf=5`, no `foundersreward` in the template.
    for height in [5, 6, 100] {
        let h = Height(height);
        let s = subsidy(&regtest, height);
        assert_eq!(
            founders_share(&regtest, h, s),
            (s * 5).unwrap().div_exact(100)
        );
        assert_eq!(
            optional_ydf_share(&regtest, h, s),
            founders_share(&regtest, h, s)
        );
        assert_eq!(template_founders_reward(&regtest, h, s), None);
        assert!(ydf_output(&regtest, h, s).is_some());
    }
    // Once the regtest subsidy has halved to zero there is no YDF output, as in ycashd.
    assert_eq!(subsidy(&regtest, 17_918), zat(0));
    assert_eq!(ydf_output(&regtest, Height(17_918), zat(0)), None);

    // ycashd's regtest bits never move from the genesis 0x200f0f0f.
    let limit = expected_difficulty(
        &regtest,
        Network::Mainnet.target_difficulty_limit().to_compact(),
    );
    assert_eq!(serde_json::to_value(limit).unwrap(), 0x200f_0f0f_u32);

    assert_eq!(chain_name(&regtest), "regtest");
    assert!(!is_testnet_field(&regtest));
    assert!(is_pre_nu5(&regtest, Height(1)));
}

/// Mainnet around the fork and the mandate end: the founders' reward before 570,000, the YDF
/// from it (`getblocksubsidy` at those heights on a synced ycashd).
#[test]
fn mainnet_shares_match_ycashd() {
    let main = Network::Mainnet;

    let s = subsidy(&main, 569_999);
    assert_eq!(s, zat(1_250_000_000));
    assert_eq!(founders_share(&main, Height(569_999), s), zat(250_000_000));
    assert_eq!(
        template_founders_reward(&main, Height(569_999), s),
        Some(zat(250_000_000))
    );
    assert_eq!(ydf_output(&main, Height(569_999), s), None);

    let s = subsidy(&main, 570_000);
    assert_eq!(founders_share(&main, Height(570_000), s), zat(62_500_000));
    assert_eq!(
        ydf_output(&main, Height(570_000), s).map(|(a, addr)| (a, addr.to_string())),
        Some((zat(62_500_000), ydf::MAINNET_YDF_ADDRESSES[0].to_string()))
    );

    let s = subsidy(&main, 2_274_999);
    assert_eq!(
        template_founders_reward(&main, Height(2_274_999), s),
        Some((s / 20).unwrap())
    );
    let s = subsidy(&main, 2_275_000);
    assert_eq!(template_founders_reward(&main, Height(2_275_000), s), None);
    assert_eq!(
        optional_ydf_share(&main, Height(2_275_000), s),
        (s * 5).unwrap().div_exact(100)
    );

    assert_eq!(chain_name(&main), "main");
    assert!(!is_testnet_field(&main));
    assert!(is_pre_nu5(&main, Height(2_275_000)));
    let computed = Network::Mainnet.target_difficulty_limit().to_compact();
    assert_eq!(expected_difficulty(&main, computed), computed);

    assert_eq!(chain_name(&Network::new_default_testnet()), "test");
    assert!(is_testnet_field(&Network::new_default_testnet()));
}

/// `getblocksubsidy` on Ycash mainnet: `(height, miner, founders, totalblocksubsidy)` in zatoshis,
/// as a ycash6 mainnet node at 65cb4ae0f answers them (`ycash-cli getblocksubsidy <height>`).
#[test]
fn mainnet_getblocksubsidy_matches_ycashd() {
    use zakura_chain::parameters::subsidy::{founders_reward, miner_subsidy};

    let main = Network::Mainnet;
    for (height, miner, founders, total) in [
        (569_999, 1_000_000_000, 250_000_000, 1_250_000_000),
        (570_000, 1_187_500_000, 62_500_000, 1_250_000_000),
        (2_274_999, 296_875_000, 15_625_000, 312_500_000),
        (2_275_000, 296_875_000, 15_625_000, 312_500_000),
        (3_000_000, 148_437_500, 7_812_500, 156_250_000),
    ] {
        let h = Height(height);
        let s = subsidy(&main, height);
        assert_eq!(s, zat(total), "total at {height}");
        let stock_miner = miner_subsidy(h, &main, s).expect("a valid miner subsidy");
        let fields = subsidy_fields(&main, h, s, stock_miner, founders_reward(&main, h));
        assert_eq!(
            fields,
            Ok((zat(miner), zat(founders))),
            "miner and founders at {height}"
        );
    }
}
