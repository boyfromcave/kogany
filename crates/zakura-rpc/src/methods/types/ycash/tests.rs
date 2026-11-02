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

/// `getblockchaininfo.testnetprofile` (W7-c): `fast` on the default Ycash testnet, `slow` on the
/// slow profile, absent on Mainnet and Regtest (`ycash6 src/rpc/blockchain.cpp:1688-1689`).
#[test]
fn testnet_profile_matches_ycashd() {
    assert_eq!(testnet_profile(&Network::Mainnet), None);
    assert_eq!(testnet_profile(&Network::new_regtest(Default::default())), None);
    assert_eq!(
        testnet_profile(&Network::new_default_testnet()).as_deref(),
        Some("fast")
    );
    assert_eq!(
        testnet_profile(&Network::new_ycash_testnet_slow()).as_deref(),
        Some("slow")
    );
}

/// `Base58Check(version || payload)`, for building addresses in the tests below.
fn base58check(version: &[u8], payload: &[u8]) -> String {
    let data = [version, payload].concat();
    kogany_yellowback::codecs::base58::encode_base58_check(&data)
}

/// `validateaddress` of a plain-YEC post-quantum address (W7-c, `ycash6 src/key_io.cpp:318-339`,
/// `src/rpc/misc.cpp` `DescribeAddressVisitor`): this network's version and a registered scheme
/// only; the script is the TX_PQPKH `<keyHash> OP_<scheme> OP_CHECKPQSIG`.
#[test]
fn pq_addresses_decode_as_ycashd() {
    let regtest = Network::new_regtest(Default::default());
    let key_hash: [u8; 32] =
        hex::decode("73efa99cd22fe553222b1db6a6a021b3cba29dafd4fb4dfb50be69abcfcf9364")
            .expect("hex")
            .try_into()
            .expect("32 bytes");

    for scheme in [1u8, 2] {
        let address = base58check(&[0x4C, 0x51], &[&[scheme][..], &key_hash].concat());
        assert!(address.starts_with("rq"), "{address}");
        assert_eq!(address.len(), 53);
        let pq = decode_pq_address(&regtest, &address).expect("a registered scheme decodes");
        assert_eq!(pq.address, address);
        assert_eq!(pq.scheme, scheme);
        assert_eq!(pq.key_hash, hex::encode(key_hash));
        assert_eq!(
            pq.script_pub_key,
            format!("20{}{:02x}c2", hex::encode(key_hash), 0x50 + scheme)
        );
    }

    // An unregistered scheme, another network's version, and the Yellowback forms are not
    // destinations.
    let unregistered = base58check(&[0x4C, 0x51], &[&[3u8][..], &key_hash].concat());
    assert_eq!(decode_pq_address(&regtest, &unregistered), None);
    let testnet_form = base58check(&[0x4F, 0x61], &[&[1u8][..], &key_hash].concat());
    assert!(testnet_form.starts_with("tq"));
    assert_eq!(decode_pq_address(&regtest, &testnet_form), None);
    assert!(decode_pq_address(&Network::new_default_testnet(), &testnet_form).is_some());
    let mainnet_form = base58check(&[0x4D, 0xD9], &[&[2u8][..], &key_hash].concat());
    assert!(mainnet_form.starts_with("sq"));
    assert!(decode_pq_address(&Network::Mainnet, &mainnet_form).is_some());
    assert_eq!(decode_pq_address(&regtest, &mainnet_form), None);
    let yed_pq = base58check(&[0x57, 0x10], &[&[1u8][..], &key_hash].concat());
    assert!(yed_pq.starts_with("yr"));
    assert_eq!(decode_pq_address(&regtest, &yed_pq), None);
    let yed_key = base58check(&[0x20, 0x02], &key_hash[..20]);
    assert!(yed_key.starts_with("yr"));
    assert_eq!(decode_pq_address(&regtest, &yed_key), None);

    let answer = super::super::validate_address::validate_address(regtest.clone(), yed_key)
        .expect("validateaddress answers");
    assert!(!answer.is_valid());
    let address = base58check(&[0x4C, 0x51], &[&[2u8][..], &key_hash].concat());
    let answer = super::super::validate_address::validate_address(regtest, address.clone())
        .expect("validateaddress answers");
    assert_eq!(
        serde_json::to_value(answer).expect("serializes"),
        serde_json::json!({
            "isvalid": true,
            "address": address,
            "scriptPubKey": format!("20{}52c2", hex::encode(key_hash)),
            "isscript": false,
            "pqscheme": 2,
            "pqkeyhash": hex::encode(key_hash),
        })
    );
}

/// The default miner addresses of a Ycash build are Ycash addresses (W7-c), and a Zcash one is
/// refused with ycashd's message (`ycash6 src/init.cpp:1680-1683`).
#[test]
fn default_miner_addresses_are_ycash() {
    use crate::config::mining::{default_miner_address, Config, MinerAddressType};
    use zakura_chain::parameters::NetworkKind;

    for kind in [NetworkKind::Mainnet, NetworkKind::Testnet, NetworkKind::Regtest] {
        for addr_type in [
            MinerAddressType::Transparent,
            MinerAddressType::Sapling,
            MinerAddressType::Unified,
        ] {
            let encoded = default_miner_address(kind, &addr_type);
            let config: Config = toml::from_str(&format!("miner_address = {encoded:?}"))
                .unwrap_or_else(|e| panic!("{encoded} parses: {e}"));
            assert_eq!(
                config.miner_address.expect("set").to_string(),
                encoded,
                "{kind:?}"
            );
        }
    }

    let regtest = Network::new_regtest(Default::default());
    let transparent = default_miner_address(NetworkKind::Regtest, &MinerAddressType::Transparent);
    assert!(
        super::super::validate_address::validate_address(regtest, transparent.to_string())
            .expect("validateaddress answers")
            .is_valid()
    );

    let error = toml::from_str::<Config>("miner_address = 'tmJymvcUCn1ctbghvTJpXBwHiMEB8P6wxNV'")
        .expect_err("a Zcash address is refused")
        .to_string();
    assert!(
        error.contains(
            "Invalid address for mining.miner_address: Unable to parse \
             'tmJymvcUCn1ctbghvTJpXBwHiMEB8P6wxNV' as a Ycash address."
        ),
        "{error}"
    );
}
