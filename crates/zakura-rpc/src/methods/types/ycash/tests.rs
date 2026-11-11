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
    assert_eq!(
        testnet_profile(&Network::new_regtest(Default::default())),
        None
    );
    assert_eq!(
        testnet_profile(&Network::new_default_testnet()).as_deref(),
        Some("fast")
    );
    assert_eq!(
        testnet_profile(&Network::new_ycash_testnet_slow()).as_deref(),
        Some("slow")
    );
    assert_eq!(
        testnet_profile(&Network::new_ycash_testnet_legacy()).as_deref(),
        Some("legacy")
    );
}

/// `Base58Check(version || payload)`, for building addresses in the tests below.
fn base58check(version: &[u8], payload: &[u8]) -> String {
    let data = [version, payload].concat();
    kogany_yellowback::codecs::base58::encode_base58_check(&data)
}

/// `validateaddress` of a plain-YEC post-quantum address (W7-c, D-9, `ycash6 src/key_io.cpp`,
/// `src/rpc/misc.cpp` `DescribeAddressVisitor`): one of this network's per-scheme versions only;
/// the script is the TX_PQPKH `<keyHash> OP_<scheme> OP_CHECKPQSIG`.
#[test]
fn pq_addresses_decode_as_ycashd() {
    let regtest = Network::new_regtest(Default::default());
    let key_hash: [u8; 32] =
        hex::decode("73efa99cd22fe553222b1db6a6a021b3cba29dafd4fb4dfb50be69abcfcf9364")
            .expect("hex")
            .try_into()
            .expect("32 bytes");

    // regtest: 4c5655 `rqs…` (SLH-DSA, 1), 4c54ef `rqf…` (FN-DSA-512, 2)
    for (scheme, version, prefix) in [
        (1u8, [0x4C, 0x56, 0x55], "rqs"),
        (2u8, [0x4C, 0x54, 0xEF], "rqf"),
    ] {
        let address = base58check(&version, &key_hash);
        assert!(address.starts_with(prefix), "{address}");
        assert_eq!(address.len(), 53);
        let pq = decode_pq_address(&regtest, &address).expect("a registered scheme decodes");
        assert_eq!(pq.address, address);
        assert_eq!(pq.scheme, scheme);
        assert_eq!(pq.key_hash, hex::encode(key_hash));
        assert_eq!(
            pq.script_pub_key,
            format!("20{}{:02x}c2", hex::encode(key_hash), 0x50 + scheme)
        );
        // The pre-D-9 form of the same key (2-byte version || scheme || keyHash) is refused.
        let old = base58check(&[0x4C, 0x51], &[&[scheme][..], &key_hash].concat());
        assert!(old.starts_with("rq"));
        assert_eq!(decode_pq_address(&regtest, &old), None);
        let answer = super::super::validate_address::validate_address(regtest.clone(), old)
            .expect("validateaddress answers");
        assert!(!answer.is_valid());
    }

    // Another network's version, and the Yellowback forms, are not destinations.
    let testnet_form = base58check(&[0x4F, 0x66, 0x7F], &key_hash);
    assert!(testnet_form.starts_with("tqs"));
    assert_eq!(decode_pq_address(&regtest, &testnet_form), None);
    assert!(decode_pq_address(&Network::new_default_testnet(), &testnet_form).is_some());
    let mainnet_form = base58check(&[0x4D, 0xDD, 0x04], &key_hash);
    assert!(mainnet_form.starts_with("sqf"));
    assert!(decode_pq_address(&Network::Mainnet, &mainnet_form).is_some());
    assert_eq!(decode_pq_address(&regtest, &mainnet_form), None);
    let yed_pq = base58check(&[0x57, 0x15, 0xAA], &key_hash);
    assert!(yed_pq.starts_with("yrs"));
    assert_eq!(decode_pq_address(&regtest, &yed_pq), None);
    let yed_key = base58check(&[0x20, 0x02], &key_hash[..20]);
    assert!(yed_key.starts_with("yr"));
    assert_eq!(decode_pq_address(&regtest, &yed_key), None);

    let answer = super::super::validate_address::validate_address(regtest.clone(), yed_key)
        .expect("validateaddress answers");
    assert!(!answer.is_valid());
    let answer = super::super::validate_address::validate_address(regtest.clone(), yed_pq)
        .expect("validateaddress answers");
    assert!(!answer.is_valid());
    let address = base58check(&[0x4C, 0x54, 0xEF], &key_hash);
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

    for kind in [
        NetworkKind::Mainnet,
        NetworkKind::Testnet,
        NetworkKind::Regtest,
    ] {
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

/// `finalState` (W9-c finding 4): trailing empty parents dropped, interior ones kept; anything
/// that is not a commitment tree is returned unchanged.
#[test]
fn tree_parents_are_trimmed_as_ycashd() {
    let some = |b: u8| [vec![1u8], vec![b; 32]].concat();
    let mut tree = [some(1), vec![0], vec![31], some(2), vec![0], some(3)].concat();
    tree.extend(std::iter::repeat_n(0u8, 28));
    let trimmed = super::trim_tree_parents(tree);
    assert_eq!(
        trimmed,
        [some(1), vec![0], vec![3], some(2), vec![0], some(3)].concat()
    );
    assert_eq!(super::trim_tree_parents(trimmed.clone()), trimmed);
    let empty = vec![0u8, 0, 0];
    assert_eq!(super::trim_tree_parents(empty.clone()), empty);
    let junk = vec![7u8, 1, 2];
    assert_eq!(super::trim_tree_parents(junk.clone()), junk);
}

/// Three UTXOs of one address whose chain order differs from ycashd's index order, plus a second
/// address and a later height: ycashd orders by height, then request address, then the txid's
/// internal bytes, then the output index's little-endian bytes (`ycash6 src/rpc/misc.cpp`,
/// `getaddressutxos`; `src/addressindex.h`, `CAddressUnspentKey`).
#[test]
fn ycash_address_utxos_follow_ycashd_index_order() {
    use crate::methods::Utxo;
    use zakura_chain::{parameters::NetworkKind, transaction};

    let first = transparent::Address::from_pub_key_hash(NetworkKind::Regtest, [0x22; 20]);
    let second = transparent::Address::from_pub_key_hash(NetworkKind::Regtest, [0x11; 20]);
    let txid = |lead: u8| {
        let mut bytes = [0u8; 32];
        bytes[0] = lead;
        transaction::Hash(bytes)
    };
    let utxo = |address: &transparent::Address, lead: u8, index: u64, height: u32| {
        Utxo::new(
            *address,
            txid(lead),
            transparent::OutputIndex::from_u64(index),
            transparent::Script::new(&[0x51]),
            1,
            Height(height),
        )
    };

    // Chain order, as Zakura's state returns it: height 5 holds txids 0x30, 0x10 and 0x20 in
    // that block order (0x10 with outputs 1 and 256), the second address's 0x05 comes later in
    // the same block, and height 7 holds 0x01.
    let mut utxos = vec![
        utxo(&first, 0x30, 0, 5),
        utxo(&first, 0x10, 1, 5),
        utxo(&first, 0x10, 256, 5),
        utxo(&first, 0x20, 0, 5),
        utxo(&second, 0x05, 0, 5),
        utxo(&first, 0x01, 0, 7),
    ];

    order_address_utxos_as_ycashd(&mut utxos, &[first, second]);

    let order: Vec<(u8, u32, u32)> = utxos
        .iter()
        .map(|u| (u.txid().0[0], u.output_index().index(), u.height().0))
        .collect();
    assert_eq!(
        order,
        vec![
            // height 5, the first requested address: txid bytes, then index little-endian
            // (256 = 00 01 00 00 sorts before 1 = 01 00 00 00)
            (0x10, 256, 5),
            (0x10, 1, 5),
            (0x20, 0, 5),
            (0x30, 0, 5),
            // height 5, the second requested address
            (0x05, 0, 5),
            // height 7
            (0x01, 0, 7),
        ]
    );

    // The request order decides between addresses at one height, not the address bytes.
    order_address_utxos_as_ycashd(&mut utxos, &[second, first]);
    assert_eq!(utxos[0].txid().0[0], 0x05);
    assert_eq!(utxos[0].address(), &second);
}

/// S5 parity (`vault_upgrade.py`): `getblock.chainhistoryroot` is the header's commitment from
/// after the Heartwood activation block, null before and at it.
#[test]
fn ycash_chain_history_root_follows_heartwood() {
    use zakura_chain::parameters::testnet::ConfiguredActivationHeights;
    let network = Network::new_regtest(
        ConfiguredActivationHeights {
            overwinter: Some(1),
            sapling: Some(1),
            ycash: Some(1),
            blossom: Some(1),
            heartwood: Some(1),
            canopy: Some(1),
            vault: Some(105),
            ..Default::default()
        }
        .into(),
    );
    let c = [7; 32];
    assert_eq!(chain_history_root(&network, Height(0), c), [0; 32]);
    assert_eq!(chain_history_root(&network, Height(1), c), [0; 32]);
    assert_eq!(chain_history_root(&network, Height(2), c), c);
    assert_eq!(chain_history_root(&network, Height(105), c), c);
    assert_eq!(chain_history_root(&network, Height(106), c), c);
}

/// S5 parity (`wallet_pq_address`): an insight address parameter may be a YED form; `yrs…` names
/// the same post-quantum key as `rqs…` (D-9), and `yr…` of a P2PKH key its `tm…` address.
#[test]
fn ycash_insight_address_takes_the_yed_forms() {
    use kogany_vault::{Hash32, PqOwner};
    use kogany_yellowback::codecs::address::{encode_address, encode_pq_address};
    use zakura_chain::parameters::NetworkKind;
    let p = kogany_yellowback::params::params_for_network("regtest").expect("regtest");
    let rq = transparent::Address::PayToPqKeyHash {
        network_kind: NetworkKind::Regtest,
        scheme: 1,
        key_hash: [3; 32],
    };
    let yr = encode_pq_address(
        &PqOwner {
            scheme: 1,
            hash: Hash32([3; 32]),
        },
        &p,
    )
    .expect("a yr… address");
    assert!(rq.to_string().starts_with("rqs"), "{rq}");
    assert!(yr.starts_with("yrs"), "{yr}");
    assert_eq!(insight_address(&rq.to_string()), Some(rq));
    assert_eq!(insight_address(&yr), Some(rq));
    let t = transparent::Address::from_pub_key_hash(NetworkKind::Testnet, [4; 20]);
    assert_eq!(insight_address(&encode_address(&[4; 20], &p)), Some(t));
    assert_eq!(insight_address("nope"), None);
}

/// S5 parity (`wallet_pq_address`): a `getaddressutxos` row names a post-quantum key with the
/// caller's form, and any other address canonically, in zcashd's field set.
#[test]
fn ycash_utxo_address_is_the_callers_name() {
    use crate::methods::Utxo;
    use zakura_chain::{parameters::NetworkKind, transaction};
    let t = transparent::Address::from_pub_key_hash(NetworkKind::Testnet, [4; 20]);
    let mut utxo = Utxo::new(
        t,
        transaction::Hash([1; 32]),
        transparent::OutputIndex::from_u64(0),
        transparent::Script::new(&[0x51]),
        5,
        Height(3),
    );
    let json = serde_json::to_value(&utxo).expect("json");
    assert_eq!(json["address"], t.to_string());
    let keys: Vec<&String> = json.as_object().expect("object").keys().collect();
    assert_eq!(
        keys,
        [
            "address",
            "txid",
            "outputIndex",
            "script",
            "satoshis",
            "height"
        ]
    );
    utxo.set_address_name("yr2named".to_owned());
    assert_eq!(
        serde_json::to_value(&utxo).expect("json")["address"],
        "yr2named"
    );
}

/// D-9: a TX_PQPKH output's verbose `scriptPubKey` (`getrawtransaction 1`, `getblock 2`,
/// `gettxout`) names it by its scheme-visible plain-YEC address, exactly the shared vector of
/// its network and scheme (`testdata/yellowback/pq_address_vectors.json`, byte-identical to
/// ycash6's); `validateaddress` describes every such vector and refuses the YED forms and every
/// invalid vector on every network.
#[test]
fn verbose_script_pub_key_and_validateaddress_use_the_shared_vectors() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata/yellowback/pq_address_vectors.json");
    let v: serde_json::Value =
        serde_json::from_slice(&std::fs::read(path).expect("the pinned vectors")).expect("json");
    let network = |n: &str| match n {
        "main" => Network::Mainnet,
        "test" => Network::new_default_testnet(),
        "regtest" => Network::new_regtest(Default::default()),
        other => panic!("network {other}"),
    };
    let networks = ["main", "test", "regtest"];
    let mut plain = 0;
    for row in v["valid"].as_array().expect("valid") {
        let address = row["address"].as_str().expect("address");
        let key_hash = row["keyhash"].as_str().expect("keyhash");
        let scheme = row["scheme"].as_u64().expect("scheme");
        let script = transparent::Script::new(
            &hex::decode(format!("20{key_hash}{:02x}c2", 0x50 + scheme)).expect("hex"),
        );
        let own = network(row["network"].as_str().expect("network"));
        if row["coin"] == "yed" {
            for n in networks {
                let answer =
                    super::super::validate_address::validate_address(network(n), address.into())
                        .expect("validateaddress answers");
                assert!(!answer.is_valid(), "YED {address} on {n}");
            }
            continue;
        }
        plain += 1;
        assert_eq!(
            super::super::ycash_script::script_pub_key_fields(
                &script,
                "nonstandard".to_owned(),
                &own
            ),
            (
                Some(1),
                "pqpubkeyhash".to_owned(),
                Some(vec![address.to_owned()])
            )
        );
        let pq = decode_pq_address(&own, address).expect("its own network decodes it");
        assert_eq!(pq.address, address);
        assert_eq!(u64::from(pq.scheme), scheme);
        assert_eq!(pq.key_hash, key_hash);
        assert_eq!(pq.script_pub_key, hex::encode(script.as_raw_bytes()));
        let answer = super::super::validate_address::validate_address(own, address.into())
            .expect("validateaddress answers");
        assert!(answer.is_valid(), "{address}");
    }
    assert_eq!(plain, 36);
    for row in v["invalid"].as_array().expect("invalid") {
        let address = row["address"].as_str().expect("address");
        for n in networks {
            let answer =
                super::super::validate_address::validate_address(network(n), address.into())
                    .expect("validateaddress answers");
            assert!(!answer.is_valid(), "{} {address} on {n}", row["reason"]);
        }
    }
}
