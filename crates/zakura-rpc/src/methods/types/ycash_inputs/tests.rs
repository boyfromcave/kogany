//! ycashd's insight input fields and `blockfee` (beta3 item 6).

use zakura_chain::{
    amount::{Amount, NonNegative},
    parameters::NetworkKind,
    transaction::LockTime,
    transparent::{Input as ChainInput, Output, Script},
};

use super::*;

fn zat(value: i64) -> Amount<NonNegative> {
    Amount::try_from(value).expect("test amounts are valid")
}

fn output(script: Vec<u8>) -> Output {
    Output::new(zat(250_000), Script::new(&script))
}

fn pq_script(scheme: u8, key_hash: [u8; 32]) -> Vec<u8> {
    let mut s = vec![0x20];
    s.extend_from_slice(&key_hash);
    s.extend_from_slice(&[0x50 + scheme, 0xc2]);
    s
}

fn networks() -> Vec<(Network, NetworkKind)> {
    vec![
        (Network::Mainnet, NetworkKind::Mainnet),
        (Network::new_default_testnet(), NetworkKind::Testnet),
        (
            Network::new_regtest(Default::default()),
            NetworkKind::Regtest,
        ),
    ]
}

/// P2PKH and P2SH are named by their hash, a bare P2PK (compressed or uncompressed) as the P2PKH
/// of Hash160(key) (`CScript::AddressIndexKey`), on every network.
#[test]
fn ecc_inputs_are_named_as_the_spent_index_names_them() {
    let compressed = [&[0x21, 0x02][..], &[7; 32], &[0xac]].concat();
    let uncompressed = [&[0x41, 0x04][..], &[8; 64], &[0xac]].concat();
    for (network, _) in networks() {
        let t = network.t_addr_kind();
        let p2pkh = Address::from_pub_key_hash(t, [1; 20]);
        let p2sh = Address::from_script_hash(t, [2; 20]);
        for address in [p2pkh, p2sh] {
            assert_eq!(
                spent_output_address(&network, &output(address.script().as_raw_bytes().to_vec())),
                Some(address.to_string())
            );
        }
        for script in [&compressed, &uncompressed] {
            let key = &script[1..script.len() - 1];
            assert_eq!(
                spent_output_address(&network, &output(script.clone())),
                Some(
                    Address::from_pub_key_hash(t, kogany_vault::template::hash160(key)).to_string()
                ),
            );
        }
    }
}

/// A TX_PQPKH of either scheme is named in the D-9 form (the scheme in the third character),
/// also when it carries YED (it is the same plain TX_PQPKH script).
#[test]
fn post_quantum_inputs_are_named_in_the_d9_form() {
    for (network, kind) in networks() {
        let prefix = match kind {
            NetworkKind::Mainnet => "sq",
            NetworkKind::Testnet => "tq",
            NetworkKind::Regtest => "rq",
        };
        for (scheme, letter) in [(1, 's'), (2, 'f')] {
            let name = spent_output_address(&network, &output(pq_script(scheme, [scheme; 32])))
                .expect("a TX_PQPKH is named");
            assert_eq!(&name[..3], format!("{prefix}{letter}"), "{name}");
            let want = Address::PayToPqKeyHash {
                network_kind: kind,
                scheme,
                key_hash: [scheme; 32],
            };
            assert_eq!(name, want.to_string());
        }
    }
}

/// Scripts the spent index keys as unknown name no address: a near-miss of each shape, a
/// multisig, OP_TRUE, an empty script, an unknown scheme byte.
#[test]
fn other_scripts_name_no_address() {
    let network = Network::new_regtest(Default::default());
    let mut multisig = vec![0x51, 0x21, 0x02];
    multisig.extend_from_slice(&[3; 32]);
    multisig.extend_from_slice(&[0x51, 0xae]);
    let hybrid = [&[0x41, 0x06][..], &[8; 64], &[0xac]].concat();
    let short_p2pk = [&[0x21, 0x04][..], &[7; 32], &[0xac]].concat();
    let mut p2pkh_trailing = Address::from_pub_key_hash(network.t_addr_kind(), [1; 20])
        .script()
        .as_raw_bytes()
        .to_vec();
    p2pkh_trailing.push(0x75);
    for script in [
        vec![],
        vec![0x51],
        multisig,
        hybrid,
        short_p2pk,
        p2pkh_trailing,
        pq_script(3, [1; 32]),
        pq_script(1, [1; 32])[..34].to_vec(),
    ] {
        assert_eq!(
            spent_output_address(&network, &output(script.clone())),
            None,
            "{script:02x?}"
        );
    }
}

/// `name_input` sets the value fields (and the address where named) on a spend and leaves a
/// coinbase input alone.
#[test]
fn name_input_fills_spends_only() {
    let network = Network::new_regtest(Default::default());
    let address = Address::from_pub_key_hash(network.t_addr_kind(), [1; 20]);
    let spent = Output::new(zat(123_456_789), address.script());
    let mut spend = Input::NonCoinbase {
        txid: "00".repeat(32),
        vout: 0,
        script_sig: crate::methods::types::transaction::ScriptSig::new(
            String::new(),
            Script::new(&[]),
        ),
        sequence: 0,
        value: None,
        value_zat: None,
        address: None,
    };
    name_input(&network, &mut spend, &spent);
    let Input::NonCoinbase {
        value,
        value_zat,
        address: named,
        ..
    } = &spend
    else {
        unreachable!("a spend stays a spend")
    };
    assert_eq!(
        (*value, *value_zat, named.clone()),
        (
            Some(1.23456789),
            Some(123_456_789),
            Some(address.to_string())
        )
    );

    let mut vault = spend.clone();
    name_input(&network, &mut vault, &output(vec![0x51]));
    let Input::NonCoinbase { address, value, .. } = &vault else {
        unreachable!("a spend stays a spend")
    };
    assert_eq!((address.clone(), *value), (None, Some(0.0025)));

    let mut coinbase = Input::Coinbase {
        coinbase: vec![1, 2],
        sequence: 0,
    };
    let before = coinbase.clone();
    name_input(&network, &mut coinbase, &spent);
    assert_eq!(coinbase, before);
}

fn coinbase(outputs: Vec<Output>) -> Transaction {
    Transaction::V4 {
        inputs: vec![ChainInput::Coinbase {
            height: Height(10),
            data: vec![0],
            sequence: u32::MAX,
        }],
        outputs,
        lock_time: LockTime::unlocked(),
        expiry_height: Height(0),
        joinsplit_data: None,
        sapling_shielded_data: None,
    }
}

fn transparent_delta(zats: i64) -> ValueBalance<NegativeAllowed> {
    ValueBalance::from_transparent_amount(Amount::try_from(zats).expect("valid delta"))
}

/// The fee is what left the pools other than through the coinbase: a miner paid in full, one
/// who claims less (the rest is burnt, the fee is the same), a block with no spend, genesis and
/// unknown pools.
#[test]
fn block_fee_is_the_value_the_pools_lost_to_fees() {
    let script = || Script::new(&[0x51]);
    let subsidy = 312_500_000;
    let fee = 166_500;
    // one spend: 100_000_000 in, 100_000_000 - fee out
    let spend_delta = -fee;
    let full = coinbase(vec![Output::new(zat(subsidy + fee), script())]);
    let delta = transparent_delta(subsidy + fee + spend_delta);
    assert_eq!(block_fee(Height(10), Some(delta), &full), fee);

    let short = coinbase(vec![Output::new(zat(subsidy), script())]);
    let delta = transparent_delta(subsidy + spend_delta);
    assert_eq!(block_fee(Height(10), Some(delta), &short), fee);

    // the fee also when the spend moves value into the Sapling pool
    let mut shielded =
        ValueBalance::from_sapling_amount(Amount::try_from(40_000_000).expect("valid delta"));
    shielded.set_transparent_value_balance(transparent_delta(subsidy + fee - 40_000_000 - fee));
    assert_eq!(block_fee(Height(10), Some(shielded), &full), fee);

    let alone = transparent_delta(subsidy);
    let only = coinbase(vec![Output::new(zat(subsidy), script())]);
    assert_eq!(block_fee(Height(10), Some(alone), &only), 0);

    assert_eq!(block_fee(Height(0), Some(transparent_delta(0)), &only), 0);
    assert_eq!(block_fee(Height(10), None, &full), 0);
}
