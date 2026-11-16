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
    assert_eq!(block_fee(Height(10), Some(delta), Some(&full)), Some(fee));

    let short = coinbase(vec![Output::new(zat(subsidy), script())]);
    let delta = transparent_delta(subsidy + spend_delta);
    assert_eq!(block_fee(Height(10), Some(delta), Some(&short)), Some(fee));

    // the fee also when the spend moves value into the Sapling pool
    let mut shielded =
        ValueBalance::from_sapling_amount(Amount::try_from(40_000_000).expect("valid delta"));
    shielded.set_transparent_value_balance(transparent_delta(subsidy + fee - 40_000_000 - fee));
    assert_eq!(
        block_fee(Height(10), Some(shielded), Some(&full)),
        Some(fee)
    );

    let alone = transparent_delta(subsidy);
    let only = coinbase(vec![Output::new(zat(subsidy), script())]);
    assert_eq!(block_fee(Height(10), Some(alone), Some(&only)), Some(0));

    assert_eq!(
        block_fee(Height(0), Some(transparent_delta(0)), Some(&only)),
        Some(0)
    );
}

/// Missing data is a missing field, never a wrong number: unknown pools (this block's or its
/// parent's) or an unknown coinbase give no `blockfee`; genesis is 0 without either.
#[test]
fn block_fee_is_absent_when_its_data_is_missing() {
    let full = coinbase(vec![Output::new(zat(312_500_000), Script::new(&[0x51]))]);
    assert_eq!(block_fee(Height(10), None, Some(&full)), None);
    assert_eq!(
        block_fee(Height(10), Some(transparent_delta(0)), None),
        None
    );
    assert_eq!(block_fee(Height(10), None, None), None);
    assert_eq!(block_fee(Height(0), None, None), Some(0));
}

/// The parent cap: at the cap a call reads, above it it does not.
#[test]
fn insight_parent_cap() {
    let insight = InsightExplorer::new(true).with_max_parents(3);
    assert!(insight.enabled());
    assert!(!insight.over_cap(3));
    assert!(insight.over_cap(4));
    assert!(!InsightExplorer::default().enabled());
    assert!(!InsightExplorer::default().over_cap(MAX_INSIGHT_PARENTS));
    assert!(InsightExplorer::default().over_cap(MAX_INSIGHT_PARENTS + 1));
}

/// The parent reads of one call keep at most [`PARENT_READ_CONCURRENCY`] reads in flight, so
/// another caller of the same read state is served while a call with many parents runs (a
/// `getblock 2` of a large block reads its parents through [`read_parents`]).
#[tokio::test(flavor = "multi_thread")]
async fn parent_reads_are_bounded_and_leave_room_for_other_callers() {
    use std::{
        sync::atomic::{AtomicUsize, Ordering},
        time::Duration,
    };

    use tower::{buffer::Buffer, ServiceExt as _};
    use zakura_node_services::BoxError;
    use zakura_state::{ReadRequest, ReadResponse};

    let in_flight = Arc::new(AtomicUsize::new(0));
    let most = Arc::new(AtomicUsize::new(0));
    let parent_reads = Arc::new(AtomicUsize::new(0));
    let service = {
        let (in_flight, most, parent_reads) =
            (in_flight.clone(), most.clone(), parent_reads.clone());
        tower::service_fn(move |request: ReadRequest| {
            let (in_flight, most, parent_reads) =
                (in_flight.clone(), most.clone(), parent_reads.clone());
            async move {
                match request {
                    ReadRequest::Transaction(_) => {
                        let now = in_flight.fetch_add(1, Ordering::SeqCst) + 1;
                        most.fetch_max(now, Ordering::SeqCst);
                        tokio::time::sleep(Duration::from_millis(5)).await;
                        in_flight.fetch_sub(1, Ordering::SeqCst);
                        parent_reads.fetch_add(1, Ordering::SeqCst);
                        Ok::<_, BoxError>(ReadResponse::Transaction(None))
                    }
                    _ => Ok(ReadResponse::Tip(None)),
                }
            }
        })
    };
    // A shared read state with room for the bounded reads and one more caller.
    let read_state = Buffer::new(service, PARENT_READ_CONCURRENCY + 1);

    let wanted: HashSet<transaction::Hash> = (0..2_000u32)
        .map(|n| {
            let mut hash = [0; 32];
            hash[..4].copy_from_slice(&n.to_le_bytes());
            transaction::Hash(hash)
        })
        .collect();
    let large = tokio::spawn(read_parents(read_state.clone(), wanted));

    // Another caller, while the large call runs: served at once, not after 2,000 reads.
    tokio::time::sleep(Duration::from_millis(20)).await;
    let other = tokio::time::timeout(
        Duration::from_millis(500),
        read_state.clone().oneshot(ReadRequest::Tip),
    )
    .await
    .expect("another caller is served while the large call runs")
    .expect("the read succeeds");
    assert_eq!(other, ReadResponse::Tip(None));
    assert!(
        parent_reads.load(Ordering::SeqCst) < 2_000,
        "the other caller was served before the large call finished"
    );

    let parents = large.await.expect("the large call does not panic");
    assert_eq!(parents.len(), 2_000);
    assert!(parents.values().all(Option::is_none));
    assert!(
        most.load(Ordering::SeqCst) <= PARENT_READ_CONCURRENCY,
        "at most {PARENT_READ_CONCURRENCY} parent reads in flight, saw {}",
        most.load(Ordering::SeqCst)
    );
}
