//! Tests of `getcoinbasetemplatefor` (beta3 item 3): the request, the amount, the coinbase of
//! every address kind against this node's own `getblocktemplate` coinbase, the errors of the
//! contract in their order, and the block limits.
//!
//! The Sapling tests need `sapling-output.params` (ycashd's file): in ycashd's parameter
//! directory, or at `KOGANY_SAPLING_OUTPUT_PARAMS`. Without the file they are skipped with a
//! note, unless `KOGANY_REQUIRE_SAPLING_PARAMS=1` makes its absence a failure.

use std::sync::Arc;

use serde_json::{json, Value};
use zakura_chain::{
    amount::{Amount, NonNegative},
    block::{self, Height},
    chain_tip::NoChainTip,
    parameters::Network,
    serialization::{ZcashDeserializeInto, ZcashSerialize},
    transaction::{self, LockTime, Transaction, UnminedTx, VerifiedUnminedTx},
    transparent::{self, Output, Script},
};
use zakura_node_services::mempool::TransactionDependencies;

use super::*;
use crate::{
    config,
    methods::types::{
        get_block_template::{
            ycash::{NotLive, YellowbackMiner},
            MinerParams,
        },
        transaction::{
            sapling_coinbase::{
                default_params_dir, SAPLING_OUTPUT_PARAMS_BYTES, SAPLING_OUTPUT_PARAMS_FILE,
            },
            TransactionTemplate,
        },
    },
};

const P2PKH: &str = "smKfGwyRJhcNVEQL3ZC2Kitx3WhmHHGLxFR";
const SAPLING: &str =
    "yregtestsapling1xl84ekz6stprmvrp39s77mf9t953nqjndwlcjtzfrr3cgjjez87639xm4u9pfuvylrhec7x0pw7";
/// `testdata/yellowback/pq_address_vectors.json`: regtest, FN-DSA-512 and SLH-DSA-SHA2-128s.
const PQ_FN: &str = "rqf2UsjFAdzsYwqphjSkcTigtzZv2jVWQc3F6XLvBUuVrY97KQTYq";
const PQ_SLH: &str = "rqs2PNtFr55Bg27WkDzGpBBVYEQkVpDc65k4T4gYSQn6FNop3aVFk";
/// The same vectors' YED form of a key: not a destination.
const YED: &str = "yrf1M2hF2xLQGsrzJ4ws7UbCjTiHvJxJrsFGg1im6SnVT6iCwEd3r";

const SUBSIDY: i64 = 625_000_000;
const VAULT: u32 = 100;

/// Ycash regtest with the Vault upgrade at height 100 (regtest schedules none by default).
fn regtest() -> Network {
    use zakura_chain::parameters::testnet::{ConfiguredActivationHeights, RegtestParameters};

    Network::new_regtest(RegtestParameters {
        activation_heights: ConfiguredActivationHeights {
            vault: Some(VAULT),
            ..Default::default()
        },
        ..Default::default()
    })
}

fn zat(value: i64) -> Amount<NonNegative> {
    Amount::try_from(value).expect("a valid test amount")
}

fn p2sh_address(network: &Network) -> String {
    transparent::Address::from_script_hash(network.t_addr_kind(), [0x5c; 20]).to_string()
}

fn payout(text: &str) -> Payout {
    Payout::parse(&regtest(), &json!(text)).expect("a payable address")
}

fn error_of<T: std::fmt::Debug>(result: RpcResult<T>) -> (i32, String) {
    let error = result.expect_err("the call must refuse");
    (error.code(), error.message().to_string())
}

/// The Sapling output prover of the tests, `None` (with a note) without the parameters file.
// The note of a skipped or timed test must reach the test log.
#[allow(clippy::print_stderr)]
fn test_prover() -> Option<SaplingOutputProver> {
    let path = std::env::var_os("KOGANY_SAPLING_OUTPUT_PARAMS")
        .map(std::path::PathBuf::from)
        .or_else(|| default_params_dir().map(|dir| dir.join(SAPLING_OUTPUT_PARAMS_FILE)));
    let bytes = path.as_ref().and_then(|path| std::fs::read(path).ok());
    let Some(bytes) = bytes else {
        assert!(
            std::env::var("KOGANY_REQUIRE_SAPLING_PARAMS").as_deref() != Ok("1"),
            "KOGANY_REQUIRE_SAPLING_PARAMS=1 and no {SAPLING_OUTPUT_PARAMS_FILE} at {path:?}"
        );
        eprintln!("SKIPPED: no {SAPLING_OUTPUT_PARAMS_FILE} at {path:?}");
        return None;
    };
    assert_eq!(bytes.len() as u64, SAPLING_OUTPUT_PARAMS_BYTES);
    Some(SaplingOutputProver::from_verified_bytes(&bytes).expect("the parameters parse"))
}

/// This node's own `getblocktemplate` coinbase for a P2PKH miner address, as `zakurad` builds
/// its miner parameters from the configuration.
fn stock_coinbase(
    network: &Network,
    height: u32,
    fees: i64,
    ydf: i64,
    yellowback: Option<YellowbackMiner>,
) -> Transaction {
    let config = config::mining::Config {
        miner_address: Some(P2PKH.parse().expect("a valid address")),
        ydf,
        ..Default::default()
    };
    let params = MinerParams::new(network, config)
        .expect("valid miner parameters")
        .with_yellowback(yellowback);
    TransactionTemplate::new_coinbase(network, Height(height), &params, zat(fees), None)
        .expect("the stock coinbase builds")
        .data
        .as_ref()
        .zcash_deserialize_into()
        .expect("the stock coinbase parses")
}

fn values(tx: &Transaction) -> Vec<i64> {
    tx.outputs().iter().map(|o| i64::from(o.value)).collect()
}

fn tagged_miner() -> YellowbackMiner {
    let tag =
        YellowbackMiner::build_tag(true, Some([0x11; 20]), 1_234_567, 0x0003).expect("a valid tag");
    YellowbackMiner {
        tag: Some(tag),
        payout_key: Some(tag.payout_key),
        quote_age_seconds: Some(0),
        registered: false,
        eligible: false,
    }
}

// ---- the request -----------------------------------------------------------------------------

#[test]
fn the_reference_is_exactly_two_keys_and_no_amount() {
    let prev = "00".repeat(31) + "0a";
    let txid = "ab".repeat(32);
    let ok = json!({"previousblockhash": prev, "txids": [txid]});
    let reference = TemplateReference::parse(&ok).expect("a valid reference");
    assert_eq!(reference.previous_block_hash.to_string(), prev);
    assert_eq!(reference.txids.len(), 1);
    assert_eq!(reference.txids[0].to_string(), txid);

    // Upper-case hex names the same template.
    let upper = json!({"previousblockhash": prev.to_uppercase(), "txids": [txid.to_uppercase()]});
    assert_eq!(TemplateReference::parse(&upper).expect("valid"), reference);

    let shape = (
        -8,
        "template must be an object with exactly the keys previousblockhash and txids".to_string(),
    );
    for bad in [
        json!({"previousblockhash": prev}),
        json!({"txids": []}),
        json!({}),
        json!([]),
        json!("x"),
        json!(1),
        Value::Null,
        // No way to ask for an amount: any third key is refused, whatever it is called.
        json!({"previousblockhash": prev, "txids": [], "amount": 1}),
        json!({"previousblockhash": prev, "txids": [], "fees": 0}),
        json!({"previousblockhash": prev, "txids": [], "coinbasevalue": 1}),
        json!({"previousblockhash": prev, "amount": 1}),
    ] {
        assert_eq!(error_of(TemplateReference::parse(&bad)), shape, "{bad}");
    }

    for bad in [
        json!("00"),
        json!(prev[..63]),
        json!(prev[..63].to_string() + "g"),
        json!(1),
    ] {
        assert_eq!(
            error_of(TemplateReference::parse(
                &json!({"previousblockhash": bad, "txids": []})
            )),
            (
                -8,
                "previousblockhash must be 64 hex characters".to_string()
            ),
        );
    }

    for bad in [
        json!("x"),
        json!({}),
        json!(["00"]),
        json!([txid, 1]),
        json!([txid[..63].to_string() + "z"]),
    ] {
        assert_eq!(
            error_of(TemplateReference::parse(
                &json!({"previousblockhash": prev, "txids": bad})
            )),
            (
                -8,
                "txids must be an array of strings of 64 hex characters".to_string()
            ),
        );
    }

    let many: Vec<String> = (0..=MAX_TXIDS).map(|n| format!("{n:064x}")).collect();
    assert_eq!(
        error_of(TemplateReference::parse(
            &json!({"previousblockhash": prev, "txids": many})
        )),
        (-8, "txids has more than 50000 entries".to_string()),
    );
    let most: Vec<String> = (0..MAX_TXIDS).map(|n| format!("{n:064x}")).collect();
    assert_eq!(
        TemplateReference::parse(&json!({"previousblockhash": prev, "txids": most}))
            .expect("50,000 ids are allowed")
            .txids
            .len(),
        MAX_TXIDS
    );
}

#[test]
fn the_address_is_one_of_the_four_payable_kinds() {
    let network = regtest();
    assert_eq!(payout(P2PKH).address_type(), "p2pkh");
    assert_eq!(payout(&p2sh_address(&network)).address_type(), "p2sh");
    assert_eq!(payout(SAPLING).address_type(), "sapling");
    for pq in [PQ_FN, PQ_SLH] {
        let Payout::Pq(script) = payout(pq) else {
            panic!("{pq} is a post-quantum address");
        };
        // <32-byte key hash> <scheme> OP_CHECKPQSIG.
        let bytes = script.as_raw_bytes();
        assert_eq!((bytes.len(), bytes[0], bytes[34]), (35, 0x20, 0xc2));
    }

    let invalid = (-5, "Invalid address".to_string());
    let old_form = "sq4f3xNwus8MoS2YpysjcMfUTmwyWqkcMqzFCdvYbmyMsvZYyKQAD";
    for bad in [
        json!(""),
        json!("x"),
        json!(P2PKH[..P2PKH.len() - 1]),
        json!(1),
        Value::Null,
        // A YED address is not a destination, and neither is the old post-quantum form.
        json!(YED),
        json!(old_form),
        // Another network's addresses.
        json!("s1hfWJ4ej1H3s8XCUb7YnrU68K64AsGVUHE"),
        json!("sqf2UsjFAdzsYwqphjSkcTigtzZv2jVWQc3F6XLvBUuVrY97KQTYq"),
    ] {
        assert_eq!(error_of(Payout::parse(&network, &bad)), invalid, "{bad}");
    }

    // A Sprout address of this network is an address, of a kind no coinbase pays
    // (regtest `ZCPAYMENT_ADDRESS` 0x16 0x52, as the C++ lines' test builds it).
    let mut sprout = vec![0x16, 0x52];
    sprout.extend_from_slice(&[0u8; 64]);
    let sprout = kogany_yellowback::codecs::base58::encode_base58_check(&sprout);
    assert_eq!(
        error_of(Payout::parse(&network, &json!(sprout))),
        (
            -5,
            "Address type cannot receive a coinbase: sprout".to_string()
        ),
    );
}

#[test]
fn an_address_kind_is_payable_from_its_upgrade_on() {
    let network = regtest();
    let heartwood = NetworkUpgrade::Heartwood
        .activation_height(&network)
        .expect("regtest schedules Heartwood");
    for kind in [P2PKH, SAPLING, PQ_FN] {
        let payout = payout(kind);
        for height in (1..=12).chain(VAULT - 1..=VAULT + 1) {
            let height = Height(height);
            let want = match payout {
                Payout::Sapling(_) => height >= heartwood,
                Payout::Pq(_) => network.is_vault_active(height),
                _ => true,
            };
            if matches!(payout, Payout::Pq(_)) {
                assert_eq!(want, height.0 >= VAULT);
            }
            let got = payout.check_payable_at(&network, height);
            assert_eq!(got.is_ok(), want, "{kind} at {height:?}");
            if let Err(error) = got {
                assert_eq!(
                    (error.code(), error.message().to_string()),
                    (
                        -5,
                        format!(
                            "Address type cannot receive a coinbase at height {}: {}",
                            height.0,
                            payout.address_type()
                        )
                    )
                );
            }
        }
    }
}

// ---- the amount and the coinbase -------------------------------------------------------------

/// Regtest, the mandate ends at height 5: below it the fund output is consensus's 5 % whatever
/// `mining.ydf` says; from it on the node's share, none by default. The fees are the miner's on
/// every row, and `amount = subsidy - fund + fees`.
#[test]
fn the_amount_is_the_subsidy_less_the_fund_plus_every_fee() {
    let network = regtest();
    let fees = 734;
    for (height, ydf, fund, rule) in [
        (4, 0, 31_250_000, "mandated"),
        (4, 5, 31_250_000, "mandated"),
        (4, 100, 31_250_000, "mandated"),
        (5, 0, 0, "none"),
        (6, 0, 0, "none"),
        (5, 1, 6_250_000, "optional"),
        (5, 5, 31_250_000, "optional"),
        (100, 5, 31_250_000, "optional"),
        (5, 100, 625_000_000, "optional"),
    ] {
        let amounts = CoinbaseAmounts::derive(&network, Height(height), zat(fees), ydf)
            .expect("valid amounts");
        assert_eq!(i64::from(amounts.subsidy), SUBSIDY);
        assert_eq!(i64::from(amounts.fund_value()), fund, "{height} {ydf}");
        assert_eq!(amounts.fund_rule, rule, "{height} {ydf}");
        assert_eq!(i64::from(amounts.fees), fees);
        assert_eq!(i64::from(amounts.amount), SUBSIDY - fund + fees);
        assert_eq!(amounts.fund.is_some(), fund != 0);
    }
}

/// The transparent coinbase is this node's own `getblocktemplate` coinbase for the same address:
/// the same input script (`<height> OP_0 <tag>`), the same outputs in the same order, the same
/// fund output; version 4, lock time 0. Only the expiry height differs: 0, as ycashd's coinbase
/// has it (kogany's own coinbase carries its height).
#[test]
fn a_transparent_coinbase_is_the_stock_coinbase_with_expiry_zero() {
    let network = regtest();
    let fees = 734;
    for (height, ydf) in [(4, 0), (4, 5), (5, 0), (5, 5), (120, 5), (120, 0)] {
        for miner in [None, Some(tagged_miner())] {
            let flags = miner
                .as_ref()
                .map(YellowbackMiner::flags)
                .unwrap_or_default();
            let stock = stock_coinbase(&network, height, fees, ydf, miner.clone());
            let amounts = CoinbaseAmounts::derive(&network, Height(height), zat(fees), ydf as u64)
                .expect("valid amounts");
            let built = build_coinbase(
                &network,
                Height(height),
                &payout(P2PKH),
                &amounts,
                &flags,
                None,
            )
            .expect("a transparent coinbase needs no prover");

            assert_eq!(built.inputs(), stock.inputs(), "{height} {ydf}");
            assert_eq!(built.outputs(), stock.outputs(), "{height} {ydf}");
            assert_eq!(built.version(), 4);
            assert_eq!(built.lock_time(), None);
            assert_eq!(built.expiry_height(), None, "expiry height 0");
            assert_eq!(stock.expiry_height(), Some(Height(height)));

            // The input script reads <height> OP_0 <flags>.
            let script = built.inputs()[0]
                .coinbase_script()
                .expect("a coinbase input");
            let mut tail = vec![0x00];
            tail.extend_from_slice(&flags);
            assert!(script.ends_with(&tail));
            assert_eq!(flags.len(), if miner.is_some() { 37 } else { 0 });

            // vout[0] pays the address the amount; then only the fund output.
            let mut want = vec![i64::from(amounts.amount)];
            want.extend(amounts.fund.as_ref().map(|(value, _)| i64::from(*value)));
            assert_eq!(values(&built), want);
            assert_eq!(total_output(&built), Some(SUBSIDY + fees));
            assert_eq!(built.sigops(), stock.sigops());

            // It is a canonical transaction: it reads back as itself.
            let bytes = built.zcash_serialize_to_vec().expect("serializes");
            let back: Transaction = bytes.zcash_deserialize_into().expect("parses");
            assert_eq!(back, built);
        }
    }
}

/// With `mining.ydf = 5` past the mandate every transparent kind is paid 95 % of the subsidy and
/// every fee, and the fund output is the stock coinbase's, value and script.
#[test]
fn every_transparent_kind_carries_the_stock_fund_output() {
    let network = regtest();
    let (height, fees) = (120, 20_000);
    let stock = stock_coinbase(&network, height, fees, 5, None);
    let stock_fund = stock.outputs()[1].clone();
    assert_eq!(i64::from(stock_fund.value), SUBSIDY * 5 / 100);
    let amounts =
        CoinbaseAmounts::derive(&network, Height(height), zat(fees), 5).expect("valid amounts");
    assert_eq!(amounts.fund_rule, "optional");
    assert_eq!(
        i64::from(amounts.amount),
        SUBSIDY - SUBSIDY * 5 / 100 + fees
    );

    for address in [
        P2PKH.to_string(),
        p2sh_address(&network),
        PQ_FN.into(),
        PQ_SLH.into(),
    ] {
        let payout = payout(&address);
        let built =
            build_coinbase(&network, Height(height), &payout, &amounts, &[], None).expect("builds");
        let (Payout::P2pkh(script) | Payout::P2sh(script) | Payout::Pq(script)) = &payout else {
            unreachable!("transparent kinds only");
        };
        assert_eq!(
            built.outputs(),
            [
                Output::new(amounts.amount, script.clone()),
                stock_fund.clone()
            ],
            "{address}"
        );
        assert_eq!(total_output(&built), Some(SUBSIDY + fees));
        // One legacy signature operation for a P2PKH script, none for the others.
        let fund_sigops = stock.sigops() - 1;
        let own = u32::from(matches!(payout, Payout::P2pkh(_)));
        assert_eq!(built.sigops(), own + fund_sigops, "{address}");
    }
}

#[test]
fn a_sapling_coinbase_without_the_parameters_is_refused_and_the_others_are_not() {
    let network = regtest();
    let amounts = CoinbaseAmounts::derive(&network, Height(120), zat(0), 0).expect("valid amounts");
    assert_eq!(
        build_coinbase(&network, Height(120), &payout(SAPLING), &amounts, &[], None),
        Err("Sapling output parameters are not loaded".to_string())
    );
    for address in [P2PKH, PQ_FN] {
        build_coinbase(&network, Height(120), &payout(address), &amounts, &[], None)
            .expect("no prover is needed");
    }
}

/// The Sapling coinbase: only the fund output is transparent (it is `vout[0]`), one Sapling
/// output carries the amount, `valueBalance = -amount`; the output decrypts with the all-zero
/// outgoing viewing key to exactly the amount for exactly the address, with an empty memo; the
/// binding signature verifies against the transaction's signature hash.
#[test]
// The note of a skipped or timed test must reach the test log.
#[allow(clippy::print_stderr)]
fn a_sapling_coinbase_pays_the_amount_in_one_output() {
    use sapling_crypto::{keys::OutgoingViewingKey, note_encryption::try_sapling_output_recovery};
    use zcash_primitives::transaction::components::sapling::zip212_enforcement;
    use zcash_protocol::consensus::{BlockHeight, BranchId};

    let Some(prover) = test_prover() else { return };
    let network = regtest();
    let Payout::Sapling(address) = payout(SAPLING) else {
        panic!("a Sapling address");
    };

    let mut timings = Vec::new();
    for (height, ydf, fees, fund) in [
        (4, 0, 0, Some(31_250_000)),
        (120, 0, 734, None),
        (120, 5, 734, Some(31_250_000)),
    ] {
        let amounts = CoinbaseAmounts::derive(&network, Height(height), zat(fees), ydf)
            .expect("valid amounts");
        let flags = tagged_miner().flags();
        let started = std::time::Instant::now();
        let built = build_coinbase(
            &network,
            Height(height),
            &payout(SAPLING),
            &amounts,
            &flags,
            Some(&prover),
        )
        .expect("the Sapling coinbase builds");
        timings.push(started.elapsed());
        let amount = SUBSIDY - fund.unwrap_or(0) + fees;
        assert_eq!(i64::from(amounts.amount), amount);

        // The layout.
        assert_eq!(built.version(), 4);
        assert_eq!(built.lock_time(), None);
        assert_eq!(built.expiry_height(), None);
        assert_eq!(values(&built), fund.into_iter().collect::<Vec<_>>());
        if fund.is_some() {
            let stock = stock_coinbase(&network, height, fees, ydf as i64, None);
            assert_eq!(
                built.outputs()[0],
                stock.outputs()[1],
                "the stock fund output"
            );
        }
        assert_eq!(built.sapling_outputs().count(), 1);
        assert_eq!(built.sapling_spends_per_anchor().count(), 0);
        assert_eq!(
            i64::from(built.sapling_value_balance().sapling_amount()),
            -amount
        );
        assert_eq!(total_output(&built), Some(SUBSIDY + fees));
        assert_eq!(
            built.inputs(),
            stock_coinbase(&network, height, fees, ydf as i64, Some(tagged_miner())).inputs()
        );

        // It reads back as itself, and as the transaction the Sapling library reads.
        let bytes = built.zcash_serialize_to_vec().expect("serializes");
        let back: Transaction = bytes.zcash_deserialize_into().expect("parses");
        assert_eq!(back, built);
        let branch = BranchId::for_height(&network, BlockHeight::from(Height(height)));
        let library = zcash_primitives::transaction::Transaction::read(bytes.as_slice(), branch)
            .expect("the Sapling library reads the coinbase");
        let bundle = library.sapling_bundle().expect("a Sapling bundle");
        let [output] = bundle.shielded_outputs() else {
            panic!("exactly one Sapling output");
        };

        // The note: the amount, to the address, empty memo, under the all-zero ovk (ZIP 213).
        let (note, to, memo) = try_sapling_output_recovery(
            &OutgoingViewingKey([0u8; 32]),
            output,
            zip212_enforcement(&network, BlockHeight::from(Height(height))),
        )
        .expect("the output decrypts with the all-zero outgoing viewing key");
        assert_eq!(i64::try_from(note.value().inner()).expect("fits"), amount);
        assert_eq!(to, address);
        assert_eq!(memo[0], 0xf6);
        assert!(memo[1..].iter().all(|byte| *byte == 0));

        // The binding signature, against the signature hash consensus computes.
        let sighash = built
            .sighasher_on(
                &network,
                NetworkUpgrade::current(&network, Height(height)),
                Arc::new(Vec::new()),
            )
            .expect("a sighasher")
            .sighash(HashType::ALL, None);
        let Transaction::V4 {
            sapling_shielded_data: Some(shielded),
            ..
        } = &built
        else {
            panic!("a v4 transaction with Sapling data");
        };
        let bvk = shielded
            .binding_verification_key()
            .expect("a binding verification key");
        zakura_chain::primitives::redjubjub::VerificationKey::try_from(bvk)
            .expect("a valid key")
            .verify(sighash.as_ref(), &shielded.binding_sig)
            .expect("the binding signature verifies");

        // Two coinbases for the same arguments differ in the output's randomness only.
        let again = build_coinbase(
            &network,
            Height(height),
            &payout(SAPLING),
            &amounts,
            &flags,
            Some(&prover),
        )
        .expect("builds");
        assert_ne!(again, built);
        assert_eq!(again.outputs(), built.outputs());
        assert_eq!(again.inputs(), built.inputs());
    }
    eprintln!("Sapling coinbase build times (proof and signature): {timings:?}");
}

// ---- the limits ------------------------------------------------------------------------------

#[test]
fn a_block_over_the_size_or_sigop_limit_is_refused() {
    let network = regtest();
    // 140 bytes and a 36-byte Equihash (48, 5) solution with its length byte.
    assert_eq!(header_size(&network), 177);
    assert_eq!(
        (
            compact_size_len(0),
            compact_size_len(252),
            compact_size_len(253),
            compact_size_len(65_535),
            compact_size_len(65_536)
        ),
        (1, 1, 3, 3, 5)
    );

    let room = MAX_BLOCK_BYTES - 177 - 1;
    check_fits(&network, 1_000, 1, 10, room - 1_000, 19_999).expect("exactly at both limits");
    assert_eq!(
        error_of(check_fits(&network, 1_000, 1, 10, room - 999, 0)),
        (
            -1,
            "coinbase-does-not-fit: block size 2000001 exceeds 2000000".to_string()
        ),
    );
    assert_eq!(
        error_of(check_fits(&network, 1_000, 1, 10, 0, 20_000)),
        (
            -1,
            "coinbase-does-not-fit: sigops 20001 exceed 20000".to_string()
        ),
    );
    // The size is looked at first.
    assert!(error_of(check_fits(&network, 1_000, 1, 10, room, 30_000))
        .1
        .starts_with("coinbase-does-not-fit: block size"));
}

// ---- the call --------------------------------------------------------------------------------

fn mempool_tx(seed: u8, fee: i64) -> VerifiedUnminedTx {
    let tx = Transaction::V4 {
        inputs: vec![transparent::Input::PrevOut {
            outpoint: transparent::OutPoint {
                hash: transaction::Hash([seed; 32]),
                index: 0,
            },
            unlock_script: Script::new(&[]),
            sequence: u32::MAX,
        }],
        outputs: vec![Output::new(zat(1), Script::new(&[0x51]))],
        lock_time: LockTime::unlocked(),
        expiry_height: Height(0),
        joinsplit_data: None,
        sapling_shielded_data: None,
    };
    let spent = vec![Output::new(zat(1 + fee), Script::new(&[0x51]))];
    VerifiedUnminedTx::new(UnminedTx::from(tx), zat(fee), 0, 0, Arc::new(spent))
        .expect("the test transaction pays the relay fee")
}

/// A hook whose Yellowback index is unhealthy.
struct Unhealthy;

#[async_trait::async_trait]
impl YcashMining for Unhealthy {
    async fn yellowback_miner(&self) -> Result<Option<YellowbackMiner>, String> {
        Err("the test says so".to_string())
    }
}

/// A hook that holds a quote.
struct Tagged;

#[async_trait::async_trait]
impl YcashMining for Tagged {
    async fn yellowback_miner(&self) -> Result<Option<YellowbackMiner>, String> {
        Ok(Some(tagged_miner()))
    }
}

type TestMempool =
    tower::util::BoxService<mempool::Request, mempool::Response, zakura_node_services::BoxError>;
type TestState = tower::util::BoxCloneService<
    zakura_state::ReadRequest,
    zakura_state::ReadResponse,
    zakura_state::BoxError,
>;

/// A node whose tip is `tip` at height 119 (and, from the second tip read on, `later_tip`),
/// whose mempool holds `transactions` and has seen the block `mempool_tip`.
fn node(
    tip: block::Hash,
    later_tip: block::Hash,
    mempool_tip: block::Hash,
    transactions: Vec<VerifiedUnminedTx>,
    mining: Arc<dyn YcashMining>,
    ydf_percentage: u64,
    prover: Option<SaplingOutputProver>,
) -> CoinbaseForNode<TestMempool, TestState, NoChainTip> {
    let reads = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let read_state = tower::service_fn(move |request: zakura_state::ReadRequest| {
        let n = reads.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        async move {
            assert!(matches!(request, zakura_state::ReadRequest::Tip));
            let hash = if n == 0 { tip } else { later_tip };
            Ok(zakura_state::ReadResponse::Tip(Some((Height(119), hash))))
        }
    });
    let mempool = tower::service_fn(move |request: mempool::Request| {
        let transactions = transactions.clone();
        async move {
            assert!(matches!(request, mempool::Request::FullTransactions));
            Ok(mempool::Response::FullTransactions {
                transactions,
                transaction_dependencies: TransactionDependencies::default(),
                last_seen_tip_hash: mempool_tip,
            })
        }
    });
    CoinbaseForNode {
        network: regtest(),
        mempool: tower::util::BoxService::new(mempool),
        read_state: tower::util::BoxCloneService::new(read_state),
        latest_chain_tip: NoChainTip,
        mining,
        ydf_percentage,
        sapling_output_prover: prover,
    }
}

fn reference(tip: block::Hash, txids: &[transaction::Hash]) -> Value {
    json!({
        "previousblockhash": tip.to_string(),
        "txids": txids.iter().map(ToString::to_string).collect::<Vec<_>>(),
    })
}

fn id(tx: &VerifiedUnminedTx) -> transaction::Hash {
    tx.transaction.id().mined_id()
}

/// The whole call on a scripted node: the answer's fields, and the amount derived from the
/// mempool's fees of exactly the named transactions, for a transparent and a post-quantum
/// address, at `mining.ydf` 0 and 5.
#[tokio::test]
async fn the_call_answers_with_the_amount_the_node_derived() {
    let tip = block::Hash([7; 32]);
    let txs = vec![
        mempool_tx(1, 1_000),
        mempool_tx(2, 20_000),
        mempool_tx(3, 300_000),
    ];
    let named = [id(&txs[0]), id(&txs[2])];
    let fees = 301_000;

    for (address, kind, ydf, hook) in [
        (P2PKH, "p2pkh", 0, Arc::new(NotLive) as Arc<dyn YcashMining>),
        (P2PKH, "p2pkh", 5, Arc::new(Tagged)),
        (PQ_SLH, "pq", 5, Arc::new(NotLive)),
        (PQ_FN, "pq", 0, Arc::new(Tagged)),
    ] {
        let tagged = hook.yellowback_miner().await.expect("healthy").is_some();
        let answer = get_coinbase_template_for(
            node(tip, tip, tip, txs.clone(), hook, ydf, None),
            &json!(address),
            &reference(tip, &named),
        )
        .await
        .expect("the call answers");

        let fund = SUBSIDY * i64::try_from(ydf).expect("fits") / 100;
        assert_eq!(answer.height, 120);
        assert_eq!(answer.previousblockhash, tip.to_string());
        assert_eq!(answer.addresstype, kind);
        assert_eq!(answer.subsidy, SUBSIDY);
        assert_eq!(answer.fund, fund);
        assert_eq!(answer.fundrule, if ydf == 0 { "none" } else { "optional" });
        assert_eq!(answer.fees, fees);
        assert_eq!(answer.amount, SUBSIDY - fund + fees);
        assert_eq!(answer.txcount, 2);
        assert_eq!(
            answer.flags,
            if tagged {
                hex::encode(tagged_miner().flags())
            } else {
                String::new()
            }
        );

        let coinbase: Transaction = hex::decode(&answer.data)
            .expect("hex")
            .zcash_deserialize_into()
            .expect("the coinbase parses");
        assert_eq!(coinbase.hash().to_string(), answer.hash);
        assert_eq!(coinbase.sigops(), answer.sigops);
        assert_eq!(i64::from(coinbase.outputs()[0].value), answer.amount);
        assert_eq!(total_output(&coinbase), Some(SUBSIDY + fees));
        assert_eq!(coinbase.outputs().len(), if ydf == 0 { 1 } else { 2 });

        // The JSON carries exactly the contract's keys, in its order.
        let json = serde_json::to_string(&answer).expect("serializes");
        let keys: Vec<&str> = json
            .split('"')
            .skip(1)
            .step_by(2)
            .filter(|key| {
                [
                    "data",
                    "hash",
                    "height",
                    "previousblockhash",
                    "addresstype",
                    "subsidy",
                    "fund",
                    "fundrule",
                    "fees",
                    "amount",
                    "txcount",
                    "flags",
                    "sigops",
                ]
                .contains(key)
            })
            .collect();
        assert_eq!(keys.len(), 13, "{json}");
    }

    // An empty template: the subsidy alone, and the mempool is not asked.
    let answer = get_coinbase_template_for(
        node(
            tip,
            tip,
            block::Hash([9; 32]),
            txs,
            Arc::new(NotLive),
            0,
            None,
        ),
        &json!(P2PKH),
        &reference(tip, &[]),
    )
    .await
    .expect("the call answers");
    assert_eq!(
        (answer.fees, answer.amount, answer.txcount),
        (0, SUBSIDY, 0)
    );
}

/// The refusals, in the contract's order of checks.
#[tokio::test]
async fn the_call_refuses_in_the_order_of_the_contract() {
    let tip = block::Hash([7; 32]);
    let other = block::Hash([8; 32]);
    let txs = vec![mempool_tx(1, 1_000), mempool_tx(2, 20_000)];
    let (a, b) = (id(&txs[0]), id(&txs[1]));
    let unknown = transaction::Hash([0xee; 32]);
    let healthy = || Arc::new(NotLive) as Arc<dyn YcashMining>;
    let stale = (
        -1,
        "template-stale: previousblockhash is not the tip".to_string(),
    );
    let missing = |txid: transaction::Hash| {
        (
            -1,
            format!("template-stale: transaction is not in the mempool: {txid}"),
        )
    };
    let call = |node, address: Value, template: Value| async move {
        error_of(get_coinbase_template_for(node, &address, &template).await)
    };
    let fresh = || node(tip, tip, tip, txs.clone(), healthy(), 0, None);

    // The shape of the reference before the address, the address before everything of the node.
    assert_eq!(call(fresh(), json!("x"), json!({})).await.0, -8);
    assert_eq!(
        call(fresh(), json!("x"), reference(other, &[])).await,
        (-5, "Invalid address".to_string())
    );

    // The unhealthy index before the tip.
    assert_eq!(
        call(
            node(tip, tip, tip, txs.clone(), Arc::new(Unhealthy), 0, None),
            json!(P2PKH),
            reference(other, &[]),
        )
        .await,
        (
            -26,
            "yellowback-unhealthy: the test says so; restart with -reindex-yellowback".to_string()
        )
    );

    // A stale tip before the mempool; a missing transaction before a repeated one, and the
    // first missing one in the request's order.
    assert_eq!(
        call(fresh(), json!(P2PKH), reference(other, &[unknown])).await,
        stale
    );
    assert_eq!(
        call(fresh(), json!(P2PKH), reference(tip, &[a, unknown, b])).await,
        missing(unknown)
    );
    assert_eq!(
        call(fresh(), json!(P2PKH), reference(tip, &[unknown, unknown])).await,
        missing(unknown)
    );
    assert_eq!(
        call(fresh(), json!(P2PKH), reference(tip, &[a, b, a])).await,
        (-8, format!("txids names a transaction twice: {a}"))
    );

    // A mempool that has not reached this tip can state no fee.
    assert_eq!(
        call(
            node(tip, tip, other, txs.clone(), healthy(), 0, None),
            json!(P2PKH),
            reference(tip, &[a]),
        )
        .await,
        missing(a)
    );

    // A Sapling address on a node without the parameters: the operator's error, after the
    // reference was checked; the same request for a transparent address is answered.
    assert_eq!(
        call(fresh(), json!(SAPLING), reference(tip, &[a])).await,
        (
            -32603,
            "coinbase construction failed: Sapling output parameters are not loaded".to_string()
        )
    );
    assert_eq!(
        call(fresh(), json!(SAPLING), reference(tip, &[unknown])).await,
        missing(unknown)
    );
    get_coinbase_template_for(fresh(), &json!(P2PKH), &reference(tip, &[a]))
        .await
        .expect("a transparent address needs no parameters");

    // The tip moved while the coinbase was built.
    assert_eq!(
        call(
            node(tip, other, tip, txs.clone(), healthy(), 0, None),
            json!(P2PKH),
            reference(tip, &[a]),
        )
        .await,
        stale
    );

    // A mempool that cannot answer states no fee either: the first named transaction is not in
    // it (row 11), never the service's own error. An empty template does not ask it.
    let failing = || CoinbaseForNode {
        mempool: tower::util::BoxService::new(tower::service_fn(|_: mempool::Request| async {
            Err::<mempool::Response, zakura_node_services::BoxError>("no mempool".into())
        })),
        ..fresh()
    };
    assert_eq!(
        call(failing(), json!(P2PKH), reference(tip, &[b, a])).await,
        missing(b)
    );
    get_coinbase_template_for(failing(), &json!(P2PKH), &reference(tip, &[]))
        .await
        .expect("an empty template needs no mempool");
}

/// A mempool transaction with `legacy_sigops` counted signature operations that spends an output
/// locked by `spent_script`.
fn mempool_tx_spending(
    seed: u8,
    fee: i64,
    legacy_sigops: u32,
    spent_script: Vec<u8>,
) -> VerifiedUnminedTx {
    let tx = mempool_tx(seed, fee)
        .transaction
        .transaction()
        .as_ref()
        .clone();
    let spent = vec![Output::new(zat(1 + fee), Script::new(&spent_script))];
    VerifiedUnminedTx::new(
        UnminedTx::from(tx),
        zat(fee),
        legacy_sigops,
        0,
        Arc::new(spent),
    )
    .expect("the test transaction pays the relay fee")
}

/// Row 12 counts signature operations as block validity does (legacy and P2SH, ycashd's
/// `ConnectBlock` and its own call), not with the policy count of 20 per `OP_CHECKPQSIG` the
/// template selection adds: a template heavy in post-quantum spends is answered as ycashd
/// answers it, and one over the consensus count is refused.
#[tokio::test]
async fn the_fit_check_counts_the_consensus_sigops() {
    use crate::methods::types::get_block_template::ycash::pq_sigops;

    let tip = block::Hash([7; 32]);
    // 1,001 `OP_CHECKPQSIG` in the spent script: 20,020 policy sigops, none for consensus.
    let pq_heavy = mempool_tx_spending(1, 1_000, 0, vec![0xc2; 1_001]);
    assert!(pq_sigops(&pq_heavy) > MAX_BLOCK_SIGOPS);
    assert_eq!(pq_heavy.block_sigop_count(), 0);
    let answer = get_coinbase_template_for(
        node(
            tip,
            tip,
            tip,
            vec![pq_heavy.clone()],
            Arc::new(NotLive),
            0,
            None,
        ),
        &json!(P2PKH),
        &reference(tip, &[id(&pq_heavy)]),
    )
    .await
    .expect("a template heavy in post-quantum spends is answered");
    assert_eq!(answer.fees, 1_000);

    // Consensus sigops: the named transaction's 20,000 and the coinbase's own exceed the limit.
    let heavy = mempool_tx_spending(2, 1_000, MAX_BLOCK_SIGOPS, vec![0x51]);
    let (code, message) = error_of(
        get_coinbase_template_for(
            node(
                tip,
                tip,
                tip,
                vec![heavy.clone()],
                Arc::new(NotLive),
                0,
                None,
            ),
            &json!(P2PKH),
            &reference(tip, &[id(&heavy)]),
        )
        .await,
    );
    assert_eq!(code, -1);
    assert!(
        message.starts_with(&format!(
            "coinbase-does-not-fit: sigops {} exceed {MAX_BLOCK_SIGOPS}",
            MAX_BLOCK_SIGOPS + 1
        )),
        "{message}"
    );
}

/// A Sapling call waits for a proof slot at most the bound, then answers row 17.
#[tokio::test(start_paused = true)]
async fn a_proof_slot_wait_is_bounded() {
    static FULL: Semaphore = Semaphore::const_new(0);
    static FREE: Semaphore = Semaphore::const_new(1);

    let started = tokio::time::Instant::now();
    assert_eq!(
        error_of(acquire_proof_slot(&FULL, PROOF_SLOT_WAIT).await),
        (
            -32603,
            "coinbase construction failed: timed out waiting for a Sapling proof slot".to_string()
        )
    );
    assert!(started.elapsed() >= PROOF_SLOT_WAIT);
    assert!(PROOF_SLOT_WAIT <= Duration::from_secs(30));

    let permit = acquire_proof_slot(&FREE, PROOF_SLOT_WAIT)
        .await
        .expect("a free slot is taken at once");
    assert_eq!(FREE.available_permits(), 0);
    drop(permit);
    assert_eq!(FREE.available_permits(), 1);
}

/// The call for a Sapling address: sixteen at once on a multi-threaded runtime, each answered
/// with its own coinbase of exactly the derived amount.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
// The note of a skipped or timed test must reach the test log.
#[allow(clippy::print_stderr)]
async fn sapling_calls_in_parallel_all_answer() {
    let Some(prover) = test_prover() else { return };
    let tip = block::Hash([7; 32]);
    let txs = vec![mempool_tx(1, 1_000), mempool_tx(2, 20_000)];
    let named = [id(&txs[0]), id(&txs[1])];

    let started = std::time::Instant::now();
    let calls = (0..16).map(|_| {
        let node = node(
            tip,
            tip,
            tip,
            txs.clone(),
            Arc::new(NotLive),
            5,
            Some(prover.clone()),
        );
        let template = reference(tip, &named);
        tokio::spawn(
            async move { get_coinbase_template_for(node, &json!(SAPLING), &template).await },
        )
    });
    let mut seen = std::collections::HashSet::new();
    for call in futures::future::join_all(calls).await {
        let answer = call.expect("the task ran").expect("the call answers");
        let fund = SUBSIDY * 5 / 100;
        assert_eq!(
            (
                answer.addresstype.as_str(),
                answer.fund,
                answer.fundrule.as_str(),
                answer.fees,
                answer.amount
            ),
            ("sapling", fund, "optional", 21_000, SUBSIDY - fund + 21_000)
        );
        let coinbase: Transaction = hex::decode(&answer.data)
            .expect("hex")
            .zcash_deserialize_into()
            .expect("the coinbase parses");
        assert_eq!(values(&coinbase), [fund]);
        assert_eq!(coinbase.sigops(), answer.sigops);
        assert_eq!(
            i64::from(coinbase.sapling_value_balance().sapling_amount()),
            -answer.amount
        );
        assert!(seen.insert(answer.hash), "every coinbase is its own");
    }
    eprintln!("16 Sapling calls at once: {:?}", started.elapsed());
}

// ---- the node's own coinbase -----------------------------------------------------------------

/// With the parameters installed, the node's own `getblocktemplate` coinbase pays a Sapling
/// `mining.miner_address` too (ycashd's `-mineraddress=<Sapling>`): one Sapling output of the
/// miner's whole reward, only the fund output transparent, within the size the template
/// reserved for it. Before Heartwood the address is refused as before.
#[test]
fn the_nodes_own_coinbase_pays_a_sapling_miner_address() {
    use crate::methods::types::transaction::sapling_coinbase::install_output_prover;

    let Some(prover) = test_prover() else { return };
    install_output_prover(prover);

    let network = regtest();
    let fees = 734;
    let config = |ydf| config::mining::Config {
        miner_address: Some(SAPLING.parse().expect("a valid address")),
        ydf,
        ..Default::default()
    };
    for (height, ydf, fund) in [
        (4, 0, Some(31_250_000)),
        (120, 0, None),
        (120, 5, Some(31_250_000)),
    ] {
        let params = MinerParams::new(&network, config(ydf)).expect("valid miner parameters");
        let template =
            TransactionTemplate::new_coinbase(&network, Height(height), &params, zat(fees), None)
                .expect("the Sapling coinbase builds");
        let usage =
            TransactionTemplate::coinbase_resource_usage(&network, Height(height), &params, None)
                .expect("the resource usage is known");
        assert!(template.data.as_ref().len() <= usage.max_serialized_size);
        assert_eq!(usage.shielded_action_counts.sapling_ios, 1);

        let tx: Transaction = template
            .data
            .as_ref()
            .zcash_deserialize_into()
            .expect("the coinbase parses");
        assert_eq!(values(&tx), fund.into_iter().collect::<Vec<_>>());
        assert_eq!(tx.sapling_outputs().count(), 1);
        assert_eq!(
            i64::from(tx.sapling_value_balance().sapling_amount()),
            -(SUBSIDY - fund.unwrap_or(0) + fees)
        );
        assert_eq!(total_output(&tx), Some(SUBSIDY + fees));
    }

    let heartwood = NetworkUpgrade::Heartwood
        .activation_height(&network)
        .expect("regtest schedules Heartwood");
    if let Ok(before) = heartwood.previous() {
        if before > Height(0) {
            let params = MinerParams::new(&network, config(0)).expect("valid miner parameters");
            assert!(
                TransactionTemplate::new_coinbase(&network, before, &params, zat(0), None).is_err()
            );
        }
    }
}
