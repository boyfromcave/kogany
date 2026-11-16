//! YDF coinbase golden vectors: real Ycash mainnet blocks (`testdata/ycash-mainnet/`, fetched over
//! P2P from `lite.ycash.xyz:8833`, `/YcashCpp:4.5.0/`, provenance in `PROVENANCE.json` there)
//! checked by `subsidy_is_valid` against ycashd's rule (`ycash6 src/main.cpp:6248-6286`).

use std::sync::Arc;

use zakura_chain::{
    amount::{Amount, NonNegative},
    block::{Block, Height},
    parameters::{
        subsidy::{block_subsidy, founders_reward, miner_subsidy},
        ycash::ydf,
        Network,
    },
    serialization::ZcashDeserializeInto,
    transaction::Transaction,
};

use super::check::subsidy_is_valid;

macro_rules! ycash_block {
    ($height:literal) => {
        (
            $height,
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../testdata/ycash-mainnet/",
                stringify!($height),
                ".hex"
            )),
        )
    };
}

/// Every fetched block: the fork, the YDF address boundaries 570,000 + 17,917·k for
/// k = 0, 1, 2, 23, 47, 48 (the wrap to index 0) and 95, the first halving at 850,000, Blossom,
/// Heartwood and Canopy, and the end of the mandate at 2,275,000.
const BLOCKS: &[(u32, &str)] = &[
    ycash_block!(569999),
    ycash_block!(570000),
    ycash_block!(570001),
    ycash_block!(587916),
    ycash_block!(587917),
    ycash_block!(605834),
    ycash_block!(849999),
    ycash_block!(850000),
    ycash_block!(982091),
    ycash_block!(1100000),
    ycash_block!(1100005),
    ycash_block!(1100006),
    ycash_block!(1412099),
    ycash_block!(1430016),
    ycash_block!(2272115),
    ycash_block!(2274999),
    ycash_block!(2275000),
    ycash_block!(2275001),
];

fn block(hex_block: &str) -> Block {
    hex::decode(hex_block.trim())
        .expect("test vector is hex")
        .zcash_deserialize_into()
        .expect("a real Ycash mainnet block parses in a ycash build")
}

/// ycashd's `GetBlockSubsidy` on Ycash mainnet, computed by hand: 12.5 YEC before the first
/// halving at 850,000, 6.25 YEC until Blossom at 1,100,000, then 6.25 / 2 for the 75 s spacing
/// until the second halving at 2,280,000.
fn expected_subsidy(height: u32) -> i64 {
    match height {
        ..850_000 => 1_250_000_000,
        850_000..1_100_000 => 625_000_000,
        1_100_000..2_280_000 => 312_500_000,
        _ => unreachable!("no vector past the second halving"),
    }
}

/// The YDF list index at a post-fork height (`ycash6 src/chainparams.cpp:1026-1033`).
fn expected_ydf_index(height: u32) -> usize {
    ((height - 570_000) / 17_917) as usize % 48
}

#[test]
fn ydf_golden_vectors_from_mainnet() {
    let _init_guard = zakura_test::init();
    let net = Network::Mainnet;

    for &(height, hex_block) in BLOCKS {
        let block = block(hex_block);
        let h = Height(height);
        assert_eq!(block.coinbase_height(), Some(h));

        let subsidy = block_subsidy(h, &net, None).expect("valid subsidy");
        assert_eq!(
            i64::from(subsidy),
            expected_subsidy(height),
            "subsidy at {height}"
        );

        let ydf = ydf::ydf_reward(&net, h);
        let mandated = (570_000..2_275_000).contains(&height);
        assert_eq!(
            i64::from(ydf),
            if mandated {
                expected_subsidy(height) / 20
            } else {
                0
            },
            "YDF at {height}"
        );
        if height >= 570_000 {
            assert_eq!(founders_reward(&net, h), Amount::<NonNegative>::zero());
            assert_eq!(
                ydf::ydf_address(&net, h).map(|a| a.to_string()),
                Some(ydf::MAINNET_YDF_ADDRESSES[expected_ydf_index(height)].to_string()),
                "YDF address at {height}"
            );
        } else {
            assert_eq!(ydf::ydf_address(&net, h), None);
            assert_eq!(
                i64::from(founders_reward(&net, h)),
                expected_subsidy(height) / 5
            );
        }
        assert_eq!(
            miner_subsidy(h, &net, subsidy).expect("valid"),
            ((subsidy - ydf).expect("ydf <= subsidy") - founders_reward(&net, h)).expect("valid"),
        );

        subsidy_is_valid(&block, &net, subsidy)
            .unwrap_or_else(|error| panic!("real block at {height} must pass: {error:?}"));
    }

    // The index wraps: 1,430,016 = 570,000 + 48 · 17,917 pays the first address again.
    assert_eq!(expected_ydf_index(1_430_016), 0);
    assert_eq!(expected_ydf_index(1_412_099), 47);
}

/// Removes the coinbase output equal to `amount`, or adds one zatoshi to it.
fn tamper(block: &Block, amount: Amount<NonNegative>, add_one: bool) -> Option<Block> {
    let mut block = block.clone();
    let mut coinbase: Transaction = (*block.transactions[0]).clone();
    let outputs = coinbase.outputs_mut();
    let index = outputs.iter().position(|o| o.value() == amount)?;
    if add_one {
        let value = (outputs[index].value() + Amount::<NonNegative>::try_from(1).expect("valid"))
            .expect("valid");
        outputs[index] =
            zakura_chain::transparent::Output::new(value, outputs[index].lock_script.clone());
    } else {
        outputs.remove(index);
    }
    block.transactions[0] = Arc::new(coinbase);
    Some(block)
}

#[test]
fn ydf_missing_or_wrong_amount_rejects_until_the_mandate_ends() {
    let _init_guard = zakura_test::init();
    let net = Network::Mainnet;

    for &(height, hex_block) in BLOCKS.iter().filter(|(h, _)| *h >= 570_000) {
        let block = block(hex_block);
        let h = Height(height);
        let subsidy = block_subsidy(h, &net, None).expect("valid subsidy");
        let ydf_amount =
            Amount::<NonNegative>::try_from(expected_subsidy(height) / 20).expect("valid");

        for add_one in [false, true] {
            let Some(tampered) = tamper(&block, ydf_amount, add_one) else {
                assert!(
                    height >= 2_275_000,
                    "a mandated block has its YDF output at {height}"
                );
                continue;
            };
            let result = subsidy_is_valid(&tampered, &net, subsidy);
            if height < 2_275_000 {
                assert!(
                    result.is_err(),
                    "tampered YDF at {height} (add_one {add_one}) must reject"
                );
            } else {
                assert!(result.is_ok(), "the YDF is optional at {height}");
            }
        }
    }
}

#[test]
fn ydf_lists_and_heights_on_testnet_and_regtest() {
    let fast = Network::new_default_testnet();
    // The fast profile's own end (beta3 item 5): provisional until the release-candidate cut,
    // the same constant as `TESTNET_FAST_YDF_MANDATE_END_HEIGHT` on the C++ lines.
    assert_eq!(ydf::mandate_end::TESTNET_FAST, Height(600_000));
    assert_eq!(ydf::ydf_mandate_end_height(&fast), Height(600_000));
    assert_eq!(ydf::ydf_address(&fast, Height(510_247)), None);
    assert_eq!(
        ydf::ydf_address(&fast, Height(510_248)).map(|a| a.to_string()),
        Some(ydf::TESTNET_YDF_ADDRESSES[0].to_string())
    );
    assert_eq!(
        ydf::ydf_address(&fast, Height(510_248 + 17_917)).map(|a| a.to_string()),
        Some(ydf::TESTNET_YDF_ADDRESSES[1].to_string())
    );
    assert!(ydf::ydf_reward(&fast, Height(599_999)) > Amount::<NonNegative>::zero());
    assert_eq!(
        ydf::ydf_reward(&fast, Height(600_000)),
        Amount::<NonNegative>::zero()
    );

    // Regtest: every upgrade through Canopy at 1 by default, so the Ycash rules apply from 1 and
    // the YDF is mandatory below 5 (`ycash6 src/chainparams.cpp:777`).
    let regtest = Network::new_regtest(Default::default());
    assert_eq!(ydf::ydf_mandate_end_height(&regtest), Height(5));
    assert!(ydf::ydf_reward(&regtest, Height(4)) > Amount::<NonNegative>::zero());
    assert_eq!(
        ydf::ydf_reward(&regtest, Height(5)),
        Amount::<NonNegative>::zero()
    );
    assert_eq!(
        ydf::ydf_address(&regtest, Height(1)).map(|a| a.to_string()),
        Some(ydf::TESTNET_YDF_ADDRESSES[0].to_string())
    );

    // Every list entry parses under the Ycash prefixes, as do the re-encoded founders' lists.
    for list in [
        &ydf::MAINNET_YDF_ADDRESSES[..],
        &ydf::TESTNET_YDF_ADDRESSES[..],
    ] {
        for address in list {
            address
                .parse::<zakura_chain::transparent::Address>()
                .unwrap_or_else(|_| panic!("{address} parses"));
        }
    }
    for list in [
        Network::Mainnet.founder_address_list(),
        fast.founder_address_list(),
    ] {
        for address in list {
            address
                .parse::<zakura_chain::transparent::Address>()
                .unwrap_or_else(|_| panic!("{address} parses"));
        }
    }

    // No funding streams or lockbox anywhere on Ycash.
    for net in [Network::Mainnet, fast] {
        assert!(net.all_funding_streams().is_empty());
    }
}

/// A block whose only transaction is a v4 coinbase at `height` with `outputs`: everything
/// `subsidy_is_valid` reads of a block. The header is a real mainnet block's and is not read.
fn block_with_coinbase(height: Height, outputs: Vec<zakura_chain::transparent::Output>) -> Block {
    use zakura_chain::{transaction::LockTime, transparent::Input};

    let mut block = block(BLOCKS[0].1);
    block.transactions = vec![Arc::new(Transaction::V4 {
        inputs: vec![Input::Coinbase {
            height,
            data: Vec::new(),
            sequence: u32::MAX,
        }],
        outputs,
        lock_time: LockTime::unlocked(),
        expiry_height: Height(0),
        joinsplit_data: None,
        sapling_shielded_data: None,
    })];
    block
}

/// The four coinbases the mandate distinguishes at `height` on `net`, and whether each passes
/// `subsidy_is_valid`: with exactly `subsidy / 20` to the fund address of the height, without a
/// fund output, with one zatoshi more, and with the right amount to another script.
fn fund_output_verdicts(net: &Network, height: u32) -> [bool; 4] {
    use zakura_chain::transparent::{Output, Script};

    let h = Height(height);
    let subsidy = block_subsidy(h, net, None).expect("valid subsidy");
    let fund = (subsidy / 20).expect("valid");
    let miner = (subsidy - fund).expect("valid");
    let fund_script = ydf::ydf_address(net, h)
        .expect("the YDF address is defined from the Ycash upgrade on")
        .script();
    let miner_script = Script::new(&[0x51]);
    let one = Amount::<NonNegative>::try_from(1).expect("valid");

    let verdict = |outputs: Vec<Output>| {
        subsidy_is_valid(&block_with_coinbase(h, outputs), net, subsidy).is_ok()
    };
    [
        verdict(vec![
            Output::new(miner, miner_script.clone()),
            Output::new(fund, fund_script.clone()),
        ]),
        verdict(vec![Output::new(subsidy, miner_script.clone())]),
        verdict(vec![
            Output::new(miner, miner_script.clone()),
            Output::new((fund + one).expect("valid"), fund_script),
        ]),
        verdict(vec![
            Output::new(miner, miner_script.clone()),
            Output::new(fund, miner_script),
        ]),
    ]
}

/// Beta3 item 5: the end of the YDF mandate, E, on every network. At E - 1 the output of exactly
/// `subsidy / 20` to the fund address is required: its absence, another amount and another script
/// are rejected. At E and at E + 1 a block is valid without it and with it (and with any other
/// output: the rule no longer looks). E is 600,000 on the fast testnet (provisional), 5 on
/// regtest, 2,275,000 on mainnet and on the slow and legacy shadow forks, and 900,000 on a
/// configured testnet with a magic of its own.
#[test]
fn fund_output_is_required_below_the_mandate_end_and_optional_from_it() {
    let _init_guard = zakura_test::init();

    let fast = Network::new_default_testnet();
    assert!(zakura_chain::parameters::ycash::is_fast_network(&fast));
    let other_testnet = zakura_chain::parameters::testnet::Parameters::build()
        .with_network_name("YdfTestOther")
        .and_then(|builder| {
            builder.with_network_magic(zakura_chain::parameters::Magic([0x79, 0x64, 0x66, 0x00]))
        })
        .and_then(|builder| builder.to_network())
        .expect("a configured testnet with its own magic is valid");
    assert!(!zakura_chain::parameters::ycash::is_fast_network(
        &other_testnet
    ));

    for (name, net, end) in [
        ("fast", fast, 600_000),
        ("regtest", Network::new_regtest(Default::default()), 5),
        ("mainnet", Network::Mainnet, 2_275_000),
        ("slow", Network::new_ycash_testnet_slow(), 2_275_000),
        ("legacy", Network::new_ycash_testnet_legacy(), 2_275_000),
        ("configured", other_testnet, 900_000),
    ] {
        assert_eq!(ydf::ydf_mandate_end_height(&net), Height(end), "{name}");
        assert_eq!(
            fund_output_verdicts(&net, end - 1),
            [true, false, false, false],
            "{name}: the fund output is required at E - 1 = {}",
            end - 1
        );
        for height in [end, end + 1] {
            assert_eq!(
                fund_output_verdicts(&net, height),
                [true, true, true, true],
                "{name}: the fund output is optional at {height}"
            );
        }
    }

    // Blocks the fast testnet already has stay valid: they carry the output, which is required
    // below E and allowed from it. Its Ycash upgrade is at 510,248.
    assert_eq!(
        fund_output_verdicts(&Network::new_default_testnet(), 510_248),
        [true, false, false, false]
    );
}
