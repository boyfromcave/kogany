// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

//! The network-fee derivation (W6-b) against ycash6's C++ cases at `65cb4ae0f`, under their names:
//! `src/test/yellowback_txbuilder_tests.cpp` `yed_network_fee_caps_at_maxtxfee` and
//! `yed_network_fee_dollars_per_kb_at_the_attested_price` (lines 1453-1574), and
//! `src/test/pq_wallet_tests.cpp` `pq_size_fee` (lines 459-470). The C++ mutates the globals
//! (`pqFeeRate`, `maxTxFee`, `attestedFeePolicy`, the published price); here each step sets the
//! same field of a [`FeePolicy`] value and passes the price explicitly.

#![allow(clippy::unwrap_used, clippy::arithmetic_side_effects)]

use kogany_yellowback::fee::*;
use kogany_yellowback::params::{COIN, DEFAULT_YELLOWBACK_FEE, PRICE_MAX, PRICE_MIN};

const FALCON: u8 = 2;
const SLH_DSA: u8 = 1;

/// The fixture's `g_yellowbackFee` and `minCapZat` (`init.cpp` never ran: the static defaults).
fn base() -> FeePolicy {
    FeePolicy::default()
}

#[test]
fn pq_spend_input_size_matches_kogany_pq_and_the_cpp_values() {
    for scheme in [SLH_DSA, FALCON] {
        let sig = kogany_pq::sig_size(scheme) + 1;
        let pk = kogany_pq::pubkey_size(scheme);
        assert_eq!(
            pq_spend_input_size(scheme),
            Some(pq_spend_input_size_for(sig, pk))
        );
    }
    // PQ_SPEND_INPUT in yellowback_fees.py; mempool_ycash_parity.py's pq_spend_input_size(2)
    assert_eq!(pq_spend_input_size(SLH_DSA), Some(7981));
    assert_eq!(pq_spend_input_size(FALCON), Some(1620));
    assert_eq!(pq_spend_input_size(3), None);
}

/// `YedNetworkFee({falcon, p2pkh}, nullopt)`: one Falcon input, one P2PKH input.
fn falcon_p2pkh() -> usize {
    yed_estimated_size(&[FALCON], 1)
}

// -maxtxfee as CWallet::CreateTransaction does: capped, never refused, never below the flat fee.
#[test]
fn yed_network_fee_caps_at_maxtxfee() {
    let mut p = base();
    let price = None; // D-Q-23 (b): no attested price here, the -pqfeerate fallback
    p.pq_fee_rate = COIN / 100; // -pqfeerate=0.01
    let bytes = 1000 + 150 + pq_spend_input_size(FALCON).unwrap();
    assert_eq!(falcon_p2pkh(), bytes);
    let uncapped = fee_at_rate(p.pq_fee_rate, bytes);
    assert!(uncapped > COIN / 50);
    p.max_tx_fee = DEFAULT_TRANSACTION_MAXFEE; // 0.1 YEC: not binding
    assert_eq!(p.yed_network_fee(price, falcon_p2pkh()), uncapped);
    p.max_tx_fee = COIN / 50; // -maxtxfee=0.02: capped
    assert_eq!(p.yed_network_fee(price, falcon_p2pkh()), COIN / 50);
    p.max_tx_fee = 1; // below the flat fees: the cap's floor, minCapZat
    assert_eq!(p.yed_max_tx_fee(price), p.attested.min_cap_zat); // a low -maxtxfee never blocks the flat fees
    assert_eq!(p.attested.min_cap_zat, VAULT_RPC_FEE);
    let flat = DEFAULT_YELLOWBACK_FEE.max(VAULT_RPC_FEE);
    assert_eq!(
        p.yed_network_fee(price, yed_estimated_size(&[FALCON], 0)),
        flat
    );
    assert_eq!(p.yed_network_fee(price, yed_estimated_size(&[], 1)), flat);
    p.max_tx_fee = DEFAULT_TRANSACTION_MAXFEE; // review A-2: no PQ input is priced by size too
    assert_eq!(
        p.yed_network_fee(price, yed_estimated_size(&[], 1)),
        fee_at_rate(p.pq_fee_rate, 1000 + 150)
    );
    assert_eq!(
        p.yed_network_fee(price, yed_estimated_size(&[], 0)),
        fee_at_rate(p.pq_fee_rate, 1000)
    );
}

// D-Q-23 (b), D-Q-23a: with an attested price the rates are dollars per KB (plain $0.02, Yellowback
// $0.05), never below the 5,000 zat/KB floor (nor -pqfeerate, review A-7); the Yellowback cap is
// min(max(-maxtxfee, $2 at the price), -yellowbackmaxtxfee) (review M-1); no price = the fallback.
#[test]
fn yed_network_fee_dollars_per_kb_at_the_attested_price() {
    let bytes = 1000 + 150 + pq_spend_input_size(FALCON).unwrap();
    // the rate arithmetic: ceil(uUSD/KB x COIN / price), floored
    assert_eq!(attested_rate_zat_per_kb(20000, 18000, 5000), 111_111_112);
    assert_eq!(attested_rate_zat_per_kb(50000, 18000, 5000), 277_777_778);
    assert_eq!(attested_rate_zat_per_kb(20000, PRICE_MAX, 5000), 5000); // 466 zat/KB at PRICE_MAX: the floor binds
    assert_eq!(attested_rate_zat_per_kb(50000, PRICE_MAX, 5000), 5000); // 1,165 zat/KB: the floor
    assert_eq!(attested_rate_zat_per_kb(50000, PRICE_MAX, 0), 1165);
    assert_eq!(attested_rate_zat_per_kb(20000, 4_000_000, 5000), 500_000); // $4/YEC: 0.005 YEC/KB
    assert_eq!(attested_rate_zat_per_kb(20000, 400_000_000, 5000), 5000); // $400/YEC: 5,000 exactly
    assert_eq!(attested_rate_zat_per_kb(20000, 399_999_999, 5000), 5001);
    assert_eq!(
        attested_rate_zat_per_kb(20000, PRICE_MIN, 5000),
        20000 * COIN / 100
    ); // 20,000 YEC/KB at $0.0001
    assert_eq!(attested_rate_zat_per_kb(0, 18000, 5000), 5000);
    assert_eq!(attested_rate_zat_per_kb(20000, 0, 5000), 5000);
    assert_eq!(
        attested_rate_zat_per_kb(2_000_000, 18000, 0),
        11_111_111_112
    ); // $2 at $0.018 = 111.1 YEC (the cap's arithmetic)

    // with a price: the Yellowback rate, the dollar cap above -maxtxfee
    let mut p = base();
    p.pq_fee_rate = 100;
    p.max_tx_fee = DEFAULT_TRANSACTION_MAXFEE;
    p.attested.plain_usd_per_kb_micro = DEFAULT_PQ_FEE_USD_PER_KB_MICRO;
    p.attested.yed_usd_per_kb_micro = DEFAULT_YED_FEE_USD_PER_KB_MICRO;
    p.attested.floor_zat_per_kb = DEFAULT_ATTESTED_FEE_FLOOR_PER_KB;
    p.attested.yed_max_tx_fee_usd_micro = DEFAULT_YED_MAX_TX_FEE_USD_MICRO;
    p.attested.yed_max_tx_fee_zat = DEFAULT_YED_MAX_TX_FEE;
    let mut price = Some(18000);
    assert_eq!(p.plain_pq_fee_rate(price), 111_111_112);
    assert_eq!(p.yed_fee_rate(price), 277_777_778);
    assert_eq!(p.yed_max_tx_fee(price), 10 * COIN); // review M-1: $2 = 111 YEC, the 10-YEC ceiling binds
    assert_eq!(p.pq_max_tx_fee(price), p.yed_max_tx_fee(price)); // D-Q-26: plain PQ transfers share the cap
    p.attested.yed_max_tx_fee_zat = 1000 * COIN; // -yellowbackmaxtxfee=1000: the dollar cap stands
    assert_eq!(p.yed_max_tx_fee(price), 11_111_111_112); // $2 > 0.1 YEC at $0.018
                                                         // review A-2: a transaction without a PQ input is priced at the Yellowback rate by its size too
    assert_eq!(
        p.yed_network_fee(price, yed_estimated_size(&[], 1)),
        fee_at_rate(p.yed_fee_rate(price), 1000 + 150)
    );
    assert_eq!(falcon_p2pkh(), bytes);
    assert_eq!(
        p.yed_network_fee(price, falcon_p2pkh()),
        fee_at_rate(p.yed_fee_rate(price), bytes)
    );
    assert_eq!(
        p.pq_size_fee(price, 1000, bytes),
        fee_at_rate(p.plain_pq_fee_rate(price), bytes)
    );
    assert!(p.yed_size_fee(price, 1000, bytes) > p.pq_size_fee(price, 1000, bytes));
    p.max_tx_fee = COIN / 50; // -maxtxfee below $2: the dollar cap stands
    assert_eq!(p.yed_max_tx_fee(price), 11_111_111_112);
    price = Some(PRICE_MAX); // $2 = 46,566,129 zat at PRICE_MAX < 0.1 YEC: -maxtxfee binds
    p.max_tx_fee = DEFAULT_TRANSACTION_MAXFEE;
    assert_eq!(p.yed_max_tx_fee(price), DEFAULT_TRANSACTION_MAXFEE);
    assert_eq!(p.yed_fee_rate(price), 5000); // the floor
    p.attested.floor_zat_per_kb = 0;
    assert_eq!(p.yed_fee_rate(price), 1165);
    p.attested.floor_zat_per_kb = DEFAULT_ATTESTED_FEE_FLOOR_PER_KB;
    // review A-7: with a price the floor is max(floorZatPerKB, -pqfeerate), so -pqfeerate stays a floor
    p.pq_fee_rate = 8000;
    assert_eq!(p.attested_fee_floor_per_kb(), 8000);
    assert_eq!(p.yed_fee_rate(price), 8000);
    assert_eq!(p.plain_pq_fee_rate(price), 8000);
    assert_eq!(p.yed_floor_size_fee(price, 1000, 2000), 16000); // review L-1's clamp: the floor rate x size
    assert_eq!(p.yed_floor_size_fee(price, 100_000, 2000), 100_000); // never below the flat fee
    p.pq_fee_rate = 100;
    assert_eq!(
        p.attested_fee_floor_per_kb(),
        DEFAULT_ATTESTED_FEE_FLOOR_PER_KB
    );
    assert_eq!(p.yed_floor_size_fee(price, 1000, 2000), 10000);
    p.max_tx_fee = COIN / 50;
    price = Some(50000); // regtest's $0.05: a 2.6 KB Falcon spend
    assert_eq!(p.yed_fee_rate(price), 100_000_000); // 1 YEC/KB
    assert_eq!(p.yed_max_tx_fee(price), 40 * COIN); // $2 = 40 YEC
    p.attested.yed_max_tx_fee_zat = DEFAULT_YED_MAX_TX_FEE;
    assert_eq!(p.yed_max_tx_fee(price), 10 * COIN); // the ceiling
    p.attested.yed_max_tx_fee_zat = 1000 * COIN;
    assert_eq!(
        p.yed_network_fee(price, falcon_p2pkh()),
        fee_at_rate(p.yed_fee_rate(price), bytes)
    );
    // the target off (0): the fallback even with a price; no price: the fallback
    p.attested.yed_usd_per_kb_micro = 0;
    assert_eq!(p.yed_fee_rate(price), 100);
    p.attested.yed_usd_per_kb_micro = DEFAULT_YED_FEE_USD_PER_KB_MICRO;
    price = None;
    assert_eq!(p.yed_fee_rate(price), 100);
    assert_eq!(p.plain_pq_fee_rate(price), 100);
    assert_eq!(p.yed_max_tx_fee(price), COIN / 50);
    assert_eq!(p.yed_floor_size_fee(price, 1000, 20000), 2000); // no price: -pqfeerate x size
    p.attested.yed_max_tx_fee_zat = COIN / 100;
    assert_eq!(p.yed_max_tx_fee(price), COIN / 100); // the ceiling binds without a price too
    p.attested.yed_max_tx_fee_zat = DEFAULT_YED_MAX_TX_FEE;
    price = Some(0); // an undefined price (0) is no price
    assert_eq!(normalize_price(price), None);
    assert_eq!(p.yed_fee_rate(price), 100);
}

// max(floor, -pqfeerate x size) (quantum plan §4.5); the default rate is 1x the 100 zat/kB relay floor.
#[test]
fn pq_size_fee() {
    let mut p = base();
    let price = None; // D-Q-23 (b): no attested price, the -pqfeerate fallback
    p.pq_fee_rate = 100;
    assert_eq!(
        p.pq_size_fee(price, LEGACY_DEFAULT_FEE, 8100),
        LEGACY_DEFAULT_FEE
    ); // 810 < 1,000 (C-5)
    p.pq_fee_rate = 1000;
    assert_eq!(p.pq_size_fee(price, LEGACY_DEFAULT_FEE, 8100), 8100);
    assert_eq!(p.pq_size_fee(price, 10000, 8100), 10000);
}

/// `CFeeRate::GetFee`: `rate * size / 1000`, the rate when that rounds to zero.
#[test]
fn fee_at_rate_matches_cfeerate_get_fee() {
    assert_eq!(fee_at_rate(100, 0), 100);
    assert_eq!(fee_at_rate(100, 9), 100);
    assert_eq!(fee_at_rate(100, 10), 1);
    assert_eq!(fee_at_rate(0, 1000), 0);
    assert_eq!(fee_at_rate(5000, 8981), 44905);
}

/// `yed_getinfo.params.fees.network` as ycash6 renders it (`rpc/yellowback.cpp:768-787`), with
/// and without a price; the regtest worked values of `yellowback_fees.py`.
#[test]
fn network_fee_report_matches_yed_getinfo() {
    let p = base().with_min_cap();
    let r = p.network_fee_report(Some(750_000_000)); // $750/YEC (yellowback_fees.py DOWN)
    assert_eq!(r.price_micro_usd, Some(750_000_000));
    assert_eq!(r.plain_zat_per_kb, 5000); // 2,667 zat/KB: the floor
    assert_eq!(r.yed_zat_per_kb, 6667);
    assert_eq!(r.yed_max_tx_fee_zat, DEFAULT_TRANSACTION_MAXFEE); // $2 = 0.0027 YEC < 0.1
    assert_eq!(r.floor_zat_per_kb, DEFAULT_ATTESTED_FEE_FLOOR_PER_KB);
    assert_eq!(r.fallback_zat_per_kb, DEFAULT_MIN_RELAY_TX_FEE);
    assert_eq!(r.flat_zat, DEFAULT_YELLOWBACK_FEE);
    assert_eq!(r.max_tx_fee_zat, DEFAULT_TRANSACTION_MAXFEE);
    assert_eq!(r.yed_max_tx_fee_ceiling_zat, DEFAULT_YED_MAX_TX_FEE);
    let none = p.network_fee_report(Some(-5));
    assert_eq!(none.price_micro_usd, None);
    assert_eq!(none.plain_zat_per_kb, DEFAULT_MIN_RELAY_TX_FEE);
    assert_eq!(none.yed_zat_per_kb, DEFAULT_MIN_RELAY_TX_FEE);
    assert_eq!(none.yed_max_tx_fee_zat, DEFAULT_TRANSACTION_MAXFEE);
}

/// ycashd's init checks (`init.cpp:1346-1379, 1639-1650`).
#[test]
fn fee_policy_validate_matches_init() {
    assert_eq!(base().with_min_cap().validate(), Ok(()));
    let mut p = base();
    p.yellowback_fee = 999;
    assert!(p
        .with_min_cap()
        .validate()
        .unwrap_err()
        .contains("-yellowbackfee"));
    let mut p = base();
    p.pq_fee_rate = 0;
    assert!(p.validate().unwrap_err().contains("-pqfeerate"));
    let mut p = base();
    p.attested.yed_max_tx_fee_zat = MIN_YED_MAX_TX_FEE - 1;
    assert!(p.validate().unwrap_err().contains("-yellowbackmaxtxfee"));
    let mut p = base();
    p.yellowback_fee = 200_000;
    p.attested.yed_max_tx_fee_zat = 150_000;
    let p = p.with_min_cap();
    assert_eq!(p.attested.min_cap_zat, 200_000);
    assert!(p.validate().unwrap_err().contains("max(-yellowbackfee"));
    let mut p = base();
    p.attested.yed_usd_per_kb_micro = MAX_USD_MICRO + 1;
    assert!(p.validate().unwrap_err().contains("-yellowbackfeeusdperkb"));
}
