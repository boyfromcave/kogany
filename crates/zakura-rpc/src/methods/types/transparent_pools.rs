// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE-MIT or https://www.opensource.org/licenses/mit-license.php .

//! Ycash (beta3 item 2): the `transparentPools` object of `getblockchaininfo` and `getblock`,
//! the transparent value pool split by address type.
//!
//! The names, the shape and the field order are ycash6's (`src/valuepools.cpp`
//! `TransparentPoolsToJSON`). `monitored` means "the node knows this value", as on ycash6: it is
//! false, and the amounts are absent, for a block the node's index does not cover. (The entries
//! of `valuePools` keep Zakura's meaning, "the pool is not zero".)

use zakura_chain::amount::{Amount, NegativeAllowed};
use zakura_state::transparent_pools::{BlockIndexInfo, TransparentPools};

use super::zec::Zec;

/// The amounts of one entry: the fields of a `valuePools` entry, in ycash6's order.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransparentPoolAmounts {
    /// Whether the node knows this value.
    pub monitored: bool,
    /// The total after the block, in YEC.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chain_value: Option<Zec<NegativeAllowed>>,
    /// The total after the block, in zatoshis.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chain_value_zat: Option<Amount<NegativeAllowed>>,
    /// The change in this block, in YEC (`getblock` only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value_delta: Option<Zec<NegativeAllowed>>,
    /// The change in this block, in zatoshis (`getblock` only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value_delta_zat: Option<Amount<NegativeAllowed>>,
}

impl TransparentPoolAmounts {
    /// The entry of the value `amount` reads from a record: unmonitored without the block's
    /// record, and without a delta unless the parent's record is given too.
    fn new(
        record: Option<&TransparentPools>,
        parent: Option<&TransparentPools>,
        amount: fn(&TransparentPools) -> i64,
    ) -> Self {
        let chain_value = record.and_then(|record| Amount::try_from(amount(record)).ok());
        let value_delta = record.zip(parent).and_then(|(record, parent)| {
            Amount::try_from(amount(record).checked_sub(amount(parent))?).ok()
        });
        Self {
            monitored: chain_value.is_some(),
            chain_value: chain_value.map(Zec::from),
            chain_value_zat: chain_value,
            value_delta: value_delta.map(Zec::from),
            value_delta_zat: value_delta,
        }
    }
}

/// One of the disjoint pools: they sum to `transparent`.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct TransparentPoolById {
    /// `transparent_ecc`, `transparent_pq`, `pq_channel`, `vault` or `vault_intent`.
    pub id: String,
    /// The amounts.
    #[serde(flatten)]
    pub amounts: TransparentPoolAmounts,
}

/// The part of `transparent_pq` under one signature scheme.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct TransparentPoolByScheme {
    /// The scheme byte.
    pub pqscheme: u8,
    /// The scheme's name.
    pub pqschemename: String,
    /// The amounts.
    #[serde(flatten)]
    pub amounts: TransparentPoolAmounts,
}

/// A registered rule module's part of `vault` plus `vault_intent`.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct TransparentPoolByModule {
    /// The module's name.
    pub module: String,
    /// The module's template tag, hex.
    pub tag: String,
    /// The amounts.
    #[serde(flatten)]
    pub amounts: TransparentPoolAmounts,
}

/// The `transparentPools` object. Find entries by `id`, never by position.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct TransparentPoolsInfo {
    /// False until the node's index covers this block.
    pub monitored: bool,
    /// The whole transparent pool.
    pub transparent: TransparentPoolAmounts,
    /// The disjoint pools.
    pub pools: Vec<TransparentPoolById>,
    /// `transparent_pq` by scheme: both schemes always, in the wallet's order.
    pub pq_by_scheme: Vec<TransparentPoolByScheme>,
    /// Registered rule modules only: today YED.
    pub vault_by_module: Vec<TransparentPoolByModule>,
}

impl TransparentPoolsInfo {
    /// The object of a block from its index figures; `with_delta` adds the change in the block
    /// (`getblock`), which needs the parent's record too.
    pub fn new(info: Option<&BlockIndexInfo>, with_delta: bool) -> Self {
        let record = info.and_then(|info| info.pools.as_ref());
        let parent = info
            .filter(|_| with_delta)
            .and_then(|info| info.parent_pools.as_ref());
        let amounts = |amount| TransparentPoolAmounts::new(record, parent, amount);

        let pools: [(&str, fn(&TransparentPools) -> i64); 5] = [
            ("transparent_ecc", TransparentPools::transparent_ecc),
            ("transparent_pq", TransparentPools::transparent_pq),
            ("pq_channel", |r| r.channel),
            ("vault", |r| r.vault),
            ("vault_intent", |r| r.intent),
        ];
        // The wallet's order and names (ycash6 `rpcwallet.cpp` `PQ_BALANCE_SCHEMES`).
        let schemes: [(u8, &str, fn(&TransparentPools) -> i64); 2] = [
            (1, "SLH-DSA-SHA2-128s", |r| r.pq1),
            (2, "FN-DSA-512", |r| r.pq2),
        ];

        Self {
            monitored: record.is_some(),
            transparent: amounts(|r| r.transparent),
            pools: pools
                .into_iter()
                .map(|(id, amount)| TransparentPoolById {
                    id: id.to_string(),
                    amounts: amounts(amount),
                })
                .collect(),
            pq_by_scheme: schemes
                .into_iter()
                .map(|(pqscheme, name, amount)| TransparentPoolByScheme {
                    pqscheme,
                    pqschemename: name.to_string(),
                    amounts: amounts(amount),
                })
                .collect(),
            vault_by_module: vec![TransparentPoolByModule {
                module: "YED".to_string(),
                tag: hex::encode(kogany_yellowback::codecs::script::YED_TAG.0),
                amounts: amounts(TransparentPools::yed),
            }],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const COIN: i64 = 100_000_000;

    fn info() -> BlockIndexInfo {
        BlockIndexInfo {
            chain_tx_count: Some(7),
            pools: Some(TransparentPools {
                transparent: 100 * COIN,
                pq1: 3 * COIN,
                pq2: 2 * COIN,
                channel: COIN,
                vault: 20 * COIN,
                intent: 4 * COIN,
                vault_yed: 15 * COIN,
                intent_yed: 4 * COIN,
            }),
            parent_pools: Some(TransparentPools {
                transparent: 90 * COIN,
                pq1: 3 * COIN,
                pq2: 0,
                channel: COIN,
                vault: 22 * COIN,
                intent: 2 * COIN,
                vault_yed: 17 * COIN,
                intent_yed: 2 * COIN,
            }),
        }
    }

    fn json(info: Option<&BlockIndexInfo>, with_delta: bool) -> String {
        serde_json::to_string(&TransparentPoolsInfo::new(info, with_delta))
            .expect("the object serializes")
    }

    /// `getblockchaininfo`: ycash6's names, order and shape (`TransparentPoolsToJSON(tip,
    /// false)`), no deltas.
    #[test]
    fn the_tip_object_is_ycash6s() {
        assert_eq!(
            json(Some(&info()), false),
            concat!(
                r#"{"monitored":true,"#,
                r#""transparent":{"monitored":true,"chainValue":100.0,"chainValueZat":10000000000},"#,
                r#""pools":["#,
                r#"{"id":"transparent_ecc","monitored":true,"chainValue":70.0,"chainValueZat":7000000000},"#,
                r#"{"id":"transparent_pq","monitored":true,"chainValue":5.0,"chainValueZat":500000000},"#,
                r#"{"id":"pq_channel","monitored":true,"chainValue":1.0,"chainValueZat":100000000},"#,
                r#"{"id":"vault","monitored":true,"chainValue":20.0,"chainValueZat":2000000000},"#,
                r#"{"id":"vault_intent","monitored":true,"chainValue":4.0,"chainValueZat":400000000}],"#,
                r#""pq_by_scheme":["#,
                r#"{"pqscheme":1,"pqschemename":"SLH-DSA-SHA2-128s","monitored":true,"chainValue":3.0,"chainValueZat":300000000},"#,
                r#"{"pqscheme":2,"pqschemename":"FN-DSA-512","monitored":true,"chainValue":2.0,"chainValueZat":200000000}],"#,
                r#""vault_by_module":["#,
                r#"{"module":"YED","tag":"59454400","monitored":true,"chainValue":19.0,"chainValueZat":1900000000}]}"#,
            )
        );
    }

    /// `getblock`: the same object with the change in the block, negative where the pool
    /// shrank and zero where it did not move.
    #[test]
    fn the_block_object_adds_the_deltas() {
        assert_eq!(
            json(Some(&info()), true),
            concat!(
                r#"{"monitored":true,"#,
                r#""transparent":{"monitored":true,"chainValue":100.0,"chainValueZat":10000000000,"valueDelta":10.0,"valueDeltaZat":1000000000},"#,
                r#""pools":["#,
                r#"{"id":"transparent_ecc","monitored":true,"chainValue":70.0,"chainValueZat":7000000000,"valueDelta":8.0,"valueDeltaZat":800000000},"#,
                r#"{"id":"transparent_pq","monitored":true,"chainValue":5.0,"chainValueZat":500000000,"valueDelta":2.0,"valueDeltaZat":200000000},"#,
                r#"{"id":"pq_channel","monitored":true,"chainValue":1.0,"chainValueZat":100000000,"valueDelta":0.0,"valueDeltaZat":0},"#,
                r#"{"id":"vault","monitored":true,"chainValue":20.0,"chainValueZat":2000000000,"valueDelta":-2.0,"valueDeltaZat":-200000000},"#,
                r#"{"id":"vault_intent","monitored":true,"chainValue":4.0,"chainValueZat":400000000,"valueDelta":2.0,"valueDeltaZat":200000000}],"#,
                r#""pq_by_scheme":["#,
                r#"{"pqscheme":1,"pqschemename":"SLH-DSA-SHA2-128s","monitored":true,"chainValue":3.0,"chainValueZat":300000000,"valueDelta":0.0,"valueDeltaZat":0},"#,
                r#"{"pqscheme":2,"pqschemename":"FN-DSA-512","monitored":true,"chainValue":2.0,"chainValueZat":200000000,"valueDelta":2.0,"valueDeltaZat":200000000}],"#,
                r#""vault_by_module":["#,
                r#"{"module":"YED","tag":"59454400","monitored":true,"chainValue":19.0,"chainValueZat":1900000000,"valueDelta":0.0,"valueDeltaZat":0}]}"#,
            )
        );
    }

    /// A block the index does not cover: `monitored: false` everywhere and no amounts, with
    /// every entry still present (ycash6 `Entry` without a value).
    #[test]
    fn an_uncovered_block_is_not_monitored() {
        let unmonitored = concat!(
            r#"{"monitored":false,"#,
            r#""transparent":{"monitored":false},"#,
            r#""pools":["#,
            r#"{"id":"transparent_ecc","monitored":false},"#,
            r#"{"id":"transparent_pq","monitored":false},"#,
            r#"{"id":"pq_channel","monitored":false},"#,
            r#"{"id":"vault","monitored":false},"#,
            r#"{"id":"vault_intent","monitored":false}],"#,
            r#""pq_by_scheme":["#,
            r#"{"pqscheme":1,"pqschemename":"SLH-DSA-SHA2-128s","monitored":false},"#,
            r#"{"pqscheme":2,"pqschemename":"FN-DSA-512","monitored":false}],"#,
            r#""vault_by_module":["#,
            r#"{"module":"YED","tag":"59454400","monitored":false}]}"#,
        );
        // The state does not have the block, or has it without a record.
        let no_record = BlockIndexInfo {
            pools: None,
            ..info()
        };
        for with_delta in [false, true] {
            assert_eq!(json(None, with_delta), unmonitored);
            assert_eq!(json(Some(&no_record), with_delta), unmonitored);
        }

        // A record without its parent's: the values are known, the change is not.
        let no_parent = BlockIndexInfo {
            parent_pools: None,
            ..info()
        };
        assert_eq!(json(Some(&no_parent), true), json(Some(&info()), false));
    }

    /// The object reads back: clients of this crate deserialize what the node serializes.
    #[test]
    fn the_object_round_trips() {
        for (info, with_delta) in [(Some(info()), true), (Some(info()), false), (None, true)] {
            let object = TransparentPoolsInfo::new(info.as_ref(), with_delta);
            let text = serde_json::to_string(&object).unwrap();
            assert_eq!(
                serde_json::from_str::<TransparentPoolsInfo>(&text).unwrap(),
                object
            );
        }
    }
}
