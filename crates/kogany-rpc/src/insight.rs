//! `getaddressmempool`, ycashd's insight-explorer mempool read (S5 parity, `wallet_pq_address`).
//!
//! Copyright (c) 2026 The Ycash developers. Distributed under the MIT software license.
//!
//! ycash6 `src/rpc/misc.cpp` `getaddressmempool`: every mempool delta of the named transparent
//! addresses (an output paying one, `satoshis > 0`; an input spending one, `satoshis < 0` with
//! `prevtxid`/`prevout`), sorted by the time the transaction entered the mempool. Zakura serves
//! the other insight reads (`getaddressbalance`, `getaddresstxids`, `getaddressutxos`) from its
//! address index; kogany has no mempool address index, so this one scans the mempool's verified
//! set (`crate::mempool`), whose entries carry the outputs their inputs spend. Like Zakura's
//! `getaddressbalance`, it is always on (ycashd needs `-insightexplorer` or `-lightwalletd`).

use std::collections::HashMap;

use serde_json::{json, Value};
use zakura_chain::{parameters::Network, transaction::VerifiedUnminedTx, transparent::Address};
use zakura_rpc::server::jsonrpc::{ErrorObject, RpcResult};

crate::kogany_rpc_trait! {
    /// ycashd's insight-explorer reads that Zakura does not serve.
    pub trait InsightRpc {
        /// Every mempool delta of `{"addresses": [...]}` (or one address string).
        #[method(name = "getaddressmempool", access = Unauthenticated)]
        async fn getaddressmempool(&self, addresses: Value) -> RpcResult<Vec<Value>>;
    }
    dispatch = InsightRpcDispatch;
}

/// [`InsightRpc`] on a network.
#[derive(Clone, Debug)]
pub struct InsightRpcImpl {
    network: Network,
}

impl InsightRpcImpl {
    /// The insight reads on `network`.
    pub fn new(network: Network) -> Self {
        Self { network }
    }

    /// These methods as a server extension.
    pub fn into_extension(self) -> zakura_rpc::server::kogany_extension::RpcExtension {
        InsightRpcDispatch(self).into_extension()
    }
}

/// ycashd's `RPC_INVALID_ADDRESS_OR_KEY` "Invalid address" (`getAddressesFromParams`).
fn invalid_address() -> ErrorObject {
    ErrorObject::new(-5, "Invalid address")
}

/// `getAddressesFromParams`: one address string, or `{"addresses": [string, ...]}`; each named
/// address with the text the caller gave (ycashd's `AddressNames`, the form the delta answers).
pub fn parse_addresses(params: &Value) -> RpcResult<Vec<(Address, String)>> {
    let texts: Vec<&str> = match params {
        Value::String(text) => vec![text.as_str()],
        Value::Object(object) => match object.get("addresses") {
            Some(Value::Array(items)) => items
                .iter()
                .map(|item| item.as_str().ok_or_else(invalid_address))
                .collect::<RpcResult<_>>()?,
            _ => return Err(invalid_address()),
        },
        _ => return Err(invalid_address()),
    };
    texts
        .into_iter()
        .map(|text| {
            text.parse::<Address>()
                .map(|address| (address, text.to_owned()))
                .map_err(|_| invalid_address())
        })
        .collect()
}

/// The deltas of `addresses` in `transactions` (`mempool.getAddressIndex` then the sort by entry
/// time): ycashd's key order (address, txid, index, spending) within one entry time.
pub fn address_deltas(
    network: &Network,
    transactions: &[VerifiedUnminedTx],
    addresses: &[(Address, String)],
) -> Vec<Value> {
    let mut names: HashMap<Address, &str> = HashMap::new();
    for (address, text) in addresses {
        names.entry(*address).or_insert(text.as_str());
    }
    // (time, address text, txid, index, spending, delta)
    let mut rows: Vec<(i64, String, [u8; 32], u32, bool, Value)> = Vec::new();
    for tx in transactions {
        let time = tx.time.map_or(0, |t| t.timestamp());
        let transaction = tx.transaction.transaction();
        let txid = tx.transaction.id().mined_id();
        for (index, input) in transaction.inputs().iter().enumerate() {
            let Some(outpoint) = input.outpoint() else {
                continue;
            };
            let Some(spent) = tx.spent_outputs.get(index) else {
                continue;
            };
            let Some(name) = spent.address(network).and_then(|a| names.get(&a)) else {
                continue;
            };
            let index = u32::try_from(index).unwrap_or(u32::MAX);
            rows.push((
                time,
                (*name).to_owned(),
                txid.0,
                index,
                true,
                json!({
                    "address": name,
                    "txid": txid.to_string(),
                    "index": index,
                    "satoshis": -i64::from(spent.value),
                    "timestamp": time,
                    "prevtxid": outpoint.hash.to_string(),
                    "prevout": outpoint.index,
                }),
            ));
        }
        for (index, output) in transaction.outputs().iter().enumerate() {
            let Some(name) = output.address(network).and_then(|a| names.get(&a)) else {
                continue;
            };
            let index = u32::try_from(index).unwrap_or(u32::MAX);
            rows.push((
                time,
                (*name).to_owned(),
                txid.0,
                index,
                false,
                json!({
                    "address": name,
                    "txid": txid.to_string(),
                    "index": index,
                    "satoshis": i64::from(output.value),
                    "timestamp": time,
                }),
            ));
        }
    }
    rows.sort_by(|a, b| (a.0, &a.1, a.2, a.3, a.4).cmp(&(b.0, &b.1, b.2, b.3, b.4)));
    rows.into_iter().map(|row| row.5).collect()
}

#[async_trait::async_trait]
impl InsightRpc for InsightRpcImpl {
    async fn getaddressmempool(&self, addresses: Value) -> RpcResult<Vec<Value>> {
        let addresses = parse_addresses(&addresses)?;
        Ok(address_deltas(
            &self.network,
            &crate::mempool::transactions().await,
            &addresses,
        ))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use zakura_chain::{
        amount::Amount,
        block::Height,
        parameters::NetworkKind,
        transaction::{self, LockTime, Transaction, UnminedTx},
        transparent::{Input, OutPoint, Output, Script},
    };

    use super::*;

    fn spend(prev: OutPoint, outputs: Vec<Output>) -> Transaction {
        Transaction::V4 {
            inputs: vec![Input::PrevOut {
                outpoint: prev,
                unlock_script: Script::new(&[0x51]),
                sequence: u32::MAX,
            }],
            outputs,
            lock_time: LockTime::unlocked(),
            expiry_height: Height(0),
            joinsplit_data: None,
            sapling_shielded_data: None,
        }
    }

    fn verified(tx: Transaction, spent: Vec<Output>, time: i64) -> VerifiedUnminedTx {
        let mut v = VerifiedUnminedTx::new(
            UnminedTx::from(tx),
            Amount::try_from(10_000).expect("a fee"),
            0,
            0,
            Arc::new(spent),
        )
        .expect("verified");
        v.time = chrono::DateTime::from_timestamp(time, 0);
        v
    }

    /// One mempool transaction spends A's coin and pays B and A: B's output delta, and A's
    /// input and output deltas with `prevtxid`/`prevout`, in ycashd's shape and order; the
    /// mempool's spender of A's coin is that transaction (F-S5-5).
    #[test]
    fn address_deltas_and_the_spender() {
        let network = Network::new_regtest(Default::default());
        let kind = NetworkKind::Regtest;
        let a = Address::from_pub_key_hash(kind, [1; 20]);
        let b = Address::from_pub_key_hash(kind, [2; 20]);
        let prev = OutPoint {
            hash: transaction::Hash([9; 32]),
            index: 3,
        };
        let coin = Output::new(Amount::try_from(500_000).expect("amount"), a.script());
        let tx = spend(
            prev,
            vec![
                Output::new(Amount::try_from(200_000).expect("amount"), b.script()),
                Output::new(Amount::try_from(290_000).expect("amount"), a.script()),
            ],
        );
        let txid = tx.hash();
        let pool = vec![verified(tx, vec![coin], 1_700_000_000)];

        assert_eq!(crate::mempool::spender_in(&pool, &prev), Some(txid));
        let other = OutPoint {
            hash: transaction::Hash([9; 32]),
            index: 4,
        };
        assert_eq!(crate::mempool::spender_in(&pool, &other), None);

        let names = parse_addresses(&json!({ "addresses": [b.to_string(), a.to_string()] }))
            .expect("addresses");
        let deltas = address_deltas(&network, &pool, &names);
        let a_text = a.to_string();
        let b_text = b.to_string();
        let (first, second) = if a_text < b_text {
            (&a_text, &b_text)
        } else {
            (&b_text, &a_text)
        };
        let rows: Vec<(String, u64, i64)> = deltas
            .iter()
            .map(|d| {
                (
                    d["address"].as_str().unwrap_or_default().to_owned(),
                    d["index"].as_u64().unwrap_or(99),
                    d["satoshis"].as_i64().unwrap_or_default(),
                )
            })
            .collect();
        let mut want = vec![
            (a_text.clone(), 0, -500_000),
            (a_text.clone(), 1, 290_000),
            (b_text.clone(), 0, 200_000),
        ];
        want.sort_by(|x, y| (&x.0, x.1).cmp(&(&y.0, y.1)));
        assert_eq!(rows, want);
        assert!(first < second);
        let input = deltas
            .iter()
            .find(|d| d["satoshis"].as_i64() == Some(-500_000))
            .expect("the input delta");
        assert_eq!(input["prevtxid"], json!(prev.hash.to_string()));
        assert_eq!(input["prevout"], json!(3));
        assert_eq!(input["txid"], json!(txid.to_string()));
        assert_eq!(input["timestamp"], json!(1_700_000_000));
        assert!(deltas
            .iter()
            .filter(|d| d["satoshis"].as_i64() > Some(0))
            .all(|d| d.get("prevtxid").is_none()));

        // One string is one address; anything else is ycashd's "Invalid address".
        assert_eq!(
            parse_addresses(&json!(a_text)).expect("one address").len(),
            1
        );
        for bad in [json!(1), json!({ "addresses": ["nope"] }), json!({})] {
            let e = parse_addresses(&bad).expect_err("invalid");
            assert_eq!((e.code(), e.message()), (-5, "Invalid address"));
        }
        // Nothing named, nothing answered.
        assert!(address_deltas(&network, &pool, &[]).is_empty());
    }
}
