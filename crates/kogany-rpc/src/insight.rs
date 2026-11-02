//! `getaddressmempool` and `getaddressdeltas`, ycashd's insight-explorer reads that Zakura does
//! not serve (S5 parity, `wallet_pq_address`).
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
//!
//! `getaddressdeltas` (ycash6 `src/rpc/misc.cpp`): every confirmed delta of the named addresses
//! in a height range, per address in the order named, then by height, position in the block,
//! txid, index and spending. It reads Zakura's address transaction index
//! (`ReadRequest::TransactionIdsByAddresses`) and each transaction (and, for an input, the
//! transaction whose output it spends) from the read state: no index is added.

use std::collections::{HashMap, HashSet};

use serde_json::{json, Value};
use tower::{util::BoxCloneSyncService, ServiceExt};
use zakura_chain::{
    block::Height, parameters::Network, transaction::VerifiedUnminedTx, transparent::Address,
};
use zakura_rpc::server::jsonrpc::{ErrorObject, RpcResult};
use zakura_state::{BoxError, ReadRequest, ReadResponse};

/// The read state service the insight reads use.
pub type ReadStateService = BoxCloneSyncService<ReadRequest, ReadResponse, BoxError>;

crate::kogany_rpc_trait! {
    /// ycashd's insight-explorer reads that Zakura does not serve.
    pub trait InsightRpc {
        /// Every mempool delta of `{"addresses": [...]}` (or one address string).
        #[method(name = "getaddressmempool", access = Unauthenticated)]
        async fn getaddressmempool(&self, addresses: Value) -> RpcResult<Vec<Value>>;

        /// Every confirmed delta of `{"addresses": [...], "start", "end", "chainInfo"}` (or one
        /// address string).
        #[method(name = "getaddressdeltas", access = Unauthenticated)]
        async fn getaddressdeltas(&self, request: Value) -> RpcResult<Value>;
    }
    dispatch = InsightRpcDispatch;
}

/// [`InsightRpc`] on a network.
#[derive(Clone)]
pub struct InsightRpcImpl {
    network: Network,
    read_state: Option<ReadStateService>,
}

impl InsightRpcImpl {
    /// The insight reads on `network` over `read_state` (`None`: the confirmed reads answer
    /// nothing).
    pub fn new(network: Network, read_state: Option<ReadStateService>) -> Self {
        Self {
            network,
            read_state,
        }
    }

    async fn read(&self, request: ReadRequest) -> RpcResult<ReadResponse> {
        let Some(state) = self.read_state.clone() else {
            return Err(ErrorObject::new(-32603, "no chain state"));
        };
        state
            .oneshot(request)
            .await
            .map_err(|e| ErrorObject::new(-32603, e.to_string()))
    }

    async fn tip_height(&self) -> RpcResult<i64> {
        match self.read(ReadRequest::Tip).await? {
            ReadResponse::Tip(tip) => Ok(tip.map_or(-1, |(h, _)| i64::from(h.0))),
            _ => Err(ErrorObject::new(-32603, "unexpected tip response")),
        }
    }

    async fn transaction(
        &self,
        hash: zakura_chain::transaction::Hash,
    ) -> RpcResult<Option<std::sync::Arc<zakura_chain::transaction::Transaction>>> {
        match self.read(ReadRequest::Transaction(hash)).await? {
            ReadResponse::Transaction(tx) => Ok(tx.map(|m| m.tx)),
            _ => Err(ErrorObject::new(-32603, "unexpected transaction response")),
        }
    }

    async fn block_hash(&self, height: i64) -> RpcResult<String> {
        let height = u32::try_from(height).map_err(|_| invalid_range("out of range"))?;
        match self
            .read(ReadRequest::BestChainBlockHash(Height(height)))
            .await?
        {
            ReadResponse::BlockHash(Some(hash)) => Ok(hash.to_string()),
            _ => Err(invalid_range("Start or end is outside chain range")),
        }
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

/// ycashd's `RPC_INVALID_ADDRESS_OR_KEY` with `text` (`getHeightRange`).
fn invalid_range(text: &str) -> ErrorObject {
    ErrorObject::new(-5, text.to_owned())
}

/// `getHeightRange`: `start`/`end` of the request object (0 when absent), clamped to the tip;
/// `end` 0 is the tip.
pub fn height_range(params: &Value, tip: i64) -> RpcResult<(i64, i64)> {
    let field = |name: &str, negative: &str| -> RpcResult<i64> {
        match params.get(name) {
            None | Some(Value::Null) => Ok(0),
            Some(v) => {
                let n = v
                    .as_i64()
                    .ok_or_else(|| ErrorObject::new(-1, "JSON value is not an integer as expected"))?;
                if n < 0 {
                    Err(invalid_range(negative))
                } else {
                    Ok(n)
                }
            }
        }
    };
    let (mut start, mut end) = if params.is_object() {
        (
            field("start", "Start height must be nonnegative")?,
            field("end", "End height must be nonnegative")?,
        )
    } else {
        (0, 0)
    };
    if start > tip {
        start = tip;
    }
    if end == 0 || end > tip {
        end = tip;
    }
    if start > end {
        return Err(invalid_range(
            "End value is expected to be greater than or equal to start",
        ));
    }
    Ok((start, end))
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

    async fn getaddressdeltas(&self, request: Value) -> RpcResult<Value> {
        let tip = self.tip_height().await?;
        let (start, end) = height_range(&request, tip)?;
        let addresses = parse_addresses(&request)?;
        let include_chain_info = match request.get("chainInfo") {
            None | Some(Value::Null) => false,
            Some(v) => v
                .as_bool()
                .ok_or_else(|| ErrorObject::new(-1, "JSON value is not a boolean as expected"))?,
        };
        let mut deltas = Vec::new();
        let mut seen = HashSet::new();
        for (address, name) in &addresses {
            if !seen.insert(*address) || tip < 0 {
                continue;
            }
            let range = Height(u32::try_from(start).unwrap_or(0))
                ..=Height(u32::try_from(end).unwrap_or(0));
            let ReadResponse::AddressesTransactionIds(txids) = self
                .read(ReadRequest::TransactionIdsByAddresses {
                    addresses: HashSet::from([*address]),
                    height_range: range,
                })
                .await?
            else {
                return Err(ErrorObject::new(-32603, "unexpected address index response"));
            };
            // (height, blockindex, txid, index, spending, delta)
            let mut rows: Vec<(u32, u16, [u8; 32], u32, bool, Value)> = Vec::new();
            for (location, txid) in txids {
                let Some(tx) = self.transaction(txid).await? else {
                    continue;
                };
                let row = |index: usize, satoshis: i64| {
                    json!({
                        "address": name,
                        "blockindex": location.index.index(),
                        "height": location.height.0,
                        "index": index,
                        "satoshis": satoshis,
                        "txid": txid.to_string(),
                    })
                };
                for (index, output) in tx.outputs().iter().enumerate() {
                    if output.address(&self.network).as_ref() == Some(address) {
                        let i = u32::try_from(index).unwrap_or(u32::MAX);
                        rows.push((
                            location.height.0,
                            location.index.index(),
                            txid.0,
                            i,
                            false,
                            row(index, i64::from(output.value)),
                        ));
                    }
                }
                for (index, input) in tx.inputs().iter().enumerate() {
                    let Some(outpoint) = input.outpoint() else {
                        continue;
                    };
                    let Some(prev) = self.transaction(outpoint.hash).await? else {
                        continue;
                    };
                    let Some(spent) = prev.outputs().get(outpoint.index as usize) else {
                        continue;
                    };
                    if spent.address(&self.network).as_ref() == Some(address) {
                        let i = u32::try_from(index).unwrap_or(u32::MAX);
                        rows.push((
                            location.height.0,
                            location.index.index(),
                            txid.0,
                            i,
                            true,
                            row(index, -i64::from(spent.value)),
                        ));
                    }
                }
            }
            rows.sort_by(|a, b| (a.0, a.1, a.2, a.3, a.4).cmp(&(b.0, b.1, b.2, b.3, b.4)));
            deltas.extend(rows.into_iter().map(|row| row.5));
        }
        if !(include_chain_info && start > 0 && end > 0) {
            return Ok(Value::Array(deltas));
        }
        if start > tip || end > tip {
            return Err(invalid_range("Start or end is outside chain range"));
        }
        Ok(json!({
            "deltas": deltas,
            "start": { "hash": self.block_hash(start).await?, "height": start },
            "end": { "hash": self.block_hash(end).await?, "height": end },
        }))
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

    /// `getHeightRange`: absent or 0 bounds are the whole chain, a start past the tip is the tip,
    /// and ycashd's -5 refusals.
    #[test]
    fn height_range_is_ycashds() {
        assert_eq!(height_range(&json!("addr"), 50).expect("ok"), (0, 50));
        assert_eq!(height_range(&json!({}), 50).expect("ok"), (0, 50));
        assert_eq!(height_range(&json!({"start": 10, "end": 20}), 50).expect("ok"), (10, 20));
        assert_eq!(height_range(&json!({"start": 60}), 50).expect("ok"), (50, 50));
        assert_eq!(height_range(&json!({"end": 99}), 50).expect("ok"), (0, 50));
        for (bad, text) in [
            (json!({"start": -1}), "Start height must be nonnegative"),
            (json!({"end": -1}), "End height must be nonnegative"),
            (
                json!({"start": 30, "end": 20}),
                "End value is expected to be greater than or equal to start",
            ),
        ] {
            let e = height_range(&bad, 50).expect_err("refused");
            assert_eq!((e.code(), e.message()), (-5, text));
        }
    }
}
