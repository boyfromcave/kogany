//! `getcoinbasetemplatefor`: a coinbase for a payout address and a block template the caller
//! names (beta3 item 3; the contract is `docs/plans/beta3/getcoinbasetemplatefor.md` of the
//! Yellowback workspace, and `ycash6 src/rpc/mining.cpp` `getcoinbasetemplatefor` its C++ form).
//!
//! Copyright (c) 2026 The Ycash developers. Distributed under the MIT software license.
//!
//! A pool keeps the stock `getblocktemplate` reply and asks for a coinbase that pays one miner.
//! The caller names its template by the previous block hash and the ids of the template's
//! transactions; the node derives the amount itself (the block subsidy, less the
//! development-fund output its own coinbase carries, plus the mempool fee of every named
//! transaction). There is no amount argument, and nothing is kept between calls.
//!
//! The coinbase is the one ycashd's call returns, field for field: version 4, lock time 0,
//! expiry height 0, the input script `<height> OP_0 <tag>`, `vout[0]` the payout (a transparent
//! or post-quantum script) followed by the fund output, or, for a Sapling address, only the fund
//! output and one Sapling output of the amount.

use std::{collections::HashSet, sync::Arc};

use serde_json::Value;
use tokio::sync::Semaphore;
use tower::{Service, ServiceExt};
use zcash_address::{unified, ConversionError, TryFromAddress, ZcashAddress};
use zcash_protocol::consensus::NetworkType;

use zakura_chain::{
    amount::{Amount, NegativeAllowed, NonNegative},
    block::{self, Height, MAX_BLOCK_BYTES},
    chain_tip::ChainTip,
    parameters::{subsidy::block_subsidy, ycash::ydf, Network, NetworkUpgrade},
    primitives::redjubjub::{Binding, Signature},
    sapling,
    serialization::{ZcashDeserialize, ZcashSerialize},
    transaction::{self, HashType, LockTime, Transaction},
    transparent,
    work::equihash::Solution,
};
use zakura_consensus::MAX_BLOCK_SIGOPS;
use zakura_node_services::mempool;
use zakura_script::Sigops;

use super::{
    check_synced_to_tip, fetch_mempool_transactions,
    ycash::{pq_sigops, unhealthy_error, YcashMining, YellowbackMiner},
};
use crate::{
    methods::types::{
        transaction::sapling_coinbase::{
            prove_coinbase_output, ProvenCoinbaseBundle, SaplingOutputProver, NOT_LOADED,
        },
        ycash::{decode_pq_address, is_pre_nu5, ydf_output},
    },
    server::jsonrpc::{ErrorObject, RpcResult},
};

#[cfg(test)]
mod tests;

/// The most transaction ids a request may name (the contract's row 4).
pub const MAX_TXIDS: usize = 50_000;

/// The most Sapling proofs this node makes at once for this call. The contract leaves the cap on
/// parallel requests to the pool; this only keeps a burst from taking every blocking thread.
const MAX_PROOFS_IN_FLIGHT: usize = 4;

static PROOF_SLOTS: Semaphore = Semaphore::const_new(MAX_PROOFS_IN_FLIGHT);

// ---- errors (the contract's table; codes and strings are identical on the three node lines) ----

/// `RPC_INVALID_PARAMETER`.
const INVALID_PARAMETER: i32 = -8;
/// `RPC_INVALID_ADDRESS_OR_KEY`.
const INVALID_ADDRESS_OR_KEY: i32 = -5;
/// `RPC_MISC_ERROR`.
const MISC_ERROR: i32 = -1;
/// `RPC_CLIENT_IN_INITIAL_DOWNLOAD`.
const IN_INITIAL_DOWNLOAD: i32 = -10;
/// `RPC_INTERNAL_ERROR`.
const INTERNAL_ERROR: i32 = -32603;

fn bad_template() -> ErrorObject {
    ErrorObject::new(
        INVALID_PARAMETER,
        "template must be an object with exactly the keys previousblockhash and txids",
    )
}

fn invalid_address() -> ErrorObject {
    ErrorObject::new(INVALID_ADDRESS_OR_KEY, "Invalid address")
}

fn stale_tip() -> ErrorObject {
    ErrorObject::new(
        MISC_ERROR,
        "template-stale: previousblockhash is not the tip",
    )
}

fn stale_transaction(txid: transaction::Hash) -> ErrorObject {
    ErrorObject::new(
        MISC_ERROR,
        format!("template-stale: transaction is not in the mempool: {txid}"),
    )
}

fn construction_failed(detail: impl std::fmt::Display) -> ErrorObject {
    ErrorObject::new(
        INTERNAL_ERROR,
        format!("coinbase construction failed: {detail}"),
    )
}

// ---- the request ----

/// The template reference of a request: nothing but the previous block hash and the ids of the
/// template's transactions, in the template's order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TemplateReference {
    /// `previousblockhash` of the caller's `getblocktemplate` reply.
    pub previous_block_hash: block::Hash,
    /// The `hash` of every entry of that reply's `transactions`.
    pub txids: Vec<transaction::Hash>,
}

/// True for a JSON string of exactly 64 hex characters, either case (ycashd's `IsHash64`).
fn hash64(value: &Value) -> Option<&str> {
    value
        .as_str()
        .filter(|text| text.len() == 64 && text.bytes().all(|byte| byte.is_ascii_hexdigit()))
}

impl TemplateReference {
    /// Parses parameter 1 of the call. Any key but the two is refused, so no amount, fee or
    /// coinbase value can ever be passed in (rows 1 to 4 of the contract, in that order).
    pub fn parse(template: &Value) -> RpcResult<Self> {
        let object = template.as_object().ok_or_else(bad_template)?;
        let (Some(previous), Some(txids), 2) = (
            object.get("previousblockhash"),
            object.get("txids"),
            object.len(),
        ) else {
            return Err(bad_template());
        };

        let previous_block_hash = hash64(previous)
            .and_then(|text| text.parse::<block::Hash>().ok())
            .ok_or_else(|| {
                ErrorObject::new(
                    INVALID_PARAMETER,
                    "previousblockhash must be 64 hex characters",
                )
            })?;

        let bad_txids = || {
            ErrorObject::new(
                INVALID_PARAMETER,
                "txids must be an array of strings of 64 hex characters",
            )
        };
        let txids = txids.as_array().ok_or_else(bad_txids)?;
        if !txids.iter().all(|txid| hash64(txid).is_some()) {
            return Err(bad_txids());
        }
        if txids.len() > MAX_TXIDS {
            return Err(ErrorObject::new(
                INVALID_PARAMETER,
                format!("txids has more than {MAX_TXIDS} entries"),
            ));
        }
        let txids = txids
            .iter()
            .map(|txid| {
                hash64(txid)
                    .and_then(|text| text.parse::<transaction::Hash>().ok())
                    .ok_or_else(bad_txids)
            })
            .collect::<RpcResult<Vec<_>>>()?;

        Ok(Self {
            previous_block_hash,
            txids,
        })
    }
}

/// A payout address of the call: where the coinbase pays the amount.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Payout {
    /// A transparent P2PKH address: `vout[0]` pays this script.
    P2pkh(transparent::Script),
    /// A transparent P2SH address: `vout[0]` pays this script.
    P2sh(transparent::Script),
    /// A plain-YEC post-quantum address: `vout[0]` pays this 35-byte script
    /// (`<32-byte key hash> <scheme> OP_CHECKPQSIG`).
    Pq(transparent::Script),
    /// A Sapling address: one Sapling output.
    Sapling(sapling_crypto::PaymentAddress),
}

/// What an address of this network decodes to, the kinds the call refuses by name included.
enum DecodedAddress {
    P2pkh([u8; 20]),
    P2sh([u8; 20]),
    Sapling(sapling_crypto::PaymentAddress),
    /// A valid address of a kind no coinbase pays, as `z_validateaddress` names it.
    Refused(&'static str),
}

impl TryFromAddress for DecodedAddress {
    type Error = &'static str;

    fn try_from_sprout(
        _net: NetworkType,
        _data: [u8; 64],
    ) -> Result<Self, ConversionError<Self::Error>> {
        Ok(Self::Refused("sprout"))
    }

    fn try_from_sapling(
        _net: NetworkType,
        data: [u8; 43],
    ) -> Result<Self, ConversionError<Self::Error>> {
        sapling_crypto::PaymentAddress::from_bytes(&data)
            .map(Self::Sapling)
            .ok_or(ConversionError::User("Invalid Sapling payment address"))
    }

    fn try_from_unified(
        _net: NetworkType,
        _data: unified::Address,
    ) -> Result<Self, ConversionError<Self::Error>> {
        Ok(Self::Refused("unified"))
    }

    fn try_from_transparent_p2pkh(
        _net: NetworkType,
        data: [u8; 20],
    ) -> Result<Self, ConversionError<Self::Error>> {
        Ok(Self::P2pkh(data))
    }

    fn try_from_transparent_p2sh(
        _net: NetworkType,
        data: [u8; 20],
    ) -> Result<Self, ConversionError<Self::Error>> {
        Ok(Self::P2sh(data))
    }
}

impl Payout {
    /// Decodes parameter 0 of the call for `network` (rows 6 and 7 of the contract): a
    /// transparent P2PKH or P2SH address, a Sapling address or a plain-YEC post-quantum address
    /// in its scheme-visible form. A Sprout or unified address is refused by name; anything
    /// else, a YED address and the old post-quantum form among it, is not an address.
    pub fn parse(network: &Network, address: &Value) -> RpcResult<Self> {
        let text = address.as_str().ok_or_else(invalid_address)?;

        if let Some(pq) = decode_pq_address(network, text) {
            let script = hex::decode(pq.script_pub_key).map_err(|_| invalid_address())?;
            return Ok(Self::Pq(transparent::Script::new(&script)));
        }

        let decoded = text
            .parse::<ZcashAddress>()
            .ok()
            .and_then(|address| {
                address
                    .convert_if_network::<DecodedAddress>(
                        zcash_protocol::consensus::Parameters::network_type(network),
                    )
                    .ok()
            })
            .ok_or_else(invalid_address)?;

        let kind = network.t_addr_kind();
        match decoded {
            DecodedAddress::P2pkh(hash) => Ok(Self::P2pkh(
                transparent::Address::from_pub_key_hash(kind, hash).script(),
            )),
            DecodedAddress::P2sh(hash) => Ok(Self::P2sh(
                transparent::Address::from_script_hash(kind, hash).script(),
            )),
            DecodedAddress::Sapling(address) => Ok(Self::Sapling(address)),
            DecodedAddress::Refused(kind) => Err(ErrorObject::new(
                INVALID_ADDRESS_OR_KEY,
                format!("Address type cannot receive a coinbase: {kind}"),
            )),
        }
    }

    /// The kind's name in the response, as `z_validateaddress` names it.
    pub fn address_type(&self) -> &'static str {
        match self {
            Self::P2pkh(_) => "p2pkh",
            Self::P2sh(_) => "p2sh",
            Self::Pq(_) => "pq",
            Self::Sapling(_) => "sapling",
        }
    }

    /// Row 8 of the contract: a post-quantum script is payable from the Vault upgrade on, a
    /// Sapling output in a coinbase from Heartwood on (ZIP 213).
    fn check_payable_at(&self, network: &Network, height: Height) -> RpcResult<()> {
        let payable = match self {
            Self::P2pkh(_) | Self::P2sh(_) => true,
            Self::Pq(_) => network.is_vault_active(height),
            Self::Sapling(_) => NetworkUpgrade::Heartwood
                .activation_height(network)
                .is_some_and(|activation| height >= activation),
        };
        if payable {
            Ok(())
        } else {
            Err(ErrorObject::new(
                INVALID_ADDRESS_OR_KEY,
                format!(
                    "Address type cannot receive a coinbase at height {}: {}",
                    height.0,
                    self.address_type()
                ),
            ))
        }
    }
}

// ---- the amount ----

/// The amounts of one coinbase, all derived by the node.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoinbaseAmounts {
    /// The block subsidy at the coinbase's height.
    pub subsidy: Amount<NonNegative>,
    /// The development-fund output this node's own coinbase carries at that height: its value
    /// and script, `None` when it carries none.
    pub fund: Option<(Amount<NonNegative>, transparent::Script)>,
    /// `"mandated"`, `"optional"` or `"none"`: why the fund output is there.
    pub fund_rule: &'static str,
    /// The sum of the fees of the named transactions.
    pub fees: Amount<NonNegative>,
    /// What the address receives: `subsidy - fund + fees`.
    pub amount: Amount<NonNegative>,
}

impl CoinbaseAmounts {
    /// The amounts of a coinbase at `height` whose block carries transactions paying `fees`, on
    /// a node whose `mining.ydf` is `ydf_percentage`.
    ///
    /// The fund output is [`ydf_output`]'s, the one this node's own `getblocktemplate` coinbase
    /// carries: the mandated 5 % of the subsidy below the mandate's end, the node's optional
    /// share from it on. It is a share of the subsidy, never of the fees.
    pub fn derive(
        network: &Network,
        height: Height,
        fees: Amount<NonNegative>,
        ydf_percentage: u64,
    ) -> Result<Self, String> {
        let subsidy = block_subsidy(height, network, None).map_err(|error| error.to_string())?;
        let fund = ydf_output(network, height, subsidy, ydf_percentage)
            .map(|(value, address)| (value, address.script()));
        let fund_rule = match &fund {
            None => "none",
            Some(_) if height < ydf::ydf_mandate_end_height(network) => "mandated",
            Some(_) => "optional",
        };
        let fund_value = fund.as_ref().map_or(Amount::zero(), |(value, _)| *value);
        let amount = ((subsidy - fund_value).map_err(|error| error.to_string())? + fees)
            .map_err(|error| error.to_string())?;
        Ok(Self {
            subsidy,
            fund,
            fund_rule,
            fees,
            amount,
        })
    }

    /// The value of the fund output, 0 without one.
    pub fn fund_value(&self) -> Amount<NonNegative> {
        self.fund
            .as_ref()
            .map_or(Amount::zero(), |(value, _)| *value)
    }
}

// ---- the coinbase ----

/// The input of the coinbase at `height`: `<height> OP_0 <flags>`, the script ycashd's own
/// coinbase and its call carry (`ycash6 src/miner.cpp`), and kogany's own coinbase without
/// `extra_coinbase_data`.
fn coinbase_input(height: Height, flags: &[u8]) -> transparent::Input {
    // OP_0, where ycashd's internal miner puts its extranonce.
    let mut data = vec![0x00];
    data.extend_from_slice(flags);
    transparent::Input::Coinbase {
        height,
        data,
        sequence: u32::MAX,
    }
}

/// The coinbase of the call, before any Sapling part: version 4, lock time 0, expiry height 0.
fn transparent_coinbase(
    height: Height,
    flags: &[u8],
    outputs: Vec<transparent::Output>,
) -> Transaction {
    Transaction::V4 {
        inputs: vec![coinbase_input(height, flags)],
        outputs,
        lock_time: LockTime::unlocked(),
        expiry_height: Height(0),
        joinsplit_data: None,
        sapling_shielded_data: None,
    }
}

/// The 948 bytes of a v4 output description.
fn output_description_v4(bundle: &ProvenCoinbaseBundle) -> Result<Vec<u8>, String> {
    let [output] = bundle.shielded_outputs() else {
        return Err("Sapling bundle: not exactly one output".to_string());
    };
    let mut bytes = Vec::with_capacity(948);
    bytes.extend_from_slice(&output.cv().to_bytes());
    bytes.extend_from_slice(&output.cmu().to_bytes());
    bytes.extend_from_slice(output.ephemeral_key().as_ref());
    bytes.extend_from_slice(output.enc_ciphertext());
    bytes.extend_from_slice(output.out_ciphertext());
    bytes.extend_from_slice(output.zkproof());
    Ok(bytes)
}

/// Builds the coinbase at `height` that pays `amounts.amount` to `payout` (§5 of the contract).
///
/// For a Sapling payout this proves the output and signs the bundle: call it off the async
/// worker threads. Without `prover` a Sapling payout fails with [`NOT_LOADED`]; the transparent
/// and post-quantum kinds need no prover.
pub fn build_coinbase(
    network: &Network,
    height: Height,
    payout: &Payout,
    amounts: &CoinbaseAmounts,
    flags: &[u8],
    prover: Option<&SaplingOutputProver>,
) -> Result<Transaction, String> {
    let fund_output = amounts
        .fund
        .as_ref()
        .map(|(value, script)| transparent::Output::new(*value, script.clone()));

    let to = match payout {
        Payout::P2pkh(script) | Payout::P2sh(script) | Payout::Pq(script) => {
            let outputs = std::iter::once(transparent::Output::new(amounts.amount, script.clone()))
                .chain(fund_output)
                .collect();
            return Ok(transparent_coinbase(height, flags, outputs));
        }
        Payout::Sapling(to) => *to,
    };

    let prover = prover.ok_or_else(|| NOT_LOADED.to_string())?;
    let value = u64::try_from(i64::from(amounts.amount)).map_err(|error| error.to_string())?;
    let bundle = prove_coinbase_output(network, height, prover, to, value)?;

    let output = sapling::output::OutputInTransactionV4::zcash_deserialize(
        output_description_v4(&bundle)?.as_slice(),
    )
    .map_err(|error| format!("Sapling output: {error}"))?
    .into_output();
    let value_balance = Amount::<NegativeAllowed>::try_from(-i64::from(amounts.amount))
        .map_err(|error| error.to_string())?;
    let shielded_data = |binding_sig| sapling::ShieldedData {
        value_balance,
        transfers: sapling::TransferData::JustOutputs {
            outputs: vec![output.clone()]
                .try_into()
                .expect("one output is at least one"),
        },
        binding_sig,
    };

    // The binding signature signs the ZIP 243 hash of the transaction, which covers everything
    // but the input script and the signature itself.
    let mut tx = transparent_coinbase(height, flags, fund_output.into_iter().collect());
    let Transaction::V4 {
        sapling_shielded_data,
        ..
    } = &mut tx
    else {
        unreachable!("transparent_coinbase builds a v4 transaction");
    };
    *sapling_shielded_data = Some(Box::new(shielded_data(Signature::<Binding>::from(
        [0u8; 64],
    ))));
    let sighash = tx
        .sighasher_on(
            network,
            NetworkUpgrade::current(network, height),
            Arc::new(Vec::new()),
        )
        .map_err(|error| format!("signature hash: {error}"))?
        .sighash(HashType::ALL, None);

    let signed = bundle
        .apply_signatures(rand_10::rng(), sighash.0, &[])
        .map_err(|error| format!("binding signature: {error}"))?;
    let Transaction::V4 {
        sapling_shielded_data,
        ..
    } = &mut tx
    else {
        unreachable!("transparent_coinbase builds a v4 transaction");
    };
    *sapling_shielded_data = Some(Box::new(shielded_data(signed.authorization().binding_sig)));
    Ok(tx)
}

/// The total a coinbase pays out: its transparent outputs minus its Sapling value balance.
fn total_output(tx: &Transaction) -> Option<i64> {
    let transparent = tx.outputs().iter().try_fold(0i64, |sum, output| {
        sum.checked_add(i64::from(output.value()))
    })?;
    transparent.checked_sub(i64::from(tx.sapling_value_balance().sapling_amount()))
}

// ---- the limits ----

/// The serialized size of a block header of `network` above the Ycash upgrade: 140 bytes and
/// the Equihash solution with its length prefix.
fn header_size(network: &Network) -> u64 {
    let solution = Solution::for_proposal_for_network(network)
        .zcash_serialize_to_vec()
        .map_or(0, |bytes| bytes.len());
    // A header is far smaller than `u64::MAX`.
    140 + solution as u64
}

/// The size of the compact-size encoding of `n`.
fn compact_size_len(n: usize) -> u64 {
    match n {
        0..=252 => 1,
        253..=0xffff => 3,
        _ => 5,
    }
}

/// Row 12 of the contract: the block of a header, `coinbase` and the named transactions
/// (`txs_size` bytes and `txs_sigops` signature operations in `tx_count` transactions) must
/// respect the block size and signature-operation limits.
fn check_fits(
    network: &Network,
    coinbase_size: usize,
    coinbase_sigops: u32,
    tx_count: usize,
    txs_size: u64,
    txs_sigops: u64,
) -> RpcResult<()> {
    let block_size = header_size(network)
        .saturating_add(compact_size_len(tx_count.saturating_add(1)))
        // A coinbase is far smaller than `u64::MAX`.
        .saturating_add(coinbase_size as u64)
        .saturating_add(txs_size);
    if block_size > MAX_BLOCK_BYTES {
        return Err(ErrorObject::new(
            MISC_ERROR,
            format!("coinbase-does-not-fit: block size {block_size} exceeds {MAX_BLOCK_BYTES}"),
        ));
    }
    let sigops = txs_sigops.saturating_add(u64::from(coinbase_sigops));
    if sigops > u64::from(MAX_BLOCK_SIGOPS) {
        return Err(ErrorObject::new(
            MISC_ERROR,
            format!("coinbase-does-not-fit: sigops {sigops} exceed {MAX_BLOCK_SIGOPS}"),
        ));
    }
    Ok(())
}

// ---- the response ----

/// The answer of `getcoinbasetemplatefor` (§3.2 of the contract). Amounts are in zatoshi.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CoinbaseTemplateFor {
    /// The serialized coinbase transaction, in hex.
    pub data: String,
    /// Its transaction id.
    pub hash: String,
    /// The height the coinbase is for.
    pub height: u32,
    /// Echo of the request.
    pub previousblockhash: String,
    /// `"p2pkh"`, `"p2sh"`, `"sapling"` or `"pq"`.
    pub addresstype: String,
    /// The block subsidy at `height`.
    pub subsidy: i64,
    /// The value of the coinbase's development-fund output, 0 without one.
    pub fund: i64,
    /// `"mandated"`, `"optional"` or `"none"`.
    pub fundrule: String,
    /// The sum of the fees of the named transactions.
    pub fees: i64,
    /// What the address receives: `subsidy - fund + fees`.
    pub amount: i64,
    /// The number of transaction ids the amount was derived from.
    pub txcount: usize,
    /// The input script bytes after `<height> OP_0`, in hex: the Yellowback tag push, or empty.
    pub flags: String,
    /// The coinbase's legacy signature-operation count.
    pub sigops: u32,
}

// ---- the call ----

/// What the call reads of the node.
pub struct CoinbaseForNode<Mempool, ReadState, Tip> {
    /// The node's network.
    pub network: Network,
    /// The mempool service.
    pub mempool: Mempool,
    /// The read state service.
    pub read_state: ReadState,
    /// The chain tip, for the same sync check `getblocktemplate` makes.
    pub latest_chain_tip: Tip,
    /// The Yellowback state of the miner: the index's health and the coinbase tag.
    pub mining: Arc<dyn YcashMining>,
    /// The node's `mining.ydf`, as its own coinbase reads it.
    pub ydf_percentage: u64,
    /// The Sapling output prover, `None` on a node without the parameters.
    pub sapling_output_prover: Option<SaplingOutputProver>,
}

/// The best tip of `read_state`.
async fn best_tip<ReadState>(read_state: ReadState) -> RpcResult<Option<(Height, block::Hash)>>
where
    ReadState: Service<
            zakura_state::ReadRequest,
            Response = zakura_state::ReadResponse,
            Error = zakura_state::BoxError,
        > + Send
        + 'static,
    ReadState::Future: Send,
{
    match read_state
        .oneshot(zakura_state::ReadRequest::Tip)
        .await
        .map_err(|error| ErrorObject::new(MISC_ERROR, error.to_string()))?
    {
        zakura_state::ReadResponse::Tip(tip) => Ok(tip),
        _ => unreachable!("unmatched response to a tip request"),
    }
}

/// `getcoinbasetemplatefor "address" {"previousblockhash": "<hex>", "txids": ["<hex>", ...]}`.
///
/// The checks run in the contract's order: the shape of the reference, the address, the
/// refusals of `getblocktemplate` (not synced, an unhealthy Yellowback index), then against the
/// tip and the mempool: a stale tip, an address kind not yet payable, a header that commits to
/// the coinbase, a transaction that is not in the mempool or is named twice; then the
/// construction, the block limits, and the tip once more. It reads the node and keeps nothing.
pub async fn get_coinbase_template_for<Mempool, ReadState, Tip>(
    node: CoinbaseForNode<Mempool, ReadState, Tip>,
    address: &Value,
    template: &Value,
) -> RpcResult<CoinbaseTemplateFor>
where
    Mempool: Service<
            mempool::Request,
            Response = mempool::Response,
            Error = zakura_node_services::BoxError,
        > + 'static,
    Mempool::Future: Send,
    ReadState: Service<
            zakura_state::ReadRequest,
            Response = zakura_state::ReadResponse,
            Error = zakura_state::BoxError,
        > + Clone
        + Send
        + 'static,
    ReadState::Future: Send,
    Tip: ChainTip + Clone + Send + Sync + 'static,
{
    // 1. Parse: the reference first, then the address.
    let reference = TemplateReference::parse(template)?;
    let payout = Payout::parse(&node.network, address)?;

    // 2. Refuse as `getblocktemplate` does. (Zakura's `getblocktemplate` has no check for
    //    peers, so ycashd's "Ycash is not connected!" has no counterpart here.)
    check_synced_to_tip(&node.network, node.latest_chain_tip.clone())
        .map_err(|_| ErrorObject::new(IN_INITIAL_DOWNLOAD, "Ycash is downloading blocks..."))?;
    let yellowback = node
        .mining
        .yellowback_miner()
        .await
        .map_err(|reason| unhealthy_error(&reason))?;
    let flags = yellowback
        .as_ref()
        .map(YellowbackMiner::flags)
        .unwrap_or_default();

    // 3. Read the tip and the mempool; nothing is written.
    let Some((tip_height, tip_hash)) = best_tip(node.read_state.clone()).await? else {
        return Err(stale_tip());
    };
    if tip_hash != reference.previous_block_hash {
        return Err(stale_tip());
    }
    let height = tip_height
        .next()
        .map_err(|error| ErrorObject::new(MISC_ERROR, error.to_string()))?;

    payout.check_payable_at(&node.network, height)?;

    // From NU5 the header commits to the coinbase, so a coinbase cannot be paired with another
    // template's header fields. No Ycash network activates NU5.
    if !is_pre_nu5(&node.network, height) {
        return Err(ErrorObject::new(
            MISC_ERROR,
            format!(
                "unsupported: the header commits to the coinbase at height {}",
                height.0
            ),
        ));
    }

    // The fee of every named transaction, from this node's mempool: the number `getblocktemplate`
    // prints per transaction. A mempool that is not at this tip can state no fee.
    let (mut fees, mut txs_size, mut txs_sigops) = (0i64, 0u64, 0u64);
    if !reference.txids.is_empty() {
        let in_mempool = fetch_mempool_transactions(node.mempool, tip_hash)
            .await?
            .map(|(transactions, _)| transactions)
            .unwrap_or_default();
        let by_id: std::collections::HashMap<_, _> = in_mempool
            .iter()
            .map(|tx| (tx.transaction.id().mined_id(), tx))
            .collect();
        let mut seen = HashSet::with_capacity(reference.txids.len());
        for txid in &reference.txids {
            let Some(tx) = by_id.get(txid) else {
                return Err(stale_transaction(*txid));
            };
            if !seen.insert(*txid) {
                return Err(ErrorObject::new(
                    INVALID_PARAMETER,
                    format!("txids names a transaction twice: {txid}"),
                ));
            }
            fees = fees.saturating_add(i64::from(tx.miner_fee));
            // A transaction is far smaller than `u64::MAX`.
            txs_size = txs_size.saturating_add(tx.transaction.size() as u64);
            txs_sigops = txs_sigops.saturating_add(u64::from(
                tx.block_sigop_count().saturating_add(pq_sigops(tx)),
            ));
        }
    }
    let fees = Amount::<NonNegative>::try_from(fees).map_err(construction_failed)?;

    // 4. Build the coinbase; the proof of a Sapling payout is made off the async workers.
    let amounts = CoinbaseAmounts::derive(&node.network, height, fees, node.ydf_percentage)
        .map_err(construction_failed)?;
    let coinbase = if matches!(payout, Payout::Sapling(_)) {
        if node.sapling_output_prover.is_none() {
            return Err(construction_failed(NOT_LOADED));
        }
        let permit = PROOF_SLOTS
            .acquire()
            .await
            .map_err(|error| construction_failed(error.to_string()))?;
        let (network, payout, amounts, flags, prover) = (
            node.network.clone(),
            payout.clone(),
            amounts.clone(),
            flags.clone(),
            node.sapling_output_prover.clone(),
        );
        let built = tokio::task::spawn_blocking(move || {
            // The slot is the job's: dropping the request cannot free it while the proof runs.
            let _permit = permit;
            build_coinbase(&network, height, &payout, &amounts, &flags, prover.as_ref())
        })
        .await;
        built.map_err(|error| construction_failed(error.to_string()))?
    } else {
        build_coinbase(&node.network, height, &payout, &amounts, &flags, None)
    }
    .map_err(construction_failed)?;

    // The outputs must add up to the subsidy plus the fees: the builder is never trusted to have
    // paid another amount.
    let expected_total = i64::from(amounts.subsidy).checked_add(i64::from(amounts.fees));
    if expected_total.is_none() || total_output(&coinbase) != expected_total {
        return Err(construction_failed(
            "outputs do not add up to subsidy plus fees",
        ));
    }

    // 5. The block of a header, this coinbase and the named transactions must respect the limits.
    let data = coinbase
        .zcash_serialize_to_vec()
        .map_err(|error| construction_failed(error.to_string()))?;
    let sigops = coinbase.sigops();
    check_fits(
        &node.network,
        data.len(),
        sigops,
        reference.txids.len(),
        txs_size,
        txs_sigops,
    )?;

    // 6. The tip must still be the one the coinbase was built for.
    if best_tip(node.read_state).await?.map(|(_, hash)| hash) != Some(tip_hash) {
        return Err(stale_tip());
    }

    Ok(CoinbaseTemplateFor {
        data: hex::encode(data),
        hash: coinbase.hash().to_string(),
        height: height.0,
        previousblockhash: tip_hash.to_string(),
        addresstype: payout.address_type().to_string(),
        subsidy: i64::from(amounts.subsidy),
        fund: i64::from(amounts.fund_value()),
        fundrule: amounts.fund_rule.to_string(),
        fees: i64::from(amounts.fees),
        amount: i64::from(amounts.amount),
        txcount: reference.txids.len(),
        flags: hex::encode(&flags),
        sigops,
    })
}
