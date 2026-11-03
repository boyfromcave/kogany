//! The `yed_*` read state over the node's registered Yellowback index (kogany plan W5-f): a
//! [`YedReadState`] that reads `zakura_state`'s best-chain YED snapshot
//! (`ReadRequest::BestChainYedSnapshot`, `zakura_state::yed::YedSnapshot`), as ycash6's
//! `src/rpc/yellowback.cpp` reads one `State` of `g_yellowback` under `cs_yellowback`.
//!
//! The index rows are [`LiveIndex`]'s (`super::live_index`). This state adds what ycashd reads
//! beyond the index: the node-local miner quote (`yed_setquote`, which the template's coinbase
//! tag reads, W8-b), the node-local attestation pool (`yed_addattestation`, in memory and bounded,
//! `super::pool`), and the chain reads through the read state service: a stored block's coinbase
//! tag (`yed_gettag`), the dry run of a raw transaction over the tip snapshot
//! (`yed_validaterawtransaction`), `EvaluateBlock` on a stored block (`yed_getblockverdict`),
//! the transaction behind a TxLog row (`yed_gettxinfo`) and the notice transaction
//! (`yed_getnotice`).
//!
//! The mempool (`crate::mempool`, F-S5-5) is read for `yed_getvault.spendPending` only: a
//! mempool coin is still an unknown input to the dry run's script check, and MINTPOL-1's
//! pending mints count zero.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use kogany_vault::Hash32;
use kogany_vault::{state::VaultTx, OutPoint};
use kogany_yellowback::{
    attest::{attestation_valid, Attestation as KAttestation},
    codecs::{
        payload::{find_payload, Payload},
        tag::{find_tag, height_prefix},
    },
    params::{PRICE_MAX, PRICE_MIN},
    state::{block_hash_at, eligible_payees, evaluate_block, TxLogType},
};
use tower::{Service, ServiceExt};
use zakura_chain::{
    block::{self, Height},
    chain_tip::ChainTip,
    parameters::{subsidy::halving_block_subsidy, Network, NetworkUpgrade},
    serialization::ZcashDeserializeInto,
    transaction::{self, Transaction},
};
use zakura_state::{BoxError, HashOrHeight, ReadRequest, ReadResponse};

pub use super::live_index::LiveIndex;
use super::pool::AttestationPool;
use super::state::*;

/// ycash6 `MinerConfig::quoteMaxAge` (`-yellowbackquotemaxage`, `src/yellowback/index.h:123`):
/// a held quote older than this builds no tag (MINER-1).
pub const QUOTE_MAX_AGE_SECONDS: i64 = 1_800;

/// The miner's payout key: the P2PKH key hash of the configured miner address (ycash6
/// `-yellowbackpayoutaddress`, defaulting to the mining address's key, `src/init.cpp`), set once
/// at start by `zakurad` ([`set_payout_address`]).
static PAYOUT_KEY: std::sync::OnceLock<Option<[u8; 20]>> = std::sync::OnceLock::new();

/// A transparent P2PKH receiver's key hash.
struct P2pkhKey([u8; 20]);

impl zcash_address::TryFromAddress for P2pkhKey {
    type Error = &'static str;

    fn try_from_transparent_p2pkh(
        _network: zcash_protocol::consensus::NetworkType,
        data: [u8; 20],
    ) -> Result<Self, zcash_address::ConversionError<Self::Error>> {
        Ok(P2pkhKey(data))
    }
}

/// Sets the miner's payout key from the node's miner address (`mining.miner_address`); only a
/// transparent P2PKH address has one (MINER-2: otherwise no tag). The first call wins.
pub fn set_payout_address(address: Option<&zcash_address::ZcashAddress>) {
    let key = address.and_then(|a| a.clone().convert::<P2pkhKey>().ok().map(|k| k.0));
    let _ = PAYOUT_KEY.set(key);
}

/// The miner's payout key, `None` without a P2PKH miner address.
pub fn payout_key() -> Option<[u8; 20]> {
    PAYOUT_KEY.get().copied().flatten()
}

/// ycash6 `yed_setquote`'s refusal on a node without a payout key (`RPC_INVALID_PARAMETER`,
/// `src/rpc/yellowback.cpp`); kogany's payout key is its P2PKH `mining.miner_address`.
pub const NO_PAYOUT_ADDRESS: &str =
    "set -yellowbackpayoutaddress (or a P2PKH -mineraddress) so the node can emit a tag";

fn no_payout_address() -> YedError {
    YedError::new(
        YedErrorKind::InvalidParameter,
        "no-payout-address",
        NO_PAYOUT_ADDRESS,
    )
}

/// The node-local miner state (`QuoteHolder`): the held quote and when it was set (seconds).
#[derive(Clone, Copy, Debug, Default)]
struct Quote {
    price_micro_usd: i64,
    source_mask: u16,
    received_at: i64,
}

/// The node's network (`zakurad` sets it once, [`set_network`]): the dry run's script check
/// and the block verdict's subsidy read it.
static NETWORK: std::sync::OnceLock<Network> = std::sync::OnceLock::new();

/// Sets the node's network for the live YED state. The first call wins.
pub fn set_network(network: &Network) {
    let _ = NETWORK.set(network.clone());
}

/// The Yellowback state of a running node: the best chain's YED index from `read_state`, the
/// chain tip, the node-local quote and the node-local attestation pool.
pub struct LiveYedState<T, R> {
    tip: T,
    read_state: R,
    quote: Mutex<Option<Quote>>,
    pool: Arc<Mutex<AttestationPool>>,
}

impl<T, R> LiveYedState<T, R> {
    /// The live state of `read_state` at `tip`.
    pub fn new(tip: T, read_state: R) -> Self {
        Self {
            tip,
            read_state,
            quote: Mutex::new(None),
            pool: Arc::default(),
        }
    }

    fn held_quote(&self) -> Option<Quote> {
        *self
            .quote
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// ycashd's `GetTime()`: the `setmocktime` clock when set (regtest), else the system clock, so
/// a quote's age (MINER-1, `-yellowbackquotemaxage`) follows the mock clock as on ycashd.
fn now_seconds() -> i64 {
    zakura_rpc::server::kogany_extension::mock_clock::now()
}

/// ycash6 `PlainPQAddressVersion` (`src/key_io.cpp:25-31`, D-Q-20).
fn plain_pq_address_version(network: &str) -> [u8; 2] {
    match network {
        "main" => [0x4D, 0xD9],
        "test" => [0x4F, 0x61],
        _ => [0x4C, 0x51],
    }
}

#[async_trait]
impl<T, R> YedReadState for LiveYedState<T, R>
where
    T: ChainTip + Clone + Send + Sync + 'static,
    R: Service<ReadRequest, Response = ReadResponse, Error = BoxError>
        + Clone
        + Send
        + Sync
        + 'static,
    R::Future: Send,
{
    async fn snapshot(&self) -> Result<Option<YedSnapshot>, String> {
        let response = self
            .read_state
            .clone()
            .oneshot(ReadRequest::BestChainYedSnapshot)
            .await
            .map_err(|e| e.to_string())?;
        let ReadResponse::YedSnapshot(Some(snap)) = response else {
            return Err("the Yellowback index is not available".to_owned());
        };
        let Some(params) = snap.params else {
            return Ok(None);
        };
        let chain_height = self.tip.best_tip_height().map_or(-1, |h| i64::from(h.0));
        let price = snap.attested_fee_price();
        let (network_fees, fee_zat, ref_lag) = super::fees::node_info_fees(price);
        let index = LiveIndex::with_pool(snap, params, ref_lag, self.pool.clone());
        let tip_height = index.tip().map_or(-1, |t| t.height);
        let quote = self.held_quote();
        // ycash6 `GetMinerStatus` (`src/yellowback/index.cpp:766-786`).
        let now = now_seconds();
        let payout = payout_key();
        let healthy = index.health().healthy;
        let fresh =
            quote.is_some_and(|q| now.saturating_sub(q.received_at) <= QUOTE_MAX_AGE_SECONDS);
        let quote_kind = if healthy && payout.is_some() && fresh {
            "quote"
        } else {
            "none"
        };
        let (registered, eligible) = match payout {
            Some(key) if healthy && tip_height >= i64::from(params.start_height) => (
                kogany_yellowback::state::registered(index.snap(), &params, &key, tip_height),
                eligible_payees(index.snap(), &params, tip_height).contains(&key),
            ),
            _ => (false, false),
        };
        Ok(Some(YedSnapshot {
            chain_height,
            params,
            node: NodeInfo {
                ref_lag,
                fee_zat,
                payee_policy: PayeePolicy {
                    penalty_blocks: i64::from(params.n_penalty),
                    accuracy_window: i64::from(params.accuracy_window),
                    tilt_bps: i64::from(params.payee_tilt_bps),
                    preferred: None,
                },
                preferred_attestor: None,
                miner: MinerStatus {
                    payout_key: payout,
                    quote_kind,
                    quote_age_seconds: quote.map(|q| now.saturating_sub(q.received_at)),
                    registered,
                    eligible,
                    quote: quote.map(|q| HeldQuote {
                        price_micro_usd: q.price_micro_usd,
                        source_mask: q.source_mask,
                    }),
                },
                network_fees,
                falcon_active_next: params.is_pq_falcon_active(tip_height.saturating_add(1)),
                plain_pq_address_version: plain_pq_address_version(params.network),
            },
            index: Arc::new(index),
        }))
    }

    async fn set_quote(
        &self,
        price_micro_usd: i64,
        source_mask: u16,
    ) -> Result<QuoteAck, YedError> {
        // ycash6 `yed_setquote` (`src/rpc/yellowback.cpp`): a node without a payout key cannot
        // emit a tag, so it refuses to hold a quote (F-S5-3), after the argument checks.
        let payout = payout_key().ok_or_else(no_payout_address)?;
        let now = now_seconds();
        *self
            .quote
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) =
            (price_micro_usd != 0).then_some(Quote {
                price_micro_usd,
                source_mask,
                received_at: now,
            });
        Ok(QuoteAck {
            received_at: now,
            // MINER-1..3: a quote tag iff a quote is held, the node has a payout key and the
            // index is healthy.
            next_kind: if price_micro_usd != 0
                && zakura_state::yed::yed_unhealthy_reason().is_none()
            {
                "quote"
            } else {
                "none"
            },
            payout_key: Some(payout),
        })
    }

    /// `AddAttestationLocked` (ycash6 `src/yellowback/index.cpp`).
    async fn add_attestation(&self, att: &Attestation) -> Result<AttestationAck, YedError> {
        let (snap, p) = self.yed_snapshot().await?;
        let tip = snap.index_tip().map_or(-1, |t| i64::from(t.height));
        let rejected = |id, text: String| YedError::new(YedErrorKind::Rejected, id, text);
        let rec = kogany_yellowback::state::view::attestor_of(&snap, att.seq).ok_or_else(|| {
            rejected(
                "attest-unknown-seq",
                format!("no attestor with seq {}", att.seq),
            )
        })?;
        use kogany_yellowback::attest::registry::AttestorStatus as S;
        if let S::Ejected | S::Withdrawn = rec.status {
            let name = if rec.status == S::Ejected {
                "EJECTED"
            } else {
                "WITHDRAWN"
            };
            return Err(rejected(
                "attest-not-eligible",
                format!("seq {} is {name}", att.seq),
            ));
        }
        let ref_lag = i64::from(super::fees::node_policy().ref_lag);
        let cited = i64::from(att.cited_height);
        let start = i64::from(p.start_height);
        let floor = tip
            .saturating_sub(ref_lag)
            .saturating_sub(i64::from(p.attest_max_age));
        if cited <= floor || cited > tip || cited < start {
            return Err(rejected(
                "attest-stale",
                format!(
                    "citedHeight {cited} is not in ({}, {tip}]",
                    floor.max(start.saturating_sub(1))
                ),
            ));
        }
        let price = i64::from(att.price_micro_usd);
        if !(PRICE_MIN..=PRICE_MAX).contains(&price) {
            return Err(rejected(
                "attest-range",
                format!("priceMicroUsd {price} is outside [{PRICE_MIN}, {PRICE_MAX}]"),
            ));
        }
        let katt = KAttestation {
            seq: att.seq,
            price_micro_usd: att.price_micro_usd,
            cited_height: att.cited_height,
            sig: att.sig,
        };
        let valid = block_hash_at(&snap, &p, cited).is_some_and(|hash| {
            attestation_valid(
                &katt,
                &rec.attestor_pub_key,
                &hash,
                Some(zakura_state::yed::module::node_yed_sig_cache()),
            )
        });
        if !valid {
            return Err(rejected(
                "attest-bad-sig",
                format!(
                    "the signature does not verify under attestorPubKey({}) for block {cited}",
                    att.seq
                ),
            ));
        }
        let mut pool = self
            .pool
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let replaced = pool.add(*att, tip).unwrap_or(false);
        Ok(AttestationAck {
            replaced,
            pool_size: i64::try_from(pool.size()).unwrap_or(i64::MAX),
        })
    }

    /// `yed_gettag`: `FindTag` over the coinbase scriptSig of a stored block at or above
    /// `startHeight` (a height on the best chain, or a hash on any chain).
    async fn coinbase_tag(
        &self,
        r: BlockRef,
    ) -> Result<Option<kogany_yellowback::codecs::tag::CoinbaseTag>, YedError> {
        let (_, p) = self.yed_snapshot().await?;
        let invalid = |text: &str| YedError::plain(YedErrorKind::InvalidParameter, text);
        let start = i64::from(p.start_height);
        let block = match r {
            BlockRef::Height(h) => {
                let tip = self.tip.best_tip_height().map_or(-1, |t| i64::from(t.0));
                if h < 0 || h > tip {
                    return Err(invalid("height out of range"));
                }
                // ycashd reads no body below startHeight, so a pruned one is no refusal there.
                if h < start {
                    return Ok(None);
                }
                let height = u32::try_from(h).map_err(|_| invalid("height out of range"))?;
                self.block(HashOrHeight::Height(Height(height)), false)
                    .await?
            }
            BlockRef::Hash(hash) => {
                let at = HashOrHeight::Hash(block::Hash(hash.0));
                match self.block(at, true).await {
                    Err(e) if e == YedError::pruned() => {
                        return match self.header_height(at).await {
                            Some(h) if h < start => Ok(None),
                            _ => Err(e),
                        };
                    }
                    other => other?,
                }
            }
        }
        .ok_or_else(|| invalid("block not found"))?;
        let Some(height) = block.coinbase_height() else {
            return Ok(None);
        };
        if i64::from(height.0) < i64::from(p.start_height) {
            return Ok(None);
        }
        let Some(cb) = block.transactions.first() else {
            return Ok(None);
        };
        let vtx = zakura_state::vault::vault_tx(cb, &cb.hash());
        Ok(vtx
            .inputs
            .first()
            .and_then(|i| find_tag(&i.script_sig, i32::try_from(height.0).unwrap_or(i32::MAX))))
    }

    /// `yed_validaterawtransaction`: the §3.8 dry run over a one-transaction pseudo-block at
    /// `tip + 1` (`MempoolCheck`'s predicate) and the script check at `tip + 1`
    /// (`VerifyAllInputs`: the standard flags, the vault flags by height, the set state at the
    /// tip).
    async fn validate_raw_transaction(&self, raw: &[u8]) -> Result<TxValidation, YedError> {
        let tx: Transaction = raw
            .zcash_deserialize_into()
            .map_err(|_| YedError::plain(YedErrorKind::Deserialization, "TX decode failed"))?;
        let txid = tx.hash();
        let (snap, p) = self.yed_snapshot().await?;
        let next = snap
            .index_tip()
            .map_or(-1, |t| i64::from(t.height))
            .saturating_add(1);
        let vtx = zakura_state::vault::vault_tx(&tx, &txid);
        let coinbase = VaultTx {
            txid: Hash32::ZERO,
            coinbase: true,
            inputs: vec![kogany_vault::state::VaultTxIn {
                prevout: OutPoint {
                    txid: Hash32::ZERO,
                    n: u32::MAX,
                },
                script_sig: height_prefix(i32::try_from(next).unwrap_or(i32::MAX)),
            }],
            outputs: Vec::new(),
        };
        let ev = evaluate_block(
            &snap,
            &p,
            &[coinbase, vtx.clone()],
            next,
            &Hash32::ZERO,
            0,
            Some(zakura_state::yed::module::node_yed_sig_cache()),
        );
        let log = ev
            .txlogs
            .iter()
            .rev()
            .find(|(id, _)| *id == vtx.txid)
            .map(|(_, l)| l.clone());
        let relevant = log.is_some();
        let log = log.unwrap_or_default();
        let expiry = tx.expiry_height().map_or(0, |h| h.0);
        let expiry_ok = if log.tx_type == TxLogType::Redeem {
            let scripts: Vec<&[u8]> = vtx
                .outputs
                .iter()
                .map(|o| o.script_pubkey.as_slice())
                .collect();
            let ref_height = match find_payload(&scripts).map(|f| f.payload) {
                Some(Payload::Redeem(r)) => i64::from(r.ref_height),
                _ => -1,
            };
            expiry != 0
                && ref_height >= 0
                && i64::from(expiry) <= ref_height.saturating_add(i64::from(p.ref_window))
        } else {
            true
        };
        let would_be_rejected = snap.mempool_check(&vtx, expiry).is_some();
        let (valid, invalid_reason, unconfirmed) = self.verify_inputs(tx, next).await;
        Ok(TxValidation {
            valid,
            invalid_reason,
            verdict: if relevant {
                log.verdict.clone()
            } else {
                "ok".to_owned()
            },
            kind: if relevant {
                super::live_index::tx_type_name(log.tx_type).to_owned()
            } else {
                "none".to_owned()
            },
            path: log.path.clone(),
            yed_in: log.yed_in,
            yed_out: log.yed_out,
            burned: log.burned,
            fee_zat: log.fee_zat,
            payee: log.has_payee.then_some(log.payee),
            block_valid: !ev.block_invalid,
            would_be_rejected,
            mempool_expiry_ok: expiry_ok,
            unconfirmed_inputs: unconfirmed,
        })
    }

    /// `yed_getblockverdict`: `EvaluateBlock` on a stored block whose parent is the index tip.
    async fn block_verdict(&self, hash: Hash32) -> Result<BlockVerdict, YedError> {
        let block = self
            .block(HashOrHeight::Hash(block::Hash(hash.0)), true)
            .await?
            .ok_or_else(|| YedError::plain(YedErrorKind::InvalidParameter, "block not found"))?;
        let (snap, p) = self.yed_snapshot().await?;
        let height = block.coinbase_height().map_or(-1, |h| i64::from(h.0));
        let tip = snap.index_tip();
        let parent_is_tip = match &tip {
            Some(t) => block.header.previous_block_hash.0 == t.block_hash.0,
            None => height == i64::from(p.start_height),
        };
        if !parent_is_tip {
            return Err(YedError::new(
                YedErrorKind::InvalidParameter,
                "verdict-parent-not-tip",
                format!(
                    "the block's parent is not the index tip ({}); the state at another parent would need an undo replay",
                    tip.map_or(-1, |t| i64::from(t.height))
                ),
            ));
        }
        let txs: Vec<VaultTx> = block
            .transactions
            .iter()
            .map(|t| zakura_state::vault::vault_tx(t, &t.hash()))
            .collect();
        let subsidy = match (NETWORK.get(), u32::try_from(height)) {
            (Some(network), Ok(h)) => halving_block_subsidy(Height(h), network)
                .map(i64::from)
                .unwrap_or(0),
            _ => 0,
        };
        let ev = evaluate_block(
            &snap,
            &p,
            &txs,
            height,
            &hash,
            subsidy,
            Some(zakura_state::yed::module::node_yed_sig_cache()),
        );
        Ok(BlockVerdict {
            block_invalid: ev.block_invalid,
            reason: ev.reason,
            verdict: ev.verdict,
            transactions: ev
                .txlogs
                .iter()
                .map(|(txid, l)| BlockVerdictTx {
                    txid: *txid,
                    kind: super::live_index::tx_type_name(l.tx_type).to_owned(),
                    path: l.path.clone(),
                    verdict: l.verdict.clone(),
                    yed_in: l.yed_in,
                    yed_out: l.yed_out,
                    fee_zat: l.fee_zat,
                    payee: l.has_payee.then_some(l.payee),
                    closed_vaults: l.closed_vaults.clone(),
                })
                .collect(),
        })
    }

    /// `yed_gettxinfo` with the transaction ycashd's `GetTransaction` finds (`-txindex`). A row
    /// whose transaction a pruned node no longer stores is [`YedError::pruned`], not the
    /// index-only row (`carrierVin` -1, no reference height), which would read as a different
    /// answer.
    async fn tx_info(&self, s: &YedSnapshot, txid: &Hash32) -> Result<Option<TxInfoRow>, YedError> {
        let tx = match self
            .read_state
            .clone()
            .oneshot(ReadRequest::Transaction(transaction::Hash(txid.0)))
            .await
        {
            Ok(ReadResponse::Transaction(Some(mined))) => Some(zakura_state::vault::vault_tx(
                &mined.tx,
                &transaction::Hash(txid.0),
            )),
            _ => None,
        };
        let row = s.index.tx_info_with(txid, tx.as_ref());
        if let (None, Some(r)) = (&tx, &row) {
            if self.body_pruned_at(r.height).await? {
                return Err(YedError::pruned());
            }
        }
        Ok(row)
    }

    /// The node's mempool (`crate::mempool`): its spender of `outpoint` (F-S5-5).
    async fn mempool_spender(&self, outpoint: &OutPoint) -> Option<Hash32> {
        let outpoint = zakura_chain::transparent::OutPoint {
            hash: zakura_chain::transaction::Hash(outpoint.txid.0),
            index: outpoint.n,
        };
        crate::mempool::spender_of(&outpoint)
            .await
            .map(|hash| Hash32(hash.0))
    }

    /// `AuditLockedValue` over the best chain's set state.
    async fn set_audit(&self) -> (Vec<String>, Vec<SetAudit>) {
        match self
            .read_state
            .clone()
            .oneshot(ReadRequest::BestChainVaultSnapshot)
            .await
        {
            Ok(ReadResponse::VaultSnapshot(Some(v))) => {
                let (mismatches, sets) = kogany_vault::state::audit_locked_value(&v.state);
                (
                    mismatches,
                    sets.into_iter()
                        .map(|a| SetAudit {
                            set_id: a.set_id,
                            locked_value_zat: a.stored,
                            records_zat: a.derived,
                        })
                        .collect(),
                )
            }
            _ => (Vec::new(), Vec::new()),
        }
    }

    /// `yed_getnotice`, naming the notice transaction: the CLAIM_NOTICE of this vault in the
    /// block at the notice's height whose TxLog row says it held.
    /// The block at the notice's height is read; a pruned node that no longer stores it
    /// answers [`YedError::pruned`] (a standing notice lives at most `EMERGENCY_NOTICE_TTL`
    /// blocks, well inside Zakura's retention floor, so this is a guard, not a path).
    async fn notice(&self, s: &YedSnapshot, txid: &Hash32) -> Result<NoticeLookup, YedError> {
        let NoticeLookup::Standing(mut n) = s.index.notice(txid) else {
            return Ok(s.index.notice(txid));
        };
        let vault = OutPoint { txid: *txid, n: 0 };
        let block = match u32::try_from(n.height) {
            Ok(h) => match self.block(HashOrHeight::Height(Height(h)), false).await {
                Ok(b) => b,
                Err(e) if e == YedError::pruned() => return Err(e),
                Err(_) => None,
            },
            Err(_) => None,
        };
        for tx in block.iter().flat_map(|b| b.transactions.iter()) {
            let vt = zakura_state::vault::vault_tx(tx, &tx.hash());
            let scripts: Vec<&[u8]> = vt
                .outputs
                .iter()
                .map(|o| o.script_pubkey.as_slice())
                .collect();
            let Some(Payload::ClaimNotice(c)) = find_payload(&scripts).map(|f| f.payload) else {
                continue;
            };
            if c.vault_outpoint() == vault && s.index.tx_info(&vt.txid).is_some_and(|l| l.notice) {
                n.txid = vt.txid;
                break;
            }
        }
        Ok(NoticeLookup::Standing(n))
    }
}

impl<T, R> LiveYedState<T, R>
where
    T: ChainTip + Clone + Send + Sync + 'static,
    R: Service<ReadRequest, Response = ReadResponse, Error = BoxError>
        + Clone
        + Send
        + Sync
        + 'static,
    R::Future: Send,
{
    /// The best chain's YED snapshot and the parameters in force (an `Internal` refusal where
    /// Yellowback is off, which the RPC layer has already answered `-32601`).
    async fn yed_snapshot(
        &self,
    ) -> Result<
        (
            zakura_state::yed::YedSnapshot,
            kogany_yellowback::params::Params,
        ),
        YedError,
    > {
        let internal = |text: String| YedError::plain(YedErrorKind::Internal, text);
        match self
            .read_state
            .clone()
            .oneshot(ReadRequest::BestChainYedSnapshot)
            .await
        {
            Ok(ReadResponse::YedSnapshot(Some(snap))) => match snap.params {
                Some(p) => Ok((snap, p)),
                None => Err(internal("Yellowback is not active on this node".to_owned())),
            },
            Ok(_) => Err(internal("the Yellowback index is not available".to_owned())),
            Err(e) => Err(internal(e.to_string())),
        }
    }

    /// A stored block: on the best chain, or (`any_chain`) on any chain. A block this node
    /// knows (its header is kept) but whose body it pruned is [`YedError::pruned`], so no
    /// caller answers "block not found" or a degraded row for it (pruning assessment KP-1).
    async fn block(
        &self,
        at: HashOrHeight,
        any_chain: bool,
    ) -> Result<Option<Arc<block::Block>>, YedError> {
        let request = if any_chain {
            ReadRequest::AnyChainBlock(at)
        } else {
            ReadRequest::Block(at)
        };
        let block = match self.read_state.clone().oneshot(request).await {
            Ok(ReadResponse::Block(b)) => b,
            Ok(_) => None,
            Err(e) => return Err(YedError::plain(YedErrorKind::Internal, e.to_string())),
        };
        if block.is_some() {
            return Ok(block);
        }
        match self.header_height(at).await {
            Some(h) if self.body_pruned_at(h).await? => Err(YedError::pruned()),
            _ => Ok(None),
        }
    }

    /// The height of a block this node holds the header of (a height is its own answer).
    async fn header_height(&self, at: HashOrHeight) -> Option<i64> {
        match at {
            HashOrHeight::Height(h) => Some(i64::from(h.0)),
            HashOrHeight::Hash(_) => match self
                .read_state
                .clone()
                .oneshot(ReadRequest::BlockHeader(at))
                .await
            {
                Ok(ReadResponse::BlockHeader { height, .. }) => Some(i64::from(height.0)),
                _ => None,
            },
        }
    }

    /// Whether the body of the block at `height` was pruned: the node prunes (Zakura's
    /// `getblockchaininfo.pruned`) and `height` is below the lowest height whose body it keeps
    /// (`pruneheight`). Genesis is never pruned.
    async fn body_pruned_at(&self, height: i64) -> Result<bool, YedError> {
        match self
            .read_state
            .clone()
            .oneshot(ReadRequest::PruningInfo)
            .await
        {
            Ok(ReadResponse::PruningInfo {
                pruned: true,
                prune_height: Some(lowest),
            }) => Ok(height > 0 && height < i64::from(lowest.0)),
            Ok(_) => Ok(false),
            Err(e) => Err(YedError::plain(YedErrorKind::Internal, e.to_string())),
        }
    }

    /// `VerifyAllInputs` at `next` over the best chain's unspent outputs: `(valid, reason,
    /// unconfirmed inputs)`. A mempool parent is an unknown input here (no mempool access).
    async fn verify_inputs(
        &self,
        tx: Transaction,
        next: i64,
    ) -> (bool, Option<String>, Vec<OutPoint>) {
        let mut spent = Vec::new();
        let mut unconfirmed = Vec::new();
        let mut first_unknown = None;
        for (i, input) in tx.inputs().iter().enumerate() {
            let Some(outpoint) = input.outpoint() else {
                continue;
            };
            let utxo = match self
                .read_state
                .clone()
                .oneshot(ReadRequest::UnspentBestChainUtxo(outpoint))
                .await
            {
                Ok(ReadResponse::UnspentBestChainUtxo(u)) => u,
                _ => None,
            };
            match utxo {
                Some(u) => spent.push(u.output),
                None => {
                    unconfirmed.push(zakura_state::vault::vault_outpoint(&outpoint));
                    first_unknown.get_or_insert(i);
                }
            }
        }
        if let Some(i) = first_unknown {
            return (
                false,
                Some(format!("input {i} is unknown or spent")),
                unconfirmed,
            );
        }
        let (Some(network), Ok(height)) = (NETWORK.get(), u32::try_from(next)) else {
            return (
                false,
                Some("the node's network is not configured".to_owned()),
                unconfirmed,
            );
        };
        if tx.is_coinbase() {
            return (true, None, unconfirmed);
        }
        let height = Height(height);
        let vault_state: Option<zakura_script::VaultStateSnapshot> = match self
            .read_state
            .clone()
            .oneshot(ReadRequest::BestChainVaultSnapshot)
            .await
        {
            Ok(ReadResponse::VaultSnapshot(Some(v))) => Some(v.state),
            _ => None,
        };
        let nu = NetworkUpgrade::current(network, height);
        let cached =
            match zakura_script::CachedFfiTransaction::new(Arc::new(tx), Arc::new(spent), nu) {
                Ok(c) => c,
                Err(e) => {
                    return (
                        false,
                        Some(format!(
                            "input 0 fails script verification: {}",
                            script_error_text(&e)
                        )),
                        unconfirmed,
                    )
                }
            };
        let context = zakura_script::ScriptContext::new(network.clone(), height, vault_state)
            .with_standard_policy();
        for i in 0..cached.inputs().len() {
            if let Err(e) = cached.is_valid_in(i, &context) {
                return (
                    false,
                    Some(format!(
                        "input {i} fails script verification: {}",
                        script_error_text(&e)
                    )),
                    unconfirmed,
                );
            }
        }
        (true, None, unconfirmed)
    }
}

/// ycashd's `ScriptErrorString` of a script failure (zakura-rpc's Ycash table; the error's own
/// text in a Zcash build).
fn script_error_text(e: &zakura_script::Error) -> String {
    #[cfg(feature = "ycash")]
    {
        zakura_rpc::ycash_script_error_string(e).to_owned()
    }
    #[cfg(not(feature = "ycash"))]
    {
        e.to_string()
    }
}

/// Pruning assessment KP-1: a pruned body is an explicit `"Block not available (pruned data)"`
/// (-32603, ycashd's `getblock` refusal), never "block not found" or a degraded row.
#[cfg(test)]
mod pruned_tests {
    use super::*;
    use zakura_chain::{block::genesis::regtest_genesis_block, chain_tip::NoChainTip};

    /// A read state that stores no body, knows one header (`known` at `header_height`) and
    /// reports `pruning` (`None`: an archive node).
    fn state(
        pruning: Option<u32>,
        known: block::Hash,
        header_height: u32,
    ) -> LiveYedState<
        NoChainTip,
        impl Service<ReadRequest, Response = ReadResponse, Error = BoxError, Future = impl Send>
            + Clone
            + Send
            + Sync
            + 'static,
    > {
        let header = regtest_genesis_block().header.clone();
        let svc = tower::service_fn(move |req: ReadRequest| {
            let header = header.clone();
            async move {
                Ok::<_, BoxError>(match req {
                    ReadRequest::Block(_) | ReadRequest::AnyChainBlock(_) => {
                        ReadResponse::Block(None)
                    }
                    ReadRequest::Transaction(_) => ReadResponse::Transaction(None),
                    ReadRequest::BlockHeader(HashOrHeight::Hash(h)) if h == known => {
                        ReadResponse::BlockHeader {
                            header,
                            hash: known,
                            height: Height(header_height),
                            next_block_hash: None,
                        }
                    }
                    ReadRequest::BlockHeader(_) => ReadResponse::Block(None),
                    ReadRequest::PruningInfo => ReadResponse::PruningInfo {
                        pruned: pruning.is_some(),
                        prune_height: pruning.map(Height),
                    },
                    other => panic!("unexpected request {other:?}"),
                })
            }
        });
        LiveYedState::new(NoChainTip, svc)
    }

    #[tokio::test]
    async fn a_pruned_body_is_the_pruned_error() {
        let known = block::Hash([7; 32]);
        let s = state(Some(1_000), known, 5);
        let h = |n| HashOrHeight::Height(Height(n));
        assert_eq!(s.block(h(5), false).await, Err(YedError::pruned()));
        assert_eq!(s.block(h(999), false).await, Err(YedError::pruned()));
        // Genesis is never pruned; at and above pruneheight a missing body is "not found".
        assert_eq!(s.block(h(0), false).await, Ok(None));
        assert_eq!(s.block(h(1_000), false).await, Ok(None));
        // By hash: the kept header names the height.
        assert_eq!(
            s.block(HashOrHeight::Hash(known), true).await,
            Err(YedError::pruned())
        );
        assert_eq!(
            s.block(HashOrHeight::Hash(block::Hash([8; 32])), true)
                .await,
            Ok(None)
        );
        assert!(s.body_pruned_at(999).await.unwrap());
        assert!(!s.body_pruned_at(0).await.unwrap());
        assert!(!s.body_pruned_at(1_000).await.unwrap());
    }

    #[tokio::test]
    async fn an_archive_node_never_answers_pruned() {
        let known = block::Hash([7; 32]);
        let s = state(None, known, 5);
        assert_eq!(
            s.block(HashOrHeight::Height(Height(5)), false).await,
            Ok(None)
        );
        assert_eq!(s.block(HashOrHeight::Hash(known), true).await, Ok(None));
        assert!(!s.body_pruned_at(5).await.unwrap());
        // A pruning node that has pruned nothing yet (pruneheight 0) is the same.
        let s = state(Some(0), known, 5);
        assert!(!s.body_pruned_at(5).await.unwrap());
    }

    #[test]
    fn the_pruned_error_is_ycashds_getblock_refusal() {
        let e = YedError::pruned();
        assert_eq!(e.kind, YedErrorKind::Internal);
        assert_eq!(e.message(), "Block not available (pruned data)");
        let o = zakura_rpc::server::jsonrpc::ErrorObject::from(e);
        assert_eq!(o.code(), -32603);
        assert_eq!(o.message(), "Block not available (pruned data)");
    }

    /// The relation the assessment's §3 rests on: at Zakura's Mainnet/Testnet floor every block
    /// whose YED snapshot is servable by hash (`UNDO_KEEP` below the finalized tip, which trails
    /// the best tip by at most `MAX_BLOCK_REORG_HEIGHT`) still has its body, and any retention
    /// Zakura accepts exceeds the reorg window (no reorg ever needs a pruned body). If either
    /// fails, a pruned kogany needs its own floor (mapping §24, the K-14 coupling).
    #[test]
    fn retention_floor_covers_the_yed_undo_window_and_the_reorg_window() {
        use zakura_state::constants::{min_pruning_retention, MIN_PRUNING_RETENTION};
        use zakura_state::yed::UNDO_KEEP;
        use zakura_state::MAX_BLOCK_REORG_HEIGHT;
        const { assert!(MIN_PRUNING_RETENTION > UNDO_KEEP + MAX_BLOCK_REORG_HEIGHT) };
        for network in [Network::Mainnet, Network::new_default_testnet()] {
            assert_eq!(min_pruning_retention(&network), MIN_PRUNING_RETENTION);
        }
        let regtest = Network::new_regtest(Default::default());
        assert!(min_pruning_retention(&regtest) > MAX_BLOCK_REORG_HEIGHT);
    }
}

/// F-S5-3: without a payout key (`mining.miner_address` unset or not P2PKH; no test in this
/// binary sets one) `yed_setquote` is ycashd's `no-payout-address` refusal and holds no quote.
#[cfg(test)]
mod payout_tests {
    use super::*;
    use zakura_chain::chain_tip::NoChainTip;

    #[tokio::test]
    async fn set_quote_without_a_payout_key_is_refused() {
        let svc = tower::service_fn(|req: ReadRequest| async move {
            panic!("unexpected request {req:?}");
            #[allow(unreachable_code)]
            Ok::<_, BoxError>(ReadResponse::VaultSnapshot(None))
        });
        let s = LiveYedState::new(NoChainTip, svc);
        assert_eq!(payout_key(), None);
        let e = s.set_quote(50_000_000, 1).await.expect_err("refused");
        assert_eq!(e.kind, YedErrorKind::InvalidParameter);
        assert_eq!(
            e.message(),
            "no-payout-address: set -yellowbackpayoutaddress (or a P2PKH -mineraddress) so the \
             node can emit a tag"
        );
        let o = zakura_rpc::server::jsonrpc::ErrorObject::from(e);
        assert_eq!(o.code(), -8);
        assert!(s.held_quote().is_none());
    }
}
