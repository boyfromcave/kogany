//! The Ycash mining hooks of `getblocktemplate` (kogany plan W8), compiled under the `ycash`
//! feature.
//!
//! Copyright (c) 2026 The Ycash developers. Distributed under the MIT software license.
//!
//! Every function here is called from one hook in an upstream body, so the upstream code stays as
//! it is. Each value cites the ycashd line it mirrors: `ycash6` at `65cb4ae0f`
//! (`vaults/kogany-compat` = `upgrade/vault`).
//!
//! - **The coinbase tag (W8-b, M24-19).** ycashd appends `COINBASE_FLAGS` to its coinbase input
//!   script, and with Yellowback live that is the miner's tag push built from the node-local
//!   quote (`src/miner.cpp:291,354`, `yellowback::policy::BuildTagScript`,
//!   `src/yellowback/policy.cpp:27-39`). kogany builds the same tag from the same inputs
//!   ([`YellowbackMiner::tag`]) and appends the same 37 bytes after Zakura's own coinbase data
//!   ([`append_coinbase_flags`]), so the tag bytes equal ycashd's for the same quote; the
//!   template reports them as `coinbaseaux.flags` and its `yellowback` object
//!   ([`template_fields`], `src/rpc/mining.cpp:790-847`, `src/yellowback/index.cpp:794-831`).
//! - **The health refusal.** ycashd refuses `getblocktemplate` while the YED index is unhealthy
//!   (`src/rpc/mining.cpp:519-523`): [`unhealthy_error`].
//! - **The `sigops` field.** ycashd's mempool entry counts 20 policy sigops per `OP_CHECKPQSIG`
//!   in the spend (`src/main.cpp:2087-2089`, `GetPQSigOpCount`, `src/policy/policy.cpp:436-473`),
//!   and its miner charges and reports that count: [`pq_sigops`].
//! - **The template filter (W8-a).** ycashd's `BlockAssembler::TestForBlock` applies each
//!   candidate's acts and template rules to a running copy of the set state and skips one that
//!   fails (`vault::TemplateRun::Try`, `src/vault/node.cpp:316-358`; the TPL-1 analogue), then
//!   asks the YED module (`yellowback::policy::FilterTemplate`, `src/miner.cpp:555-609`):
//!   [`TemplateFilter`]. Templates are still verified through `Request::Prepare`, which runs
//!   the scripts and BIP68 that `TemplateRun::Try` also re-runs.

use std::sync::Arc;

use async_trait::async_trait;
use kogany_vault::{
    act::is_act_output,
    state::{
        check_tx, CoinAccessor, Rules, SetState, SpentCoin, StateRead, VaultTx, VaultTxIn,
        VaultTxOut,
    },
    template::{match_intent, match_vault, parse_intent, parse_vault, Shape},
    Hash32, OutPoint,
};
use kogany_yellowback::codecs::tag::{find_tag, tag_push, CoinbaseTag};
use zakura_chain::{
    amount::NegativeOrZero,
    block::{self, Height},
    parameters::Network,
    serialization::ZcashDeserializeInto,
    transaction::{self, Transaction, VerifiedUnminedTx},
    transparent,
};
use zakura_consensus::error::TransactionError;
use zcash_script::{script::Code, vault::pq_sig_op_count};
use zcash_transparent::coinbase::MAX_COINBASE_SCRIPT_LEN;

use crate::{
    config::mining::ZAKURA_COINBASE_MARKER, methods::types::transaction::TransactionTemplate,
    server::error::LegacyCode,
};

#[cfg(test)]
mod tests;

// ---- the node-side hooks ----------------------------------------------------------------

/// What the template builder asks of the node's Yellowback module and vault state.
///
/// `zakurad` installs one with `RpcImpl::with_ycash_mining`; until then (and on a node where
/// Yellowback is not live) [`NotLive`] answers: no tag, no `yellowback` field, no refusal, and
/// no YED filter. kogany-rpc implements it over the `yed_*` read state, so `yed_setquote` and the
/// template read one quote.
#[async_trait]
pub trait YcashMining: Send + Sync + 'static {
    /// The miner's Yellowback state for the next template (ycashd `g_yellowback`,
    /// `GetMinerStatus`, `GetQuote`).
    ///
    /// `Ok(None)` when Yellowback is not live on this node (ycashd: `g_yellowback` null).
    /// `Err(reason)` when the YED index is unhealthy (`UnhealthyReason()`): `getblocktemplate`
    /// then refuses with [`unhealthy_error`].
    async fn yellowback_miner(&self) -> Result<Option<YellowbackMiner>, String>;

    /// The set state after the block `parent` (ycash6 `vault::TemplateRun`'s copy of the set
    /// state at the tip), `None` when it is not available. Plan W4-d answers it from
    /// `zakura_state::ReadRequest::VaultSnapshot`. While it is `None` and Vault is active, the
    /// template leaves out every candidate that touches the vault primitive (fail closed).
    async fn vault_state(&self, parent: block::Hash) -> Option<Arc<SetState>> {
        let _ = parent;
        None
    }

    /// The YED half of the template filter for a template at `height` (ycash6
    /// `yellowback::policy::FilterTemplate` over a `TemplateView`), `None` = keep every
    /// candidate. Plan W5-f implements it once the YED index is registered.
    fn yed_template_filter(&self, height: Height) -> Option<Box<dyn YedTemplateFilter>> {
        let _ = height;
        None
    }
}

/// Yellowback is not live: the hooks of a node without the YED module (the default).
#[derive(Clone, Copy, Debug, Default)]
pub struct NotLive;

#[async_trait]
impl YcashMining for NotLive {
    async fn yellowback_miner(&self) -> Result<Option<YellowbackMiner>, String> {
        Ok(None)
    }
}

/// The YED half of the template filter (ycash6 `yellowback::policy::FilterTemplate`,
/// `src/yellowback/policy.cpp:49-94`), one per template.
///
/// The template asks it about each candidate in selection order, after the candidate has passed
/// the block limits and the vault filter. It keeps a candidate iff the candidate is valid under
/// the YED module at the template's height after the candidates it kept before (in-block
/// chaining and first-claim-wins exactly as block validation evaluates them); a kept
/// candidate's effect joins the filter's own overlay. A non-Yellowback transaction is a no-op
/// that it keeps. While the index is unhealthy it keeps nothing.
pub trait YedTemplateFilter: Send {
    /// Keep `tx` (and apply its effect to the template overlay), or skip it.
    fn keep(&mut self, tx: &VerifiedUnminedTx) -> bool;
}

/// The miner's Yellowback state for one template (ycashd `MinerStatus` with the tag
/// `BuildTagScript` would build).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct YellowbackMiner {
    /// The tag the next coinbase carries, `None` for no tag (MINER-1..3: no payout key, an
    /// unhealthy index, or no fresh quote). [`YellowbackMiner::flags`] encodes it.
    pub tag: Option<CoinbaseTag>,
    /// The payout key (`-yellowbackpayoutaddress`, else the miner address's key), `None` without
    /// one.
    pub payout_key: Option<[u8; 20]>,
    /// Seconds since the held quote was set, `None` without one.
    pub quote_age_seconds: Option<i64>,
    /// REG-1 of the payout key at the tip.
    pub registered: bool,
    /// Membership of the payout key in `E(tip)` (FEE-2).
    pub eligible: bool,
}

impl YellowbackMiner {
    /// `BuildTagScript` (`src/yellowback/policy.cpp:27-39`): the tag for a held quote, or `None`.
    ///
    /// `fresh_quote` is `MinerStatus.kind == "quote"` (healthy, a payout key, a non-zero quote at
    /// most `-yellowbackquotemaxage` old). The flags byte is 0 (no signal bit since the vault
    /// upgrade), and a tag that fails TAG-2 is no tag.
    pub fn build_tag(
        fresh_quote: bool,
        payout_key: Option<[u8; 20]>,
        price_micro_usd: i64,
        source_mask: u16,
    ) -> Option<CoinbaseTag> {
        let payout_key = payout_key.filter(|_| fresh_quote)?;
        let tag = CoinbaseTag {
            flags: 0,
            price_micro_usd: u64::try_from(price_micro_usd).ok()?,
            source_mask,
            payout_key,
        };
        tag.is_valid().then_some(tag)
    }

    /// ycashd's `COINBASE_FLAGS`: the tag push (`0x24 ‖ 36 bytes`), or nothing.
    pub fn flags(&self) -> Vec<u8> {
        self.tag.as_ref().map(tag_push).unwrap_or_default()
    }
}

/// ycashd's refusal while the YED index is unhealthy (`src/rpc/mining.cpp:521-523`):
/// `RPC_VERIFY_REJECTED`, `"yellowback-unhealthy: <reason>; restart with -reindex-yellowback"`.
pub fn unhealthy_error(reason: &str) -> crate::server::jsonrpc::ErrorObject {
    crate::server::jsonrpc::ErrorObject::new(
        LegacyCode::VerifyRejected,
        format!("yellowback-unhealthy: {reason}; restart with -reindex-yellowback"),
    )
}

// ---- the coinbase tag -------------------------------------------------------------------

/// Appends ycashd's `COINBASE_FLAGS` (`flags`) to the input script of the coinbase `template`
/// (`src/miner.cpp:291`: `(CScript() << nHeight << OP_0) + COINBASE_FLAGS`).
///
/// Zakura's coinbase input script is the height push and one push of Zakura's coinbase data; the
/// flags follow it, so the script reads `<height> <data> <tag>` and the tag is found by the same
/// scan (`FindTag`) at the same place relative to ycashd's two leading pushes. If the configured
/// `extra_coinbase_data` leaves no room for the 37 tag bytes under the 100-byte limit, the data
/// push shrinks to Zakura's marker alone, so the tag is never dropped for a pool's text.
///
/// The txid and the serialized data are recomputed; the sigop count and the fee are unchanged
/// (the flags are pushes).
pub fn append_coinbase_flags(
    mut template: TransactionTemplate<NegativeOrZero>,
    flags: &[u8],
) -> Result<TransactionTemplate<NegativeOrZero>, TransactionError> {
    if flags.is_empty() {
        return Ok(template);
    }

    let mut tx: Transaction = template
        .data
        .as_ref()
        .zcash_deserialize_into()
        .map_err(|error| TransactionError::CoinbaseConstruction(error.to_string()))?;
    let Some(transparent::Input::Coinbase { height, data, .. }) = coinbase_input_mut(&mut tx)
    else {
        return Err(TransactionError::CoinbaseConstruction(
            "the coinbase template has no coinbase input".to_string(),
        ));
    };

    let height_len = transparent::Input::Coinbase {
        height: *height,
        data: Vec::new(),
        sequence: 0,
    }
    .coinbase_script()
    .map_or(0, |script| script.len());

    if height_len + data.len() + flags.len() > MAX_COINBASE_SCRIPT_LEN {
        // The marker's direct push: 4 bytes, so its length byte is the push opcode.
        let marker = ZAKURA_COINBASE_MARKER.as_bytes();
        let mut marker_only = vec![u8::try_from(marker.len()).unwrap_or(u8::MAX)];
        marker_only.extend_from_slice(marker);
        *data = marker_only;
    }
    if height_len + data.len() + flags.len() > MAX_COINBASE_SCRIPT_LEN {
        return Err(TransactionError::CoinbaseConstruction(
            "the coinbase input script has no room for the Yellowback tag".to_string(),
        ));
    }
    data.extend_from_slice(flags);

    template.hash = tx.hash();
    if let Some(auth_digest) = tx.auth_digest() {
        template.auth_digest = auth_digest;
    }
    template.data = (&tx).into();
    Ok(template)
}

/// The coinbase input of `tx`, if its first input is one.
fn coinbase_input_mut(tx: &mut Transaction) -> Option<&mut transparent::Input> {
    match tx {
        Transaction::V1 { inputs, .. }
        | Transaction::V2 { inputs, .. }
        | Transaction::V3 { inputs, .. }
        | Transaction::V4 { inputs, .. }
        | Transaction::V5 { inputs, .. }
        | Transaction::V6 { inputs, .. } => inputs.first_mut(),
    }
}

/// The input script of a coinbase template's transaction.
pub fn coinbase_script_sig(template: &TransactionTemplate<NegativeOrZero>) -> Option<Vec<u8>> {
    let tx: Transaction = template.data.as_ref().zcash_deserialize_into().ok()?;
    tx.inputs().first()?.coinbase_script()
}

/// One script operation as ycashd's `CScript::GetOp` reads it: the opcode and its push data
/// (empty for a non-push opcode), or `None` for a truncated push.
fn get_op(script: &[u8], pc: &mut usize) -> Option<(u8, Vec<u8>)> {
    let opcode = *script.get(*pc)?;
    *pc += 1;
    let len = match opcode {
        0x01..=0x4b => usize::from(opcode),
        0x4c => {
            let n = usize::from(*script.get(*pc)?);
            *pc += 1;
            n
        }
        0x4d => {
            let b = script.get(*pc..*pc + 2)?;
            *pc += 2;
            usize::from(u16::from_le_bytes([b[0], b[1]]))
        }
        0x4e => {
            let b = script.get(*pc..*pc + 4)?;
            *pc += 4;
            usize::try_from(u32::from_le_bytes([b[0], b[1], b[2], b[3]])).ok()?
        }
        _ => 0,
    };
    let data = script.get(*pc..pc.checked_add(len)?)?.to_vec();
    *pc += len;
    Some((opcode, data))
}

/// `CoinbaseFlagsOf` (`src/yellowback/index.cpp:794-804`): everything after the input script's
/// two leading operations, the bytes the coinbase flags contributed; empty when the script has
/// fewer than two.
pub fn coinbase_flags_of(script_sig: &[u8]) -> Vec<u8> {
    let mut pc = 0;
    for _ in 0..2 {
        if get_op(script_sig, &mut pc).is_none() {
            return Vec::new();
        }
    }
    script_sig.get(pc..).map(<[u8]>::to_vec).unwrap_or_default()
}

/// `coinbaseaux` (`src/rpc/mining.cpp:790-792,830-832`): the coinbase flags as hex.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CoinbaseAux {
    /// `flags`: the hex of the template coinbase's flags.
    pub flags: String,
}

/// The template's `yellowback` object (`YellowbackIndex::TemplateInfo`,
/// `src/yellowback/index.cpp:806-831`), in ycashd's field order.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct YellowbackTemplateInfo {
    /// The hex of the coinbase flags.
    pub tag: String,
    /// `"none"`, `"quote"` or `"signal"`: the tag the coinbase carries, decoded by `FindTag`.
    pub kind: String,
    /// The tag's quote, 0 without one.
    #[serde(rename = "priceMicroUsd")]
    pub price_micro_usd: i64,
    /// Seconds since the held quote was set, `null` without one.
    #[serde(rename = "quoteAgeSeconds")]
    pub quote_age_seconds: Option<i64>,
    /// The tag's payout key, else the node's, as a P2PKH address; `null` without either.
    #[serde(rename = "payoutAddress")]
    pub payout_address: Option<String>,
    /// REG-1 of the payout key at the tip.
    pub registered: bool,
    /// The payout key's membership in `E(tip)`.
    pub eligible: bool,
    /// The index is healthy (always, in a template: an unhealthy index refuses one).
    pub healthy: bool,
}

/// The `coinbaseaux` and `yellowback` fields of a template at `height` whose coinbase input
/// script is `script_sig`, for the miner state `miner`.
///
/// As ycashd, the tag is read back from the coinbase through the scan a node applies to the
/// mined block, not from the quote (audit A-7).
pub fn template_fields(
    network: &Network,
    height: Height,
    script_sig: &[u8],
    miner: &YellowbackMiner,
) -> (CoinbaseAux, YellowbackTemplateInfo) {
    let flags = coinbase_flags_of(script_sig);
    let tag = if flags.is_empty() {
        None
    } else {
        i32::try_from(height.0)
            .ok()
            .and_then(|h| find_tag(script_sig, h))
    };
    let payout = tag.map(|t| t.payout_key).or(miner.payout_key);
    let info = YellowbackTemplateInfo {
        tag: hex::encode(&flags),
        kind: match tag {
            None => "none",
            Some(t) if t.is_quote() => "quote",
            Some(_) => "signal",
        }
        .to_string(),
        price_micro_usd: tag
            .filter(CoinbaseTag::is_quote)
            .and_then(|t| i64::try_from(t.price_micro_usd).ok())
            .unwrap_or(0),
        quote_age_seconds: miner.quote_age_seconds,
        payout_address: payout
            .map(|key| transparent::Address::from_pub_key_hash(network.kind(), key).to_string()),
        registered: miner.registered,
        eligible: miner.eligible,
        healthy: true,
    };
    (
        CoinbaseAux {
            flags: hex::encode(&flags),
        },
        info,
    )
}

/// The BIP 22 `mutable` entry ycashd adds while Yellowback is live (`src/rpc/mining.cpp:802`).
pub const MUTABLE_COINBASE_APPEND: &str = "coinbase/append";

// ---- sigops -----------------------------------------------------------------------------

/// The policy sigops of `OP_CHECKPQSIG` in a candidate (`GetPQSigOpCount(tx, view)`,
/// `src/policy/policy.cpp:448-473`): 20 per `OP_CHECKPQSIG` in each input script, in the
/// script it spends, and, when that is P2SH and the input script is push-only, in the redeem
/// script (its last push). An input whose spent output is unknown counts its input script only.
///
/// ycashd adds this to the entry's legacy and P2SH count (`src/main.cpp:2087-2089`), charges it
/// against `MAX_BLOCK_SIGOPS` when it selects and reports it as the template's `sigops`.
pub fn pq_sigops(tx: &VerifiedUnminedTx) -> u32 {
    let transaction = tx.transaction.transaction();
    if transaction.is_coinbase() {
        return 0;
    }
    let count = |script: &[u8]| pq_sig_op_count(&Code(script.to_vec()));
    let mut n: u32 = 0;
    for (i, input) in transaction.inputs().iter().enumerate() {
        let transparent::Input::PrevOut { unlock_script, .. } = input else {
            continue;
        };
        let script_sig = unlock_script.as_raw_bytes();
        n = n.saturating_add(count(script_sig));
        let Some(spent) = tx.spent_outputs.get(i) else {
            continue;
        };
        let spent = spent.lock_script.as_raw_bytes();
        n = n.saturating_add(count(spent));
        if is_p2sh(spent) {
            if let Some(redeem) = last_push_if_push_only(script_sig) {
                n = n.saturating_add(count(&redeem));
            }
        }
    }
    n
}

/// `CScript::IsPayToScriptHash`: `OP_HASH160 <20 bytes> OP_EQUAL`.
fn is_p2sh(script: &[u8]) -> bool {
    script.len() == 23 && script[0] == 0xa9 && script[1] == 0x14 && script[22] == 0x87
}

/// The data of the last operation of `script_sig` when every operation is at most `OP_16`
/// (the loop of `GetPQSigOpCount`), `None` otherwise.
fn last_push_if_push_only(script_sig: &[u8]) -> Option<Vec<u8>> {
    let mut pc = 0;
    let mut data = Vec::new();
    while pc < script_sig.len() {
        let (opcode, d) = get_op(script_sig, &mut pc)?;
        if opcode > 0x60 {
            return None;
        }
        data = d;
    }
    Some(data)
}

// ---- the template filter ----------------------------------------------------------------

/// The per-template filter of ZIP-317 selection (the ycashd `TestForBlock` checks that follow the
/// block limits): the vault half, then the YED half.
pub struct TemplateFilter {
    height: Height,
    vault: VaultFilter,
    yed: Option<Box<dyn YedTemplateFilter>>,
}

/// The vault half of the template filter.
enum VaultFilter {
    /// Vault is not active at the template's height (ycashd builds no `TemplateRun` there).
    Inactive,
    /// Vault is active but no set state is available: every candidate that touches the
    /// primitive is left out, so a template never carries an unchecked act.
    Unavailable,
    /// ycashd's `TemplateRun`: the running set state of the template.
    Running {
        state: Box<SetState>,
        rules: Rules<'static>,
    },
}

impl std::fmt::Debug for TemplateFilter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let vault = match self.vault {
            VaultFilter::Inactive => "inactive",
            VaultFilter::Unavailable => "unavailable",
            VaultFilter::Running { .. } => "running",
        };
        f.debug_struct("TemplateFilter")
            .field("height", &self.height)
            .field("vault", &vault)
            .field("yed", &self.yed.is_some())
            .finish()
    }
}

impl TemplateFilter {
    /// The filter of a template at `height` on the parent `parent`, from the node's hooks.
    pub async fn prepare(
        network: &Network,
        height: Height,
        parent: block::Hash,
        hooks: &dyn YcashMining,
    ) -> Self {
        let vault = if !network.is_vault_active(height) {
            VaultFilter::Inactive
        } else {
            match (
                zakura_state::vault::vault_network_params(network),
                hooks.vault_state(parent).await,
            ) {
                (Some(params), Some(state)) => VaultFilter::Running {
                    state: Box::new(Arc::unwrap_or_clone(state)),
                    rules: params.rules(),
                },
                _ => {
                    tracing::debug!(
                        ?height,
                        "Vault is active but its set state is unavailable: \
                         the template leaves out every vault transaction"
                    );
                    VaultFilter::Unavailable
                }
            }
        };
        Self {
            height,
            vault,
            yed: hooks.yed_template_filter(height),
        }
    }

    /// A filter with the vault half running over `state` under `rules` (`None`: Vault inactive)
    /// and the YED half `yed`.
    #[cfg(test)]
    pub fn new(
        height: Height,
        vault: Option<(SetState, Rules<'static>)>,
        yed: Option<Box<dyn YedTemplateFilter>>,
    ) -> Self {
        Self {
            height,
            vault: match vault {
                Some((state, rules)) => VaultFilter::Running {
                    state: Box::new(state),
                    rules,
                },
                None => VaultFilter::Inactive,
            },
            yed,
        }
    }

    /// A filter of a template at `height` where Vault is active and its state unavailable.
    #[cfg(test)]
    pub fn unavailable(height: Height) -> Self {
        Self {
            height,
            vault: VaultFilter::Unavailable,
            yed: None,
        }
    }

    /// The running set state, `None` unless the vault half runs.
    #[cfg(test)]
    pub fn vault_state(&self) -> Option<&SetState> {
        match &self.vault {
            VaultFilter::Running { state, .. } => Some(state),
            _ => None,
        }
    }

    /// `TestForBlock`'s vault trial, the YED filter and the vault commit
    /// (`src/miner.cpp:555-609`): keep `tx` and apply its effect, or skip it and change nothing.
    pub fn keep(&mut self, tx: &VerifiedUnminedTx) -> bool {
        let height = i64::from(self.height.0);
        let delta = match &self.vault {
            VaultFilter::Inactive => None,
            VaultFilter::Unavailable => {
                if touches_primitive(tx, None) {
                    return false;
                }
                None
            }
            VaultFilter::Running { state, rules } => {
                let Some(coins) = TemplateCoins::new(tx, state, height, rules.activation_height)
                else {
                    // The spent outputs are not all known: a candidate the primitive cannot
                    // evaluate is left out; any other is a no-op for the primitive.
                    if touches_primitive(tx, Some(state)) {
                        return false;
                    }
                    if self.yed.as_mut().is_some_and(|yed| !yed.keep(tx)) {
                        return false;
                    }
                    return true;
                };
                let vtx = vault_tx(
                    tx.transaction.transaction(),
                    &tx.transaction.id().mined_id(),
                );
                match check_tx(state.as_ref(), &vtx, height, &coins, rules) {
                    Ok(delta) => Some(delta),
                    Err(reject) => {
                        tracing::debug!(
                            txid = ?tx.transaction.id().mined_id(),
                            ?height,
                            reason = reject.reason(),
                            "template filter: skipping a candidate the vault rules refuse"
                        );
                        return false;
                    }
                }
            }
        };

        if self.yed.as_mut().is_some_and(|yed| !yed.keep(tx)) {
            return false;
        }

        if let (Some(delta), VaultFilter::Running { state, .. }) = (delta, &mut self.vault) {
            state.apply(&delta);
        }
        true
    }
}

/// Does `tx` touch the vault primitive: an act, a vault or intent output (or a malformed one),
/// a spend of a vault or intent, or (with the state) a spend of an indexed template output or
/// bond?
fn touches_primitive(tx: &VerifiedUnminedTx, state: Option<&SetState>) -> bool {
    let transaction = tx.transaction.transaction();
    let template_shaped = |spk: &[u8]| {
        !matches!(match_vault(spk), Shape::NotTemplate)
            || !matches!(match_intent(spk), Shape::NotTemplate)
    };
    if transaction.outputs().iter().any(|o| {
        let spk = o.lock_script.as_raw_bytes();
        is_act_output(spk) || template_shaped(spk)
    }) {
        return true;
    }
    if tx.spent_outputs.iter().any(|o| {
        let spk = o.lock_script.as_raw_bytes();
        parse_vault(spk).is_some() || parse_intent(spk).is_some()
    }) {
        return true;
    }
    let Some(state) = state else {
        return false;
    };
    transaction.inputs().iter().any(|input| {
        input.outpoint().is_some_and(|op| {
            let op = vault_outpoint(&op);
            state.bond(&op).is_some() || state.template_out(&op).is_some()
        })
    })
}

/// The coins a candidate spends, as the vault rules read them (ycashd's `ViewCoinAccessor` over
/// the tip and the mempool at the template's height).
///
/// Script and value come from the mempool's spent outputs. Only a template coin's height is
/// read by the rules: an indexed template output's is its record's (a template output created
/// earlier in this template is indexed at the template's height by then), and a template-shaped
/// coin outside the index predates the activation height (every valid vault or intent output
/// from activation on is indexed), so it gets the height below it, which S-0 refuses.
struct TemplateCoins {
    coins: Vec<(OutPoint, SpentCoin)>,
}

impl TemplateCoins {
    /// `None` unless every transparent input of `tx` has its spent output.
    fn new(
        tx: &VerifiedUnminedTx,
        state: &SetState,
        height: i64,
        activation_height: i64,
    ) -> Option<Self> {
        let transaction = tx.transaction.transaction();
        let mut coins = Vec::new();
        for (i, input) in transaction.inputs().iter().enumerate() {
            let Some(outpoint) = input.outpoint() else {
                continue;
            };
            let spent = tx.spent_outputs.get(i)?;
            let op = vault_outpoint(&outpoint);
            let script_pubkey = spent.lock_script.as_raw_bytes().to_vec();
            let coin_height = match state.template_out(&op) {
                Some(record) => record.height,
                None if parse_vault(&script_pubkey).is_some()
                    || parse_intent(&script_pubkey).is_some() =>
                {
                    activation_height.saturating_sub(1)
                }
                None => height,
            };
            coins.push((
                op,
                SpentCoin {
                    script_pubkey,
                    value: spent.value.zatoshis(),
                    height: coin_height,
                },
            ));
        }
        Some(Self { coins })
    }
}

impl CoinAccessor for TemplateCoins {
    fn spent_coin(&self, prevout: &OutPoint) -> Option<SpentCoin> {
        self.coins
            .iter()
            .find(|(op, _)| op == prevout)
            .map(|(_, coin)| coin.clone())
    }
}

/// A Zakura outpoint in the vault crate's byte form (txid in internal order), as
/// `zakura_state`'s `vault_outpoint` converts it.
fn vault_outpoint(outpoint: &transparent::OutPoint) -> OutPoint {
    OutPoint {
        txid: Hash32(outpoint.hash.0),
        n: outpoint.index,
    }
}

/// The vault rules' view of a Zakura transaction, as `zakura_state`'s `vault_tx` builds it for
/// blocks (`service/finalized_state/zakura_db/vault.rs`).
fn vault_tx(tx: &Transaction, txid: &transaction::Hash) -> VaultTx {
    let inputs = tx
        .inputs()
        .iter()
        .map(|input| match input {
            transparent::Input::PrevOut {
                outpoint,
                unlock_script,
                ..
            } => VaultTxIn {
                prevout: vault_outpoint(outpoint),
                script_sig: unlock_script.as_raw_bytes().to_vec(),
            },
            transparent::Input::Coinbase { .. } => VaultTxIn {
                prevout: OutPoint {
                    txid: Hash32::ZERO,
                    n: u32::MAX,
                },
                script_sig: Vec::new(),
            },
        })
        .collect();
    let outputs = tx
        .outputs()
        .iter()
        .map(|output| VaultTxOut {
            value: output.value.zatoshis(),
            script_pubkey: output.lock_script.as_raw_bytes().to_vec(),
        })
        .collect();
    VaultTx {
        txid: Hash32(txid.0),
        coinbase: tx.is_coinbase(),
        inputs,
        outputs,
    }
}
