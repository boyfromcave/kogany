// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE-MIT or https://www.opensource.org/licenses/mit-license.php .

//! The transparent value pools by address type (Ycash, beta3 item 2) and the chain
//! transaction count: a node-side index, never a validity rule.
//!
//! The index mirrors ycash6's `src/valuepools.{h,cpp}`: one [`TransparentPools`] record per
//! block holds the chain totals after that block, split by the class of each output script
//! ([`classify_transparent_script`]). Nothing here can reject a block: every function is total
//! over its inputs, uses checked arithmetic and reports a failure as a value, which the callers
//! log before they leave the block without a record (its entries then say `monitored: false`).
//!
//! The record is not part of [`ValueBalance`](zakura_chain::value_balance::ValueBalance), so the
//! chain-value consensus rule is exactly where it was.

use std::sync::LazyLock;

use zakura_chain::{amount::MAX_MONEY, block, transparent};

/// The class of a transparent output script; the first match in this order wins.
///
/// ycash6 `valuepools::PoolClass`.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum PoolClass {
    /// TX_PQPKH: exactly `0x20 <keyHash:32> OP_1|OP_2 OP_CHECKPQSIG`.
    TransparentPq,
    /// TX_PQCHANNEL.
    PqChannel,
    /// TX_VAULT.
    Vault,
    /// TX_VAULT_INTENT.
    VaultIntent,
    /// Everything else: P2PKH, P2PK, P2SH, multisig, OP_RETURN, nonstandard.
    TransparentEcc,
}

/// The class of a script, with the sub-split keys (ycash6 `valuepools::ScriptClass`).
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct ScriptClass {
    /// The class.
    pub class: PoolClass,
    /// [`PoolClass::TransparentPq`]: the scheme byte (1 or 2); 0 otherwise.
    pub pq_scheme: u8,
    /// [`PoolClass::Vault`] or [`PoolClass::VaultIntent`] whose template tag is the YED module's.
    pub yed: bool,
}

/// The class of `script`. Pure and byte-level: the same answer on every node, whatever its
/// options (ycash6 `ClassifyTransparentScript`, with kogany's matchers in the same order).
pub fn classify_transparent_script(script: &transparent::Script) -> ScriptClass {
    use kogany_yellowback::codecs::script::{match_pq_channel, YED_TAG};

    let class = |class, pq_scheme, yed| ScriptClass {
        class,
        pq_scheme,
        yed,
    };

    if let Some(id) = script.pq_key_id() {
        return class(PoolClass::TransparentPq, id.scheme, false);
    }
    let bytes = script.as_raw_bytes();
    if match_pq_channel(bytes).is_some() {
        return class(PoolClass::PqChannel, 0, false);
    }
    if let Some(vault) = kogany_vault::template::parse_vault(bytes) {
        return class(PoolClass::Vault, 0, vault.tag == YED_TAG);
    }
    if let Some(intent) = kogany_vault::template::parse_intent(bytes) {
        return class(PoolClass::VaultIntent, 0, intent.tag == YED_TAG);
    }
    class(PoolClass::TransparentEcc, 0, false)
}

/// Why a block has no record. Never an error of the block: the callers log it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TransparentPoolsError {
    /// The parent's record is out of range.
    ParentOutOfRange,
    /// An input's spent output is not in the supplied set.
    MissingSpentOutput(transparent::OutPoint),
    /// A total leaves its range.
    TotalOutOfRange,
}

impl std::fmt::Display for TransparentPoolsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ParentOutOfRange => write!(f, "the parent's record is out of range"),
            Self::MissingSpentOutput(outpoint) => {
                write!(f, "the output spent by {outpoint:?} is not available")
            }
            Self::TotalOutOfRange => write!(f, "a total leaves its range"),
        }
    }
}

/// The chain totals after one block, in zatoshis (ycash6 `valuepools::Record`).
///
/// `transparent_ecc` is derived (transparent minus the rest), so the classes sum to the total
/// by construction.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct TransparentPools {
    /// Every transparent output.
    pub transparent: i64,
    /// `transparent_pq`, scheme 1 (SLH-DSA-SHA2-128s).
    pub pq1: i64,
    /// `transparent_pq`, scheme 2 (FN-DSA-512).
    pub pq2: i64,
    /// `pq_channel`.
    pub channel: i64,
    /// `vault`.
    pub vault: i64,
    /// `vault_intent`.
    pub intent: i64,
    /// The YED module's part of `vault`.
    pub vault_yed: i64,
    /// The YED module's part of `vault_intent`.
    pub intent_yed: i64,
}

/// A signed running total: wide enough that no sum of 64-bit amounts can overflow it.
#[derive(Copy, Clone, Default)]
struct Wide([i128; 8]);

impl Wide {
    fn add_output(&mut self, output: &transparent::Output, sign: i128) {
        let value = sign * i128::from(i64::from(output.value()));
        let class = classify_transparent_script(&output.lock_script);
        self.0[0] += value;
        match class.class {
            PoolClass::TransparentPq => {
                if class.pq_scheme == 1 {
                    self.0[1] += value
                } else {
                    self.0[2] += value
                }
            }
            PoolClass::PqChannel => self.0[3] += value,
            PoolClass::Vault => {
                self.0[4] += value;
                if class.yed {
                    self.0[6] += value
                }
            }
            PoolClass::VaultIntent => {
                self.0[5] += value;
                if class.yed {
                    self.0[7] += value
                }
            }
            PoolClass::TransparentEcc => {}
        }
    }
}

impl TransparentPools {
    /// The length of [`Self::to_bytes`].
    pub const DISK_LEN: usize = 1 + 8 * 8;
    /// The record version byte.
    const DISK_VERSION: u8 = 1;

    fn amounts(&self) -> [i64; 8] {
        [
            self.transparent,
            self.pq1,
            self.pq2,
            self.channel,
            self.vault,
            self.intent,
            self.vault_yed,
            self.intent_yed,
        ]
    }

    fn from_amounts(v: [i64; 8]) -> Self {
        let [transparent, pq1, pq2, channel, vault, intent, vault_yed, intent_yed] = v;
        Self {
            transparent,
            pq1,
            pq2,
            channel,
            vault,
            intent,
            vault_yed,
            intent_yed,
        }
    }

    /// `transparent_pq`: both schemes.
    pub fn transparent_pq(&self) -> i64 {
        self.pq1.saturating_add(self.pq2)
    }

    /// `transparent_ecc`: the total minus every other class.
    pub fn transparent_ecc(&self) -> i64 {
        let rest: i128 = [self.pq1, self.pq2, self.channel, self.vault, self.intent]
            .into_iter()
            .map(i128::from)
            .sum();
        i64::try_from(i128::from(self.transparent) - rest).unwrap_or(i64::MIN)
    }

    /// The YED module's part of `vault` plus `vault_intent`.
    pub fn yed(&self) -> i64 {
        self.vault_yed.saturating_add(self.intent_yed)
    }

    /// Every stored amount and the derived ECC amount is non-negative and within `MAX_MONEY`
    /// (ycash6 `Record::IsSane`).
    pub fn is_sane(&self) -> bool {
        let in_range = |v: i64| (0..=MAX_MONEY).contains(&v);
        self.amounts().into_iter().all(in_range)
            && self.vault_yed <= self.vault
            && self.intent_yed <= self.intent
            && in_range(self.transparent_ecc())
    }

    /// The record after a block, from its parent's record, the block's outputs and the outputs
    /// its inputs spend (ycash6 `ApplyBlock`).
    ///
    /// `spent` returns the output an outpoint spends, including outputs created earlier in the
    /// same block. The genesis block's parent is [`TransparentPools::default`].
    pub fn apply_block<'a>(
        &self,
        block: &block::Block,
        spent: impl Fn(&transparent::OutPoint) -> Option<&'a transparent::Output>,
    ) -> Result<Self, TransparentPoolsError> {
        if !self.is_sane() {
            return Err(TransparentPoolsError::ParentOutOfRange);
        }
        let mut wide = Wide(self.amounts().map(i128::from));
        for transaction in &block.transactions {
            for input in transaction.inputs() {
                // A coinbase input spends nothing.
                let Some(outpoint) = input.outpoint() else {
                    continue;
                };
                let output =
                    spent(&outpoint).ok_or(TransparentPoolsError::MissingSpentOutput(outpoint))?;
                wide.add_output(output, -1);
            }
            for output in transaction.outputs() {
                wide.add_output(output, 1);
            }
        }
        let mut amounts = [0i64; 8];
        for (amount, wide) in amounts.iter_mut().zip(wide.0) {
            *amount = i64::try_from(wide).map_err(|_| TransparentPoolsError::TotalOutOfRange)?;
        }
        let record = Self::from_amounts(amounts);
        if !record.is_sane() {
            return Err(TransparentPoolsError::TotalOutOfRange);
        }
        Ok(record)
    }

    /// The on-disk form: a version byte, then the eight amounts as little-endian `u64`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(Self::DISK_LEN);
        bytes.push(Self::DISK_VERSION);
        for amount in self.amounts() {
            bytes.extend_from_slice(&amount.to_le_bytes());
        }
        bytes
    }

    /// The record in `bytes`, or `None` for an unknown version, a wrong length or totals out of
    /// range (a corrupt row): nothing is ever computed from such a row.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let (version, rest) = bytes.split_first()?;
        let (chunks, []) = rest.as_chunks::<8>() else {
            return None;
        };
        if *version != Self::DISK_VERSION {
            return None;
        }
        let amounts: [[u8; 8]; 8] = chunks.try_into().ok()?;
        let amounts = amounts.map(i64::from_le_bytes);
        let record = Self::from_amounts(amounts);
        record.is_sane().then_some(record)
    }
}

/// A compiled seed: the chain totals at a block of the network's history (ycash6
/// `valuepools::Seed`).
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct TransparentPoolsSeed {
    /// The seed block's height.
    pub height: block::Height,
    /// The seed block's hash.
    pub hash: block::Hash,
    /// The totals after the seed block.
    pub record: TransparentPools,
}

/// The height of the compiled seed: ycash6's mainnet chain-supply checkpoint
/// (`chainparams.cpp` `nChainSupplyCheckpointHeight`).
const SEED_HEIGHT: u32 = 2_800_000;
/// The seed block's hash (`hashChainSupplyCheckpointBlock`).
const SEED_HASH: &str = "000003170414909d5104f4a71708eca4e5b545d231c412c2d3e0e3f33874facb";
/// The transparent value after the seed block (`nChainSupplyCheckpointTransparentValue`).
const SEED_TRANSPARENT: i64 = 1_053_104_265_390_951;

/// The compiled seed.
///
/// It names its block by hash, so it applies to every chain that contains that block: Ycash
/// mainnet and the testnets that share mainnet below their split. The claim behind it is that no
/// output at or below the seed height matches a PQ, channel, vault or intent template, so every
/// class but `transparent` is 0 there. The C++ line checked the claim on mainnet on 2026-11-15
/// (a fill from genesis matched the seed, ycash6 `valuepools.cpp` `SEED_CHECKED_MAX_HEIGHT`), and
/// a node that syncs from genesis checks it again as it commits the seed block.
///
/// The hash is parsed once; every block write asks for the seed.
pub fn compiled_seed() -> Option<TransparentPoolsSeed> {
    static SEED: LazyLock<Option<TransparentPoolsSeed>> = LazyLock::new(|| {
        Some(TransparentPoolsSeed {
            height: block::Height(SEED_HEIGHT),
            hash: SEED_HASH.parse().ok()?,
            record: TransparentPools {
                transparent: SEED_TRANSPARENT,
                ..TransparentPools::default()
            },
        })
    });
    *SEED
}

/// What a block's index rows say (the read side of the index).
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct BlockIndexInfo {
    /// The number of transactions in the chain up to and including the block (ycash6
    /// `nChainTx`), or `None` when the node does not know it.
    pub chain_tx_count: Option<u64>,
    /// The transparent pools after the block, or `None` when the index does not cover it.
    pub pools: Option<TransparentPools>,
    /// The transparent pools after the block's parent (all zero for the genesis block), or
    /// `None` when the index does not cover the parent.
    pub parent_pools: Option<TransparentPools>,
}

#[cfg(test)]
mod tests;
