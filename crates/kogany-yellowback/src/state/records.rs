// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

//! The YED state's records (ycash6 `src/yellowback/view.h` at `65cb4ae0f`, §3.6) other than the
//! attest-side ones of [`crate::attest::registry`], and their canonical encodings: each
//! `encode` is the C++ `SerializeRecord` (`SER_DISK`) byte for byte, so the `yed_getstatehash`
//! preimage (key ‖ value, [`super::state_hash`]) is the C++ one; each `decode` parses exactly
//! that and nothing else (trailing bytes fail). Field order and widths are the C++
//! `SerializationOp`s'; the fields appended by later schema versions are last, as there.

use kogany_vault::{Hash32, OutPoint};

use super::codec::{Reader, Writer};
use crate::attest::registry::AttestState;
use crate::params::{Amount, Cents, MicroUsd, Params};

/// `SCHEMA_VERSION`: 15 (`Totals.openDebtCents`, `Snapshot.openDebtCents`); written in the tip.
pub const SCHEMA_VERSION: u32 = 15;

/// The null `COutPoint` (`SetNull`: zero txid, `n = 0xffffffff`): `IntentRecord.heldBy` when no
/// cancel holds the residual.
pub const NULL_OUTPOINT: OutPoint = OutPoint {
    txid: Hash32::ZERO,
    n: u32::MAX,
};

/// `COutPoint::IsNull`.
pub fn is_null_outpoint(o: &OutPoint) -> bool {
    *o == NULL_OUTPOINT
}

/// The serialised `AttestState` (status u8, triggerHeight, armHeight).
fn put_attest(w: &mut Writer, a: &AttestState) {
    w.raw(&a.encode());
}

fn get_attest(r: &mut Reader<'_>) -> Option<AttestState> {
    AttestState::decode(r.raw(9)?)
}

// ---------------------------------------------------------------- Tip, Tags, Judgements

/// `Tip` (`T`): the last applied block.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TipRecord {
    /// Its height.
    pub height: i32,
    /// Its hash, internal byte order.
    pub block_hash: Hash32,
    /// [`SCHEMA_VERSION`].
    pub schema_version: u32,
    /// `Params::network`.
    pub network: String,
}

impl TipRecord {
    /// The zero tip the state hash carries before any block (`TipRecord()` with `network`).
    pub fn zero(network: &str) -> TipRecord {
        TipRecord {
            height: 0,
            block_hash: Hash32::ZERO,
            schema_version: SCHEMA_VERSION,
            network: network.to_owned(),
        }
    }

    /// The canonical serialisation.
    pub fn encode(&self) -> Vec<u8> {
        Writer::new()
            .i32(self.height)
            .hash(&self.block_hash)
            .u32(self.schema_version)
            .bytes(self.network.as_bytes())
            .finish()
    }

    /// Parses [`TipRecord::encode`].
    pub fn decode(b: &[u8]) -> Option<TipRecord> {
        let mut r = Reader(b);
        let v = TipRecord {
            height: r.i32()?,
            block_hash: r.hash()?,
            schema_version: r.u32()?,
            network: r.string()?,
        };
        r.done().then_some(v)
    }
}

/// `Tags[height]` (`Q`): a valid coinbase tag (TAG-1..5).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TagRecord {
    /// Hash160 of the miner's fee key.
    pub payout_key: [u8; 20],
    /// The quote; 0 = signal-only (TAG-3).
    pub price_micro_usd: u64,
    /// Flag bit 0.
    pub signal: bool,
    /// The informational source mask.
    pub source_mask: u16,
}

impl TagRecord {
    /// `IsQuote`.
    pub fn is_quote(&self) -> bool {
        self.price_micro_usd != 0
    }

    /// The canonical serialisation (31 bytes).
    pub fn encode(&self) -> Vec<u8> {
        Writer::new()
            .raw(&self.payout_key)
            .u64(self.price_micro_usd)
            .bool(self.signal)
            .u16(self.source_mask)
            .finish()
    }

    /// Parses [`TagRecord::encode`].
    pub fn decode(b: &[u8]) -> Option<TagRecord> {
        let mut r = Reader(b);
        let v = TagRecord {
            payout_key: r.take()?,
            price_micro_usd: r.u64()?,
            signal: r.bool()?,
            source_mask: r.u16()?,
        };
        r.done().then_some(v)
    }
}

/// `Judgements[t]` (`J`): REG-4 for the quote tag at `t`, written when block `t + PEER_LAG` is
/// applied.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Judgement {
    /// False when fewer than `PEER_MIN` peers quoted around `t`.
    pub evaluated: bool,
    /// Within `ACCURACY_BAND_BPS` of the peers' median.
    pub in_band: bool,
    /// Beyond `DEVIATION_BPS`.
    pub penalized: bool,
}

impl Judgement {
    /// The canonical serialisation (3 bytes).
    pub fn encode(&self) -> Vec<u8> {
        Writer::new()
            .bool(self.evaluated)
            .bool(self.in_band)
            .bool(self.penalized)
            .finish()
    }

    /// Parses [`Judgement::encode`].
    pub fn decode(b: &[u8]) -> Option<Judgement> {
        let mut r = Reader(b);
        let v = Judgement {
            evaluated: r.bool()?,
            in_band: r.bool()?,
            penalized: r.bool()?,
        };
        r.done().then_some(v)
    }
}

// ---------------------------------------------------------------- Vaults, Tokens

/// `Vaults.status`, declaration order. `Voided` is never produced since the vault upgrade (a
/// failing mint is invalid); `Claiming` is a vault whose claim intents await `CLAIM_DELAY`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub enum VaultStatus {
    /// 0.
    Active,
    /// 1 (the C++ default record's status).
    #[default]
    Voided,
    /// 2: redeemed by its owner.
    Closed,
    /// 3: its claimant intent was released.
    Claimed,
    /// 4: claimed, the intents pending.
    Claiming,
}

impl VaultStatus {
    /// The serialised byte.
    pub const fn to_u8(self) -> u8 {
        match self {
            VaultStatus::Active => 0,
            VaultStatus::Voided => 1,
            VaultStatus::Closed => 2,
            VaultStatus::Claimed => 3,
            VaultStatus::Claiming => 4,
        }
    }

    /// The status of a byte; `None` outside `0..=4`.
    pub const fn from_u8(b: u8) -> Option<VaultStatus> {
        match b {
            0 => Some(VaultStatus::Active),
            1 => Some(VaultStatus::Voided),
            2 => Some(VaultStatus::Closed),
            3 => Some(VaultStatus::Claimed),
            4 => Some(VaultStatus::Claiming),
            _ => None,
        }
    }

    /// `VaultStatusName` (RPC).
    pub const fn name(self) -> &'static str {
        match self {
            VaultStatus::Active => "ACTIVE",
            VaultStatus::Voided => "VOID",
            VaultStatus::Closed => "CLOSED",
            VaultStatus::Claimed => "CLAIMED",
            VaultStatus::Claiming => "CLAIMING",
        }
    }
}

/// `Vaults[outpoint]` (`V`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VaultRecord {
    /// The 33 MINT payload owner bytes verbatim, `scheme || keyHash` (serialised as a byte
    /// vector).
    pub owner_pub_key: [u8; 33],
    /// The payload's class byte (0/1/2 = A/B/C).
    pub term_class: u8,
    /// The term's end.
    pub lock_height: i32,
    /// `lockHeight + GRACE`.
    pub claim_height: i32,
    /// The V output's value (the mint's vout 0, or a cancel's re-lock).
    pub collateral_zat: Amount,
    /// The debt.
    pub minted_cents: Cents,
    /// The mint's height.
    pub mint_height: i32,
    /// The mint's reference height.
    pub ref_height: i32,
    /// The status.
    pub status: VaultStatus,
    /// Always empty since the vault upgrade.
    pub void_reason: String,
    /// The closing (redeem or claim) height; 0 while open.
    pub close_height: i32,
    /// The closing transaction.
    pub closing_txid: Hash32,
    /// IN-3's burn of the closing transaction.
    pub burned_cents: Cents,
    /// The mint's fee, rewritten by a passing redeem or claim (0 under FEE-0).
    pub fee_paid_zat: Amount,
    /// Always false since the vault upgrade.
    pub unbacked: bool,
    /// The V's `appHeight` (`refHeight + 1`, IT-1).
    pub app_height: i32,
    /// The V's `ownerHeight` (`refHeight + 1`, IT-1 extended).
    pub owner_height: i32,
    /// FEE-1′ (D-Q-23): MINT-5's price, the fee price of every later spend.
    pub p_mint: MicroUsd,
    /// CAN-2: the position's counted cancels, `min(q + 1, 255)` after each.
    pub cancel_count: u8,
    /// CAN-2: the height of the position's last cancel; 0 = none.
    pub last_cancel_height: i32,
}

impl VaultRecord {
    /// `IsOpen`: ACTIVE or VOID.
    pub fn is_open(&self) -> bool {
        matches!(self.status, VaultStatus::Active | VaultStatus::Voided)
    }

    /// `Owner()`: the owner bytes as `scheme || keyHash`.
    pub fn owner(&self) -> kogany_vault::PqOwner {
        crate::codecs::script::owner_from_bytes(&self.owner_pub_key)
    }

    /// The canonical serialisation.
    pub fn encode(&self) -> Vec<u8> {
        Writer::new()
            .bytes(&self.owner_pub_key)
            .u8(self.term_class)
            .i32(self.lock_height)
            .i32(self.claim_height)
            .i64(self.collateral_zat)
            .i64(self.minted_cents)
            .i32(self.mint_height)
            .i32(self.ref_height)
            .u8(self.status.to_u8())
            .bytes(self.void_reason.as_bytes())
            .i32(self.close_height)
            .hash(&self.closing_txid)
            .i64(self.burned_cents)
            .i64(self.fee_paid_zat)
            .bool(self.unbacked)
            .i32(self.app_height)
            .i32(self.owner_height)
            .i64(self.p_mint)
            .u8(self.cancel_count)
            .i32(self.last_cancel_height)
            .finish()
    }

    /// Parses [`VaultRecord::encode`]; the owner must be 33 bytes and the status known.
    pub fn decode(b: &[u8]) -> Option<VaultRecord> {
        let mut r = Reader(b);
        let v = VaultRecord {
            owner_pub_key: <[u8; 33]>::try_from(r.bytes()?.as_slice()).ok()?,
            term_class: r.u8()?,
            lock_height: r.i32()?,
            claim_height: r.i32()?,
            collateral_zat: r.i64()?,
            minted_cents: r.i64()?,
            mint_height: r.i32()?,
            ref_height: r.i32()?,
            status: VaultStatus::from_u8(r.u8()?)?,
            void_reason: r.string()?,
            close_height: r.i32()?,
            closing_txid: r.hash()?,
            burned_cents: r.i64()?,
            fee_paid_zat: r.i64()?,
            unbacked: r.bool()?,
            app_height: r.i32()?,
            owner_height: r.i32()?,
            p_mint: r.i64()?,
            cancel_count: r.u8()?,
            last_cancel_height: r.i32()?,
        };
        r.done().then_some(v)
    }
}

/// `Tokens[outpoint]` (`K`): a YED holding.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TokenRecord {
    /// The YED, cents.
    pub cents: Cents,
    /// The carrier output's value.
    pub n_value: Amount,
    /// The holder script.
    pub script_pub_key: Vec<u8>,
    /// The creating height.
    pub height: i32,
}

impl TokenRecord {
    /// The canonical serialisation.
    pub fn encode(&self) -> Vec<u8> {
        Writer::new()
            .i64(self.cents)
            .i64(self.n_value)
            .bytes(&self.script_pub_key)
            .i32(self.height)
            .finish()
    }

    /// Parses [`TokenRecord::encode`].
    pub fn decode(b: &[u8]) -> Option<TokenRecord> {
        let mut r = Reader(b);
        let v = TokenRecord {
            cents: r.i64()?,
            n_value: r.i64()?,
            script_pub_key: r.bytes()?,
            height: r.i32()?,
        };
        r.done().then_some(v)
    }
}

/// One created or spent YED output in a TxLog entry (`AssignedOutput`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AssignedOutput {
    /// The output.
    pub outpoint: OutPoint,
    /// Its YED, cents.
    pub cents: Cents,
    /// Its script.
    pub script_pub_key: Vec<u8>,
}

impl AssignedOutput {
    fn put(w: &mut Writer, a: &AssignedOutput) {
        w.outpoint(&a.outpoint)
            .i64(a.cents)
            .bytes(&a.script_pub_key);
    }

    fn get(r: &mut Reader<'_>) -> Option<AssignedOutput> {
        Some(AssignedOutput {
            outpoint: r.outpoint()?,
            cents: r.i64()?,
            script_pub_key: r.bytes()?,
        })
    }
}

// ---------------------------------------------------------------- TxLog

/// `TxLog.type`: the payload family a transaction was processed as.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub enum TxLogType {
    /// 0: no Yellowback payload rule (inputs only).
    #[default]
    None,
    /// 1.
    Mint,
    /// 2.
    Transfer,
    /// 3: any ACTIVE-vault spend (M3), or a REDEEM payload spending none.
    Redeem,
    /// 4: a SET_JOIN to the attestor set (P4-b); the retired payload of that name.
    AttestorRegister,
    /// 5.
    ClaimNotice,
    /// 6.
    Equivocation,
    /// 7: the retired payload (never written since P4-b).
    AttestorRevive,
    /// 8: a claim intent's release (selector 1).
    ClaimRelease,
    /// 9: a claimant intent's attestor cancel (selector 2).
    ClaimCancel,
    /// 10: a set act of the attestor set other than a join.
    AttestorSetAct,
}

impl TxLogType {
    /// The serialised byte.
    pub const fn to_u8(self) -> u8 {
        match self {
            TxLogType::None => 0,
            TxLogType::Mint => 1,
            TxLogType::Transfer => 2,
            TxLogType::Redeem => 3,
            TxLogType::AttestorRegister => 4,
            TxLogType::ClaimNotice => 5,
            TxLogType::Equivocation => 6,
            TxLogType::AttestorRevive => 7,
            TxLogType::ClaimRelease => 8,
            TxLogType::ClaimCancel => 9,
            TxLogType::AttestorSetAct => 10,
        }
    }

    /// The type of a byte; `None` outside `0..=10`.
    pub const fn from_u8(b: u8) -> Option<TxLogType> {
        match b {
            0 => Some(TxLogType::None),
            1 => Some(TxLogType::Mint),
            2 => Some(TxLogType::Transfer),
            3 => Some(TxLogType::Redeem),
            4 => Some(TxLogType::AttestorRegister),
            5 => Some(TxLogType::ClaimNotice),
            6 => Some(TxLogType::Equivocation),
            7 => Some(TxLogType::AttestorRevive),
            8 => Some(TxLogType::ClaimRelease),
            9 => Some(TxLogType::ClaimCancel),
            10 => Some(TxLogType::AttestorSetAct),
            _ => None,
        }
    }

    /// `TxLogTypeName` (RPC).
    pub const fn name(self) -> &'static str {
        match self {
            TxLogType::None => "NONE",
            TxLogType::Mint => "MINT",
            TxLogType::Transfer => "TRANSFER",
            TxLogType::Redeem => "REDEEM",
            TxLogType::AttestorRegister => "ATTESTOR_REGISTER",
            TxLogType::ClaimNotice => "CLAIM_NOTICE",
            TxLogType::Equivocation => "EQUIVOCATION",
            TxLogType::AttestorRevive => "ATTESTOR_REVIVE",
            TxLogType::ClaimRelease => "CLAIM_RELEASE",
            TxLogType::ClaimCancel => "CLAIM_CANCEL",
            TxLogType::AttestorSetAct => "ATTESTOR_SET_ACT",
        }
    }
}

/// `TxLog[txid]` (`L`): one entry per transaction that created or spent a Tokens / Vaults entry
/// (N7). History only: in the store and the undo, never in the state hash.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TxLogRecord {
    /// The block height.
    pub height: i32,
    /// The payload family.
    pub tx_type: TxLogType,
    /// `"owner"` | `"claim"` | `""` (vault spends only).
    pub path: String,
    /// The §4.2a verdict string ([`super::verdict`]).
    pub verdict: String,
    /// The YED the inputs carried.
    pub yed_in: Cents,
    /// Cents assigned (XFER/RED), minted (MINT) or refunded (a cancel).
    pub yed_out: Cents,
    /// IN-3's burn.
    pub burned: Cents,
    /// The protocol fee paid (0 under FEE-0 or on failure).
    pub fee_zat: Amount,
    /// `payee` is set.
    pub has_payee: bool,
    /// The fee output's key hash.
    pub payee: [u8; 20],
    /// The YED outputs created.
    pub assigned: Vec<AssignedOutput>,
    /// The Tokens consumed, in input order.
    pub spent_tokens: Vec<AssignedOutput>,
    /// The vaults this transaction closed or claimed.
    pub closed_vaults: Vec<OutPoint>,
    /// The bundle's `aMint` when BUNDLE-1 held (0 = undefined).
    pub a_mint: i64,
    /// The bundle's `aClaim`.
    pub a_claim: i64,
    /// The verified bundle's seqs in bundle order (or a cancel's counted co-signers, or EQV-1's
    /// evidence seq).
    pub bundle_seqs: Vec<u16>,
    /// The attestor fee paid.
    pub attest_fee_zat: Amount,
    /// `attest_payee` is set.
    pub has_attest_payee: bool,
    /// The seq whose bond key received the attestor fee.
    pub attest_payee: u16,
    /// RED-5's residual.
    pub residual_zat: Amount,
    /// `"a"` | `"b"` | `""`: the RED-4 clause of a passing claim.
    pub claim_path: String,
    /// This transaction wrote a Notices record (NOT-1).
    pub notice: bool,
    /// The seq a join assigned, an act moved or EQV-1 ejected.
    pub attestor_seq: u16,
    /// The vault a cancel re-created.
    pub reopened_vaults: Vec<OutPoint>,
}

impl TxLogRecord {
    /// `AMint`: `a_mint` when positive.
    pub fn a_mint(&self) -> Option<MicroUsd> {
        (self.a_mint > 0).then_some(self.a_mint)
    }

    /// `AClaim`: `a_claim` when positive.
    pub fn a_claim(&self) -> Option<MicroUsd> {
        (self.a_claim > 0).then_some(self.a_claim)
    }

    /// The canonical serialisation.
    pub fn encode(&self) -> Vec<u8> {
        Writer::new()
            .i32(self.height)
            .u8(self.tx_type.to_u8())
            .bytes(self.path.as_bytes())
            .bytes(self.verdict.as_bytes())
            .i64(self.yed_in)
            .i64(self.yed_out)
            .i64(self.burned)
            .i64(self.fee_zat)
            .bool(self.has_payee)
            .raw(&self.payee)
            .vec(&self.assigned, AssignedOutput::put)
            .vec(&self.spent_tokens, AssignedOutput::put)
            .vec(&self.closed_vaults, |w, o| {
                w.outpoint(o);
            })
            .i64(self.a_mint)
            .i64(self.a_claim)
            .vec(&self.bundle_seqs, |w, s| {
                w.u16(*s);
            })
            .i64(self.attest_fee_zat)
            .bool(self.has_attest_payee)
            .u16(self.attest_payee)
            .i64(self.residual_zat)
            .bytes(self.claim_path.as_bytes())
            .bool(self.notice)
            .u16(self.attestor_seq)
            .vec(&self.reopened_vaults, |w, o| {
                w.outpoint(o);
            })
            .finish()
    }

    /// Parses [`TxLogRecord::encode`].
    pub fn decode(b: &[u8]) -> Option<TxLogRecord> {
        let mut r = Reader(b);
        let v = TxLogRecord {
            height: r.i32()?,
            tx_type: TxLogType::from_u8(r.u8()?)?,
            path: r.string()?,
            verdict: r.string()?,
            yed_in: r.i64()?,
            yed_out: r.i64()?,
            burned: r.i64()?,
            fee_zat: r.i64()?,
            has_payee: r.bool()?,
            payee: r.take()?,
            assigned: r.vec(AssignedOutput::get)?,
            spent_tokens: r.vec(AssignedOutput::get)?,
            closed_vaults: r.vec(Reader::outpoint)?,
            a_mint: r.i64()?,
            a_claim: r.i64()?,
            bundle_seqs: r.vec(Reader::u16)?,
            attest_fee_zat: r.i64()?,
            has_attest_payee: r.bool()?,
            attest_payee: r.u16()?,
            residual_zat: r.i64()?,
            claim_path: r.string()?,
            notice: r.bool()?,
            attestor_seq: r.u16()?,
            reopened_vaults: r.vec(Reader::outpoint)?,
        };
        r.done().then_some(v)
    }
}

// ---------------------------------------------------------------- Totals

/// `Totals` (`G`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Totals {
    /// YED in circulation, cents.
    pub supply_cents: Cents,
    /// The collateral of the ACTIVE and CLAIMING vaults (IT-6).
    pub collateral_zat: Amount,
    /// ACTIVE vaults.
    pub active_vaults: u32,
    /// VOID vaults (none since the vault upgrade).
    pub void_vaults: u32,
    /// CLOSED vaults.
    pub closed_vaults: u32,
    /// CLAIMED vaults.
    pub claimed_vaults: u32,
    /// Always 0 since the vault upgrade.
    pub unbacked_cents: Cents,
    /// HALT-2's denominator: the `mintedCents` of every ACTIVE and CLAIMING vault.
    pub open_debt_cents: Cents,
}

impl Totals {
    /// The canonical serialisation (48 bytes).
    pub fn encode(&self) -> Vec<u8> {
        Writer::new()
            .i64(self.supply_cents)
            .i64(self.collateral_zat)
            .u32(self.active_vaults)
            .u32(self.void_vaults)
            .u32(self.closed_vaults)
            .u32(self.claimed_vaults)
            .i64(self.unbacked_cents)
            .i64(self.open_debt_cents)
            .finish()
    }

    /// Parses [`Totals::encode`].
    pub fn decode(b: &[u8]) -> Option<Totals> {
        let mut r = Reader(b);
        let v = Totals {
            supply_cents: r.i64()?,
            collateral_zat: r.i64()?,
            active_vaults: r.u32()?,
            void_vaults: r.u32()?,
            closed_vaults: r.u32()?,
            claimed_vaults: r.u32()?,
            unbacked_cents: r.i64()?,
            open_debt_cents: r.i64()?,
        };
        r.done().then_some(v)
    }
}

// ---------------------------------------------------------------- Notices, Intents

/// `Notices[vaultOutpoint]` (`E`, NOT-1): a standing CLAIM_NOTICE; deleted when the vault leaves
/// ACTIVE.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NoticeRecord {
    /// The notice's height.
    pub height: i32,
    /// Its reference height.
    pub ref_height: i32,
    /// The `pEmerg` it was judged at.
    pub p_emerg: MicroUsd,
}

impl NoticeRecord {
    /// The canonical serialisation (16 bytes).
    pub fn encode(&self) -> Vec<u8> {
        Writer::new()
            .i32(self.height)
            .i32(self.ref_height)
            .i64(self.p_emerg)
            .finish()
    }

    /// Parses [`NoticeRecord::encode`].
    pub fn decode(b: &[u8]) -> Option<NoticeRecord> {
        let mut r = Reader(b);
        let v = NoticeRecord {
            height: r.i32()?,
            ref_height: r.i32()?,
            p_emerg: r.i64()?,
        };
        r.done().then_some(v)
    }
}

/// `IntentRecord.role`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub enum IntentRole {
    /// 0: the claimant's debt-worth.
    #[default]
    Claimant,
    /// 1: the owner's residual (RED-5).
    Residual,
}

impl IntentRole {
    /// The serialised byte.
    pub const fn to_u8(self) -> u8 {
        match self {
            IntentRole::Claimant => 0,
            IntentRole::Residual => 1,
        }
    }

    /// The role of a byte; `None` outside `0..=1`.
    pub const fn from_u8(b: u8) -> Option<IntentRole> {
        match b {
            0 => Some(IntentRole::Claimant),
            1 => Some(IntentRole::Residual),
            _ => None,
        }
    }
}

/// `Intents[intentOutpoint]` (`I`, U-23): a claim's intent output and the vault it was claimed
/// from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IntentRecord {
    /// The claimed vault's outpoint (its record is CLAIMING).
    pub vault: OutPoint,
    /// The claimant's or the owner's residual.
    pub role: IntentRole,
    /// The claim's height.
    pub height: i32,
    /// CAN-1: on the claimant intent, the script of the YED token the claim spent at its
    /// lowest-index YED input (the cancel's refund holder); empty on the residual.
    pub refund_script: Vec<u8>,
    /// C4b: the claim's REDEEM `refHeight`, on both intents.
    pub claim_ref_height: i32,
    /// CAN-3: on a residual whose claimant intent was cancelled, the re-created position;
    /// [`NULL_OUTPOINT`] otherwise.
    pub held_by: OutPoint,
}

impl Default for IntentRecord {
    fn default() -> IntentRecord {
        IntentRecord {
            vault: NULL_OUTPOINT,
            role: IntentRole::Claimant,
            height: 0,
            refund_script: Vec::new(),
            claim_ref_height: 0,
            held_by: NULL_OUTPOINT,
        }
    }
}

impl IntentRecord {
    /// The canonical serialisation.
    pub fn encode(&self) -> Vec<u8> {
        Writer::new()
            .outpoint(&self.vault)
            .u8(self.role.to_u8())
            .i32(self.height)
            .bytes(&self.refund_script)
            .i32(self.claim_ref_height)
            .outpoint(&self.held_by)
            .finish()
    }

    /// Parses [`IntentRecord::encode`].
    pub fn decode(b: &[u8]) -> Option<IntentRecord> {
        let mut r = Reader(b);
        let v = IntentRecord {
            vault: r.outpoint()?,
            role: IntentRole::from_u8(r.u8()?)?,
            height: r.i32()?,
            refund_script: r.bytes()?,
            claim_ref_height: r.i32()?,
            held_by: r.outpoint()?,
        };
        r.done().then_some(v)
    }
}

// ---------------------------------------------------------------- Snapshots

/// `Snapshots[H]` (`S`). Undefined prices and ratios are 0 (`PRICE_MIN` is 100, so 0 is never a
/// value); `sigma_mult_bps` is always defined.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Snapshot {
    /// The block's hash.
    pub block_hash: Hash32,
    /// The block carried a valid tag.
    pub tagged: bool,
    /// ... a quote.
    pub quote: bool,
    /// PRICE-1 medians; `p_mint` / `p_claim` are the cross-section `xMint` / `xClaim`.
    pub p_fast: i64,
    /// The mid window's median.
    pub p_mid: i64,
    /// The slow window's median.
    pub p_slow: i64,
    /// `min(pFast, pMid, pSlow)`.
    pub p_mint: i64,
    /// `max(pMid, pSlow)`.
    pub p_claim: i64,
    /// SIGMA-1.
    pub sigma_mult_bps: i32,
    /// The circulating supply at H (D-Q-25).
    pub issued_zat: Amount,
    /// `Totals.supplyCents` at H.
    pub supply_cents: Cents,
    /// `Totals.collateralZat` at H.
    pub collateral_zat: Amount,
    /// HALT-2's ratio; 0 = undefined.
    pub global_ratio_bps: i64,
    /// The halt bits ([`crate::attest::price`]).
    pub halt_mask: u32,
    /// The carried arming state after ARM-1/2 at H.
    pub attest: AttestState,
    /// The seated seqs, ascending.
    pub seated: Vec<u16>,
    /// PIN-1: payout keys excluded from the medians and E(H), ascending.
    pub pinned_keys: Vec<[u8; 20]>,
    /// PIN-2: seqs excluded from selection at H.
    pub pinned_seqs: Vec<u16>,
    /// `Totals.openDebtCents` at H.
    pub open_debt_cents: Cents,
}

impl Default for Snapshot {
    fn default() -> Snapshot {
        Snapshot {
            block_hash: Hash32::ZERO,
            tagged: false,
            quote: false,
            p_fast: 0,
            p_mid: 0,
            p_slow: 0,
            p_mint: 0,
            p_claim: 0,
            sigma_mult_bps: 10_000,
            issued_zat: 0,
            supply_cents: 0,
            collateral_zat: 0,
            global_ratio_bps: 0,
            halt_mask: 0,
            attest: AttestState::default(),
            seated: Vec::new(),
            pinned_keys: Vec::new(),
            pinned_seqs: Vec::new(),
            open_debt_cents: 0,
        }
    }
}

fn price(v: i64) -> Option<MicroUsd> {
    (v > 0).then_some(v)
}

impl Snapshot {
    /// The virtual snapshot every rule sees below the start height: `NOT_ACTIVE | NO_PRICE`.
    pub fn virtual_snapshot() -> Snapshot {
        Snapshot {
            halt_mask: crate::attest::price::HALT_NOT_ACTIVE | crate::attest::price::HALT_NO_PRICE,
            ..Snapshot::default()
        }
    }

    /// `PFast()`.
    pub fn pfast(&self) -> Option<MicroUsd> {
        price(self.p_fast)
    }
    /// `PMid()`.
    pub fn pmid(&self) -> Option<MicroUsd> {
        price(self.p_mid)
    }
    /// `PSlow()`.
    pub fn pslow(&self) -> Option<MicroUsd> {
        price(self.p_slow)
    }
    /// `PMint()`: `xMint`.
    pub fn pmint(&self) -> Option<MicroUsd> {
        price(self.p_mint)
    }
    /// `PClaim()`: `xClaim`.
    pub fn pclaim(&self) -> Option<MicroUsd> {
        price(self.p_claim)
    }
    /// `GlobalRatioBps()`.
    pub fn global_ratio(&self) -> Option<i64> {
        (self.global_ratio_bps > 0).then_some(self.global_ratio_bps)
    }

    /// The canonical serialisation.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.hash(&self.block_hash)
            .bool(self.tagged)
            .bool(self.quote)
            .i64(self.p_fast)
            .i64(self.p_mid)
            .i64(self.p_slow)
            .i64(self.p_mint)
            .i64(self.p_claim)
            .i32(self.sigma_mult_bps)
            .i64(self.issued_zat)
            .i64(self.supply_cents)
            .i64(self.collateral_zat)
            .i64(self.global_ratio_bps)
            .u32(self.halt_mask);
        put_attest(&mut w, &self.attest);
        w.vec(&self.seated, |w, s| {
            w.u16(*s);
        })
        .vec(&self.pinned_keys, |w, k| {
            w.raw(k);
        })
        .vec(&self.pinned_seqs, |w, s| {
            w.u16(*s);
        })
        .i64(self.open_debt_cents)
        .finish()
    }

    /// Parses [`Snapshot::encode`].
    pub fn decode(b: &[u8]) -> Option<Snapshot> {
        let mut r = Reader(b);
        let v = Snapshot {
            block_hash: r.hash()?,
            tagged: r.bool()?,
            quote: r.bool()?,
            p_fast: r.i64()?,
            p_mid: r.i64()?,
            p_slow: r.i64()?,
            p_mint: r.i64()?,
            p_claim: r.i64()?,
            sigma_mult_bps: r.i32()?,
            issued_zat: r.i64()?,
            supply_cents: r.i64()?,
            collateral_zat: r.i64()?,
            global_ratio_bps: r.i64()?,
            halt_mask: r.u32()?,
            attest: get_attest(&mut r)?,
            seated: r.vec(Reader::u16)?,
            pinned_keys: r.vec(|r| r.take::<20>())?,
            pinned_seqs: r.vec(Reader::u16)?,
            open_debt_cents: r.i64()?,
        };
        r.done().then_some(v)
    }
}

// ---------------------------------------------------------------- Params

/// `Params` (`P`): the hashed regtest values (M13, N18), written by the first applied block.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ParamsRecord {
    /// `START_HEIGHT` (the Vault activation height).
    pub start_height: i32,
    /// `SIGMA_REF_BPS`.
    pub sigma_ref_bps: i32,
    /// `SUPPLY_CAP_BPS`.
    pub supply_cap_bps: i32,
    /// `attestorSetId`, internal bytes.
    pub attestor_set_id: Hash32,
    /// `max(0, ATTEST_ARM_MIN)`.
    pub attest_arm_min: u32,
    /// `BUNDLE_CARRIER`'s discriminant.
    pub bundle_carrier: u8,
    /// `MINT_REQUIRES_ARMED`.
    pub mint_requires_armed: u8,
}

impl ParamsRecord {
    /// `ParamsRecord(const Params&)`.
    pub fn of(p: &Params) -> ParamsRecord {
        ParamsRecord {
            start_height: p.start_height,
            sigma_ref_bps: p.sigma_ref_bps,
            supply_cap_bps: p.supply_cap_bps,
            attestor_set_id: Hash32(p.attestor_set_id),
            attest_arm_min: u32::try_from(p.attest_arm_min.max(0)).unwrap_or(0),
            bundle_carrier: p.bundle_carrier as u8,
            mint_requires_armed: u8::from(p.mint_requires_armed),
        }
    }

    /// The canonical serialisation (50 bytes).
    pub fn encode(&self) -> Vec<u8> {
        Writer::new()
            .i32(self.start_height)
            .i32(self.sigma_ref_bps)
            .i32(self.supply_cap_bps)
            .hash(&self.attestor_set_id)
            .u32(self.attest_arm_min)
            .u8(self.bundle_carrier)
            .u8(self.mint_requires_armed)
            .finish()
    }

    /// Parses [`ParamsRecord::encode`].
    pub fn decode(b: &[u8]) -> Option<ParamsRecord> {
        let mut r = Reader(b);
        let v = ParamsRecord {
            start_height: r.i32()?,
            sigma_ref_bps: r.i32()?,
            supply_cap_bps: r.i32()?,
            attestor_set_id: r.hash()?,
            attest_arm_min: r.u32()?,
            bundle_carrier: r.u8()?,
            mint_requires_armed: r.u8()?,
        };
        r.done().then_some(v)
    }
}

impl Default for VaultRecord {
    /// The C++ default record: every field zero, status VOID.
    fn default() -> VaultRecord {
        VaultRecord {
            owner_pub_key: [0u8; 33],
            term_class: 0,
            lock_height: 0,
            claim_height: 0,
            collateral_zat: 0,
            minted_cents: 0,
            mint_height: 0,
            ref_height: 0,
            status: VaultStatus::Voided,
            void_reason: String::new(),
            close_height: 0,
            closing_txid: Hash32::ZERO,
            burned_cents: 0,
            fee_paid_zat: 0,
            unbacked: false,
            app_height: 0,
            owner_height: 0,
            p_mint: 0,
            cancel_count: 0,
            last_cancel_height: 0,
        }
    }
}
