// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

//! The YED key space (ycash6 `src/yellowback/view.{h,cpp}` `keys::*` at `65cb4ae0f`): one
//! prefix byte per table, big-endian heights and seqs (so byte order is height order), an
//! outpoint as txid ‖ n big-endian, a txid raw. [`YedKey`] is typed; its derived order is the
//! canonical byte order of [`YedKey::encode`] (the variants are declared in prefix-byte order and
//! every payload's derived order is its big-endian bytes' order; `keys_order_is_byte_order`
//! checks it), so a `BTreeMap<YedKey, _>` iterates exactly as the C++ ordered store does.
//!
//! [`YedRecord`] is the value of one key; [`YedRecord::decode`] reads the bytes a store holds
//! back under the table its key names.

use kogany_vault::{Hash32, OutPoint};

use super::records::{
    IntentRecord, Judgement, NoticeRecord, ParamsRecord, Snapshot, TagRecord, TipRecord,
    TokenRecord, Totals, TxLogRecord, VaultRecord,
};
use crate::attest::registry::{
    decode_seq, encode_seq, AttestState, AttestorRecord, AttestorSetRecord, BundleLogRecord,
};

/// A table of the YED state, by its key prefix.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Table {
    /// `A<u16 seq>` `AttestorRecord`.
    Attestor,
    /// `B<outpoint>` bond index (derived, not hashed).
    BondIndex,
    /// `E<outpoint>` `NoticeRecord`.
    Notice,
    /// `G` `Totals`.
    Totals,
    /// `I<outpoint>` `IntentRecord`.
    Intent,
    /// `J<u32 height>` `Judgement`.
    Judgement,
    /// `K<outpoint>` `TokenRecord`.
    Token,
    /// `L<txid>` `TxLogRecord` (history, not hashed).
    TxLog,
    /// `M` `AttestState`.
    Attest,
    /// `N` the next seq.
    AttestorSeq,
    /// `P` `ParamsRecord`.
    Params,
    /// `Q<u32 height>` `TagRecord`.
    Tag,
    /// `S<u32 height>` `Snapshot`.
    Snapshot,
    /// `T` `TipRecord`.
    Tip,
    /// `V<outpoint>` `VaultRecord`.
    Vault,
    /// `W<u32 height>` `BundleLogRecord`.
    BundleLog,
    /// `Z` `AttestorSetRecord`.
    AttestorSet,
}

impl Table {
    /// The key prefix byte.
    pub const fn prefix(self) -> u8 {
        match self {
            Table::Attestor => b'A',
            Table::BondIndex => b'B',
            Table::Notice => b'E',
            Table::Totals => b'G',
            Table::Intent => b'I',
            Table::Judgement => b'J',
            Table::Token => b'K',
            Table::TxLog => b'L',
            Table::Attest => b'M',
            Table::AttestorSeq => b'N',
            Table::Params => b'P',
            Table::Tag => b'Q',
            Table::Snapshot => b'S',
            Table::Tip => b'T',
            Table::Vault => b'V',
            Table::BundleLog => b'W',
            Table::AttestorSet => b'Z',
        }
    }

    /// The tables the state hash digests after the tip, in the C++ order (`StateHash`:
    /// `Q J V K G S P A N M W E I Z`); TxLog (`L`) and the bond index (`B`) are excluded.
    pub const HASHED: [Table; 14] = [
        Table::Tag,
        Table::Judgement,
        Table::Vault,
        Table::Token,
        Table::Totals,
        Table::Snapshot,
        Table::Params,
        Table::Attestor,
        Table::AttestorSeq,
        Table::Attest,
        Table::BundleLog,
        Table::Notice,
        Table::Intent,
        Table::AttestorSet,
    ];

    /// The least and greatest key of the table (an inclusive range over [`YedKey`]'s order).
    pub fn bounds(self) -> (YedKey, YedKey) {
        const OP_MIN: OutPoint = OutPoint {
            txid: Hash32([0u8; 32]),
            n: 0,
        };
        const OP_MAX: OutPoint = OutPoint {
            txid: Hash32([0xffu8; 32]),
            n: u32::MAX,
        };
        match self {
            Table::Attestor => (YedKey::Attestor(0), YedKey::Attestor(u16::MAX)),
            Table::BondIndex => (YedKey::BondIndex(OP_MIN), YedKey::BondIndex(OP_MAX)),
            Table::Notice => (YedKey::Notice(OP_MIN), YedKey::Notice(OP_MAX)),
            Table::Totals => (YedKey::Totals, YedKey::Totals),
            Table::Intent => (YedKey::Intent(OP_MIN), YedKey::Intent(OP_MAX)),
            Table::Judgement => (YedKey::Judgement(0), YedKey::Judgement(u32::MAX)),
            Table::Token => (YedKey::Token(OP_MIN), YedKey::Token(OP_MAX)),
            Table::TxLog => (
                YedKey::TxLog(Hash32([0u8; 32])),
                YedKey::TxLog(Hash32([0xffu8; 32])),
            ),
            Table::Attest => (YedKey::Attest, YedKey::Attest),
            Table::AttestorSeq => (YedKey::AttestorSeq, YedKey::AttestorSeq),
            Table::Params => (YedKey::Params, YedKey::Params),
            Table::Tag => (YedKey::Tag(0), YedKey::Tag(u32::MAX)),
            Table::Snapshot => (YedKey::Snapshot(0), YedKey::Snapshot(u32::MAX)),
            Table::Tip => (YedKey::Tip, YedKey::Tip),
            Table::Vault => (YedKey::Vault(OP_MIN), YedKey::Vault(OP_MAX)),
            Table::BundleLog => (YedKey::BundleLog(0), YedKey::BundleLog(u32::MAX)),
            Table::AttestorSet => (YedKey::AttestorSet, YedKey::AttestorSet),
        }
    }
}

/// One key of the YED state. Declared in prefix-byte order: the derived `Ord` is the byte order
/// of [`YedKey::encode`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum YedKey {
    /// `'A' ‖ seq BE16`.
    Attestor(u16),
    /// `'B' ‖ txid ‖ n BE32`.
    BondIndex(OutPoint),
    /// `'E' ‖ txid ‖ n BE32`.
    Notice(OutPoint),
    /// `"G"`.
    Totals,
    /// `'I' ‖ txid ‖ n BE32`.
    Intent(OutPoint),
    /// `'J' ‖ height BE32`.
    Judgement(u32),
    /// `'K' ‖ txid ‖ n BE32`.
    Token(OutPoint),
    /// `'L' ‖ txid`.
    TxLog(Hash32),
    /// `"M"`.
    Attest,
    /// `"N"`.
    AttestorSeq,
    /// `"P"`.
    Params,
    /// `'Q' ‖ height BE32`.
    Tag(u32),
    /// `'S' ‖ height BE32`.
    Snapshot(u32),
    /// `"T"`.
    Tip,
    /// `'V' ‖ txid ‖ n BE32`.
    Vault(OutPoint),
    /// `'W' ‖ height BE32`.
    BundleLog(u32),
    /// `"Z"`.
    AttestorSet,
}

fn outpoint_key(prefix: u8, o: &OutPoint) -> Vec<u8> {
    let mut k = Vec::with_capacity(37);
    k.push(prefix);
    k.extend_from_slice(&o.txid.0);
    k.extend_from_slice(&o.n.to_be_bytes());
    k
}

fn height_key(prefix: u8, h: u32) -> Vec<u8> {
    let mut k = Vec::with_capacity(5);
    k.push(prefix);
    k.extend_from_slice(&h.to_be_bytes());
    k
}

impl YedKey {
    /// The table the key belongs to.
    pub const fn table(&self) -> Table {
        match self {
            YedKey::Attestor(_) => Table::Attestor,
            YedKey::BondIndex(_) => Table::BondIndex,
            YedKey::Notice(_) => Table::Notice,
            YedKey::Totals => Table::Totals,
            YedKey::Intent(_) => Table::Intent,
            YedKey::Judgement(_) => Table::Judgement,
            YedKey::Token(_) => Table::Token,
            YedKey::TxLog(_) => Table::TxLog,
            YedKey::Attest => Table::Attest,
            YedKey::AttestorSeq => Table::AttestorSeq,
            YedKey::Params => Table::Params,
            YedKey::Tag(_) => Table::Tag,
            YedKey::Snapshot(_) => Table::Snapshot,
            YedKey::Tip => Table::Tip,
            YedKey::Vault(_) => Table::Vault,
            YedKey::BundleLog(_) => Table::BundleLog,
            YedKey::AttestorSet => Table::AttestorSet,
        }
    }

    /// The canonical key bytes (`keys::*`).
    pub fn encode(&self) -> Vec<u8> {
        let p = self.table().prefix();
        match self {
            YedKey::Attestor(seq) => {
                let [hi, lo] = seq.to_be_bytes();
                vec![p, hi, lo]
            }
            YedKey::BondIndex(o)
            | YedKey::Notice(o)
            | YedKey::Intent(o)
            | YedKey::Token(o)
            | YedKey::Vault(o) => outpoint_key(p, o),
            YedKey::Judgement(h) | YedKey::Tag(h) | YedKey::Snapshot(h) | YedKey::BundleLog(h) => {
                height_key(p, *h)
            }
            YedKey::TxLog(txid) => {
                let mut k = vec![p];
                k.extend_from_slice(&txid.0);
                k
            }
            YedKey::Totals
            | YedKey::Attest
            | YedKey::AttestorSeq
            | YedKey::Params
            | YedKey::Tip
            | YedKey::AttestorSet => vec![p],
        }
    }

    /// Parses [`YedKey::encode`]; `None` for an unknown prefix or a wrong length (the C++ never
    /// writes such a key; the undo table `U` and the node-local `R` are not state keys).
    pub fn decode(b: &[u8]) -> Option<YedKey> {
        let (&p, rest) = b.split_first()?;
        let outpoint = || -> Option<OutPoint> {
            let (txid, n) = rest.split_first_chunk::<32>()?;
            let n = <[u8; 4]>::try_from(n).ok()?;
            Some(OutPoint {
                txid: Hash32(*txid),
                n: u32::from_be_bytes(n),
            })
        };
        let height = || <[u8; 4]>::try_from(rest).ok().map(u32::from_be_bytes);
        let single = |k: YedKey| rest.is_empty().then_some(k);
        match p {
            b'A' => <[u8; 2]>::try_from(rest)
                .ok()
                .map(|s| YedKey::Attestor(u16::from_be_bytes(s))),
            b'B' => outpoint().map(YedKey::BondIndex),
            b'E' => outpoint().map(YedKey::Notice),
            b'G' => single(YedKey::Totals),
            b'I' => outpoint().map(YedKey::Intent),
            b'J' => height().map(YedKey::Judgement),
            b'K' => outpoint().map(YedKey::Token),
            b'L' => Hash32::from_slice(rest).map(YedKey::TxLog),
            b'M' => single(YedKey::Attest),
            b'N' => single(YedKey::AttestorSeq),
            b'P' => single(YedKey::Params),
            b'Q' => height().map(YedKey::Tag),
            b'S' => height().map(YedKey::Snapshot),
            b'T' => single(YedKey::Tip),
            b'V' => outpoint().map(YedKey::Vault),
            b'W' => height().map(YedKey::BundleLog),
            b'Z' => single(YedKey::AttestorSet),
            _ => None,
        }
    }
}

/// The value of one [`YedKey`] (its table's record).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum YedRecord {
    /// [`Table::Attestor`].
    Attestor(AttestorRecord),
    /// [`Table::BondIndex`]: the bond's seq.
    BondIndex(u16),
    /// [`Table::Notice`].
    Notice(NoticeRecord),
    /// [`Table::Totals`].
    Totals(Totals),
    /// [`Table::Intent`].
    Intent(IntentRecord),
    /// [`Table::Judgement`].
    Judgement(Judgement),
    /// [`Table::Token`].
    Token(TokenRecord),
    /// [`Table::TxLog`].
    TxLog(Box<TxLogRecord>),
    /// [`Table::Attest`].
    Attest(AttestState),
    /// [`Table::AttestorSeq`]: the next seq.
    AttestorSeq(u16),
    /// [`Table::Params`].
    Params(ParamsRecord),
    /// [`Table::Tag`].
    Tag(TagRecord),
    /// [`Table::Snapshot`].
    Snapshot(Box<Snapshot>),
    /// [`Table::Tip`].
    Tip(TipRecord),
    /// [`Table::Vault`].
    Vault(Box<VaultRecord>),
    /// [`Table::BundleLog`].
    BundleLog(BundleLogRecord),
    /// [`Table::AttestorSet`].
    AttestorSet(AttestorSetRecord),
}

impl YedRecord {
    /// The table this record belongs in.
    pub const fn table(&self) -> Table {
        match self {
            YedRecord::Attestor(_) => Table::Attestor,
            YedRecord::BondIndex(_) => Table::BondIndex,
            YedRecord::Notice(_) => Table::Notice,
            YedRecord::Totals(_) => Table::Totals,
            YedRecord::Intent(_) => Table::Intent,
            YedRecord::Judgement(_) => Table::Judgement,
            YedRecord::Token(_) => Table::Token,
            YedRecord::TxLog(_) => Table::TxLog,
            YedRecord::Attest(_) => Table::Attest,
            YedRecord::AttestorSeq(_) => Table::AttestorSeq,
            YedRecord::Params(_) => Table::Params,
            YedRecord::Tag(_) => Table::Tag,
            YedRecord::Snapshot(_) => Table::Snapshot,
            YedRecord::Tip(_) => Table::Tip,
            YedRecord::Vault(_) => Table::Vault,
            YedRecord::BundleLog(_) => Table::BundleLog,
            YedRecord::AttestorSet(_) => Table::AttestorSet,
        }
    }

    /// The canonical value bytes (`SerializeRecord`).
    pub fn encode(&self) -> Vec<u8> {
        match self {
            YedRecord::Attestor(r) => r.encode(),
            YedRecord::BondIndex(s) | YedRecord::AttestorSeq(s) => encode_seq(*s).to_vec(),
            YedRecord::Notice(r) => r.encode(),
            YedRecord::Totals(r) => r.encode(),
            YedRecord::Intent(r) => r.encode(),
            YedRecord::Judgement(r) => r.encode(),
            YedRecord::Token(r) => r.encode(),
            YedRecord::TxLog(r) => r.encode(),
            YedRecord::Attest(r) => r.encode(),
            YedRecord::Params(r) => r.encode(),
            YedRecord::Tag(r) => r.encode(),
            YedRecord::Snapshot(r) => r.encode(),
            YedRecord::Tip(r) => r.encode(),
            YedRecord::Vault(r) => r.encode(),
            YedRecord::BundleLog(r) => r.encode(),
            YedRecord::AttestorSet(r) => r.encode(),
        }
    }

    /// Parses the value bytes of a key of `table`.
    pub fn decode(table: Table, b: &[u8]) -> Option<YedRecord> {
        Some(match table {
            Table::Attestor => YedRecord::Attestor(AttestorRecord::decode(b)?),
            Table::BondIndex => YedRecord::BondIndex(decode_seq(b)?),
            Table::Notice => YedRecord::Notice(NoticeRecord::decode(b)?),
            Table::Totals => YedRecord::Totals(Totals::decode(b)?),
            Table::Intent => YedRecord::Intent(IntentRecord::decode(b)?),
            Table::Judgement => YedRecord::Judgement(Judgement::decode(b)?),
            Table::Token => YedRecord::Token(TokenRecord::decode(b)?),
            Table::TxLog => YedRecord::TxLog(Box::new(TxLogRecord::decode(b)?)),
            Table::Attest => YedRecord::Attest(AttestState::decode(b)?),
            Table::AttestorSeq => YedRecord::AttestorSeq(decode_seq(b)?),
            Table::Params => YedRecord::Params(ParamsRecord::decode(b)?),
            Table::Tag => YedRecord::Tag(TagRecord::decode(b)?),
            Table::Snapshot => YedRecord::Snapshot(Box::new(Snapshot::decode(b)?)),
            Table::Tip => YedRecord::Tip(TipRecord::decode(b)?),
            Table::Vault => YedRecord::Vault(Box::new(VaultRecord::decode(b)?)),
            Table::BundleLog => YedRecord::BundleLog(BundleLogRecord::decode(b)?),
            Table::AttestorSet => YedRecord::AttestorSet(AttestorSetRecord::decode(b)?),
        })
    }
}
