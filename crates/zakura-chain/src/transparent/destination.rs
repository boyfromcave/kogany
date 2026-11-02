// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

//! Ycash (kogany): the destination of a transparent output script, as ycash6's
//! `ExtractDestination` (`src/script/standard.cpp`) names it, including the post-quantum
//! TX_PQPKH `0x20 <keyHash:32> OP_1|OP_2 OP_CHECKPQSIG` (quantum spec §2.1), whose destination
//! is a [`PqKeyId`] (`CPQKeyID`). A TX_PQPKH has no plain-YEC address encoding (ycash6's
//! `EncodeDestination` returns ""), so it is not an [`Address`](super::Address) variant. The
//! TX_PQPKH shape is kogany-yellowback's (`holder_key`, `pq_key_script`), not re-derived here.

use kogany_yellowback::codecs::script::{holder_key, pq_key_script, Holder};

use super::{Output, Script};

/// A post-quantum key id, the TX_PQPKH destination (ycash6 `CPQKeyID`): the scheme byte and
/// `keyHash = SHA256(scheme || pk)`.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct PqKeyId {
    /// The scheme byte (1 = SLH-DSA-SHA2-128s, 2 = FN-DSA-512).
    pub scheme: u8,
    /// `SHA256(scheme || pk)`.
    pub key_hash: [u8; 32],
}

/// What a transparent output script pays to (ycash6 `CTxDestination` from `ExtractDestination`).
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum Destination {
    /// A P2PKH's key hash, or the Hash160 of a valid P2PK key (`CKeyID`).
    PubKeyHash([u8; 20]),
    /// A P2SH's script hash (`CScriptID`).
    ScriptHash([u8; 20]),
    /// A TX_PQPKH's key id (`CPQKeyID`).
    PqKeyHash(PqKeyId),
}

/// `CPubKey::ValidSize` for a push: the length its header byte implies.
fn valid_pubkey_size(key: &[u8]) -> bool {
    match key.first() {
        Some(2 | 3) => key.len() == 33,
        Some(4 | 6 | 7) => key.len() == 65,
        _ => false,
    }
}

impl Script {
    /// The TX_PQPKH key id (ycash6 `MatchPayToPQKeyHash`): exactly the 35-byte
    /// `0x20 <keyHash:32> OP_1|OP_2 OP_CHECKPQSIG`, else `None`.
    pub fn pq_key_id(&self) -> Option<PqKeyId> {
        let bytes = self.as_raw_bytes();
        // holder_key also names a TX_PQCHANNEL's client; only the exact rebuilt script is a TX_PQPKH.
        let Some(Holder::Pq(owner)) = holder_key(bytes) else {
            return None;
        };
        (pq_key_script(&owner).as_deref() == Some(bytes)).then_some(PqKeyId {
            scheme: owner.scheme,
            key_hash: owner.hash.0,
        })
    }

    /// The destination (ycash6 `ExtractDestination`): P2SH, P2PKH, a P2PK with a valid-size key
    /// (as its Hash160) and TX_PQPKH; `None` for every other script, multisig and OP_RETURN
    /// included.
    pub fn destination(&self) -> Option<Destination> {
        let s = self.as_raw_bytes();
        if let [0xa9, 20, hash @ .., 0x87] = s {
            return <[u8; 20]>::try_from(hash).ok().map(Destination::ScriptHash);
        }
        if let [0x76, 0xa9, 20, hash @ .., 0x88, 0xac] = s {
            return <[u8; 20]>::try_from(hash).ok().map(Destination::PubKeyHash);
        }
        if let [n @ (33 | 65), key @ .., 0xac] = s {
            if key.len() == usize::from(*n) && valid_pubkey_size(key) {
                return Some(Destination::PubKeyHash(kogany_vault::template::hash160(
                    key,
                )));
            }
        }
        self.pq_key_id().map(Destination::PqKeyHash)
    }
}

impl Output {
    /// The destination of this output's lock script ([`Script::destination`]).
    pub fn destination(&self) -> Option<Destination> {
        self.lock_script.destination()
    }
}
