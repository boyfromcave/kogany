//! Rendering keys, owners, holders and payloads the way ycashd does (`src/rpc/yellowback.cpp`
//! `P2PKHAddress`, `P2SHAddress`, `EncodeAddress`, `PayloadToJSON`), and parsing the address
//! forms `yed_listtokens` takes.

use kogany_vault::{template::hash160, OutPoint, PqOwner, PubKeyBytes};
use kogany_yellowback::{
    codecs::{
        address::{decode_address, decode_pq_address, encode_address, encode_pq_address},
        base58::{decode_base58_check, encode_base58_check},
        payload::Payload,
        script::{bond_script, Holder},
    },
    params::Params,
};
use serde_json::{json, Map, Value};
use zakura_chain::{
    parameters::{Network, NetworkKind},
    transparent,
};

use crate::json::{display_hex, raw_hex};

use super::types::OutPointJson;

/// Addresses and payloads of one network and parameter set.
pub struct Fmt<'a> {
    /// The network (transparent addresses).
    pub network: &'a Network,
    /// The Yellowback parameters (YED address versions).
    pub params: &'a Params,
    /// The plain-YEC post-quantum address version (`sq`/`tq`/`rq`, D-Q-20).
    pub plain_pq_version: [u8; 2],
}

impl Fmt<'_> {
    fn kind(&self) -> NetworkKind {
        self.network.kind()
    }

    /// `P2PKHAddress`: the transparent P2PKH address of a key hash (`s1…`/`sm…`).
    pub fn p2pkh(&self, key: &[u8; 20]) -> String {
        transparent::Address::from_pub_key_hash(self.kind(), *key).to_string()
    }

    /// `P2SHAddress`: the P2SH address of a redeem script.
    pub fn p2sh(&self, redeem: &[u8]) -> String {
        transparent::Address::from_script_hash(self.kind(), hash160(redeem)).to_string()
    }

    /// The P2PKH address of a public key's hash.
    pub fn key_address(&self, key: &PubKeyBytes) -> String {
        self.p2pkh(&hash160(&key.0))
    }

    /// The P2SH address of `BondScript(key, locktime)`, `""` when no bond script exists for
    /// them (ycashd renders `null` from `yed_decodepayload` and never meets it elsewhere).
    pub fn bond_address(&self, key: &PubKeyBytes, locktime: u32) -> Option<String> {
        bond_script(key, locktime).map(|s| self.p2sh(&s))
    }

    /// `EncodeAddress(CKeyID)`: the YED P2PKH address (`yb…`/`yt…`/`yr…`, 35 characters).
    pub fn yed_address(&self, key: &[u8; 20]) -> String {
        encode_address(key, self.params)
    }

    /// `EncodeAddress(CPQKeyID)`: the YED post-quantum address, `""` for an unregistered scheme.
    pub fn yed_pq_address(&self, owner: &PqOwner) -> String {
        encode_pq_address(owner, self.params).unwrap_or_default()
    }

    /// The plain-YEC post-quantum address of a key (`sq…`/`tq…`/`rq…`, D-Q-20).
    pub fn plain_pq_address(&self, owner: &PqOwner) -> String {
        let mut data = self.plain_pq_version.to_vec();
        data.push(owner.scheme);
        data.extend_from_slice(&owner.hash.0);
        encode_base58_check(&data)
    }

    /// A holder's YED address and its plain-YEC twin.
    pub fn holder_addresses(&self, holder: &Holder) -> (String, String) {
        match holder {
            Holder::KeyId(k) => (self.yed_address(k), self.p2pkh(k)),
            Holder::Pq(o) => (self.yed_pq_address(o), self.plain_pq_address(o)),
        }
    }

    /// A `yed_listtokens` address: a YED address (either form), a transparent P2PKH address or a
    /// plain-YEC post-quantum address of this network.
    pub fn parse_holder(&self, s: &str) -> Option<Holder> {
        if let Some(k) = decode_address(s, self.params) {
            return Some(Holder::KeyId(k));
        }
        if let Some(o) = decode_pq_address(s, self.params) {
            return Some(Holder::Pq(o));
        }
        // The plain-YEC post-quantum form first: a ycash build of zakura-chain parses it as a
        // transparent::Address too (its index key, W9-c finding 3).
        if let Some(owner) = decode_base58_check(s).and_then(|data| {
            let body = data
                .strip_prefix(self.plain_pq_version.as_slice())?
                .to_vec();
            let (scheme, hash) = body.split_first()?;
            Some(PqOwner {
                scheme: *scheme,
                hash: kogany_vault::Hash32::from_slice(hash)?,
            })
        }) {
            return kogany_vault::template::is_known_pq_scheme(owner.scheme)
                .then_some(Holder::Pq(owner));
        }
        let a = s.parse::<transparent::Address>().ok()?;
        // A P2PKH address of this network: it re-encodes to itself here (regtest shares
        // testnet's prefixes, so the parsed network kind alone cannot tell).
        let key = a.hash_bytes();
        (!a.is_script_hash() && self.p2pkh(&key) == s).then_some(Holder::KeyId(key))
    }
}

/// `{"txid", "vout"}` of an outpoint.
pub fn outpoint_json(o: &OutPoint) -> OutPointJson {
    OutPointJson {
        txid: display_hex(&o.txid),
        vout: o.n,
    }
}

/// `"A"`, `"B"`, `"C"`, or the number of an out-of-range class (`ClassLetter`).
pub fn class_letter(term_class: u8) -> String {
    match term_class {
        0..=2 => char::from(b'A' + term_class).to_string(),
        n => n.to_string(),
    }
}

/// `PayloadToJSON`: the decoded payload's object, in ycashd's field order.
pub fn payload_json(p: &Payload, fmt: &Fmt<'_>) -> Map<String, Value> {
    let mut o = Map::new();
    o.insert("valid".into(), json!(true));
    o.insert("version".into(), json!(p.version()));
    o.insert("type".into(), json!(p.payload_type().name()));
    o.insert("reason".into(), json!(""));
    match p {
        Payload::Mint(m) => {
            let owner = m.owner();
            o.insert("termClass".into(), json!(class_letter(m.term_class)));
            o.insert("cents".into(), json!(m.cents));
            o.insert("lockHeight".into(), json!(m.lock_height));
            o.insert("refHeight".into(), json!(m.ref_height));
            o.insert("ownerScheme".into(), json!(owner.scheme));
            o.insert("ownerHash".into(), json!(raw_hex(&owner.hash.0)));
            o.insert("feeVout".into(), json!(m.fee_vout));
            o.insert("attestFeeVout".into(), json!(m.attest_fee_vout));
        }
        Payload::Transfer(_) | Payload::Redeem(_) => {
            if let Payload::Redeem(r) = p {
                o.insert("refHeight".into(), json!(r.ref_height));
                o.insert("feeVout".into(), json!(r.fee_vout));
                o.insert("attestFeeVout".into(), json!(r.attest_fee_vout));
            }
            let assignments: Vec<Value> = p
                .assignments()
                .iter()
                .map(|a| json!({"vout": a.vout, "cents": a.cents}))
                .collect();
            o.insert("assignments".into(), Value::Array(assignments));
            o.insert("assignedCents".into(), json!(p.assigned_cents()));
        }
        Payload::AttestorRegister(r) => {
            o.insert(
                "register".into(),
                json!({
                    "attestorPubKey": raw_hex(&r.attestor_key.0),
                    "bondPubKey": raw_hex(&r.bond_key.0),
                    "bondAddress": fmt.bond_address(&r.bond_key, r.bond_locktime),
                    "bondKeyAddress": r.bond_key.is_compressed().then(|| fmt.key_address(&r.bond_key)),
                    "bondLocktime": r.bond_locktime,
                    "flags": {"tier": r.flags & 0x03, "pool": r.flags & 0x04 != 0},
                }),
            );
        }
        Payload::ClaimNotice(n) => {
            o.insert(
                "notice".into(),
                json!({
                    "vault": {"txid": display_hex(&n.vault_txid), "vout": n.vault_vout},
                    "refHeight": n.ref_height,
                }),
            );
        }
        Payload::Equivocation => {
            o.insert("equivocation".into(), json!({}));
        }
        Payload::CancelCosign => {
            o.insert("cancelCosign".into(), json!({}));
        }
        Payload::AttestorRevive(r) => {
            let att = super::state::Attestation {
                seq: r.seq,
                price_micro_usd: r.price_micro_usd,
                cited_height: r.cited_height,
                sig: r.sig,
            };
            o.insert(
                "revive".into(),
                json!({"attestation": attestation_json(&att)}),
            );
        }
    }
    o
}

/// `AttestationToJSON`.
pub fn attestation_json(a: &super::state::Attestation) -> Value {
    json!({
        "seq": a.seq,
        "priceMicroUsd": a.price_micro_usd,
        "citedHeight": a.cited_height,
        "sig": raw_hex(&a.sig),
        "hex": raw_hex(&a.encode()),
    })
}

/// `DecodeBundle(data, 255)`: `"YA" ‖ 0x01 ‖ count ‖ count × 74 bytes`, decoded only (never
/// verified); `None` for any other shape. (W5-c's bundle codec replaces this when it lands.)
pub fn decode_bundle(data: &[u8]) -> Option<(u8, Vec<super::state::Attestation>)> {
    let (header, body) = data.split_at_checked(4)?;
    let [b'Y', b'A', version @ 0x01, count] = *header else {
        return None;
    };
    if body.len() != usize::from(count).checked_mul(super::state::Attestation::SIZE)? {
        return None;
    }
    let (chunks, _) = body.as_chunks::<{ super::state::Attestation::SIZE }>();
    let atts = chunks
        .iter()
        .map(|c| super::state::Attestation::decode(c))
        .collect::<Option<Vec<_>>>()?;
    Some((version, atts))
}
