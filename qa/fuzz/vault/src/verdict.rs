// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

//! kogany's verdicts for the vault fuzz replay (qa/fuzz/vault/README.md): the same `key=value`
//! string `recorder/record_verdicts.cpp` prints for ycash6, built from kogany's parsers. Shared,
//! by `#[path]`, by the replay test (`crates/zakura-consensus/tests/vault_fuzz_verdicts.rs`) and
//! the libFuzzer target (`fuzz_targets/vault_verdicts.rs`).
//!
//! Every function here is total: it returns a verdict for any bytes, and a panic is a finding.

use sha2::{Digest as _, Sha256};

use kogany_vault::act::{act_fields_valid, body_fields_valid, decode_act, decode_payload};
use kogany_vault::template::{
    match_intent, match_vault, parse_bond_redeem, parse_intent, parse_selector,
    parse_template_spend, parse_vault, Shape,
};
use kogany_yellowback::codecs::payload::{
    decode_payload as decode_yed_payload, extract_op_return_data, find_payload, payload_script,
};
use kogany_yellowback::codecs::script::{
    extract_redeem_script, holder_key, is_carrier_script, match_pq_channel, parse_bond_script,
    parse_v2_vault_script, parse_vault_spend_path, Holder,
};
use kogany_yellowback::codecs::tag::{find_tag, CoinbaseTag};
use zakura_chain::transparent::{Destination, Script};
use zakura_consensus::transaction::check::ycash_standard_script_kind;

/// The recorder's verdict formats (its first argument), by corpus.
pub const CORPORA: &[(&str, &str)] = &[
    ("Vault", "Vault"),
    ("YellowbackScript", "YellowbackScript"),
    ("YellowbackPayload", "YellowbackPayload"),
    ("YellowbackTag", "YellowbackTag"),
    ("PQVectors", "YellowbackScript"),
    ("PQPKH", "YellowbackScript"),
];

/// The verdict of `data` in `format`; `None` for an unknown format.
pub fn verdict(format: &str, data: &[u8]) -> Option<String> {
    Some(match format {
        "Vault" => vault(data),
        "YellowbackScript" => yellowback_script(data),
        "YellowbackPayload" => yellowback_payload(data),
        "YellowbackTag" => yellowback_tag(data),
        _ => return None,
    })
}

/// The first 8 bytes of SHA-256, as hex (the recorder's `Digest`).
fn digest(v: &[u8]) -> String {
    hex::encode(&Sha256::digest(v)[..8])
}

/// The recorder's `PushesDigest`: SHA-256 over each push as u32 LE length || bytes.
fn pushes_digest(pushes: &[Vec<u8>]) -> String {
    let mut buf = Vec::new();
    for p in pushes {
        buf.extend_from_slice(&u32::try_from(p.len()).unwrap_or(u32::MAX).to_le_bytes());
        buf.extend_from_slice(p);
    }
    digest(&buf)
}

fn holder(h: &Holder) -> String {
    match h {
        Holder::KeyId(k) => format!("key:{}", hex::encode(k)),
        Holder::Pq(o) => format!("pq:{}:{}", o.scheme, hex::encode(o.hash.0)),
    }
}

fn dest(d: Option<Destination>) -> String {
    match d {
        None => "none".to_owned(),
        Some(Destination::PubKeyHash(k)) => format!("key:{}", hex::encode(k)),
        Some(Destination::ScriptHash(s)) => format!("script:{}", hex::encode(s)),
        Some(Destination::PqKeyHash(q)) => format!("pq:{}:{}", q.scheme, hex::encode(q.key_hash)),
    }
}

/// ycash6 `Solver`'s type name, from kogany's classifiers: the standard kinds (the
/// `zcash_script` solver plus TX_PQPKH), then TX_PQCHANNEL, V and I as Solver orders them.
pub fn script_kind(s: &[u8]) -> &'static str {
    if let Some(kind) = ycash_standard_script_kind(&Script::new(s)) {
        return kind.as_str();
    }
    if match_pq_channel(s).is_some() {
        "pqchannel"
    } else if parse_vault(s).is_some() {
        "vault"
    } else if parse_intent(s).is_some() {
        "vaultintent"
    } else {
        "nonstandard"
    }
}

/// The recorder's `ScriptFields`: `kind=<Solver type>;dest=<ExtractDestination>`.
fn script_fields(s: &[u8]) -> String {
    format!(
        "kind={};dest={}",
        script_kind(s),
        dest(Script::new(s).destination())
    )
}

fn shape<T>(s: &Shape<T>) -> &'static str {
    match s {
        Shape::NotTemplate => "none",
        Shape::Match(_) => "match",
        Shape::Malformed => "malformed",
    }
}

/// The Vault corpus (ycash6 `vault_fuzz::RunVault`): `u16 LE n || spk || scriptSig`.
pub fn vault(data: &[u8]) -> String {
    let (spk, script_sig) = match data {
        [a, b, rest @ ..] => {
            let n = (usize::from(*a) | usize::from(*b) << 8).min(rest.len());
            rest.split_at(n)
        }
        _ => (data, &[][..]),
    };
    let mut r = script_fields(spk);
    r += &format!(";V={}", shape(&match_vault(spk)));
    r += &format!(";I={}", shape(&match_intent(spk)));
    r += &format!(";bond={}", u8::from(parse_bond_redeem(spk).is_some()));
    r += &match decode_act(spk) {
        Ok(act) => format!(
            ";act=ok:{}:{}:{}",
            act.body.act_type(),
            act.sigs.len(),
            u8::from(act_fields_valid(&act))
        ),
        Err(e) => format!(";act={}", e.reject_reason()),
    };
    r += &match decode_payload(spk) {
        Ok(body) => format!(
            ";P=ok:{}:{}",
            body.act_type(),
            u8::from(body_fields_valid(&body))
        ),
        Err(e) => format!(";P={}", e.reject_reason()),
    };
    r += &match parse_selector(script_sig) {
        Some((sel, pushes)) => format!(";sel={sel}:{}:{}", pushes.len(), pushes_digest(&pushes)),
        None => ";sel=none".to_owned(),
    };
    r += &match parse_template_spend(spk, script_sig) {
        Some(ts) => format!(
            ";ts={}:{}:{}",
            if ts.is_vault() { "v" } else { "i" },
            ts.selector,
            ts.sigs.len()
        ),
        None => ";ts=none".to_owned(),
    };
    r
}

/// The YellowbackScript corpus (ycash6 `fuzz_YellowbackScript`), also the PQVectors and PQPKH
/// corpora: the bytes as one script.
pub fn yellowback_script(s: &[u8]) -> String {
    let mut r = script_fields(s);
    r += &match parse_v2_vault_script(s) {
        Some(v) => format!(";v2={}:{}", v.lock_height, v.claim_height),
        None => ";v2=none".to_owned(),
    };
    r += &match parse_vault_spend_path(s) {
        Some(p) => format!(
            ";path={}:{}:{}:{}",
            u8::from(p.owner_path),
            p.pushes,
            digest(&p.selector),
            digest(&p.owner_sig)
        ),
        None => ";path=none".to_owned(),
    };
    r += &match extract_redeem_script(s) {
        Some(redeem) => format!(";redeem={}:{}", redeem.len(), digest(&redeem)),
        None => ";redeem=none".to_owned(),
    };
    r += &format!(
        ";holder={}",
        holder_key(s).map_or("none".to_owned(), |h| holder(&h))
    );
    r += &match match_pq_channel(s) {
        Some(c) => format!(";chan={}:{}", c.client.scheme, c.refund_height),
        None => ";chan=none".to_owned(),
    };
    r += &format!(";carrier={}", u8::from(is_carrier_script(s).is_some()));
    r += &match parse_bond_script(s) {
        Some((_, locktime)) => format!(";bond={locktime}"),
        None => ";bond=none".to_owned(),
    };
    r
}

/// The YellowbackPayload corpus (ycash6 `fuzz_YellowbackPayload`).
pub fn yellowback_payload(data: &[u8]) -> String {
    let mut r = match decode_yed_payload(data) {
        Some(p) => format!("payload={}", p.payload_type() as u8),
        None => "payload=none".to_owned(),
    };
    let script = payload_script(data);
    r += &match extract_op_return_data(&script) {
        Some(op) => format!(";opret={}", op.len()),
        None => ";opret=none".to_owned(),
    };
    r += &match find_payload(&[data, script.as_slice()]) {
        Some(f) => format!(
            ";found={}:{}",
            f.op_return_index,
            f.payload.payload_type() as u8
        ),
        None => ";found=none".to_owned(),
    };
    r + ";" + &script_fields(data)
}

fn tag(t: Option<CoinbaseTag>) -> String {
    match t {
        None => "none".to_owned(),
        Some(t) => format!(
            "{}:{}:{}:{}",
            t.flags,
            t.price_micro_usd,
            t.source_mask,
            hex::encode(t.payout_key)
        ),
    }
}

/// The YellowbackTag corpus (ycash6 `fuzz_YellowbackTag`): `u32 LE height || scriptSig`.
pub fn yellowback_tag(data: &[u8]) -> String {
    let (height, script_sig) = match data {
        [a, b, c, d, rest @ ..] => {
            let h = u32::from_le_bytes([*a, *b, *c, *d]) & 0x7fff_ffff;
            (i32::try_from(h).unwrap_or(i32::MAX), rest)
        }
        _ => (1, data),
    };
    let mut r = format!("tag={}", tag(find_tag(script_sig, height)));
    r += ";h=";
    for h in [0, 1, 16, 17, 65535, 1234567] {
        r += if find_tag(data, h).is_some() {
            "1"
        } else {
            "0"
        };
    }
    r
}

/// One row of a `verdicts/<Corpus>.tsv` file.
pub struct Row {
    /// The input's name in its corpus.
    pub name: String,
    /// The input.
    pub data: Vec<u8>,
    /// ycash6's verdict.
    pub verdict: String,
}

/// The rows of a verdicts file; an `Err` names a malformed line or a hash mismatch.
pub fn parse_verdicts(text: &str) -> Result<Vec<Row>, String> {
    let mut rows = Vec::new();
    for (i, line) in text.lines().enumerate() {
        if line.starts_with('#') || line.is_empty() {
            continue;
        }
        let f: Vec<&str> = line.split('\t').collect();
        let [name, sha, hex_data, verdict] = f.as_slice() else {
            return Err(format!("line {}: {} fields", i + 1, f.len()));
        };
        let data = hex::decode(hex_data).map_err(|e| format!("line {}: {e}", i + 1))?;
        if hex::encode(Sha256::digest(&data)) != *sha {
            return Err(format!("line {}: sha256 mismatch", i + 1));
        }
        rows.push(Row {
            name: (*name).to_owned(),
            data,
            verdict: (*verdict).to_owned(),
        });
    }
    Ok(rows)
}
