//! `statehash` equals the C++ value on real ycash6 chains: every block of the recorded regtest
//! chains (`tests/data/ycash6_statehash_*.json`, recorded once from ycashd at ycash6 `65cb4ae0f`)
//! is parsed (Zcash v4 transactions; Vault is v4-only), applied with `apply_block` from the
//! activation height, and the canonical `statehash` after it compared with the
//! `vault_getinfo.statehash` ycashd reported for that block. Every delta is also reverted
//! back to the parent state at the end (the reorg path).

use std::collections::BTreeMap;

use kogany_vault::state::{
    apply_block, display_hex, Delta, Rules, SetState, SpentCoin, VaultTx, VaultTxIn, VaultTxOut,
};
use kogany_vault::{Hash32, OutPoint};
use serde_json::Value;
use sha2::{Digest, Sha256};

struct Reader<'a> {
    b: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> &'a [u8] {
        let s = &self.b[self.pos..self.pos + n];
        self.pos += n;
        s
    }
    fn u32(&mut self) -> u32 {
        u32::from_le_bytes(self.take(4).try_into().unwrap())
    }
    fn i64(&mut self) -> i64 {
        i64::from_le_bytes(self.take(8).try_into().unwrap())
    }
    fn compact(&mut self) -> usize {
        match self.take(1)[0] {
            253 => u16::from_le_bytes(self.take(2).try_into().unwrap()) as usize,
            254 => self.u32() as usize,
            255 => u64::from_le_bytes(self.take(8).try_into().unwrap()) as usize,
            n => n as usize,
        }
    }
    fn bytes(&mut self) -> Vec<u8> {
        let n = self.compact();
        self.take(n).to_vec()
    }
}

fn sha256d(b: &[u8]) -> Hash32 {
    Hash32(Sha256::digest(Sha256::digest(b)).into())
}

/// One v4 (Sapling) transaction: the transparent parts, the shielded parts skipped by size.
fn parse_tx(r: &mut Reader<'_>) -> VaultTx {
    let start = r.pos;
    let header = r.u32();
    assert_eq!(header, 0x8000_0004, "an overwintered v4 transaction");
    assert_eq!(r.u32(), 0x892f_2085, "the Sapling version group");
    let mut inputs = Vec::new();
    for _ in 0..r.compact() {
        let txid = Hash32(r.take(32).try_into().unwrap());
        let n = r.u32();
        let script_sig = r.bytes();
        let _sequence = r.u32();
        inputs.push(VaultTxIn {
            prevout: OutPoint { txid, n },
            script_sig,
        });
    }
    let mut outputs = Vec::new();
    for _ in 0..r.compact() {
        let value = r.i64();
        outputs.push(VaultTxOut {
            value,
            script_pubkey: r.bytes(),
        });
    }
    let _lock_time = r.u32();
    let _expiry = r.u32();
    let _value_balance = r.i64();
    let spends = r.compact();
    r.take(spends * 384);
    let outs = r.compact();
    r.take(outs * 948);
    let joinsplits = r.compact();
    r.take(joinsplits * 1698);
    if joinsplits > 0 {
        r.take(32 + 64);
    }
    if spends + outs > 0 {
        r.take(64);
    }
    let raw = &r.b[start..r.pos];
    let coinbase = VaultTx::inputs_are_coinbase(&inputs);
    VaultTx {
        txid: sha256d(raw),
        coinbase,
        inputs,
        outputs,
    }
}

fn parse_block(hex_block: &str) -> (Hash32, Vec<VaultTx>) {
    let raw = hex::decode(hex_block).unwrap();
    let mut r = Reader { b: &raw, pos: 0 };
    r.take(4 + 32 + 32 + 32 + 4 + 4 + 32);
    let sol = r.compact();
    r.take(sol);
    let header_hash = sha256d(&raw[..r.pos]);
    let n = r.compact();
    let txs = (0..n).map(|_| parse_tx(&mut r)).collect();
    assert_eq!(r.pos, raw.len(), "the whole block parsed");
    (header_hash, txs)
}

fn display(h: &Hash32) -> String {
    display_hex(h)
}

fn replay(name: &str) {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/data")
        .join(name);
    let doc: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    let activation = doc["vaultActivation"].as_i64().unwrap();
    let rules = Rules::new(activation, doc["minSetMaturity"].as_u64().unwrap() as u32);
    let mut coins: BTreeMap<OutPoint, SpentCoin> = BTreeMap::new();
    let mut st = SetState::new();
    let mut deltas: Vec<(SetState, Delta)> = Vec::new();
    let mut checked = 0;
    let mut distinct = std::collections::BTreeSet::new();
    for b in doc["blocks"].as_array().unwrap() {
        let height = b["height"].as_i64().unwrap();
        let (hash, txs) = parse_block(b["hex"].as_str().unwrap());
        assert_eq!(
            display(&hash),
            b["hash"].as_str().unwrap(),
            "block hash at {height}"
        );
        // In-block outputs are spendable later in the block (ConnectBlock's coins view).
        let mut view = coins.clone();
        for tx in &txs {
            for (o, out) in tx.outputs.iter().enumerate() {
                view.insert(
                    OutPoint {
                        txid: tx.txid,
                        n: o as u32,
                    },
                    SpentCoin {
                        script_pubkey: out.script_pubkey.clone(),
                        value: out.value,
                        height,
                    },
                );
            }
        }
        if height >= activation {
            let delta = apply_block(&st, &txs, height, &view, &rules)
                .unwrap_or_else(|e| panic!("{name}: block {height} rejected: {e}"));
            deltas.push((st.clone(), delta.clone()));
            st.apply(&delta);
        }
        coins = view;
        if let Some(want) = b["statehash"].as_str() {
            assert_eq!(
                display(&st.state_hash()),
                want,
                "{name}: statehash after block {height}"
            );
            checked += 1;
            distinct.insert(want.to_owned());
        }
    }
    assert!(checked >= 50, "{name}: {checked} heights checked");
    assert!(
        distinct.len() >= 10,
        "{name}: {} distinct state hashes",
        distinct.len()
    );
    assert!(!st.sets.is_empty() && !st.members.is_empty());
    // The reorg path: every delta reverts to its parent, byte for byte, down to the empty state.
    for (before, delta) in deltas.iter().rev() {
        st.revert(delta);
        assert_eq!(&st, before);
    }
    assert_eq!(st, SetState::new());
}

#[test]
fn statehash_equals_ycash6_vault_rpc() {
    replay("ycash6_statehash_vault_rpc.json");
}

#[test]
fn statehash_equals_ycash6_vault_slashing() {
    replay("ycash6_statehash_vault_slashing.json");
}
