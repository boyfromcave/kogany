// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

//! A miniature of `yellowback_state_tests.cpp`'s `Fixture`, restricted to the attestor registry:
//! set acts and bond spends applied to a [`Registry`] by the mirror rules, then SNAP's attestor
//! passes (maturity, ARM-1/2, seating, S15) per block, each height's selection basis kept. Prices,
//! vaults and tags are the state machine's (W5-d) and are not modelled.
#![allow(dead_code, missing_docs)]

use std::collections::BTreeMap;

use kogany_vault::act::{encode_act, Act, ActBody, SetCreateBody, SetJoinBody, SET_FLAG_OPEN};
use kogany_vault::state::{VaultTx, VaultTxIn, VaultTxOut};
use kogany_vault::{Hash32, OutPoint, PubKeyBytes};
use kogany_yellowback::attest::mirror::{
    apply_bond_spend, apply_set_act, attestor_join_refused, refused_attestor_set_act, SetActEffect,
};
use kogany_yellowback::attest::registry::{
    AttestState, AttestorRecord, BundleLogRecord, Registry, RegistryRead, RegistryWrite,
};
use kogany_yellowback::attest::seats::{
    arm_pass, dormancy_pass, dormancy_window, maturity_pass, seating_pass, SelectionBasis,
};
use kogany_yellowback::params::{regtest_params, Params, COIN};
use sha2::{Digest, Sha256};

pub fn fake_hash(h: i64, tag: u8) -> Hash32 {
    let mut x = [0u8; 32];
    x[0] = (h & 0xff) as u8;
    x[1] = ((h >> 8) & 0xff) as u8;
    x[31] = tag;
    Hash32(x)
}

/// A deterministic test key: secret `SHA256(tag ‖ i)`.
pub fn det_secret(tag: &str, i: u32) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(tag.as_bytes());
    h.update(i.to_le_bytes());
    h.finalize().into()
}

pub fn det_key(tag: &str, i: u32) -> PubKeyBytes {
    kogany_vault::act::public_key(&det_secret(tag, i)).unwrap()
}

pub fn txid_of(outputs: &[VaultTxOut], salt: u64) -> Hash32 {
    let mut h = Sha256::new();
    h.update(salt.to_le_bytes());
    for o in outputs {
        h.update(o.value.to_le_bytes());
        h.update(&o.script_pubkey);
    }
    Hash32(h.finalize().into())
}

pub fn act_out(body: ActBody) -> VaultTxOut {
    VaultTxOut {
        value: 0,
        script_pubkey: encode_act(&Act {
            body,
            sigs: Vec::new(),
        }),
    }
}

pub fn act_tx(body: ActBody, extra: Vec<VaultTxOut>, salt: u64) -> VaultTx {
    let mut outputs = extra;
    outputs.push(act_out(body));
    VaultTx {
        txid: txid_of(&outputs, salt),
        coinbase: false,
        inputs: vec![VaultTxIn {
            prevout: OutPoint {
                txid: Hash32([0xfe; 32]),
                n: u32::try_from(salt & 0xffff_ffff).unwrap(),
            },
            script_sig: Vec::new(),
        }],
        outputs,
    }
}

/// The C++ fixture's SET_CREATE: open, 15 seats, 1/1/1 thresholds, maturity 8, livenessWindow
/// 1,000,000.
pub fn set_create_body() -> SetCreateBody {
    SetCreateBody {
        seats: 15,
        unlock_threshold: 1,
        cancel_threshold: 1,
        slash_threshold: 1,
        flags: SET_FLAG_OPEN,
        rate_limit_bps: 0,
        rate_window: 100,
        liveness_window: 1_000_000,
        bond_min: 1000,
        bond_lock_min: 0,
        maturity: 8,
        admit_key: det_key("yellowback-state-test-admit", 0),
    }
}

pub struct MiniChain {
    pub p: Params,
    pub reg: Registry,
    pub attest: AttestState,
    pub tip: i64,
    pub bases: BTreeMap<i64, SelectionBasis>,
    pub bundle_log: BTreeMap<i64, BundleLogRecord>,
    pub set_create: VaultTx,
    pub salt: u64,
    pub hot: Vec<[u8; 32]>,
}

impl MiniChain {
    /// `Fixture(start = 100)`: regtest parameters, the attestor set's SET_CREATE built (not
    /// mined), 20 deterministic hot keys.
    pub fn new() -> MiniChain {
        MiniChain::with_create(set_create_body())
    }

    pub fn with_create(body: SetCreateBody) -> MiniChain {
        let set_create = act_tx(ActBody::Create(body), Vec::new(), 0);
        let p = regtest_params(100, 0, 0, set_create.txid.0);
        MiniChain {
            p,
            reg: Registry::new(),
            attest: AttestState::default(),
            tip: 99,
            bases: BTreeMap::new(),
            bundle_log: BTreeMap::new(),
            set_create,
            salt: 1,
            hot: (0..20)
                .map(|i| det_secret("yellowback-state-test-hot", i))
                .collect(),
        }
    }

    pub fn hot_key(&self, i: usize) -> PubKeyBytes {
        kogany_vault::act::public_key(&self.hot[i]).unwrap()
    }

    pub fn block_hash(&self, h: i64) -> Option<Hash32> {
        self.bases.get(&h).map(|b| b.block_hash)
    }

    /// One block of `txs` at `tip + 1`: the mirror's per-transaction rules (bond spends, the
    /// refused acts, the set act), then SNAP's attestor passes. Returns each transaction's verdict
    /// ("" = applied or not an act).
    pub fn mine(&mut self, txs: &[VaultTx]) -> Vec<String> {
        let h = self.tip + 1;
        let mut verdicts = Vec::new();
        for tx in txs {
            for i in &tx.inputs {
                apply_bond_spend(&mut self.reg, &i.prevout, h);
            }
            if refused_attestor_set_act(tx, &self.p) {
                verdicts.push("attestor-set-act".to_owned());
                continue;
            }
            let floor = self.p.bond_min_floor_zat;
            if let Some(v) = attestor_join_refused(&self.reg, tx, &self.p, h, &|_: i64| floor) {
                verdicts.push(v.to_owned());
                continue;
            }
            apply_set_act(&mut self.reg, tx, &self.p, h);
            verdicts.push(String::new());
        }
        self.snap(h);
        self.tip = h;
        verdicts
    }

    pub fn snap(&mut self, h: i64) {
        let height = i32::try_from(h).unwrap();
        let mut attestors = self.reg.attestors();
        let set = self.reg.attestor_set();
        let floor = self.p.bond_min_floor_zat;
        let eligible = maturity_pass(&mut attestors, set.as_ref(), &self.p, height, &|_: i64| {
            floor
        });
        self.attest = arm_pass(&self.attest, &self.p, height, eligible);
        let seated = seating_pass(&mut attestors, set.as_ref(), &self.attest, &self.p, height);
        let rows: Vec<BundleLogRecord> = dormancy_window(&self.p, h)
            .filter_map(|x| self.bundle_log.get(&x).cloned())
            .collect();
        dormancy_pass(&mut attestors, &rows, &self.p, height);
        for (seq, rec) in attestors {
            if self.reg.attestor(seq) != Some(rec) {
                self.reg.put_attestor(seq, rec);
            }
        }
        self.bases.insert(
            h,
            SelectionBasis {
                block_hash: fake_hash(h, 0x5b),
                seated,
                pinned_seqs: Vec::new(),
                attest: self.attest,
            },
        );
    }

    pub fn empty(&mut self, n: i64) {
        for _ in 0..n {
            self.mine(&[]);
        }
    }

    pub fn ensure_set(&mut self) {
        if self.reg.attestor_set().is_none() {
            let c = self.set_create.clone();
            self.mine(&[c]);
            assert!(self.reg.attestor_set().is_some(), "the set is adopted");
        }
    }

    pub fn join_tx(&mut self, key: PubKeyBytes, bond: i64) -> VaultTx {
        self.salt += 1;
        let body = SetJoinBody {
            set_id: Hash32(self.p.attestor_set_id),
            member_key: key,
            bond_locktime: 1_000_000,
            bond_vout: 0,
        };
        act_tx(
            ActBody::Join(body),
            vec![VaultTxOut {
                value: bond,
                script_pubkey: vec![0x51],
            }],
            self.salt,
        )
    }

    /// `Register(n, first)`: one SET_JOIN per block of hot keys `first..first + n`, 10 YEC each.
    pub fn register(&mut self, n: usize, first: usize) -> Vec<u16> {
        self.ensure_set();
        let mut seqs = Vec::new();
        for i in first..first + n {
            let tx = self.join_tx(self.hot_key(i), 10 * COIN);
            let before = self.reg.next_seq();
            assert_eq!(self.mine(&[tx]), vec![String::new()]);
            assert_eq!(self.reg.next_seq(), before + 1);
            seqs.push(before);
        }
        seqs
    }

    pub fn attestor(&self, seq: u16) -> AttestorRecord {
        self.reg.attestor(seq).unwrap()
    }

    /// `Arm(n)`: register n, mine until ARMED.
    pub fn arm(&mut self, n: usize) {
        self.register(n, 0);
        let mut guard = 0;
        while !self.attest.is_armed() {
            self.mine(&[]);
            guard += 1;
            assert!(guard < 200, "never armed");
        }
    }

    pub fn last_effect(&mut self, tx: &VaultTx) -> Option<SetActEffect> {
        apply_set_act(&mut self.reg, tx, &self.p, self.tip + 1)
    }
}
