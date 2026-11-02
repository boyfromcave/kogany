// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

//! The Rust port of `yellowback_state_tests.cpp`'s `Fixture` (ycash6 `65cb4ae0f`): a synthetic
//! regtest chain over an in-memory [`YedState`], the C++ transaction builders (`MintTx`,
//! `TransferTx`, `SpendTx`, `RegisterTx`, `BundleFor`, `CarrierIn`, `Cosign`, …) and `Mine`, which
//! — as the template filter does — leaves out a transaction the module makes invalid (keeping
//! its log in `refused`) and evaluates the block again. The keys are deterministic where the C++
//! draws random ones; nothing a case asserts depends on which key it is.
#![allow(dead_code, missing_docs, clippy::too_many_arguments)]

use std::collections::{BTreeMap, BTreeSet};

use kogany_vault::act::{
    act_msg, encode_act, encode_payload as encode_act_payload, public_key, sign_recoverable, Act,
    ActBody, SetCreateBody, SetHeartbeatBody, SetJoinBody, SetRemoveBody, SET_FLAG_OPEN,
};
use kogany_vault::state::{VaultTx, VaultTxIn, VaultTxOut};
use kogany_vault::template::{build_intent, hash160, intent_for, p2sh_script_pubkey};
use kogany_vault::{Hash32, OutPoint, PqOwner, PubKeyBytes};
use kogany_yellowback::attest::attestation::{attest_message, cancel_cosign_message};
use kogany_yellowback::attest::bundle::{encode_bundle, Bundle, CancelCosignEntry, SigCache};
use kogany_yellowback::attest::registry::{
    AttestState, AttestorRecord, BundleLogRecord, RegistryRead,
};
use kogany_yellowback::attest::seats::selected;
use kogany_yellowback::attest::Attestation;
use kogany_yellowback::codecs::payload::{encode_payload, payload_script, Assignment, Payload};
use kogany_yellowback::codecs::script::{
    bond_script, carrier_script, carrier_script_sig, p2pkh_script, pq_key_script,
    yed_vault_params_at, yed_vault_script, yed_vault_script_at,
};
use kogany_yellowback::codecs::tag::{height_prefix, tag_push, CoinbaseTag};
use kogany_yellowback::math::{
    attest_fee_zat, early_redeem_fee_zat, min_ratio_bps, protocol_fee_zat,
    required_collateral_rounded,
};
use kogany_yellowback::params::{
    regtest_params_with, Amount, BundleCarrier, Cents, MicroUsd, Params, COIN, FEE_VOUT_NONE,
    TOKEN_VALUE,
};
use kogany_yellowback::state::{
    evaluate_block, selection_basis, BlockEvaluation, NoticeRecord, Snapshot, TokenRecord, Totals,
    TxLogRecord, VaultRecord, YedDelta, YedRead, YedState,
};
use secp256k1::{ecdsa, Message, SecretKey};
use sha2::{Digest, Sha256};

/// Regtest post-Blossom.
pub const SUBSIDY: Amount = 625_000_000;

pub fn sha256(b: &[u8]) -> [u8; 32] {
    Sha256::digest(b).into()
}

pub fn sha256d(b: &[u8]) -> [u8; 32] {
    Sha256::digest(Sha256::digest(b)).into()
}

/// The C++ `uint256S` of a display hex.
pub fn u256s(hex_str: &str) -> Hash32 {
    let mut b: [u8; 32] = hex::decode(format!("{hex_str:0>64}"))
        .unwrap()
        .try_into()
        .unwrap();
    b.reverse();
    Hash32(b)
}

/// The YED attestor set every fixture's V template names before the SET_CREATE replaces it.
pub fn test_set() -> Hash32 {
    u256s("5e75e75e75e75e75e75e75e75e75e75e75e75e75e75e75e75e75e75e75e75e7")
}

/// `KeyOf(i)`: twenty bytes of `0x10 + i`.
pub fn key_of(i: i64) -> [u8; 20] {
    [u8::try_from(0x10 + i).unwrap(); 20]
}

/// `DeterministicKey(tag, i)`: the secret `SHA256(tag ‖ i LE32)`.
pub fn det_secret(tag: &str, i: i32) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(tag.as_bytes());
    h.update(i.to_le_bytes());
    h.finalize().into()
}

pub fn pubkey(secret: &[u8; 32]) -> PubKeyBytes {
    public_key(secret).unwrap()
}

/// `CPubKey::GetID`.
pub fn key_id(pk: &PubKeyBytes) -> [u8; 20] {
    hash160(&pk.0)
}

/// `GetScriptForDestination(pk.GetID())`.
pub fn p2pkh_of(pk: &PubKeyBytes) -> Vec<u8> {
    p2pkh_script(&key_id(pk))
}

/// `TestPQOwner(k)`: an SLH-DSA key id `Hash(k)` standing in for the owner.
pub fn test_pq_owner(pk: &PubKeyBytes) -> PqOwner {
    PqOwner {
        scheme: 1,
        hash: Hash32(sha256d(&pk.0)),
    }
}

/// `Fixture::FakeHash(h)`.
pub fn fake_hash(h: i64) -> Hash32 {
    let mut v = [0u8; 32];
    v[0] = (h & 0xff) as u8;
    v[1] = ((h >> 8) & 0xff) as u8;
    v[31] = 0x5a;
    Hash32(v)
}

/// A push of `n` bytes of `0x30` (the C++ `valtype(71, 0x30)` placeholder signature).
pub fn fake_sig_push(n: usize) -> Vec<u8> {
    let mut s = vec![u8::try_from(n).unwrap()];
    s.extend(std::iter::repeat_n(0x30u8, n));
    s
}

/// A mutable transaction (the C++ `CMutableTransaction` restricted to what the module reads).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MTx {
    pub vin: Vec<VaultTxIn>,
    pub vout: Vec<VaultTxOut>,
    pub lock_time: u32,
}

pub fn txin(prevout: OutPoint) -> VaultTxIn {
    VaultTxIn {
        prevout,
        script_sig: Vec::new(),
    }
}

pub fn txout(value: Amount, script: Vec<u8>) -> VaultTxOut {
    VaultTxOut {
        value,
        script_pubkey: script,
    }
}

pub fn op(txid: Hash32, n: u32) -> OutPoint {
    OutPoint { txid, n }
}

impl MTx {
    /// A deterministic id over everything the transaction carries (the stand-in of `GetHash`).
    pub fn txid(&self) -> Hash32 {
        let mut b = Vec::new();
        b.extend_from_slice(&(self.vin.len() as u32).to_le_bytes());
        for i in &self.vin {
            b.extend_from_slice(&i.prevout.to_bytes());
            b.extend_from_slice(&(i.script_sig.len() as u32).to_le_bytes());
            b.extend_from_slice(&i.script_sig);
        }
        b.extend_from_slice(&(self.vout.len() as u32).to_le_bytes());
        for o in &self.vout {
            b.extend_from_slice(&o.value.to_le_bytes());
            b.extend_from_slice(&(o.script_pubkey.len() as u32).to_le_bytes());
            b.extend_from_slice(&o.script_pubkey);
        }
        b.extend_from_slice(&self.lock_time.to_le_bytes());
        Hash32(sha256d(&b))
    }

    pub fn tx(&self) -> VaultTx {
        VaultTx {
            txid: self.txid(),
            coinbase: VaultTx::inputs_are_coinbase(&self.vin),
            inputs: self.vin.clone(),
            outputs: self.vout.clone(),
        }
    }
}

/// `MintOpts`.
#[derive(Clone, Debug)]
pub struct MintOpts {
    pub term_class: u8,
    /// -1 = the required amount.
    pub collateral: Amount,
    /// -2 = the payee of the tag at refHeight; -1 = no fee output.
    pub fee_key: i64,
    pub fee_vout: u8,
    /// -1 = ProtocolFeeZat(cents, pMint).
    pub fee_value: Amount,
    pub p_mint: Option<MicroUsd>,
    pub owner: Option<PubKeyBytes>,
    pub raw_owner: Option<[u8; 33]>,
    pub extra_outputs: usize,
    /// The vault output is the V template; false = P2PKH(owner).
    pub p2sh_vault: bool,
    pub yed_inputs: Vec<OutPoint>,
    pub vault_script_override: Option<Vec<u8>>,
    pub bundle: Option<Vec<u8>>,
    /// -1 = no attestor-fee output.
    pub attest_payee: i64,
    pub attest_fee_value: Amount,
    pub attest_fee_vout: u8,
    pub attest_fee_script: Option<Vec<u8>>,
    pub pq_owner: Option<PqOwner>,
    pub token_script: Option<Vec<u8>>,
}

impl Default for MintOpts {
    fn default() -> MintOpts {
        MintOpts {
            term_class: 0,
            collateral: -1,
            fee_key: -2,
            fee_vout: 3,
            fee_value: -1,
            p_mint: None,
            owner: None,
            raw_owner: None,
            extra_outputs: 0,
            p2sh_vault: true,
            yed_inputs: Vec::new(),
            vault_script_override: None,
            bundle: None,
            attest_payee: -1,
            attest_fee_value: -1,
            attest_fee_vout: 4,
            attest_fee_script: None,
            pq_owner: None,
            token_script: None,
        }
    }
}

/// `SpendOpts`.
#[derive(Clone, Debug)]
pub struct SpendOpts {
    pub owner_path: bool,
    pub script_sig: Option<Vec<u8>>,
    pub fee_key: i64,
    pub fee_vout: u8,
    pub fee_value: Amount,
    pub assigned: Vec<Assignment>,
    pub payload: bool,
    pub payload_override: Option<Payload>,
    pub extra_vaults: Vec<OutPoint>,
    pub vault_first: bool,
    pub bundle: Option<Vec<u8>>,
    pub attest_payee: i64,
    pub attest_fee_value: Amount,
    pub residual_value: Option<Amount>,
    pub residual_script: Option<Vec<u8>>,
}

impl Default for SpendOpts {
    fn default() -> SpendOpts {
        SpendOpts {
            owner_path: true,
            script_sig: None,
            fee_key: -2,
            fee_vout: 1,
            fee_value: -1,
            assigned: Vec::new(),
            payload: true,
            payload_override: None,
            extra_vaults: Vec::new(),
            vault_first: true,
            bundle: None,
            attest_payee: -1,
            attest_fee_value: -1,
            residual_value: None,
            residual_script: None,
        }
    }
}

/// The C++ `Payload::Transfer`.
pub fn transfer_payload(a: &[Assignment]) -> Payload {
    Payload::Transfer(a.to_vec())
}

pub fn payload_out(p: &Payload) -> VaultTxOut {
    txout(0, payload_script(&encode_payload(p).unwrap()))
}

/// A synthetic chain over a [`YedState`] with the regtest parameters.
pub struct Fixture {
    pub p: Params,
    pub state: YedState,
    pub deltas: BTreeMap<i64, YedDelta>,
    pub evals: BTreeMap<i64, BlockEvaluation>,
    /// U-21: the transactions the module made invalid, which `mine` left out.
    pub refused: BTreeMap<Hash32, TxLogRecord>,
    pub tip: i64,
    pub owner_secret: [u8; 32],
    pub user_secret: [u8; 32],
    pub fake_counter: u32,
    /// Attestor i joins with member key `hot[i]` (the bond key since P4-b) and becomes seq i.
    pub hot: Vec<[u8; 32]>,
    pub cache: Option<Box<dyn SigCache>>,
    pub set_create: MTx,
    pub set_mined: bool,
}

pub const ACTIVATE_BLOCKS: i64 = 130;

impl Fixture {
    /// `Fixture()`: start 1, no sigma reference, no cap, `ATTEST_ARM_MIN` 3.
    pub fn new() -> Fixture {
        Fixture::with(1, 0, 0, 3)
    }

    /// `Fixture(start, sigmaRef, capBps, armMin)`.
    pub fn with(start: i32, sigma_ref: i32, cap_bps: i32, arm_min: i32) -> Fixture {
        let p = regtest_params_with(
            start,
            sigma_ref,
            cap_bps,
            test_set().0,
            arm_min,
            BundleCarrier::ScriptSig,
            false,
        );
        let hot = (0..20)
            .map(|i| det_secret("yellowback-state-test-hot", i))
            .collect();
        let mut f = Fixture {
            p,
            state: YedState::new(),
            deltas: BTreeMap::new(),
            evals: BTreeMap::new(),
            refused: BTreeMap::new(),
            tip: i64::from(start) - 1,
            owner_secret: det_secret("yellowback-state-test-owner", 0),
            user_secret: det_secret("yellowback-state-test-user", 0),
            fake_counter: 0,
            hot,
            cache: None,
            set_create: MTx::default(),
            set_mined: false,
        };
        f.recreate_set(1_000_000, 8, 15);
        f
    }

    pub fn owner_pub(&self) -> PubKeyBytes {
        pubkey(&self.owner_secret)
    }
    pub fn user_pub(&self) -> PubKeyBytes {
        pubkey(&self.user_secret)
    }
    pub fn user_p2pkh(&self) -> Vec<u8> {
        p2pkh_of(&self.user_pub())
    }
    pub fn hot_pub(&self, i: usize) -> PubKeyBytes {
        pubkey(&self.hot[i])
    }

    /// `RecreateSet`: the attestor set's SET_CREATE; `P.attestorSetId` becomes its txid.
    pub fn recreate_set(&mut self, liveness_window: u32, maturity: u32, seats: u8) {
        assert!(self.tip < i64::from(self.p.start_height));
        let body = SetCreateBody {
            seats,
            unlock_threshold: 1,
            cancel_threshold: 1,
            slash_threshold: 1,
            flags: SET_FLAG_OPEN,
            rate_limit_bps: 0,
            rate_window: 1000,
            liveness_window,
            bond_min: 1,
            bond_lock_min: 0,
            maturity,
            admit_key: pubkey(&det_secret("yellowback-state-test-admit", 0)),
        };
        let mut m = MTx::default();
        m.vin.push(txin(op(test_set(), 0)));
        m.vout.push(txout(
            0,
            encode_act(&Act {
                body: ActBody::Create(body),
                sigs: Vec::new(),
            }),
        ));
        self.p.attestor_set_id = m.txid().0;
        self.set_create = m;
    }

    /// `EnsureSet`: mine the SET_CREATE once, in its own block.
    pub fn ensure_set(&mut self) {
        if self.set_mined {
            return;
        }
        self.set_mined = true;
        let t = Fixture::quote(50000, (self.tip + 1) % 3);
        let sc = self.set_create.clone();
        self.mine(Some(t), vec![sc]);
        assert!(self.state.attestor_set().is_some());
    }

    /// `ActTx`: vin 0 a fake input, `before`, the act signed by `signers`, a change output.
    pub fn act_tx(&mut self, body: ActBody, signers: &[usize], before: Vec<VaultTxOut>) -> MTx {
        let mut m = MTx::default();
        m.vin.push(txin(self.fake_input()));
        m.vout = before;
        let msg = act_msg(&encode_act_payload(&body), &m.vin[0].prevout);
        let sigs = signers
            .iter()
            .map(|i| sign_recoverable(&self.hot[*i], &msg).unwrap())
            .collect();
        m.vout.push(txout(0, encode_act(&Act { body, sigs })));
        m.vout.push(txout(1000, self.user_p2pkh()));
        m
    }

    pub fn heartbeat_tx(&mut self, i: usize) -> MTx {
        let body = ActBody::Heartbeat(SetHeartbeatBody {
            set_id: Hash32(self.p.attestor_set_id),
            member_key: self.hot_pub(i),
        });
        self.act_tx(body, &[i], Vec::new())
    }

    pub fn remove_tx(&mut self, i: usize, by: usize, burn: bool) -> MTx {
        let body = ActBody::Remove(SetRemoveBody {
            set_id: Hash32(self.p.attestor_set_id),
            member_key: self.hot_pub(i),
            burn: u8::from(burn),
        });
        self.act_tx(body, &[by], Vec::new())
    }

    pub fn fake_input(&mut self) -> OutPoint {
        let mut v = [0x77u8; 32];
        v[0] = (self.fake_counter & 0xff) as u8;
        v[1] = ((self.fake_counter >> 8) & 0xff) as u8;
        self.fake_counter += 1;
        op(Hash32(v), 0)
    }

    /// `Quote(price, key, signal, mask)`.
    pub fn quote_with(price: MicroUsd, key: i64, signal: bool, mask: u16) -> CoinbaseTag {
        CoinbaseTag {
            flags: u8::from(signal),
            price_micro_usd: u64::try_from(price).unwrap(),
            source_mask: mask,
            payout_key: key_of(key),
        }
    }

    pub fn quote(price: MicroUsd, key: i64) -> CoinbaseTag {
        Fixture::quote_with(price, key, true, 7)
    }

    pub fn signal_only(key: i64) -> CoinbaseTag {
        Fixture::quote_with(0, key, true, 0)
    }

    pub fn coinbase(height: i64, tag: Option<&CoinbaseTag>) -> MTx {
        let mut sig = height_prefix(i32::try_from(height).unwrap());
        if let Some(t) = tag {
            sig.extend(tag_push(t));
        }
        MTx {
            vin: vec![VaultTxIn {
                prevout: op(Hash32::ZERO, u32::MAX),
                script_sig: sig,
            }],
            vout: vec![txout(SUBSIDY, p2pkh_script(&key_of(0)))],
            lock_time: 0,
        }
    }

    fn block(height: i64, tag: Option<&CoinbaseTag>, txs: &[MTx]) -> Vec<VaultTx> {
        let mut b = vec![Fixture::coinbase(height, tag).tx()];
        b.extend(txs.iter().map(MTx::tx));
        b
    }

    /// Evaluates a block at the next height (or `height`) without committing it.
    pub fn evaluate(
        &self,
        tag: Option<CoinbaseTag>,
        txs: &[MTx],
        height: Option<i64>,
    ) -> BlockEvaluation {
        let h = height.unwrap_or(self.tip + 1);
        let block = Fixture::block(h, tag.as_ref(), txs);
        evaluate_block(
            &self.state,
            &self.p,
            &block,
            h,
            &fake_hash(h),
            SUBSIDY,
            self.cache.as_deref(),
        )
    }

    /// Evaluates a raw block (`txs[0]` the coinbase) without committing it.
    pub fn evaluate_raw(&self, block: &[VaultTx], height: i64) -> BlockEvaluation {
        evaluate_block(
            &self.state,
            &self.p,
            block,
            height,
            &fake_hash(height),
            SUBSIDY,
            self.cache.as_deref(),
        )
    }

    /// `Mine`: evaluate and commit a block at the next height; a transaction the module makes
    /// invalid is left out (its log kept in `refused`) and the block evaluated again.
    pub fn mine(&mut self, tag: Option<CoinbaseTag>, txs: Vec<MTx>) -> BlockEvaluation {
        let h = self.tip + 1;
        self.mine_at(tag, txs, h)
    }

    pub fn mine_at(
        &mut self,
        tag: Option<CoinbaseTag>,
        mut txs: Vec<MTx>,
        h: i64,
    ) -> BlockEvaluation {
        loop {
            let ev = self.evaluate(tag, &txs, Some(h));
            if ev.block_invalid {
                let (bad, log) = ev
                    .txlogs
                    .last()
                    .cloned()
                    .expect("an invalid block names its transaction");
                self.refused.insert(bad, log);
                let before = txs.len();
                txs.retain(|m| m.txid() != bad);
                assert!(
                    txs.len() < before,
                    "the refused transaction is in the block"
                );
                continue;
            }
            self.state.apply(&ev.delta);
            self.deltas.insert(h, ev.delta.clone());
            self.evals.insert(h, ev.clone());
            self.tip = h;
            return ev;
        }
    }

    /// Mines an empty block (no tag).
    pub fn mine_empty(&mut self) -> BlockEvaluation {
        self.mine(None, Vec::new())
    }

    pub fn undo(&mut self) {
        let d = self.deltas.remove(&self.tip).unwrap();
        self.state.revert(&d);
        self.evals.remove(&self.tip);
        self.tip -= 1;
    }

    /// `MineQuotesTo`: quote+signal blocks from three rotating pools up to `h`.
    pub fn mine_quotes_to(&mut self, h: i64, price: MicroUsd) {
        while self.tip < h {
            let t = Fixture::quote(price, (self.tip + 1) % 3);
            self.mine(Some(t), Vec::new());
        }
    }

    /// `Activate`: every window filled and no halt.
    pub fn activate(&mut self, price: MicroUsd) {
        let h = i64::from(self.p.start_height) + ACTIVATE_BLOCKS;
        self.mine_quotes_to(h, price);
        assert_eq!(self.snap(self.tip).halt_mask, 0);
    }

    pub fn snap(&self, h: i64) -> Snapshot {
        self.state.snapshot(u32::try_from(h).unwrap()).unwrap()
    }
    pub fn snap_opt(&self, h: i64) -> Option<Snapshot> {
        u32::try_from(h).ok().and_then(|k| self.state.snapshot(k))
    }
    pub fn totals(&self) -> Totals {
        self.state.totals()
    }
    pub fn vault(&self, txid: &Hash32) -> Option<VaultRecord> {
        self.state.vault(&op(*txid, 0))
    }
    pub fn token(&self, txid: &Hash32, n: u32) -> Option<TokenRecord> {
        self.state.token(&op(*txid, n))
    }
    pub fn log(&self, txid: &Hash32) -> Option<TxLogRecord> {
        self.state
            .txlog(txid)
            .or_else(|| self.refused.get(txid).cloned())
    }
    /// U-21: the verdict that made `txid` invalid, or "".
    pub fn refused_verdict(&self, txid: &Hash32) -> String {
        self.refused
            .get(txid)
            .map(|l| l.verdict.clone())
            .unwrap_or_default()
    }

    pub fn required(&self, cents: Cents, class: usize, ref_height: i64) -> Amount {
        let s = self.snap(ref_height);
        required_collateral_rounded(
            cents,
            min_ratio_bps(self.p.base_ratio_bps[class], s.sigma_mult_bps),
            s.pmint().unwrap(),
            1000,
        )
        .unwrap()
    }

    /// The cross-section xMint at refHeight (0 = undefined).
    pub fn pmint_at(&self, ref_height: i64) -> MicroUsd {
        self.snap_opt(ref_height)
            .and_then(|s| s.pmint())
            .unwrap_or(0)
    }
    pub fn mint_fee(&self, cents: Cents, ref_height: i64) -> Amount {
        protocol_fee_zat(cents, self.pmint_at(ref_height), &self.p).unwrap_or(0)
    }
    pub fn vault_fee(&self, v: &VaultRecord) -> Amount {
        protocol_fee_zat(v.minted_cents, v.p_mint, &self.p).unwrap_or(0)
    }

    /// `MintTx`: a MINT of `cents` with `lockHeight = refHeight + lockBlocks`.
    pub fn mint_tx(&mut self, cents: Cents, lock_blocks: i64, ref_height: i64, o: MintOpts) -> MTx {
        let owner = o.owner.unwrap_or_else(|| self.owner_pub());
        let lock = u32::try_from(ref_height + lock_blocks).unwrap();
        let pq_owner = o.pq_owner.unwrap_or_else(|| test_pq_owner(&owner));
        let vs = o
            .vault_script_override
            .clone()
            .unwrap_or_else(|| yed_vault_script(&self.p, &pq_owner, ref_height).unwrap());
        let mut collateral = o.collateral;
        if collateral < 0 {
            let cls = if self.p.is_valid_class(i64::from(o.term_class)) {
                usize::from(o.term_class)
            } else {
                0
            };
            collateral = self.required(cents, cls, ref_height);
        }
        let mut m = MTx::default();
        m.vin.push(txin(self.fake_input()));
        for y in &o.yed_inputs {
            m.vin.push(txin(*y));
        }
        m.vout.push(txout(
            collateral,
            if o.p2sh_vault { vs } else { p2pkh_of(&owner) },
        ));
        m.vout.push(txout(
            TOKEN_VALUE,
            o.token_script.clone().unwrap_or_else(|| p2pkh_of(&owner)),
        ));
        let mut payload = Payload::mint(
            o.term_class,
            u32::try_from(cents).unwrap(),
            lock,
            u32::try_from(ref_height).unwrap(),
            &pq_owner,
            if o.fee_key == -1 {
                FEE_VOUT_NONE
            } else {
                o.fee_vout
            },
            if o.attest_payee >= 0 {
                o.attest_fee_vout
            } else {
                FEE_VOUT_NONE
            },
        );
        if let (Some(raw), Payload::Mint(mm)) = (o.raw_owner, &mut payload) {
            mm.owner_bytes = raw;
        }
        m.vout.push(payload_out(&payload));
        let fee_price = o.p_mint.unwrap_or_else(|| self.pmint_at(ref_height));
        if o.fee_key != -1 {
            let key = if o.fee_key == -2 {
                ref_height % 3
            } else {
                o.fee_key
            };
            let fee = if o.fee_value >= 0 {
                o.fee_value
            } else {
                protocol_fee_zat(cents, fee_price, &self.p).unwrap_or(0)
            };
            m.vout.push(txout(fee, p2pkh_script(&key_of(key))));
        }
        if o.attest_payee >= 0 {
            while m.vout.len() < 4 {
                m.vout.push(txout(1000, self.user_p2pkh()));
            }
            let afee = if o.attest_fee_value >= 0 {
                o.attest_fee_value
            } else {
                attest_fee_zat(
                    protocol_fee_zat(cents, fee_price, &self.p).unwrap_or(0),
                    self.p.attest_fee_bps,
                )
            };
            let s = o.attest_fee_script.clone().unwrap_or_else(|| {
                p2pkh_of(&self.hot_pub(usize::try_from(o.attest_payee).unwrap()))
            });
            m.vout.push(txout(afee, s));
        }
        for _ in 0..o.extra_outputs {
            m.vout.push(txout(1000, self.user_p2pkh()));
        }
        if let Some(b) = &o.bundle {
            let ci = self.carrier_in(b);
            m.vin.push(ci);
        }
        m
    }

    /// `TransferTx`.
    pub fn transfer_tx(
        &mut self,
        inputs: &[OutPoint],
        a: &[Assignment],
        redeem_type: bool,
        ref_height: u32,
    ) -> MTx {
        let mut m = MTx::default();
        for i in inputs {
            m.vin.push(txin(*i));
        }
        let n_out = a.iter().map(|x| usize::from(x.vout) + 1).max().unwrap_or(0);
        for _ in 0..n_out {
            m.vout.push(txout(TOKEN_VALUE, self.user_p2pkh()));
        }
        let p = if redeem_type {
            Payload::redeem(ref_height, FEE_VOUT_NONE, a.to_vec(), FEE_VOUT_NONE)
        } else {
            transfer_payload(a)
        };
        m.vout.push(payload_out(&p));
        m
    }

    /// `SpendTx`: vin 0 the vault (or a YED input when `!vault_first`), the YED inputs; vout 0
    /// collateral (the owner) or the claimant intent (a claim), vout 1 fee, vout 2 OP_RETURN,
    /// vout 3.. tokens.
    pub fn spend_tx(
        &mut self,
        vault_txid: &Hash32,
        yed: &[OutPoint],
        ref_height: i64,
        o: SpendOpts,
    ) -> MTx {
        let v = self.vault(vault_txid).expect("the vault");
        let p = self.p.clone();
        let owner = v.owner();
        let (oh, ah) = (i64::from(v.owner_height), i64::from(v.app_height));
        let vs = yed_vault_script_at(&p, &owner, oh, ah).unwrap();
        let vp = yed_vault_params_at(&p, &owner, oh, ah);
        let sig = o.script_sig.clone().unwrap_or_else(|| {
            if o.owner_path {
                let mut s = fake_sig_push(71);
                s.push(0x52); // OP_2
                s
            } else {
                vec![0x54] // OP_4
            }
        });
        let mut m = MTx {
            lock_time: u32::try_from(if o.owner_path { oh } else { ah }).unwrap(),
            ..MTx::default()
        };
        if !o.vault_first {
            m.vin.push(txin(yed[0]));
        }
        m.vin.push(VaultTxIn {
            prevout: op(*vault_txid, 0),
            script_sig: sig.clone(),
        });
        for e in &o.extra_vaults {
            m.vin.push(VaultTxIn {
                prevout: *e,
                script_sig: sig.clone(),
            });
        }
        for y in yed.iter().skip(if o.vault_first { 0 } else { 1 }) {
            m.vin.push(txin(*y));
        }
        if o.owner_path {
            m.vout
                .push(txout(v.collateral_zat - 1000, self.user_p2pkh()));
        } else {
            let residual = o.residual_value.unwrap_or(0);
            let intent = build_intent(&intent_for(&vp, &vs, &self.user_p2pkh())).unwrap();
            m.vout.push(txout(v.collateral_zat - residual, intent));
            let fi = self.fake_input();
            m.vin.push(txin(fi)); // the claim's fees
        }
        let key = if o.fee_key == -2 {
            ref_height % 3
        } else {
            o.fee_key
        };
        let mut fee = if o.fee_value >= 0 {
            o.fee_value
        } else {
            self.vault_fee(&v)
        };
        if o.fee_value < 0 && o.owner_path && self.tip + 1 < i64::from(v.lock_height) {
            fee += early_redeem_fee_zat(
                v.minted_cents,
                p.early_redeem_fee_bps[usize::from(v.term_class)],
                v.p_mint,
            );
        }
        m.vout.push(txout(
            fee,
            p2pkh_script(&key_of(if key < 0 { 9 } else { key })),
        ));
        let mut n_out = 3usize;
        for a in &o.assigned {
            n_out = n_out.max(usize::from(a.vout) + 1);
        }
        let attest_fee_vout = if o.attest_payee >= 0 {
            u8::try_from(n_out).unwrap()
        } else {
            FEE_VOUT_NONE
        };
        if o.payload {
            let pl = o.payload_override.clone().unwrap_or_else(|| {
                Payload::redeem(
                    u32::try_from(ref_height).unwrap(),
                    if o.fee_key == -1 {
                        FEE_VOUT_NONE
                    } else {
                        o.fee_vout
                    },
                    o.assigned.clone(),
                    attest_fee_vout,
                )
            });
            m.vout.push(payload_out(&pl));
        } else {
            m.vout.push(txout(0, self.user_p2pkh()));
        }
        while m.vout.len() < n_out {
            m.vout.push(txout(TOKEN_VALUE, self.user_p2pkh()));
        }
        if o.attest_payee >= 0 {
            let afee = if o.attest_fee_value >= 0 {
                o.attest_fee_value
            } else {
                attest_fee_zat(self.vault_fee(&v), p.attest_fee_bps)
            };
            m.vout.push(txout(
                afee,
                p2pkh_of(&self.hot_pub(usize::try_from(o.attest_payee).unwrap())),
            ));
        }
        if let Some(rv) = o.residual_value {
            let to = o
                .residual_script
                .clone()
                .unwrap_or_else(|| pq_key_script(&owner).unwrap());
            let s = if o.owner_path {
                to
            } else {
                build_intent(&intent_for(&vp, &vs, &to)).unwrap()
            };
            m.vout.push(txout(rv, s));
        }
        if let Some(b) = &o.bundle {
            let ci = self.carrier_in(b);
            m.vin.push(ci);
        }
        m
    }

    // ---------------------------------------------------------------- v3 helpers

    pub fn attestor(&self, seq: u16) -> Option<AttestorRecord> {
        self.state.attestor(seq)
    }
    pub fn attest(&self) -> AttestState {
        self.state.attest()
    }
    pub fn notice(&self, vault_txid: &Hash32) -> Option<NoticeRecord> {
        self.state.notice(&op(*vault_txid, 0))
    }
    pub fn bundle_row(&self, h: i64) -> Option<BundleLogRecord> {
        self.state.bundle_log(u32::try_from(h).unwrap())
    }
    pub fn armed(&self) -> bool {
        self.p.is_armed(self.attest().is_armed())
    }
    pub fn armed_at(&self, r: i64) -> bool {
        kogany_yellowback::state::armed_at(&self.state, &self.p, r)
    }

    /// `RegisterTx`: attestor i joins the attestor set: vout 0 the bond, vout 1 the SET_JOIN.
    pub fn register_tx(
        &mut self,
        i: usize,
        bond_zat: Amount,
        lock_blocks: i64,
        signer: Option<usize>,
    ) -> MTx {
        self.ensure_set();
        let s = signer.unwrap_or(i);
        let key = self.hot_pub(s);
        let lb = if lock_blocks < 0 {
            i64::from(self.p.bond_min_lock)
        } else {
            lock_blocks
        };
        let locktime = u32::try_from(self.tip + 1 + lb).unwrap();
        let body = ActBody::Join(SetJoinBody {
            set_id: Hash32(self.p.attestor_set_id),
            member_key: key,
            bond_locktime: locktime,
            bond_vout: 0,
        });
        let bond = txout(
            bond_zat,
            p2sh_script_pubkey(&bond_script(&key, locktime).unwrap()),
        );
        self.act_tx(body, &[s], vec![bond])
    }

    /// `Register(n, from)`: attestors `[from, from + n)`, one per block.
    pub fn register(&mut self, n: usize, from: usize) {
        self.ensure_set();
        for i in from..from + n {
            let t = Fixture::quote(50000, (self.tip + 1) % 3);
            let r = self.register_tx(i, 10 * COIN, -1, None);
            self.mine(Some(t), vec![r]);
            assert!(
                self.attestor(u16::try_from(i).unwrap()).is_some(),
                "attestor {i} not registered"
            );
        }
    }

    /// `Arm(n, price)`: activate, register n attestors and mine until ARMED (and one more).
    pub fn arm(&mut self, n: usize, price: MicroUsd) {
        if self.tip < i64::from(self.p.start_height) + ACTIVATE_BLOCKS {
            self.activate(price);
        }
        self.register(n, 0);
        while !self.attest().is_armed() {
            let t = Fixture::quote(price, (self.tip + 1) % 3);
            self.mine(Some(t), Vec::new());
        }
        let t = Fixture::quote(price, (self.tip + 1) % 3);
        self.mine(Some(t), Vec::new());
        assert!(self.attest().is_armed());
        assert_eq!(self.armed_at(self.tip - 1), self.p.attest_required);
    }

    /// `Att`: attestor `seq`'s compact low-S signature over (seq, price, cited, blockHash).
    pub fn att(
        &self,
        seq: usize,
        price: MicroUsd,
        cited: i64,
        block_hash: Option<Hash32>,
    ) -> Attestation {
        let (s, pr, c) = (
            u16::try_from(seq).unwrap(),
            u32::try_from(price).unwrap(),
            u32::try_from(cited).unwrap(),
        );
        let bh = block_hash.unwrap_or_else(|| fake_hash(cited));
        let msg = attest_message(s, pr, c, &bh);
        let sk = SecretKey::from_secret_bytes(self.hot[seq]).unwrap();
        let sig = ecdsa::sign(Message::from_digest(msg.0), &sk).serialize_compact();
        Attestation {
            seq: s,
            price_micro_usd: pr,
            cited_height: c,
            sig,
        }
    }

    /// `Selected(view, P, R, selector)`.
    pub fn selected(&self, r: i64, selector: &[u8]) -> Vec<u16> {
        let basis = selection_basis(&self.state, &self.p, r);
        selected(basis.as_ref(), &self.state, &self.p, r, selector)
    }

    /// `BundleFor`: every selected seq not in `skip` signs `price` (or `prices[seq]`) citing
    /// `cited` (default R).
    pub fn bundle_for(
        &self,
        r: i64,
        selector: &[u8],
        price: MicroUsd,
        skip: &BTreeSet<u16>,
        cited: Option<i64>,
        prices: &BTreeMap<u16, MicroUsd>,
    ) -> Vec<u8> {
        let atts: Vec<Attestation> = self
            .selected(r, selector)
            .into_iter()
            .filter(|s| !skip.contains(s))
            .map(|s| {
                self.att(
                    usize::from(s),
                    prices.get(&s).copied().unwrap_or(price),
                    cited.unwrap_or(r),
                    None,
                )
            })
            .collect();
        encode_bundle(&Bundle::of(atts))
    }

    pub fn bundle_simple(&self, r: i64, selector: &[u8], price: MicroUsd) -> Vec<u8> {
        self.bundle_for(r, selector, price, &BTreeSet::new(), None, &BTreeMap::new())
    }

    /// `CarrierIn`: a carrier-shaped input whose redeem script commits to `bundle`.
    pub fn carrier_in(&mut self, bundle: &[u8]) -> VaultTxIn {
        let h = Hash32(sha256(bundle));
        let redeem = carrier_script(&self.user_pub(), &h).unwrap();
        VaultTxIn {
            prevout: self.fake_input(),
            script_sig: carrier_script_sig(bundle, &[0x30; 71], &redeem),
        }
    }

    /// `Cosign`: member `seq`'s CANCEL_COSIGN statement of `intent` at the claim's R.
    pub fn cosign(
        &self,
        seq: usize,
        price: MicroUsd,
        intent: &OutPoint,
        r: i64,
        block_hash: Option<Hash32>,
    ) -> CancelCosignEntry {
        let pr = u32::try_from(price).unwrap();
        let msg = cancel_cosign_message(
            &Hash32(self.p.attestor_set_id),
            &intent.txid,
            intent.n,
            u32::try_from(r).unwrap(),
            pr,
            &block_hash.unwrap_or_else(|| fake_hash(r)),
        );
        CancelCosignEntry {
            price_micro_usd: pr,
            sig: sign_recoverable(&self.hot[seq], &msg).unwrap(),
        }
    }

    /// `NoticeTx`: a CLAIM_NOTICE for `(vault, 0)` with refHeight R carrying `bundle`.
    pub fn notice_tx(&mut self, vault_txid: &Hash32, r: i64, bundle: &[u8]) -> MTx {
        let mut m = MTx::default();
        m.vin.push(txin(self.fake_input()));
        let ci = self.carrier_in(bundle);
        m.vin.push(ci);
        let n = kogany_yellowback::codecs::payload::ClaimNotice::from_outpoint(
            &op(*vault_txid, 0),
            u32::try_from(r).unwrap(),
        );
        m.vout.push(payload_out(&Payload::ClaimNotice(n)));
        m.vout.push(txout(1000, self.user_p2pkh()));
        m
    }

    pub fn equivocation_tx(&mut self, a: &Attestation, b: &Attestation) -> MTx {
        let bundle = encode_bundle(&Bundle::of(vec![*a, *b]));
        let mut m = MTx::default();
        let ci = self.carrier_in(&bundle);
        m.vin.push(ci);
        m.vout.push(payload_out(&Payload::Equivocation));
        m.vout.push(txout(1000, self.user_p2pkh()));
        m
    }

    pub fn bond_spend_tx(&self, seq: u16) -> MTx {
        let rec = self.attestor(seq).unwrap();
        let bond = bond_script(&rec.bond_pub_key, rec.bond_locktime).unwrap();
        let mut sig = fake_sig_push(71);
        sig.extend(
            kogany_vault::script::Builder::new()
                .push(&bond)
                .into_bytes(),
        );
        MTx {
            vin: vec![VaultTxIn {
                prevout: rec.bond_outpoint,
                script_sig: sig,
            }],
            vout: vec![txout(rec.bond_zat - 1000, self.user_p2pkh())],
            lock_time: rec.bond_locktime,
        }
    }

    /// `MintV3`: an ARMED mint at tip + 1 with refHeight = tip - 1.
    pub fn mint_v3(
        &mut self,
        cents: Cents,
        price: MicroUsd,
        mut o: MintOpts,
        skip: &BTreeSet<u16>,
        lock_blocks: i64,
    ) -> MTx {
        let r = self.tip - 1;
        o.bundle = Some(self.bundle_for(r, &[], price, skip, None, &BTreeMap::new()));
        if o.p_mint.is_none() && self.pmint_at(r) > 0 {
            o.p_mint = Some(self.pmint_at(r).min(price));
        }
        if o.attest_payee == -1 {
            if let Some(q) = self
                .selected(r, &[])
                .into_iter()
                .find(|q| !skip.contains(q))
            {
                o.attest_payee = i64::from(q);
            }
        }
        if o.collateral < 0 {
            let s = self.snap(r);
            let pm = s.pmint().unwrap().min(price);
            let cls = if self.p.is_valid_class(i64::from(o.term_class)) {
                usize::from(o.term_class)
            } else {
                0
            };
            o.collateral = required_collateral_rounded(
                cents,
                min_ratio_bps(self.p.base_ratio_bps[cls], s.sigma_mult_bps),
                pm,
                1000,
            )
            .unwrap();
        }
        self.mint_tx(cents, lock_blocks, r, o)
    }

    /// `MintActive`: a ready ACTIVE vault (mint at tip + 1, refHeight = tip - 1); the mint txid.
    pub fn mint_active(&mut self, cents: Cents, lock_blocks: i64, term_class: u8) -> Hash32 {
        let r = self.tip - 1;
        let m = self.mint_tx(
            cents,
            lock_blocks,
            r,
            MintOpts {
                term_class,
                ..MintOpts::default()
            },
        );
        let t = Fixture::quote(50000, (self.tip + 1) % 3);
        self.mine(Some(t), vec![m.clone()]);
        let txid = m.txid();
        let v = self.vault(&txid);
        assert!(
            v.as_ref()
                .is_some_and(|v| v.status == kogany_yellowback::state::VaultStatus::Active),
            "MintActive at {} ref {r}: {}",
            self.tip,
            self.refused_verdict(&txid)
        );
        txid
    }

    pub fn mint_active10k(&mut self) -> Hash32 {
        self.mint_active(10000, 48, 0)
    }
}

/// `MintVerdictOf`: mine a MINT at the next height; the verdict that made it invalid, "" for an
/// ACTIVE vault, "none" when no vault was created. `invalid`: the mint was refused.
pub fn mint_verdict_of(f: &mut Fixture, m: &MTx) -> (String, bool) {
    let t = Fixture::quote(50000, (f.tip + 1) % 3);
    f.mine(Some(t), vec![m.clone()]);
    let txid = m.txid();
    let refused = f.refused_verdict(&txid);
    if !refused.is_empty() {
        return (refused, true);
    }
    match f.vault(&txid) {
        None => ("none".to_owned(), false),
        Some(v) if v.status == kogany_yellowback::state::VaultStatus::Active => {
            (String::new(), false)
        }
        Some(v) => (v.void_reason, false),
    }
}

/// `mint_verdict_of(..).0`.
pub fn mv(f: &mut Fixture, m: &MTx) -> String {
    mint_verdict_of(f, m).0
}

/// The result of a vault spend (`RedResult`).
pub struct RedResult {
    pub verdict: String,
    pub invalid: bool,
    pub vault: VaultRecord,
    pub log: TxLogRecord,
}

/// `Spend`: mine `tx` at the next height; its verdict and the vault after.
pub fn spend(f: &mut Fixture, vault_txid: &Hash32, tx: &MTx) -> RedResult {
    let t = Fixture::quote(50000, (f.tip + 1) % 3);
    f.mine(Some(t), vec![tx.clone()]);
    let txid = tx.txid();
    let log = f.log(&txid);
    RedResult {
        invalid: !f.refused_verdict(&txid).is_empty(),
        vault: f.vault(vault_txid).unwrap(),
        verdict: log
            .as_ref()
            .map_or("none".to_owned(), |l| l.verdict.clone()),
        log: log.unwrap_or_default(),
    }
}

/// The 36-byte outpoint selector of `(txid, 0)`.
pub fn vault_selector(txid: &Hash32) -> Vec<u8> {
    op(*txid, 0).to_bytes().to_vec()
}

/// The state hash's hex.
pub fn hash_hex(s: &YedState) -> String {
    hex::encode(kogany_yellowback::state::state_hash(s, "regtest"))
}

pub fn none_skip() -> BTreeSet<u16> {
    BTreeSet::new()
}

/// Reads a registry entry (silences an unused import on some test files).
pub fn attestors_of(s: &YedState) -> Vec<(u16, AttestorRecord)> {
    s.attestors()
}
