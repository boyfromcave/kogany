//! The C++ `vault_state_tests.cpp` fixture, re-expressed: a tiny chain over an in-memory
//! [`SetState`], coins for every output created, one delta per block.
#![allow(dead_code, missing_docs)]

use std::collections::BTreeMap;

use kogany_vault::act::{
    act_msg, encode_act, encode_payload, public_key, sign_recoverable, Act, ActBody, SetCreateBody,
    SetHeartbeatBody, SetJoinBody, SetRemoveBody, SetWindDownBody, SET_FLAG_OPEN,
};
use kogany_vault::script::{op, Builder};
use kogany_vault::state::{
    apply_block, check_tx, registered_modules, BlockHashFn, Delta, MemberRecord, ModuleEntry,
    Rules, SetState, SpentCoin, StateRead, VaultTx, VaultTxIn, VaultTxOut,
};
use kogany_vault::template::{bond_script_pubkey, build_vault, hash160, VaultParams};
use kogany_vault::{Hash32, OutPoint, PqOwner, PubKeyBytes, SetId, Tag};
use sha2::{Digest, Sha256};

pub const COIN: i64 = 100_000_000;

pub fn sha256d(b: &[u8]) -> Hash32 {
    Hash32(Sha256::digest(Sha256::digest(b)).into())
}

/// The C++ `uint256S("0x…")` of a small number: its little-endian internal bytes.
pub fn u256(n: u64) -> Hash32 {
    let mut h = [0u8; 32];
    h[..8].copy_from_slice(&n.to_le_bytes());
    Hash32(h)
}

/// A test key: secret `0x33 0…0 seed` (C++ `MakeKey`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Key {
    pub secret: [u8; 32],
}

pub fn make_key(seed: u8) -> Key {
    let mut secret = [0u8; 32];
    secret[0] = 0x33;
    secret[31] = seed;
    Key { secret }
}

impl Key {
    pub fn pubkey(&self) -> PubKeyBytes {
        public_key(&self.secret).unwrap()
    }
    pub fn sign(&self, msg: &Hash32) -> kogany_vault::RecoverableSig {
        sign_recoverable(&self.secret, msg).unwrap()
    }
}

/// P2PKH of the key `seed` (C++ `Recipient`).
pub fn recipient(seed: u8) -> Vec<u8> {
    p2pkh(&make_key(seed).pubkey())
}

pub fn p2pkh(pk: &PubKeyBytes) -> Vec<u8> {
    Builder::new()
        .op(op::OP_DUP)
        .op(op::OP_HASH160)
        .push(&hash160(&pk.0))
        .op(op::OP_EQUALVERIFY)
        .op(op::OP_CHECKSIG)
        .into_bytes()
}

/// The SET_CREATE parameters every case starts from (C++ `Params`).
pub fn params(open: bool) -> SetCreateBody {
    SetCreateBody {
        seats: 5,
        unlock_threshold: 2,
        cancel_threshold: 1,
        slash_threshold: 2,
        flags: if open { SET_FLAG_OPEN } else { 0 },
        rate_limit_bps: 0,
        rate_window: 100,
        liveness_window: 50,
        bond_min: 1000,
        bond_lock_min: 10,
        maturity: 5,
        admit_key: make_key(200).pubkey(),
    }
}

pub fn txin(prevout: OutPoint, script_sig: Vec<u8>) -> VaultTxIn {
    VaultTxIn {
        prevout,
        script_sig,
    }
}

pub fn txout(value: i64, spk: Vec<u8>) -> VaultTxOut {
    VaultTxOut {
        value,
        script_pubkey: spk,
    }
}

/// A transaction with its txid computed over its contents (a test-only serialisation: the
/// rules never read the txid's preimage) and the C++ coinbase predicate.
pub fn mk(inputs: Vec<VaultTxIn>, outputs: Vec<VaultTxOut>) -> VaultTx {
    rehash(VaultTx {
        txid: Hash32::ZERO,
        coinbase: false,
        inputs,
        outputs,
    })
}

/// Recomputes txid and the coinbase flag after a mutation.
pub fn rehash(mut t: VaultTx) -> VaultTx {
    let mut b = Vec::new();
    for i in &t.inputs {
        b.extend_from_slice(&i.prevout.to_bytes());
        b.extend_from_slice(&(i.script_sig.len() as u64).to_le_bytes());
        b.extend_from_slice(&i.script_sig);
    }
    b.push(0xee);
    for o in &t.outputs {
        b.extend_from_slice(&o.value.to_le_bytes());
        b.extend_from_slice(&(o.script_pubkey.len() as u64).to_le_bytes());
        b.extend_from_slice(&o.script_pubkey);
    }
    t.txid = sha256d(&b);
    t.coinbase = VaultTx::inputs_are_coinbase(&t.inputs);
    t
}

pub fn null_prevout() -> OutPoint {
    OutPoint {
        txid: Hash32::ZERO,
        n: u32::MAX,
    }
}

/// "OK" or the reject reason (C++ `Res`).
pub fn res<T>(r: Result<T, kogany_vault::state::VaultReject>) -> String {
    match r {
        Ok(_) => "OK".to_owned(),
        Err(e) => e.reason().to_owned(),
    }
}

pub struct Chain {
    pub st: SetState,
    pub coins: BTreeMap<OutPoint, SpentCoin>,
    pub h: i64,
    pub activation: i64,
    pub min_maturity: u32,
    pub fund_counter: u32,
    pub modules: &'static [ModuleEntry<'static>],
    pub hashes: Option<BlockHashFn<'static>>,
    /// (state before the block, the block's delta), per connected block.
    pub history: Vec<(SetState, Delta)>,
}

impl Default for Chain {
    fn default() -> Self {
        Chain::new()
    }
}

impl Chain {
    pub fn new() -> Chain {
        Chain {
            st: SetState::new(),
            coins: BTreeMap::new(),
            h: 100,
            activation: 0,
            // The unit cases use small set maturities: D-Q-31's floor is lifted for the suite
            // and checked in min_set_maturity.
            min_maturity: 0,
            fund_counter: 0,
            modules: registered_modules(),
            hashes: None,
            history: Vec::new(),
        }
    }

    pub fn rules(&self) -> Rules<'static> {
        Rules {
            activation_height: self.activation,
            min_set_maturity: self.min_maturity,
            modules: self.modules,
            block_hashes: self.hashes,
        }
    }

    pub fn fund(&mut self, value: i64) -> OutPoint {
        self.fund_counter += 1;
        let mut h = [0u8; 32];
        h[..4].copy_from_slice(&self.fund_counter.to_le_bytes());
        h[31] = 0xfe;
        let op = OutPoint {
            txid: Hash32(h),
            n: 0,
        };
        self.coins.insert(
            op,
            SpentCoin {
                script_pubkey: recipient(250),
                value,
                height: 1,
            },
        );
        op
    }

    pub fn fund10(&mut self) -> OutPoint {
        self.fund(10 * COIN)
    }

    /// Applies a block at h; on success commits and advances h.
    pub fn block(&mut self, txs: &[VaultTx]) -> String {
        let rules = self.rules();
        match apply_block(&self.st, txs, self.h, &self.coins, &rules) {
            Err(e) => e.reason().to_owned(),
            Ok(delta) => {
                self.history.push((self.st.clone(), delta.clone()));
                self.st.apply(&delta);
                for tx in txs {
                    for (o, out) in tx.outputs.iter().enumerate() {
                        self.coins.insert(
                            OutPoint {
                                txid: tx.txid,
                                n: o as u32,
                            },
                            SpentCoin {
                                script_pubkey: out.script_pubkey.clone(),
                                value: out.value,
                                height: self.h,
                            },
                        );
                    }
                }
                self.h += 1;
                "OK".to_owned()
            }
        }
    }

    pub fn block1(&mut self, tx: &VaultTx) -> String {
        self.block(std::slice::from_ref(tx))
    }

    pub fn empty(&mut self, n: i64) {
        for _ in 0..n {
            assert_eq!(self.block(&[]), "OK");
        }
    }

    /// A reject check that does not advance.
    pub fn try_tx(&self, tx: &VaultTx) -> String {
        res(check_tx(&self.st, tx, self.h, &self.coins, &self.rules()))
    }

    pub fn member(&self, s: &SetId, k: &Key) -> MemberRecord {
        self.st.member(s, &k.pubkey()).expect("a member")
    }
}

/// A transaction carrying one act, signed by `signers` over actMsg; extra outputs first.
pub fn act_tx(c: &mut Chain, body: ActBody, signers: &[Key], extra: Vec<VaultTxOut>) -> VaultTx {
    let vin0 = c.fund10();
    let msg = act_msg(&encode_payload(&body), &vin0);
    let sigs = signers.iter().map(|k| k.sign(&msg)).collect();
    let mut outputs = extra;
    outputs.push(txout(0, encode_act(&Act { body, sigs })));
    mk(vec![txin(vin0, Vec::new())], outputs)
}

pub fn make_set(c: &mut Chain, p: SetCreateBody) -> SetId {
    let m = act_tx(c, ActBody::Create(p), &[], vec![]);
    assert_eq!(c.block1(&m), "OK");
    m.txid
}

pub fn join_tx_with(
    c: &mut Chain,
    set_id: SetId,
    member: &Key,
    cosigners: &[Key],
    bond: i64,
    locktime_ahead: i64,
) -> VaultTx {
    let j = SetJoinBody {
        set_id,
        member_key: member.pubkey(),
        bond_locktime: (c.h + locktime_ahead) as u32,
        bond_vout: 0,
    };
    let mut signers = vec![*member];
    signers.extend_from_slice(cosigners);
    let spk = bond_script_pubkey(j.bond_locktime, &member.pubkey()).unwrap();
    act_tx(c, ActBody::Join(j), &signers, vec![txout(bond, spk)])
}

pub fn join_tx(c: &mut Chain, set_id: SetId, member: &Key, cosigners: &[Key]) -> VaultTx {
    join_tx_with(c, set_id, member, cosigners, 1000, 1000)
}

pub fn heartbeat_tx(c: &mut Chain, set_id: SetId, member: &Key) -> VaultTx {
    let b = ActBody::Heartbeat(SetHeartbeatBody {
        set_id,
        member_key: member.pubkey(),
    });
    act_tx(c, b, &[*member], vec![])
}

pub fn remove_tx(
    c: &mut Chain,
    set_id: SetId,
    target: PubKeyBytes,
    burn: bool,
    signers: &[Key],
) -> VaultTx {
    let b = ActBody::Remove(SetRemoveBody {
        set_id,
        member_key: target,
        burn: u8::from(burn),
    });
    act_tx(c, b, signers, vec![])
}

pub fn winddown_tx(c: &mut Chain, set_id: SetId, signers: &[Key]) -> VaultTx {
    act_tx(
        c,
        ActBody::WindDown(SetWindDownBody { set_id }),
        signers,
        vec![],
    )
}

/// A spend of `prevout` with scriptSig `<dummy sig> <selector>`; a fee input unless `fee` is
/// false (C++ `SpendTx`).
pub fn spend_tx(
    c: &mut Chain,
    prevout: OutPoint,
    selector: i64,
    outs: Vec<VaultTxOut>,
    fee: bool,
) -> VaultTx {
    let sig = Builder::new().push(&[0x20; 65]).num(selector).into_bytes();
    let mut inputs = vec![txin(prevout, sig)];
    if fee {
        let f = c.fund10();
        inputs.push(txin(f, Builder::new().push(&[1u8; 72]).into_bytes()));
    }
    mk(inputs, outs)
}

pub fn spend(c: &mut Chain, prevout: OutPoint, selector: i64, outs: Vec<VaultTxOut>) -> VaultTx {
    spend_tx(c, prevout, selector, outs, true)
}

/// A V under `set_id` with a post-quantum owner id per test key (C++ `VaultFor`).
pub fn vault_for(set_id: SetId, owner: &Key, app_height: i64) -> VaultParams {
    VaultParams {
        tag: Tag(*b"TEST"),
        set_id,
        cancel_set_id: set_id,
        delay: 5,
        owner_height: 100_000,
        owner: PqOwner {
            scheme: 1,
            hash: sha256d(&owner.pubkey().0),
        },
        app_height,
    }
}

pub fn find_out(tx: &VaultTx, spk: &[u8]) -> OutPoint {
    let n = tx
        .outputs
        .iter()
        .position(|o| o.script_pubkey == spk)
        .expect("output not found");
    OutPoint {
        txid: tx.txid,
        n: n as u32,
    }
}

/// Locks `value` in a new vault; returns its outpoint.
pub fn lock(c: &mut Chain, v: &VaultParams, value: i64) -> OutPoint {
    let f = c.fund(value + COIN);
    let m = mk(
        vec![txin(f, Vec::new())],
        vec![txout(value, build_vault(v).unwrap())],
    );
    assert_eq!(c.block1(&m), "OK");
    OutPoint { txid: m.txid, n: 0 }
}

/// A set with `members` joined (open set) and matured.
pub fn set_with_members_p(c: &mut Chain, members: &[Key], mut p: SetCreateBody) -> SetId {
    p.flags |= SET_FLAG_OPEN;
    let s = make_set(c, p);
    for k in members {
        let j = join_tx(c, s, k, &[]);
        assert_eq!(c.block1(&j), "OK");
    }
    c.empty(i64::from(p.maturity));
    s
}

pub fn set_with_members(c: &mut Chain, members: &[Key]) -> SetId {
    set_with_members_p(c, members, params(true))
}
