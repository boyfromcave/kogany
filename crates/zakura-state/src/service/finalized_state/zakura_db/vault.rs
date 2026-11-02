//! The Vault upgrade's set state in the finalized database (kogany plan W4-c, M24-13, M24-16).
//!
//! ycash6 keeps the set state in its own LevelDB (`src/vault/db.*`) with a per-block undo record
//! kept 4,096 deep, a tip marker and a reconcile pass, and replays acts from undo on `-reindex`
//! (`src/vault/node.cpp` `CoinsFromUndo`). Zakura has one RocksDB write path for checkpointed and
//! finalized blocks (`prepare_block_batch`) and undoes finalized state only offline. So here:
//!
//! - the four record kinds live in four column families, [`VAULT_SET`], [`VAULT_MEMBER`],
//!   [`VAULT_BOND`] and [`VAULT_TEMPLATE_OUT`], each keyed by the record's **canonical key**
//!   (`kogany_vault::state::records::key_*`, prefix byte included) and holding its **canonical
//!   encoding**, so [`ZakuraDb::vault_state_hash`] is `state_hash_of_entries` over a plain scan;
//! - the block's transition is **computed** inside `prepare_block_batch`
//!   ([`DiskWriteBatch::prepare_vault_batch`]) for checkpoint and finalized commits alike, in the
//!   same atomic batch as the block, and it is **total**: a rejected transaction or module verdict
//!   at this layer is a bug (contextual validation rejects such a block first, and checkpoints
//!   never cover the Vault epoch, K-9/M24-14), so it is logged and skipped, never an error;
//! - there is no finalized undo: the offline `rollback` refuses to cross the Vault activation
//!   height and asks for a resync (K-14).
//!
//! The activation height is [`vault_network_params`]: `None` where the network does not schedule
//! the Vault upgrade (every Zcash network), so the delta is empty and nothing is written. Tests
//! may register parameters per network with [`register_vault_params_for_test`].

use std::collections::{BTreeMap, HashMap};

use kogany_vault::{
    state::{
        records::{key_member, KEY_BOND, KEY_MEMBER, KEY_SET, KEY_TEMPLATE_OUT},
        state_hash_of_entries, BlockHashFn, BondRecord, CoinAccessor, Delta, MemberList,
        MemberRecord, Rules, SetRecord, SetState, SpentCoin, StateRead, TemplateOutRecord,
        VaultOverlay, VaultTx, VaultTxIn, VaultTxOut,
    },
    Hash32, OutPoint, PubKeyBytes, SetId,
};
use zakura_chain::{
    block::{self, Block, Height},
    parameters::Network,
    transaction::{self, Transaction},
    transparent,
};

use crate::{
    request::FinalizedBlock,
    service::{
        finalized_state::{
            disk_db::DiskWriteBatch, disk_format::RawBytes, zakura_db::ZakuraDb, TypedColumnFamily,
        },
        yed::{
            module::{finalized_block_hash_at, with_vault_rules},
            YellowbackConfig,
        },
    },
};

/// The set records: `'s' ‖ setId` → `SetRecord`.
pub const VAULT_SET: &str = "vault_set";
/// The member records: `'m' ‖ setId ‖ memberKey` → `MemberRecord`.
pub const VAULT_MEMBER: &str = "vault_member";
/// The bond index: `'b' ‖ outpoint` → `BondRecord`.
pub const VAULT_BOND: &str = "vault_bond";
/// The template-output index: `'v' ‖ outpoint` → `TemplateOutRecord`.
pub const VAULT_TEMPLATE_OUT: &str = "vault_template_out";

/// The vault column families, in canonical key-prefix order (`'b'`, `'m'`, `'s'`, `'v'` all sort
/// apart, so the order of the scan does not matter to the state hash).
pub const VAULT_COLUMN_FAMILIES: [&str; 4] =
    [VAULT_SET, VAULT_MEMBER, VAULT_BOND, VAULT_TEMPLATE_OUT];

/// A vault column family handle: raw canonical keys to raw canonical values.
type VaultCf<'cf> = TypedColumnFamily<'cf, RawBytes, RawBytes>;

// ---- the activation seam ----------------------------------------------------------------

/// The network's Vault parameters (`Consensus::Params` `vUpgrades[UPGRADE_VAULT]` and
/// `nVaultMinSetMaturity` on the C++ lines).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VaultNetworkParams {
    /// `UPGRADE_VAULT`'s activation height.
    pub activation_height: Height,
    /// D-Q-31: the smallest `SET_CREATE` maturity (mainnet 16,128; regtest 2).
    pub min_set_maturity: u32,
}

impl VaultNetworkParams {
    /// The state machine's [`Rules`] for these parameters, over the registered module table.
    pub fn rules(&self) -> Rules<'static> {
        Rules::new(i64::from(self.activation_height.0), self.min_set_maturity)
    }

    /// Is the Vault upgrade active at `height`?
    pub fn is_active(&self, height: Height) -> bool {
        height >= self.activation_height
    }
}

/// The Vault parameters of `network`, `None` when the upgrade is not scheduled there.
///
/// The activation height is [`Network::vault_activation_height`] (W2-b: explicit membership in
/// the activation list, never a fallback to a later upgrade's height). The minimum set maturity
/// is [`vault_min_set_maturity`]. A network a test registered answers its registered parameters
/// first.
pub fn vault_network_params(network: &Network) -> Option<VaultNetworkParams> {
    #[cfg(any(test, feature = "proptest-impl"))]
    if let Some(params) = test_params::lookup(network) {
        return Some(params);
    }
    Some(VaultNetworkParams {
        activation_height: network.vault_activation_height()?,
        min_set_maturity: vault_min_set_maturity(network),
    })
}

/// The `testnet-yb-fast` profile's network magic (`ycash6 src/chainparams.cpp:644-647`), the one
/// profile with a short set maturity.
const YCASH_TESTNET_FAST_MAGIC: [u8; 4] = [0xf7, 0x79, 0x62, 0xd3];

/// D-Q-31's `Consensus::Params::nVaultMinSetMaturity` of `network` (ycash6
/// `src/chainparams.cpp:643,664,769`): regtest 2, `testnet-yb-fast` 48, mainnet,
/// `testnet-yb-slow` and every other network the default 16,128.
pub fn vault_min_set_maturity(network: &Network) -> u32 {
    if network.is_regtest() {
        2
    } else if network.magic().0 == YCASH_TESTNET_FAST_MAGIC {
        48
    } else {
        kogany_vault::state::MIN_SET_MATURITY
    }
}

/// Registers Vault parameters for one test network instance (matched by identity of its
/// parameters, so other tests' networks are unaffected).
#[cfg(any(test, feature = "proptest-impl"))]
pub fn register_vault_params_for_test(network: &Network, params: VaultNetworkParams) {
    test_params::register(network, params)
}

#[cfg(any(test, feature = "proptest-impl"))]
mod test_params {
    use std::sync::{Arc, Mutex};

    use zakura_chain::parameters::Network;

    use super::VaultNetworkParams;

    /// Registered (network, params); the network clone keeps its `Arc` alive, so a pointer is
    /// never reused by another network while it is registered.
    static REGISTERED: Mutex<Vec<(Network, VaultNetworkParams)>> = Mutex::new(Vec::new());

    fn same(a: &Network, b: &Network) -> bool {
        match (a, b) {
            (Network::Testnet(a), Network::Testnet(b)) => Arc::ptr_eq(a, b),
            _ => false,
        }
    }

    pub(super) fn register(network: &Network, params: VaultNetworkParams) {
        assert!(
            matches!(network, Network::Testnet(_)),
            "only a test network instance can be given Vault parameters"
        );
        let mut reg = REGISTERED.lock().expect("registry lock is not poisoned");
        reg.retain(|(n, _)| !same(n, network));
        reg.push((network.clone(), params));
    }

    pub(super) fn lookup(network: &Network) -> Option<VaultNetworkParams> {
        let reg = REGISTERED.lock().expect("registry lock is not poisoned");
        reg.iter().find(|(n, _)| same(n, network)).map(|(_, p)| *p)
    }
}

// ---- conversions ------------------------------------------------------------------------

/// The vault rules' view of a Zakura transaction: txid, coinbase flag, transparent inputs and
/// outputs in order (the shielded parts are not the primitive's concern).
pub fn vault_tx(tx: &Transaction, txid: &transaction::Hash) -> VaultTx {
    let inputs = tx
        .inputs()
        .iter()
        .map(|input| match input {
            transparent::Input::PrevOut {
                outpoint,
                unlock_script,
                ..
            } => VaultTxIn {
                prevout: vault_outpoint(outpoint),
                script_sig: unlock_script.as_raw_bytes().to_vec(),
            },
            // The C++ null prevout. The vault rules never read a coinbase input's script; the
            // YED module reads its coinbase tag there (TAG, W5-f), so it is the serialized
            // scriptSig (the BIP34 height push, then the miner data).
            coinbase @ transparent::Input::Coinbase { .. } => VaultTxIn {
                prevout: OutPoint {
                    txid: Hash32::ZERO,
                    n: u32::MAX,
                },
                script_sig: coinbase.coinbase_script().unwrap_or_default(),
            },
        })
        .collect();
    let outputs = tx
        .outputs()
        .iter()
        .map(|output| VaultTxOut {
            value: output.value.zatoshis(),
            script_pubkey: output.lock_script.as_raw_bytes().to_vec(),
        })
        .collect();
    VaultTx {
        txid: Hash32(txid.0),
        coinbase: tx.is_coinbase(),
        inputs,
        outputs,
    }
}

/// Every transaction of `block` as a [`VaultTx`], in block order. `transaction_hashes` are the
/// block's precomputed txids, in the same order.
pub fn vault_txs(block: &Block, transaction_hashes: &[transaction::Hash]) -> Vec<VaultTx> {
    block
        .transactions
        .iter()
        .zip(transaction_hashes)
        .map(|(tx, txid)| vault_tx(tx, txid))
        .collect()
}

/// A Zakura outpoint in the vault crate's byte form (txid in internal order).
pub fn vault_outpoint(outpoint: &transparent::OutPoint) -> OutPoint {
    OutPoint {
        txid: Hash32(outpoint.hash.0),
        n: outpoint.index,
    }
}

fn spent_coin(utxo: &transparent::Utxo) -> SpentCoin {
    SpentCoin {
        script_pubkey: utxo.output.lock_script.as_raw_bytes().to_vec(),
        value: utxo.output.value.zatoshis(),
        height: i64::from(utxo.height.0),
    }
}

/// The spent coins of a block, keyed by Zakura outpoint, as the rules' [`CoinAccessor`].
///
/// Both the finalized write path (`spent_utxos_by_outpoint`) and contextual validation
/// (`ContextuallyVerifiedBlock::spent_outputs`) already include outputs created earlier in the
/// same block, at the block's height, which is what the C++ `CCoinsViewCache` answers.
pub struct UtxoCoins<'a>(pub &'a HashMap<transparent::OutPoint, transparent::Utxo>);

impl CoinAccessor for UtxoCoins<'_> {
    fn spent_coin(&self, prevout: &OutPoint) -> Option<SpentCoin> {
        self.0.get(&zakura_outpoint(prevout)).map(spent_coin)
    }
}

/// [`UtxoCoins`] over ordered UTXOs (the contextual-validation map).
pub struct OrderedUtxoCoins<'a>(pub &'a HashMap<transparent::OutPoint, transparent::OrderedUtxo>);

impl CoinAccessor for OrderedUtxoCoins<'_> {
    fn spent_coin(&self, prevout: &OutPoint) -> Option<SpentCoin> {
        self.0
            .get(&zakura_outpoint(prevout))
            .map(|ordered| spent_coin(&ordered.utxo))
    }
}

fn zakura_outpoint(prevout: &OutPoint) -> transparent::OutPoint {
    transparent::OutPoint {
        hash: transaction::Hash(prevout.txid.0),
        index: prevout.n,
    }
}

// ---- the total transition ---------------------------------------------------------------

/// What the total transition skipped: the reject reasons, in order (empty in every correct run).
pub type SkippedRejects = Vec<String>;

/// The block's vault delta over `base` (the state after the parent), **total**: before the
/// network's Vault activation height, or on a network without one, it is empty; otherwise every
/// transaction is applied in block order as ycash6 `VaultState::ApplyBlock` does, then every
/// module's `check_block`.
///
/// A transaction or module verdict that rejects is skipped (the transaction changes nothing, as
/// `ApplyTx` guarantees) and its reason returned. On a block that passed contextual validation
/// nothing is ever skipped, so the result equals `kogany_vault::state::apply_block`'s.
///
/// The module table is the node's ([`with_vault_rules`]: `YED\0` registered where Yellowback is
/// configured under `yellowback`), and `block_hashes` the ancestor hashes of the chain the block
/// extends (the module hooks' `blockHashAt`).
pub fn block_vault_delta_total(
    network: &Network,
    yellowback: &YellowbackConfig,
    base: &dyn StateRead,
    txs: &[VaultTx],
    height: Height,
    coins: &dyn CoinAccessor,
    block_hashes: Option<BlockHashFn<'_>>,
) -> (Delta, SkippedRejects) {
    let Some(params) = vault_network_params(network).filter(|p| p.is_active(height)) else {
        return (Delta::default(), Vec::new());
    };
    with_vault_rules(&params, network, yellowback, block_hashes, |rules| {
        block_vault_delta_total_with(base, txs, height, coins, rules)
    })
}

fn block_vault_delta_total_with(
    base: &dyn StateRead,
    txs: &[VaultTx],
    height: Height,
    coins: &dyn CoinAccessor,
    rules: &Rules<'_>,
) -> (Delta, SkippedRejects) {
    let h = i64::from(height.0);
    let mut skipped = Vec::new();
    let mut st = VaultOverlay::new(base);
    for tx in txs {
        if let Err(reject) = st.apply_tx(tx, h, coins, rules) {
            skipped.push(format!(
                "tx {}: {}",
                display_txid(&tx.txid),
                reject.reason()
            ));
        }
    }
    for (_, module) in rules.modules {
        let ctx = kogany_vault::state::ModuleContext {
            height: h,
            state: &st,
            block_hash_at: rules.block_hashes,
        };
        if let Err(reject) = module.check_block(txs, &ctx) {
            skipped.push(format!("module check_block: {}", reject.reason()));
        }
    }
    (st.delta(), skipped)
}

fn display_txid(txid: &Hash32) -> String {
    transaction::Hash(txid.0).to_string()
}

/// Logs a total transition that skipped anything: a consensus-state bug at this layer.
pub(crate) fn report_skipped(source: &str, height: Height, hash: block::Hash, skipped: &[String]) {
    if skipped.is_empty() {
        return;
    }
    metrics::counter!("zakura.state.vault.total_transition.skipped")
        .increment(u64::try_from(skipped.len()).unwrap_or(u64::MAX));
    tracing::error!(
        ?height,
        %hash,
        source,
        ?skipped,
        "vault: a committed block carried vault rejects; they were skipped. Contextual \
         validation should have rejected the block, and checkpoints must not cover the \
         Vault epoch (K-9). This node's vault state may now differ from ycashd's: resync."
    );
}

// ---- reads ------------------------------------------------------------------------------

fn cf_for_key(key: &[u8]) -> &'static str {
    match key.first() {
        Some(&KEY_SET) => VAULT_SET,
        Some(&KEY_MEMBER) => VAULT_MEMBER,
        Some(&KEY_BOND) => VAULT_BOND,
        Some(&KEY_TEMPLATE_OUT) => VAULT_TEMPLATE_OUT,
        _ => panic!("a canonical vault key starts with one of the four record prefixes"),
    }
}

fn decoded<T>(value: Option<T>, what: &str) -> T {
    value.unwrap_or_else(|| panic!("a stored vault {what} record decodes: the database is corrupt"))
}

/// The finalized set state as the rules' [`StateRead`] (the C++ `KVReader` over the vault DB).
#[derive(Clone, Copy)]
pub struct FinalizedVaultState<'a>(pub &'a ZakuraDb);

impl StateRead for FinalizedVaultState<'_> {
    fn set(&self, set_id: &SetId) -> Option<SetRecord> {
        self.0
            .vault_raw_get(&kogany_vault::state::records::key_set(set_id))
            .map(|b| decoded(SetRecord::decode(&b), "set"))
    }
    fn member(&self, set_id: &SetId, key: &PubKeyBytes) -> Option<MemberRecord> {
        self.0
            .vault_raw_get(&key_member(set_id, key))
            .map(|b| decoded(MemberRecord::decode(&b), "member"))
    }
    fn members(&self, set_id: &SetId) -> MemberList {
        self.0.vault_members(set_id)
    }
    fn bond(&self, outpoint: &OutPoint) -> Option<BondRecord> {
        self.0
            .vault_raw_get(&kogany_vault::state::records::key_bond(outpoint))
            .map(|b| decoded(BondRecord::decode(&b), "bond"))
    }
    fn template_out(&self, outpoint: &OutPoint) -> Option<TemplateOutRecord> {
        self.0
            .vault_raw_get(&kogany_vault::state::records::key_template_out(outpoint))
            .map(|b| decoded(TemplateOutRecord::decode(&b), "template-output"))
    }
}

/// The member range of a set in canonical keys: `'m' ‖ setId ‖ 00…` ..= `'m' ‖ setId ‖ ff…`.
pub fn member_key_range(set_id: &SetId) -> (Vec<u8>, Vec<u8>) {
    (
        key_member(set_id, &PubKeyBytes([0u8; 33])),
        key_member(set_id, &PubKeyBytes([0xffu8; 33])),
    )
}

/// Decodes a member entry's key suffix (the 33-byte member key after `'m' ‖ setId`).
pub fn member_key_of(canonical_key: &[u8]) -> PubKeyBytes {
    canonical_key
        .get(33..66)
        .and_then(PubKeyBytes::from_slice)
        .expect("a canonical member key is 'm' || setId(32) || memberKey(33)")
}

impl ZakuraDb {
    fn vault_cf(&self, name: &str) -> VaultCf<'_> {
        VaultCf::new(&self.db, name).expect("vault column families are created with the database")
    }

    /// The canonical value stored under a canonical vault key, `None` when absent.
    pub fn vault_raw_get(&self, canonical_key: &[u8]) -> Option<Vec<u8>> {
        self.vault_cf(cf_for_key(canonical_key))
            .zs_get(&RawBytes::new_raw_bytes(canonical_key.to_vec()))
            .map(|v| v.raw_bytes().clone())
    }

    /// Every member record of a set, in member-key byte order.
    pub fn vault_members(&self, set_id: &SetId) -> MemberList {
        let (from, to) = member_key_range(set_id);
        self.vault_cf(VAULT_MEMBER)
            .zs_forward_range_iter(RawBytes::new_raw_bytes(from)..=RawBytes::new_raw_bytes(to))
            .map(|(k, v)| {
                (
                    member_key_of(k.raw_bytes()),
                    decoded(MemberRecord::decode(v.raw_bytes()), "member"),
                )
            })
            .collect()
    }

    /// The finalized set state as a [`StateRead`].
    pub fn vault_state(&self) -> FinalizedVaultState<'_> {
        FinalizedVaultState(self)
    }

    /// Every stored vault entry, canonical key → canonical value: the `statehash` preimage's
    /// entries (one scan of the four column families).
    pub fn vault_canonical_entries(&self) -> BTreeMap<Vec<u8>, Vec<u8>> {
        let mut out = BTreeMap::new();
        for name in VAULT_COLUMN_FAMILIES {
            for (k, v) in self
                .vault_cf(name)
                .zs_forward_range_iter::<std::ops::RangeFull>(..)
            {
                out.insert(k.raw_bytes().clone(), v.raw_bytes().clone());
            }
        }
        out
    }

    /// Is any vault entry stored?
    pub fn has_vault_state(&self) -> bool {
        VAULT_COLUMN_FAMILIES
            .iter()
            .any(|name| !self.vault_cf(name).zs_is_empty())
    }

    /// The canonical `statehash` of the finalized set state (ycash6 `vault::StateHash`,
    /// `vault_getinfo.statehash`), internal byte order.
    pub fn vault_state_hash(&self) -> Hash32 {
        state_hash_of_entries(&self.vault_canonical_entries())
    }

    /// The whole finalized set state in memory (decoded from one scan).
    pub fn vault_set_state(&self) -> SetState {
        set_state_from_entries(&self.vault_canonical_entries())
    }
}

/// Decodes canonical entries into a [`SetState`].
pub fn set_state_from_entries(entries: &BTreeMap<Vec<u8>, Vec<u8>>) -> SetState {
    let mut st = SetState::new();
    for (k, v) in entries {
        let id_at = |from: usize| {
            k.get(from..from + 32)
                .and_then(Hash32::from_slice)
                .expect("a canonical vault key carries a 32-byte id")
        };
        let op_at = || {
            k.get(1..)
                .and_then(OutPoint::from_slice)
                .expect("a canonical outpoint key is prefix || txid(32) || n(4)")
        };
        match k.first() {
            Some(&KEY_SET) => {
                st.sets
                    .insert(id_at(1), decoded(SetRecord::decode(v), "set"));
            }
            Some(&KEY_MEMBER) => {
                st.members.insert(
                    (id_at(1), member_key_of(k)),
                    decoded(MemberRecord::decode(v), "member"),
                );
            }
            Some(&KEY_BOND) => {
                st.bonds
                    .insert(op_at(), decoded(BondRecord::decode(v), "bond"));
            }
            Some(&KEY_TEMPLATE_OUT) => {
                st.template_outs.insert(
                    op_at(),
                    decoded(TemplateOutRecord::decode(v), "template-output"),
                );
            }
            _ => panic!("a canonical vault key starts with one of the four record prefixes"),
        }
    }
    st
}

// ---- writes -----------------------------------------------------------------------------

impl DiskWriteBatch {
    /// Computes `finalized`'s vault transition over the finalized state (the block's parent) and
    /// adds its writes to this batch: the vault half of `prepare_block_batch`, for checkpoint and
    /// finalized commits alike. Total: it never fails (see [`block_vault_delta_total`]).
    ///
    /// `spent_utxos_by_outpoint` is the write path's map of every coin the block spends,
    /// including outputs created earlier in the block.
    pub fn prepare_vault_batch(
        &mut self,
        zakura_db: &ZakuraDb,
        network: &Network,
        finalized: &FinalizedBlock,
        spent_utxos_by_outpoint: &HashMap<transparent::OutPoint, transparent::Utxo>,
    ) {
        self.prepare_vault_batch_for_block(
            zakura_db,
            network,
            &finalized.block,
            finalized.height,
            finalized.hash,
            &finalized.transaction_hashes,
            spent_utxos_by_outpoint,
        )
    }

    /// [`Self::prepare_vault_batch`] from the block's parts.
    #[allow(clippy::too_many_arguments)]
    pub fn prepare_vault_batch_for_block(
        &mut self,
        zakura_db: &ZakuraDb,
        network: &Network,
        block: &Block,
        height: Height,
        hash: block::Hash,
        transaction_hashes: &[transaction::Hash],
        spent_utxos_by_outpoint: &HashMap<transparent::OutPoint, transparent::Utxo>,
    ) {
        if vault_network_params(network).is_none_or(|p| !p.is_active(height)) {
            return;
        }
        let txs = vault_txs(block, transaction_hashes);
        // The block's parent is the finalized tip, so its ancestors are finalized.
        let block_hash_at = |h: i64| finalized_block_hash_at(zakura_db, h);
        let (delta, skipped) = block_vault_delta_total(
            network,
            &zakura_db.config().yellowback,
            &zakura_db.vault_state(),
            &txs,
            height,
            &UtxoCoins(spent_utxos_by_outpoint),
            Some(&block_hash_at),
        );
        report_skipped("finalized write", height, hash, &skipped);
        self.prepare_vault_delta_batch(zakura_db, &delta);
    }

    /// Adds a computed vault delta's writes to this batch (every changed entry to its `after`
    /// value; `None` deletes).
    pub fn prepare_vault_delta_batch(&mut self, zakura_db: &ZakuraDb, delta: &Delta) {
        for (key, (_before, after)) in delta.canonical_entries() {
            let cf = zakura_db.vault_cf(cf_for_key(&key));
            let key = RawBytes::new_raw_bytes(key);
            let _ = match after {
                Some(value) => cf
                    .with_batch_for_writing(self)
                    .zs_insert(&key, &RawBytes::new_raw_bytes(value)),
                None => cf.with_batch_for_writing(self).zs_delete(&key),
            };
        }
    }
}

#[cfg(test)]
mod tests;
