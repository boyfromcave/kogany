//! The Ycash vault network upgrade's script context (kogany plan W3-c, mapping M24-11).
//!
//! ycash6 verifies a vault-era input with flags from the spending height
//! (`GetVaultScriptFlags`, `ycash6/src/main.cpp:845`) and a checker that reads the signer-set
//! state after the parent block (`vault::SetSigChecker`, `ycash6/src/vault/checker.cpp`). Zakura's
//! script request carried neither, and its flags were a constant. This module is that context:
//!
//! - [`ScriptContext`]: the network, the spending height and the set-state snapshot;
//! - [`script_flags`]: `P2SH | CHECKLOCKTIMEVERIFY` always, plus `CHECKSEQUENCEVERIFY | Vault`
//!   where the Vault upgrade is active, plus `PqFalcon` from the Falcon height — never keyed on
//!   the transaction version (a version-keyed shortcut would turn 0xb2 back into `OP_NOP3`);
//! - [`YcashSignatureChecker`]: the forked interpreter's five Ycash checker methods over
//!   `kogany_pq::verify`, `kogany_vault::act::set_sig_msg` and the snapshot's
//!   [`StateRead::threshold`] / [`StateRead::check_set_sigs`] / [`StateRead::is_released`].

use std::{fmt, sync::Arc};

use kogany_vault::{
    act::set_sig_msg,
    state::StateRead,
    {Hash32, OutPoint},
};
use zakura_chain::{block::Height, parameters::Network, transaction::Transaction, transparent};
use zcash_script::{
    interpreter::{self, Flags, SighashCalculator, SignatureChecker, SET_SIG_SIZE},
    script, signature,
};

/// The set state script evaluation reads: the state after the parent of the block the spend is
/// in (or, for the mempool, after the best chain tip), asked at the spending height (ycash6
/// `std::shared_ptr<const SetSnapshot>`).
///
/// `kogany_vault::state::SetState` implements it, so `zakura_state::vault::VaultSnapshot::state`
/// converts directly.
pub type VaultStateSnapshot = Arc<dyn StateRead + Send + Sync>;

/// The consensus context of one script verification: what ycash6 passes to `CScriptCheck`
/// beside the transaction (`nFlags`, `vaultSnapshot`, `vaultHeight`).
#[derive(Clone)]
pub struct ScriptContext {
    /// The network the transaction is verified on.
    pub network: Network,
    /// The spending height: the block's height, or the next block's height for the mempool.
    pub height: Height,
    /// The set state after the parent block. `None` fails every set opcode closed (no threshold,
    /// never released, no set signature verifies), like ycash6's checker without a snapshot.
    ///
    /// Not the same as an empty state: in an empty state every set is unknown, and an unknown
    /// set is *released* (§15.4), so `OP_CHECKSETDORMANT` would succeed.
    pub vault_state: Option<VaultStateSnapshot>,
}

impl fmt::Debug for ScriptContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ScriptContext")
            .field("network", &self.network)
            .field("height", &self.height)
            .field(
                "vault_state",
                &self.vault_state.as_ref().map(|_| "StateRead"),
            )
            .finish()
    }
}

impl ScriptContext {
    /// A context for `network` at `height` with the set-state snapshot `vault_state`.
    pub fn new(network: Network, height: Height, vault_state: Option<VaultStateSnapshot>) -> Self {
        Self {
            network,
            height,
            vault_state,
        }
    }

    /// The script verification flags at this height ([`script_flags`]).
    pub fn flags(&self) -> Flags {
        script_flags(&self.network, self.height)
    }
}

/// The consensus script verification flags of a block at `height` on `network` (ycash6
/// `ConnectBlock`: `SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY |
/// GetVaultScriptFlags(nHeight)`).
///
/// Independent of the transaction version. On every Zcash network (and every Ycash network
/// before Vault) this is upstream's constant `P2SH | CHECKLOCKTIMEVERIFY`.
pub fn script_flags(network: &Network, height: Height) -> Flags {
    let mut flags = Flags::P2SH | Flags::CHECKLOCKTIMEVERIFY;
    if network.is_vault_active(height) {
        flags |= Flags::CHECKSEQUENCEVERIFY | Flags::Vault;
        if is_pq_falcon_active(network, height) {
            flags |= Flags::PqFalcon;
        }
    }
    flags
}

/// The height from which `OP_CHECKPQSIG` admits scheme 0x02 (FN-DSA-512), given Vault is active
/// (ycash6 `Consensus::Params::pqFalconHeight`, `src/chainparams.cpp`).
///
/// - Every network but regtest: 0, so Falcon follows the Vault upgrade exactly (quantum plan
///   D-Q-2: mainnet and testnet `pqFalconHeight = 0`).
/// - Regtest: none (ycash6's `NO_ACTIVATION_HEIGHT` default without `-pqfalcon` /
///   `-pqfalconheight`). kogany has no regtest Falcon parameter yet, so a regtest that needs
///   Falcon cannot be configured; that parameter belongs with the network's upgrade heights in
///   `zakura-chain` (finding W3-c/F-1).
pub fn pq_falcon_height(network: &Network) -> Option<Height> {
    if network.is_regtest() {
        None
    } else {
        Some(Height(0))
    }
}

/// ycash6 `IsPQFalconActive`: Vault active at `height`, and `height` at or above the Falcon
/// height.
pub fn is_pq_falcon_active(network: &Network, height: Height) -> bool {
    network.is_vault_active(height) && pq_falcon_height(network).is_some_and(|h| height >= h)
}

/// The `SIGHASH_ALL | SIGHASH_ANYONECANPAY` hash type a set signature signs (ycash6
/// `SetSigChecker::CheckSetSigs`, remedial 01/V-2).
const SET_SIG_HASH_TYPE: i32 = 0x81;

/// The Ycash transaction checker (ycash6 `vault::SetSigChecker` over
/// `TransactionSignatureChecker`): ECDSA signatures and lock times through upstream's callback
/// checker, the vault extensions from the input, the transaction and the snapshot.
pub struct YcashSignatureChecker<'a> {
    /// Upstream's checker: `check_sig` and `check_lock_time`.
    base: interpreter::CallbackTransactionSignatureChecker<'a>,
    /// The same signature-hash callback `base` uses (scriptCode, hash type → sighash).
    sighash: SighashCalculator<'a>,
    /// The transaction's version (BIP112's `nVersion >= 2`).
    tx_version: u32,
    /// This input's `nSequence`.
    tx_sequence: u32,
    /// This input's prevout, the set-signature message's `prevout`.
    prevout: OutPoint,
    /// The set state after the parent block.
    vault_state: Option<&'a (dyn StateRead + Send + Sync)>,
    /// The spending height.
    height: i64,
}

impl<'a> YcashSignatureChecker<'a> {
    /// The checker for input `input_index` of `transaction`.
    ///
    /// Returns `None` for a coinbase input or an index out of range.
    pub fn new(
        base: interpreter::CallbackTransactionSignatureChecker<'a>,
        transaction: &Transaction,
        input_index: usize,
        context: &'a ScriptContext,
    ) -> Option<Self> {
        let transparent::Input::PrevOut {
            outpoint, sequence, ..
        } = transaction.inputs().get(input_index)?
        else {
            return None;
        };
        Some(Self {
            base,
            sighash: base.sighash,
            tx_version: transaction.version(),
            tx_sequence: *sequence,
            prevout: OutPoint {
                txid: Hash32(outpoint.hash.0),
                n: outpoint.index,
            },
            vault_state: context.vault_state.as_deref(),
            height: i64::from(context.height.0),
        })
    }
}

impl SignatureChecker for YcashSignatureChecker<'_> {
    fn check_sig(
        &self,
        sig: &signature::Decoded,
        vch_pub_key: &[u8],
        script_code: &script::Code,
    ) -> bool {
        self.base.check_sig(sig, vch_pub_key, script_code)
    }

    fn check_lock_time(&self, lock_time: i64) -> bool {
        self.base.check_lock_time(lock_time)
    }

    fn check_sequence(&self, sequence: i64) -> bool {
        interpreter::check_sequence(self.tx_version, self.tx_sequence, sequence)
    }

    fn set_threshold(&self, set_id: &[u8; 32], role: u8) -> Option<u32> {
        self.vault_state?
            .threshold(&Hash32(*set_id), role)
            .map(u32::from)
    }

    fn check_set_sigs(
        &self,
        set_id: &[u8; 32],
        role: u8,
        sigs: &[[u8; SET_SIG_SIZE]],
        script_code: &script::Code,
    ) -> bool {
        let Some(state) = self.vault_state else {
            return false;
        };
        let Ok(hash_type) = signature::HashType::from_bits(SET_SIG_HASH_TYPE, false) else {
            return false;
        };
        let Some(sighash) = (self.sighash)(script_code, &hash_type) else {
            return false;
        };
        let set_id = Hash32(*set_id);
        let msg = set_sig_msg(&set_id, role, &self.prevout, &Hash32(sighash));
        let sigs: Vec<Vec<u8>> = sigs.iter().map(|sig| sig.to_vec()).collect();
        state.check_set_sigs(&set_id, role, &msg, &sigs, self.height)
    }

    fn is_set_released(&self, set_id: &[u8; 32]) -> bool {
        self.vault_state
            .is_some_and(|state| state.is_released(&Hash32(*set_id), self.height))
    }

    fn check_pq_sig(
        &self,
        scheme: u8,
        sig: &[u8],
        hash_type: &signature::HashType,
        pub_key: &[u8],
        script_code: &script::Code,
    ) -> bool {
        // ycash6 `TransactionSignatureChecker::CheckPQSig`: the sighash of the raw hash-type
        // byte, as for `OP_CHECKSIG`.
        (self.sighash)(script_code, hash_type)
            .is_some_and(|sighash| kogany_pq::verify(scheme, pub_key, &sighash, sig))
    }
}
