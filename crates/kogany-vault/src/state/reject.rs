//! Why a transaction or block violates the primitive's rules; each maps to the C++ reject string.

use crate::act::ActError;

/// A rule violation of the vault primitive (ycash6 `src/vault/state.cpp` reject reasons), or a
/// module's. The C++ reason string is [`VaultReject::reason`]; every variant is a consensus
/// rejection of the transaction (and of a block carrying it).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VaultReject {
    /// `bad-vault-act-multi`: more than one `YV` output.
    ActMulti,
    /// `bad-txns-vault-malformed`: a V/I skeleton with non-canonical bytes (§15.3).
    Malformed,
    /// `bad-vault-bond-frozen`: a spend of a frozen bond.
    BondFrozen,
    /// `bad-vault-bond-locked`: a spend of a bond still in its member's seat or exit delay.
    BondLocked,
    /// `bad-txns-vault-inputs-missing`: a spent coin the accessor does not know.
    InputsMissing,
    /// `bad-txns-vault-preactivation`: S-0, a template input created below activation.
    Preactivation,
    /// `bad-txns-vault-multi`: S-1, more than one template input.
    Multi,
    /// `bad-txns-vault-selector`: S-1, no valid selector.
    Selector,
    /// `bad-txns-vault-intent`: I-0, an intent output outside an UNLOCK/APP spend.
    Intent,
    /// `bad-txns-vault-app`: S-4 / V-1, an APP spend or branch where none is allowed.
    App,
    /// `bad-txns-vault-covenant`: S-2, an intent or re-lock that is not the vault's.
    Covenant,
    /// `bad-txns-vault-amount`: a value or sum outside the money range.
    Amount,
    /// `bad-txns-vault-value`: S-2, the vault's value leaves to ordinary outputs.
    Value,
    /// `bad-txns-vault-rate`: S-3, the set's rate limit.
    Rate,
    /// `bad-txns-vault-release`: I-1.
    Release,
    /// `bad-txns-vault-cancel`: I-2.
    Cancel,
    /// `bad-txns-vault-noset`: V-1, a V naming a set (or cancel set) not created before.
    NoSet,
    /// An act output that does not decode (`bad-vault-act-malformed` / `-version` / `-type` /
    /// `-sigs`).
    ActDecode(ActError),
    /// `bad-vault-act-coinbase`.
    ActCoinbase,
    /// `bad-vault-act-novin`.
    ActNoVin,
    /// `bad-vault-act-sigs`: the wrong number or set of signatures.
    ActSigs,
    /// `bad-vault-act-params`.
    ActParams,
    /// `bad-vault-act-noset`.
    ActNoSet,
    /// `bad-vault-act-winddown`.
    ActWindDown,
    /// `bad-vault-act-remove`.
    ActRemove,
    /// `bad-vault-act-sig`: a signature that does not recover, or recovers to the wrong key.
    ActSig,
    /// `bad-vault-act-exists`.
    ActExists,
    /// `bad-vault-act-seats`.
    ActSeats,
    /// `bad-vault-act-join`.
    ActJoin,
    /// `bad-vault-act-bond`.
    ActBond,
    /// `bad-vault-act-heartbeat`.
    ActHeartbeat,
    /// `bad-vault-act-equivocation`.
    ActEquivocation,
    /// A registered module's rejection, with its own reason string.
    Module(String),
}

impl VaultReject {
    /// The C++ reject reason.
    pub fn reason(&self) -> &str {
        match self {
            VaultReject::ActMulti => "bad-vault-act-multi",
            VaultReject::Malformed => "bad-txns-vault-malformed",
            VaultReject::BondFrozen => "bad-vault-bond-frozen",
            VaultReject::BondLocked => "bad-vault-bond-locked",
            VaultReject::InputsMissing => "bad-txns-vault-inputs-missing",
            VaultReject::Preactivation => "bad-txns-vault-preactivation",
            VaultReject::Multi => "bad-txns-vault-multi",
            VaultReject::Selector => "bad-txns-vault-selector",
            VaultReject::Intent => "bad-txns-vault-intent",
            VaultReject::App => "bad-txns-vault-app",
            VaultReject::Covenant => "bad-txns-vault-covenant",
            VaultReject::Amount => "bad-txns-vault-amount",
            VaultReject::Value => "bad-txns-vault-value",
            VaultReject::Rate => "bad-txns-vault-rate",
            VaultReject::Release => "bad-txns-vault-release",
            VaultReject::Cancel => "bad-txns-vault-cancel",
            VaultReject::NoSet => "bad-txns-vault-noset",
            VaultReject::ActDecode(e) => e.reject_reason(),
            VaultReject::ActCoinbase => "bad-vault-act-coinbase",
            VaultReject::ActNoVin => "bad-vault-act-novin",
            VaultReject::ActSigs => "bad-vault-act-sigs",
            VaultReject::ActParams => "bad-vault-act-params",
            VaultReject::ActNoSet => "bad-vault-act-noset",
            VaultReject::ActWindDown => "bad-vault-act-winddown",
            VaultReject::ActRemove => "bad-vault-act-remove",
            VaultReject::ActSig => "bad-vault-act-sig",
            VaultReject::ActExists => "bad-vault-act-exists",
            VaultReject::ActSeats => "bad-vault-act-seats",
            VaultReject::ActJoin => "bad-vault-act-join",
            VaultReject::ActBond => "bad-vault-act-bond",
            VaultReject::ActHeartbeat => "bad-vault-act-heartbeat",
            VaultReject::ActEquivocation => "bad-vault-act-equivocation",
            VaultReject::Module(r) => r,
        }
    }
}

impl core::fmt::Display for VaultReject {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.reason())
    }
}

impl std::error::Error for VaultReject {}
