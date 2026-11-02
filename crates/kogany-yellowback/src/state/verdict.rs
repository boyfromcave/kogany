// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

//! The verdict strings (§4.2a; ycash6 `state.cpp` `namespace verdict`). `TxLog.verdict`,
//! `yed_getblockverdict.reason` and the block reject reason (`bad-yellowback-<verdict>`) carry
//! them, so they are the C++ spellings exactly. The bundle failures are
//! [`MINT9_BUNDLE_PREFIX`] / [`RED1_BUNDLE_PREFIX`] followed by BUNDLE-1's reason
//! ([`crate::attest::BundleError::reason`]) or [`BUNDLE_STAT`].

/// The rule held.
pub const OK: &str = "ok";
/// XFER-1..3 held and Σ assigned < yedIn: a burn by rule.
pub const BURNED: &str = "burned";
/// Dry runs only: the transaction touched nothing (never logged).
pub const NON_YELLOWBACK: &str = "non-yellowback";
/// MINT-2.
pub const BAD_MINT_AMOUNT: &str = "bad-mint-amount";
/// MINT-2.
pub const BAD_MINT_CLASS: &str = "bad-mint-class";
/// MINT-2.
pub const BAD_MINT_LOCK_HEIGHT: &str = "bad-mint-lock-height";
/// MINT-2.
pub const BAD_MINT_REF_HEIGHT: &str = "bad-mint-ref-height";
/// MINT-3.
pub const BAD_MINT_OUTPUTS: &str = "bad-mint-outputs";
/// MINT-3.
pub const BAD_MINT_OWNER_KEY: &str = "bad-mint-owner-key";
/// MINT-3.
pub const BAD_MINT_VAULT_SCRIPT: &str = "bad-mint-vault-script";
/// MINT-4.
pub const MINT_NOT_ACTIVE: &str = "mint-not-active";
/// MINT-4.
pub const MINT_HALTED_NO_PRICE: &str = "mint-halted-no-price";
/// MINT-4.
pub const MINT_HALTED_GLOBAL_RATIO: &str = "mint-halted-global-ratio";
/// MINT-4.
pub const MINT_HALTED_DIVERGENCE: &str = "mint-halted-divergence";
/// MINT-4 (H-1).
pub const MINT_HALTED_UNARMED: &str = "mint-halted-unarmed";
/// MINT-5.
pub const BAD_MINT_COLLATERAL: &str = "bad-mint-collateral";
/// MINT-5.
pub const MINT_UNSATISFIABLE: &str = "mint-unsatisfiable";
/// MINT-6.
pub const MINT_SUPPLY_CAP: &str = "mint-supply-cap";
/// MINT-6b (D-Q-23a).
pub const MINT_VAULT_SHARE: &str = "mint-vault-share";
/// MINT-7.
pub const BAD_MINT_TOKEN_OUTPUT: &str = "bad-mint-token-output";
/// MINT-8.
pub const BAD_MINT_FEE: &str = "bad-mint-fee";
/// XFER-1.
pub const BAD_TRANSFER_ASSIGNMENT: &str = "bad-transfer-assignment";
/// XFER-2.
pub const TRANSFER_OVER_ASSIGNED: &str = "transfer-over-assigned";
/// XFER-3.
pub const TRANSFER_NO_YED_INPUT: &str = "transfer-no-yed-input";
/// RED-1.
pub const VAULT_SPEND_MALFORMED: &str = "vault-spend-malformed";
/// RED-2.
pub const VAULT_SPEND_MISSING_BURN: &str = "vault-spend-missing-burn";
/// RED-2.
pub const VAULT_SPEND_SHORT_BURN: &str = "vault-spend-short-burn";
/// RED-3.
pub const VAULT_SPEND_BAD_FEE: &str = "vault-spend-bad-fee";
/// RED-3.
pub const VAULT_SPEND_BAD_PAYEE: &str = "vault-spend-bad-payee";
/// IT-9: an owner redeem before `lockHeight` short of the early-redeem fee.
pub const BAD_REDEEM_EARLY_FEE: &str = "bad-redeem-early-fee";
/// RED-4.
pub const VAULT_CLAIM_NOT_UNDERWATER: &str = "vault-claim-not-underwater";
/// MINT-9: ARMED and no carrier-shaped input at all.
pub const MINT9_NO_BUNDLE: &str = "mint9-no-bundle";
/// MINT-9: `"mint9-bundle-" ‖ BUNDLE-1's reason`.
pub const MINT9_BUNDLE_PREFIX: &str = "mint9-bundle-";
/// MINT-10.
pub const MINT10_DIVERGED: &str = "mint10-diverged";
/// RED-1 (amended): `"red1-bundle-" ‖ BUNDLE-1's reason`.
pub const RED1_BUNDLE_PREFIX: &str = "red1-bundle-";
/// RED-5.
pub const RED5_RESIDUAL: &str = "red5-residual";
/// RED-5a: the lower-index intent is under `collateral − residualZat`.
pub const RED5_CLAIMANT_SHORT: &str = "red5-claimant-short";
/// AFEE-1.
pub const AFEE1_FEE: &str = "afee1-fee";
/// U-23: a claim's outputs are not one claimant intent (+ at most one owner residual intent),
/// or re-lock.
pub const VAULT_CLAIM_INTENTS: &str = "vault-claim-intents";
/// U-23: a claim intent spent by a selector other than release/cancel, or with a payload.
pub const INTENT_SPEND_MALFORMED: &str = "intent-spend-malformed";
/// U-23: an attestor cancel of the owner's residual intent.
pub const INTENT_CANCEL_RESIDUAL: &str = "intent-cancel-residual";
/// U-23: a cancel that does not re-create exactly one byte-identical vault at vout 0.
pub const INTENT_CANCEL_NO_VAULT: &str = "intent-cancel-no-vault";
/// CAN-1 (03/H-1): a cancel without the refund output to the claim's YED holder.
pub const INTENT_CANCEL_NO_REFUND: &str = "intent-cancel-no-refund";
/// CAN-2 + C4b: too few distinct valid CANCEL_COSIGN statements of current members.
pub const INTENT_CANCEL_COSIGN: &str = "intent-cancel-cosign";
/// CAN-3: the release of a residual intent held by its re-created position.
pub const INTENT_RESIDUAL_HELD: &str = "intent-residual-held";
/// TOK-PQ: from the Falcon height a YED output that is not a Falcon holder.
pub const BAD_YED_HOLDER: &str = "bad-yed-holder";
/// U-23: a YED-tagged V or I output no mint, claim or cancel created.
pub const YED_TEMPLATE_OUTPUT: &str = "yed-template-output";
/// The reason suffix when BUNDLE-1 held but the statistic is undefined.
pub const BUNDLE_STAT: &str = "stat";
/// P4-b: an ATTESTOR_REGISTER payload.
pub const ATTESTOR_REGISTER_RETIRED: &str = "attestor-register-retired";
/// P4-b: an ATTESTOR_REVIVE payload.
pub const ATTESTOR_REVIVE_RETIRED: &str = "attestor-revive-retired";
/// A SET_REMOVE or SET_WINDDOWN of the attestor set.
pub const ATTESTOR_SET_ACT: &str = crate::attest::mirror::ATTESTOR_SET_ACT;
/// A SET_JOIN of the attestor set once the u16 seq space is used up.
pub const ATTESTOR_SEQ_EXHAUSTED: &str = crate::attest::mirror::ATTESTOR_SEQ_EXHAUSTED;
/// A bundle that credits liveness on a transaction that is not a held YED act.
pub const LIVENESS_UNHELD: &str = crate::attest::mirror::LIVENESS_UNHELD;
/// A SET_JOIN of the attestor set below `BondMinZat`.
pub const ATTESTOR_BOND_BELOW_MIN: &str = crate::attest::mirror::ATTESTOR_BOND_BELOW_MIN;
