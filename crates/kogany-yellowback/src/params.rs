// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

//! The module's parameters: the Rust face of ycash6 `src/yellowback/params.{h,cpp}` (§3.1 of the
//! v2/v3 plans as amended by the upgrade plan §6, the in-term claims plan §3 and the quantum plan's
//! D-Q-23..D-Q-30), with the constants of `src/amount.h` and `src/script/script.h` they use.
//!
//! **Never hand-copied without the check.** Every value here is compared, column by column and field
//! by field, with what the C++ source assigns: `tests/params_cpp.rs` parses ycash6's `params.h`,
//! `params.cpp` and `amount.h` (path from `YCASH6_SRC`) and fails on any difference, on any field one
//! side has and the other lacks, and on any construct it cannot evaluate. A parameter changes here
//! only in the same change set as ycash6 (plan §4.2 rule 5) and, for a calibrated constant, with the
//! `yb-calibration` result that justifies it.
//!
//! Field names are the C++ names in `snake_case`; [`Params::fields`] lists them under their C++
//! spelling (`classMin[0]`, `feeBands[1].bps`) for the parsing test and the audit's vault-params leg.
//!
//! The upgrade line has no activation valve, enforcement window or abandonment (the v2/v3
//! `ABANDON_BLOCKS` and `ENFORCE_UNTIL_HEIGHT` are retired, upgrade plan §6, U-21): the module is
//! consensus wherever `UPGRADE_VAULT` is active and [`Params::is_configured`] holds.

/// Yellowback amounts are integer US cents; 100 == $1.00 (`Cents`).
pub type Cents = i64;
/// Prices are integer micro-USD per YEC; 1,000,000 == $1.00 (`MicroUsd`).
pub type MicroUsd = i64;
/// An amount of YEC in zatoshis (`CAmount`).
pub type Amount = i64;

/// Zatoshis per YEC (`amount.h` `COIN`).
pub const COIN: Amount = 100_000_000;
/// The largest amount of YEC (`amount.h` `MAX_MONEY`, 21,000,000 YEC).
pub const MAX_MONEY: Amount = 21_000_000 * COIN;

/// `MoneyRange`: `0 <= v <= MAX_MONEY`.
pub const fn money_range(v: Amount) -> bool {
    v >= 0 && v <= MAX_MONEY
}

/// `script.h` `LOCKTIME_THRESHOLD`: lock times below it are heights.
pub const LOCKTIME_THRESHOLD: u32 = 500_000_000;

/// Payload magic byte 0 (`'Y'`, §3.3).
pub const PAYLOAD_MAGIC_0: u8 = 0x59;
/// Payload magic byte 1 (`'B'`).
pub const PAYLOAD_MAGIC_1: u8 = 0x42;
/// The payload version this release emits and accepts for every type but MINT (v3 plan W14).
pub const PAYLOAD_VERSION: u8 = 0x03;
/// The MINT payload version on the post-quantum line (quantum spec C-1, §3.1): its owner field is
/// `ownerScheme u8 || ownerHash 32`. A MINT at [`PAYLOAD_VERSION`] is non-Yellowback.
pub const MINT_PAYLOAD_VERSION: u8 = 0x04;
/// Largest payload: Ycash `nMaxDatacarrierBytes` (83) minus `OP_RETURN` and the push opcode.
pub const MAX_PAYLOAD: usize = 80;
/// Smallest payload.
pub const MIN_PAYLOAD: usize = 4;

/// Coinbase tag magic `"YED!"` (§3.2).
pub const TAG_MAGIC: [u8; 4] = [0x59, 0x45, 0x44, 0x21];
/// Coinbase tag version.
pub const TAG_VERSION: u8 = 0x01;
/// Coinbase tag size in bytes.
pub const TAG_SIZE: usize = 36;

/// Blocks per hour at the 75-second post-Blossom spacing.
pub const BLOCKS_PER_HOUR: i32 = 48;
/// Blocks per day.
pub const BLOCKS_PER_DAY: i32 = 1152;
/// Blocks per year.
pub const BLOCKS_PER_YEAR: i32 = 420_480;

/// Lowest price, micro-USD per YEC ($0.0001; DigiByte's bound).
pub const PRICE_MIN: MicroUsd = 100;
/// Highest price, `UINT32_MAX` micro-USD per YEC (the attestation format's `u32`, D-Q-22).
pub const PRICE_MAX: MicroUsd = 4_294_967_295;

/// MINT-2: `H - REF_WINDOW <= refHeight <= H - 1`. Equal to the default transaction expiry delta
/// but deliberately not derived from it.
pub const REF_WINDOW: i32 = 40;
/// Wallet-side only: `refHeight = indexTip - REF_LAG`.
pub const DEFAULT_REF_LAG: i32 = 2;
/// Wallet-side bound on the reference lag.
pub const MAX_REF_LAG: i32 = 36;

/// YEC carried by every Yellowback output: 10,000 zat.
pub const TOKEN_VALUE: Amount = 10_000;
/// The network fee floor of a wallet-built Yellowback transaction (wallet policy).
pub const DEFAULT_YELLOWBACK_FEE: Amount = 1000;

/// Term classes (V19, D-IT-10): A = 30-90 d, B = 91-180 d, C = 181-365 d.
pub const NUM_CLASSES: usize = 3;
/// The price a signal-only tag carries (V9).
pub const TAG_PRICE_SIGNAL_ONLY: u64 = 0;
/// `feeVout` / `attestFeeVout` value meaning "no fee output" (§3.3).
pub const FEE_VOUT_NONE: u8 = 0xFF;

/// Number of FEE-1′ debt bands (D-Q-23, fees spec §1.1).
pub const FEE_BANDS: usize = 3;

/// Default regtest `-yellowbackattestarmmin` (`RegtestParams`'s default argument).
pub const REGTEST_DEFAULT_ATTEST_ARM_MIN: i32 = 3;
/// Default regtest `-yellowbackbundlecarrier`.
pub const REGTEST_DEFAULT_BUNDLE_CARRIER: BundleCarrier = BundleCarrier::ScriptSig;
/// Default regtest `-yellowbackmintrequiresarmed`.
pub const REGTEST_DEFAULT_MINT_REQUIRES_ARMED: bool = false;

/// One FEE-1′ band: the debt in `(previous upto_cents, upto_cents]` pays `bps` (`FeeBand`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FeeBand {
    /// The band's upper edge in cents, inclusive; 0 = unbounded (the last band only).
    pub upto_cents: Cents,
    /// The rate inside the band, basis points of the debt.
    pub bps: i32,
}

/// Where a transaction carries its attestation bundle (v3 plan §3.1 `BUNDLE_CARRIER`, W2).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum BundleCarrier {
    /// The scriptSig of a P2SH carrier input (shipped).
    #[default]
    ScriptSig = 0,
    /// The `OP_RETURN` payload tail (unshipped).
    OpReturn = 1,
    /// Either.
    Either = 2,
}

impl BundleCarrier {
    /// `ParseBundleCarrier`: `"scriptsig"`, `"opreturn"` or `"either"`; `None` for anything else.
    pub fn parse(name: &str) -> Option<BundleCarrier> {
        match name {
            "scriptsig" => Some(BundleCarrier::ScriptSig),
            "opreturn" => Some(BundleCarrier::OpReturn),
            "either" => Some(BundleCarrier::Either),
            _ => None,
        }
    }

    /// `BundleCarrierName`: the flag's spelling.
    pub const fn name(self) -> &'static str {
        match self {
            BundleCarrier::ScriptSig => "scriptsig",
            BundleCarrier::OpReturn => "opreturn",
            BundleCarrier::Either => "either",
        }
    }
}

/// A parameter's value as [`Params::fields`] reports it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ParamValue {
    /// An integer, a `bool` (0/1) or an enum's discriminant.
    Int(i64),
    /// A byte string (`std::vector<unsigned char>`, `uint256` in its memory order).
    Bytes(Vec<u8>),
    /// A string.
    Text(&'static str),
}

/// Per-network parameters (`yellowback::Params`, §3.1, field list §4.2a).
///
/// `start_height` is the `UPGRADE_VAULT` activation height and `attestor_set_id` the network's YED
/// attestor set (U-22); both unset means YED is off. `attestor_set_id` is the 32 bytes of the C++
/// `uint256` in memory order (the order `uint256::begin()` reads, the reverse of its hex).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Params {
    /// `"main"`, `"test"` or `"regtest"` (`CChainParams::NetworkIDString`); `""` by default.
    pub network: &'static str,

    /// First height whose tags count: the `UPGRADE_VAULT` activation height; 0 = YED off.
    pub start_height: i32,
    /// Base58Check version bytes of Yellowback addresses (D10); `None` only in
    /// [`Params::default`], where the C++ vector is empty (every column sets it).
    pub address_version: Option<[u8; 2]>,
    /// The same for a PQ key, `scheme || keyHash` (quantum spec §4).
    pub pq_address_version: Option<[u8; 2]>,
    /// The vault primitive set whose members cancel claims (U-22, U-23); all zero = YED off.
    pub attestor_set_id: [u8; 32],
    /// `CLAIM_DELAY`: the YED vault's and its claim intents' delay, blocks (U-23).
    pub claim_delay: i32,

    /// PRICE-1 window `P_fast`.
    pub p_fast_window: i32,
    /// PRICE-1 window `P_mid`.
    pub p_mid_window: i32,
    /// PRICE-1 window `P_slow`.
    pub p_slow_window: i32,
    /// `WINDOW_MIN_FILL` of `P_fast`.
    pub p_fast_min_fill: i32,
    /// `WINDOW_MIN_FILL` of `P_mid`.
    pub p_mid_min_fill: i32,
    /// `WINDOW_MIN_FILL` of `P_slow`.
    pub p_slow_min_fill: i32,

    /// REG-1..4 `N_REG` (informational).
    pub n_reg: i32,
    /// `PEER_LAG`.
    pub peer_lag: i32,
    /// `PEER_MIN`.
    pub peer_min: i32,
    /// `DEVIATION_BPS`.
    pub deviation_bps: i32,
    /// `ACCURACY_BAND_BPS`.
    pub accuracy_band_bps: i32,
    /// FEE-2 `PAYEE_WINDOW`.
    pub payee_window: i32,

    /// FEE-1′ bands (D-Q-23), read by [`crate::math::protocol_fee_units`]; never restate them.
    pub fee_bands: [FeeBand; FEE_BANDS],
    /// FEE-1′ floor per action, cents; the early fee has no floor.
    pub fee_floor_cents: Cents,

    /// `GRACE`: `claimHeight = lockHeight + grace`.
    pub grace: i32,
    /// θ, RED-4(a)'s claim threshold (D-IT-2).
    pub claim_threshold_bps: i32,
    /// MINT-6 supply cap share of the market capitalisation; 0 = no cap.
    pub supply_cap_bps: i32,
    /// HALT-2 floor of the global ratio (D-IT-11).
    pub global_ratio_halt_bps: i32,
    /// IT-5: under HALT-2 and above the cap a MINT is accepted iff its class base is at least this.
    pub recap_ratio_bps: i32,
    /// `DIVERGENCE_BPS`.
    pub divergence_bps: i32,
    /// Lock length range per class (blocks), inclusive lower bound.
    pub class_min: [i32; NUM_CLASSES],
    /// Inclusive upper bound; `class_min > class_max` disables the class (H-5).
    pub class_max: [i32; NUM_CLASSES],
    /// MINT-5 base ratio per class (D-IT-4).
    pub base_ratio_bps: [i32; NUM_CLASSES],
    /// IT-9′ early-redeem fee per class, bps of the debt at `pMint` (D-Q-23).
    pub early_redeem_fee_bps: [i32; NUM_CLASSES],

    /// SIGMA-1 `VOL_WINDOW`.
    pub vol_window: i32,
    /// SIGMA-1 `VOL_STEP`.
    pub vol_step: i32,
    /// SIGMA-1 periods per year (K13: equal on every network).
    pub vol_periods_per_year: i32,
    /// SIGMA-1 reference; 0 fixes the multiplier at 1 (D-IT-5).
    pub sigma_ref_bps: i32,
    /// SIGMA-1 multiplier cap.
    pub sigma_mult_max_bps: i32,

    /// MINT-2 smallest mint, cents.
    pub min_mint: Cents,
    /// MINT-6b: a mint's debt may not exceed this share of the MINT-6 cap ...; 0 = off.
    pub max_vault_share_bps: i32,
    /// MINT-6b: ... nor this floor, whatever the cap.
    pub vault_share_floor_cents: Cents,
    /// MINT-6 (D-Q-25): YEC circulating below `start_height`, set by the index from the chain
    /// parameters (`CirculatingSupplyAt(startHeight - 1)`); never hashed.
    pub issued_before_start: Amount,
    /// MINT-2 largest mint, cents (D-Q-24).
    pub max_mint: Cents,
    /// XFER-1 smallest output, cents.
    pub min_output: Cents,
    /// XFER-1 largest output, cents.
    pub max_output: Cents,
    /// [`TOKEN_VALUE`].
    pub token_value: Amount,
    /// [`REF_WINDOW`].
    pub ref_window: i32,

    /// L6 wallet default (never hashed).
    pub n_penalty: i32,
    /// L6 wallet default (never hashed).
    pub accuracy_window: i32,
    /// L6 wallet default (never hashed).
    pub payee_tilt_bps: i32,

    /// `ATTEST_ARM_MIN` (ARM-1); 0 = never arms (regtest).
    pub attest_arm_min: i32,
    /// `ATTEST_ARM_DELAY` (ARM-2).
    pub attest_arm_delay: i32,
    /// `ATTEST_REQUIRED` (W15): false => PRICE-2 reads x only.
    pub attest_required: bool,
    /// `BUNDLE_CARRIER` (W2).
    pub bundle_carrier: BundleCarrier,
    /// `N_SLOTS`.
    pub n_slots: i32,
    /// `M_SELECT`.
    pub m_select: i32,
    /// `K_SLACK`.
    pub k_slack: i32,
    /// `BUNDLE_MAX` (the 520-byte push).
    pub bundle_max: i32,
    /// `Q_LOW_BPS`.
    pub q_low_bps: i32,
    /// `Q_HIGH_BPS`.
    pub q_high_bps: i32,
    /// `ATTEST_MAX_AGE` (= 2 k).
    pub attest_max_age: i32,
    /// `PIN_WINDOW` (PIN-1/2).
    pub pin_window: i32,
    /// `PIN_DELTA_BPS`.
    pub pin_delta_bps: i32,
    /// `PIN_MIN_TAGS`.
    pub pin_min_tags: i32,
    /// `PIN_MIN_BUNDLES`.
    pub pin_min_bundles: i32,
    /// `DIVERGE_BPS_ATTEST` (MINT-10).
    pub diverge_bps_attest: i32,
    /// `EMERGENCY_RATIO_BPS` (NOT-1, RED-4(b)).
    pub emergency_ratio_bps: i32,
    /// `EMERGENCY_PERSIST`.
    pub emergency_persist: i32,
    /// `EMERGENCY_NOTICE_TTL`.
    pub emergency_notice_ttl: i32,
    /// `RESIDUAL_MIN_ZAT` (RED-5): the zat floor of the residual threshold.
    pub residual_min_zat: Amount,
    /// RED-5′ (D-Q-23a): the residual threshold in cents at the vault's `pMint`.
    pub residual_min_cents: Cents,
    /// `ATTEST_FEE_BPS` (AFEE-1′): the attestor share of the protocol fee.
    pub attest_fee_bps: i32,
    /// D-Q-30: the attestor bond minimum's floor.
    pub bond_min_floor_zat: Amount,
    /// D-Q-30: its cap.
    pub bond_min_cap_zat: Amount,
    /// D-Q-30 `BOND_SHARE_BPS`.
    pub bond_share_bps: i32,
    /// `BOND_MIN_LOCK`.
    pub bond_min_lock: i32,
    /// `BOND_MATURITY`.
    pub bond_maturity: i32,
    /// `AGE_CAP` (bond weight).
    pub age_cap: i32,
    /// `FOUNDING_WINDOW`.
    pub founding_window: i32,
    /// `SEAT_AGE_UNIT` (u of [`crate::math::seat_age_factor_q16`]).
    pub seat_age_unit: i32,
    /// `SEAT_AGE_CAP`.
    pub seat_age_cap: i32,
    /// `SEAT_MARGIN_BPS`.
    pub seat_margin_bps: i32,
    /// `EVICT_MARGIN_BPS`.
    pub evict_margin_bps: i32,
    /// `ATTESTOR_SEATS`: the module adopts only an OPEN attestor set of this many seats.
    pub attestor_seats: i32,
    /// `ATTESTOR_CANCEL_THRESHOLD` (03/I-3); consensus constant, not hashed.
    pub attestor_cancel_threshold: i32,
    /// `ATTESTOR_UNLOCK_THRESHOLD` (03/I-3); consensus constant, not hashed.
    pub attestor_unlock_threshold: i32,
    /// `ATTESTOR_RATE_LIMIT_BPS` (W3-Y-3); consensus constant, not hashed.
    pub attestor_rate_limit_bps: i32,
    /// `CANCEL_SIGNERS_MAX` (CAN-2); consensus constant, not hashed.
    pub cancel_signers_max: i32,
    /// `CANCEL_QUIET` (CAN-2/CAN-3); not hashed.
    pub cancel_quiet: i32,
    /// `ATTESTOR_LIVENESS_MIN` (seats review B3).
    pub attestor_liveness_min: i32,
    /// `DORMANCY_BLOCKS`.
    pub dormancy_blocks: i32,
    /// `DORMANCY_MIN_BUNDLES`.
    pub dormancy_min_bundles: i32,
    /// `DORMANCY_CHECK` (S15).
    pub dormancy_check: i32,
    /// `CARRIER_VALUE` (wallet policy, never hashed).
    pub carrier_value: Amount,
    /// k, the attestor signing interval (agent policy).
    pub attest_interval: i32,
    /// `WALLET_CONFIRMATIONS` (wallet policy).
    pub wallet_confirmations: i32,
    /// `MINT_REQUIRES_ARMED` (H-1): MINT-4 refuses a mint whose R is not ARMED.
    pub mint_requires_armed: bool,
    /// The Falcon (scheme 0x02) activation height mirrored from consensus; -1 = never. Set by
    /// `ParamsFromArgs` (index), not by the column constructors.
    pub pq_falcon_height: i32,
}

impl Default for Params {
    /// `Params::Params()`: every count 0, `attest_required` true, `pq_falcon_height` -1.
    fn default() -> Params {
        Params {
            network: "",
            start_height: 0,
            address_version: None,
            pq_address_version: None,
            attestor_set_id: [0; 32],
            claim_delay: 0,
            p_fast_window: 0,
            p_mid_window: 0,
            p_slow_window: 0,
            p_fast_min_fill: 0,
            p_mid_min_fill: 0,
            p_slow_min_fill: 0,
            n_reg: 0,
            peer_lag: 0,
            peer_min: 0,
            deviation_bps: 0,
            accuracy_band_bps: 0,
            payee_window: 0,
            fee_bands: [FeeBand {
                upto_cents: 0,
                bps: 0,
            }; FEE_BANDS],
            fee_floor_cents: 0,
            grace: 0,
            claim_threshold_bps: 0,
            supply_cap_bps: 0,
            global_ratio_halt_bps: 0,
            recap_ratio_bps: 0,
            divergence_bps: 0,
            class_min: [0; NUM_CLASSES],
            class_max: [0; NUM_CLASSES],
            base_ratio_bps: [0; NUM_CLASSES],
            early_redeem_fee_bps: [0; NUM_CLASSES],
            vol_window: 0,
            vol_step: 0,
            vol_periods_per_year: 0,
            sigma_ref_bps: 0,
            sigma_mult_max_bps: 0,
            min_mint: 0,
            max_vault_share_bps: 0,
            vault_share_floor_cents: 0,
            issued_before_start: 0,
            max_mint: 0,
            min_output: 0,
            max_output: 0,
            token_value: 0,
            ref_window: 0,
            n_penalty: 0,
            accuracy_window: 0,
            payee_tilt_bps: 0,
            attest_arm_min: 0,
            attest_arm_delay: 0,
            attest_required: true,
            bundle_carrier: BundleCarrier::ScriptSig,
            n_slots: 0,
            m_select: 0,
            k_slack: 0,
            bundle_max: 0,
            q_low_bps: 0,
            q_high_bps: 0,
            attest_max_age: 0,
            pin_window: 0,
            pin_delta_bps: 0,
            pin_min_tags: 0,
            pin_min_bundles: 0,
            diverge_bps_attest: 0,
            emergency_ratio_bps: 0,
            emergency_persist: 0,
            emergency_notice_ttl: 0,
            residual_min_zat: 0,
            residual_min_cents: 0,
            attest_fee_bps: 0,
            bond_min_floor_zat: 0,
            bond_min_cap_zat: 0,
            bond_share_bps: 0,
            bond_min_lock: 0,
            bond_maturity: 0,
            age_cap: 0,
            founding_window: 0,
            seat_age_unit: 0,
            seat_age_cap: 0,
            seat_margin_bps: 0,
            evict_margin_bps: 0,
            attestor_seats: 0,
            attestor_cancel_threshold: 0,
            attestor_unlock_threshold: 0,
            attestor_rate_limit_bps: 0,
            cancel_signers_max: 0,
            cancel_quiet: 0,
            attestor_liveness_min: 0,
            dormancy_blocks: 0,
            dormancy_min_bundles: 0,
            dormancy_check: 0,
            carrier_value: 0,
            attest_interval: 0,
            wallet_confirmations: 0,
            mint_requires_armed: false,
            pq_falcon_height: -1,
        }
    }
}

impl Params {
    /// `IsConfigured`: the start height and the attestor set are both known (U-22).
    pub fn is_configured(&self) -> bool {
        self.start_height > 0 && self.attestor_set_id != [0u8; 32]
    }

    /// `ClassForLockBlocks`: the class index (0..2) for a lock length in blocks, the first whose
    /// range holds it; `None` if in no class (V19).
    pub fn class_for_lock_blocks(&self, lock_blocks: i64) -> Option<usize> {
        self.class_min
            .iter()
            .zip(self.class_max.iter())
            .position(|(min, max)| lock_blocks >= i64::from(*min) && lock_blocks <= i64::from(*max))
    }

    /// `IsValidClass`.
    pub fn is_valid_class(&self, term_class: i64) -> bool {
        usize::try_from(term_class).is_ok_and(|c| c < NUM_CLASSES)
    }

    /// `IsClassEnabled` (H-5): a class with an empty term range (`class_min > class_max`) is disabled.
    pub fn is_class_enabled(&self, term_class: i64) -> bool {
        let Ok(c) = usize::try_from(term_class) else {
            return false;
        };
        match (self.class_min.get(c), self.class_max.get(c)) {
            (Some(min), Some(max)) => min <= max,
            _ => false,
        }
    }

    /// `IsArmed`: "ARMED" in every v3 rule means the snapshot's status and `attest_required` (W15).
    pub fn is_armed(&self, snapshot_armed: bool) -> bool {
        self.attest_required && snapshot_armed
    }

    /// `IsPQFalconActive`: `pq_falcon_height >= 0 && height >= pq_falcon_height`.
    pub fn is_pq_falcon_active(&self, height: i64) -> bool {
        self.pq_falcon_height >= 0 && height >= i64::from(self.pq_falcon_height)
    }

    /// `MinFill`: `WINDOW_MIN_FILL` of a price window (PRICE-1, L9); the slow fill for any window
    /// that is neither the fast nor the mid one.
    pub fn min_fill(&self, window: i32) -> i32 {
        if window == self.p_fast_window {
            self.p_fast_min_fill
        } else if window == self.p_mid_window {
            self.p_mid_min_fill
        } else {
            self.p_slow_min_fill
        }
    }

    /// Every field under its C++ name, in declaration order (`classMin[0]`, `feeBands[2].bps`, ...):
    /// the cross-check against `params.cpp` and the audit's vault-params leg read this.
    pub fn fields(&self) -> Vec<(String, ParamValue)> {
        use ParamValue::{Bytes, Int, Text};
        let mut v: Vec<(String, ParamValue)> = Vec::new();
        let mut int = |name: &str, x: i64| v.push((name.to_string(), Int(x)));
        int("startHeight", self.start_height.into());
        int("claimDelay", self.claim_delay.into());
        int("pFastWindow", self.p_fast_window.into());
        int("pMidWindow", self.p_mid_window.into());
        int("pSlowWindow", self.p_slow_window.into());
        int("pFastMinFill", self.p_fast_min_fill.into());
        int("pMidMinFill", self.p_mid_min_fill.into());
        int("pSlowMinFill", self.p_slow_min_fill.into());
        int("nReg", self.n_reg.into());
        int("peerLag", self.peer_lag.into());
        int("peerMin", self.peer_min.into());
        int("deviationBps", self.deviation_bps.into());
        int("accuracyBandBps", self.accuracy_band_bps.into());
        int("payeeWindow", self.payee_window.into());
        for (i, band) in self.fee_bands.iter().enumerate() {
            int(&format!("feeBands[{i}].uptoCents"), band.upto_cents);
            int(&format!("feeBands[{i}].bps"), band.bps.into());
        }
        int("feeFloorCents", self.fee_floor_cents);
        int("grace", self.grace.into());
        int("claimThresholdBps", self.claim_threshold_bps.into());
        int("supplyCapBps", self.supply_cap_bps.into());
        int("globalRatioHaltBps", self.global_ratio_halt_bps.into());
        int("recapRatioBps", self.recap_ratio_bps.into());
        int("divergenceBps", self.divergence_bps.into());
        for (name, arr) in [
            ("classMin", &self.class_min),
            ("classMax", &self.class_max),
            ("baseRatioBps", &self.base_ratio_bps),
            ("earlyRedeemFeeBps", &self.early_redeem_fee_bps),
        ] {
            for (i, x) in arr.iter().enumerate() {
                int(&format!("{name}[{i}]"), (*x).into());
            }
        }
        int("volWindow", self.vol_window.into());
        int("volStep", self.vol_step.into());
        int("volPeriodsPerYear", self.vol_periods_per_year.into());
        int("sigmaRefBps", self.sigma_ref_bps.into());
        int("sigmaMultMaxBps", self.sigma_mult_max_bps.into());
        int("minMint", self.min_mint);
        int("maxVaultShareBps", self.max_vault_share_bps.into());
        int("vaultShareFloorCents", self.vault_share_floor_cents);
        int("issuedBeforeStart", self.issued_before_start);
        int("maxMint", self.max_mint);
        int("minOutput", self.min_output);
        int("maxOutput", self.max_output);
        int("tokenValue", self.token_value);
        int("refWindow", self.ref_window.into());
        int("nPenalty", self.n_penalty.into());
        int("accuracyWindow", self.accuracy_window.into());
        int("payeeTiltBps", self.payee_tilt_bps.into());
        int("attestArmMin", self.attest_arm_min.into());
        int("attestArmDelay", self.attest_arm_delay.into());
        int("attestRequired", self.attest_required.into());
        int("bundleCarrier", (self.bundle_carrier as u8).into()); // the repr(u8) discriminant, the C++ enum value
        int("nSlots", self.n_slots.into());
        int("mSelect", self.m_select.into());
        int("kSlack", self.k_slack.into());
        int("bundleMax", self.bundle_max.into());
        int("qLowBps", self.q_low_bps.into());
        int("qHighBps", self.q_high_bps.into());
        int("attestMaxAge", self.attest_max_age.into());
        int("pinWindow", self.pin_window.into());
        int("pinDeltaBps", self.pin_delta_bps.into());
        int("pinMinTags", self.pin_min_tags.into());
        int("pinMinBundles", self.pin_min_bundles.into());
        int("divergeBpsAttest", self.diverge_bps_attest.into());
        int("emergencyRatioBps", self.emergency_ratio_bps.into());
        int("emergencyPersist", self.emergency_persist.into());
        int("emergencyNoticeTtl", self.emergency_notice_ttl.into());
        int("residualMinZat", self.residual_min_zat);
        int("residualMinCents", self.residual_min_cents);
        int("attestFeeBps", self.attest_fee_bps.into());
        int("bondMinFloorZat", self.bond_min_floor_zat);
        int("bondMinCapZat", self.bond_min_cap_zat);
        int("bondShareBps", self.bond_share_bps.into());
        int("bondMinLock", self.bond_min_lock.into());
        int("bondMaturity", self.bond_maturity.into());
        int("ageCap", self.age_cap.into());
        int("foundingWindow", self.founding_window.into());
        int("seatAgeUnit", self.seat_age_unit.into());
        int("seatAgeCap", self.seat_age_cap.into());
        int("seatMarginBps", self.seat_margin_bps.into());
        int("evictMarginBps", self.evict_margin_bps.into());
        int("attestorSeats", self.attestor_seats.into());
        int(
            "attestorCancelThreshold",
            self.attestor_cancel_threshold.into(),
        );
        int(
            "attestorUnlockThreshold",
            self.attestor_unlock_threshold.into(),
        );
        int("attestorRateLimitBps", self.attestor_rate_limit_bps.into());
        int("cancelSignersMax", self.cancel_signers_max.into());
        int("cancelQuiet", self.cancel_quiet.into());
        int("attestorLivenessMin", self.attestor_liveness_min.into());
        int("dormancyBlocks", self.dormancy_blocks.into());
        int("dormancyMinBundles", self.dormancy_min_bundles.into());
        int("dormancyCheck", self.dormancy_check.into());
        int("carrierValue", self.carrier_value);
        int("attestInterval", self.attest_interval.into());
        int("walletConfirmations", self.wallet_confirmations.into());
        int("mintRequiresArmed", self.mint_requires_armed.into());
        int("pqFalconHeight", self.pq_falcon_height.into());
        v.push(("network".to_string(), Text(self.network)));
        v.push((
            "addressVersion".to_string(),
            Bytes(self.address_version.map_or_else(Vec::new, |v| v.to_vec())),
        ));
        v.push((
            "pqAddressVersion".to_string(),
            Bytes(
                self.pq_address_version
                    .map_or_else(Vec::new, |v| v.to_vec()),
            ),
        ));
        v.push((
            "attestorSetId".to_string(),
            Bytes(self.attestor_set_id.to_vec()),
        ));
        v
    }
}

/// `SetCommon`: the §3.1 mainnet/testnet column. Every rule-read value is compiled in (K10).
const fn common(mut p: Params) -> Params {
    p.min_mint = 10_000; // $100
    p.max_vault_share_bps = 1000; // MINT-6b (D-Q-23a): 10 % of the MINT-6 cap ...
    p.vault_share_floor_cents = 1_000_000; // ... but always $10,000
    p.issued_before_start = 0; // MINT-6 (D-Q-25): set by the index
    p.max_mint = 10_000_000; // $100,000 (D-Q-24)
    p.min_output = 100; // $1.00
    p.max_output = 10_000_000; // $100,000
    p.token_value = TOKEN_VALUE;
    p.ref_window = REF_WINDOW;

    p.p_fast_window = 96;
    p.p_fast_min_fill = 48; // ceil(W/2)
    p.p_mid_window = 576;
    p.p_mid_min_fill = 384; // ceil(2W/3) (L9)
    p.p_slow_window = 2016;
    p.p_slow_min_fill = 1344;

    p.n_reg = 576;
    p.peer_lag = 10;
    p.peer_min = 5;
    p.deviation_bps = 1000;
    p.accuracy_band_bps = 300;
    p.payee_window = 100;

    // FEE-1' (D-Q-23): tiered by the debt; yb-calibration's fee study (D-Q-23a) confirmed these.
    p.fee_bands = [
        FeeBand {
            upto_cents: 100_000,
            bps: 100,
        }, // the first $1,000 at 1.0 %
        FeeBand {
            upto_cents: 1_000_000,
            bps: 50,
        }, // $1,000 - $10,000 at 0.5 %
        FeeBand {
            upto_cents: 0,
            bps: 10,
        }, // above $10,000 at 0.1 % (unbounded)
    ];
    p.fee_floor_cents = 100; // $1 per action

    p.grace = 34_560; // 30 d
    p.claim_delay = 576; // CLAIM_DELAY 12 h (U-23)
                         // In-term claims (D-IT-2, D-IT-11, D-IT-12)
    p.claim_threshold_bps = 12_500; // θ 125 %
    p.supply_cap_bps = 1500; // 15 % of market cap (V21)
    p.global_ratio_halt_bps = 20_000; // D-IT-11
    p.recap_ratio_bps = 50_000; // D-IT-12: class C's base
    p.divergence_bps = 2000;
    // D-IT-4, D-IT-9, D-IT-10: three flat tiers, the longer the term the higher the ratio.
    p.class_min = [34_560, 103_681, 207_361]; // A 30-90 d, B 91-180 d, C 181-365 d
    p.class_max = [103_680, 207_360, 420_480];
    p.base_ratio_bps = [30_000, 40_000, 50_000]; // 300 / 400 / 500 %
    p.early_redeem_fee_bps = [500, 250, 100]; // IT-9' (D-Q-23): of the debt at pMint

    p.vol_window = 2016;
    p.vol_step = 48;
    p.vol_periods_per_year = 8760; // K13
    p.sigma_ref_bps = 0; // D-IT-5: multiplier pinned at 1
    p.sigma_mult_max_bps = 10_000;

    p.n_penalty = 288; // L6 wallet defaults
    p.accuracy_window = 576;
    p.payee_tilt_bps = 10_000;

    // v3 §3.1: price attestation
    p.attest_arm_min = 7; // ARM-1 (H-2)
    p.attest_arm_delay = 1152; // ARM-2: one day
    p.attest_required = true; // W15
    p.bundle_carrier = BundleCarrier::ScriptSig; // W2
    p.n_slots = 9;
    p.m_select = 4;
    p.k_slack = 2;
    p.bundle_max = 6;
    p.q_low_bps = 3333;
    p.q_high_bps = 6667;
    p.attest_max_age = 20; // 2 k (R4)
    p.pin_window = 288;
    p.pin_delta_bps = 500;
    p.pin_min_tags = 3;
    p.pin_min_bundles = 2;
    p.diverge_bps_attest = 1500; // MINT-10
    p.emergency_ratio_bps = 10_500; // NOT-1, RED-4(b)
    p.emergency_persist = 48;
    p.emergency_notice_ttl = 1152;
    p.residual_min_zat = 100_000; // RED-5: the zat floor
    p.residual_min_cents = 48; // RED-5' (D-Q-23a): $0.48 at the vault's pMint
    p.attest_fee_bps = 5000; // AFEE-1 (H-4)
    p.bond_min_floor_zat = 10_000 * COIN; // D-Q-30
    p.bond_min_cap_zat = 20_000 * COIN;
    p.bond_share_bps = 500;
    p.bond_min_lock = 0;
    p.bond_maturity = 16_128; // two weeks
    p.age_cap = 207_360; // 180 d
    p.founding_window = 8064; // 7 d
    p.seat_age_unit = 1152; // one day
    p.seat_age_cap = 420_480; // one year: x1.9
    p.seat_margin_bps = 500;
    p.evict_margin_bps = 500;
    p.attestor_seats = 15;
    p.attestor_cancel_threshold = 1; // 03/I-3
    p.attestor_unlock_threshold = 1;
    p.attestor_rate_limit_bps = 0; // W3-Y-3 (R-1d)
    p.attestor_liveness_min = 1152; // seats review B3
    p.cancel_signers_max = 4; // CAN-2 round 2
    p.cancel_quiet = 8064; // CAN-2/CAN-3: 7 d
    p.dormancy_blocks = 16_128;
    p.dormancy_min_bundles = 20;
    p.dormancy_check = 48; // S15
    p.carrier_value = 10_000; // wallet policy
    p.attest_interval = 10; // k, agent policy
    p.wallet_confirmations = 6; // wallet policy
    p.mint_requires_armed = true; // H-1
    p
}

/// `SetTestnet`: network `"test"`, the `yt…` versions, YED unset (U-22).
const fn testnet(mut t: Params) -> Params {
    t.network = "test";
    t.address_version = Some([0x20, 0x07]); // "yt…" (D10)
    t.pq_address_version = Some([0x57, 0x1E]); // "yt…", 53 characters
    t.start_height = 0;
    t
}

/// `MainParams`. `start_height` and `attestor_set_id` are unset until the gate-passing release (P8).
pub fn main_params() -> Params {
    let mut m = common(Params {
        network: "main",
        ..Params::default()
    });
    m.address_version = Some([0x1F, 0xDD]); // "yb…", 35 characters (D10; D-Q-21)
    m.pq_address_version = Some([0x56, 0xAB]); // "yb…", 53 characters
    m.start_height = 0;
    m
}

/// `TestParams`: the testnet column (testnet-yb-slow and testnet-legacy), mainnet's values.
pub fn test_params() -> Params {
    testnet(common(Params::default()))
}

/// `TestFastParams`: testnet-yb-fast (testnet plan Revision 3, T-16). Every lifecycle window is
/// `max(floor, ceil(mainnet x 48 / 16,128))`; everything else is the testnet column's, but for the
/// bond amounts (one thousandth of mainnet's, 2026-10-29).
pub fn test_fast_params() -> Params {
    let mut f = testnet(common(Params::default()));
    f.claim_delay = 20;
    f.grace = 103;
    f.class_min = [103, 310, 619];
    f.class_max = [309, 618, 1252];
    f.attest_arm_delay = 20;
    f.emergency_notice_ttl = 88;
    f.bond_maturity = 48;
    f.age_cap = 618;
    f.founding_window = 24;
    f.seat_age_unit = 4;
    f.seat_age_cap = 1252;
    f.attestor_liveness_min = 40;
    f.cancel_quiet = 80;
    f.dormancy_blocks = 48;
    f.dormancy_check = 1;
    f.bond_min_floor_zat = 10 * COIN;
    f.bond_min_cap_zat = 20 * COIN;
    f
}

/// `RegtestParams` with the three defaulted flags at their defaults
/// ([`REGTEST_DEFAULT_ATTEST_ARM_MIN`], [`REGTEST_DEFAULT_BUNDLE_CARRIER`],
/// [`REGTEST_DEFAULT_MINT_REQUIRES_ARMED`]).
pub fn regtest_params(
    start_height: i32,
    sigma_ref_bps: i32,
    supply_cap_bps: i32,
    attestor_set_id: [u8; 32],
) -> Params {
    regtest_params_with(
        start_height,
        sigma_ref_bps,
        supply_cap_bps,
        attestor_set_id,
        REGTEST_DEFAULT_ATTEST_ARM_MIN,
        REGTEST_DEFAULT_BUNDLE_CARRIER,
        REGTEST_DEFAULT_MINT_REQUIRES_ARMED,
    )
}

/// `RegtestParams`: the §3.1 regtest column; only the seven arguments come from the chain and the
/// regtest-only flags (`-nuparams`, `-yellowbackattestorset`, `-yellowbacksigmaref`,
/// `-yellowbacksupplycapbps`, `-yellowbackattestarmmin`, `-yellowbackbundlecarrier`,
/// `-yellowbackmintrequiresarmed`; all seven hashed, M13).
pub fn regtest_params_with(
    start_height: i32,
    sigma_ref_bps: i32,
    supply_cap_bps: i32,
    attestor_set_id: [u8; 32],
    attest_arm_min: i32,
    bundle_carrier: BundleCarrier,
    mint_requires_armed: bool,
) -> Params {
    let mut r = common(Params {
        network: "regtest",
        ..Params::default()
    });
    r.address_version = Some([0x20, 0x02]); // "yr…" (D10)
    r.pq_address_version = Some([0x57, 0x10]); // "yr…", 53 characters
    r.p_fast_window = 8;
    r.p_fast_min_fill = 4;
    r.p_mid_window = 24;
    r.p_mid_min_fill = 16;
    r.p_slow_window = 64;
    r.p_slow_min_fill = 43;
    r.n_reg = 24;
    r.peer_lag = 4;
    r.peer_min = 3;
    r.payee_window = 10;
    r.grace = 24;
    r.claim_delay = 10;
    // The hardening plan's mainnet values (H-4, H-11, H-12) stay out of the regtest column.
    r.attest_fee_bps = 2500;
    r.global_ratio_halt_bps = 25_000;
    r.recap_ratio_bps = 50_000;
    r.class_min = [48, 97, 145];
    r.class_max = [96, 144, 240];
    r.vol_window = 64;
    r.vol_step = 8;
    r.n_penalty = 12;
    r.accuracy_window = 24;
    // v3 §3.1 regtest column
    r.attest_arm_delay = 8;
    r.n_slots = 5;
    r.m_select = 2;
    r.k_slack = 1;
    r.attest_max_age = 8; // k = 4
    r.pin_window = 16;
    r.pin_min_tags = 2;
    r.emergency_persist = 4;
    r.emergency_notice_ttl = 64;
    // D-Q-30 at 1/2,000 of mainnet
    r.bond_min_floor_zat = 5 * COIN;
    r.bond_min_cap_zat = 10 * COIN;
    r.bond_min_lock = 0;
    r.attestor_liveness_min = 16;
    r.cancel_signers_max = 3;
    r.cancel_quiet = 40;
    r.bond_maturity = 8;
    r.age_cap = 64;
    r.founding_window = 16;
    r.dormancy_blocks = 16;
    r.dormancy_min_bundles = 2;
    r.dormancy_check = 4;
    r.attest_interval = 4;
    r.wallet_confirmations = 1;
    // the seven flags
    r.start_height = start_height;
    r.sigma_ref_bps = sigma_ref_bps;
    r.supply_cap_bps = supply_cap_bps;
    r.attestor_set_id = attestor_set_id;
    r.attest_arm_min = attest_arm_min;
    r.bundle_carrier = bundle_carrier;
    r.mint_requires_armed = mint_requires_armed;
    r
}

/// `SelectParams` (§3.1 *Parameter versioning*, K10): the set with the greatest
/// `start_height <= height` (the last such on a tie), or the first set when none qualifies; `None`
/// only for an empty `sets` (the C++ precondition).
pub fn select_params(sets: &[Params], height: i32) -> Option<&Params> {
    let mut best: Option<&Params> = None;
    for p in sets {
        if p.start_height <= height && best.is_none_or(|b| p.start_height >= b.start_height) {
            best = Some(p);
        }
    }
    best.or_else(|| sets.first())
}

/// `ParamsForNetwork`: by `CChainParams::NetworkIDString()`; regtest gives unconfigured defaults
/// (`RegtestParams(0, 0, 0, null)`). `None` for an unknown id, where the C++ throws.
pub fn params_for_network(network_id: &str) -> Option<Params> {
    match network_id {
        "main" => Some(main_params()),
        "test" => Some(test_params()),
        "regtest" => Some(regtest_params(0, 0, 0, [0u8; 32])),
        _ => None,
    }
}
