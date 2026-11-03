// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

//! The network-fee policy of post-quantum and Yellowback transactions (kogany W6-b; quantum plan
//! D-Q-23 (b), D-Q-23a, D-Q-26; fees spec `docs/plans/yellowback-quantum-fees-spec.md` §3, §5.1),
//! ported from ycash6 at `65cb4ae0f`: `src/policy/policy.{h,cpp}` (`AttestedFeePolicy`,
//! `AttestedRateZatPerKB`, `PlainPQFeeRate`, `YedFeeRate`, `AttestedFeeFloorPerKB`,
//! `YedMaxTxFee`, `PQMaxTxFee`, `PQSizeFee`, `YedSizeFee`, `YedFloorSizeFee`,
//! `PQSpendInputSize`), `src/amount.cpp` (`CFeeRate::GetFee`) and `src/yellowback/txbuilder.cpp`
//! (`YedEstimatedSize`, `YedNetworkFee`).
//!
//! **Node and wallet policy only.** ycash6 reads these numbers in its wallet, its YED and vault
//! transaction builders and `yed_getinfo.params.fees.network`; no relay or consensus rule reads
//! them (`AcceptToMemoryPool` keeps the minimum relay fee and the per-Sapling-output floor,
//! kogany's `zakura_chain::transaction::ycash_relay`). A node that refused a transaction paying
//! less than this policy would hold a different mempool than ycashd.
//!
//! The C++ keeps the parameters and the published price in globals (`attestedFeePolicy`,
//! `pqFeeRate`, `maxTxFee`, `g_yellowbackFee`, `g_attestedFeePriceMicroUsd`); here they are a
//! [`FeePolicy`] value and an explicit `price` argument, so every function is pure. The price is
//! the one [`crate::attest::price::attested_fee_price`] publishes: `None` (no index, below the
//! start height, or HALT-1/HALT-3) selects the `-pqfeerate` fallback.

use crate::params::{Amount, MicroUsd, COIN, MAX_MONEY};

/// `DEFAULT_MIN_RELAY_TX_FEE` (ycash6 `main.h:75`), zatoshis per 1,000 bytes: `-pqfeerate`'s
/// default (1x the relay floor, quantum plan §4.5).
pub const DEFAULT_MIN_RELAY_TX_FEE: Amount = 100;
/// `DEFAULT_TRANSACTION_MAXFEE` (ycash6 `main.h:77`): `-maxtxfee`'s default, 0.1 YEC.
pub const DEFAULT_TRANSACTION_MAXFEE: Amount = COIN / 10;
/// `LEGACY_DEFAULT_FEE` (ycash6 `amount.h:38`): the wallet's flat fee floor of a PQ transfer.
pub const LEGACY_DEFAULT_FEE: Amount = 1_000;
/// `VAULT_RPC_FEE` (ycash6 `policy.h:194`): the flat fee of the `vault_*` / `set_*` RPCs, the
/// floor of the vault/Yellowback cap.
pub const VAULT_RPC_FEE: Amount = 10_000;
/// `DEFAULT_PQ_FEE_USD_PER_KB_MICRO` (`-pqfeeusdperkb`): $0.02 per KB.
pub const DEFAULT_PQ_FEE_USD_PER_KB_MICRO: i64 = 20_000;
/// `DEFAULT_YED_FEE_USD_PER_KB_MICRO` (`-yellowbackfeeusdperkb`): $0.05 per KB.
pub const DEFAULT_YED_FEE_USD_PER_KB_MICRO: i64 = 50_000;
/// `DEFAULT_ATTESTED_FEE_FLOOR_PER_KB` (D-Q-23a): with a price, no rate goes below
/// max(this, `-pqfeerate`).
pub const DEFAULT_ATTESTED_FEE_FLOOR_PER_KB: Amount = 5_000;
/// `DEFAULT_YED_MAX_TX_FEE_USD_MICRO` (`-yellowbackmaxtxfeeusd`): $2.
pub const DEFAULT_YED_MAX_TX_FEE_USD_MICRO: i64 = 2_000_000;
/// `DEFAULT_YED_MAX_TX_FEE` (`-yellowbackmaxtxfee`): the cap's absolute ceiling, 10 YEC.
pub const DEFAULT_YED_MAX_TX_FEE: Amount = 10 * COIN;
/// `MIN_YED_MAX_TX_FEE` (ycash6 `policy.h:204`): the least `-yellowbackmaxtxfee` may be.
pub const MIN_YED_MAX_TX_FEE: Amount = 100_000;

/// The largest dollar option ycashd accepts, micro-USD (`init.cpp:1366`: $1,000,000).
pub const MAX_USD_MICRO: i64 = 1_000_000_000_000;

/// The serialized size of a P2PKH-style input the YED builder assumes for a non-PQ input
/// (`YedEstimatedSize`).
pub const NON_PQ_INPUT_SIZE: usize = 150;
/// The bytes `YedEstimatedSize` adds for the rest of the transaction.
pub const ESTIMATED_TX_OVERHEAD: usize = 1_000;
/// `pq::MAX_CHUNK` (= `MAX_SCRIPT_ELEMENT_SIZE`): the largest push of a chunked PQ signature or key.
pub const PQ_MAX_CHUNK: usize = 520;

/// `(signature size without the hash-type byte, public key size)` of the two post-quantum schemes
/// (`pq::SigSize`, `pq::PubKeySize`): 1 = SLH-DSA-SHA2-128s, 2 = FN-DSA-512 (Falcon). kogany-pq
/// holds the same table (checked by `tests/yellowback_fee_tests.rs`).
const PQ_SIZES: [(u8, usize, usize); 2] = [(1, 7856, 32), (2, 666, 897)];

/// `AttestedFeePolicy` (ycash6 `policy.h:184-192`): the dollar targets, the floor and the cap.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AttestedFeePolicy {
    /// `-pqfeeusdperkb`, micro-USD per KB (0 = off: the `-pqfeerate` behaviour).
    pub plain_usd_per_kb_micro: i64,
    /// `-yellowbackfeeusdperkb`, micro-USD per KB (0 = off).
    pub yed_usd_per_kb_micro: i64,
    /// `DEFAULT_ATTESTED_FEE_FLOOR_PER_KB`: with `-pqfeerate`, the floor rate with a price.
    pub floor_zat_per_kb: Amount,
    /// `-yellowbackmaxtxfeeusd`, micro-USD: the cap is max(`-maxtxfee`, this at the price).
    pub yed_max_tx_fee_usd_micro: i64,
    /// `-yellowbackmaxtxfee`, zatoshis: the cap's absolute ceiling (0 = none).
    pub yed_max_tx_fee_zat: Amount,
    /// The least the cap may be: max(`-yellowbackfee`, [`VAULT_RPC_FEE`]), set at init.
    pub min_cap_zat: Amount,
}

impl Default for AttestedFeePolicy {
    /// ycash6's static initialiser (`policy.cpp:476-478`).
    fn default() -> Self {
        AttestedFeePolicy {
            plain_usd_per_kb_micro: DEFAULT_PQ_FEE_USD_PER_KB_MICRO,
            yed_usd_per_kb_micro: DEFAULT_YED_FEE_USD_PER_KB_MICRO,
            floor_zat_per_kb: DEFAULT_ATTESTED_FEE_FLOOR_PER_KB,
            yed_max_tx_fee_usd_micro: DEFAULT_YED_MAX_TX_FEE_USD_MICRO,
            yed_max_tx_fee_zat: DEFAULT_YED_MAX_TX_FEE,
            min_cap_zat: VAULT_RPC_FEE,
        }
    }
}

/// The node's whole network-fee configuration: ycashd's [`AttestedFeePolicy`] plus the globals the
/// functions read beside it (`pqFeeRate`, `maxTxFee`, `g_yellowbackFee`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FeePolicy {
    /// The dollar policy.
    pub attested: AttestedFeePolicy,
    /// `-pqfeerate`, zatoshis per 1,000 bytes: the fallback rate without a price, and a floor
    /// with one (review A-7).
    pub pq_fee_rate: Amount,
    /// `-maxtxfee`, zatoshis.
    pub max_tx_fee: Amount,
    /// `-yellowbackfee`, zatoshis: the YED builder's flat fee (`g_yellowbackFee`).
    pub yellowback_fee: Amount,
}

impl Default for FeePolicy {
    fn default() -> Self {
        FeePolicy {
            attested: AttestedFeePolicy::default(),
            pq_fee_rate: DEFAULT_MIN_RELAY_TX_FEE,
            max_tx_fee: DEFAULT_TRANSACTION_MAXFEE,
            yellowback_fee: crate::params::DEFAULT_YELLOWBACK_FEE,
        }
    }
}

/// The numbers `yed_getinfo.params.fees.network` reports (ycash6 `rpc/yellowback.cpp:768-787`),
/// at one price.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NetworkFeeReport {
    /// `priceMicroUsd` (`None`: `priceSource` is `"fallback"`).
    pub price_micro_usd: Option<MicroUsd>,
    /// `plain.usdPerKBMicro`.
    pub plain_usd_per_kb_micro: i64,
    /// `plain.zatPerKB` (`PlainPQFeeRate().GetFeePerK()`; also `params.pq.feeRateZatPerKB`).
    pub plain_zat_per_kb: Amount,
    /// `yellowback.usdPerKBMicro`.
    pub yed_usd_per_kb_micro: i64,
    /// `yellowback.zatPerKB` (`YedFeeRate().GetFeePerK()`).
    pub yed_zat_per_kb: Amount,
    /// `yellowback.maxTxFeeUsdMicro`.
    pub yed_max_tx_fee_usd_micro: i64,
    /// `yellowback.maxTxFeeCeilingZat` (`-yellowbackmaxtxfee`).
    pub yed_max_tx_fee_ceiling_zat: Amount,
    /// `yellowback.maxTxFeeZat` (`YedMaxTxFee()`).
    pub yed_max_tx_fee_zat: Amount,
    /// `floorZatPerKB` (the policy's floor field, not max(floor, `-pqfeerate`)).
    pub floor_zat_per_kb: Amount,
    /// `fallbackZatPerKB` (`-pqfeerate`).
    pub fallback_zat_per_kb: Amount,
    /// `flatZat` (`g_yellowbackFee`).
    pub flat_zat: Amount,
    /// `maxTxFeeZat` (`-maxtxfee`).
    pub max_tx_fee_zat: Amount,
}

/// `SetAttestedFeePrice` / `AttestedFeePrice`: a price that is not positive is no price.
pub fn normalize_price(price: Option<MicroUsd>) -> Option<MicroUsd> {
    price.filter(|p| *p > 0)
}

/// `AttestedRateZatPerKB(usdPerKBMicro, priceMicroUsd, floorZatPerKB)` (ycash6 `policy.cpp:482-489`):
/// `max(floor, ceil(usdPerKBMicro * COIN / price))`, the quotient capped at `MAX_MONEY`; the
/// floor alone (never below 0) when the target or the price is not positive.
pub fn attested_rate_zat_per_kb(
    usd_per_kb_micro: i64,
    price_micro_usd: MicroUsd,
    floor_zat_per_kb: Amount,
) -> Amount {
    let floor = floor_zat_per_kb.max(0);
    if usd_per_kb_micro <= 0 || price_micro_usd <= 0 {
        return floor;
    }
    // Both factors are positive i64, so the product fits i128 and the sum below cannot wrap.
    let numerator = i128::from(usd_per_kb_micro)
        .saturating_mul(i128::from(COIN))
        .saturating_add(i128::from(price_micro_usd))
        .saturating_sub(1);
    let rate = numerator
        .checked_div(i128::from(price_micro_usd))
        .unwrap_or(i128::MAX);
    let rate = Amount::try_from(rate.min(i128::from(MAX_MONEY))).unwrap_or(MAX_MONEY);
    rate.max(floor)
}

/// `CFeeRate(rate_per_k).GetFee(size)` (ycash6 `amount.cpp:30-38`): `rate * size / 1000`, the
/// rate itself when that rounds to zero and the rate is positive.
pub fn fee_at_rate(rate_per_k: Amount, size: usize) -> Amount {
    let size = i128::try_from(size).unwrap_or(i128::MAX);
    let fee = i128::from(rate_per_k).saturating_mul(size) / 1_000;
    let fee = Amount::try_from(fee).unwrap_or(Amount::MAX);
    if fee == 0 && rate_per_k > 0 {
        rate_per_k
    } else {
        fee
    }
}

/// `PQSpendInputSize(scheme)` (ycash6 `policy.cpp:372-388`): the serialized size of the input that
/// spends a TX_PQPKH output of `scheme` (outpoint, sequence, the compact size and the chunked
/// `<sig chunks> <s> <pk chunks> <p>` scriptSig); `None` for an unknown scheme (the C++ 0).
pub fn pq_spend_input_size(scheme: u8) -> Option<usize> {
    let (_, sig, pk) = PQ_SIZES.iter().find(|(s, _, _)| *s == scheme)?;
    Some(pq_spend_input_size_for(sig.saturating_add(1), *pk))
}

/// [`pq_spend_input_size`] for a signature of `sig_len` bytes (with its hash-type byte) and a key
/// of `pk_len` bytes.
pub fn pq_spend_input_size_for(sig_len: usize, pk_len: usize) -> usize {
    let chunked = |mut left: usize| {
        let mut bytes = 0usize;
        while left > 0 {
            let c = left.min(PQ_MAX_CHUNK);
            let push = if c < 0x4c {
                1
            } else if c <= 0xff {
                2
            } else {
                3
            };
            bytes = bytes.saturating_add(c).saturating_add(push);
            left = left.saturating_sub(c);
        }
        bytes
    };
    // <s> <p> as OP_n
    let ss = chunked(sig_len)
        .saturating_add(chunked(pk_len))
        .saturating_add(2);
    // outpoint (36) + nSequence (4) + the scriptSig's compact size (3 above 252 bytes, else 1)
    let compact = if ss > 252 { 3 } else { 1 };
    40usize.saturating_add(compact).saturating_add(ss)
}

/// `YedEstimatedSize` (ycash6 `txbuilder.cpp:48-62`): every PQ input (its scheme in
/// `pq_schemes`: a TX_PQPKH among the inputs, or the V's owner) at [`pq_spend_input_size`], every
/// other input at [`NON_PQ_INPUT_SIZE`], [`ESTIMATED_TX_OVERHEAD`] for the rest. An unknown scheme
/// counts 0, as the C++ does.
pub fn yed_estimated_size(pq_schemes: &[u8], other_inputs: usize) -> usize {
    pq_schemes.iter().fold(
        ESTIMATED_TX_OVERHEAD.saturating_add(NON_PQ_INPUT_SIZE.saturating_mul(other_inputs)),
        |bytes, scheme| bytes.saturating_add(pq_spend_input_size(*scheme).unwrap_or(0)),
    )
}

impl FeePolicy {
    /// `AttestedFeeFloorPerKB` (review A-7): max(`floorZatPerKB`, `-pqfeerate`).
    pub fn attested_fee_floor_per_kb(&self) -> Amount {
        self.attested.floor_zat_per_kb.max(self.pq_fee_rate)
    }

    /// `PlainPQFeeRate().GetFeePerK()`: the rate of a transaction with a PQ input, zat/KB.
    pub fn plain_pq_fee_rate(&self, price: Option<MicroUsd>) -> Amount {
        self.rate(self.attested.plain_usd_per_kb_micro, price)
    }

    /// `YedFeeRate().GetFeePerK()`: the rate of a vault or Yellowback transaction, zat/KB.
    pub fn yed_fee_rate(&self, price: Option<MicroUsd>) -> Amount {
        self.rate(self.attested.yed_usd_per_kb_micro, price)
    }

    fn rate(&self, usd_per_kb_micro: i64, price: Option<MicroUsd>) -> Amount {
        match normalize_price(price) {
            Some(price) if usd_per_kb_micro > 0 => {
                attested_rate_zat_per_kb(usd_per_kb_micro, price, self.attested_fee_floor_per_kb())
            }
            // the fallback
            _ => self.pq_fee_rate,
        }
    }

    /// `YedMaxTxFee()` (D-Q-23a, review M-1): min(max(`-maxtxfee`, `yedMaxTxFeeUsdMicro` at the
    /// price), `-yellowbackmaxtxfee`), never below `minCapZat`.
    pub fn yed_max_tx_fee(&self, price: Option<MicroUsd>) -> Amount {
        let p = &self.attested;
        let mut cap = self.max_tx_fee;
        if let Some(price) = normalize_price(price) {
            if p.yed_max_tx_fee_usd_micro > 0 {
                cap = cap.max(attested_rate_zat_per_kb(
                    p.yed_max_tx_fee_usd_micro,
                    price,
                    0,
                ));
            }
        }
        if p.yed_max_tx_fee_zat > 0 {
            cap = cap.min(p.yed_max_tx_fee_zat);
        }
        cap.max(p.min_cap_zat)
    }

    /// `PQMaxTxFee()` (owner D-Q-26): plain PQ transfers share the Yellowback cap.
    pub fn pq_max_tx_fee(&self, price: Option<MicroUsd>) -> Amount {
        self.yed_max_tx_fee(price)
    }

    /// `PQSizeFee(floor, nBytes)`: max(floor, the plain PQ rate x size).
    pub fn pq_size_fee(&self, price: Option<MicroUsd>, floor: Amount, n_bytes: usize) -> Amount {
        floor.max(fee_at_rate(self.plain_pq_fee_rate(price), n_bytes))
    }

    /// `YedSizeFee(floor, nBytes)`: max(floor, the Yellowback rate x size).
    pub fn yed_size_fee(&self, price: Option<MicroUsd>, floor: Amount, n_bytes: usize) -> Amount {
        floor.max(fee_at_rate(self.yed_fee_rate(price), n_bytes))
    }

    /// `YedFloorSizeFee(flat, nBytes)` (review L-1's owner clamp): max(flat, the floor rate x
    /// size) with a price, max(flat, `-pqfeerate` x size) without one.
    pub fn yed_floor_size_fee(
        &self,
        price: Option<MicroUsd>,
        flat: Amount,
        n_bytes: usize,
    ) -> Amount {
        let rate = if normalize_price(price).is_some() {
            self.attested_fee_floor_per_kb()
        } else {
            self.pq_fee_rate
        };
        flat.max(fee_at_rate(rate, n_bytes))
    }

    /// `YedNetworkFee` (ycash6 `txbuilder.cpp:72-76`) for a transaction of `estimated_size` bytes
    /// ([`yed_estimated_size`]): max(`-yellowbackfee`, min(`YedSizeFee(-yellowbackfee, size)`,
    /// `YedMaxTxFee()`)): capped, never refused, never below the flat fee.
    pub fn yed_network_fee(&self, price: Option<MicroUsd>, estimated_size: usize) -> Amount {
        let flat = self.yellowback_fee;
        flat.max(
            self.yed_size_fee(price, flat, estimated_size)
                .min(self.yed_max_tx_fee(price)),
        )
    }

    /// The `yed_getinfo.params.fees.network` numbers at `price`.
    pub fn network_fee_report(&self, price: Option<MicroUsd>) -> NetworkFeeReport {
        let price = normalize_price(price);
        NetworkFeeReport {
            price_micro_usd: price,
            plain_usd_per_kb_micro: self.attested.plain_usd_per_kb_micro,
            plain_zat_per_kb: self.plain_pq_fee_rate(price),
            yed_usd_per_kb_micro: self.attested.yed_usd_per_kb_micro,
            yed_zat_per_kb: self.yed_fee_rate(price),
            yed_max_tx_fee_usd_micro: self.attested.yed_max_tx_fee_usd_micro,
            yed_max_tx_fee_ceiling_zat: self.attested.yed_max_tx_fee_zat,
            yed_max_tx_fee_zat: self.yed_max_tx_fee(price),
            floor_zat_per_kb: self.attested.floor_zat_per_kb,
            fallback_zat_per_kb: self.pq_fee_rate,
            flat_zat: self.yellowback_fee,
            max_tx_fee_zat: self.max_tx_fee,
        }
    }

    /// ycashd's init checks (`init.cpp:1346-1379, 1639-1650`) of a configured policy, after
    /// `min_cap_zat` is set from the flat fees ([`FeePolicy::with_min_cap`]): `Err` with the
    /// message ycashd's `InitError` gives.
    pub fn validate(&self) -> Result<(), String> {
        if self.pq_fee_rate <= 0 || self.pq_fee_rate > MAX_MONEY {
            return Err("Invalid amount for -pqfeerate: it must be positive".to_owned());
        }
        for (name, v) in [
            ("-pqfeeusdperkb", self.attested.plain_usd_per_kb_micro),
            ("-yellowbackfeeusdperkb", self.attested.yed_usd_per_kb_micro),
            (
                "-yellowbackmaxtxfeeusd",
                self.attested.yed_max_tx_fee_usd_micro,
            ),
        ] {
            if !(0..=MAX_USD_MICRO).contains(&v) {
                return Err(format!("Invalid amount for {name}=<usd>: {v} micro-USD"));
            }
        }
        if self.attested.yed_max_tx_fee_zat <= 0 || self.attested.yed_max_tx_fee_zat > MAX_MONEY {
            return Err("Invalid amount for -yellowbackmaxtxfee".to_owned());
        }
        if self.attested.yed_max_tx_fee_zat < MIN_YED_MAX_TX_FEE {
            return Err(
                "-yellowbackmaxtxfee must be at least 0.001, above the fees the wallet must pay"
                    .to_owned(),
            );
        }
        if self.max_tx_fee < 0 || self.max_tx_fee > MAX_MONEY {
            return Err("Invalid amount for -maxtxfee".to_owned());
        }
        if self.yellowback_fee < crate::params::DEFAULT_YELLOWBACK_FEE {
            return Err(format!(
                "-yellowbackfee must be at least {} zatoshi.",
                crate::params::DEFAULT_YELLOWBACK_FEE
            ));
        }
        if self.attested.yed_max_tx_fee_zat < self.attested.min_cap_zat {
            return Err(
                "-yellowbackmaxtxfee must be at least max(-yellowbackfee, 0.0001)".to_owned(),
            );
        }
        Ok(())
    }

    /// `minCapZat = max(-yellowbackfee, VAULT_RPC_FEE)` (ycash6 `init.cpp:1644`).
    pub fn with_min_cap(mut self) -> Self {
        self.attested.min_cap_zat = self.yellowback_fee.max(VAULT_RPC_FEE);
        self
    }
}
