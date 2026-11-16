//! The Sapling output prover of a Ycash node's coinbase (beta3 item 3).
//!
//! Copyright (c) 2026 The Ycash developers. Distributed under the MIT software license.
//!
//! ycashd pays a Sapling miner address with one Sapling output in the coinbase
//! (`ycash6 src/miner.cpp` `AddOutputsToCoinbaseTxAndSign`), proved with the Sapling output
//! parameters it loads at start. Zakura links the Sapling verifying keys only and its coinbase
//! builder is given a prover that cannot prove ([`super::no_sapling`]). A Ycash node reads the
//! same `sapling-output.params` file ycashd uses, once, at start; without it every coinbase that
//! needs a Sapling output is refused with [`NOT_LOADED`], and nothing else changes.

use std::{
    io,
    path::PathBuf,
    sync::{Arc, OnceLock},
};

use sapling_crypto::{
    builder::{BundleType, InProgress, Proven, Unsigned},
    circuit::OutputParameters,
    keys::OutgoingViewingKey,
    value::NoteValue,
    Anchor, Bundle, PaymentAddress,
};
use zakura_chain::{block::Height, parameters::Network};
use zcash_primitives::transaction::components::sapling::zip212_enforcement;
use zcash_protocol::{consensus::BlockHeight, memo::MemoBytes};

use super::no_sapling::NoSaplingProver;

/// The file name of the Sapling output parameters, as ycashd and `fetch-params` name it.
pub const SAPLING_OUTPUT_PARAMS_FILE: &str = "sapling-output.params";

/// The size of the Sapling output parameters file in bytes.
pub const SAPLING_OUTPUT_PARAMS_BYTES: u64 = 3_592_860;

/// The SHA-256 of the Sapling output parameters file, in hex (`ycash6 zcutil/fetch-params.sh`;
/// the file of the project's `zcash-params-v1` release).
pub const SAPLING_OUTPUT_PARAMS_SHA256: &str =
    "2f0ebbcbb9bb0bcffe95a397e7eba89c29eb4dde6191c339db88570e3f3fb0e4";

/// Why a coinbase with a Sapling output cannot be built on a node without the parameters.
pub const NOT_LOADED: &str = "Sapling output parameters are not loaded";

/// The directory ycashd reads the Zcash parameters from (`ZC_GetParamsDir`, `ycash6
/// src/util/system.cpp`): `~/Library/Application Support/ZcashParams` on macOS,
/// `%APPDATA%\ZcashParams` on Windows, `~/.zcash-params` elsewhere. `None` without a home
/// directory.
pub fn default_params_dir() -> Option<PathBuf> {
    if cfg!(target_os = "windows") {
        return std::env::var_os("APPDATA")
            .map(|appdata| PathBuf::from(appdata).join("ZcashParams"));
    }
    let home = std::env::home_dir()?;
    Some(if cfg!(target_os = "macos") {
        home.join("Library/Application Support/ZcashParams")
    } else {
        home.join(".zcash-params")
    })
}

/// The Sapling output parameters, ready to prove the output of a coinbase.
#[derive(Clone)]
pub struct SaplingOutputProver(Arc<OutputParameters>);

impl std::fmt::Debug for SaplingOutputProver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SaplingOutputProver")
    }
}

impl SaplingOutputProver {
    /// Reads the parameters from the bytes of `sapling-output.params`.
    ///
    /// The caller has checked that `bytes` hash to [`SAPLING_OUTPUT_PARAMS_SHA256`]: the point
    /// encodings are not verified again here (as `OutputParameters::read` allows for a file
    /// whose hash is pinned).
    pub fn from_verified_bytes(bytes: &[u8]) -> io::Result<Self> {
        OutputParameters::read(bytes, false).map(|params| Self(Arc::new(params)))
    }

    /// The parameters.
    pub fn parameters(&self) -> &OutputParameters {
        &self.0
    }
}

static INSTALLED: OnceLock<SaplingOutputProver> = OnceLock::new();

/// Gives this process its Sapling output prover. `zakurad` calls it once at start, after the
/// hash check; the first call wins.
pub fn install_output_prover(prover: SaplingOutputProver) {
    let _ = INSTALLED.set(prover);
}

/// The prover [`install_output_prover`] installed, `None` on a node without the parameters.
pub fn installed_output_prover() -> Option<SaplingOutputProver> {
    INSTALLED.get().cloned()
}

/// A Sapling bundle of one proved output and no spend, not yet signed.
pub(crate) type ProvenCoinbaseBundle = Bundle<InProgress<Proven, Unsigned>, i64>;

/// The Sapling part of a coinbase at `height` that pays `value` zatoshi to `to`: one output with
/// an empty memo, encrypted to the all-zero outgoing viewing key as consensus requires of a
/// coinbase from Heartwood on (ZIP 213), proved, and no spend. The binding signature is added by
/// the caller once the transaction's signature hash is known.
///
/// This makes a zero-knowledge proof: call it off the async worker threads.
pub(crate) fn prove_coinbase_output(
    network: &Network,
    height: Height,
    prover: &SaplingOutputProver,
    to: PaymentAddress,
    value: u64,
) -> Result<ProvenCoinbaseBundle, String> {
    let mut rng = rand_10::rng();
    let mut builder = sapling_crypto::builder::Builder::new(
        zip212_enforcement(network, BlockHeight::from(height)),
        BundleType::Coinbase,
        Anchor::empty_tree(),
    );
    builder
        .add_output(
            Some(OutgoingViewingKey([0u8; 32])),
            to,
            NoteValue::from_raw(value),
            MemoBytes::empty().into_bytes(),
        )
        .map_err(|error| format!("Sapling output: {error}"))?;
    let (bundle, _) = builder
        .build_coinbase::<NoSaplingProver, OutputParameters, _, i64>(&mut rng)
        .map_err(|error| format!("Sapling bundle: {error}"))?
        .ok_or_else(|| "Sapling bundle: no output".to_string())?;
    Ok(bundle.create_proofs(&NoSaplingProver, prover.parameters(), &mut rng, ()))
}
