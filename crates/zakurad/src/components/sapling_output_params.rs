//! Loads the Sapling output parameters a Ycash node proves a Sapling coinbase with (beta3
//! item 3).
//!
//! Copyright (c) 2026 The Ycash developers. Distributed under the MIT software license.
//!
//! The file is ycashd's `sapling-output.params`, read from `mining.sapling_output_params` or
//! from ycashd's parameter directory. It is read once, at start, and must have the pinned size
//! and SHA-256. A node without it runs as before and refuses only a coinbase that needs a
//! Sapling output (`getcoinbasetemplatefor` for a Sapling address, `getblocktemplate` with a
//! Sapling miner address).

use std::path::Path;

use sha2::{Digest, Sha256};
use zakura_rpc::ycash_sapling_coinbase::{
    install_output_prover, SaplingOutputProver, SAPLING_OUTPUT_PARAMS_BYTES,
    SAPLING_OUTPUT_PARAMS_SHA256,
};

/// Why the Sapling output parameters were not loaded.
#[derive(Debug, thiserror::Error)]
pub enum LoadError {
    /// There is no file at the path.
    #[error("no file")]
    Absent,
    /// The file could not be read.
    #[error("cannot read the file: {0}")]
    Io(#[from] std::io::Error),
    /// The file is not the pinned one.
    #[error("the file is {0} bytes, expected {SAPLING_OUTPUT_PARAMS_BYTES}")]
    Size(u64),
    /// The file is not the pinned one.
    #[error("the file's SHA-256 is {0}, expected {SAPLING_OUTPUT_PARAMS_SHA256}")]
    Hash(String),
    /// The file has the pinned hash and does not parse.
    #[error("the parameters do not parse: {0}")]
    Parse(std::io::Error),
}

/// Reads the Sapling output parameters at `path`, checking their size and SHA-256.
pub fn load(path: &Path) -> Result<SaplingOutputProver, LoadError> {
    let size = match std::fs::metadata(path) {
        Ok(metadata) => metadata.len(),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(LoadError::Absent)
        }
        Err(error) => return Err(error.into()),
    };
    if size != SAPLING_OUTPUT_PARAMS_BYTES {
        return Err(LoadError::Size(size));
    }
    let bytes = std::fs::read(path)?;
    let hash = hex::encode(Sha256::digest(&bytes));
    if hash != SAPLING_OUTPUT_PARAMS_SHA256 {
        return Err(LoadError::Hash(hash));
    }
    SaplingOutputProver::from_verified_bytes(&bytes).map_err(LoadError::Parse)
}

/// Loads the parameters `mining` names and gives them to the RPC methods, or logs why this node
/// cannot build a Sapling coinbase. Never fails the start.
pub fn install(mining: &zakura_rpc::config::mining::Config) {
    let Some(path) = mining.sapling_output_params_path() else {
        tracing::info!(
            "no Sapling output parameters: no mining.sapling_output_params and no home \
             directory; this node cannot build a coinbase that pays a Sapling address"
        );
        return;
    };
    match load(&path) {
        Ok(prover) => {
            install_output_prover(prover);
            tracing::info!(?path, "loaded the Sapling output parameters");
        }
        Err(LoadError::Absent) => tracing::info!(
            ?path,
            "no Sapling output parameters at this path: this node cannot build a coinbase \
             that pays a Sapling address (getcoinbasetemplatefor answers \"Sapling output \
             parameters are not loaded\"); set mining.sapling_output_params or install \
             sapling-output.params there"
        ),
        Err(error) => tracing::warn!(
            ?path,
            %error,
            "the Sapling output parameters were not loaded: this node cannot build a \
             coinbase that pays a Sapling address"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A missing file, a file of another size and a file of the right size with other bytes are
    /// each refused with their reason; ycashd's own file loads when the test machine has it.
    #[test]
    // The note of a skipped part must reach the test log.
    #[allow(clippy::print_stderr)]
    fn only_the_pinned_file_loads() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let path = dir.path().join("sapling-output.params");
        assert!(matches!(load(&path), Err(LoadError::Absent)));

        std::fs::write(&path, b"short").expect("writes");
        assert!(matches!(load(&path), Err(LoadError::Size(5))));

        let zeros = vec![0u8; usize::try_from(SAPLING_OUTPUT_PARAMS_BYTES).expect("fits")];
        std::fs::write(&path, zeros).expect("writes");
        assert!(matches!(load(&path), Err(LoadError::Hash(_))));

        // The same file the zakura-rpc tests prove with: `KOGANY_SAPLING_OUTPUT_PARAMS`, or
        // ycashd's parameter directory.
        let real = std::env::var_os("KOGANY_SAPLING_OUTPUT_PARAMS")
            .map(std::path::PathBuf::from)
            .or_else(|| zakura_rpc::config::mining::Config::default().sapling_output_params_path())
            .filter(|path| path.exists());
        match real {
            Some(real) => {
                load(&real).expect("ycashd's parameters load");
            }
            None => {
                assert!(
                    std::env::var("KOGANY_REQUIRE_SAPLING_PARAMS").as_deref() != Ok("1"),
                    "KOGANY_REQUIRE_SAPLING_PARAMS=1 and no sapling-output.params"
                );
                eprintln!("SKIPPED: no sapling-output.params on this machine");
            }
        }
    }
}
