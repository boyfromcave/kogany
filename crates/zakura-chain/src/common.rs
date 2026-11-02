//! Common functions used in Zebra.

use std::{
    ffi::OsString,
    fs,
    io::{self, Write},
    path::PathBuf,
};

mod directories;
mod temp;

use directories::cache_dir;
pub use directories::{home_dir, preference_dir};
pub use temp::{TempDir, TempFile};

/// The name of the node's directory in the platform cache directory: `zakura`.
#[cfg(not(feature = "ycash"))]
pub const CACHE_DIR_NAME: &str = "zakura";

/// The name of the node's directory in the platform cache directory: kogany's own, so a kogany
/// node and a Zcash `zakurad` on one host never share a state database, a peer cache or an RPC
/// cookie ([`crate::parameters::ycash::dirs`]).
#[cfg(feature = "ycash")]
pub const CACHE_DIR_NAME: &str = crate::parameters::ycash::dirs::CACHE_DIR_NAME;

/// Returns Zakura's default cache directory path.
///
/// kogany: `<platform cache directory>/kogany` in a `ycash` build ([`CACHE_DIR_NAME`]).
pub fn default_cache_dir() -> PathBuf {
    cache_dir()
        .unwrap_or_else(|| std::env::current_dir().unwrap().join("cache"))
        .join(CACHE_DIR_NAME)
}

/// Accepts a target file path and a byte-slice.
///
/// Atomically writes the byte-slice to a file to avoid corrupting the file if Zebra
/// panics, crashes, or exits while the file is being written, or if multiple Zebra instances
/// try to read and write the same file.
///
/// Returns the provided file path if successful. The outer error means the data
/// could not be written; the inner error means it could not be moved to `file_path`.
///
/// # Concurrency
///
/// This function blocks on filesystem operations and should be called in a blocking task
/// when calling from an async environment.
///
/// # Panics
///
/// If the provided `file_path` is a directory path.
pub fn atomic_write(file_path: PathBuf, data: &[u8]) -> io::Result<io::Result<PathBuf>> {
    // Get the file's parent directory, or use Zebra's default cache directory
    let file_dir = file_path
        .parent()
        .map(|p| p.to_owned())
        .unwrap_or_else(default_cache_dir);

    // Create the directory if needed.
    fs::create_dir_all(&file_dir)?;

    // Give the temporary file a similar name to the permanent file,
    // but hide it in directory listings.
    let mut tmp_file_prefix: OsString = ".tmp.".into();
    tmp_file_prefix.push(
        file_path
            .file_name()
            .expect("file path must have a file name"),
    );
    tmp_file_prefix.push(".");

    // Create the temporary file in the same directory as the permanent file,
    // so atomic filesystem operations are possible.
    let mut tmp_file = TempFile::new_in(&file_dir, &tmp_file_prefix)?;

    tmp_file.as_file_mut().write_all(data)?;
    tmp_file.as_file().sync_all()?;

    // Atomically write the temp file to `file_path`.
    let persist_result = tmp_file
        .persist(&file_path)
        // Drops the temp file and returns the file path.
        .map(|_| file_path);

    #[cfg(unix)]
    if persist_result.is_ok() {
        fs::File::open(file_dir)?.sync_all()?;
    }

    Ok(persist_result)
}
