//! The `zakurad` process lifecycle.
//!
//! This is the code that starts `zakurad`, and launches its tasks and services.
//! See [the crate docs](crate) and [the start docs](crate::commands::start) for more details.

use std::{
    env,
    fmt::Write as _,
    process,
    sync::{Arc, LazyLock, OnceLock},
};

use clap::Parser;
use eyre::{eyre, Report};
use semver::{BuildMetadata, Version};
use tokio::sync::watch;

use zakura_state::{state_database_format_version_in_code, state_database_format_version_on_disk};

use crate::{
    commands::EntryPoint,
    components::{metrics, tracing::Tracing},
    config::ZakuradConfig,
};

/// The node binary's name in user-facing messages: `koganyd` in the Ycash build, `zakurad`
/// upstream.
pub const NODE_NAME: &str = if cfg!(feature = "ycash") {
    "koganyd"
} else {
    "zakurad"
};

/// The node's product name in user-facing messages: `kogany` in the Ycash build, `Zakura`
/// upstream.
pub const PRODUCT_NAME: &str = if cfg!(feature = "ycash") {
    "kogany"
} else {
    "Zakura"
};

/// The package-style lowercase name used in metric names and fatal errors: `kogany` in the
/// Ycash build, `zakura` upstream (the package is `kogany`; upstream's `zakurad` keeps the
/// `zakura` names its dashboards and tests expect).
pub const PACKAGE_NAME: &str = if cfg!(feature = "ycash") {
    "kogany"
} else {
    "zakura"
};

/// The last log event that occurred in the application.
pub static LAST_WARN_ERROR_LOG_SENDER: LazyLock<
    watch::Sender<Option<(String, tracing::Level, chrono::DateTime<chrono::Utc>)>>,
> = LazyLock::new(|| watch::Sender::new(None));

/// Returns the `zakurad` version for this build, in SemVer 2.0 format.
///
/// Includes build metadata identifying the source commit when available:
/// - the number of commits since the last version tag, and
/// - the git commit.
///
/// For details, see <https://semver.org/>
///
/// kogany: the Ycash build (`koganyd`) uses kogany's scheme instead, see
/// [`kogany_build_metadata`]: the package version (the Zakura line kogany tracks) plus
/// `+kogany.<n>.g<sha>`, `<n>` counted from the `kogany-ycash-baseline` tag.
#[cfg_attr(feature = "ycash", allow(unreachable_code))]
pub fn build_version() -> Version {
    // CARGO_PKG_VERSION is always a valid SemVer 2.0 version.
    const CARGO_PKG_VERSION: &str = env!("CARGO_PKG_VERSION");

    // We're using the same library as cargo uses internally, so this is guaranteed.
    let fallback_version: Version = CARGO_PKG_VERSION.parse().unwrap_or_else(|error| {
        panic!(
            "unexpected invalid CARGO_PKG_VERSION: {error:?} in {CARGO_PKG_VERSION:?}, \
             should have been checked by cargo"
        )
    });

    // kogany: never an upstream `v*` tag's version; the version core is always the package's.
    #[cfg(feature = "ycash")]
    {
        let mut version = fallback_version;
        version.build = kogany_build_metadata(option_env!("KOGANY_GIT_DESCRIBE"), git_commit());
        return version;
    }

    let mut version = vergen_build_version().unwrap_or(fallback_version);

    // Docker builds do not include `.git`, so use the explicitly supplied
    // commit when `git describe` could not add build metadata.
    if version.build == BuildMetadata::EMPTY {
        if let Some(git_commit) = git_commit() {
            let short_commit: String = git_commit.chars().take(12).collect();
            if let Ok(build) = BuildMetadata::new(&format!("g{short_commit}")) {
                version.build = build;
            }
        }
    }

    version
}

/// Returns the build version in the static form required by `clap`.
pub fn clap_build_version() -> &'static str {
    static BUILD_VERSION: OnceLock<String> = OnceLock::new();

    BUILD_VERSION
        .get_or_init(|| build_version().to_string())
        .as_str()
}

/// Returns the `zakurad` version from this build, if available from `vergen`.
fn vergen_build_version() -> Option<Version> {
    // VERGEN_GIT_DESCRIBE should be in the format:
    // - v1.0.0-rc.9-6-g319b01bb84
    // - v1.0.0-6-g319b01bb84
    // but sometimes it is just a short commit hash. See #6879 for details.
    //
    // Currently it is the output of `git describe --tags --dirty --match='v*.*.*'`,
    // or whatever is specified in zakurad/build.rs.
    const VERGEN_GIT_DESCRIBE: Option<&str> = option_env!("VERGEN_GIT_DESCRIBE");

    // The SemVer 2.0 format is:
    // - 1.0.0-rc.9+6.g319b01bb84
    // - 1.0.0+6.g319b01bb84
    //
    // Or as a pattern:
    // - version: major`.`minor`.`patch
    // - optional pre-release: `-`tag[`.`tag ...]
    // - optional build: `+`tag[`.`tag ...]
    // change the git describe format to the semver 2.0 format
    let vergen_git_describe = VERGEN_GIT_DESCRIBE?;

    // `git describe` uses "dirty" for uncommitted changes,
    // but users won't understand what that means.
    let vergen_git_describe = vergen_git_describe.replace("dirty", "modified");

    // Split using "git describe" separators.
    let mut vergen_git_describe = vergen_git_describe.split('-').peekable();

    // Check the "version core" part.
    let mut version = vergen_git_describe.next()?;

    // strip the leading "v", if present.
    version = version.strip_prefix('v').unwrap_or(version);

    // If the initial version is empty, just a commit hash, or otherwise invalid.
    if Version::parse(version).is_err() {
        return None;
    }

    let mut semver = version.to_string();

    // Check if the next part is a pre-release or build part,
    // but only consume it if it is a pre-release tag.
    let Some(part) = vergen_git_describe.peek() else {
        // No pre-release or build.
        return semver.parse().ok();
    };

    if part.starts_with(char::is_alphabetic) {
        // It's a pre-release tag.
        semver.push('-');
        semver.push_str(part);

        // Consume the pre-release tag to move on to the build tags, if any.
        let _ = vergen_git_describe.next();
    }

    // Check if the next part is a build part.
    let Some(build) = vergen_git_describe.peek() else {
        // No build tags.
        return semver.parse().ok();
    };

    if !build.starts_with(char::is_numeric) {
        // It's not a valid "commit count" build tag from "git describe".
        return None;
    }

    // Append the rest of the build parts with the correct `+` and `.` separators.
    let build_parts: Vec<_> = vergen_git_describe.collect();
    let build_parts = build_parts.join(".");

    semver.push('+');
    semver.push_str(&build_parts);

    semver.parse().ok()
}

/// kogany: the build metadata of `koganyd`'s version, `kogany.<n>.g<sha>`.
///
/// `describe` is `git describe --tags --match kogany-ycash-baseline --long --abbrev=12` (with
/// `-dirty` appended for uncommitted changes, shown as `.modified`), so `<n>` is the number of
/// commits since kogany's baseline tag, never since an upstream Zakura `v*` tag. Without it (a
/// Docker or source-archive build has no `.git`), the supplied `commit` gives `kogany.g<sha>`; with
/// neither, the metadata is just `kogany`.
#[cfg(feature = "ycash")]
pub fn kogany_build_metadata(describe: Option<&str>, commit: Option<&str>) -> BuildMetadata {
    const PREFIX: &str = "kogany-ycash-baseline-";

    let from_describe = describe.and_then(|describe| {
        let rest = describe.strip_prefix(PREFIX)?;
        let mut parts = rest.split('-');
        let count = parts.next()?;
        let sha = parts.next()?;
        let modified = match parts.next() {
            None => false,
            Some("dirty") => true,
            Some(_) => return None,
        };
        if parts.next().is_some()
            || count.is_empty()
            || !count.bytes().all(|b| b.is_ascii_digit())
            || !sha.starts_with('g')
        {
            return None;
        }
        // SemVer build identifiers may have leading zeros, but `git describe` never prints them.
        let mut build = format!("kogany.{count}.{sha}");
        if modified {
            build.push_str(".modified");
        }
        BuildMetadata::new(&build).ok()
    });

    from_describe
        .or_else(|| {
            let short_commit: String = commit?.chars().take(12).collect();
            BuildMetadata::new(&format!("kogany.g{short_commit}")).ok()
        })
        .unwrap_or_else(|| BuildMetadata::new("kogany").expect("valid build metadata"))
}

/// Returns the git commit for this build, if available.
///
/// # Accuracy
///
/// If the user makes changes, but does not commit them, the git commit will
/// not match the compiled source code.
pub fn git_commit() -> Option<&'static str> {
    const GIT_COMMIT_GCLOUD: Option<&str> = option_env!("SHORT_SHA");
    const GIT_COMMIT_VERGEN: Option<&str> = option_env!("VERGEN_GIT_SHA");

    GIT_COMMIT_GCLOUD.or(GIT_COMMIT_VERGEN)
}

/// The Zebra current release version, without any build metadata.
pub fn release_version() -> Version {
    let mut release_version = build_version();

    release_version.build = BuildMetadata::EMPTY;

    release_version
}

/// The User-Agent string provided by the node.
///
/// This must be a valid [BIP 14] user agent.
///
/// kogany: `/koganyd:<package version>/`, without the `+kogany.<n>.g<sha>` build metadata:
/// ycashd keeps only `[A-Za-z0-9 .-/:]` of a peer's subversion (`SAFE_CHARS_SUBVERSION`,
/// `ycash6 src/util/strencodings.cpp:25`, applied at `src/main.cpp:8020`), so a `+` would be
/// dropped and the version run together.
///
/// [BIP 14]: https://github.com/bitcoin/bips/blob/master/bip-0014.mediawiki
#[cfg_attr(feature = "ycash", allow(unreachable_code))]
pub fn user_agent() -> String {
    let release_version = release_version();
    // kogany: `/koganyd:<version>/` on Ycash (`zakura_network::ycash::user_agent`).
    #[cfg(feature = "ycash")]
    return zakura_network::ycash::user_agent(release_version);

    format!("/Zakura:{release_version}/")
}

/// Runs `zakurad` with the process's command-line arguments, then exits the process.
///
/// Invalid arguments, `--help` and `--version` exit with the argument parser's status.
/// Startup errors are printed to stderr and exit with status 1. Otherwise the command
/// runs, its logs are flushed, and the process exits with status 0 if the command
/// succeeded, or 1 if it failed.
///
/// A panic unwinds through [`run`], which drops the log writer and flushes its logs.
pub fn boot() -> ! {
    let args =
        EntryPoint::process_cli_args(env::args_os().collect()).unwrap_or_else(|err| err.exit());
    let command = EntryPoint::try_parse_from(args).unwrap_or_else(|err| err.exit());

    let status = run(&command);

    process::exit(status)
}

/// Sets up `zakurad` for `command`, runs it, and returns the process exit status.
///
/// Commands report their own errors, so a failed command only changes the status.
/// The log writer is dropped before this returns, including while a panic unwinds,
/// so the logs written while the command stops are flushed.
fn run(command: &EntryPoint) -> i32 {
    let (config, _tracing) = match start(command) {
        Ok(started) => started,
        Err(error) => {
            report_fatal_error(&error);
            return 1;
        }
    };

    match command.cmd().run(config) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

/// Prints an error that stopped `zakurad` from starting.
#[allow(clippy::print_stderr)]
fn report_fatal_error(error: &Report) {
    eprintln!("error: {PACKAGE_NAME} fatal error: {error}");
}

/// Installs a panic hook that prints the default panic report, followed by the
/// diagnostic metadata that bug reports need.
fn install_panic_hook(metadata_section: String) {
    let default_hook = std::panic::take_hook();

    #[allow(clippy::print_stderr)]
    std::panic::set_hook(Box::new(move |info| {
        default_hook(info);
        eprintln!("\n{metadata_section}");
    }));
}

/// Loads the configuration for `command`, then sets up error reporting, the Rayon
/// thread pool and tracing. Server commands also get the metrics endpoint.
///
/// The order matches what earlier releases did, so a config error is reported before
/// anything else is set up, and later setup steps are logged. The one change is that
/// `start` now builds its async runtime after the metrics endpoint opens, which logs
/// nothing.
#[allow(clippy::print_stderr, clippy::unwrap_in_result)]
fn start(command: &EntryPoint) -> Result<(Arc<ZakuradConfig>, Tracing), Report> {
    let config = match ZakuradConfig::load(command.config_path()) {
        Ok(config) => config,
        // Ignore errors loading the config for some commands.
        Err(_e) if command.cmd().should_ignore_load_config_error() => Default::default(),
        Err(e) => {
            // The line break and the indentation after it are part of the message that
            // `zakurad` has always printed.
            eprintln!(
                "error: {PRODUCT_NAME} could not load the provided configuration file and/or environment variables.\
                 This might mean you are using a deprecated format of the file, or are attempting to
                     configure deprecated or unknown fields via environment variables.\
                 You can generate a valid config by running \"{NODE_NAME} generate\", \
                 and diff it against yours to examine any format inconsistencies."
            );
            return Err(eyre!("I/O operation failed: Configuration error: {e}"));
        }
    };

    let config = command.process_config(config)?;

    // collect the common metadata for the panic report,
    // skipping any env vars that aren't present

    // reads state disk version file, doesn't open RocksDB database
    let disk_db_version = match state_database_format_version_on_disk(
        &config.mirrored_state_config(),
        &config.network.network,
    ) {
        Ok(Some(version)) => version.to_string(),
        // This "version" is specially formatted to match a relaxed version regex in CI
        Ok(None) => "creating.new.database".to_string(),
        Err(error) => {
            let mut error = format!("error: {error:?}");
            error.truncate(100);
            error
        }
    };

    let app_metadata = [
        // build-time constant: cargo or git tag + short commit
        ("version", build_version().to_string()),
        // config
        ("Zcash network", config.network.network.to_string()),
        // code constant
        (
            "running state version",
            state_database_format_version_in_code().to_string(),
        ),
        // state disk file, doesn't open database
        ("initial disk state version", disk_db_version),
        // build-time constant
        ("features", env!("VERGEN_CARGO_FEATURES").to_string()),
    ];

    // git env vars can be skipped if there is no `.git` during the
    // build, so they must all be optional
    let git_metadata: &[(_, Option<_>)] = &[
        ("branch", option_env!("VERGEN_GIT_BRANCH")),
        ("git commit", git_commit()),
        (
            "commit timestamp",
            option_env!("VERGEN_GIT_COMMIT_TIMESTAMP"),
        ),
    ];
    // skip missing metadata
    let git_metadata: Vec<(_, String)> = git_metadata
        .iter()
        .filter_map(|(k, v)| Some((k, (*v)?)))
        .map(|(k, v)| (*k, v.to_string()))
        .collect();

    let build_metadata: Vec<_> = [
        ("target triple", env!("VERGEN_CARGO_TARGET_TRIPLE")),
        ("rust compiler", env!("VERGEN_RUSTC_SEMVER")),
        ("rust release date", env!("VERGEN_RUSTC_COMMIT_DATE")),
        ("optimization level", env!("VERGEN_CARGO_OPT_LEVEL")),
        ("debug checks", env!("VERGEN_CARGO_DEBUG")),
    ]
    .iter()
    .map(|(k, v)| (*k, v.to_string()))
    .collect();

    let panic_metadata: Vec<_> = app_metadata
        .iter()
        .chain(git_metadata.iter())
        .chain(build_metadata.iter())
        .collect();

    let mut metadata_section = "Diagnostic metadata:".to_string();
    for (k, v) in panic_metadata {
        write!(&mut metadata_section, "\n{k}: {v}").expect("unexpected failure writing to string");
    }

    install_panic_hook(metadata_section.clone());

    // Apply the configured number of threads to the thread pool.
    //
    // Known limits, kept from earlier releases:
    // - Rayon uses its default panic handler, which doesn't report through the panic hook.
    // - `zakura_consensus::init()` doesn't configure this pool when that crate is used by
    //   itself.
    rayon::ThreadPoolBuilder::new()
        .num_threads(config.sync.parallel_cpu_threads)
        .thread_name(|thread_index| format!("rayon {thread_index}"))
        .build_global()
        .expect("unable to initialize rayon thread pool");

    let default_filter = command.cmd().default_tracing_filter(command.verbose);
    let is_server = command.cmd().is_server();

    // Ignore the configured tracing filter for short-lived utility commands
    let mut tracing_config = config.tracing.clone();
    if is_server {
        // Override the default tracing filter based on the command-line verbosity.
        tracing_config.filter = tracing_config
            .filter
            .clone()
            .or_else(|| Some(default_filter.to_owned()));
    } else {
        // Don't apply the configured filter for short-lived commands.
        tracing_config.filter = Some(default_filter.to_owned());
    }

    let tracing = Tracing::new(
        &config.network.network,
        tracing_config,
        command.cmd().uses_intro(),
    )?;

    // Log git metadata and platform info when zakurad starts up
    if is_server {
        info!("{metadata_section}");

        if command.config_path().is_some() {
            info!("Using config file at: {:?}", command.config_path().unwrap());
        } else {
            info!("No config file provided, using default configuration");
        }

        // Log only selected diagnostics. The full config can contain credentials.
        info!(
            network = %config.network.network,
            p2p_stack = ?config.network.p2p_stack.resolve(&config.network.network),
            peerset_initial_target_size = config.network.peerset_initial_target_size,
            ephemeral_state = config.state.ephemeral,
            "loaded node configuration",
        );

        // Explicitly log the configured miner address so CI can assert env override
        if let Some(miner_address) = &config.mining.miner_address {
            info!(%miner_address, "configured miner address");
        }
    }

    // Activate the global span, so it's visible when we load the other
    // components. Space is at a premium here, so we use an empty message,
    // short commit hash, and the unique part of the network name.
    let net = config.network.network.to_string();
    let net = match net.as_str() {
        default_net_name @ ("Testnet" | "Mainnet") => &default_net_name[..4],
        other_net_name => other_net_name,
    };
    let global_span = if let Some(git_commit) = git_commit() {
        // kogany: the commit field is named after the binary.
        #[cfg(feature = "ycash")]
        let span = error_span!("", koganyd = git_commit, net);
        #[cfg(not(feature = "ycash"))]
        let span = error_span!("", zakurad = git_commit, net);
        span
    } else {
        error_span!("", net)
    };

    let global_guard = global_span.enter();
    // leak the global span, to make sure it stays active
    std::mem::forget(global_guard);

    tracing::info!(
        num_threads = rayon::current_num_threads(),
        "initialized rayon thread pool for CPU-bound tasks",
    );

    // Start the metrics endpoint while the global span is still open, so its logs are in
    // that span, as in earlier releases.
    if is_server {
        metrics::start_endpoint(&config.metrics);
    }

    Ok((Arc::new(config), tracing))
}

#[cfg(all(test, feature = "ycash"))]
mod kogany_version_tests {
    use semver::{BuildMetadata, Version};

    use super::{build_version, kogany_build_metadata, release_version, user_agent};

    fn metadata(describe: Option<&str>, commit: Option<&str>) -> String {
        kogany_build_metadata(describe, commit).to_string()
    }

    #[test]
    fn describe_counts_commits_since_the_kogany_baseline() {
        let commit = Some("f96338437a7e1f2fb07c0e1a2b3c4d5e6f708192");
        assert_eq!(
            metadata(Some("kogany-ycash-baseline-26-gf96338437a7e"), commit),
            "kogany.26.gf96338437a7e"
        );
        assert_eq!(
            metadata(Some("kogany-ycash-baseline-0-gf96338437a7e"), None),
            "kogany.0.gf96338437a7e"
        );
        assert_eq!(
            metadata(Some("kogany-ycash-baseline-3-gf96338437a7e-dirty"), None),
            "kogany.3.gf96338437a7e.modified"
        );
    }

    #[test]
    fn without_git_the_supplied_commit_is_used() {
        // A Docker build has no `.git`: only the commit passed in (`SHORT_SHA`) is known.
        assert_eq!(
            metadata(None, Some("f96338437a7e1f2fb07c0e1a2b3c4d5e6f708192")),
            "kogany.gf96338437a7e"
        );
        assert_eq!(metadata(None, None), "kogany");
    }

    #[test]
    fn upstream_tags_are_never_used() {
        // An upstream Zakura `git describe` is not kogany's: fall back to the commit.
        assert_eq!(
            metadata(Some("v1.7.0-458-gfd3d6bece"), Some("fd3d6bece0123")),
            "kogany.gfd3d6bece012"
        );
        assert_eq!(
            metadata(Some("kogany-ycash-baseline-x-gabc"), None),
            "kogany"
        );
        assert_eq!(
            metadata(Some("kogany-ycash-baseline-1-abc"), None),
            "kogany"
        );
        assert_eq!(
            metadata(Some("kogany-ycash-baseline-1-gabc-x"), None),
            "kogany"
        );
    }

    #[test]
    fn build_version_is_the_package_line_plus_kogany_metadata() {
        let version = build_version();
        let package: Version = env!("CARGO_PKG_VERSION").parse().expect("valid");
        assert_eq!(
            (version.major, version.minor, version.patch, &version.pre),
            (package.major, package.minor, package.patch, &package.pre)
        );
        assert!(version.build.as_str().starts_with("kogany"), "{version}");

        // When this build saw kogany's tag, the count is the one in its `git describe`.
        if let Some(describe) = option_env!("KOGANY_GIT_DESCRIBE") {
            let count = describe
                .strip_prefix("kogany-ycash-baseline-")
                .and_then(|rest| rest.split('-').next())
                .expect("kogany describe");
            assert!(
                version
                    .build
                    .as_str()
                    .starts_with(&format!("kogany.{count}.g")),
                "{version} from {describe}"
            );
        }

        assert_eq!(release_version().build, BuildMetadata::EMPTY);
        assert_eq!(release_version().to_string(), env!("CARGO_PKG_VERSION"));
    }

    #[test]
    fn user_agent_carries_no_build_metadata() {
        let user_agent = user_agent();
        assert_eq!(
            user_agent,
            format!("/koganyd:{}/", env!("CARGO_PKG_VERSION"))
        );
        // ycashd's SAFE_CHARS_SUBVERSION.
        assert!(user_agent
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || " .-/:".contains(c)));
    }
}
