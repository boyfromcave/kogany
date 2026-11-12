//! Emits Cargo, Rust compiler, and Git metadata for `zakurad`.

use std::{
    env,
    path::{Path, PathBuf},
    process::Command,
};

/// Emits all metadata consumed by `zakurad` diagnostics.
#[allow(clippy::print_stderr)]
pub fn emit() {
    println!("cargo:rerun-if-env-changed=SOURCE_DATE_EPOCH");
    println!("cargo:rerun-if-env-changed=KOGANY_RELEASE_TAG");

    emit_cargo_metadata();
    emit_rustc_metadata();
    emit_kogany_release_tag();

    if let Err(error) = emit_git_metadata() {
        // Source archives and `cargo install` builds do not have a `.git`
        // directory, so Git metadata is intentionally optional.
        eprintln!("git metadata unavailable: skipping git env vars: {error}");
    }
}

fn emit_cargo_metadata() {
    let mut features: Vec<_> = env::vars()
        .filter_map(|(name, _)| {
            name.strip_prefix("CARGO_FEATURE_")
                .map(|feature| feature.to_lowercase())
        })
        .collect();
    features.sort_unstable();

    emit_env("VERGEN_CARGO_FEATURES", features.join(","));
    emit_env("VERGEN_CARGO_TARGET_TRIPLE", required_env("TARGET"));
    emit_env("VERGEN_CARGO_OPT_LEVEL", required_env("OPT_LEVEL"));
    emit_env("VERGEN_CARGO_DEBUG", required_env("DEBUG"));
}

fn emit_rustc_metadata() {
    let rustc = env::var_os("RUSTC").expect("Cargo always sets RUSTC for build scripts");
    let output = Command::new(rustc)
        .arg("-vV")
        .output()
        .expect("rustc must be executable to compile zakurad");
    assert!(output.status.success(), "rustc -vV must succeed");

    let version = String::from_utf8(output.stdout).expect("rustc -vV output must be UTF-8");
    emit_env("VERGEN_RUSTC_SEMVER", rustc_field(&version, "release"));
    emit_env(
        "VERGEN_RUSTC_COMMIT_DATE",
        rustc_field(&version, "commit-date"),
    );
}

fn emit_git_metadata() -> Result<(), String> {
    if git(&["rev-parse", "--is-inside-work-tree"])? != "true" {
        return Err("not inside a Git worktree".to_string());
    }

    emit_git_rerun_triggers()?;

    let branch = git(&["rev-parse", "--abbrev-ref", "--symbolic-full-name", "HEAD"])?;
    let sha = git(&["rev-parse", "HEAD"])?;
    let timestamp = match env::var("SOURCE_DATE_EPOCH") {
        Ok(epoch) => format_source_date_epoch(&epoch)?,
        Err(env::VarError::NotPresent) => git(&["log", "-1", "--pretty=format:%cI"])?,
        Err(error) => return Err(format!("invalid SOURCE_DATE_EPOCH: {error}")),
    };

    let dirty = !git(&["status", "--porcelain", "--untracked-files=no"])?.is_empty();
    let mut describe = git(&["describe", "--always", "--tags", "--match", "v*.*.*"])?;
    if dirty {
        describe.push_str("-dirty");
    }

    // kogany: the Ycash build's metadata counts commits since kogany's own baseline tag, never
    // since an upstream Zakura `v*` tag (`application::kogany_build_metadata`). Optional: a
    // checkout without the tag falls back to the commit alone.
    if let Ok(mut kogany_describe) = git(&[
        "describe",
        "--tags",
        "--match",
        KOGANY_BASELINE_TAG,
        "--long",
        "--abbrev=12",
    ]) {
        if dirty {
            kogany_describe.push_str("-dirty");
        }
        emit_env("KOGANY_GIT_DESCRIBE", kogany_describe);
    }

    emit_env("VERGEN_GIT_BRANCH", branch);
    emit_env("VERGEN_GIT_COMMIT_TIMESTAMP", timestamp);
    emit_env("VERGEN_GIT_DESCRIBE", describe);
    emit_env("VERGEN_GIT_SHA", sha);

    Ok(())
}

/// kogany: the release tag the build is cut at, for the user agent
/// (`zakura_network::ycash::user_agent_for_release`). The release workflow sets
/// `KOGANY_RELEASE_TAG`; a value that is not a kogany release tag ([`is_kogany_release_tag`])
/// fails the build, so it never reaches `cargo:rustc-env` unchecked. A local build without the
/// variable falls back to a clean checkout exactly at a `v*-ycash.*` tag, and reruns when a tag is
/// added or the index changes ([`emit_git_rerun_triggers`]). Anything else emits nothing, and the
/// user agent carries the crate version.
fn emit_kogany_release_tag() {
    let tag = match env::var("KOGANY_RELEASE_TAG") {
        Ok(tag) if !tag.is_empty() => {
            assert!(
                is_kogany_release_tag(&tag),
                "KOGANY_RELEASE_TAG={tag:?} is not a kogany release tag \
                 v<X.Y.Z>-ycash.<beta|rc><n> (at most {MAX_RELEASE_DIGITS} digits per number)"
            );
            Some(tag)
        }
        _ => git(&["status", "--porcelain", "--untracked-files=no"])
            .ok()
            .filter(|status| status.is_empty())
            .and_then(|_| {
                git(&[
                    "describe",
                    "--tags",
                    "--exact-match",
                    "--match",
                    "v*-ycash.*",
                ])
                .ok()
            })
            .filter(|tag| is_kogany_release_tag(tag)),
    };
    if let Some(tag) = tag {
        emit_env("KOGANY_RELEASE_TAG", tag);
    }
}

/// The most digits in each number of a release tag: `zakura_network::ycash::MAX_RELEASE_DIGITS`
/// (a build script cannot use the crate; `kogany_version_tests` checks the two agree).
pub(crate) const MAX_RELEASE_DIGITS: usize = 5;

/// Is `tag` a kogany release tag, `v<X.Y.Z>-ycash.<beta|rc><n>` with 1 to
/// [`MAX_RELEASE_DIGITS`] digits per number? The shape `zakura_network::ycash::release_name`
/// accepts; it also keeps anything but `[0-9a-z.-]` (a newline, a second `cargo:` directive) out
/// of the emitted value.
pub(crate) fn is_kogany_release_tag(tag: &str) -> bool {
    let digits = |s: &str| {
        (1..=MAX_RELEASE_DIGITS).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_digit())
    };
    let Some((version, stage)) = tag
        .strip_prefix('v')
        .and_then(|name| name.split_once("-ycash."))
    else {
        return false;
    };
    let numbers: Vec<&str> = version.split('.').collect();
    numbers.len() == 3
        && numbers.iter().all(|n| digits(n))
        && stage
            .strip_prefix("beta")
            .or_else(|| stage.strip_prefix("rc"))
            .is_some_and(digits)
}

/// kogany's baseline tag: the commit the Ycash work was cut from (plan §4.2). `koganyd`'s build
/// metadata counts commits since it.
const KOGANY_BASELINE_TAG: &str = "kogany-ycash-baseline";

fn emit_git_rerun_triggers() -> Result<(), String> {
    let git_dir = PathBuf::from(git(&["rev-parse", "--git-dir"])?);
    emit_rerun_if_exists(&git_dir.join("HEAD"));

    if let Ok(reference) = git(&["symbolic-ref", "HEAD"]) {
        emit_rerun_if_exists(&git_dir.join(&reference));

        // kogany: in a linked worktree the branch ref (and `packed-refs`) live in the common
        // git dir, not in `--git-dir`, so a new commit would not rerun this script and the
        // version would name the old commit. `--git-path` resolves both layouts.
        for path in [reference.as_str(), "packed-refs"] {
            if let Ok(resolved) = git(&["rev-parse", "--git-path", path]) {
                emit_rerun_if_exists(Path::new(&resolved));
            }
        }
    }

    // kogany: the `git describe` fallbacks (the release tag, `KOGANY_GIT_DESCRIBE`) and the
    // `-dirty` mark also depend on the tags and on the tree's state. A new tag lands in
    // `refs/tags/` (a directory: Cargo reruns when anything in it changes) or `packed-refs`
    // (above); `git add`, `commit`, `checkout`, `stash` and `reset` rewrite the index, and so does
    // `git status` when it refreshes stat data, so an edit is seen once the index is touched. An
    // unstaged edit nobody has run git on since is not; the release workflow sets
    // `KOGANY_RELEASE_TAG` and does not depend on this. Only the `ycash` build without that
    // variable derives its version this way, so only it watches these: a feature-off build keeps
    // upstream's triggers, and a `git status` does not relink it.
    let tag_from_git = env::var_os("CARGO_FEATURE_YCASH").is_some()
        && env::var("KOGANY_RELEASE_TAG")
            .unwrap_or_default()
            .is_empty();
    if tag_from_git {
        for path in ["refs/tags", "index"] {
            if let Ok(resolved) = git(&["rev-parse", "--git-path", path]) {
                emit_rerun_if_exists(Path::new(&resolved));
            }
        }
    }

    Ok(())
}

fn emit_rerun_if_exists(path: &Path) {
    if path.exists() {
        println!("cargo:rerun-if-changed={}", path.display());
    }
}

fn git(args: &[&str]) -> Result<String, String> {
    let output = Command::new("git")
        .args(args)
        .env("GIT_OPTIONAL_LOCKS", "0")
        .output()
        .map_err(|error| format!("could not run git: {error}"))?;

    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).trim().to_string());
    }

    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn format_source_date_epoch(epoch: &str) -> Result<String, String> {
    let seconds: i64 = epoch
        .parse()
        .map_err(|error| format!("SOURCE_DATE_EPOCH must be an integer: {error}"))?;
    let days = seconds.div_euclid(86_400);
    let seconds_of_day = seconds.rem_euclid(86_400);
    let (year, month, day) = civil_date(days);
    let hour = seconds_of_day / 3_600;
    let minute = seconds_of_day % 3_600 / 60;
    let second = seconds_of_day % 60;

    Ok(format!(
        "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.000000000Z"
    ))
}

fn civil_date(days_since_unix_epoch: i64) -> (i64, i64, i64) {
    let days = days_since_unix_epoch + 719_468;
    let era = days.div_euclid(146_097);
    let day_of_era = days - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let mut year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    year += i64::from(month <= 2);
    (year, month, day)
}

fn rustc_field<'a>(version: &'a str, field: &str) -> &'a str {
    version
        .lines()
        .find_map(|line| line.strip_prefix(&format!("{field}: ")))
        .unwrap_or_else(|| panic!("rustc -vV output must contain {field}"))
}

fn required_env(name: &str) -> String {
    env::var(name).unwrap_or_else(|_| panic!("Cargo always sets {name} for build scripts"))
}

fn emit_env(name: &str, value: impl AsRef<str>) {
    println!("cargo:rustc-env={name}={}", value.as_ref());
}
