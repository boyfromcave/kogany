// The body of zakurad's entry point (kogany: moved out of `main.rs` so that `koganyd`, the
// `ycash` build's binary, shares it; an included file cannot carry the crate's inner doc comment).

use zakurad::application::boot;

#[cfg(all(target_os = "linux", target_env = "gnu"))]
const GLIBC_MALLOC_ARENA_MAX: i32 = 16;

#[cfg(all(target_os = "linux", target_env = "gnu"))]
#[allow(
    unsafe_code,
    reason = "calling glibc mallopt is required to bound allocator arena retention"
)]
fn limit_glibc_malloc_arenas() {
    if std::env::var_os("MALLOC_ARENA_MAX").is_some() {
        return;
    }

    // SAFETY: this process-global allocator setting is configured before worker threads start.
    let configured = unsafe { libc::mallopt(libc::M_ARENA_MAX, GLIBC_MALLOC_ARENA_MAX) };

    assert_ne!(
        configured, 0,
        "glibc accepts M_ARENA_MAX before worker threads start"
    );
}

#[cfg(target_arch = "x86_64")]
mod cpu_features;

/// Process entry point for `zakurad`
#[cfg_attr(
    feature = "ycash",
    allow(clippy::print_stderr, reason = "the refusal exits before logging starts")
)]
fn main() {
    // kogany: a `ycash` build is the Ycash node, `koganyd`; under Zcash's name it refuses to run,
    // so `cargo install --features ycash` can never shadow a Zcash `zakurad` on the same host.
    #[cfg(feature = "ycash")]
    if env!("CARGO_BIN_NAME") != "koganyd" {
        eprintln!(
            "this zakurad was built with the ycash feature: it is the Ycash node, run it as koganyd"
        );
        std::process::exit(2);
    }

    #[cfg(target_arch = "x86_64")]
    cpu_features::exit_if_cpu_lacks_pasta_assembly_features();

    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    limit_glibc_malloc_arenas();

    // Enable backtraces by default for zakurad, but allow users to override it.
    if std::env::var_os("RUST_BACKTRACE").is_none() {
        std::env::set_var("RUST_BACKTRACE", "1");
        // Disable library backtraces (i.e. eyre) to avoid performance hit for
        // non-panic errors, but allow users to override it.
        if std::env::var_os("RUST_LIB_BACKTRACE").is_none() {
            std::env::set_var("RUST_LIB_BACKTRACE", "0");
        }
    }
    boot();
}
