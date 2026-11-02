// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

//! The thin FFI layer over the vendored C (`csrc/`). The only `unsafe` code in the crate.
//!
//! The C symbols are the `kogany_pq_`-prefixed names `build.rs` gives them. Every function here
//! takes slices and upholds the C side's length preconditions itself before it calls in, so a
//! caller cannot make the C read past a buffer.
#![allow(unsafe_code)]

use std::{
    ffi::c_int,
    marker::{PhantomData, PhantomPinned},
};

/// `slh_param_t` (`csrc/slhdsa/slh_param.h`), only ever handled by address.
#[repr(C)]
struct SlhParam {
    _opaque: [u8; 0],
    _not_send_sync_unpin: PhantomData<(*mut u8, PhantomPinned)>,
}

extern "C" {
    /// `const slh_param_t slh_dsa_sha2_128s` (`csrc/slhdsa/slh_sha2.c`).
    #[link_name = "kogany_pq_slh_dsa_sha2_128s"]
    static SLH_DSA_SHA2_128S: SlhParam;

    /// FIPS 205 Algorithm 24 (`csrc/slhdsa/slh_dsa.c`): 1 on success, 0 on failure. Reads
    /// `m_sz`, `sig_sz` (only if it equals the parameter set's size) and `ctx_sz` (only if at
    /// most 255) bytes, and `slh_pk_sz(prm)` bytes of `pk`, which has no length argument.
    #[link_name = "kogany_pq_slh_verify"]
    fn slh_verify(
        m: *const u8,
        m_sz: usize,
        sig: *const u8,
        sig_sz: usize,
        ctx: *const u8,
        ctx_sz: usize,
        pk: *const u8,
        prm: *const SlhParam,
    ) -> c_int;

    /// `csrc/falcon/ycash_falcon.h`: 0 on success, -1 on failure. Returns -1 before reading
    /// anything unless `siglen == 666` and `pklen == 897` (local patch P2); reads `mlen` bytes
    /// of `m`.
    #[link_name = "kogany_pq_ycash_falcon512_verify"]
    fn ycash_falcon512_verify(
        sig: *const u8,
        siglen: usize,
        m: *const u8,
        mlen: usize,
        pk: *const u8,
        pklen: usize,
    ) -> c_int;
}

/// SLH-DSA-SHA2-128s public key size, the bytes `slh_verify` reads through `pk`.
pub(crate) const SLH_DSA_SHA2_128S_PK: usize = 32;

/// A pointer for a byte slice that the C side may hand to `memcpy` even when the slice is empty:
/// an empty Rust slice's pointer is dangling, so it is replaced by the address of a real byte
/// (the C++ lines pass `&dummy` for the same reason).
fn c_ptr(bytes: &[u8]) -> *const u8 {
    static NO_BYTES: u8 = 0;
    if bytes.is_empty() {
        &NO_BYTES
    } else {
        bytes.as_ptr()
    }
}

/// Pure SLH-DSA-SHA2-128s verification with context `ctx` (FIPS 205 Algorithm 24).
pub(crate) fn slh_dsa_sha2_128s_verify(pk: &[u8], msg: &[u8], ctx: &[u8], sig: &[u8]) -> bool {
    if pk.len() != SLH_DSA_SHA2_128S_PK {
        return false;
    }
    // SAFETY: `pk` holds exactly the 32 bytes `slh_verify` reads through it (checked above).
    // `msg`, `sig` and `ctx` are passed with their own lengths, and `c_ptr` gives a valid
    // address for each even when empty; `slh_verify` reads no more than those lengths and
    // rejects a `sig` or `ctx` of the wrong length before reading it. `SLH_DSA_SHA2_128S` is an
    // immutable C object with static storage, only passed by address. The C code keeps all its
    // state on its own stack and writes through none of these pointers, so concurrent calls
    // are sound.
    let ok = unsafe {
        slh_verify(
            c_ptr(msg),
            msg.len(),
            c_ptr(sig),
            sig.len(),
            c_ptr(ctx),
            ctx.len(),
            pk.as_ptr(),
            &raw const SLH_DSA_SHA2_128S,
        )
    };
    ok == 1
}

/// Falcon-512 padded verification through the C++ lines' entry point.
pub(crate) fn falcon512_verify(pk: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    // SAFETY: every buffer is passed with its own length and through `c_ptr`, so each pointer
    // is valid for exactly the bytes its length names; `ycash_falcon512_verify` returns before
    // reading `sig` or `pk` unless their lengths are exactly 666 and 897, and reads `msg.len()`
    // bytes of `msg`. It keeps its state on its own stack and writes through none of these
    // pointers, so concurrent calls are sound.
    let ok = unsafe {
        ycash_falcon512_verify(
            c_ptr(sig),
            sig.len(),
            c_ptr(msg),
            msg.len(),
            c_ptr(pk),
            pk.len(),
        )
    };
    ok == 0
}
