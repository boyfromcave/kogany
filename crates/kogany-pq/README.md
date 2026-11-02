# kogany-pq

Post-quantum signature verification for `OP_CHECKPQSIG`: the Rust face of ycash6
`src/crypto/pq/scheme.{h,cpp}` (plan `docs/plans/kogany/kogany-yellowback-plan.md` W3-b, K-8,
mapping M24-25). Verification only: no key generation, no signing.

| byte | scheme | pk | sig (without hashtype) |
|---|---|---|---|
| `0x01` | SLH-DSA-SHA2-128s (FIPS 205, pure, empty context) | 32 | 7,856 |
| `0x02` | FN-DSA-512 / Falcon-512, PQClean padded | 897 | 666 |

API: `verify(scheme: u8, pk, msg: &[u8; 32], sig) -> bool`, `key_hash(scheme: u8, pk) -> KeyHash`
(`SHA256(scheme ‖ pk)`), `Scheme` (`from_byte`, `byte`, `pubkey_size`, `sig_size`, `key_hash`,
`verify`), `is_known_scheme`, `pubkey_size`, `sig_size`, and `primitive::{slh_dsa_sha2_128s_verify,
falcon512_padded_verify}` (arbitrary message and, for SLH-DSA, context: the C entry points the
conformance tests call).

## Vendored C: `csrc/`

Byte copies of ycash6 `src/crypto/pq/{falcon,slhdsa}/` at `vaults/kogany-compat` `65cb4ae0ff`
(identical to ycash-dd's), **verify subset only**. ycash6 `src/crypto/pq/README.md` is the
authority on provenance and the local patches; in short:

* `falcon/`: PQClean `crypto_sign/falcon-padded-512/clean` and `common/fips202.{c,h}` at
  `0586a824fc0d49df0b6b6e9179d8d15d06d0974f` (MIT; `fips202` public domain), plus the Ycash entry
  point `ycash_falcon_verify.c` and `ycash_falcon.h`. Vendored: `codec.c common.c vrfy.c fips202.c
  ycash_falcon_verify.c` and the headers `inner.h fpr.h fips202.h ycash_falcon.h`, `LICENSE`.
  **Not vendored** (signing/keygen/floating point): `keygen.c sign.c fft.c fpr.c rng.c
  ycash_falcon_sign.c`. `ycash_falcon.h` still declares the signing entry points; nothing defines
  or binds them.
* `slhdsa/`: pq-code-package `slhdsa-c` at `174c02e42257f95c210963272877c49dbb50070f`
  (`Apache-2.0 OR ISC OR MIT`, used under MIT), the same 13 files the C++ lines carry.
  `slh_dsa.c` is one translation unit holding signing and verification; it is vendored whole so
  its bytes stay identical, and only `slh_verify` is bound.
* Local patches carried unchanged (lines marked `YCASH LOCAL PATCH`): **P1** `falcon/fips202.{c,h}`
  (SHAKE256 incremental context inline: no `malloc`/`exit` on the consensus path), **P2**
  `falcon/ycash_falcon_verify.c` + `ycash_falcon.h` (exactly 666-byte signatures and 897-byte keys
  in the C entry point, so the compact form is refused), **P3** `slhdsa/slh_dsa.c` (zeroization in
  keygen/sign; the verify path is untouched).

`csrc/SHA256SUMS` pins every file; `build.rs` refuses to compile if a file drifts or the set
changes, and `tests/vendored.rs` checks the same. Regenerate after a deliberate re-vendor with
`(cd csrc && find falcon slhdsa -type f | sort | xargs sha256sum > SHA256SUMS)`.

Build: the `cc` crate, C99, no target-feature flags, optimisation from the Cargo profile. The
generic global names (`sha2_*`, `sha3_*`, `shake*`, `slh_*`, `ycash_falcon512_verify`) are renamed
`kogany_pq_*` with `-D` defines (no file edit) so they cannot collide with another C library in
`zakurad`. `src/ffi.rs` is the only `unsafe` code.

## Tests

`cargo test -p kogany-pq` and `cargo test -p kogany-pq --release` replay the pinned cross-line
files `testdata/yellowback/{pq_vectors,pq_acvp_slhdsa,pq_falcon_kat}.json` (checked against
`testdata/yellowback/PIN` before use) and the malformed-encoding cases of ycash6
`src/test/pq_crypto_tests.cpp`; `testdata/yellowback/CHECKLIST.md` maps each schema key to its test.
