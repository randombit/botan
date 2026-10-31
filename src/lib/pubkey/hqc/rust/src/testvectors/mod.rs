//! Reference test vectors that require no C library.
//!
//! Two sources in Botan's `src/tests/data/pubkey/`, both covering all three
//! parameter sets:
//!
//! - [`intermediates`] — reference traces in `hqc_intermediates/` for
//!   keygen, encaps and decaps.
//! - `hqc_kat.vec` — 100 vectors per set, shared with the C++ tests and
//!   driven here by `kem::tests_kat`. PK and CT are SHAKE-256(128) digests.
//!
//! This module is the reference coverage that survives onto the `main`
//! branch. `src/ffi` and the `tests_ffi.rs` modules do not.

pub mod intermediates;

pub mod nist_rng;
