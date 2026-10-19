//! Reference test vectors that require no C library.
//!
//! Two sources, both already vendored under `kats/`, both covering all three
//! parameter sets:
//!
//! - [`intermediates`] — the reference's own trace of every internal value
//!   through keygen, encaps and decaps.
//! - `.rsp` KAT files — 100 seed/pk/sk/ct/ss vectors per set, driven by
//!   `kem::tests_kat`.
//!
//! This module is the reference coverage that survives onto the `main`
//! branch. `src/ffi` and the `tests_ffi.rs` modules do not.

pub mod intermediates;

pub mod nist_rng;
