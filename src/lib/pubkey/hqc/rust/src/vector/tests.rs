//! Pure-Rust tests for `vector` (no C reference required).

use super::*;
use crate::parameters::HqcParameterSet;

/// `barrett_reduce` must agree with `x % n` over the whole input domain the
/// sampler can produce, plus the boundary values.
///
/// Modelled on the C project's own `test_barrett_reduce` in
/// `tests/unit/test_vector.c`, which likewise checks against `x % n`
/// rather than against another implementation. That matters: the existing
/// `tests_ffi.rs` version compares Rust against C, so it disappears whenever
/// the reference is unavailable — including on the Botan-facing branch. This
/// one holds everywhere, and it is the stronger check anyway, since an
/// identical mistake in both implementations would pass a Rust-vs-C
/// comparison and fail here.
#[test]
fn barrett_reduce_matches_modulo_over_sampler_domain() {
    // The fixed-weight sampler draws 24-bit candidates, so this is the full
    // domain `barrett_reduce` is ever asked to handle. Now checked for every
    // parameter set, since `n_mu` differs across them.
    for set in HqcParameterSet::ALL {
        let p = set.params();
        for x in 0..(1u32 << 24) {
            let got = barrett_reduce(p, x);
            let want = x % p.n as u32;
            assert_eq!(got, want, "{}: barrett_reduce({x})", set.name());
        }
    }
}

#[test]
fn barrett_reduce_handles_boundaries() {
    for set in HqcParameterSet::ALL {
        let p = set.params();
        let n = p.n as u32;
        for x in [0, 1, n - 1, n, n + 1, 2 * n - 1, 2 * n, u32::MAX] {
            assert_eq!(barrett_reduce(p, x), x % n, "{}: barrett_reduce({x})", set.name());
        }
    }
}
