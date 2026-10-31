//! Implementation of the additive FFT and its transpose.
//! This implementation is based on the paper from Gao and Mateer:
//! Shuhong Gao and Todd Mateer, Additive Fast Fourier Transforms over Finite Fields,
//! IEEE Transactions on Information Theory 56 (2010), 6265--6272.
//! http://www.math.clemson.edu/~sgao/papers/GM10.pdf <br>
//! and includes improvements proposed by Bernstein, Chou and Schwabe here:
//! https://binary.cr.yp.to/mcbits-20130616.pdf

use crate::gf::*;
use crate::parameters::{PARAM_GF_MUL_ORDER, PARAM_M};

/// Computes the basis of betas (omitting 1) used in the additive FFT and its transpose.
///
/// # Returns
/// Array of `PARAM_M - 1` beta values.
pub fn compute_fft_betas() -> [u16; PARAM_M - 1] {
    let mut betas = [0u16; PARAM_M - 1];
    for i in 0..PARAM_M - 1 {
        betas[i] = 1u16 << (PARAM_M - 1 - i);
    }
    betas
}

/// Computes the subset sums of the given set.
///
/// The array `subset_sums` is such that its i-th element is
/// the subset sum of the set elements given by the binary form of i.
///
/// # Arguments
/// * `set` - Slice of `set_size` elements.
///
/// # Returns
/// Array of `2^set_size` subset sums.
pub fn compute_subset_sums(set: &[u16], subset_sums: &mut [u16]) {
    let set_size = set.len();
    assert_eq!(
        subset_sums.len(),
        1 << set_size,
        "subset_sums must have length 2^set_size"
    );

    subset_sums[0] = 0;
    for i in 0..set_size {
        for j in 0..(1 << i) {
            subset_sums[(1 << i) + j] = set[i] ^ subset_sums[j];
        }
    }
}

/// Computes the radix conversion of a polynomial `f` in GF(2^m)[x].
///
/// Computes `f0` and `f1` such that `f(x) = f0(x^2-x) + x*f1(x^2-x)`,
/// as proposed by Bernstein, Chou and Schwabe:
/// <https://binary.cr.yp.to/mcbits-20130616.pdf>
///
/// # Arguments
/// * `f`   - Slice of coefficients, size a power of 2.
/// * `m_f` - `2^m_f` is the smallest power of 2 ≥ number of coefficients of `f`.
/// * `f0`  - Output slice, half the size of `f`.
/// * `f1`  - Output slice, half the size of `f`.
pub fn radix(f0: &mut [u16], f1: &mut [u16], f: &[u16], m_f: u32) {
    match m_f {
        4 => {
            f0[4] = f[8] ^ f[12];
            f0[6] = f[12] ^ f[14];
            f0[7] = f[14] ^ f[15];
            f1[5] = f[11] ^ f[13];
            f1[6] = f[13] ^ f[14];
            f1[7] = f[15];
            f0[5] = f[10] ^ f[12] ^ f1[5];
            f1[4] = f[9] ^ f[13] ^ f0[5];
            f0[0] = f[0];
            f1[3] = f[7] ^ f[11] ^ f[15];
            f0[3] = f[6] ^ f[10] ^ f[14] ^ f1[3];
            f0[2] = f[4] ^ f0[4] ^ f0[3] ^ f1[3];
            f1[1] = f[3] ^ f[5] ^ f[9] ^ f[13] ^ f1[3];
            f1[2] = f[3] ^ f1[1] ^ f0[3];
            f0[1] = f[2] ^ f0[2] ^ f1[1];
            f1[0] = f[1] ^ f0[1];
        }
        3 => {
            f0[0] = f[0];
            f0[2] = f[4] ^ f[6];
            f0[3] = f[6] ^ f[7];
            f1[1] = f[3] ^ f[5] ^ f[7];
            f1[2] = f[5] ^ f[6];
            f1[3] = f[7];
            f0[1] = f[2] ^ f0[2] ^ f1[1];
            f1[0] = f[1] ^ f0[1];
        }
        2 => {
            f0[0] = f[0];
            f0[1] = f[2] ^ f[3];
            f1[0] = f[1] ^ f0[1];
            f1[1] = f[3];
        }
        1 => {
            f0[0] = f[0];
            f1[0] = f[1];
        }
        _ => {
            radix_big(f0, f1, f, m_f);
        }
    }
}

/// Radix conversion for large polynomials in GF(2^m)[x].
///
/// Generalized radix step when the polynomial size `2^m_f` exceeds
/// the small-case thresholds (handled in `radix()`).
///
/// This function operates only on public FFT basis / polynomial data
/// — no secret-dependent branches or memory accesses; the recursion
/// structure depends solely on `m_f`, a public parameter.
///
/// # Arguments
/// * `f`   - Input slice of size `2^m_f`.
/// * `m_f` - Log₂ of the input size.
/// * `f0`  - Output slice, size `2^(m_f-1)`.
/// * `f1`  - Output slice, size `2^(m_f-1)`.
pub fn radix_big(f0: &mut [u16], f1: &mut [u16], f: &[u16], m_f: u32) {
    let n = 1usize << (m_f - 2);

    let mut q = vec![0u16; 2 * n];
    let mut r = vec![0u16; 2 * n];

    q[0..n].copy_from_slice(&f[3 * n..4 * n]);
    q[n..2 * n].copy_from_slice(&f[3 * n..4 * n]);
    r[0..2 * n].copy_from_slice(&f[0..2 * n]);

    for i in 0..n {
        q[i] ^= f[2 * n + i];
        r[n + i] ^= q[i];
    }

    let mut q0 = vec![0u16; n];
    let mut q1 = vec![0u16; n];
    let mut r0 = vec![0u16; n];
    let mut r1 = vec![0u16; n];

    radix(&mut q0, &mut q1, &q, m_f - 1);
    radix(&mut r0, &mut r1, &r, m_f - 1);

    f0[0..n].copy_from_slice(&r0);
    f0[n..2 * n].copy_from_slice(&q0);
    f1[0..n].copy_from_slice(&r1);
    f1[n..2 * n].copy_from_slice(&q1);
}

/// Evaluates `f` at all subset sums of a given set.
///
/// Subroutine of the `fft` function.
///
/// # Arguments
/// * `f`        - Input/output slice — mutated in place (Step 2 scaling).
/// * `f_coeffs` - Number of coefficients of `f`.
/// * `m`        - Number of betas.
/// * `m_f`      - Number of coefficients of `f` (one more than its degree).
/// * `betas`    - FFT constants.
/// * `w`        - Output array.
pub fn fft_rec(w: &mut [u16], f: &mut [u16], f_coeffs: usize, m: u8, m_f: u32, betas: &[u16]) {
    // Step 1: base case
    if m_f == 1 {
        let mut tmp = vec![0u16; m as usize];
        for i in 0..m as usize {
            tmp[i] = gf_mul(betas[i], f[1]);
        }
        w[0] = f[0];
        let mut x: usize = 1;
        for j in 0..m as usize {
            for k in 0..x {
                w[x + k] = w[k] ^ tmp[j];
            }
            x <<= 1;
        }
        return;
    }

    // Step 2: compute g
    if betas[(m - 1) as usize] != 1 {
        let mut beta_m_pow: u16 = 1;
        let x: usize = 1usize << m_f;
        for i in 1..x {
            beta_m_pow = gf_mul(beta_m_pow, betas[(m - 1) as usize]);
            f[i] = gf_mul(beta_m_pow, f[i]);
        }
    }

    // Step 3: radix
    let half = 1usize << (m_f - 1);
    let mut f0 = vec![0u16; half];
    let mut f1 = vec![0u16; half];
    radix(&mut f0, &mut f1, f, m_f);

    // Step 4: compute gammas and deltas
    let mm1 = (m - 1) as usize;
    let mut gammas = vec![0u16; mm1];
    let mut deltas = vec![0u16; mm1];
    let beta_m_inv = gf_inverse(betas[(m - 1) as usize]);
    for i in 0..mm1 {
        gammas[i] = gf_mul(betas[i], beta_m_inv);
        deltas[i] = gf_square(gammas[i]) ^ gammas[i];
    }

    // Compute gammas sums
    let mut gammas_sums = vec![0u16; 1usize << mm1];
    compute_subset_sums(&gammas, &mut gammas_sums);

    // Step 5
    let mut u = vec![0u16; 1usize << mm1];
    fft_rec(&mut u, &mut f0, (f_coeffs + 1) / 2, m - 1, m_f - 1, &deltas);

    let k: usize = 1usize << mm1;

    if f_coeffs <= 3 {
        // 3-coefficient polynomial f case: f1 is constant
        w[0] = u[0];
        w[k] = u[0] ^ f1[0];
        for i in 1..k {
            w[i] = u[i] ^ gf_mul(gammas_sums[i], f1[0]);
            w[k + i] = w[i] ^ f1[0];
        }
    } else {
        let mut v = vec![0u16; 1usize << mm1];
        fft_rec(&mut v, &mut f1, f_coeffs / 2, m - 1, m_f - 1, &deltas);

        // Step 6
        w[k..k + k].copy_from_slice(&v[..k]);
        w[0] = u[0];
        w[k] ^= u[0];
        for i in 1..k {
            w[i] = u[i] ^ gf_mul(gammas_sums[i], v[i]);
            w[k + i] ^= w[i];
        }
    }
}

/// Evaluates `f` on all field elements using an additive FFT algorithm.
///
/// `f_coeffs` is the number of coefficients of `f`. The FFT proceeds
/// recursively to evaluate `f` at all subset sums of a basis B.
///
/// Based on Gao and Mateer, "Additive Fast Fourier Transforms over Finite
/// Fields" (IEEE Transactions on Information Theory 56, 2010), with
/// improvements from Bernstein, Chou and Schwabe:
/// <https://binary.cr.yp.to/mcbits-20130616.pdf>
///
/// On this first call (as opposed to recursive `fft_rec` calls), gammas
/// equal betas, so the first gammas subset sums are the subset sums of
/// betas (except 1). `f` is not altered here (a local copy is passed
/// to `radix`, matching the `const` C signature).
///
/// Constant-time with respect to the coefficients of `f`: all structure
/// (loop bounds, recursion depth) depends only on public compile-time
/// parameters (`PARAM_M`, `fft_exp`), never on secret coefficient values.
///
/// # Arguments
/// * `f`        - Input array of `2^fft_exp` elements.
/// * `f_coeffs` - Number of coefficients of `f` (i.e. deg(f)+1).
/// * `fft_exp`  - `HqcParameters::fft_exp`: 4 for HQC-1, 5 for HQC-3 and
///                HQC-5. The only parameter-dependent quantity in this module;
///                everything else derives from the invariant `PARAM_M`.
///
/// # Returns
/// Output array `w` of `2^PARAM_M` field evaluations.
pub fn fft(f: &[u16], f_coeffs: usize, fft_exp: usize) -> Vec<u16> {
    let betas = compute_fft_betas(); // [u16; PARAM_M - 1]

    // Compute betas subset sums
    let mut betas_sums = vec![0u16; 1usize << (PARAM_M - 1)];
    compute_subset_sums(&betas, &mut betas_sums);

    // Step 3: radix split
    let half = 1usize << (fft_exp - 1);
    let mut f0 = vec![0u16; half];
    let mut f1 = vec![0u16; half];
    let f_copy = f.to_vec(); // radix takes f by reference, no mutation needed here
    radix(&mut f0, &mut f1, &f_copy, fft_exp as u32);

    // Step 4: compute deltas
    let mut deltas = vec![0u16; PARAM_M - 1];
    for i in 0..PARAM_M - 1 {
        deltas[i] = gf_square(betas[i]) ^ betas[i];
    }

    // Step 5
    let mut u = vec![0u16; 1usize << (PARAM_M - 1)];
    let mut v = vec![0u16; 1usize << (PARAM_M - 1)];
    fft_rec(
        &mut u,
        &mut f0,
        (f_coeffs + 1) / 2,
        (PARAM_M - 1) as u8,
        (fft_exp - 1) as u32,
        &deltas,
    );
    fft_rec(
        &mut v,
        &mut f1,
        f_coeffs / 2,
        (PARAM_M - 1) as u8,
        (fft_exp - 1) as u32,
        &deltas,
    );

    let k: usize = 1usize << (PARAM_M - 1);
    let mut w = vec![0u16; 2 * k];

    // Step 6, 7 and error polynomial computation
    w[k..k + k].copy_from_slice(&v[..k]);

    // Check if 0 is root
    w[0] = u[0];
    // Check if 1 is root
    w[k] ^= u[0];
    // Find other roots
    for i in 1..k {
        w[i] = u[i] ^ gf_mul(betas_sums[i], v[i]);
        w[k + i] ^= w[i];
    }

    w
}

/// Retrieves the error polynomial from the evaluations `w` of the ELP
/// (Error Locator Polynomial) on all field elements.
///
/// # Arguments
/// * `w` - Array of size `2^PARAM_M`, ELP evaluations.
/// * `error` - Output error polynomial
pub fn fft_retrieve_error_poly(error: &mut [u8], w: &[u16]) {
    let gammas = compute_fft_betas(); // PARAM_M - 1 public basis elements

    let mut gammas_sums = vec![0u16; 1usize << (PARAM_M - 1)];
    compute_subset_sums(&gammas, &mut gammas_sums);

    let k: usize = 1usize << (PARAM_M - 1);

    // Constant-time zero test: bit = 1 if w[i] == 0, else 0
    let is_zero = |x: u16| -> u16 { 1u16 ^ (x.wrapping_neg() >> 15) };

    error[0] ^= is_zero(w[0]) as u8;
    error[0] ^= is_zero(w[k]) as u8;

    for i in 1..k {
        let index = PARAM_GF_MUL_ORDER - (GF_LOG[gammas_sums[i] as usize] as usize);
        error[index] ^= is_zero(w[i]) as u8;

        let index = PARAM_GF_MUL_ORDER - (GF_LOG[(gammas_sums[i] ^ 1) as usize] as usize);
        error[index] ^= is_zero(w[k + i]) as u8;
    }
}

#[cfg(all(test, feature = "ref-ffi"))]
mod tests_ffi;
