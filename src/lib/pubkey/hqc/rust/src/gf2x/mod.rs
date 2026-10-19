use crate::parameters::*;

/// Input size in words below which schoolbook_mul is used.
const KARATSUBA_THRESHOLD: usize = 16;

/// Total size in 64-bit words for the temporary buffer used by recursive Karatsuba.
/// Karatsuba scratch, in 64-bit words.
///
/// Sixteen times the operand size, matching the C reference. At HQC-5 that is
/// 14416 words (115 kB), which is why it stays on the heap.
const fn tmp_buffer_words(p: &HqcParameters) -> usize {
    16 * p.vec_n_size_64
}

/// Schoolbook multiplication over GF(2).
///
/// Computes `r = a * b` where `a`, `b` are length-`n` words.
/// Result `r` is `2*n` words.
///
/// Constant-time: no secret-dependent branches or memory accesses.
///
/// # Arguments
/// * `r` - Result buffer of `2*n` 64-bit words.
/// * `a` - Operand a of `n` 64-bit words.
/// * `b` - Operand b of `n` 64-bit words.
pub fn schoolbook_mul(r: &mut [u64], a: &[u64], b: &[u64]) {
    let n = a.len();

    // Zero the result buffer
    r.fill(0);

    for i in 0..n {
        let ai = a[i];
        for bit in 0..64u32 {
            // Constant-time mask: all 1s if bit is set, all 0s otherwise
            // No branch on secret data
            let mask = ((ai >> bit) & 1u64).wrapping_neg();

            let base = i;
            let sh = bit;
            let inv = 64 - sh;

            if sh == 0 {
                // No shift needed — bit 0
                for j in 0..n {
                    r[base + j] ^= b[j] & mask;
                }
            } else {
                for j in 0..n {
                    r[base + j] ^= (b[j] << sh) & mask;
                    r[base + j + 1] ^= (b[j] >> inv) & mask;
                }
            }
        }
    }
}

/// Karatsuba multiplication over GF(2) with caller-supplied temporary buffer.
///
/// Falls back to `schoolbook_mul` when `n <= KARATSUBA_THRESHOLD`.
/// Otherwise splits operands in half and applies recursion.
///
/// # Arguments
/// * `r`          - Result buffer of `2*n` 64-bit words.
/// * `a`          - Operand a of `n` 64-bit words.
/// * `b`          - Operand b of `n` 64-bit words.
/// * `n`          - Size of `a`and `b` in 64-bit words.
/// * `tmp_buffer` - Temporary buffer of at least `8*n` words.
pub fn karatsuba_mul(r: &mut [u64], a: &[u64], b: &[u64], n: usize, tmp_buffer: &mut [u64]) {
    // let n = a.len();

    // Base case — fall back to schoolbook multiplication
    if n <= KARATSUBA_THRESHOLD {
        schoolbook_mul(r, a, b);
        return;
    }

    let m = n >> 1; // low half size
    let n0 = m; // low half size
    let n1 = n - m; // high half size (may be larger by 1)

    // Carve successive chunks out of tmp_buffer:
    // z0   [0      .. 2*n)      low * low        (2*n words)
    // z2   [2*n    .. 4*n)      high * high      (2*n words)
    // zmid [4*n    .. 6*n)      middle product   (2*n words)
    // ta   [6*n    .. 6*n+n1)   a0 ^ a1          (n1 words)
    // tb   [6*n+n1 .. 6*n+2*n1) b0 ^ b1          (n1 words)
    // child_buffer [8*n ..)     for child calls
    let (z0, rest) = tmp_buffer.split_at_mut(2 * n);
    let (z2, rest) = rest.split_at_mut(2 * n);
    let (zmid, rest) = rest.split_at_mut(2 * n);
    let (ta, rest) = rest.split_at_mut(n1);
    let (tb, child_buffer) = rest.split_at_mut(n1);

    // 1) low * low: z0 = a[0..n0] * b[0..n0]
    karatsuba_mul(z0, &a[..n0], &b[..n0], n0, child_buffer);

    // 2) high * high: z2 = a[m..] * b[m..]
    karatsuba_mul(z2, &a[m..], &b[m..], n1, child_buffer);

    // 3) compute ta = a0 ^ a1, tb = b0 ^ b1
    for i in 0..n1 {
        let loa = if i < n0 { a[i] } else { 0 };
        let lob = if i < n0 { b[i] } else { 0 };
        ta[i] = loa ^ a[m + i];
        tb[i] = lob ^ b[m + i];
    }

    // zmid = ta * tb = (a0^a1) * (b0^b1)
    karatsuba_mul(zmid, ta, tb, n1, child_buffer);

    // 4) assemble result into r
    r.fill(0);

    // r ^= z0 (low product at offset 0)
    for i in 0..2 * n0 {
        r[i] ^= z0[i];
    }

    // r ^= z2 (high product at offset 2*m)
    for i in 0..2 * n1 {
        r[2 * m + i] ^= z2[i];
    }

    // r ^= middle term at offset m
    // mid[i] = zmid[i] ^ z0[i] ^ z2[i]
    for i in 0..2 * n1 {
        let z0i = if i < 2 * n0 { z0[i] } else { 0 };
        let z2i = if i < 2 * n1 { z2[i] } else { 0 };
        let mid = zmid[i] ^ z0i ^ z2i;
        r[m + i] ^= mid;
    }
}

/// Modular reduction of a degree < 2n polynomial mod (X^n - 1).
///
/// Folds the high half of the full product back into the low half
/// and masks any excess bits in the last word.
///
/// # Arguments
/// * `p` - Parameter set.
/// * `o` - Result buffer of `p.vec_n_size_64` 64-bit words.
/// * `a` - Input buffer of `2 * p.vec_n_size_64` 64-bit words.
pub fn reduce(p: &HqcParameters, o: &mut [u64], a: &[u64]) {
    assert_eq!(o.len(), p.vec_n_size_64, "output must have p.vec_n_size_64 words");
    assert_eq!(
        a.len(),
        2 * p.vec_n_size_64,
        "input must have 2 * p.vec_n_size_64 words"
    );

    let shift = p.top_word_bits();
    for i in 0..p.vec_n_size_64 {
        let r = a[i + p.vec_n_size_64 - 1] >> shift;
        // `64 - shift` is well defined: `top_word_bits` is never 0 because
        // every parameter set has n % 64 != 0, asserted in parameters.rs.
        let carry = a[i + p.vec_n_size_64] << (64 - shift);
        o[i] = a[i] ^ r ^ carry;
    }

    // Mask off bits beyond n in the last word
    o[p.vec_n_size_64 - 1] &= p.top_word_mask();
}

/// Carry-less multiplication mod (X^n - 1).
///
/// Computes `o = a1 * a2` over GF(2) mod (X^n - 1).
///
/// # Arguments
/// * `p`  - Parameter set.
/// * `a1` - Operand polynomial a(x) of `p.vec_n_size_64` 64-bit words.
/// * `a2` - Operand polynomial b(x) of `p.vec_n_size_64` 64-bit words.
///
/// # Returns
/// Result of `p.vec_n_size_64` 64-bit words.
pub fn vect_mul(p: &HqcParameters, a1: &[u64], a2: &[u64]) -> Vec<u64> {
    assert_eq!(a1.len(), p.vec_n_size_64);
    assert_eq!(a2.len(), p.vec_n_size_64);
    // Step 1: Multiply via Karatsuba into unreduced buffer
    let mut unreduced = vec![0u64; 2 * p.vec_n_size_64];
    let mut tmp_buffer = vec![0u64; tmp_buffer_words(p)];
    karatsuba_mul(&mut unreduced, a1, a2, p.vec_n_size_64, &mut tmp_buffer);

    // Step 2: Reduce modulo X^n - 1
    let mut o = p.zero_vec_n();
    reduce(p, &mut o, &unreduced);
    o
}

#[cfg(all(test, feature = "ref-ffi"))]
mod tests_ffi;
