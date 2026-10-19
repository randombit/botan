use crate::error::Result;
use crate::hash::{Callbacks, Xof};
use crate::parameters::*;
use crate::secmem::{zeroize_slice, SecureBuffer};

/// Constant-time equality comparison for u32 values.
///
/// # Returns
/// `0xFFFFFFFF` if `a == b`, `0x00000000` otherwise.
#[inline]
pub fn compare_u32(a: u32, b: u32) -> u32 {
    let diff: u32 = a.wrapping_sub(b) | b.wrapping_sub(a);
    // If a == b: diff == 0, MSB of -diff is 0 → result is 0
    // If a != b: diff != 0, MSB of -diff is 1 → result is 0xFFFFFFFF
    1u32 ^ (diff >> 31)
}

/// Constant-time Barrett reduction modulo `p.n`.
///
/// Reduces `x` modulo `p.n` using the precomputed value
/// `p.n_mu = ⌊2^32 / p.n⌋`.
///
/// # Arguments
/// * `x` - Input value to reduce.
///
/// # Returns
/// `x mod p.n` in constant time.
#[inline]
pub fn barrett_reduce(p: &HqcParameters, x: u32) -> u32 {
    let q = ((x as u64) * (p.n_mu as u64)) >> 32;
    let r = x.wrapping_sub((q as u32).wrapping_mul(p.n as u32));
    let reduce_flag = ((r.wrapping_sub(p.n as u32)) >> 31) ^ 1;
    let mask = reduce_flag.wrapping_neg();
    r.wrapping_sub(mask & p.n as u32)
}

/// Generates a random support set with uniform and unbiased sampling.
///
/// Implements a rejection sampling algorithm to generate `weight`
/// distinct indices uniformly at random from the interval `[0, p.n)`.
///
///  Internally, it samples 24-bit random values and rejects any value ≥ p.rejection_threshold,
/// where the threshold is precomputed as:
/// \f[
///   t = \left\lfloor \frac{2^{24}}{\text{PARAM\_N}} \right\rfloor \times \text{PARAM\_N}
/// \f]
///
/// # Arguments
/// * `reader` - SHAKE256 XOF reader used for random byte generation.
/// * `weight` - Desired Hamming weight (number of distinct indices).
///
/// # Returns
/// A `Vec<u32>` containing `weight` unique indices.
pub fn vect_generate_random_support1<'a>(
    p: &HqcParameters,
    cb: &'a dyn Callbacks,
    reader: &mut dyn Xof,
    weight: usize,
) -> Result<SecureBuffer<'a, u32>> {
    // The index list is the secret vector in another representation
    let mut support = SecureBuffer::<u32>::zeroed(cb, weight)?;
    let mut i = 0;
    // Exact upstream rejection sampling: loop count remains variable-time.
    // Scan every accepted entry without a duplicate-dependent early exit.
    while i < weight {
        let mut bytes = [0u8; 3];
        reader.squeeze(&mut bytes)?;
        let candidate = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], 0]);
        zeroize_slice(&mut bytes);
        let mut accept = candidate.wrapping_sub(p.rejection_threshold) >> 31;
        let candidate = barrett_reduce(p, candidate);
        let mut found = 0;
        for &entry in &support[..i] {
            found |= compare_u32(entry, candidate);
        }
        accept &= found ^ 1;
        support[i] = candidate;
        i += accept as usize;
    }

    Ok(support)
}

/// Generates a random support set of distinct indices.
///
/// Implements the **GenerateRandomSupport** algorithm from the specification.
///
/// # Arguments
/// * `reader` - Initialized SHAKE256 XOF reader used for randomness.
/// * `weight` - Number of elements to generate (Hamming weight).
///
/// # Returns
/// A `Vec<u32>` of `weight` unique indices.
pub fn vect_generate_random_support2<'a>(
    p: &HqcParameters,
    cb: &'a dyn Callbacks,
    reader: &mut dyn Xof,
    weight: usize,
) -> Result<SecureBuffer<'a, u32>> {
    // Read bytes then convert explicitly (little-endian)
    let mut rand_bytes = SecureBuffer::<u8>::zeroed(cb, 4 * weight)?;
    reader.squeeze(&mut rand_bytes)?;
    let mut rand_u32 = SecureBuffer::<u32>::zeroed(cb, weight)?;
    for (dst, b) in rand_u32.iter_mut().zip(rand_bytes.chunks_exact(4)) {
        *dst = u32::from_le_bytes(b.try_into().unwrap());
    }

    // Phase 1: Initial index assignment using scaling
    let mut support = SecureBuffer::<u32>::zeroed(cb, weight)?;
    for i in 0..weight {
        let buff = rand_u32[i] as u64;
        support[i] = i as u32 + ((buff * (p.n as u64 - i as u64)) >> 32) as u32;
    }

    // Phase 2: Constant-time collision resolution (backwards pass)
    for i in (0..weight.saturating_sub(1)).rev() {
        // runs [weight-2, weight-3, ..., 1, 0]
        let mut found = 0u32;
        for j in (i + 1)..weight {
            found |= compare_u32(support[j], support[i]);
        }
        // Constant-time conditional assignment:
        // if found: support[i] = i
        // if !found: support[i] = support[i]  (unchanged)
        let mask = found.wrapping_neg();
        support[i] = (mask & i as u32) ^ (!mask & support[i]);
    }

    Ok(support)
}

/// Sets bits in a vector based on a support set.
///
/// Writes `weight` positions from `support` into the bit-vector `v`.
/// Each index in `support` sets a corresponding bit in `v`.
///
/// # Arguments
/// * `v`       - Output bit-vector of `p.vec_n_size_64` 64-bit words.
/// * `support` - Slice of bit indices to set, from `vect_generate_random_support`.
pub fn vect_write_support_to_vector(p: &HqcParameters, v: &mut [u64], support: &[u32]) {
    assert_eq!(v.len(), p.vec_n_size_64);
    assert!(support.len() <= MAX_OMEGA_R);
    // Precompute word indices and bit masks for each support position
    let mut index_tab = [0u32; MAX_OMEGA_R];
    let mut bit_tab = [0u64; MAX_OMEGA_R];

    for (i, &s) in support.iter().enumerate() {
        index_tab[i] = s >> 6; // which 64-bit word of the p.n-bit vector.
        let pos = (s & 0x3f) as u64; // which bit within the word
        bit_tab[i] = 1u64 << pos; // TODO Prone to platform-dependent timing attack!

        // // Build the bit mask purely from arithmetic — no shift with secret amount
        //  let mut bit = 0u64;
        //  for b in 0u32..64 {
        //      let matches = (b.wrapping_sub(pos) | pos.wrapping_sub(b)).wrapping_neg() >> 31;
        //      // matches == 0xFFFFFFFF if b == pos, else 0
        //      bit |= (1u64 << b) & (matches as u64);
        //  }
        //  bit_tab[i] = bit;
    }

    // For each 64-bit word, accumulate bits from matching support entries
    for i in 0..p.vec_n_size_64 {
        let mut val = 0u64;
        for j in 0..support.len() {
            let tmp = (i as u32).wrapping_sub(index_tab[j]);
            // val1 == 1 if tmp == 0 (i.e. word index matches), else 0
            let val1 = 1u32 ^ ((tmp | tmp.wrapping_neg()) >> 31);
            let mask = (val1 as u64).wrapping_neg();
            val |= bit_tab[j] & mask;
        }
        v[i] |= val;
    }

    zeroize_slice(&mut index_tab);
    zeroize_slice(&mut bit_tab);
}

/// Generates a random binary vector of fixed Hamming weight.
///
/// Samples a binary vector with exactly `weight` bits set to 1, where
/// positions are chosen uniformly at random without bias.
///
/// Used during key expansion to generate vectors **x** and **y**.
/// Variable-time: the number of rejection-sampling iterations depends on the seed.
///
/// # Arguments
/// * `reader` - A previously initialized SHAKE-256 XOF reader.
/// * `weight` - Desired Hamming weight.
///
/// # Returns
/// A bit-vector of `p.vec_n_size_64` 64-bit words with exactly `weight` bits set.
pub fn vect_sample_fixed_weight1<'a>(
    p: &HqcParameters,
    cb: &'a dyn Callbacks,
    reader: &mut dyn Xof,
    weight: usize,
) -> Result<SecureBuffer<'a, u64>> {
    let support = vect_generate_random_support1(p, cb, reader, weight)?;
    let mut v = SecureBuffer::<u64>::zeroed(cb, p.vec_n_size_64)?;
    vect_write_support_to_vector(p, &mut v, &support);
    Ok(v)
}

/// Generates a random binary vector of fixed Hamming weight.
///
/// Implementation of Algorithm 5 in <https://eprint.iacr.org/2021/1631.pdf>
///
/// Used exclusively during **encryption** to generate vectors **r1**, **r2**, and **e**.
///
/// # Arguments
/// * `reader` - A previously initialized SHAKE-256 XOF reader.
/// * `weight` - Desired Hamming weight.
///
/// # Returns
/// A bit-vector of `p.vec_n_size_64` 64-bit words with exactly `weight` bits set.
pub fn vect_sample_fixed_weight2<'a>(
    p: &HqcParameters,
    cb: &'a dyn Callbacks,
    reader: &mut dyn Xof,
    weight: usize,
) -> Result<SecureBuffer<'a, u64>> {
    let support = vect_generate_random_support2(p, cb, reader, weight)?;
    let mut v = SecureBuffer::<u64>::zeroed(cb, p.vec_n_size_64)?;
    vect_write_support_to_vector(p, &mut v, &support);
    Ok(v)
}

/// Generates a random vector of dimension `p.n`.
///
/// Generates a random binary vector of dimension `p.n` by reading
/// random bytes from the XOF and masking off the extra bits in the
/// last 64-bit word.
///
/// # Arguments
/// * `reader` - Initialized SHAKE256 XOF reader.
///
/// # Returns
/// A random bit-vector of `p.vec_n_size_64` 64-bit words.
pub fn vect_set_random(p: &HqcParameters, reader: &mut dyn Xof) -> Result<Vec<u64>> {
    // Read random bytes safely
    let mut rand_bytes = vec![0u8; p.vec_n_size_bytes];
    reader.squeeze(&mut rand_bytes)?;

    // Convert bytes to u64 words in little-endian to match C behavior
    let mut v = p.zero_vec_n();

    for (i, chunk) in rand_bytes.chunks_exact(8).enumerate() {
        v[i] = u64::from_le_bytes(chunk.try_into().unwrap()); // ← always 8 bytes
    }
    // Handle remainder once, outside the loop
    let remainder = p.vec_n_size_bytes % 8;
    if remainder > 0 {
        let mut last = [0u8; 8];
        last[..remainder].copy_from_slice(&rand_bytes[p.vec_n_size_bytes - remainder..]);
        v[p.vec_n_size_64 - 1] = u64::from_le_bytes(last);
    }

    // Mask off bits beyond n in the last word
    v[p.vec_n_size_64 - 1] &= p.top_word_mask();

    Ok(v)
}

/// Adds two vectors (XOR operation).
///
/// # Arguments
/// * `v1`   - First input vector.
/// * `v2`   - Second input vector.
/// * `size` - Number of 64-bit words to process.
///
/// # Returns
/// A new vector of `size` 64-bit words with `v1[i] ^ v2[i]`.
pub fn vect_add(v1: &[u64], v2: &[u64], size: usize) -> Vec<u64> {
    v1.iter()
        .zip(v2.iter())
        .take(size)
        .map(|(a, b)| a ^ b)
        .collect()
}

/// Adds two vectors (XOR operation) as a procedure.
///
/// # Arguments
/// * `o`    - Output vector.
/// * `v1`   - First input vector.
/// * `v2`   - Second input vector.
/// * `size` - Number of 64-bit words to process.
///
/// # Returns
/// A new vector of `size` 64-bit words with `v1[i] ^ v2[i]`.
pub fn vect_add_into(o: &mut [u64], v1: &[u64], v2: &[u64]) {
    assert_eq!(v1.len(), v2.len(), "vectors must have equal length");
    for i in 0..v1.len() {
        o[i] = v1[i] ^ v2[i];
    }
}

/// Compares two vectors in constant time.
///
/// Function borrowed from liboqs.
///
/// # Arguments
/// * `v1` - First input vector.
/// * `v2` - Second input vector.
///
/// # Returns
/// `0` if the vectors are equal, `1` otherwise.
pub fn vect_compare(v1: &[u8], v2: &[u8]) -> u8 {
    assert_eq!(v1.len(), v2.len(), "vectors must have equal length");
    let mut r: u16 = 0x0100;
    for i in 0..v1.len() {
        r |= (v1[i] ^ v2[i]) as u16;
    }
    ((r - 1) >> 8) as u8
}

/// Truncates a bit-vector in-place to `p.n1n2` bits,
/// zeroing out all bits beyond that.
///
/// # Arguments
/// * `v` - Bit-vector of `p.vec_n_size_64` 64-bit words to truncate.
pub fn vect_truncate(p: &HqcParameters, v: &mut [u64]) {
    assert_eq!(v.len(), p.vec_n_size_64);
    let new_full_words = p.n1n2 / 64;
    let remaining_bits = p.n1n2 % 64;

    // Mask the partial word at the truncation boundary
    let mut first_zero = new_full_words;
    if remaining_bits > 0 {
        let mask = (1u64 << remaining_bits) - 1;
        v[new_full_words] &= mask;
        first_zero = new_full_words + 1; // keep the partial word
    }

    // Zero out all words beyond the truncation point
    for i in first_zero..p.vec_n_size_64 {
        v[i] = 0;
    }
}

#[cfg(test)]
mod tests;

#[cfg(all(test, feature = "ref-ffi"))]
mod tests_ffi;
