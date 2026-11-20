use crate::fft::{fft, fft_retrieve_error_poly};
use crate::gf::{gf_inverse, gf_mul, GF_EXP, GF_LOG};
use crate::secmem::{zeroize_slice, SecretVec};
use crate::parameters::{HqcParameters, PARAM_GF_MUL_ORDER, PARAM_M};




/// TODO move to gf module?
/// Returns `i` modulo the given modulus.
///
/// `i` must be less than `2 * modulus`. The return value is either
/// `i` or `i - modulus`.
///
/// # Arguments
/// * `i`       - The integer whose modulo is taken.
/// * `modulus` - The modulus.
///
/// # Returns
/// `i mod modulus`.
#[inline]
pub fn gf_mod(i: u16, modulus: u16) -> u16 {
    let tmp: u16 = i.wrapping_sub(modulus);
    // mask = 0xFFFF if tmp's sign bit is set (i.e. i < modulus), else 0x0000
    let mask: i16 = -((tmp >> 15) as i16);
    tmp.wrapping_add((mask as u16) & modulus)
}

/// Computes and prints the generator polynomial of the primitive Reed-Solomon code
/// with given parameters.
///
/// Code length is `2^m - 1`. `p.delta` is the targeted correction
/// capacity of the code.
pub fn print_generator_poly(p: &HqcParameters) {
    let mut poly = vec![0u16; 2 * p.delta + 1];
    poly[0] = 1;
    let mut tmp_degree: usize = 0;

    for i in 1..(2 * p.delta + 1) as u16 {
        for j in (1..=tmp_degree).rev() {
            poly[j] = GF_EXP
                [gf_mod(GF_LOG[poly[j] as usize] + i, PARAM_GF_MUL_ORDER as u16) as usize]
                ^ poly[j - 1];
        }
        poly[0] = GF_EXP[gf_mod(GF_LOG[poly[0] as usize] + i, PARAM_GF_MUL_ORDER as u16) as usize];
        tmp_degree += 1;
        poly[tmp_degree] = 1;
    }

    println!("{:?}", poly);
}

/// Reed-Solomon generator polynomial coefficients as u16 (for gf_mul).
/// Encodes a message of `p.k` bits to a Reed-Solomon codeword of
/// `p.n1` bytes.
///
/// Following Lin & Costello, "Error Control Coding" (Chapter 4 - Cyclic
/// Codes), performs systematic encoding using a linear
/// `(p.n1 - p.k)`-stage shift register with feedback connections
/// based on the generator polynomial `p.rs_poly`.
///
/// # Arguments
/// * `msg` - Input message of `p.vec_k_size_64` 64-bit words.
///
/// # Returns
/// Encoded codeword of `p.vec_n1_size_64` 64-bit words.
pub fn reed_solomon_encode(p: &HqcParameters, msg: &[u64]) -> Vec<u64> {
    // Extract p.k message bytes from the u64 words (little-endian)
    let msg_bytes_full: Vec<u8> = msg.iter().flat_map(|w| w.to_le_bytes()).collect();
    let msg_bytes = &msg_bytes_full[..p.k];

    let mut cdw_bytes = vec![0u8; p.n1];
    let mut tmp = vec![0u16; p.g];

    let shift_len = p.n1 - p.k; // number of shift-register stages

    for i in 0..p.k {
        let gate_value: u8 = msg_bytes[p.k - 1 - i] ^ cdw_bytes[shift_len - 1];

        for j in 0..p.g {
            tmp[j] = gf_mul(gate_value as u16, p.rs_poly[j]);
        }

        for k in (1..shift_len).rev() {
            cdw_bytes[k] = cdw_bytes[k - 1] ^ (tmp[k] as u8);
        }
        cdw_bytes[0] = tmp[0] as u8;
    }

    // Append the message bytes after the parity bytes
    cdw_bytes[shift_len..shift_len + p.k].copy_from_slice(msg_bytes);

    // Repack cdw_bytes into u64 words (little-endian), zero-padding the tail
    let word_count = p.vec_n1_size_64;
    let mut cdw = vec![0u64; word_count];
    for (i, chunk) in cdw_bytes.chunks(8).enumerate() {
        let mut buf = [0u8; 8];
        buf[..chunk.len()].copy_from_slice(chunk);
        cdw[i] = u64::from_le_bytes(buf);
    }

    cdw
}

/// Computes `2 * p.delta` syndromes.
///
/// # Arguments
/// * `cdw` - Received vector of `p.n1` bytes.
///
/// # Returns
/// Array of `2 * p.delta` computed syndromes.
pub fn compute_syndromes(p: &HqcParameters, cdw: &[u8]) -> SecretVec<u16> {
    let mut syndromes = SecretVec::<u16>::zeroed(2 * p.delta);

    for i in 0..2 * p.delta {
        for j in 1..p.n1 {
            syndromes[i] ^= gf_mul(cdw[j] as u16, p.alpha_ij_pow(i)[j - 1]);
        }
        syndromes[i] ^= cdw[0] as u16;
    }

    syndromes
}

/// Computes the error locator polynomial (ELP) sigma.
///
/// Constant-time implementation of Berlekamp's algorithm (see Lin &
/// Costello, "Error Control Coding", Chapter 6 - BCH Codes). Uses `p` for
/// rho, initialized at -1. `x_sigma_p` represents the polynomial
/// `X^(mu-rho) * sigma_p(X)`. Instead of maintaining a list of sigmas,
/// both `sigma` and `x_sigma_p` are updated in place. `sigma_copy` is a
/// temporary save of `sigma` in case `x_sigma_p` needs updating.
///
/// # Arguments
/// * `syndromes` - Array of at least `2*p.delta` syndromes.
///
/// # Returns
/// A tuple `(sigma, deg_sigma)`: the ELP coefficients and its degree.
pub fn compute_elp(p: &HqcParameters, syndromes: &[u16]) -> (SecretVec<u16>, u16) {
    let mut sigma = SecretVec::<u16>::zeroed(p.delta + 1);
    let mut sigma_copy = vec![0u16; p.delta + 1];
    let mut x_sigma_p = vec![0u16; p.delta + 1];
    x_sigma_p[1] = 1;

    let mut deg_sigma: u16 = 0;
    let mut deg_sigma_p: u16 = 0;
    let mut deg_sigma_copy: u16;

    let mut pp: u16 = 0xFFFFu16; // (uint16_t)-1, i.e. 2*rho
    let mut d_p: u16 = 1;
    let mut d: u16 = syndromes[0];

    sigma[0] = 1;

    for mu in 0..(2 * p.delta) as u16 {
        // Save sigma in case we need it to update x_sigma_p
        sigma_copy[..p.delta].copy_from_slice(&sigma[..p.delta]);
        deg_sigma_copy = deg_sigma;

        let dd = gf_mul(d, gf_inverse(d_p));

        let upper = core::cmp::min((mu + 1) as usize, p.delta);
        for i in 1..=upper {
            sigma[i] ^= gf_mul(dd, x_sigma_p[i]);
        }

        let deg_x = mu.wrapping_sub(pp);
        let deg_x_sigma_p = deg_x.wrapping_add(deg_sigma_p);

        // mask1 = 0xFFFF if d != 0, else 0x0000
        let mask1: u16 = (d.wrapping_neg() >> 15).wrapping_neg();
        // mask2 = 0xFFFF if deg_x_sigma_p > deg_sigma, else 0x0000
        let mask2: u16 = (deg_sigma.wrapping_sub(deg_x_sigma_p) >> 15).wrapping_neg();

        // mask12 = 0xFFFF if deg_sigma increased, else 0x0000
        // core::hint::black_box mirrors the C `volatile` hint, preventing
        // the compiler from optimizing away/reordering the masked update.
        let mask12: u16 = core::hint::black_box(mask1 & mask2);

        deg_sigma ^= mask12 & (deg_x_sigma_p ^ deg_sigma);

        if mu == (2 * p.delta - 1) as u16 {
            break;
        }

        pp ^= mask12 & (mu ^ pp);
        d_p ^= mask12 & (d ^ d_p);

        for i in (1..=p.delta).rev() {
            x_sigma_p[i] = (mask12 & sigma_copy[i - 1]) ^ (!mask12 & x_sigma_p[i - 1]);
        }

        deg_sigma_p ^= mask12 & (deg_sigma_copy ^ deg_sigma_p);

        d = syndromes[(mu + 1) as usize];
        let upper = core::cmp::min((mu + 1) as usize, p.delta);
        for i in 1..=upper {
            d ^= gf_mul(sigma[i], syndromes[(mu + 1) as usize - i]);
        }
    }

    (sigma, deg_sigma)
}

/// Computes the error polynomial from the error locator polynomial sigma.
///
/// See `fft` for more details.
///
/// # Arguments
/// * `sigma` - Array of `2^p.fft_exp` elements storing the error locator polynomial.
/// * `error` - Output array of `2^PARAM_M` elements receiving the error polynomial.
pub fn compute_roots(p: &HqcParameters, error: &mut [u8], sigma: &[u16]) {
    let w = fft(sigma, p.delta + 1, p.fft_exp);
    fft_retrieve_error_poly(error, &w);
}

/// Computes the polynomial z(x).
///
/// See Lin & Costello, "Error Control Coding", Chapter 6 - BCH Codes,
/// for more details.
///
/// # Arguments
/// * `sigma`     - Array of `2^p.fft_exp` elements, the error locator polynomial.
/// * `degree`    - Degree of polynomial `sigma`.
/// * `syndromes` - Array of `2*p.delta` syndromes.
///
/// # Returns
/// Array of `p.delta + 1` elements: the polynomial z(x).
pub fn compute_z_poly(
    p: &HqcParameters,
    sigma: &[u16],
    degree: u16,
    syndromes: &[u16],
) -> SecretVec<u16> {
    let mut z = SecretVec::<u16>::zeroed(p.delta + 1);
    z[0] = 1;

    for i in 1..p.delta + 1 {
        // mask = 0xFFFF if i <= degree, else 0x0000
        // matches C: -((uint16_t)(i - degree - 1) >> 15)
        let diff: u16 = (i as u16).wrapping_sub(degree).wrapping_sub(1);
        let mask: u16 = (diff >> 15).wrapping_neg();
        z[i] = mask & sigma[i];
    }

    z[1] ^= syndromes[0];

    for i in 2..=p.delta {
        let diff: u16 = (i as u16).wrapping_sub(degree).wrapping_sub(1);
        let mask: u16 = (diff >> 15).wrapping_neg();

        z[i] ^= mask & syndromes[i - 1];

        for j in 1..i {
            z[i] ^= mask & gf_mul(sigma[j], syndromes[i - j - 1]);
        }
    }

    z
}

/// Branchless "nonzero" mask matching C's `-((int32_t)x) >> 31` idiom.
///
/// # Returns
/// `0xFFFF` if `x != 0`, `0x0000` if `x == 0`.
#[inline]
fn mask_nonzero_i32(x: i32) -> u16 {
    ((-x) >> 31) as u16
}

/// Computes the error values.
///
/// See Lin & Costello, "Error Control Coding", Chapter 6 - BCH Codes,
/// for more details.
///
/// # Arguments
/// * `z`     - Array of `p.delta + 1` elements, the polynomial z(x).
/// * `error` - Array of `p.n1` bytes storing the error positions.
///
/// # Returns
/// Array of `p.n1` elements containing the error values.
pub fn compute_error_values(p: &HqcParameters, z: &[u16], error: &[u8]) -> SecretVec<u16> {
    let mut beta_j = vec![0u16; p.delta];
    let mut e_j = vec![0u16; p.delta];
    let mut error_values = SecretVec::<u16>::zeroed(p.n1);

    // Compute the beta_{j_i}
    let mut delta_counter: u16 = 0;
    for i in 0..p.n1 {
        let mut found: u16 = 0;
        let mask1: u16 = mask_nonzero_i32(error[i] as i32); // error[i] != 0
        for j in 0..p.delta {
            let xorv = (j as i32) ^ (delta_counter as i32);
            let mask2: u16 = !mask_nonzero_i32(xorv); // j == delta_counter
            beta_j[j] = beta_j[j].wrapping_add(mask1 & mask2 & GF_EXP[i]);
            found = found.wrapping_add(mask1 & mask2 & 1);
        }
        delta_counter = delta_counter.wrapping_add(found);
    }
    let delta_real_value = delta_counter;

    // Compute the e_{j_i}
    for i in 0..p.delta {
        let mut tmp1: u16 = 1;
        let mut tmp2: u16 = 1;
        let inverse = gf_inverse(beta_j[i]);
        let mut inverse_power_j: u16 = 1;

        for j in 1..=p.delta {
            inverse_power_j = gf_mul(inverse_power_j, inverse);
            tmp1 ^= gf_mul(inverse_power_j, z[j]);
        }
        for k in 1..p.delta {
            tmp2 = gf_mul(tmp2, 1 ^ gf_mul(inverse, beta_j[(i + k) % p.delta]));
        }

        // mask1 = 0xFFFF if i < delta_real_value, else 0x0000
        let diff: i32 = (i as i32) - (delta_real_value as i32);
        let mask1: u16 = (diff >> 15) as u16;

        e_j[i] = mask1 & gf_mul(tmp1, gf_inverse(tmp2));
    }

    // Place the delta e_{j_i} values at the right coordinates of the output vector
    let mut delta_counter: u16 = 0;
    for i in 0..p.n1 {
        let mut found: u16 = 0;
        let mask1: u16 = mask_nonzero_i32(error[i] as i32); // error[i] != 0
        for j in 0..p.delta {
            let xorv = (j as i32) ^ (delta_counter as i32);
            let mask2: u16 = !mask_nonzero_i32(xorv); // j == delta_counter
            error_values[i] = error_values[i].wrapping_add(mask1 & mask2 & e_j[j]);
            found = found.wrapping_add(mask1 & mask2 & 1);
        }
        delta_counter = delta_counter.wrapping_add(found);
    }

    error_values
}

/// Corrects the errors in the received codeword.
///
/// # Arguments
/// * `cdw`          - Codeword of `p.n1` bytes, corrected in place.
/// * `error_values` - Array of `p.n1` elements storing the error values.
pub fn correct_errors(p: &HqcParameters, cdw: &mut [u8], error_values: &[u16]) {
    for i in 0..p.n1 {
        cdw[i] ^= error_values[i] as u8;
    }
}

/// Decodes the received word.
///
/// This function relies on six steps:
/// 1. Compute the `2*p.delta` syndromes.
/// 2. Compute the error-locator polynomial σ(x).
/// 3. Use an additive FFT to find the roots of σ(x) (the error locations) and take their inverses.
/// 4. Compute the error-evaluator polynomial z(x).
/// 5. Compute the error values at each located position.
/// 6. Correct the received polynomial by subtracting the error values.
///
/// See Lin & Costello, "Error Control Coding: Fundamentals and
/// Applications" for a complete picture on Reed-Solomon decoding.
///
/// # Arguments
/// * `cdw` - Received word of `p.vec_n1_size_64` 64-bit words.
///
/// # Returns
/// Decoded message of `p.vec_k_size_64` 64-bit words.
pub fn reed_solomon_decode(p: &HqcParameters, cdw: &[u64]) -> Vec<u64> {
    // Copy the vector into an array of bytes
    let cdw_bytes_full: Vec<u8> = cdw.iter().flat_map(|w| w.to_le_bytes()).collect();
    let mut cdw_bytes: Vec<u8> = cdw_bytes_full[..p.n1].to_vec();

    // Step 1: compute the 2*p.delta syndromes
    let syndromes = compute_syndromes(p, &cdw_bytes);

    // Step 2: compute the error locator polynomial sigma
    // Sigma's degree is at most p.delta but the FFT requires the extra room
    let (sigma_short, deg) = compute_elp(p, &syndromes);
    let mut sigma = vec![0u16; 1usize << p.fft_exp];
    sigma[..sigma_short.len()].copy_from_slice(&sigma_short);

    // Step 3: compute the error polynomial `error` (roots of sigma via FFT)
    let mut error = vec![0u8; 1usize << PARAM_M];
    compute_roots(p, &mut error, &sigma);

    // Step 4: compute the polynomial z(x)
    let z = compute_z_poly(p, &sigma, deg, &syndromes);

    // Step 5: compute the error values
    let error_values = compute_error_values(p, &z, &error);

    // Step 6: correct the errors
    correct_errors(p, &mut cdw_bytes, &error_values);

    // Retrieve the message from the decoded codeword
    let msg_bytes = &cdw_bytes[(p.g - 1)..(p.g - 1) + p.k];

    // Repack into u64 words
    let word_count = p.vec_k_size_64;
    let mut msg = vec![0u64; word_count];
    for (i, chunk) in msg_bytes.chunks(8).enumerate() {
        let mut buf = [0u8; 8];
        buf[..chunk.len()].copy_from_slice(chunk);
        msg[i] = u64::from_le_bytes(buf);
    }

    // Zeroize sensitive data TODO use specific zerorization crate
    zeroize_slice(&mut cdw_bytes);

    msg
}
