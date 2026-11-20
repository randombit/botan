use crate::parameters::PARAM_M;

/// Powers of the primitive element alpha = 3 for 1 + x + x^3 + x^4 + x^8.
///
/// The last two elements are needed by `gf_mul`
/// (for example if both elements to multiply are zero).
pub const GF_EXP: [u16; 258] = [
    1, 3, 5, 15, 17, 51, 85, 255, 26, 46, 114, 150, 161, 248, 19, 53, 95, 225, 56, 72, 216, 115,
    149, 164, 247, 2, 6, 10, 30, 34, 102, 170, 229, 52, 92, 228, 55, 89, 235, 38, 106, 190, 217,
    112, 144, 171, 230, 49, 83, 245, 4, 12, 20, 60, 68, 204, 79, 209, 104, 184, 211, 110, 178, 205,
    76, 212, 103, 169, 224, 59, 77, 215, 98, 166, 241, 8, 24, 40, 120, 136, 131, 158, 185, 208,
    107, 189, 220, 127, 129, 152, 179, 206, 73, 219, 118, 154, 181, 196, 87, 249, 16, 48, 80, 240,
    11, 29, 39, 105, 187, 214, 97, 163, 254, 25, 43, 125, 135, 146, 173, 236, 47, 113, 147, 174,
    233, 32, 96, 160, 251, 22, 58, 78, 210, 109, 183, 194, 93, 231, 50, 86, 250, 21, 63, 65, 195,
    94, 226, 61, 71, 201, 64, 192, 91, 237, 44, 116, 156, 191, 218, 117, 159, 186, 213, 100, 172,
    239, 42, 126, 130, 157, 188, 223, 122, 142, 137, 128, 155, 182, 193, 88, 232, 35, 101, 175,
    234, 37, 111, 177, 200, 67, 197, 84, 252, 31, 33, 99, 165, 244, 7, 9, 27, 45, 119, 153, 176,
    203, 70, 202, 69, 207, 74, 222, 121, 139, 134, 145, 168, 227, 62, 66, 198, 81, 243, 14, 18, 54,
    90, 238, 41, 123, 141, 140, 143, 138, 133, 148, 167, 242, 13, 23, 57, 75, 221, 124, 132, 151,
    162, 253, 28, 36, 108, 180, 199, 82, 246, 1, 3, 5,
];

/// Logarithm of elements of GF(2^8) to the base alpha = 3 (field polynomial 1 + x + x^3 + x^4 + x^8).
/// The logarithm of 0 is set to 0 by convention.
pub const GF_LOG: [u16; 256] = [
    0, 0, 25, 1, 50, 2, 26, 198, 75, 199, 27, 104, 51, 238, 223, 3, 100, 4, 224, 14, 52, 141, 129,
    239, 76, 113, 8, 200, 248, 105, 28, 193, 125, 194, 29, 181, 249, 185, 39, 106, 77, 228, 166,
    114, 154, 201, 9, 120, 101, 47, 138, 5, 33, 15, 225, 36, 18, 240, 130, 69, 53, 147, 218, 142,
    150, 143, 219, 189, 54, 208, 206, 148, 19, 92, 210, 241, 64, 70, 131, 56, 102, 221, 253, 48,
    191, 6, 139, 98, 179, 37, 226, 152, 34, 136, 145, 16, 126, 110, 72, 195, 163, 182, 30, 66, 58,
    107, 40, 84, 250, 133, 61, 186, 43, 121, 10, 21, 155, 159, 94, 202, 78, 212, 172, 229, 243,
    115, 167, 87, 175, 88, 168, 80, 244, 234, 214, 116, 79, 174, 233, 213, 231, 230, 173, 232, 44,
    215, 117, 122, 235, 22, 11, 245, 89, 203, 95, 176, 156, 169, 81, 160, 127, 12, 246, 111, 23,
    196, 73, 236, 216, 67, 31, 45, 164, 118, 123, 183, 204, 187, 62, 90, 251, 96, 177, 134, 59, 82,
    161, 108, 170, 85, 41, 157, 151, 178, 135, 144, 97, 190, 220, 252, 188, 149, 207, 205, 55, 63,
    91, 209, 83, 57, 132, 60, 65, 162, 109, 71, 20, 42, 158, 93, 86, 242, 211, 171, 68, 17, 146,
    217, 35, 32, 46, 137, 180, 124, 184, 38, 119, 153, 227, 165, 103, 74, 237, 222, 197, 49, 254,
    24, 13, 99, 140, 128, 192, 247, 112, 7,
];

/// Generates exp and log lookup tables of GF(2^m).
///
/// Note: This function is not used in the code; it was used to generate
/// the lookup table for GF(2^8).
///
/// The logarithm of 0 is defined as 0 by convention.
/// The last two elements of the exp table are needed by `gf_mul`.
///
/// # Arguments
/// * `m` - Parameter of Galois field GF(2^m).
///
/// # Returns
/// A tuple `(exp, log)` where:
/// * `exp` - Array of size `2^m + 2` containing powers of the primitive element.
/// * `log` - Array of size `2^m` containing logarithms of GF(2^m) elements.
pub fn gf_generate(m: u16) -> (Vec<u16>, Vec<u16>) {
    let field_size = 1usize << m;
    let mut exp = vec![0u16; field_size + 2];
    let mut log = vec![0u16; field_size];

    let alpha: u16 = 3; // primitive element of GF(2^m)
    let mut elt: u16 = 1;

    for i in 0..field_size - 1 {
        exp[i] = elt;
        log[elt as usize] = i as u16;

        elt = gf_mul(elt, alpha);
    }

    exp[field_size - 1] = 1;
    exp[field_size] = alpha;
    exp[field_size + 1] = gf_mul(alpha, alpha);
    log[0] = 0; // by convention

    (exp, log)
}

/// Feedback bit positions used for modular reduction by `PARAM_GF_POLY` = 0x11B.
///
/// These values are derived from the binary form of the polynomial:
/// `0x11B = 0b100011011` → bits set at positions: 8, 4, 3, 1, 0.
///
/// To reduce a polynomial modulo this irreducible polynomial:
/// - Bit 8 (the leading term) is handled via shifting: `mod = x >> 8`
/// - Bit 0 (constant term) is handled by the initial XOR
///
/// The remaining set bits at positions 4, 3, and 1 define where the shifted
/// high bits (`mod`) must be XORed back into the result. These represent the
/// feedback positions used during reduction.
pub const GF_REDUCTION_TAPS: [u8; 3] = [4, 3, 1];

/// Reduces a polynomial modulo `PARAM_GF_POLY` in GF(2^8).
///
/// Performs modular reduction of a 16-bit polynomial `x`
/// by the irreducible polynomial `PARAM_GF_POLY` = 0x11B
/// (i.e., x⁸ + x⁴ + x³ + x + 1), used in GF(2^8).
///
/// Assumes the input polynomial has degree ≤ 14 and uses a fixed
/// number of reduction steps and fixed feedback tap positions
/// (`{4, 3, 1}`) to produce a result of degree < 8.
///
/// # Arguments
/// * `x` - 16-bit input polynomial to reduce (deg(x) ≤ 14).
///
/// # Returns
/// Reduced 8-bit polynomial modulo `PARAM_GF_POLY` (deg(x) < 8).
pub fn gf_reduce(mut x: u16) -> u16 {
    const REDUCTION_STEPS: usize = 2; // deg(x) = 2*(8-1) = 14 → reduce twice
    const TAP_COUNT: usize = 3; // number of feedback positions

    for _ in 0..REDUCTION_STEPS {
        let mut m: u64 = (x >> PARAM_M) as u64; // extract upper bits
        x &= (1u16 << PARAM_M) - 1; // keep lower bits
        x ^= m as u16; // pre-XOR with no shift

        let mut z1: u16 = 0;
        for j in (0..TAP_COUNT).rev() {
            let z2 = GF_REDUCTION_TAPS[j] as u16;
            let dist = z2 - z1;
            m <<= dist;
            x ^= m as u16;
            z1 = z2;
        }
    }

    x
}

/// Constant-time equality-to-zero mask.
///
/// # Returns
/// `0xFFFFFFFF` if `x == 0`, `0x00000000` otherwise.
#[inline]
fn eq_zero_mask_u32(x: u32) -> u32 {
    // (x | -x) has its MSB set iff x != 0 (standard branchless nonzero test)
    let t = x | x.wrapping_neg();
    (t >> 31).wrapping_sub(1)
}

/// Carry-less multiplication of two GF(2) polynomials (byte-sized).
///
/// Implementation of algorithm `mul1` from
/// <https://hal.inria.fr/inria-00188261v4/document> with s=2, w=8.
///
/// Constant-time: no secret-dependent branches or memory accesses.
///
/// # Arguments
/// * `a` - First polynomial (secret).
/// * `b` - Second polynomial (secret).
///
/// # Returns
/// `[lo, hi]` — the carryless product split into low and high bytes.
pub fn gf_carryless_mul(a: u8, b: u8) -> [u8; 2] {
    let mut u = [0u16; 4];
    u[0] = 0;
    u[1] = (b as u16) & ((1u16 << 7) - 1);
    u[2] = u[1] << 1;
    u[3] = u[2] ^ u[1];

    let tmp1 = (a as u16) & 3;
    let mut g: u16 = 0;
    for i in 0..4u32 {
        let tmp2 = (tmp1 as u32).wrapping_sub(i);
        let mask = eq_zero_mask_u32(tmp2) as u16;
        g ^= u[i as usize] & mask;
    }
    let mut l: u16 = g;
    let mut h: u16 = 0;

    // Idiomatic replacement for the while loop
    for i in (2..8u8).step_by(2) {
        g = 0;
        let tmp3 = ((a >> i) as u16) & 3;
        for j in 0..4u32 {
            let tmp2 = (tmp3 as u32).wrapping_sub(j);
            let mask = eq_zero_mask_u32(tmp2) as u16;
            g ^= u[j as usize] & mask;
        }
        l ^= g << i;
        h ^= g >> (8 - i);
    }

    let bit7_mask: u16 = ((b >> 7) & 1) as u16;
    let mask: u16 = bit7_mask.wrapping_neg();
    l ^= ((a as u16) << 7) & mask;
    h ^= ((a as u16) >> 1) & mask;

    [l as u8, h as u8]
}

/// Multiplies two elements of GF(2^PARAM_M).
///
/// (delegates to `gf_carryless_mul` and `gf_reduce`, both constant-time).
///
/// # Arguments
/// * `a` - Element of GF(2^PARAM_M).
/// * `b` - Element of GF(2^PARAM_M).
///
/// # Returns
/// The product `a * b` in GF(2^PARAM_M).
pub fn gf_mul(a: u16, b: u16) -> u16 {
    let c = gf_carryless_mul(a as u8, b as u8);
    let tmp = (c[0] as u16) ^ ((c[1] as u16) << 8);
    gf_reduce(tmp)
}

/// Squares an element of GF(2^PARAM_M).
///
///
/// # Arguments
/// * `a` - Element of GF(2^PARAM_M).
///
/// # Returns
/// `a^2` in GF(2^PARAM_M).
pub fn gf_square(a: u16) -> u16 {
    let mut b: u32 = a as u32;
    let mut s: u32 = b & 1;

    for i in 1..PARAM_M {
        b <<= 1;
        s ^= b & (1u32 << (2 * i));
    }

    gf_reduce(s as u16)
}

/// Computes the inverse of an element of GF(2^8),
/// using the addition chain 1, 2, 3, 4, 7, 11, 15, 30, 60, 120, 127, 254.
///
/// # Arguments
/// * `a` - Element of GF(2^PARAM_M).
///
/// # Returns
/// The inverse of `a` in GF(2^PARAM_M).
pub fn gf_inverse(a: u16) -> u16 {
    let mut inv: u16 = gf_square(a); // a^2
    let tmp1: u16 = gf_mul(inv, a); // a^3
    inv = gf_square(inv); // a^4
    let tmp2: u16 = gf_mul(inv, tmp1); // a^7
    let tmp1: u16 = gf_mul(inv, tmp2); // a^11
    inv = gf_mul(tmp1, inv); // a^15
    inv = gf_square(inv); // a^30
    inv = gf_square(inv); // a^60
    inv = gf_square(inv); // a^120
    inv = gf_mul(inv, tmp2); // a^127
    inv = gf_square(inv); // a^254
    inv
}

#[cfg(all(test, feature = "ref-ffi"))]
mod tests_ffi;
