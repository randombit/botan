use crate::code::{code_decode, code_encode};
use crate::error::Result;
use crate::gf2x::vect_mul;
use crate::hash::Callbacks;
use crate::parameters::{HqcParameters, SEED_BYTES};
use crate::parsing::{hqc_dk_pke_from_string, hqc_ek_pke_from_string};
use crate::secmem::{SecretVec, SecureBuffer};
use crate::symmetric::{hash_i, xof_init};
use crate::vector::{
    vect_add_into, vect_sample_fixed_weight1, vect_sample_fixed_weight2, vect_set_random,
    vect_truncate,
};

/// Unpack an `u64` slice into a `Vec<u8>`, little-endian.
/// TODO Add helper module
pub fn u64_words_to_bytes(words: &[u64]) -> Vec<u8> {
    words.iter().flat_map(|w| w.to_le_bytes()).collect()
}

/// Generates a key pair for the HQC public-key encryption (PKE) scheme.
///
/// Creates a public encryption key (`ek_pke`) and a private decryption key
/// (`dk_pke`) for use in the HQC PKE scheme, deterministically derived
/// from `seed`.
///
/// Secret intermediate values (the derived seeds, `x`, `y`) live in provider
/// memory; the product `y * h` is a heap temporary zeroized on drop.
///
/// # Arguments
/// * `cb`   - The caller's callbacks (hashing, secure memory).
/// * `seed` - Seed used to deterministically generate the key pair.
///
/// # Returns
/// A tuple `(ek_pke, dk_pke)`:
/// * `ek_pke` - Encryption key of `SEED_BYTES + p.vec_n_size_bytes` bytes.
/// * `dk_pke` - Decryption key of `SEED_BYTES` bytes, in provider memory.
pub fn hqc_pke_keygen<'a>(
    p: &HqcParameters,
    cb: &'a dyn Callbacks,
    seed: &[u8; SEED_BYTES],
) -> Result<(Vec<u8>, SecureBuffer<'a, u8>)> {
    // Derive keypair seeds: I(seed) = seed_dk || seed_ek
    let mut keypair_seed = SecureBuffer::<u8>::zeroed(cb, 2 * SEED_BYTES)?;
    hash_i(cb, seed, (&mut keypair_seed[..]).try_into().unwrap())?;

    let seed_dk: &[u8; SEED_BYTES] = (&keypair_seed[..SEED_BYTES]).try_into().unwrap();
    let seed_ek: [u8; SEED_BYTES] = keypair_seed[SEED_BYTES..].try_into().unwrap();

    // Compute decryption key
    let mut dk_reader = xof_init(cb, seed_dk)?;
    let y = vect_sample_fixed_weight1(p, cb, dk_reader.as_mut(), p.omega)?;
    let x = vect_sample_fixed_weight1(p, cb, dk_reader.as_mut(), p.omega)?;

    // Compute encryption key
    let mut ek_reader = xof_init(cb, &seed_ek)?;
    let h = vect_set_random(p, ek_reader.as_mut())?;

    // y * h reveals y given the public h, so it is a secret temporary
    let s = SecretVec::from_vec(vect_mul(p, &y, &h));
    let mut s_final = p.zero_vec_n();
    vect_add_into(&mut s_final, &x, &s);

    // Parse encryption key to bytes
    let mut ek_pke = Vec::with_capacity(SEED_BYTES + p.vec_n_size_bytes);
    ek_pke.extend_from_slice(&seed_ek);
    ek_pke.extend_from_slice(&u64_words_to_bytes(&s_final)[..p.vec_n_size_bytes]);

    // The decryption key is seed_dk
    let dk_pke = SecureBuffer::from_slice(cb, seed_dk)?;

    Ok((ek_pke, dk_pke))
}

/// PKE ciphertext for the HQC scheme.
///
/// `#[repr(C)]` was dropped with the move to runtime parameters: no FFI
/// declaration passes this struct by pointer any more (phase 1 moved all
/// marshalling to pointer+length), so a fixed layout bought nothing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CiphertextPke {
    pub u: Vec<u64>,
    pub v: Vec<u64>,
}

impl CiphertextPke {
    pub fn zeroed(p: &HqcParameters) -> Self {
        Self {
            u: p.zero_vec_n(),
            v: p.zero_vec_n(),
        }
    }
}

/// Encrypts a message using the HQC public-key encryption (PKE) scheme.
///
/// Uses the given encryption key (`ek_pke`) and encryption randomness
/// (`theta`) to encrypt the message `m`, producing a ciphertext `c_pke`.
///
/// # Arguments
/// * `cb`     - The caller's callbacks (hashing, secure memory).
/// * `ek_pke` - Encryption key.
/// * `m`      - Message to be encrypted, `p.vec_k_size_64` words.
/// * `theta`  - Encryption randomness, `SEED_BYTES` bytes.
///
/// # Returns
/// The PKE ciphertext.
pub fn hqc_pke_encrypt(
    p: &HqcParameters,
    cb: &dyn Callbacks,
    ek_pke: &[u8],
    m: &[u64],
    theta: &[u8; SEED_BYTES],
) -> Result<CiphertextPke> {
    let mut c_pke = CiphertextPke::zeroed(p);

    // Initialize Xof using theta
    let mut theta_reader = xof_init(cb, theta)?;

    // Retrieve h and s from public key
    let (h, s) = hqc_ek_pke_from_string(p, cb, ek_pke)?;

    // Generate r2, e and r1
    let r2 = vect_sample_fixed_weight2(p, cb, theta_reader.as_mut(), p.omega_r)?;
    let e = vect_sample_fixed_weight2(p, cb, theta_reader.as_mut(), p.omega_e)?;
    let r1 = vect_sample_fixed_weight2(p, cb, theta_reader.as_mut(), p.omega_r)?;

    // Compute u = r1 + r2.h  (r2.h alone would reveal r1 from the public u)
    let r2_h = SecretVec::from_vec(vect_mul(p, &r2, &h));
    vect_add_into(&mut c_pke.u, &r1, &r2_h);

    // Compute v = C.encode(m)
    let encoded = code_encode(p, m);
    c_pke.v[..p.vec_n1n2_size_64].copy_from_slice(&encoded);

    // Compute v = C.encode(m) + Truncate(s.r2 + e)
    let r2_s = SecretVec::from_vec(vect_mul(p, &r2, &s));
    let mut tmp = SecretVec::<u64>::zeroed(p.vec_n_size_64);
    vect_add_into(&mut tmp, &e, &r2_s);
    let mut tmp_trunc = SecretVec::<u64>::zeroed(p.vec_n_size_64);
    tmp_trunc.copy_from_slice(&tmp);
    vect_truncate(p, &mut tmp_trunc);

    let mut v_final = SecretVec::<u64>::zeroed(p.vec_n1n2_size_64);
    vect_add_into(
        &mut v_final,
        &c_pke.v[..p.vec_n1n2_size_64],
        &tmp_trunc[..p.vec_n1n2_size_64],
    );
    c_pke.v[..p.vec_n1n2_size_64].copy_from_slice(&v_final);

    Ok(c_pke)
}

/// Decrypts a ciphertext using the HQC public-key encryption (PKE) scheme.
///
/// Expands the seed with variable-time rejection sampling, then performs
/// fixed-work vector multiplication and decoding. Use the expanded KEM key API
/// when seed expansion must stay outside repeated decapsulation.
///
/// # Arguments
/// * `cb`     - The caller's callbacks (hashing, secure memory).
/// * `dk_pke` - Decryption key.
/// * `c_pke`  - Input PKE ciphertext.
///
/// # Returns
/// The decrypted message `m` of `p.vec_k_size_64` words, in provider memory.
pub fn hqc_pke_decrypt<'a>(
    p: &HqcParameters,
    cb: &'a dyn Callbacks,
    dk_pke: &[u8; SEED_BYTES],
    c_pke: &CiphertextPke,
) -> Result<SecureBuffer<'a, u64>> {
    let y = hqc_dk_pke_from_string(p, cb, dk_pke)?;
    hqc_pke_decrypt_expanded(p, cb, &y, c_pke)
}

/// Decrypt with an already expanded secret vector. No rejection sampling occurs.
///
/// Secret intermediate values are heap temporaries zeroized on drop; the
/// result is returned in provider memory.
pub(crate) fn hqc_pke_decrypt_expanded<'a>(
    p: &HqcParameters,
    cb: &'a dyn Callbacks,
    y: &[u64],
    c_pke: &CiphertextPke,
) -> Result<SecureBuffer<'a, u64>> {
    // Compute u.y
    let uy = SecretVec::from_vec(vect_mul(p, y, &c_pke.u));

    // Truncate(u.y)
    let mut tmp1 = SecretVec::<u64>::zeroed(p.vec_n_size_64);
    tmp1.copy_from_slice(&uy);
    vect_truncate(p, &mut tmp1);

    // Compute v - Truncate(u.y)
    let mut tmp2 = SecretVec::<u64>::zeroed(p.vec_n_size_64);
    vect_add_into(
        &mut tmp2[..p.vec_n1n2_size_64],
        &c_pke.v[..p.vec_n1n2_size_64],
        &tmp1[..p.vec_n1n2_size_64],
    );

    // Compute plaintext m and move it to provider memory
    let m = code_decode(p, &tmp2[..p.vec_n1n2_size_64]);
    SecureBuffer::from_slice(cb, &m)
}

#[cfg(all(test, feature = "ref-ffi"))]
mod tests_ffi;
