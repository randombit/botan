use crate::error::{HqcError, Result};
use crate::hash::{Callbacks, Xof};
use crate::parameters::{HqcParameters, SALT_BYTES, SEED_BYTES, SHARED_SECRET_BYTES};
use crate::parsing::{hqc_c_kem_from_string, hqc_c_kem_to_string, hqc_dk_pke_from_string};
use crate::pke::{CiphertextPke, hqc_pke_decrypt_expanded, hqc_pke_encrypt, hqc_pke_keygen};
use crate::secmem::SecureBuffer;
use crate::symmetric::{hash_g, hash_h, hash_j, xof_init_dom_sep};
use crate::vector::vect_compare;

/// KEM ciphertext for the HQC scheme.
#[repr(C)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CiphertextKem {
    pub c_pke: CiphertextPke,
    pub salt: [u8; SALT_BYTES],
}

impl CiphertextKem {
    /// A zeroed ciphertext sized for `p`.
    ///
    /// Replaces the former `Default` impl, which cannot exist now that the
    /// buffer lengths depend on the parameter set.
    pub fn zeroed(p: &HqcParameters) -> Self {
        Self {
            c_pke: CiphertextPke::zeroed(p),
            salt: [0u8; SALT_BYTES],
        }
    }
}

/// Derives `seed_pke` (and optionally `sigma`) from the 32-byte KEM master seed.
fn expand_master_seed<'a>(
    p: &HqcParameters,
    cb: &'a dyn Callbacks,
    seed_kem: &[u8; SEED_BYTES],
    with_sigma: bool,
) -> Result<(SecureBuffer<'a, u8>, SecureBuffer<'a, u8>)> {
    let mut ctx = xof_init_dom_sep(cb, seed_kem, p.k as u8)?;
    let mut seed_pke = SecureBuffer::<u8>::zeroed(cb, SEED_BYTES)?;
    ctx.squeeze(&mut seed_pke)?;
    let mut sigma = SecureBuffer::<u8>::zeroed(cb, if with_sigma { p.k } else { 0 })?;
    if with_sigma {
        ctx.squeeze(&mut sigma)?;
    }
    Ok((seed_pke, sigma))
}

/// Derives the encapsulation key that belongs to the decapsulation key
/// `seed_kem` (the 32-byte master seed).
///
/// This is the deterministic part of key generation: seed_kem -> seed_pke ->
/// (ek_pke, dk_pke), of which only ek_pke is returned. The secret
/// intermediate values live in provider memory. Uses variable-time rejection
/// sampling, like key generation itself.
///
/// # Arguments
/// * `cb`       - The caller's callbacks (hashing, secure memory).
/// * `seed_kem` - The decapsulation key.
///
/// # Returns
/// The encapsulation key of `p.ek_bytes` bytes.
pub fn derive_encapsulation_key(
    p: &HqcParameters,
    cb: &dyn Callbacks,
    seed_kem: &[u8; SEED_BYTES],
) -> Result<Vec<u8>> {
    // Derive seed_pke and the HQC-PKE keypair; dk_pke is not needed here
    let (seed_pke, _sigma) = expand_master_seed(p, cb, seed_kem, false)?;
    let seed_pke_arr: &[u8; SEED_BYTES] = (&seed_pke[..]).try_into().unwrap();
    let (ek, _dk_pke) = hqc_pke_keygen(p, cb, seed_pke_arr)?;
    Ok(ek)
}

/// Derandomized key generation: the caller supplies the master seed
/// `seed_kem`, which the specification's `KeyGen` draws from the random
/// number generator, and which *is* the decapsulation key.
///
/// Writes the encapsulation key to `ek_out` (`p.ek_bytes` bytes) and
/// `seed_kem` to `dk_out` (`p.dk_bytes` bytes). The keys are written directly
/// into the caller's buffers; the secret intermediate values live in provider
/// memory.
///
/// # Preconditions
/// `seed_kem` must come from a secure entropy source; otherwise the generated
/// key is insecure/predictable.
pub fn crypto_kem_keypair_derand(
    p: &HqcParameters,
    cb: &dyn Callbacks,
    seed_kem: &[u8; SEED_BYTES],
    ek_out: &mut [u8],
    dk_out: &mut [u8],
) -> Result<()> {
    assert_eq!(ek_out.len(), p.ek_bytes);
    assert_eq!(dk_out.len(), p.dk_bytes);

    let ek = derive_encapsulation_key(p, cb, seed_kem)?;
    ek_out.copy_from_slice(&ek);
    dk_out.copy_from_slice(seed_kem);
    Ok(())
}

/// Generates a keypair for the KEM (Key Encapsulation Mechanism) scheme.
///
/// Samples the 32-byte master seed `seed_kem` from `prng_reader`, exactly as
/// the reference implementation's `randombytes` call does, and continues as
/// [`crypto_kem_keypair_derand`].
///
/// # Preconditions
/// `prng_reader` is the KAT driver's DRBG (any [`Xof`]); production callers
/// use [`crypto_kem_keypair_derand`] with randomness from their own RNG.
///
/// # Arguments
/// * `cb`          - The caller's callbacks (hashing, secure memory).
/// * `prng_reader` - The PRNG reader used to sample `seed_kem`.
/// * `ek_out`      - Receives the encapsulation key.
/// * `dk_out`      - Receives the decapsulation key.
pub fn crypto_kem_keypair(
    p: &HqcParameters,
    cb: &dyn Callbacks,
    prng_reader: &mut dyn Xof,
    ek_out: &mut [u8],
    dk_out: &mut [u8],
) -> Result<()> {
    // Sample the master seed seed_kem
    let mut seed_kem = SecureBuffer::<u8>::zeroed(cb, SEED_BYTES)?;
    prng_reader.squeeze(&mut seed_kem)?;
    let seed_kem_arr: &[u8; SEED_BYTES] = (&seed_kem[..]).try_into().unwrap();

    crypto_kem_keypair_derand(p, cb, seed_kem_arr, ek_out, dk_out)
}

/// Derandomized key encapsulation: the caller supplies the message `m`
/// (`p.security_bytes` bytes) and the `salt`, which the specification's
/// `Encaps` draws from the random number generator.
///
/// # Preconditions
/// `m` and `salt` must come from a secure entropy source and never be reused;
/// otherwise the shared secret is insecure/predictable.
///
/// # Arguments
/// * `cb`     - The caller's callbacks (hashing, secure memory).
/// * `ek_kem` - Encapsulation key.
/// * `m`      - The message, `p.security_bytes` bytes (secret).
/// * `salt`   - The salt.
///
/// # Returns
/// A tuple `(c_kem, K)`:
/// * `c_kem` - Serialized KEM ciphertext.
/// * `K`     - Shared secret of `SHARED_SECRET_BYTES` bytes, in provider memory.
pub fn crypto_kem_enc_derand<'a>(
    p: &HqcParameters,
    cb: &'a dyn Callbacks,
    ek_kem: &[u8],
    m: &[u8],
    salt: &[u8; SALT_BYTES],
) -> Result<(Vec<u8>, SecureBuffer<'a, u8>)> {
    assert_eq!(m.len(), p.security_bytes);

    let mut c_kem_t = CiphertextKem::zeroed(p);
    c_kem_t.salt = *salt;

    // Compute shared key K and encryption randomness theta: K || theta = G(H(ek), m, salt)
    let hash_ek_kem = hash_h(cb, ek_kem)?;

    let mut k_theta = SecureBuffer::<u8>::zeroed(cb, 2 * SEED_BYTES)?;
    hash_g(cb, &hash_ek_kem, m, &c_kem_t.salt, (&mut k_theta[..]).try_into().unwrap())?;
    let theta: &[u8; SEED_BYTES] = (&k_theta[SEED_BYTES..]).try_into().unwrap();

    // Reinterpret m as u64 words for hqc_pke_encrypt
    let mut m_words = SecureBuffer::<u64>::zeroed(cb, m.len().div_ceil(8))?;
    for (word, chunk) in m_words.iter_mut().zip(m.chunks(8)) {
        let mut buf = [0u8; 8];
        buf[..chunk.len()].copy_from_slice(chunk);
        *word = u64::from_le_bytes(buf);
    }

    c_kem_t.c_pke = hqc_pke_encrypt(p, cb, ek_kem, &m_words, theta)?;

    let c_kem = hqc_c_kem_to_string(p, &c_kem_t);
    let k = SecureBuffer::from_slice(cb, &k_theta[..SHARED_SECRET_BYTES])?;

    Ok((c_kem, k))
}

/// Performs key encapsulation using the KEM scheme.
///
/// Samples the message `m` and then the `salt` from `prng_reader` in two
/// separate requests, exactly as the reference implementation's `randombytes`
/// calls do, and continues as [`crypto_kem_enc_derand`].
///
/// # Preconditions
/// `prng_reader` is the KAT driver's DRBG (any [`Xof`]); production callers
/// use [`crypto_kem_enc_derand`] with randomness from their own RNG.
///
/// # Arguments
/// * `cb`          - The caller's callbacks (hashing, secure memory).
/// * `prng_reader` - The PRNG reader used to sample `m` and `salt`.
/// * `ek_kem`      - Encapsulation key.
///
/// # Returns
/// A tuple `(c_kem, K)`:
/// * `c_kem` - Serialized KEM ciphertext.
/// * `K`     - Shared secret of `SHARED_SECRET_BYTES` bytes, in provider memory.
pub fn crypto_kem_enc<'a>(
    p: &HqcParameters,
    cb: &'a dyn Callbacks,
    prng_reader: &mut dyn Xof,
    ek_kem: &[u8],
) -> Result<(Vec<u8>, SecureBuffer<'a, u8>)> {
    // Sample message m and salt
    let mut m = SecureBuffer::<u8>::zeroed(cb, p.security_bytes)?;
    prng_reader.squeeze(&mut m)?;

    let mut salt = [0u8; SALT_BYTES];
    prng_reader.squeeze(&mut salt)?;

    crypto_kem_enc_derand(p, cb, ek_kem, &m, &salt)
}

/// Expanded secret material for repeated decapsulation. Expansion uses the
/// reference rejection sampler and is variable-time. The secret buffers live
/// in provider memory and are released (and thereby scrubbed) on drop.
pub(crate) struct ExpandedKey<'a> {
    ek_pke: Vec<u8>,
    y: SecureBuffer<'a, u64>,
    sigma: SecureBuffer<'a, u8>,
}

pub(crate) fn expand_key<'a>(
    p: &HqcParameters,
    cb: &'a dyn Callbacks,
    dk_kem: &[u8],
) -> Result<ExpandedKey<'a>> {
    let seed_kem: &[u8; SEED_BYTES] = dk_kem.try_into().map_err(|_| HqcError::InvalidKey)?;
    let (seed_pke, sigma) = expand_master_seed(p, cb, seed_kem, true)?;
    let seed_pke_arr: &[u8; SEED_BYTES] = (&seed_pke[..]).try_into().unwrap();
    let (ek_pke, dk_pke) = hqc_pke_keygen(p, cb, seed_pke_arr)?;
    let dk_pke_arr: &[u8; SEED_BYTES] = (&dk_pke[..]).try_into().unwrap();
    let y = hqc_dk_pke_from_string(p, cb, dk_pke_arr)?;
    Ok(ExpandedKey { ek_pke, y, sigma })
}

/// Decapsulates with the upstream-compatible 32-byte seed key.
///
/// Seed expansion uses variable-time rejection sampling. For repeated secret-key
/// operations use [`crate::api::Hqc::expand_decapsulation_key`] once, then the
/// expanded key's decapsulation method, which avoids that sampling entirely.
/// Invalid ciphertexts are handled through branchless implicit rejection.
///
/// # Returns
/// The recovered (or rejection) shared secret `K_prime` of
/// `SHARED_SECRET_BYTES` bytes, in provider memory.
pub fn crypto_kem_dec<'a>(
    p: &HqcParameters,
    cb: &'a dyn Callbacks,
    c_kem: &[u8],
    dk_kem: &[u8],
) -> Result<SecureBuffer<'a, u8>> {
    let key = expand_key(p, cb, dk_kem)?;
    decapsulate_expanded(p, cb, c_kem, &key)
}

/// Decapsulation with cached secret material.
///
/// Constant-time with respect to the key material and derived secrets: the
/// final re-encryption check uses branchless bitmasking (`vect_compare`,
/// `result` accumulation) rather than a data-dependent branch, matching the C
/// implicit-rejection pattern (Fujisaki-Okamoto transform). Secret
/// intermediate values live in provider memory or are heap temporaries
/// zeroized on drop.
pub(crate) fn decapsulate_expanded<'a>(
    p: &HqcParameters,
    cb: &'a dyn Callbacks,
    c_kem: &[u8],
    key: &ExpandedKey<'_>,
) -> Result<SecureBuffer<'a, u8>> {
    let ek_pke = &key.ek_pke;
    let sigma = &key.sigma;

    // Parse ciphertext c_kem
    let (c_pke, salt) = hqc_c_kem_from_string(p, c_kem);
    let c_kem_t = CiphertextKem { c_pke, salt };

    // Compute message m_prime
    let m_prime = hqc_pke_decrypt_expanded(p, cb, &key.y, &c_kem_t.c_pke)?;

    let mut m_prime_bytes = SecureBuffer::<u8>::zeroed(cb, 8 * m_prime.len())?;
    for (chunk, word) in m_prime_bytes.chunks_mut(8).zip(m_prime.iter()) {
        chunk.copy_from_slice(&word.to_le_bytes());
    }
    let m_prime_arr = &m_prime_bytes[..p.security_bytes];

    // Compute shared key K_prime and encryption randomness theta_prime
    let hash_ek_kem = hash_h(cb, ek_pke)?;

    let mut k_theta_prime = SecureBuffer::<u8>::zeroed(cb, 2 * SEED_BYTES)?;
    hash_g(cb, &hash_ek_kem, m_prime_arr, &c_kem_t.salt, (&mut k_theta_prime[..]).try_into().unwrap())?;

    let mut k_prime = SecureBuffer::from_slice(cb, &k_theta_prime[..SHARED_SECRET_BYTES])?;
    let theta_prime: &[u8; SEED_BYTES] = (&k_theta_prime[SHARED_SECRET_BYTES..]).try_into().unwrap();

    // Re-encrypt
    let c_pke_prime = hqc_pke_encrypt(p, cb, ek_pke, &m_prime, theta_prime)?;
    let c_kem_prime_t = CiphertextKem {
        c_pke: c_pke_prime,
        salt: c_kem_t.salt,
    };

    // Compute rejection key K_bar
    let mut k_bar = SecureBuffer::<u8>::zeroed(cb, SHARED_SECRET_BYTES)?;
    hash_j(cb, p, &hash_ek_kem, sigma, &c_kem_t, (&mut k_bar[..]).try_into().unwrap())?;

    // Constant-time comparison of the (public) ciphertexts — implicit rejection (branchless)
    let u_bytes: Vec<u8> = c_kem_t.c_pke.u.iter().flat_map(|w| w.to_le_bytes()).collect();
    let up_bytes: Vec<u8> = c_kem_prime_t.c_pke.u.iter().flat_map(|w| w.to_le_bytes()).collect();
    let v_bytes: Vec<u8> = c_kem_t.c_pke.v.iter().flat_map(|w| w.to_le_bytes()).collect();
    let vp_bytes: Vec<u8> = c_kem_prime_t.c_pke.v.iter().flat_map(|w| w.to_le_bytes()).collect();

    let mut result: u8 = vect_compare(&u_bytes[..p.vec_n_size_bytes], &up_bytes[..p.vec_n_size_bytes]);
    result |= vect_compare(
        &v_bytes[..p.vec_n1n2_size_bytes],
        &vp_bytes[..p.vec_n1n2_size_bytes],
    );
    result |= vect_compare(&c_kem_t.salt, &c_kem_prime_t.salt);
    let result: u8 = result.wrapping_sub(1); // 0xFF if all matched, 0x00 if any mismatched

    for i in 0..SHARED_SECRET_BYTES {
        k_prime[i] = (k_prime[i] & result) ^ (k_bar[i] & !result);
    }

    Ok(k_prime)
}

#[cfg(all(test, feature = "ref-ffi"))]
mod tests_ffi;

#[cfg(test)]
mod tests_kat;
