pub use crate::kem::CiphertextKem;
use crate::error::Result;
use crate::hash::{HashProvider, Xof};
use crate::parameters::{HqcParameters, SALT_BYTES, SEED_BYTES};
use crate::pke::u64_words_to_bytes;

/// Domain separator for HQC prng function.
pub const PRNG_DOMAIN: u8 = 0;

/// Domain separator for the G(·) function in HQC.
pub const G_FCT_DOMAIN: u8 = 0;

/// Domain separator for the H(·) function in HQC.
pub const H_FCT_DOMAIN: u8 = 1;

/// Domain separator for the I(·) function in HQC.
pub const I_FCT_DOMAIN: u8 = 2;

/// Domain separator for the J(·) function in HQC.
pub const J_FCT_DOMAIN: u8 = 3;

/// SHAKE-256 with incremental API and domain separation.
///
/// Derived from the `SHAKE_256` construction. Initializes a SHAKE-256 XOF
/// by absorbing entropy, a personalization string, and a domain separator,
/// then finalizing into squeeze mode.
///
/// # Arguments
/// * `hash`                   - The hash provider.
/// * `entropy_input`          - Input entropy bytes.
/// * `personalization_string` - Personalization string.
///
/// # Returns
/// An initialized [`Xof`] ready for squeezing pseudorandom bytes.
pub fn prng_init<'a>(
    hash: &'a dyn HashProvider,
    entropy_input: &[u8],
    personalization_string: &[u8],
) -> Result<Box<dyn Xof + 'a>> {
    hash.shake256(&[entropy_input, personalization_string, &[PRNG_DOMAIN]])
}

/// A SHAKE-256 based PRNG.
///
/// Squeezes `outlen` bytes from the given PRNG.
pub fn prng_get_bytes(reader: &mut dyn Xof, outlen: usize) -> Result<Vec<u8>> {
    let mut output = vec![0u8; outlen];
    reader.squeeze(&mut output)?;
    Ok(output)
}

/// Initializes a SHAKE256 XOF context with a given seed.
///
/// # Arguments
/// * `hash` - The hash provider.
/// * `seed` - The input seed to be absorbed.
///
/// # Returns
/// A finalized [`Xof`] ready for squeezing output.
pub fn xof_init<'a>(hash: &'a dyn HashProvider, seed: &[u8; SEED_BYTES]) -> Result<Box<dyn Xof + 'a>> {
    hash.shake256(&[seed])
}

/// SHAKE256(seed || domain), used to bind KEM seed expansion to PARAM_K.
pub fn xof_init_dom_sep<'a>(
    hash: &'a dyn HashProvider,
    seed: &[u8; SEED_BYTES],
    domain: u8,
) -> Result<Box<dyn Xof + 'a>> {
    hash.shake256(&[seed, &[domain]])
}

/// Extracts pseudorandom bytes from a SHAKE256 XOF.
pub fn xof_get_bytes(reader: &mut dyn Xof, output: &mut [u8]) -> Result<()> {
    reader.squeeze(output)
}

/// Computes the hash function I (SHA3-512) with domain separation.
///
/// # Arguments
/// * `hash` - The hash provider.
/// * `seed` - The input seed to be hashed.
///
/// * `out`  - Receives the 64-byte SHA3-512 hash output (may be provider memory).
pub fn hash_i(hash: &dyn HashProvider, seed: &[u8; SEED_BYTES], out: &mut [u8; 64]) -> Result<()> {
    hash.sha3_512(&[seed, &[I_FCT_DOMAIN]], out)
}

/// Computes the hash function G (SHA3-512) with domain separation.
///
/// # Arguments
/// * `hash`        - The hash provider.
/// * `hash_ek_kem` - Hash of the KEM encapsulation key, `SEED_BYTES` bytes.
/// * `m`           - Message bytes, `p.security_bytes` long.
/// * `salt`        - Salt value, `SALT_BYTES` bytes.
/// * `out`         - Receives the 64-byte SHA3-512 hash output (may be provider memory).
pub fn hash_g(
    hash: &dyn HashProvider,
    hash_ek_kem: &[u8; SEED_BYTES],
    m: &[u8],
    salt: &[u8; SALT_BYTES],
    out: &mut [u8; 64],
) -> Result<()> {
    hash.sha3_512(&[hash_ek_kem, m, salt, &[G_FCT_DOMAIN]], out)
}

/// Computes the hash function H (SHA3-256) with domain separation.
///
/// # Arguments
/// * `hash`   - The hash provider.
/// * `ek_kem` - Encapsulation key of the KEM, `p.ek_bytes` long.
///
/// # Returns
/// 32-byte SHA3-256 hash output.
pub fn hash_h(hash: &dyn HashProvider, ek_kem: &[u8]) -> Result<[u8; 32]> {
    let mut out = [0u8; 32];
    hash.sha3_256(&[ek_kem, &[H_FCT_DOMAIN]], &mut out)?;
    Ok(out)
}

/// Computes the hash function J (SHA3-256) with domain separation.
///
/// # Arguments
/// * `hash`        - The hash provider.
/// * `hash_ek_kem` - Hash of the KEM encapsulation key, `SEED_BYTES` bytes.
/// * `sigma`       - The string sigma, `p.security_bytes` long.
/// * `c_kem`       - Ciphertext struct (includes `c_pke.u`, `c_pke.v`, and `salt`).
/// * `out`         - Receives the 32-byte SHA3-256 hash output (may be provider memory).
pub fn hash_j(
    hash: &dyn HashProvider,
    p: &HqcParameters,
    hash_ek_kem: &[u8; SEED_BYTES],
    sigma: &[u8],
    c_kem: &CiphertextKem,
    out: &mut [u8; 32],
) -> Result<()> {
    let u_bytes = u64_words_to_bytes(&c_kem.c_pke.u);
    let v_bytes = u64_words_to_bytes(&c_kem.c_pke.v);

    hash.sha3_256(
        &[
            hash_ek_kem,
            sigma,
            &u_bytes[..p.vec_n_size_bytes],
            &v_bytes[..p.vec_n1n2_size_bytes],
            &c_kem.salt,
            &[J_FCT_DOMAIN],
        ],
        out,
    )
}

#[cfg(all(test, feature = "ref-ffi"))]
mod tests_ffi;
