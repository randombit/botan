use crate::parameters::HqcParameters;
use crate::secmem::SecretVec;

pub mod reed_muller;
mod reed_solomon;

/// Encodes the message `m` to a codeword `em` using the concatenated code.
///
/// First encodes the message using the Reed-Solomon code, then applies
/// the duplicated Reed-Muller code to obtain the concatenated codeword.
///
/// # Arguments
/// * `m` - Input message of `p.vec_k_size_64` 64-bit words.
///
/// # Returns
/// Encoded codeword of `p.vec_n1n2_size_64` 64-bit words.
pub fn code_encode(p: &HqcParameters, m: &[u64]) -> SecretVec<u64> {
    // `tmp` carries the Reed-Solomon codeword of the secret message, so it is
    // cleared on drop with volatile writes rather than by a hand-rolled loop
    // the optimiser may elide.
    let tmp = SecretVec::from_vec(reed_solomon::reed_solomon_encode(p, m));
    assert_eq!(tmp.len(), p.vec_n1_size_64);

    SecretVec::from_vec(reed_muller::reed_muller_encode(p, &tmp))
}

/// Decodes the codeword `em` to a message `m` using the concatenated code.
///
/// # Arguments
/// * `em` - Codeword of `p.vec_n1n2_size_64` 64-bit words.
///
/// # Returns
/// Decoded message of `p.vec_k_size_64` 64-bit words.
pub fn code_decode(p: &HqcParameters, em: &[u64]) -> SecretVec<u64> {
    assert_eq!(em.len(), p.vec_n1n2_size_64);

    let tmp = SecretVec::from_vec(reed_muller::reed_muller_decode(p, em));
    SecretVec::from_vec(reed_solomon::reed_solomon_decode(p, &tmp))
}

#[cfg(test)]
mod tests;

#[cfg(all(test, feature = "ref-ffi"))]
mod tests_ffi;
