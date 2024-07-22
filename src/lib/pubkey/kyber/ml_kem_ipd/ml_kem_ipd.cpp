/*
 * Module-Lattice Key Encapsulation Mechanism (ML-KEM), Initial Public Draft
 *
 * (C) 2024 Jack Lloyd
 * (C) 2024 René Meusel, Rohde & Schwarz Cybersecurity
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#include <botan/internal/ml_kem_ipd.h>

#include <botan/internal/ct_utils.h>
#include <botan/internal/kyber_constants.h>
#include <botan/internal/kyber_types.h>

namespace Botan {

/**
 * NIST FIPS 203 IPD, Algorithm 16 (ML-KEM.Encaps)
 */
void ML_KEM_IPD_Encryptor::encapsulate(StrongSpan<KyberCompressedCiphertext> out_encapsulated_key,
                                       StrongSpan<KyberSharedSecret> out_shared_key,
                                       RandomNumberGenerator& rng) {
   const auto& sym = m_public_key->mode().symmetric_primitives();

   const auto m = rng.random_vec<KyberMessage>(KyberConstants::SEED_BYTES);
   const auto [K, r] = sym.G(m, m_public_key->H_public_key_bits_raw());
   m_public_key->indcpa_encrypt(out_encapsulated_key, m, r, precomputed_matrix_At());

   // TODO: avoid this copy by letting sym.G() directly write to the span.
   copy_mem(out_shared_key, K);
}

/**
 * NIST FIPS 203 IPD, Algorithm 17 (ML-KEM.Decaps)
 */
void ML_KEM_IPD_Decryptor::decapsulate(StrongSpan<KyberSharedSecret> out_shared_key,
                                       StrongSpan<const KyberCompressedCiphertext> c) {
   const auto& sym = m_public_key->mode().symmetric_primitives();

   const auto& h = m_public_key->H_public_key_bits_raw();
   const auto& z = m_private_key->z();

   const auto m_prime = m_private_key->indcpa_decrypt(c);
   const auto [K_prime, r_prime] = sym.G(m_prime, h);

   const auto K_bar = sym.J(z, c);
   const auto c_prime = m_public_key->indcpa_encrypt(m_prime, r_prime, precomputed_matrix_At());

   BOTAN_ASSERT_NOMSG(c.size() == c_prime.size());
   BOTAN_ASSERT_NOMSG(K_prime.size() == K_bar.size() && out_shared_key.size() == K_bar.size());
   const auto reencrypt_success = CT::is_equal(c.data(), c_prime.data(), c.size());
   CT::conditional_copy_mem(reencrypt_success, out_shared_key.data(), K_prime.data(), K_bar.data(), K_prime.size());
}

}  // namespace Botan
