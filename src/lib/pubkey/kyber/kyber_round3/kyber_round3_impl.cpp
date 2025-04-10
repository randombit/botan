/*
 * Crystals Kyber key encapsulation mechanism and key codec
 *
 * (C) 2024 Jack Lloyd
 * (C) 2024 René Meusel, Rohde & Schwarz Cybersecurity
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#include <botan/internal/kyber_round3_impl.h>

#include <botan/internal/ct_utils.h>
#include <botan/internal/kyber_constants.h>
#include <botan/internal/kyber_symmetric_primitives.h>
#include <botan/internal/kyber_types.h>

namespace Botan {

/**
 * Crystals Kyber (Version 3.01), Algorithm 8 (Kyber.CCAKEM.Enc())
 */
void Kyber_KEM_Encryptor::encapsulate(StrongSpan<KyberCompressedCiphertext> out_encapsulated_key,
                                      StrongSpan<KyberSharedSecret> out_shared_key,
                                      RandomNumberGenerator& rng) {
   const auto& sym = m_public_key->mode().symmetric_primitives();

   const auto seed_m = rng.random_vec<KyberMessage>(KyberConstants::SEED_BYTES);
   CT::poison(seed_m);

   const auto m = sym.H(seed_m);
   const auto [K_bar, r] = sym.G(m, m_public_key->H_public_key_bits_raw());
   m_public_key->indcpa_encrypt(out_encapsulated_key, m, r, precomputed_matrix_At());

   sym.KDF(out_shared_key, K_bar, sym.H(out_encapsulated_key));
   CT::unpoison_all(out_shared_key, out_encapsulated_key);
}

/**
 * Crystals Kyber (Version 3.01), Algorithm 9 (Kyber.CCAKEM.Dec())
 */
void Kyber_KEM_Decryptor::decapsulate(StrongSpan<KyberSharedSecret> out_shared_key,
                                      StrongSpan<const KyberCompressedCiphertext> encapsulated_key) {
   auto scope = CT::scoped_poison(*m_private_key);

   const auto& sym = m_public_key->mode().symmetric_primitives();

   const auto& h = m_public_key->H_public_key_bits_raw();
   const auto& z = m_private_key->z();

   const auto m_prime = m_private_key->indcpa_decrypt(encapsulated_key);
   const auto [K_bar_prime, r_prime] = sym.G(m_prime, h);

   const auto c_prime = m_public_key->indcpa_encrypt(m_prime, r_prime, precomputed_matrix_At());

   KyberSharedSecret K(KyberConstants::SEED_BYTES);
   BOTAN_ASSERT_NOMSG(encapsulated_key.size() == c_prime.size());
   BOTAN_ASSERT_NOMSG(K_bar_prime.size() == K.size());
   const auto reencrypt_success = CT::is_equal(encapsulated_key.data(), c_prime.data(), encapsulated_key.size());
   CT::conditional_copy_mem(reencrypt_success, K.data(), K_bar_prime.data(), z.data(), K_bar_prime.size());

   sym.KDF(out_shared_key, K, sym.H(encapsulated_key));
   CT::unpoison(out_shared_key);
}

}  // namespace Botan
