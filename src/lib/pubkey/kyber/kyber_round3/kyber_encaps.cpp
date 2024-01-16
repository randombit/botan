/*
 * Crystals Kyber key encapsulation mechanism
 *
 * (C) 2024 Jack Lloyd
 * (C) 2024 René Meusel, Rohde & Schwarz Cybersecurity
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#include <botan/internal/kyber_encaps.h>

#include <botan/internal/ct_utils.h>
#include <botan/internal/kyber_constants.h>
#include <botan/internal/kyber_structures.h>
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

   const auto m = sym.H(rng.random_vec<KyberMessage>(KyberConstants::kSymBytes));
   const auto [K_bar, r] = sym.G(m, m_public_key->H_public_key_bits_raw());
   auto c = m_public_key->indcpa_encrypt(m, r);

   c.to_bytes(out_encapsulated_key);
   sym.KDF(out_shared_key, K_bar, sym.H(out_encapsulated_key));
}

/**
 * Crystals Kyber (Version 3.01), Algorithm 9 (Kyber.CCAKEM.Dec())
 */
void Kyber_KEM_Decryptor::decapsulate(StrongSpan<KyberSharedSecret> out_shared_key,
                                      StrongSpan<const KyberCompressedCiphertext> encapsulated_key) {
   const auto& sym = m_public_key->mode().symmetric_primitives();

   const auto& h = m_public_key->H_public_key_bits_raw();
   const auto& z = m_private_key->z();

   const auto m_prime = m_private_key->indcpa_decrypt(Ciphertext::from_bytes(encapsulated_key, m_private_key->mode()));
   const auto [K_bar_prime, r_prime] = sym.G(m_prime, h);

   const auto c_prime = m_public_key->indcpa_encrypt(m_prime, r_prime).to_bytes();

   KyberSharedSecret K(KyberConstants::kSymBytes);
   BOTAN_ASSERT_NOMSG(encapsulated_key.size() == c_prime.size());
   BOTAN_ASSERT_NOMSG(K_bar_prime.size() == K.size());
   const auto reencrypt_success = CT::is_equal(encapsulated_key.data(), c_prime.data(), encapsulated_key.size());
   CT::conditional_copy_mem(reencrypt_success, K.data(), K_bar_prime.data(), z.data(), K_bar_prime.size());

   sym.KDF(out_shared_key, K, sym.H(encapsulated_key));
}

}  // namespace Botan
