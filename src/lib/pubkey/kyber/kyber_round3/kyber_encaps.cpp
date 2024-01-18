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

void Kyber_KEM_Encryptor::encapsulate(StrongSpan<KyberCompressedCiphertext> out_encapsulated_key,
                                      StrongSpan<KyberSharedSecret> out_shared_key,
                                      RandomNumberGenerator& rng) {
   const auto& sym = m_public_key->mode().symmetric_primitives();

   const auto m = sym.H(rng.random_vec<KyberMessage>(KyberConstants::kSymBytes));
   const auto [K, r] = sym.G(m, m_public_key->H_public_key_bits_raw());

   auto ciphertext = m_public_key->indcpa_encrypt(m, r);
   ciphertext.to_bytes(out_encapsulated_key);

   auto c = StrongSpan<const KyberCompressedCiphertext>(out_encapsulated_key);
   const auto ciphertext_hash = sym.H(c);

   sym.KDF(out_shared_key, K, ciphertext_hash);
}

void Kyber_KEM_Decryptor::decapsulate(StrongSpan<KyberSharedSecret> out_shared_key,
                                      StrongSpan<const KyberCompressedCiphertext> encapsulated_key) {
   const auto& sym = m_public_key->mode().symmetric_primitives();

   const auto m = m_private_key->indcpa_decrypt(Ciphertext::from_bytes(encapsulated_key, m_private_key->mode()));

   const auto& pubkey_hash = m_public_key->H_public_key_bits_raw();
   const auto [K, r] = sym.G(m, pubkey_hash);

   const auto ciphertext_hash = sym.H(encapsulated_key);

   const auto cmp = m_public_key->indcpa_encrypt(m, r).to_bytes();
   BOTAN_ASSERT(encapsulated_key.size() == cmp.size(), "output of indcpa_enc has unexpected length");

   // Overwrite pre-k with z on re-encryption failure (constant time)
   KyberSharedSecret K_final(KyberConstants::kSymBytes);
   const auto reencrypt_success = CT::is_equal(encapsulated_key.data(), cmp.data(), encapsulated_key.size());
   CT::conditional_copy_mem(reencrypt_success, K_final.data(), K.data(), m_private_key->z().data(), K_final.size());

   sym.KDF(out_shared_key, K_final, ciphertext_hash);
}

}  // namespace Botan
