/**
* Abstraction for a combined KEM encryptors and decryptors.
*
* (C) 2024 Jack Lloyd
*     2024 Fabian Albert, René Meusel - Rohde & Schwarz Cybersecurity
*     2026 René Meusel
*
* Botan is released under the Simplified BSD License (see license.txt)
*/
#include <botan/internal/hybrid_kem_ops.h>

#include <botan/internal/buffer_slicer.h>
#include <botan/internal/buffer_stuffer.h>

namespace Botan {

KEM_Encryption_with_Combiner::KEM_Encryption_with_Combiner(const PairOfPublicKeys& public_keys,
                                                           std::string_view provider) :
      m_encryptors({
         PK_KEM_Encryptor(*public_keys.first, "Raw", provider),
         PK_KEM_Encryptor(*public_keys.second, "Raw", provider),
      }) {}

void KEM_Encryption_with_Combiner::kem_encrypt(std::span<uint8_t> out_encapsulated_key,
                                               std::span<uint8_t> out_shared_key,
                                               RandomNumberGenerator& rng,
                                               size_t desired_shared_key_len,
                                               std::span<const uint8_t> salt) {
   BOTAN_ARG_CHECK(out_encapsulated_key.size() == encapsulated_key_length(),
                   "KEM_Encryption_with_Combiner: Encapsulated key output buffer has wrong size");
   BOTAN_ARG_CHECK(out_shared_key.size() == shared_key_length(desired_shared_key_len),
                   "KEM_Encryption_with_Combiner: Shared key output buffer has wrong size");

   PairOfSharedSecrets shared_secrets;
   PairOfCiphertexts ciphertexts;

   std::tie(ciphertexts.first, shared_secrets.first) =
      KEM_Encapsulation::destructure(m_encryptors.first.encrypt(rng, 0 /* no KDF */));
   std::tie(ciphertexts.second, shared_secrets.second) =
      KEM_Encapsulation::destructure(m_encryptors.second.encrypt(rng, 0 /* no KDF */));

   combine_ciphertexts(out_encapsulated_key, ciphertexts, salt);
   combine_shared_secrets(out_shared_key, shared_secrets, ciphertexts, desired_shared_key_len, salt);
}

size_t KEM_Encryption_with_Combiner::encapsulated_key_length() const {
   return m_encryptors.first.encapsulated_key_length() + m_encryptors.second.encapsulated_key_length();
}

void KEM_Encryption_with_Combiner::combine_ciphertexts(std::span<uint8_t> out_ciphertext,
                                                       const PairOfCiphertexts& ciphertexts,
                                                       std::span<const uint8_t> salt) {
   BOTAN_ARG_CHECK(salt.empty(), "KEM_Encryption_with_Combiner: Salt not supported by this KEM");
   BOTAN_ARG_CHECK(out_ciphertext.size() == encapsulated_key_length(),
                   "KEM_Encryption_with_Combiner: Invalid output buffer size for ciphertext");
   BufferStuffer cts(out_ciphertext);
   cts.append(ciphertexts.first);
   cts.append(ciphertexts.second);
   BOTAN_ASSERT_NOMSG(cts.full());
}

KEM_Decryption_with_Combiner::KEM_Decryption_with_Combiner(const PairOfPrivateKeys& private_keys,
                                                           RandomNumberGenerator& rng,
                                                           std::string_view provider) :
      m_decryptors({
         PK_KEM_Decryptor(*private_keys.first, rng, "Raw", provider),
         PK_KEM_Decryptor(*private_keys.second, rng, "Raw", provider),
      }) {}

void KEM_Decryption_with_Combiner::kem_decrypt(std::span<uint8_t> out_shared_key,
                                               std::span<const uint8_t> encapsulated_key,
                                               size_t desired_shared_key_len,
                                               std::span<const uint8_t> salt) {
   BOTAN_ARG_CHECK(encapsulated_key.size() == encapsulated_key_length(),
                   "KEM_Decryption_with_Combiner: Invalid encapsulated key length");
   BOTAN_ARG_CHECK(out_shared_key.size() == shared_key_length(desired_shared_key_len),
                   "KEM_Decryption_with_Combiner: Invalid output buffer size");

   const PairOfCiphertexts ciphertexts = split_ciphertexts(encapsulated_key);
   const PairOfSharedSecrets shared_secrets = {
      m_decryptors.first.decrypt(ciphertexts.first, 0 /* no KDF */),
      m_decryptors.second.decrypt(ciphertexts.second, 0 /* no KDF */),
   };

   combine_shared_secrets(out_shared_key, shared_secrets, ciphertexts, desired_shared_key_len, salt);
}

size_t KEM_Decryption_with_Combiner::encapsulated_key_length() const {
   return m_decryptors.first.encapsulated_key_length() + m_decryptors.second.encapsulated_key_length();
}

PairOfCiphertexts KEM_Decryption_with_Combiner::split_ciphertexts(std::span<const uint8_t> concat_ciphertext) {
   BOTAN_ARG_CHECK(concat_ciphertext.size() == encapsulated_key_length(),
                   "KEM_Decryption_with_Combiner: Wrong ciphertext length");

   BufferSlicer cts(concat_ciphertext);
   PairOfCiphertexts ciphertexts = {
      cts.copy_as_vector(m_decryptors.first.encapsulated_key_length()),
      cts.copy_as_vector(m_decryptors.second.encapsulated_key_length()),
   };
   BOTAN_ASSERT_NOMSG(cts.empty());

   return ciphertexts;
}

}  // namespace Botan
