/**
* Abstraction for a combined KEM encryptors and decryptors.
*
* (C) 2024 Jack Lloyd
*     2024 Fabian Albert, René Meusel - Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/
#include <botan/internal/hybrid_kem_ops.h>

#include <botan/internal/stl_util.h>

namespace Botan {

KEM_Encryption_with_Combiner::KEM_Encryption_with_Combiner(const std::vector<std::unique_ptr<Public_Key>>& public_keys,
                                                           std::string_view provider) :
      m_encapsulated_key_length(0) {
   m_encryptors.reserve(public_keys.size());
   for(const auto& pk : public_keys) {
      const auto& newenc = m_encryptors.emplace_back(*pk, "Raw", provider);
      m_encapsulated_key_length += newenc.encapsulated_key_length();
   }
}

void KEM_Encryption_with_Combiner::kem_encrypt(std::span<uint8_t> out_encapsulated_key,
                                               std::span<uint8_t> out_shared_key,
                                               RandomNumberGenerator& rng,
                                               size_t desired_shared_key_len,
                                               std::span<const uint8_t> salt) {
   BOTAN_ARG_CHECK(out_encapsulated_key.size() == encapsulated_key_length(),
                   "Encapsulated key output buffer has wrong size");
   BOTAN_ARG_CHECK(out_shared_key.size() == shared_key_length(desired_shared_key_len),
                   "Shared key output buffer has wrong size");

   std::vector<secure_vector<uint8_t>> shared_secrets;
   shared_secrets.reserve(m_encryptors.size());

   std::vector<std::vector<uint8_t>> ciphertexts;
   ciphertexts.reserve(m_encryptors.size());

   for(auto& encryptor : m_encryptors) {
      auto [ct, ss] = KEM_Encapsulation::destructure(encryptor.encrypt(rng, 0 /* no KDF */));
      shared_secrets.push_back(std::move(ss));
      ciphertexts.push_back(std::move(ct));
   }
   combine_ciphertexts(out_encapsulated_key, ciphertexts, salt);
   combine_shared_secrets(out_shared_key, shared_secrets, ciphertexts, desired_shared_key_len, salt);
}

void KEM_Encryption_with_Combiner::combine_ciphertexts(std::span<uint8_t> out_ciphertext,
                                                       const std::vector<std::vector<uint8_t>>& ciphertexts,
                                                       std::span<const uint8_t> salt) {
   BOTAN_ARG_CHECK(salt.empty(), "Salt not supported by this KEM");
   BOTAN_ARG_CHECK(ciphertexts.size() == m_encryptors.size(), "Invalid number of ciphertexts");
   BOTAN_ARG_CHECK(out_ciphertext.size() == encapsulated_key_length(), "Invalid output buffer size");
   BufferStuffer ct_stuffer(out_ciphertext);
   for(size_t idx = 0; idx < ciphertexts.size(); idx++) {
      BOTAN_ARG_CHECK(ciphertexts.at(idx).size() == m_encryptors.at(idx).encapsulated_key_length(),
                      "Invalid ciphertext length");
      ct_stuffer.append(ciphertexts.at(idx));
   }
   BOTAN_ASSERT_NOMSG(ct_stuffer.full());
}

KEM_Decryption_with_Combiner::KEM_Decryption_with_Combiner(
   const std::vector<std::unique_ptr<Private_Key>>& private_keys,
   RandomNumberGenerator& rng,
   std::string_view provider) :
      m_encapsulated_key_length(0) {
   m_decryptors.reserve(private_keys.size());
   for(const auto& sk : private_keys) {
      const auto& newenc = m_decryptors.emplace_back(*sk, rng, "Raw", provider);
      m_encapsulated_key_length += newenc.encapsulated_key_length();
   }
}

void KEM_Decryption_with_Combiner::kem_decrypt(std::span<uint8_t> out_shared_key,
                                               std::span<const uint8_t> encapsulated_key,
                                               size_t desired_shared_key_len,
                                               std::span<const uint8_t> salt) {
   BOTAN_ARG_CHECK(encapsulated_key.size() == encapsulated_key_length(), "Invalid encapsulated key length");
   BOTAN_ARG_CHECK(out_shared_key.size() == shared_key_length(desired_shared_key_len), "Invalid output buffer size");

   std::vector<secure_vector<uint8_t>> shared_secrets;
   shared_secrets.reserve(m_decryptors.size());
   auto ciphertexts = split_ciphertexts(encapsulated_key);
   BOTAN_ASSERT(ciphertexts.size() == m_decryptors.size(), "Correct number of ciphertexts");

   for(size_t idx = 0; idx < m_decryptors.size(); idx++) {
      shared_secrets.push_back(m_decryptors.at(idx).decrypt(ciphertexts.at(idx), 0 /* no KDF */));
   }

   combine_shared_secrets(out_shared_key, shared_secrets, ciphertexts, desired_shared_key_len, salt);
}

std::vector<std::vector<uint8_t>> KEM_Decryption_with_Combiner::split_ciphertexts(
   std::span<const uint8_t> concat_ciphertext) {
   BOTAN_ARG_CHECK(concat_ciphertext.size() == encapsulated_key_length(), "Wrong ciphertext length");
   std::vector<std::vector<uint8_t>> ciphertexts;
   ciphertexts.reserve(m_decryptors.size());
   BufferSlicer ct_slicer(concat_ciphertext);
   for(const auto& decryptor : m_decryptors) {
      ciphertexts.push_back(ct_slicer.copy_as_vector(decryptor.encapsulated_key_length()));
   }
   BOTAN_ASSERT_NOMSG(ct_slicer.empty());
   return ciphertexts;
}

}  // namespace Botan
