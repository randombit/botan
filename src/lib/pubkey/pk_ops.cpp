/*
* PK Operation Types
* (C) 2010,2015,2023 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/pk_ops_impl.h>

#include <botan/hash.h>
#include <botan/rng.h>
#include <botan/internal/bit_ops.h>
#include <botan/internal/fmt.h>
#include <botan/internal/parsing.h>
#include <botan/internal/scan_name.h>
#include <sstream>

#if defined(BOTAN_HAS_RAW_HASH_FN)
   #include <botan/internal/raw_hash.h>
#endif

namespace Botan {

AlgorithmIdentifier PK_Ops::Signature::algorithm_identifier() const {
   throw Not_Implemented("This signature scheme does not have an algorithm identifier available");
}

PK_Ops::Encryption_with_EME::Encryption_with_EME(std::string_view eme) : m_eme(EME::create(eme)) {}

size_t PK_Ops::Encryption_with_EME::max_input_bits() const {
   return 8 * m_eme->maximum_input_size(max_ptext_input_bits());
}

secure_vector<uint8_t> PK_Ops::Encryption_with_EME::encrypt(const uint8_t msg[],
                                                            size_t msg_len,
                                                            RandomNumberGenerator& rng) {
   const size_t max_raw = max_ptext_input_bits();
   const auto encoded = m_eme->encode(msg, msg_len, max_raw, rng);
   return raw_encrypt(encoded.data(), encoded.size(), rng);
}

PK_Ops::Decryption_with_EME::Decryption_with_EME(std::string_view eme) : m_eme(EME::create(eme)) {}

secure_vector<uint8_t> PK_Ops::Decryption_with_EME::decrypt(uint8_t& valid_mask,
                                                            const uint8_t ciphertext[],
                                                            size_t ciphertext_len) {
   const secure_vector<uint8_t> raw = raw_decrypt(ciphertext, ciphertext_len);
   return m_eme->unpad(valid_mask, raw.data(), raw.size());
}

PK_Ops::Key_Agreement_with_KDF::Key_Agreement_with_KDF(std::string_view kdf) {
   if(kdf != "Raw") {
      m_kdf = KDF::create_or_throw(kdf);
   }
}

secure_vector<uint8_t> PK_Ops::Key_Agreement_with_KDF::agree(
   size_t key_len, const uint8_t w[], size_t w_len, const uint8_t salt[], size_t salt_len) {
   if(salt_len > 0 && m_kdf == nullptr) {
      throw Invalid_Argument("PK_Key_Agreement::derive_key requires a KDF to use a salt");
   }

   secure_vector<uint8_t> z = raw_agree(w, w_len);
   if(m_kdf) {
      return m_kdf->derive_key(key_len, z, salt, salt_len);
   }
   return z;
}

namespace {

std::unique_ptr<HashFunction> create_signature_hash(std::string_view padding) {
   if(auto hash = HashFunction::create(padding)) {
      return hash;
   }

   SCAN_Name req(padding);

   if(req.algo_name() == "EMSA1" && req.arg_count() == 1) {
      if(auto hash = HashFunction::create(req.arg(0))) {
         return hash;
      }
   }

#if defined(BOTAN_HAS_RAW_HASH_FN)
   if(req.algo_name() == "Raw") {
      if(req.arg_count() == 0) {
         return std::make_unique<RawHashFunction>("Raw", 0);
      }

      if(req.arg_count() == 1) {
         if(auto hash = HashFunction::create(req.arg(0))) {
            return std::make_unique<RawHashFunction>(std::move(hash));
         }
      }
   }
#endif

   throw Algorithm_Not_Found(padding);
}

}  // namespace

PK_Ops::Signature_with_Hash::Signature_with_Hash(std::string_view hash) :
      Signature(), m_hash(create_signature_hash(hash)) {}

#if defined(BOTAN_HAS_RFC6979_GENERATOR)
std::string PK_Ops::Signature_with_Hash::rfc6979_hash_function() const {
   std::string hash = m_hash->name();
   if(hash != "Raw") {
      return hash;
   }
   return "SHA-512";
}
#endif

void PK_Ops::Signature_with_Hash::update(const uint8_t msg[], size_t msg_len) {
   m_hash->update(msg, msg_len);
}

secure_vector<uint8_t> PK_Ops::Signature_with_Hash::sign(RandomNumberGenerator& rng) {
   const secure_vector<uint8_t> msg = m_hash->final();
   return raw_sign(msg.data(), msg.size(), rng);
}

PK_Ops::Verification_with_Hash::Verification_with_Hash(std::string_view padding) :
      Verification(), m_hash(create_signature_hash(padding)) {}

PK_Ops::Verification_with_Hash::Verification_with_Hash(const AlgorithmIdentifier& alg_id,
                                                       std::string_view pk_algo,
                                                       bool allow_null_parameters) {
   const auto oid_info = split_on(alg_id.oid().to_formatted_string(), '/');

   if(oid_info.size() != 2 || oid_info[0] != pk_algo) {
      throw Decoding_Error(
         fmt("Unexpected AlgorithmIdentifier OID {} in association with {} key", alg_id.oid(), pk_algo));
   }

   if(!alg_id.parameters_are_empty()) {
      if(alg_id.parameters_are_null()) {
         if(!allow_null_parameters) {
            throw Decoding_Error(fmt("Unexpected NULL AlgorithmIdentifier parameters for {}", pk_algo));
         }
      } else {
         throw Decoding_Error(fmt("Unexpected AlgorithmIdentifier parameters for {}", pk_algo));
      }
   }

   m_hash = HashFunction::create_or_throw(oid_info[1]);
}

void PK_Ops::Verification_with_Hash::update(const uint8_t msg[], size_t msg_len) {
   m_hash->update(msg, msg_len);
}

bool PK_Ops::Verification_with_Hash::is_valid_signature(const uint8_t sig[], size_t sig_len) {
   const secure_vector<uint8_t> msg = m_hash->final();
   return verify(msg.data(), msg.size(), sig, sig_len);
}

size_t PK_Ops::KEM_Encryption_with_KDF::shared_key_length(size_t desired_shared_key_len) const {
   if(m_kdf) {
      return desired_shared_key_len;
   } else {
      return this->raw_kem_shared_key_length();
   }
}

void PK_Ops::KEM_Encryption_with_KDF::kem_encrypt(std::span<uint8_t> out_encapsulated_key,
                                                  std::span<uint8_t> out_shared_key,
                                                  RandomNumberGenerator& rng,
                                                  size_t desired_shared_key_len,
                                                  std::span<const uint8_t> salt) {
   BOTAN_ARG_CHECK(salt.empty() || m_kdf, "PK_KEM_Encryptor::encrypt requires a KDF to use a salt");
   BOTAN_ASSERT_NOMSG(out_encapsulated_key.size() == encapsulated_key_length());

   if(m_kdf) {
      BOTAN_ASSERT_EQUAL(
         out_shared_key.size(), desired_shared_key_len, "KDF output length and shared key length match");

      secure_vector<uint8_t> raw_shared(raw_kem_shared_key_length());
      this->raw_kem_encrypt(out_encapsulated_key, raw_shared, rng);
      m_kdf->derive_key(out_shared_key, raw_shared, salt, {});
   } else {
      BOTAN_ASSERT_EQUAL(out_shared_key.size(), raw_kem_shared_key_length(), "Shared key has raw KEM output length");
      this->raw_kem_encrypt(out_encapsulated_key, out_shared_key, rng);
   }
}

PK_Ops::KEM_Encryption_with_KDF::KEM_Encryption_with_KDF(std::string_view kdf) {
   if(kdf != "Raw") {
      m_kdf = KDF::create_or_throw(kdf);
   }
}

size_t PK_Ops::KEM_Decryption_with_KDF::shared_key_length(size_t desired_shared_key_len) const {
   if(m_kdf) {
      return desired_shared_key_len;
   } else {
      return this->raw_kem_shared_key_length();
   }
}

void PK_Ops::KEM_Decryption_with_KDF::kem_decrypt(std::span<uint8_t> out_shared_key,
                                                  std::span<const uint8_t> encapsulated_key,
                                                  size_t desired_shared_key_len,
                                                  std::span<const uint8_t> salt) {
   BOTAN_ARG_CHECK(salt.empty() || m_kdf, "PK_KEM_Decryptor::decrypt requires a KDF to use a salt");

   if(m_kdf) {
      BOTAN_ASSERT_EQUAL(
         out_shared_key.size(), desired_shared_key_len, "KDF output length and shared key length match");

      secure_vector<uint8_t> raw_shared(raw_kem_shared_key_length());
      this->raw_kem_decrypt(raw_shared, encapsulated_key);
      m_kdf->derive_key(out_shared_key, raw_shared, salt, {});
   } else {
      BOTAN_ASSERT_EQUAL(out_shared_key.size(), raw_kem_shared_key_length(), "Shared key has raw KEM output length");
      this->raw_kem_decrypt(out_shared_key, encapsulated_key);
   }
}

PK_Ops::KEM_Decryption_with_KDF::KEM_Decryption_with_KDF(std::string_view kdf) {
   if(kdf != "Raw") {
      m_kdf = KDF::create_or_throw(kdf);
   }
}

}  // namespace Botan
