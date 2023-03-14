/*
* PK Operation Types
* (C) 2010,2015,2023 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/pk_ops_impl.h>
#include <botan/internal/bit_ops.h>
#include <botan/internal/scan_name.h>
#include <botan/internal/parsing.h>
#include <botan/hash.h>
#include <botan/rng.h>

#if defined(BOTAN_HAS_RAW_HASH_FN)
  #include <botan/internal/raw_hash.h>
#endif

namespace Botan {

AlgorithmIdentifier PK_Ops::Signature::algorithm_identifier() const
   {
   throw Not_Implemented("This signature scheme does not have an algorithm identifier available");
   }

PK_Ops::Encryption_with_EME::Encryption_with_EME(const std::string& eme) :
   m_eme(EME::create(eme))
   {
   }

size_t PK_Ops::Encryption_with_EME::max_input_bits() const
   {
   return 8 * m_eme->maximum_input_size(max_ptext_input_bits());
   }

secure_vector<uint8_t> PK_Ops::Encryption_with_EME::encrypt(const uint8_t msg[], size_t msg_len,
                                                         RandomNumberGenerator& rng)
   {
   const size_t max_raw = max_ptext_input_bits();
   const auto encoded = m_eme->encode(msg, msg_len, max_raw, rng);
   return raw_encrypt(encoded.data(), encoded.size(), rng);
   }

PK_Ops::Decryption_with_EME::Decryption_with_EME(const std::string& eme) :
   m_eme(EME::create(eme))
   {
   }

secure_vector<uint8_t>
PK_Ops::Decryption_with_EME::decrypt(uint8_t& valid_mask,
                                     const uint8_t ciphertext[],
                                     size_t ciphertext_len)
   {
   const secure_vector<uint8_t> raw = raw_decrypt(ciphertext, ciphertext_len);
   return m_eme->unpad(valid_mask, raw.data(), raw.size());
   }

PK_Ops::Key_Agreement_with_KDF::Key_Agreement_with_KDF(const std::string& kdf)
   {
   if(kdf != "Raw")
      m_kdf = KDF::create_or_throw(kdf);
   }

secure_vector<uint8_t> PK_Ops::Key_Agreement_with_KDF::agree(size_t key_len,
                                                          const uint8_t w[], size_t w_len,
                                                          const uint8_t salt[], size_t salt_len)
   {
   secure_vector<uint8_t> z = raw_agree(w, w_len);
   if(m_kdf)
      return m_kdf->derive_key(key_len, z, salt, salt_len);
   return z;
   }

namespace {

std::unique_ptr<HashFunction> create_signature_hash(const std::string& padding)
   {
   if(auto hash = HashFunction::create(padding))
      return hash;

   SCAN_Name req(padding);

   if(req.algo_name() == "EMSA1" && req.arg_count() == 1)
      {
      if(auto hash = HashFunction::create(req.arg(0)))
         return hash;
      }

#if defined(BOTAN_HAS_RAW_HASH_FN)
   if(req.algo_name() == "Raw")
      {
      if(req.arg_count() == 0)
         {
         return std::make_unique<RawHashFunction>("Raw", 0);
         }

      if(req.arg_count() == 1)
         {
         if(auto hash = HashFunction::create(req.arg(0)))
            return std::make_unique<RawHashFunction>(std::move(hash));
         }
      }
#endif

   throw Algorithm_Not_Found(padding);
   }

}

PK_Ops::Signature_with_Hash::Signature_with_Hash(const std::string& hash) :
   Signature(),
   m_hash(create_signature_hash(hash))
   {
   }

#if defined(BOTAN_HAS_RFC6979_GENERATOR)
std::string PK_Ops::Signature_with_Hash::rfc6979_hash_function() const
   {
   std::string hash = m_hash->name();
   if(hash != "Raw")
      return hash;
   return "SHA-512";
   }
#endif

void PK_Ops::Signature_with_Hash::update(const uint8_t msg[], size_t msg_len)
   {
   m_hash->update(msg, msg_len);
   }

secure_vector<uint8_t> PK_Ops::Signature_with_Hash::sign(RandomNumberGenerator& rng)
   {
   const secure_vector<uint8_t> msg = m_hash->final();
   return raw_sign(msg.data(), msg.size(), rng);
   }

PK_Ops::Verification_with_Hash::Verification_with_Hash(const std::string& padding) :
   Verification(),
   m_hash(create_signature_hash(padding))
   {
   }

PK_Ops::Verification_with_Hash::Verification_with_Hash(const AlgorithmIdentifier& alg_id,
                                                       const std::string& pk_algo,
                                                       bool allow_null_parameters)
   {
   const auto oid_info = split_on(alg_id.oid().to_formatted_string(), '/');

   if(oid_info.empty() || oid_info.size() != 2 || oid_info[0] != pk_algo)
      {
      throw Decoding_Error("Unexpected AlgorithmIdentifier OID " + alg_id.oid().to_string()
                           + " in association with " + pk_algo + " key");
      }

   if(!alg_id.parameters_are_empty())
      {
      if(alg_id.parameters_are_null())
         {
         if(!allow_null_parameters)
            {
            throw Decoding_Error("Unexpected NULL AlgorithmIdentifier parameters for " + pk_algo);
            }
         }
      else
         {
         throw Decoding_Error("Unexpected AlgorithmIdentifier parameters for " + pk_algo);
         }
      }

   m_hash = HashFunction::create_or_throw(oid_info[1]);
   }

void PK_Ops::Verification_with_Hash::update(const uint8_t msg[], size_t msg_len)
   {
   m_hash->update(msg, msg_len);
   }

bool PK_Ops::Verification_with_Hash::is_valid_signature(const uint8_t sig[], size_t sig_len)
   {
   const secure_vector<uint8_t> msg = m_hash->final();
   return verify(msg.data(), msg.size(), sig, sig_len);
   }

size_t PK_Ops::KEM_Encryption_with_KDF::shared_key_length(size_t desired_shared_key_len) const
   {
   if(m_kdf)
      return desired_shared_key_len;
   else
      return this->raw_kem_shared_key_length();
   }

void PK_Ops::KEM_Encryption_with_KDF::kem_encrypt(secure_vector<uint8_t>& out_encapsulated_key,
                                                  secure_vector<uint8_t>& out_shared_key,
                                                  size_t desired_shared_key_len,
                                                  RandomNumberGenerator& rng,
                                                  const uint8_t salt[],
                                                  size_t salt_len)
   {
   secure_vector<uint8_t> raw_shared;
   this->raw_kem_encrypt(out_encapsulated_key, raw_shared, rng);

   BOTAN_ASSERT_EQUAL(out_encapsulated_key.size(), this->encapsulated_key_length(),
                      "KEM produced encapsulated key with different length than expected");

   BOTAN_ASSERT_EQUAL(raw_shared.size(), this->raw_kem_shared_key_length(),
                      "KEM produced shared key with different length than expected");

   out_shared_key = (m_kdf)
      ? m_kdf->derive_key(desired_shared_key_len,
                          raw_shared.data(), raw_shared.size(),
                          salt, salt_len)
      : raw_shared;
   }

PK_Ops::KEM_Encryption_with_KDF::KEM_Encryption_with_KDF(const std::string& kdf)
   {
   if(kdf != "Raw")
      m_kdf = KDF::create_or_throw(kdf);
   }

size_t PK_Ops::KEM_Decryption_with_KDF::shared_key_length(size_t desired_shared_key_len) const
   {
   if(m_kdf)
      return desired_shared_key_len;
   else
      return this->raw_kem_shared_key_length();
   }

secure_vector<uint8_t>
PK_Ops::KEM_Decryption_with_KDF::kem_decrypt(const uint8_t encap_key[],
                                             size_t len,
                                             size_t desired_shared_key_len,
                                             const uint8_t salt[],
                                             size_t salt_len)
   {
   secure_vector<uint8_t> raw_shared = this->raw_kem_decrypt(encap_key, len);

   BOTAN_ASSERT_EQUAL(raw_shared.size(), this->raw_kem_shared_key_length(),
                      "KEM produced shared key with different length than expected");

   if(m_kdf)
      return m_kdf->derive_key(desired_shared_key_len,
                               raw_shared.data(), raw_shared.size(),
                               salt, salt_len);
   return raw_shared;
   }

PK_Ops::KEM_Decryption_with_KDF::KEM_Decryption_with_KDF(const std::string& kdf)
   {
   if(kdf != "Raw")
      m_kdf = KDF::create_or_throw(kdf);
   }

}
