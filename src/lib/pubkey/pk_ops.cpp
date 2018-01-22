/*
* PK Operation Types
* (C) 2010,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/pk_ops_impl.h>
#include <botan/internal/bit_ops.h>
#include <botan/rng.h>

namespace Botan {

PK_Ops::Encryption_with_EME::Encryption_with_EME(const std::string& eme)
   {
   m_eme.reset(get_eme(eme));
   if(!m_eme.get())
      throw Algorithm_Not_Found(eme);
   }

size_t PK_Ops::Encryption_with_EME::max_input_bits() const
   {
   return 8 * m_eme->maximum_input_size(max_raw_input_bits());
   }

secure_vector<uint8_t> PK_Ops::Encryption_with_EME::encrypt(const uint8_t msg[], size_t msg_len,
                                                         RandomNumberGenerator& rng)
   {
   const size_t max_raw = max_raw_input_bits();
   const std::vector<uint8_t> encoded = unlock(m_eme->encode(msg, msg_len, max_raw, rng));
   return raw_encrypt(encoded.data(), encoded.size(), rng);
   }

PK_Ops::Decryption_with_EME::Decryption_with_EME(const std::string& eme)
   {
   m_eme.reset(get_eme(eme));
   if(!m_eme.get())
      throw Algorithm_Not_Found(eme);
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
      m_kdf.reset(get_kdf(kdf));
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

PK_Ops::Signature_with_EMSA::Signature_with_EMSA(const std::string& emsa) :
   Signature(),
   m_emsa(get_emsa(emsa)),
   m_hash(hash_for_emsa(emsa)),
   m_prefix_used(false)
   {
   if(!m_emsa)
      throw Algorithm_Not_Found(emsa);
   }

void PK_Ops::Signature_with_EMSA::update(const uint8_t msg[], size_t msg_len)
   {
   if(has_prefix() && !m_prefix_used)
      {
      m_prefix_used = true;
      secure_vector<uint8_t> prefix = message_prefix();
      m_emsa->update(prefix.data(), prefix.size());
      }
   m_emsa->update(msg, msg_len);
   }

secure_vector<uint8_t> PK_Ops::Signature_with_EMSA::sign(RandomNumberGenerator& rng)
   {
   m_prefix_used = false;
   const secure_vector<uint8_t> msg = m_emsa->raw_data();
   const auto padded = m_emsa->encoding_of(msg, this->max_input_bits(), rng);
   return raw_sign(padded.data(), padded.size(), rng);
   }

PK_Ops::Verification_with_EMSA::Verification_with_EMSA(const std::string& emsa) :
   Verification(),
   m_emsa(get_emsa(emsa)),
   m_hash(hash_for_emsa(emsa)),
   m_prefix_used(false)
   {
   if(!m_emsa)
      throw Algorithm_Not_Found(emsa);
   }

void PK_Ops::Verification_with_EMSA::update(const uint8_t msg[], size_t msg_len)
   {
   if(has_prefix() && !m_prefix_used)
      {
      m_prefix_used = true;
      secure_vector<uint8_t> prefix = message_prefix();
      m_emsa->update(prefix.data(), prefix.size());
      }
   m_emsa->update(msg, msg_len);
   }

bool PK_Ops::Verification_with_EMSA::is_valid_signature(const uint8_t sig[], size_t sig_len)
   {
   m_prefix_used = false;
   const secure_vector<uint8_t> msg = m_emsa->raw_data();

   if(with_recovery())
      {
      secure_vector<uint8_t> output_of_key = verify_mr(sig, sig_len);
      return m_emsa->verify(output_of_key, msg, max_input_bits());
      }
   else
      {
      Null_RNG rng;
      secure_vector<uint8_t> encoded = m_emsa->encoding_of(msg, max_input_bits(), rng);
      return verify(encoded.data(), encoded.size(), sig, sig_len);
      }
   }

void PK_Ops::KEM_Encryption_with_KDF::kem_encrypt(secure_vector<uint8_t>& out_encapsulated_key,
                                                  secure_vector<uint8_t>& out_shared_key,
                                                  size_t desired_shared_key_len,
                                                  Botan::RandomNumberGenerator& rng,
                                                  const uint8_t salt[],
                                                  size_t salt_len)
   {
   secure_vector<uint8_t> raw_shared;
   this->raw_kem_encrypt(out_encapsulated_key, raw_shared, rng);

   out_shared_key = m_kdf->derive_key(desired_shared_key_len,
                                      raw_shared.data(), raw_shared.size(),
                                      salt, salt_len);
   }

PK_Ops::KEM_Encryption_with_KDF::KEM_Encryption_with_KDF(const std::string& kdf)
   {
   m_kdf.reset(get_kdf(kdf));
   }

secure_vector<uint8_t>
PK_Ops::KEM_Decryption_with_KDF::kem_decrypt(const uint8_t encap_key[],
                                             size_t len,
                                             size_t desired_shared_key_len,
                                             const uint8_t salt[],
                                             size_t salt_len)
   {
   secure_vector<uint8_t> raw_shared = this->raw_kem_decrypt(encap_key, len);

   return m_kdf->derive_key(desired_shared_key_len,
                            raw_shared.data(), raw_shared.size(),
                            salt, salt_len);
   }

PK_Ops::KEM_Decryption_with_KDF::KEM_Decryption_with_KDF(const std::string& kdf)
   {
   m_kdf.reset(get_kdf(kdf));
   }

}
