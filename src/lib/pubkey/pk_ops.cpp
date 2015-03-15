/*
* PK Operation Types
* (C) 2010,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/pk_ops.h>
#include <botan/eme.h>
#include <botan/kdf.h>
#include <botan/emsa.h>
#include <botan/internal/bit_ops.h>

namespace Botan {

PK_Ops::Encryption_with_EME::Encryption_with_EME(const std::string& eme)
   {
   m_eme.reset(get_eme(eme));
   if(!m_eme.get())
      throw std::runtime_error("EME " + eme + " not found");
   }

PK_Ops::Encryption_with_EME::~Encryption_with_EME() {}

size_t PK_Ops::Encryption_with_EME::max_input_bits() const
   {
   return m_eme->maximum_input_size(max_raw_input_bits());
   }

secure_vector<byte> PK_Ops::Encryption_with_EME::encrypt(const byte msg[], size_t msg_len,
                                                         RandomNumberGenerator& rng)
   {
   const size_t max_raw = max_raw_input_bits();

   const std::vector<byte> encoded = unlock(m_eme->encode(msg, msg_len, max_raw, rng));

   if(8*(encoded.size() - 1) + high_bit(encoded[0]) > max_raw)
      throw std::runtime_error("Input is too large to encrypt with this key");

   return raw_encrypt(&encoded[0], encoded.size(), rng);
   }

PK_Ops::Decryption_with_EME::Decryption_with_EME(const std::string& eme)
   {
   m_eme.reset(get_eme(eme));
   if(!m_eme.get())
      throw std::runtime_error("EME " + eme + " not found");
   }

PK_Ops::Decryption_with_EME::~Decryption_with_EME() {}

size_t PK_Ops::Decryption_with_EME::max_input_bits() const
   {
   return m_eme->maximum_input_size(max_raw_input_bits());
   }

secure_vector<byte> PK_Ops::Decryption_with_EME::decrypt(const byte msg[], size_t length)
   {
   return m_eme->decode(raw_decrypt(msg, length), max_raw_input_bits());
   }

PK_Ops::Key_Agreement_with_KDF::Key_Agreement_with_KDF(const std::string& kdf)
   {
   if(kdf != "Raw")
      m_kdf.reset(get_kdf(kdf));
   }

PK_Ops::Key_Agreement_with_KDF::~Key_Agreement_with_KDF() {}

secure_vector<byte> PK_Ops::Key_Agreement_with_KDF::agree(size_t key_len,
                                                          const byte w[], size_t w_len,
                                                          const byte salt[], size_t salt_len)
   {
   secure_vector<byte> z = raw_agree(w, w_len);
   if(m_kdf)
      return m_kdf->derive_key(key_len, z, salt, salt_len);
   return z;
  }

}
