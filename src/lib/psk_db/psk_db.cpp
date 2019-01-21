/*
* (C) 2017 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/psk_db.h>
#include <botan/exceptn.h>
#include <botan/nist_keywrap.h>
#include <botan/base64.h>
#include <botan/mac.h>
#include <botan/block_cipher.h>

namespace Botan {

Encrypted_PSK_Database::Encrypted_PSK_Database(const secure_vector<uint8_t>& master_key)
   {
   m_cipher = BlockCipher::create_or_throw("AES-256");
   m_hmac = MessageAuthenticationCode::create_or_throw("HMAC(SHA-256)");
   m_hmac->set_key(master_key);

   m_cipher->set_key(m_hmac->process("wrap"));
   m_hmac->set_key(m_hmac->process("hmac"));
   }

Encrypted_PSK_Database::~Encrypted_PSK_Database()
   {
   // for ~unique_ptr
   }

std::set<std::string> Encrypted_PSK_Database::list_names() const
   {
   const std::set<std::string> encrypted_names = kv_get_all();

   std::set<std::string> names;

   for(std::string enc_name : encrypted_names)
      {
      try
         {
         const secure_vector<uint8_t> raw_name = base64_decode(enc_name);
         const secure_vector<uint8_t> name_bits =
            nist_key_unwrap_padded(raw_name.data(), raw_name.size(), *m_cipher);

         std::string pt_name(cast_uint8_ptr_to_char(name_bits.data()), name_bits.size());
         names.insert(pt_name);
         }
      catch(Invalid_Authentication_Tag&)
         {
         }
      }

   return names;
   }

void Encrypted_PSK_Database::remove(const std::string& name)
   {
   const std::vector<uint8_t> wrapped_name =
      nist_key_wrap_padded(cast_char_ptr_to_uint8(name.data()),
                           name.size(),
                           *m_cipher);

   this->kv_del(base64_encode(wrapped_name));
   }

secure_vector<uint8_t> Encrypted_PSK_Database::get(const std::string& name) const
   {
   const std::vector<uint8_t> wrapped_name =
      nist_key_wrap_padded(cast_char_ptr_to_uint8(name.data()),
                           name.size(),
                           *m_cipher);

   const std::string val_base64 = kv_get(base64_encode(wrapped_name));

   if(val_base64.empty())
      throw Invalid_Argument("Named PSK not located");

   const secure_vector<uint8_t> val = base64_decode(val_base64);

   std::unique_ptr<BlockCipher> wrap_cipher(m_cipher->clone());
   wrap_cipher->set_key(m_hmac->process(wrapped_name));

   return nist_key_unwrap_padded(val.data(), val.size(), *wrap_cipher);
   }

void Encrypted_PSK_Database::set(const std::string& name, const uint8_t val[], size_t len)
   {
   /*
   * Both as a basic precaution wrt key seperation, and specifically to prevent
   * cut-and-paste attacks against the database, each PSK is encrypted with a
   * distinct key which is derived by hashing the wrapped key name with HMAC.
   */
   const std::vector<uint8_t> wrapped_name =
      nist_key_wrap_padded(cast_char_ptr_to_uint8(name.data()),
                           name.size(),
                           *m_cipher);

   std::unique_ptr<BlockCipher> wrap_cipher(m_cipher->clone());
   wrap_cipher->set_key(m_hmac->process(wrapped_name));
   const std::vector<uint8_t> wrapped_key = nist_key_wrap_padded(val, len, *wrap_cipher);

   this->kv_set(base64_encode(wrapped_name), base64_encode(wrapped_key));
   }

}
