/*
* HKDF
* (C) 2013,2015,2017 Jack Lloyd
* (C) 2016 René Korthaus, Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/hkdf.h>

#include <botan/exceptn.h>
#include <botan/internal/fmt.h>
#include <botan/internal/loadstor.h>

namespace Botan {

std::unique_ptr<KDF> HKDF::new_object() const {
   return std::make_unique<HKDF>(m_prf->new_object());
}

std::string HKDF::name() const {
   return fmt("HKDF({})", m_prf->name());
}

void HKDF::kdf(uint8_t key[],
               size_t key_len,
               const uint8_t secret[],
               size_t secret_len,
               const uint8_t salt[],
               size_t salt_len,
               const uint8_t label[],
               size_t label_len) const {
   HKDF_Extract extract(m_prf->new_object());
   HKDF_Expand expand(m_prf->new_object());
   secure_vector<uint8_t> prk(m_prf->output_length());

   extract.kdf(prk.data(), prk.size(), secret, secret_len, salt, salt_len, nullptr, 0);
   expand.kdf(key, key_len, prk.data(), prk.size(), nullptr, 0, label, label_len);
}

std::unique_ptr<KDF> HKDF_Extract::new_object() const {
   return std::make_unique<HKDF_Extract>(m_prf->new_object());
}

std::string HKDF_Extract::name() const {
   return fmt("HKDF-Extract({})", m_prf->name());
}

void HKDF_Extract::kdf(uint8_t key[],
                       size_t key_len,
                       const uint8_t secret[],
                       size_t secret_len,
                       const uint8_t salt[],
                       size_t salt_len,
                       const uint8_t /*label*/[],
                       size_t label_len) const {
   if(key_len == 0) {
      return;
   }

   const size_t prf_output_len = m_prf->output_length();

   if(key_len > prf_output_len) {
      throw Invalid_Argument("HKDF-Extract maximum output length exceeeded");
   }

   if(label_len > 0) {
      throw Invalid_Argument("HKDF-Extract does not support a label input");
   }

   if(salt_len == 0) {
      m_prf->set_key(std::vector<uint8_t>(prf_output_len));
   } else {
      m_prf->set_key(salt, salt_len);
   }

   m_prf->update(secret, secret_len);

   if(key_len == prf_output_len) {
      m_prf->final(key);
   } else {
      secure_vector<uint8_t> prk;
      m_prf->final(prk);
      copy_mem(&key[0], prk.data(), key_len);
   }
}

std::unique_ptr<KDF> HKDF_Expand::new_object() const {
   return std::make_unique<HKDF_Expand>(m_prf->new_object());
}

std::string HKDF_Expand::name() const {
   return fmt("HKDF-Expand({})", m_prf->name());
}

void HKDF_Expand::kdf(uint8_t key[],
                      size_t key_len,
                      const uint8_t secret[],
                      size_t secret_len,
                      const uint8_t salt[],
                      size_t salt_len,
                      const uint8_t label[],
                      size_t label_len) const {
   if(key_len == 0) {
      return;
   }

   if(key_len > m_prf->output_length() * 255) {
      throw Invalid_Argument("HKDF-Expand maximum output length exceeeded");
   }

   m_prf->set_key(secret, secret_len);

   uint8_t counter = 1;
   secure_vector<uint8_t> h;
   size_t offset = 0;

   while(offset != key_len) {
      m_prf->update(h);
      m_prf->update(label, label_len);
      m_prf->update(salt, salt_len);
      m_prf->update(counter++);
      m_prf->final(h);

      const size_t written = std::min(h.size(), key_len - offset);
      copy_mem(&key[offset], h.data(), written);
      offset += written;
   }
}

secure_vector<uint8_t> hkdf_expand_label(std::string_view hash_fn,
                                         const uint8_t secret[],
                                         size_t secret_len,
                                         std::string_view label,
                                         const uint8_t hash_val[],
                                         size_t hash_val_len,
                                         size_t length) {
   BOTAN_ARG_CHECK(length <= 0xFFFF, "HKDF-Expand-Label requested output too large");
   BOTAN_ARG_CHECK(label.size() <= 0xFF, "HKDF-Expand-Label label too long");
   BOTAN_ARG_CHECK(hash_val_len <= 0xFF, "HKDF-Expand-Label hash too long");

   const uint16_t length16 = static_cast<uint16_t>(length);

   HKDF_Expand hkdf(MessageAuthenticationCode::create_or_throw(fmt("HMAC({})", hash_fn)));

   secure_vector<uint8_t> output(length16);
   std::vector<uint8_t> prefix(3 + label.size() + 1);

   prefix[0] = get_byte<0>(length16);
   prefix[1] = get_byte<1>(length16);
   prefix[2] = static_cast<uint8_t>(label.size());

   copy_mem(prefix.data() + 3, cast_char_ptr_to_uint8(label.data()), label.size());

   prefix[3 + label.size()] = static_cast<uint8_t>(hash_val_len);

   /*
   * We do something a little dirty here to avoid copying the hash_val,
   * making use of the fact that Botan's KDF interface supports label+salt,
   * and knowing that our HKDF hashes first param label then param salt.
   */
   hkdf.kdf(output.data(), output.size(), secret, secret_len, hash_val, hash_val_len, prefix.data(), prefix.size());

   return output;
}

}  // namespace Botan
