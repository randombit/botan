/*
* HKDF
* (C) 2013,2015,2017 Jack Lloyd
* (C) 2016 René Korthaus, Rohde & Schwarz Cybersecurity
* (C) 2024 René Meusel, Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/hkdf.h>

#include <botan/exceptn.h>
#include <botan/internal/fmt.h>
#include <botan/internal/loadstor.h>
#include <botan/internal/stl_util.h>

namespace Botan {

std::unique_ptr<KDF> HKDF::new_object() const {
   return std::make_unique<HKDF>(m_prf->new_object());
}

std::string HKDF::name() const {
   return fmt("HKDF({})", m_prf->name());
}

void HKDF::perform_kdf(std::span<uint8_t> key,
                       std::span<const uint8_t> secret,
                       std::span<const uint8_t> salt,
                       std::span<const uint8_t> label) const {
   HKDF_Extract extract(m_prf->new_object());
   HKDF_Expand expand(m_prf->new_object());
   secure_vector<uint8_t> prk(m_prf->output_length());

   extract.derive_key(prk, secret, salt, {});
   expand.derive_key(key, prk, {}, label);
}

std::unique_ptr<KDF> HKDF_Extract::new_object() const {
   return std::make_unique<HKDF_Extract>(m_prf->new_object());
}

std::string HKDF_Extract::name() const {
   return fmt("HKDF-Extract({})", m_prf->name());
}

void HKDF_Extract::perform_kdf(std::span<uint8_t> key,
                               std::span<const uint8_t> secret,
                               std::span<const uint8_t> salt,
                               std::span<const uint8_t> label) const {
   const size_t prf_output_len = m_prf->output_length();
   BOTAN_ARG_CHECK(key.size() <= prf_output_len, "HKDF-Extract maximum output length exceeeded");
   BOTAN_ARG_CHECK(label.empty(), "HKDF-Extract does not support a label input");

   if(key.empty()) {
      return;
   }

   if(salt.empty()) {
      m_prf->set_key(std::vector<uint8_t>(prf_output_len));
   } else {
      m_prf->set_key(salt);
   }

   m_prf->update(secret);

   if(key.size() == prf_output_len) {
      m_prf->final(key);
   } else {
      const auto prk = m_prf->final();
      copy_mem(key, std::span{prk}.first(key.size()));
   }
}

std::unique_ptr<KDF> HKDF_Expand::new_object() const {
   return std::make_unique<HKDF_Expand>(m_prf->new_object());
}

std::string HKDF_Expand::name() const {
   return fmt("HKDF-Expand({})", m_prf->name());
}

void HKDF_Expand::perform_kdf(std::span<uint8_t> key,
                              std::span<const uint8_t> secret,
                              std::span<const uint8_t> salt,
                              std::span<const uint8_t> label) const {
   const auto prf_output_length = m_prf->output_length();
   BOTAN_ARG_CHECK(key.size() <= prf_output_length * 255, "HKDF-Expand maximum output length exceeeded");

   if(key.empty()) {
      return;
   }

   // Keep a reference to the previous PRF output (empty by default).
   std::span<uint8_t> h = {};

   BufferStuffer k(key);
   m_prf->set_key(secret);
   for(uint8_t counter = 1; !k.full(); ++counter) {
      m_prf->update(h);
      m_prf->update(label);
      m_prf->update(salt);
      m_prf->update(counter);

      // Write straight into the output buffer, except if the PRF output needs
      // a truncation in the final iteration.
      if(k.remaining_capacity() >= prf_output_length) {
         h = k.next(prf_output_length);
         m_prf->final(h);
      } else {
         const auto full_prf_output = m_prf->final();
         h = {};  // this is the final iteration!
         k.append(std::span{full_prf_output}.first(k.remaining_capacity()));
      }
   }
}

secure_vector<uint8_t> hkdf_expand_label(std::string_view hash_fn,
                                         std::span<const uint8_t> secret,
                                         std::string_view label,
                                         std::span<const uint8_t> hash_val,
                                         size_t length) {
   BOTAN_ARG_CHECK(length <= 0xFFFF, "HKDF-Expand-Label requested output too large");
   BOTAN_ARG_CHECK(label.size() <= 0xFF, "HKDF-Expand-Label label too long");
   BOTAN_ARG_CHECK(hash_val.size() <= 0xFF, "HKDF-Expand-Label hash too long");

   HKDF_Expand hkdf(MessageAuthenticationCode::create_or_throw(fmt("HMAC({})", hash_fn)));

   const auto prefix = concat<std::vector<uint8_t>>(store_be(static_cast<uint16_t>(length)),
                                                    store_be(static_cast<uint8_t>(label.size())),
                                                    std::span{cast_char_ptr_to_uint8(label.data()), label.size()},
                                                    store_be(static_cast<uint8_t>(hash_val.size())));

   /*
   * We do something a little dirty here to avoid copying the hash_val,
   * making use of the fact that Botan's KDF interface supports label+salt,
   * and knowing that our HKDF hashes first param label then param salt.
   */
   return hkdf.derive_key(length, secret, hash_val, prefix);
}

}  // namespace Botan
