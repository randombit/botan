/*
* TLS Null Cipher Handling
* (C) 2024 Sebastian Ahrens, Dirk Dobkowitz, André Schomburg (Volkswagen AG)
* (C) 2024 Lars Dürkop (CARIAD SE)
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/tls_alert.h>
#include <botan/tls_exceptn.h>
#include <botan/internal/loadstor.h>
#include <botan/internal/tls_null.h>

namespace Botan {

namespace TLS {

/*
* TLS_NULL_HMAC_AEAD_Mode Constructor
*/
TLS_NULL_HMAC_AEAD_Mode::TLS_NULL_HMAC_AEAD_Mode(std::unique_ptr<MessageAuthenticationCode> mac, size_t mac_keylen) :
      m_mac_name(mac->name()), m_mac_keylen(mac_keylen), m_tag_size(mac->output_length()), m_mac(std::move(mac)){};

void TLS_NULL_HMAC_AEAD_Mode::clear() {
   mac().clear();
   reset();
}

void TLS_NULL_HMAC_AEAD_Mode::reset() {
   m_ad.clear();
   m_msg.clear();
}

std::string TLS_NULL_HMAC_AEAD_Mode::name() const {
   return "TLS_NULL(" + m_mac_name + ")";
}

size_t TLS_NULL_HMAC_AEAD_Mode::update_granularity() const {
   return 1;  // just buffers anyway
}

size_t TLS_NULL_HMAC_AEAD_Mode::ideal_granularity() const {
   return 1;  // just buffers anyway
}

bool TLS_NULL_HMAC_AEAD_Mode::valid_nonce_length(size_t nl) const {
   return nl == 0;
}

Key_Length_Specification TLS_NULL_HMAC_AEAD_Mode::key_spec() const {
   return Key_Length_Specification(m_mac_keylen);
}

bool TLS_NULL_HMAC_AEAD_Mode::has_keying_material() const {
   return mac().has_keying_material();
}

void TLS_NULL_HMAC_AEAD_Mode::key_schedule(std::span<const uint8_t> key) {
   if(key.size() != m_mac_keylen) {
      throw Invalid_Key_Length(name(), key.size());
   }
   mac().set_key(key);
}

void TLS_NULL_HMAC_AEAD_Mode::start_msg(const uint8_t nonce[], size_t nonce_len) {
   static_cast<void>(nonce);

   if(!valid_nonce_length(nonce_len)) {
      throw Invalid_IV_Length(name(), nonce_len);
   }
   m_msg.clear();
}

size_t TLS_NULL_HMAC_AEAD_Mode::process_msg(uint8_t buf[], size_t sz) {
   m_msg.insert(m_msg.end(), buf, buf + sz);
   return 0;
}

void TLS_NULL_HMAC_AEAD_Mode::set_associated_data_n(size_t idx, std::span<const uint8_t> ad) {
   BOTAN_ARG_CHECK(idx == 0, "TLS 1.2 NULL/HMAC: cannot handle non-zero index in set_associated_data_n");
   if(ad.size() != 13) {
      throw Invalid_Argument("Invalid TLS AEAD associated data length");
   }
   m_ad.assign(ad.begin(), ad.end());
}

void TLS_NULL_HMAC_AEAD_Encryption::set_associated_data_n(size_t idx, std::span<const uint8_t> ad) {
   TLS_NULL_HMAC_AEAD_Mode::set_associated_data_n(idx, ad);
}

size_t TLS_NULL_HMAC_AEAD_Encryption::output_length(size_t input_length) const {
   return input_length + tag_size();
}

void TLS_NULL_HMAC_AEAD_Encryption::finish_msg(secure_vector<uint8_t>& buffer, size_t offset) {
   update(buffer, offset);
   buffer.resize(offset);  // truncate, leaving just header
   buffer.insert(buffer.end(), msg().begin(), msg().end());

   mac().update(assoc_data());
   mac().update(msg().data(), msg().size());
   buffer.resize(buffer.size() + tag_size());
   mac().final(&buffer[buffer.size() - tag_size()]);
}

size_t TLS_NULL_HMAC_AEAD_Decryption::output_length(size_t input_length) const {
   return input_length - tag_size();
}

void TLS_NULL_HMAC_AEAD_Decryption::finish_msg(secure_vector<uint8_t>& buffer, size_t offset) {
   update(buffer, offset);
   buffer.resize(offset);

   const size_t record_len = msg().size();
   uint8_t* record_contents = msg().data();

   if(record_len < tag_size()) {
      throw TLS_Exception(Alert::BadRecordMac, "Message authentication failure");
   }

   const size_t enc_size = record_len - tag_size();

   mac().update(assoc_data());
   mac().update(record_contents, enc_size);

   std::vector<uint8_t> mac_buf(tag_size());
   mac().final(mac_buf.data());

   const bool mac_ok = constant_time_compare(&record_contents[enc_size], mac_buf.data(), tag_size());

   if(!mac_ok) {
      throw TLS_Exception(Alert::BadRecordMac, "Message authentication failure");
   }

   buffer.insert(buffer.end(), record_contents, record_contents + enc_size);
}
}  // namespace TLS

}  // namespace Botan
