/*
* TLS Null Cipher Handling
* (C) 2024 Sebastian Ahrens, Dirk Dobkowitz, André Schomburg (Volkswagen AG)
* (C) 2024 Lars Dürkop (CARIAD SE)
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/tls_null.h>

#include <botan/assert.h>
#include <botan/tls_alert.h>
#include <botan/tls_exceptn.h>
#include <botan/internal/fmt.h>
#include <botan/internal/int_utils.h>
#include <botan/internal/loadstor.h>

namespace Botan::TLS {

/*
* TLS_NULL_HMAC_AEAD_Mode Constructor
*/
TLS_NULL_HMAC_AEAD_Mode::TLS_NULL_HMAC_AEAD_Mode(std::unique_ptr<MessageAuthenticationCode> mac, size_t mac_keylen) :
      m_mac_name(mac->name()), m_mac_keylen(mac_keylen), m_tag_size(mac->output_length()), m_mac(std::move(mac)) {}

void TLS_NULL_HMAC_AEAD_Mode::clear() {
   m_key.clear();
   m_ad.clear();
   mac().clear();
}

void TLS_NULL_HMAC_AEAD_Mode::reset() {
   m_ad.clear();
   // The base AEAD_Mode contract permits reset() before the first key has
   // been set; only re-key the MAC if there is a key to re-key with.
   if(!m_key.empty()) {
      mac().set_key(m_key);
   }
}

std::string TLS_NULL_HMAC_AEAD_Mode::name() const {
   return fmt("TLS_NULL({})", m_mac_name);
}

size_t TLS_NULL_HMAC_AEAD_Mode::update_granularity() const {
   return 1;
}

size_t TLS_NULL_HMAC_AEAD_Mode::ideal_granularity() const {
   return 1;
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

size_t TLS_NULL_HMAC_AEAD_Mode::mac_keylen() const {
   return m_mac_keylen;
}

MessageAuthenticationCode& TLS_NULL_HMAC_AEAD_Mode::mac() const {
   BOTAN_ASSERT_NONNULL(m_mac);
   return *m_mac;
}

void TLS_NULL_HMAC_AEAD_Mode::key_schedule(std::span<const uint8_t> key) {
   if(key.size() != m_mac_keylen) {
      throw Invalid_Key_Length(name(), key.size());
   }
   m_key.assign(key.begin(), key.end());
   reset();
}

void TLS_NULL_HMAC_AEAD_Mode::start_msg(const uint8_t nonce[], size_t nonce_len) {
   BOTAN_UNUSED(nonce);

   if(!valid_nonce_length(nonce_len)) {
      throw Invalid_IV_Length(name(), nonce_len);
   }

   m_processed = false;

   // AEAD_Mode contract: AD set via set_associated_data persists across
   // messages until reset. finish_msg calls mac().final() which clears the
   // internal state, so we re-feed the cached AD at the start of each
   // message rather than once at set_associated_data time.
   if(!m_ad.empty()) {
      mac().update(m_ad);
   }
}

size_t TLS_NULL_HMAC_AEAD_Mode::process_msg(uint8_t buf[], size_t sz) {
   // The TLS record code path MACs each record in a single call (via
   // finish_msg -> process). A second invocation between start_msg and
   // finish_msg would feed additional bytes into the same HMAC instance,
   // producing a tag covering more than the intended record body.
   BOTAN_ASSERT_NOMSG(!m_processed);
   m_processed = true;

   mac().update(buf, sz);
   return sz;
}

void TLS_NULL_HMAC_AEAD_Mode::set_associated_data_n(size_t idx, std::span<const uint8_t> ad) {
   BOTAN_ARG_CHECK(idx == 0, "TLS 1.2 NULL/HMAC: cannot handle non-zero index in set_associated_data_n");
   BOTAN_ARG_CHECK(ad.size() == 13, "TLS 1.2 NULL/HMAC: invalid TLS AEAD associated data length");

   // Cache the AD; the actual MAC update happens at start_msg so the AD
   // persists across messages per the AEAD_Mode contract.
   m_ad.assign(ad.begin(), ad.end());
}

void TLS_NULL_HMAC_AEAD_Encryption::set_associated_data_n(size_t idx, std::span<const uint8_t> ad) {
   TLS_NULL_HMAC_AEAD_Mode::set_associated_data_n(idx, ad);
}

size_t TLS_NULL_HMAC_AEAD_Encryption::output_length(size_t input_length) const {
   return add_or_throw(input_length, tag_size(), "TLS NULL input too large");
}

void TLS_NULL_HMAC_AEAD_Encryption::finish_msg(secure_vector<uint8_t>& buffer, size_t offset) {
   process(std::span{buffer}.subspan(offset));
   const size_t output_size = add_or_throw(buffer.size(), tag_size(), "TLS NULL input too large");
   buffer.resize(output_size);
   mac().final(std::span{buffer}.last(tag_size()));
}

size_t TLS_NULL_HMAC_AEAD_Decryption::output_length(size_t input_length) const {
   BOTAN_ARG_CHECK(input_length >= tag_size(), "Message too short to be valid");
   return input_length - tag_size();
}

void TLS_NULL_HMAC_AEAD_Decryption::finish_msg(secure_vector<uint8_t>& buffer, size_t offset) {
   BOTAN_ARG_CHECK(buffer.size() >= tag_size() + offset,
                   "TLS_NULL_HMAC_AEAD_Decryption needs at least tag_size() bytes in final buffer");

   const auto data_and_tag = std::span{buffer}.subspan(offset);
   const auto data = data_and_tag.first(data_and_tag.size() - tag_size());
   const auto tag = data_and_tag.subspan(data.size());

   process(data);
   if(!mac().verify_mac(tag)) {
      throw TLS_Exception(Alert::BadRecordMac, "Message authentication failure");
   }

   buffer.resize(buffer.size() - tag_size());
}

}  // namespace Botan::TLS
