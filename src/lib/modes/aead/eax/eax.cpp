/*
* EAX Mode Encryption
* (C) 1999-2007 Jack Lloyd
* (C) 2016 Daniel Neus, Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/eax.h>

#include <botan/internal/cmac.h>
#include <botan/internal/ct_utils.h>
#include <botan/internal/ctr.h>
#include <botan/internal/fmt.h>

namespace Botan {

namespace {

/*
* EAX MAC-based PRF
*/
secure_vector<uint8_t> eax_prf(
   uint8_t tag, size_t block_size, MessageAuthenticationCode& mac, const uint8_t in[], size_t length) {
   for(size_t i = 0; i != block_size - 1; ++i) {
      mac.update(0);
   }
   mac.update(tag);
   mac.update(in, length);
   return mac.final();
}

}  // namespace

/*
* EAX_Mode Constructor
*/
EAX_Mode::EAX_Mode(std::unique_ptr<BlockCipher> cipher, size_t tag_size) :
      m_tag_size(tag_size),
      m_cipher(std::move(cipher)),
      m_ctr(std::make_unique<CTR_BE>(m_cipher->new_object())),
      m_cmac(std::make_unique<CMAC>(m_cipher->new_object())) {
   if(m_tag_size < 8 || m_tag_size > m_cmac->output_length()) {
      throw Invalid_Argument(fmt("Tag size {} is not allowed for {}", tag_size, name()));
   }
}

void EAX_Mode::clear() {
   m_cipher->clear();
   m_ctr->clear();
   m_cmac->clear();
   reset();
}

void EAX_Mode::reset() {
   m_ad_mac.clear();
   m_nonce_mac.clear();

   // Clear out any data added to the CMAC calculation
   try {
      m_cmac->final();
   } catch(Key_Not_Set&) {}
}

std::string EAX_Mode::name() const {
   return (m_cipher->name() + "/EAX");
}

size_t EAX_Mode::update_granularity() const {
   return 1;
}

size_t EAX_Mode::ideal_granularity() const {
   return m_cipher->parallel_bytes();
}

Key_Length_Specification EAX_Mode::key_spec() const {
   return m_ctr->key_spec();
}

bool EAX_Mode::has_keying_material() const {
   return m_ctr->has_keying_material() && m_cmac->has_keying_material();
}

/*
* Set the EAX key
*/
void EAX_Mode::key_schedule(std::span<const uint8_t> key) {
   /*
   * These could share the key schedule, which is one nice part of EAX,
   * but it's much easier to ignore that here...
   */
   m_ctr->set_key(key);
   m_cmac->set_key(key);
}

/*
* Set the EAX associated data
*/
void EAX_Mode::set_associated_data_n(size_t idx, std::span<const uint8_t> ad) {
   BOTAN_ARG_CHECK(idx == 0, "EAX: cannot handle non-zero index in set_associated_data_n");
   if(m_nonce_mac.empty() == false) {
      throw Invalid_State("Cannot set AD for EAX while processing a message");
   }
   m_ad_mac = eax_prf(1, block_size(), *m_cmac, ad.data(), ad.size());
}

void EAX_Mode::start_msg(const uint8_t nonce[], size_t nonce_len) {
   if(!valid_nonce_length(nonce_len)) {
      throw Invalid_IV_Length(name(), nonce_len);
   }

   m_nonce_mac = eax_prf(0, block_size(), *m_cmac, nonce, nonce_len);

   m_ctr->set_iv(m_nonce_mac.data(), m_nonce_mac.size());

   for(size_t i = 0; i != block_size() - 1; ++i) {
      m_cmac->update(0);
   }
   m_cmac->update(2);
}

size_t EAX_Encryption::process_msg(uint8_t buf[], size_t sz) {
   BOTAN_STATE_CHECK(!m_nonce_mac.empty());
   m_ctr->cipher(buf, buf, sz);
   m_cmac->update(buf, sz);
   return sz;
}

void EAX_Encryption::finish_msg(secure_vector<uint8_t>& buffer, size_t offset) {
   BOTAN_STATE_CHECK(!m_nonce_mac.empty());
   update(buffer, offset);

   secure_vector<uint8_t> data_mac = m_cmac->final();
   xor_buf(data_mac, m_nonce_mac, data_mac.size());

   if(m_ad_mac.empty()) {
      m_ad_mac = eax_prf(1, block_size(), *m_cmac, nullptr, 0);
   }

   xor_buf(data_mac, m_ad_mac, data_mac.size());

   buffer += std::make_pair(data_mac.data(), tag_size());

   m_nonce_mac.clear();
}

size_t EAX_Decryption::process_msg(uint8_t buf[], size_t sz) {
   BOTAN_STATE_CHECK(!m_nonce_mac.empty());
   m_cmac->update(buf, sz);
   m_ctr->cipher(buf, buf, sz);
   return sz;
}

void EAX_Decryption::finish_msg(secure_vector<uint8_t>& buffer, size_t offset) {
   BOTAN_ARG_CHECK(buffer.size() >= offset, "Offset is out of range");
   const size_t sz = buffer.size() - offset;
   uint8_t* buf = buffer.data() + offset;

   BOTAN_ARG_CHECK(sz >= tag_size(), "input did not include the tag");

   const size_t remaining = sz - tag_size();

   if(remaining) {
      m_cmac->update(buf, remaining);
      m_ctr->cipher(buf, buf, remaining);
   }

   const uint8_t* included_tag = &buf[remaining];

   secure_vector<uint8_t> mac = m_cmac->final();
   mac ^= m_nonce_mac;

   if(m_ad_mac.empty()) {
      m_ad_mac = eax_prf(1, block_size(), *m_cmac, nullptr, 0);
   }

   mac ^= m_ad_mac;

   const bool accept_mac = CT::is_equal(mac.data(), included_tag, tag_size()).as_bool();

   buffer.resize(offset + remaining);

   m_nonce_mac.clear();

   if(!accept_mac) {
      throw Invalid_Authentication_Tag("EAX tag check failed");
   }
}

}  // namespace Botan
