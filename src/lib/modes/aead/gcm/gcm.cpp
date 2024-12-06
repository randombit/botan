/*
* GCM Mode Encryption
* (C) 2013,2015 Jack Lloyd
* (C) 2016 Daniel Neus, Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/gcm.h>

#include <botan/block_cipher.h>
#include <botan/internal/ct_utils.h>
#include <botan/internal/ctr.h>
#include <botan/internal/fmt.h>
#include <botan/internal/ghash.h>

#include <array>

namespace Botan {

/*
* GCM_Mode Constructor
*/
GCM_Mode::GCM_Mode(std::unique_ptr<BlockCipher> cipher, size_t tag_size) :
      m_tag_size(tag_size), m_cipher_name(cipher->name()) {
   if(cipher->block_size() != GCM_BS) {
      throw Invalid_Argument("Invalid block cipher for GCM");
   }

   /* We allow any of the values 128, 120, 112, 104, or 96 bits as a tag size */
   /* 64 bit tag is still supported but deprecated and will be removed in the future */
   if(m_tag_size != 8 && (m_tag_size < 12 || m_tag_size > 16)) {
      throw Invalid_Argument(fmt("{} cannot use a tag of {} bytes", name(), m_tag_size));
   }

   m_ctr = std::make_unique<CTR_BE>(std::move(cipher), 4);
   m_ghash = std::make_unique<GHASH>();
}

GCM_Mode::~GCM_Mode() = default;

void GCM_Mode::clear() {
   m_ctr->clear();
   m_ghash->clear();
   reset();
}

void GCM_Mode::reset() {
   m_ghash->reset();
}

std::string GCM_Mode::name() const {
   return fmt("{}/GCM({})", m_cipher_name, tag_size());
}

std::string GCM_Mode::provider() const {
   return m_ghash->provider();
}

size_t GCM_Mode::update_granularity() const {
   return 1;
}

size_t GCM_Mode::ideal_granularity() const {
   return GCM_BS * std::max<size_t>(2, BOTAN_BLOCK_CIPHER_PAR_MULT);
}

bool GCM_Mode::valid_nonce_length(size_t len) const {
   // GCM does not support empty nonces
   return (len > 0);
}

Key_Length_Specification GCM_Mode::key_spec() const {
   return m_ctr->key_spec();
}

bool GCM_Mode::has_keying_material() const {
   return m_ctr->has_keying_material();
}

void GCM_Mode::key_schedule(std::span<const uint8_t> key) {
   m_ctr->set_key(key);

   const std::vector<uint8_t> zeros(GCM_BS);
   m_ctr->set_iv(zeros.data(), zeros.size());

   secure_vector<uint8_t> H(GCM_BS);
   m_ctr->encipher(H);
   m_ghash->set_key(H);
}

void GCM_Mode::set_associated_data_n(size_t idx, std::span<const uint8_t> ad) {
   BOTAN_ARG_CHECK(idx == 0, "GCM: cannot handle non-zero index in set_associated_data_n");
   m_ghash->set_associated_data(ad);
}

void GCM_Mode::start_msg(const uint8_t nonce[], size_t nonce_len) {
   if(!valid_nonce_length(nonce_len)) {
      throw Invalid_IV_Length(name(), nonce_len);
   }

   if(m_y0.size() != GCM_BS) {
      m_y0.resize(GCM_BS);
   }

   clear_mem(m_y0.data(), m_y0.size());

   if(nonce_len == 12) {
      copy_mem(m_y0.data(), nonce, nonce_len);
      m_y0[15] = 1;
   } else {
      m_ghash->nonce_hash(m_y0, {nonce, nonce_len});
   }

   m_ctr->set_iv(m_y0.data(), m_y0.size());

   clear_mem(m_y0.data(), m_y0.size());
   m_ctr->encipher(m_y0);

   m_ghash->start(m_y0);
   clear_mem(m_y0.data(), m_y0.size());
}

size_t GCM_Encryption::process_msg(uint8_t buf[], size_t sz) {
   BOTAN_ARG_CHECK(sz % update_granularity() == 0, "Invalid buffer size");
   m_ctr->cipher(buf, buf, sz);
   m_ghash->update({buf, sz});
   return sz;
}

void GCM_Encryption::finish_msg(secure_vector<uint8_t>& buffer, size_t offset) {
   BOTAN_ARG_CHECK(offset <= buffer.size(), "Invalid offset");
   const size_t sz = buffer.size() - offset;
   uint8_t* buf = buffer.data() + offset;

   m_ctr->cipher(buf, buf, sz);
   m_ghash->update({buf, sz});

   std::array<uint8_t, 16> mac = {0};
   m_ghash->final(std::span(mac).first(tag_size()));
   buffer += std::make_pair(mac.data(), tag_size());
}

size_t GCM_Decryption::process_msg(uint8_t buf[], size_t sz) {
   BOTAN_ARG_CHECK(sz % update_granularity() == 0, "Invalid buffer size");
   m_ghash->update({buf, sz});
   m_ctr->cipher(buf, buf, sz);
   return sz;
}

void GCM_Decryption::finish_msg(secure_vector<uint8_t>& buffer, size_t offset) {
   BOTAN_ARG_CHECK(offset <= buffer.size(), "Invalid offset");
   const size_t sz = buffer.size() - offset;
   uint8_t* buf = buffer.data() + offset;

   BOTAN_ARG_CHECK(sz >= tag_size(), "input did not include the tag");

   const size_t remaining = sz - tag_size();

   // handle any final input before the tag
   if(remaining) {
      m_ghash->update({buf, remaining});
      m_ctr->cipher(buf, buf, remaining);
   }

   std::array<uint8_t, 16> mac = {0};
   m_ghash->final(std::span(mac).first(tag_size()));

   const uint8_t* included_tag = &buffer[remaining + offset];

   if(!CT::is_equal(mac.data(), included_tag, tag_size()).as_bool()) {
      throw Invalid_Authentication_Tag("GCM tag check failed");
   }

   buffer.resize(offset + remaining);
}

}  // namespace Botan
