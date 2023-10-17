/*
* ChaCha20Poly1305 AEAD
* (C) 2014,2016,2018 Jack Lloyd
* (C) 2016 Daniel Neus, Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/chacha20poly1305.h>

#include <botan/internal/ct_utils.h>
#include <botan/internal/loadstor.h>

namespace Botan {

ChaCha20Poly1305_Mode::ChaCha20Poly1305_Mode() :
      m_chacha(StreamCipher::create("ChaCha")), m_poly1305(MessageAuthenticationCode::create("Poly1305")) {
   if(!m_chacha || !m_poly1305) {
      throw Algorithm_Not_Found("ChaCha20Poly1305");
   }
}

bool ChaCha20Poly1305_Mode::valid_nonce_length(size_t n) const {
   return (n == 8 || n == 12 || n == 24);
}

size_t ChaCha20Poly1305_Mode::update_granularity() const {
   return 1;
}

size_t ChaCha20Poly1305_Mode::ideal_granularity() const {
   return 128;
}

void ChaCha20Poly1305_Mode::clear() {
   m_chacha->clear();
   m_poly1305->clear();
   reset();
}

void ChaCha20Poly1305_Mode::reset() {
   m_ad.clear();
   m_ctext_len = 0;
   m_nonce_len = 0;
}

bool ChaCha20Poly1305_Mode::has_keying_material() const {
   return m_chacha->has_keying_material();
}

void ChaCha20Poly1305_Mode::key_schedule(std::span<const uint8_t> key) {
   m_chacha->set_key(key);
}

void ChaCha20Poly1305_Mode::set_associated_data_n(size_t idx, std::span<const uint8_t> ad) {
   BOTAN_ARG_CHECK(idx == 0, "ChaCha20Poly1305: cannot handle non-zero index in set_associated_data_n");
   if(m_ctext_len > 0 || m_nonce_len > 0) {
      throw Invalid_State("Cannot set AD for ChaCha20Poly1305 while processing a message");
   }
   m_ad.assign(ad.begin(), ad.end());
}

void ChaCha20Poly1305_Mode::update_len(size_t len) {
   uint8_t len8[8] = {0};
   store_le(static_cast<uint64_t>(len), len8);
   m_poly1305->update(len8, 8);
}

void ChaCha20Poly1305_Mode::start_msg(const uint8_t nonce[], size_t nonce_len) {
   if(!valid_nonce_length(nonce_len)) {
      throw Invalid_IV_Length(name(), nonce_len);
   }

   m_ctext_len = 0;
   m_nonce_len = nonce_len;

   m_chacha->set_iv(nonce, nonce_len);

   uint8_t first_block[64];
   m_chacha->write_keystream(first_block, sizeof(first_block));

   m_poly1305->set_key(first_block, 32);
   // Remainder of first block is discarded
   secure_scrub_memory(first_block, sizeof(first_block));

   m_poly1305->update(m_ad);

   if(cfrg_version()) {
      if(m_ad.size() % 16) {
         const uint8_t zeros[16] = {0};
         m_poly1305->update(zeros, 16 - m_ad.size() % 16);
      }
   } else {
      update_len(m_ad.size());
   }
}

size_t ChaCha20Poly1305_Encryption::process_msg(uint8_t buf[], size_t sz) {
   m_chacha->cipher1(buf, sz);
   m_poly1305->update(buf, sz);  // poly1305 of ciphertext
   m_ctext_len += sz;
   return sz;
}

void ChaCha20Poly1305_Encryption::finish_msg(secure_vector<uint8_t>& buffer, size_t offset) {
   update(buffer, offset);
   if(cfrg_version()) {
      if(m_ctext_len % 16) {
         const uint8_t zeros[16] = {0};
         m_poly1305->update(zeros, 16 - m_ctext_len % 16);
      }
      update_len(m_ad.size());
   }
   update_len(m_ctext_len);

   buffer.resize(buffer.size() + tag_size());
   m_poly1305->final(&buffer[buffer.size() - tag_size()]);
   m_ctext_len = 0;
   m_nonce_len = 0;
}

size_t ChaCha20Poly1305_Decryption::process_msg(uint8_t buf[], size_t sz) {
   m_poly1305->update(buf, sz);  // poly1305 of ciphertext
   m_chacha->cipher1(buf, sz);
   m_ctext_len += sz;
   return sz;
}

void ChaCha20Poly1305_Decryption::finish_msg(secure_vector<uint8_t>& buffer, size_t offset) {
   BOTAN_ARG_CHECK(buffer.size() >= offset, "Offset is out of range");
   const size_t sz = buffer.size() - offset;
   uint8_t* buf = buffer.data() + offset;

   BOTAN_ARG_CHECK(sz >= tag_size(), "input did not include the tag");

   const size_t remaining = sz - tag_size();

   if(remaining) {
      m_poly1305->update(buf, remaining);  // poly1305 of ciphertext
      m_chacha->cipher1(buf, remaining);
      m_ctext_len += remaining;
   }

   if(cfrg_version()) {
      if(m_ctext_len % 16) {
         const uint8_t zeros[16] = {0};
         m_poly1305->update(zeros, 16 - m_ctext_len % 16);
      }
      update_len(m_ad.size());
   }

   update_len(m_ctext_len);

   uint8_t mac[16];
   m_poly1305->final(mac);

   const uint8_t* included_tag = &buf[remaining];

   m_ctext_len = 0;
   m_nonce_len = 0;

   if(!CT::is_equal(mac, included_tag, tag_size()).as_bool()) {
      throw Invalid_Authentication_Tag("ChaCha20Poly1305 tag check failed");
   }
   buffer.resize(offset + remaining);
}

}  // namespace Botan
