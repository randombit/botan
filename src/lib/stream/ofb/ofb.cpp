/*
* OFB Mode
* (C) 1999-2007,2014 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/ofb.h>

#include <botan/exceptn.h>
#include <botan/internal/fmt.h>

namespace Botan {

OFB::OFB(std::unique_ptr<BlockCipher> cipher) :
      m_cipher(std::move(cipher)), m_buffer(m_cipher->block_size()), m_buf_pos(0) {}

void OFB::clear() {
   m_cipher->clear();
   zeroise(m_buffer);
   m_buf_pos = 0;
}

bool OFB::has_keying_material() const {
   return m_cipher->has_keying_material();
}

size_t OFB::buffer_size() const {
   return m_buffer.size();  // block size
}

void OFB::key_schedule(std::span<const uint8_t> key) {
   m_cipher->set_key(key);

   // Set a default all-zeros IV
   set_iv(nullptr, 0);
}

std::string OFB::name() const {
   return fmt("OFB({})", m_cipher->name());
}

size_t OFB::default_iv_length() const {
   return m_cipher->block_size();
}

bool OFB::valid_iv_length(size_t iv_len) const {
   return (iv_len <= m_cipher->block_size());
}

Key_Length_Specification OFB::key_spec() const {
   return m_cipher->key_spec();
}

std::unique_ptr<StreamCipher> OFB::new_object() const {
   return std::make_unique<OFB>(m_cipher->new_object());
}

void OFB::cipher_bytes(const uint8_t in[], uint8_t out[], size_t length) {
   while(length >= m_buffer.size() - m_buf_pos) {
      xor_buf(out, in, &m_buffer[m_buf_pos], m_buffer.size() - m_buf_pos);
      length -= (m_buffer.size() - m_buf_pos);
      in += (m_buffer.size() - m_buf_pos);
      out += (m_buffer.size() - m_buf_pos);
      m_cipher->encrypt(m_buffer);
      m_buf_pos = 0;
   }
   xor_buf(out, in, &m_buffer[m_buf_pos], length);
   m_buf_pos += length;
}

void OFB::set_iv_bytes(const uint8_t iv[], size_t iv_len) {
   if(!valid_iv_length(iv_len)) {
      throw Invalid_IV_Length(name(), iv_len);
   }

   zeroise(m_buffer);
   BOTAN_ASSERT_NOMSG(m_buffer.size() >= iv_len);
   copy_mem(&m_buffer[0], iv, iv_len);

   m_cipher->encrypt(m_buffer);
   m_buf_pos = 0;
}

void OFB::seek(uint64_t /*offset*/) {
   throw Not_Implemented("OFB does not support seeking");
}
}  // namespace Botan
