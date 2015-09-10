/*
* ChaCha20Poly1305 AEAD
* (C) 2014 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/mode_utils.h>
#include <botan/chacha20poly1305.h>

namespace Botan {

ChaCha20Poly1305_Mode::ChaCha20Poly1305_Mode() :
   m_chacha(make_stream_cipher("ChaCha")),
   m_poly1305(make_message_auth("Poly1305"))
   {}

bool ChaCha20Poly1305_Mode::valid_nonce_length(size_t n) const
   {
   return (n == 8 || n == 12);
   }

void ChaCha20Poly1305_Mode::clear()
   {
   m_chacha->clear();
   m_poly1305->clear();
   m_ad.clear();
   m_ctext_len = 0;
   }

void ChaCha20Poly1305_Mode::key_schedule(const byte key[], size_t length)
   {
   m_chacha->set_key(key, length);
   }

void ChaCha20Poly1305_Mode::set_associated_data(const byte ad[], size_t length)
   {
   if(m_ctext_len)
      throw std::runtime_error("Too late to set AD for ChaCha20Poly1305");
   m_ad.assign(ad, ad + length);
   }

void ChaCha20Poly1305_Mode::update_len(size_t len)
   {
   byte len8[8] = { 0 };
   store_le(static_cast<u64bit>(len), len8);
   m_poly1305->update(len8, 8);
   }

secure_vector<byte> ChaCha20Poly1305_Mode::start_raw(const byte nonce[], size_t nonce_len)
   {
   if(!valid_nonce_length(nonce_len))
      throw Invalid_IV_Length(name(), nonce_len);

   m_ctext_len = 0;
   m_nonce_len = nonce_len;

   m_chacha->set_iv(nonce, nonce_len);

   secure_vector<byte> zeros(64);
   m_chacha->encrypt(zeros);

   m_poly1305->set_key(zeros.data(), 32);
   // Remainder of output is discard

   m_poly1305->update(m_ad);

   if(cfrg_version())
      {
      std::vector<byte> padding(16 - m_ad.size() % 16);
      m_poly1305->update(padding);
      }
   else
      {
      update_len(m_ad.size());
      }

   return secure_vector<byte>();
   }

void ChaCha20Poly1305_Encryption::update(secure_vector<byte>& buffer, size_t offset)
   {
   BOTAN_ASSERT(buffer.size() >= offset, "Offset is sane");
   const size_t sz = buffer.size() - offset;
   byte* buf = buffer.data() + offset;

   m_chacha->cipher1(buf, sz);
   m_poly1305->update(buf, sz); // poly1305 of ciphertext
   m_ctext_len += sz;
   }

void ChaCha20Poly1305_Encryption::finish(secure_vector<byte>& buffer, size_t offset)
   {
   update(buffer, offset);
   if(cfrg_version())
      {
      std::vector<byte> padding(16 - m_ctext_len % 16);
      m_poly1305->update(padding);
      update_len(m_ad.size());
      }
   update_len(m_ctext_len);

   const secure_vector<byte> mac = m_poly1305->final();
   buffer += std::make_pair(mac.data(), tag_size());
   m_ctext_len = 0;
   }

void ChaCha20Poly1305_Decryption::update(secure_vector<byte>& buffer, size_t offset)
   {
   BOTAN_ASSERT(buffer.size() >= offset, "Offset is sane");
   const size_t sz = buffer.size() - offset;
   byte* buf = buffer.data() + offset;

   m_poly1305->update(buf, sz); // poly1305 of ciphertext
   m_chacha->cipher1(buf, sz);
   m_ctext_len += sz;
   }

void ChaCha20Poly1305_Decryption::finish(secure_vector<byte>& buffer, size_t offset)
   {
   BOTAN_ASSERT(buffer.size() >= offset, "Offset is sane");
   const size_t sz = buffer.size() - offset;
   byte* buf = buffer.data() + offset;

   BOTAN_ASSERT(sz >= tag_size(), "Have the tag as part of final input");

   const size_t remaining = sz - tag_size();

   if(remaining)
      {
      m_poly1305->update(buf, remaining); // poly1305 of ciphertext
      m_chacha->cipher1(buf, remaining);
      m_ctext_len += remaining;
      }

   if(cfrg_version())
      {
      for(size_t i = 0; i != 16 - m_ctext_len % 16; ++i)
         m_poly1305->update(0);
      update_len(m_ad.size());
      }

   update_len(m_ctext_len);
   const secure_vector<byte> mac = m_poly1305->final();

   const byte* included_tag = &buf[remaining];

   m_ctext_len = 0;

   if(!same_mem(mac.data(), included_tag, tag_size()))
      throw Integrity_Failure("ChaCha20Poly1305 tag check failed");
   buffer.resize(offset + remaining);
   }

}
