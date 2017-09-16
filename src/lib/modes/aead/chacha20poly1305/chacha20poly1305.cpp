/*
* ChaCha20Poly1305 AEAD
* (C) 2014,2016 Jack Lloyd
* (C) 2016 Daniel Neus, Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/chacha20poly1305.h>

namespace Botan {

ChaCha20Poly1305_Mode::ChaCha20Poly1305_Mode() :
   m_chacha(StreamCipher::create("ChaCha")),
   m_poly1305(MessageAuthenticationCode::create("Poly1305"))
   {
   if(!m_chacha || !m_poly1305)
      throw Algorithm_Not_Found("ChaCha20Poly1305");
   }

bool ChaCha20Poly1305_Mode::valid_nonce_length(size_t n) const
   {
   return (n == 8 || n == 12);
   }

void ChaCha20Poly1305_Mode::clear()
   {
   m_chacha->clear();
   m_poly1305->clear();
   reset();
   }

void ChaCha20Poly1305_Mode::reset()
   {
   m_ad.clear();
   m_ctext_len = 0;
   m_nonce_len = 0;
   }

void ChaCha20Poly1305_Mode::key_schedule(const uint8_t key[], size_t length)
   {
   m_chacha->set_key(key, length);
   }

void ChaCha20Poly1305_Mode::set_associated_data(const uint8_t ad[], size_t length)
   {
   if(m_ctext_len)
      throw Exception("Too late to set AD for ChaCha20Poly1305");
   m_ad.assign(ad, ad + length);
   }

void ChaCha20Poly1305_Mode::update_len(size_t len)
   {
   uint8_t len8[8] = { 0 };
   store_le(static_cast<uint64_t>(len), len8);
   m_poly1305->update(len8, 8);
   }

void ChaCha20Poly1305_Mode::start_msg(const uint8_t nonce[], size_t nonce_len)
   {
   if(!valid_nonce_length(nonce_len))
      throw Invalid_IV_Length(name(), nonce_len);

   m_ctext_len = 0;
   m_nonce_len = nonce_len;

   m_chacha->set_iv(nonce, nonce_len);

   secure_vector<uint8_t> init(64); // zeros
   m_chacha->encrypt(init);

   m_poly1305->set_key(init.data(), 32);
   // Remainder of output is discard

   m_poly1305->update(m_ad);

   if(cfrg_version())
      {
      if(m_ad.size() % 16)
         {
         const uint8_t zeros[16] = { 0 };
         m_poly1305->update(zeros, 16 - m_ad.size() % 16);
         }
      }
   else
      {
      update_len(m_ad.size());
      }
   }

size_t ChaCha20Poly1305_Encryption::process(uint8_t buf[], size_t sz)
   {
   m_chacha->cipher1(buf, sz);
   m_poly1305->update(buf, sz); // poly1305 of ciphertext
   m_ctext_len += sz;
   return sz;
   }

void ChaCha20Poly1305_Encryption::finish(secure_vector<uint8_t>& buffer, size_t offset)
   {
   update(buffer, offset);
   if(cfrg_version())
      {
      if(m_ctext_len % 16)
         {
         const uint8_t zeros[16] = { 0 };
         m_poly1305->update(zeros, 16 - m_ctext_len % 16);
         }
      update_len(m_ad.size());
      }
   update_len(m_ctext_len);

   const secure_vector<uint8_t> mac = m_poly1305->final();
   buffer += std::make_pair(mac.data(), tag_size());
   m_ctext_len = 0;
   }

size_t ChaCha20Poly1305_Decryption::process(uint8_t buf[], size_t sz)
   {
   m_poly1305->update(buf, sz); // poly1305 of ciphertext
   m_chacha->cipher1(buf, sz);
   m_ctext_len += sz;
   return sz;
   }

void ChaCha20Poly1305_Decryption::finish(secure_vector<uint8_t>& buffer, size_t offset)
   {
   BOTAN_ASSERT(buffer.size() >= offset, "Offset is sane");
   const size_t sz = buffer.size() - offset;
   uint8_t* buf = buffer.data() + offset;

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
      if(m_ctext_len % 16)
         {
         const uint8_t zeros[16] = { 0 };
         m_poly1305->update(zeros, 16 - m_ctext_len % 16);
         }
      update_len(m_ad.size());
      }

   update_len(m_ctext_len);
   const secure_vector<uint8_t> mac = m_poly1305->final();

   const uint8_t* included_tag = &buf[remaining];

   m_ctext_len = 0;

   if(!constant_time_compare(mac.data(), included_tag, tag_size()))
      throw Integrity_Failure("ChaCha20Poly1305 tag check failed");
   buffer.resize(offset + remaining);
   }

}
