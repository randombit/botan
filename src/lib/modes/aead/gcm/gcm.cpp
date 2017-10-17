/*
* GCM Mode Encryption
* (C) 2013,2015 Jack Lloyd
* (C) 2016 Daniel Neus, Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/gcm.h>
#include <botan/ghash.h>
#include <botan/block_cipher.h>
#include <botan/ctr.h>

namespace Botan {

/*
* GCM_Mode Constructor
*/
GCM_Mode::GCM_Mode(BlockCipher* cipher, size_t tag_size) :
   m_tag_size(tag_size),
   m_cipher_name(cipher->name())
   {
   if(cipher->block_size() != GCM_BS)
      throw Invalid_Argument("Invalid block cipher for GCM");

   m_ghash.reset(new GHASH);

   m_ctr.reset(new CTR_BE(cipher, 4)); // CTR_BE takes ownership of cipher

   /* We allow any of the values 128, 120, 112, 104, or 96 bits as a tag size */
   /* 64 bit tag is still supported but deprecated and will be removed in the future */
   if(m_tag_size != 8 && (m_tag_size < 12 || m_tag_size > 16))
      throw Invalid_Argument(name() + ": Bad tag size " + std::to_string(m_tag_size));
   }

GCM_Mode::~GCM_Mode() { /* for unique_ptr */ }

void GCM_Mode::clear()
   {
   m_ctr->clear();
   m_ghash->clear();
   reset();
   }

void GCM_Mode::reset()
   {
   m_ghash->reset();
   }

std::string GCM_Mode::name() const
   {
   return (m_cipher_name + "/GCM(" + std::to_string(tag_size()) + ")");
   }

std::string GCM_Mode::provider() const
   {
   return m_ghash->provider();
   }

size_t GCM_Mode::update_granularity() const
   {
   return GCM_BS;
   }

Key_Length_Specification GCM_Mode::key_spec() const
   {
   return m_ctr->key_spec();
   }

void GCM_Mode::key_schedule(const uint8_t key[], size_t keylen)
   {
   m_ctr->set_key(key, keylen);

   const std::vector<uint8_t> zeros(GCM_BS);
   m_ctr->set_iv(zeros.data(), zeros.size());

   secure_vector<uint8_t> H(GCM_BS);
   m_ctr->encipher(H);
   m_ghash->set_key(H);
   }

void GCM_Mode::set_associated_data(const uint8_t ad[], size_t ad_len)
   {
   m_ghash->set_associated_data(ad, ad_len);
   }

void GCM_Mode::start_msg(const uint8_t nonce[], size_t nonce_len)
   {
   if(!valid_nonce_length(nonce_len))
      throw Invalid_IV_Length(name(), nonce_len);

   secure_vector<uint8_t> y0(GCM_BS);

   if(nonce_len == 12)
      {
      copy_mem(y0.data(), nonce, nonce_len);
      y0[15] = 1;
      }
   else
      {
      y0 = m_ghash->nonce_hash(nonce, nonce_len);
      }

   m_ctr->set_iv(y0.data(), y0.size());

   secure_vector<uint8_t> m_enc_y0(GCM_BS);
   m_ctr->encipher(m_enc_y0);

   m_ghash->start(m_enc_y0.data(), m_enc_y0.size());
   }

size_t GCM_Encryption::process(uint8_t buf[], size_t sz)
   {
   BOTAN_ARG_CHECK(sz % update_granularity() == 0);
   m_ctr->cipher(buf, buf, sz);
   m_ghash->update(buf, sz);
   return sz;
   }

void GCM_Encryption::finish(secure_vector<uint8_t>& buffer, size_t offset)
   {
   BOTAN_ARG_CHECK(offset <= buffer.size());
   const size_t sz = buffer.size() - offset;
   uint8_t* buf = buffer.data() + offset;

   m_ctr->cipher(buf, buf, sz);
   m_ghash->update(buf, sz);
   auto mac = m_ghash->final();
   buffer += std::make_pair(mac.data(), tag_size());
   }

size_t GCM_Decryption::process(uint8_t buf[], size_t sz)
   {
   BOTAN_ARG_CHECK(sz % update_granularity() == 0);
   m_ghash->update(buf, sz);
   m_ctr->cipher(buf, buf, sz);
   return sz;
   }

void GCM_Decryption::finish(secure_vector<uint8_t>& buffer, size_t offset)
   {
   BOTAN_ARG_CHECK(offset <= buffer.size());
   const size_t sz = buffer.size() - offset;
   uint8_t* buf = buffer.data() + offset;

   if(sz < tag_size())
      throw Exception("Insufficient input for GCM decryption, tag missing");

   const size_t remaining = sz - tag_size();

   // handle any final input before the tag
   if(remaining)
      {
      m_ghash->update(buf, remaining);
      m_ctr->cipher(buf, buf, remaining);
      }

   auto mac = m_ghash->final();

   const uint8_t* included_tag = &buffer[remaining+offset];

   if(!constant_time_compare(mac.data(), included_tag, tag_size()))
      throw Integrity_Failure("GCM tag check failed");

   buffer.resize(offset + remaining);
   }

}
