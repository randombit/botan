/*
* SIV Mode Encryption
* (C) 2013 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/mode_utils.h>
#include <botan/siv.h>
#include <botan/cmac.h>
#include <botan/ctr.h>
#include <botan/parsing.h>

namespace Botan {

SIV_Mode::SIV_Mode(BlockCipher* cipher) :
   m_name(cipher->name() + "/SIV"),
   m_ctr(new CTR_BE(cipher->clone())),
   m_cmac(new CMAC(cipher))
   {
   if(cipher->block_size() != 16)
      throw Invalid_Argument("SIV requires a 128 bit block cipher");
   }

void SIV_Mode::clear()
   {
   m_ctr.reset();
   m_nonce.clear();
   m_msg_buf.clear();
   m_ad_macs.clear();
   }

std::string SIV_Mode::name() const
   {
   return m_name;
   }

bool SIV_Mode::valid_nonce_length(size_t) const
   {
   return true;
   }

size_t SIV_Mode::update_granularity() const
   {
   /*
   This value does not particularly matter as regardless SIV_Mode::update
   buffers all input, so in theory this could be 1. However as for instance
   Transform_Filter creates update_granularity() byte buffers, use a
   somewhat large size to avoid bouncing on a tiny buffer.
   */
   return 128;
   }

Key_Length_Specification SIV_Mode::key_spec() const
   {
   return m_cmac->key_spec().multiple(2);
   }

void SIV_Mode::key_schedule(const byte key[], size_t length)
   {
   const size_t keylen = length / 2;
   m_cmac->set_key(key, keylen);
   m_ctr->set_key(key + keylen, keylen);
   m_ad_macs.clear();
   }

void SIV_Mode::set_associated_data_n(size_t n, const byte ad[], size_t length)
   {
   if(n >= m_ad_macs.size())
      m_ad_macs.resize(n+1);

   m_ad_macs[n] = m_cmac->process(ad, length);
   }

void SIV_Mode::start_msg(const byte nonce[], size_t nonce_len)
   {
   if(!valid_nonce_length(nonce_len))
      throw Invalid_IV_Length(name(), nonce_len);

   if(nonce_len)
      m_nonce = m_cmac->process(nonce, nonce_len);
   else
      m_nonce.clear();

   m_msg_buf.clear();
   }

size_t SIV_Mode::process(uint8_t buf[], size_t sz)
   {
   // all output is saved for processing in finish
   m_msg_buf.insert(m_msg_buf.end(), buf, buf + sz);
   return 0;
   }

secure_vector<byte> SIV_Mode::S2V(const byte* text, size_t text_len)
   {
   const byte zero[16] = { 0 };

   secure_vector<byte> V = m_cmac->process(zero, 16);

   for(size_t i = 0; i != m_ad_macs.size(); ++i)
      {
      V = CMAC::poly_double(V);
      V ^= m_ad_macs[i];
      }

   if(m_nonce.size())
      {
      V = CMAC::poly_double(V);
      V ^= m_nonce;
      }

   if(text_len < 16)
      {
      V = CMAC::poly_double(V);
      xor_buf(V.data(), text, text_len);
      V[text_len] ^= 0x80;
      return m_cmac->process(V);
      }

   m_cmac->update(text, text_len - 16);
   xor_buf(V.data(), &text[text_len - 16], 16);
   m_cmac->update(V);

   return m_cmac->final();
   }

void SIV_Mode::set_ctr_iv(secure_vector<byte> V)
   {
   V[8] &= 0x7F;
   V[12] &= 0x7F;

   ctr().set_iv(V.data(), V.size());
   }

void SIV_Encryption::finish(secure_vector<byte>& buffer, size_t offset)
   {
   BOTAN_ASSERT(buffer.size() >= offset, "Offset is sane");

   buffer.insert(buffer.begin() + offset, msg_buf().begin(), msg_buf().end());

   secure_vector<byte> V = S2V(buffer.data() + offset, buffer.size() - offset);

   buffer.insert(buffer.begin() + offset, V.begin(), V.end());

   set_ctr_iv(V);
   ctr().cipher1(&buffer[offset + V.size()], buffer.size() - offset - V.size());
   }

void SIV_Decryption::finish(secure_vector<byte>& buffer, size_t offset)
   {
   BOTAN_ASSERT(buffer.size() >= offset, "Offset is sane");

   buffer.insert(buffer.begin() + offset, msg_buf().begin(), msg_buf().end());

   const size_t sz = buffer.size() - offset;

   BOTAN_ASSERT(sz >= tag_size(), "We have the tag");

   secure_vector<byte> V(buffer.data() + offset, buffer.data() + offset + 16);

   set_ctr_iv(V);

   ctr().cipher(buffer.data() + offset + V.size(),
                buffer.data() + offset,
                buffer.size() - offset - V.size());

   secure_vector<byte> T = S2V(buffer.data() + offset, buffer.size() - offset - V.size());

   if(T != V)
      throw Integrity_Failure("SIV tag check failed");

   buffer.resize(buffer.size() - tag_size());
   }

}
