/*
* OFB Mode
* (C) 1999-2007,2014 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/ofb.h>
#include <botan/exceptn.h>

namespace Botan {

OFB::OFB(BlockCipher* cipher) :
   m_cipher(cipher),
   m_buffer(m_cipher->block_size()),
   m_buf_pos(0)
   {
   }

void OFB::clear()
   {
   m_cipher->clear();
   zeroise(m_buffer);
   m_buf_pos = 0;
   }

void OFB::key_schedule(const uint8_t key[], size_t key_len)
   {
   m_cipher->set_key(key, key_len);

   // Set a default all-zeros IV
   set_iv(nullptr, 0);
   }

std::string OFB::name() const
   {
   return "OFB(" + m_cipher->name() + ")";
   }

size_t OFB::default_iv_length() const
   {
   return m_cipher->block_size();
   }

bool OFB::valid_iv_length(size_t iv_len) const
   {
   return (iv_len <= m_cipher->block_size());
   }

Key_Length_Specification OFB::key_spec() const
   {
   return m_cipher->key_spec();
   }

OFB* OFB::clone() const
   {
   return new OFB(m_cipher->clone());
   }

void OFB::cipher(const uint8_t in[], uint8_t out[], size_t length)
   {
   while(length >= m_buffer.size() - m_buf_pos)
      {
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

void OFB::set_iv(const uint8_t iv[], size_t iv_len)
   {
   if(!valid_iv_length(iv_len))
      throw Invalid_IV_Length(name(), iv_len);

   zeroise(m_buffer);
   buffer_insert(m_buffer, 0, iv, iv_len);

   m_cipher->encrypt(m_buffer);
   m_buf_pos = 0;
   }


void OFB::seek(uint64_t)
   {
   throw Not_Implemented("OFB does not support seeking");
   }
}
