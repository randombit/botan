/*
* OFB Mode
* (C) 1999-2007,2014 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/stream_utils.h>
#include <botan/ofb.h>

namespace Botan {

BOTAN_REGISTER_NAMED_T(StreamCipher, "OFB", OFB, OFB::make);

OFB* OFB::make(const Spec& spec)
   {
   if(spec.algo_name() == "OFB" && spec.arg_count() == 1)
      {
      if(BlockCipher* c = Algo_Registry<BlockCipher>::global_registry().make(spec.arg(0)))
         return new OFB(c);
      }
   return nullptr;
   }

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

void OFB::key_schedule(const byte key[], size_t key_len)
   {
   m_cipher->set_key(key, key_len);

   // Set a default all-zeros IV
   set_iv(nullptr, 0);
   }

std::string OFB::name() const
   {
   return "OFB(" + m_cipher->name() + ")";
   }

void OFB::cipher(const byte in[], byte out[], size_t length)
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

void OFB::set_iv(const byte iv[], size_t iv_len)
   {
   if(!valid_iv_length(iv_len))
      throw Invalid_IV_Length(name(), iv_len);

   zeroise(m_buffer);
   buffer_insert(m_buffer, 0, iv, iv_len);

   m_cipher->encrypt(m_buffer);
   m_buf_pos = 0;
   }

}
