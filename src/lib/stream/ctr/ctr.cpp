/*
* Counter mode
* (C) 1999-2011,2014 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/stream_utils.h>
#include <botan/ctr.h>

namespace Botan {

BOTAN_REGISTER_NAMED_T(StreamCipher, "CTR-BE", CTR_BE, CTR_BE::make);

CTR_BE* CTR_BE::make(const Spec& spec)
   {
   if(spec.algo_name() == "CTR-BE" && spec.arg_count() == 1)
      {
      if(BlockCipher* c = Algo_Registry<BlockCipher>::global_registry().make(spec.arg(0)))
         return new CTR_BE(c);
      }
   return nullptr;
   }

CTR_BE::CTR_BE(BlockCipher* ciph) :
   m_cipher(ciph),
   m_counter(m_cipher->parallel_bytes()),
   m_pad(m_counter.size()),
   m_pad_pos(0)
   {
   }

void CTR_BE::clear()
   {
   m_cipher->clear();
   zeroise(m_pad);
   zeroise(m_counter);
   m_pad_pos = 0;
   }

void CTR_BE::key_schedule(const byte key[], size_t key_len)
   {
   m_cipher->set_key(key, key_len);

   // Set a default all-zeros IV
   set_iv(nullptr, 0);
   }

std::string CTR_BE::name() const
   {
   return ("CTR-BE(" + m_cipher->name() + ")");
   }

void CTR_BE::cipher(const byte in[], byte out[], size_t length)
   {
   while(length >= m_pad.size() - m_pad_pos)
      {
      xor_buf(out, in, &m_pad[m_pad_pos], m_pad.size() - m_pad_pos);
      length -= (m_pad.size() - m_pad_pos);
      in += (m_pad.size() - m_pad_pos);
      out += (m_pad.size() - m_pad_pos);
      increment_counter();
      }
   xor_buf(out, in, &m_pad[m_pad_pos], length);
   m_pad_pos += length;
   }

void CTR_BE::set_iv(const byte iv[], size_t iv_len)
   {
   if(!valid_iv_length(iv_len))
      throw Invalid_IV_Length(name(), iv_len);

   const size_t bs = m_cipher->block_size();

   zeroise(m_counter);

   const size_t n_wide = m_counter.size() / m_cipher->block_size();
   buffer_insert(m_counter, 0, iv, iv_len);

   // Set m_counter blocks to IV, IV + 1, ... IV + n
   for(size_t i = 1; i != n_wide; ++i)
      {
      buffer_insert(m_counter, i*bs, &m_counter[(i-1)*bs], bs);

      for(size_t j = 0; j != bs; ++j)
         if(++m_counter[i*bs + (bs - 1 - j)])
            break;
      }

   m_cipher->encrypt_n(&m_counter[0], &m_pad[0], n_wide);
   m_pad_pos = 0;
   }

/*
* Increment the counter and update the buffer
*/
void CTR_BE::increment_counter()
   {
   const size_t bs = m_cipher->block_size();
   const size_t n_wide = m_counter.size() / bs;

   for(size_t i = 0; i != n_wide; ++i)
      {
      uint16_t carry = n_wide;
      for(size_t j = 0; carry && j != bs; ++j)
         {
         const size_t off = i*bs + (bs-1-j);
         const uint16_t cnt = static_cast<uint16_t>(m_counter[off]) + carry;
         m_counter[off] = static_cast<byte>(cnt);
         carry = (cnt >> 8);
         }
      }

   m_cipher->encrypt_n(&m_counter[0], &m_pad[0], n_wide);
   m_pad_pos = 0;
   }

}
