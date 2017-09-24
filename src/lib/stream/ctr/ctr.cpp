/*
* Counter mode
* (C) 1999-2011,2014 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/ctr.h>

namespace Botan {

CTR_BE::CTR_BE(BlockCipher* ciph) :
   m_cipher(ciph),
   m_counter(m_cipher->parallel_bytes()),
   m_pad(m_counter.size()),
   m_iv(m_cipher->block_size()),
   m_block_size(m_cipher->block_size()),
   m_ctr_size(m_block_size),
   m_pad_pos(0)
   {
   }

CTR_BE::CTR_BE(BlockCipher* cipher, size_t ctr_size) :
   m_cipher(cipher),
   m_counter(m_cipher->parallel_bytes()),
   m_pad(m_counter.size()),
   m_iv(m_cipher->block_size()),
   m_block_size(m_cipher->block_size()),
   m_ctr_size(ctr_size),
   m_pad_pos(0)
   {
   if(m_ctr_size == 0 || m_ctr_size > m_block_size)
      throw Invalid_Argument("Invalid CTR-BE counter size");
   }

void CTR_BE::clear()
   {
   m_cipher->clear();
   zeroise(m_pad);
   zeroise(m_counter);
   zeroise(m_iv);
   m_pad_pos = 0;
   }

void CTR_BE::key_schedule(const uint8_t key[], size_t key_len)
   {
   m_cipher->set_key(key, key_len);

   // Set a default all-zeros IV
   set_iv(nullptr, 0);
   }

std::string CTR_BE::name() const
   {
   return ("CTR-BE(" + m_cipher->name() + ")");
   }

void CTR_BE::cipher(const uint8_t in[], uint8_t out[], size_t length)
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

void CTR_BE::set_iv(const uint8_t iv[], size_t iv_len)
   {
   if(!valid_iv_length(iv_len))
      throw Invalid_IV_Length(name(), iv_len);

   zeroise(m_iv);
   buffer_insert(m_iv, 0, iv, iv_len);

   seek(0);
   }

/*
* Increment the counter and update the buffer
*/
void CTR_BE::increment_counter()
   {
   const size_t n_wide = m_counter.size() / m_block_size;

   add_counter(n_wide);

   m_cipher->encrypt_n(m_counter.data(), m_pad.data(), n_wide);
   m_pad_pos = 0;
   }

void CTR_BE::add_counter(const uint64_t counter)
   {
   const size_t n_wide = m_counter.size() / m_block_size;

   for(size_t i = 0; i != n_wide; ++i)
      {
      uint64_t local_counter = counter;
      uint16_t carry = static_cast<uint8_t>(local_counter);
      for(size_t j = 0; (carry || local_counter) && j != m_ctr_size; ++j)
         {
         const size_t off = i*m_block_size + (m_block_size-1-j);
         const uint16_t cnt = static_cast<uint16_t>(m_counter[off]) + carry;
         m_counter[off] = static_cast<uint8_t>(cnt);
         local_counter = (local_counter >> 8);
         carry = (cnt >> 8) + static_cast<uint8_t>(local_counter);
         }
      }
   }

void CTR_BE::seek(uint64_t offset)
   {
   const size_t n_wide = m_counter.size() / m_block_size;
   const uint64_t base_counter = n_wide * (offset / m_counter.size());

   zeroise(m_counter);
   buffer_insert(m_counter, 0, m_iv);

   // Set m_counter blocks to IV, IV + 1, ... IV + n
   for(size_t i = 1; i != n_wide; ++i)
      {
      buffer_insert(m_counter,
                    i*m_block_size,
                    &m_counter[(i-1)*m_block_size],
                    m_block_size);

      for(size_t j = 0; j != m_ctr_size; ++j)
         if(++m_counter[i*m_block_size + (m_block_size - 1 - j)])
            break;
      }

   if (base_counter > 0)
      add_counter(base_counter);

   m_cipher->encrypt_n(m_counter.data(), m_pad.data(), n_wide);
   m_pad_pos = offset % m_counter.size();
   }
}
