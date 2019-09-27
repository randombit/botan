/*
* Counter mode
* (C) 1999-2011,2014 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/ctr.h>
#include <botan/exceptn.h>
#include <botan/loadstor.h>
#include <botan/internal/bit_ops.h>

namespace Botan {

CTR_BE::CTR_BE(BlockCipher* ciph) :
   m_cipher(ciph),
   m_block_size(m_cipher->block_size()),
   m_ctr_size(m_block_size),
   m_ctr_blocks(m_cipher->parallel_bytes() / m_block_size),
   m_counter(m_cipher->parallel_bytes()),
   m_pad(m_counter.size()),
   m_pad_pos(0)
   {
   }

CTR_BE::CTR_BE(BlockCipher* cipher, size_t ctr_size) :
   m_cipher(cipher),
   m_block_size(m_cipher->block_size()),
   m_ctr_size(ctr_size),
   m_ctr_blocks(m_cipher->parallel_bytes() / m_block_size),
   m_counter(m_cipher->parallel_bytes()),
   m_pad(m_counter.size()),
   m_pad_pos(0)
   {
   BOTAN_ARG_CHECK(m_ctr_size >= 4 && m_ctr_size <= m_block_size,
                   "Invalid CTR-BE counter size");
   }

void CTR_BE::clear()
   {
   m_cipher->clear();
   zeroise(m_pad);
   zeroise(m_counter);
   zap(m_iv);
   m_pad_pos = 0;
   }

size_t CTR_BE::default_iv_length() const
   {
   return m_block_size;
   }

bool CTR_BE::valid_iv_length(size_t iv_len) const
   {
   return (iv_len <= m_block_size);
   }

Key_Length_Specification CTR_BE::key_spec() const
   {
   return m_cipher->key_spec();
   }

CTR_BE* CTR_BE::clone() const
   {
   return new CTR_BE(m_cipher->clone(), m_ctr_size);
   }

void CTR_BE::key_schedule(const uint8_t key[], size_t key_len)
   {
   m_cipher->set_key(key, key_len);

   // Set a default all-zeros IV
   set_iv(nullptr, 0);
   }

std::string CTR_BE::name() const
   {
   if(m_ctr_size == m_block_size)
      return ("CTR-BE(" + m_cipher->name() + ")");
   else
      return ("CTR-BE(" + m_cipher->name() + "," + std::to_string(m_ctr_size) + ")");

   }

void CTR_BE::cipher(const uint8_t in[], uint8_t out[], size_t length)
   {
   verify_key_set(m_iv.empty() == false);

   const uint8_t* pad_bits = &m_pad[0];
   const size_t pad_size = m_pad.size();

   if(m_pad_pos > 0)
      {
      const size_t avail = pad_size - m_pad_pos;
      const size_t take = std::min(length, avail);
      xor_buf(out, in, pad_bits + m_pad_pos, take);
      length -= take;
      in += take;
      out += take;
      m_pad_pos += take;

      if(take == avail)
         {
         add_counter(m_ctr_blocks);
         m_cipher->encrypt_n(m_counter.data(), m_pad.data(), m_ctr_blocks);
         m_pad_pos = 0;
         }
      }

   while(length >= pad_size)
      {
      xor_buf(out, in, pad_bits, pad_size);
      length -= pad_size;
      in += pad_size;
      out += pad_size;

      add_counter(m_ctr_blocks);
      m_cipher->encrypt_n(m_counter.data(), m_pad.data(), m_ctr_blocks);
      }

   xor_buf(out, in, pad_bits, length);
   m_pad_pos += length;
   }

void CTR_BE::set_iv(const uint8_t iv[], size_t iv_len)
   {
   if(!valid_iv_length(iv_len))
      throw Invalid_IV_Length(name(), iv_len);

   m_iv.resize(m_block_size);
   zeroise(m_iv);
   buffer_insert(m_iv, 0, iv, iv_len);

   seek(0);
   }

void CTR_BE::add_counter(const uint64_t counter)
   {
   const size_t ctr_size = m_ctr_size;
   const size_t ctr_blocks = m_ctr_blocks;
   const size_t BS = m_block_size;

   if(ctr_size == 4)
      {
      const size_t off = (BS - 4);
      const uint32_t low32 = static_cast<uint32_t>(counter + load_be<uint32_t>(&m_counter[off], 0));

      for(size_t i = 0; i != ctr_blocks; ++i)
         {
         store_be(uint32_t(low32 + i), &m_counter[i*BS+off]);
         }
      }
   else if(ctr_size == 8)
      {
      const size_t off = (BS - 8);
      const uint64_t low64 = counter + load_be<uint64_t>(&m_counter[off], 0);

      for(size_t i = 0; i != ctr_blocks; ++i)
         {
         store_be(uint64_t(low64 + i), &m_counter[i*BS+off]);
         }
      }
   else if(ctr_size == 16)
      {
      const size_t off = (BS - 16);
      uint64_t b0 = load_be<uint64_t>(&m_counter[off], 0);
      uint64_t b1 = load_be<uint64_t>(&m_counter[off], 1);
      b1 += counter;
      b0 += (b1 < counter) ? 1 : 0; // carry

      for(size_t i = 0; i != ctr_blocks; ++i)
         {
         store_be(b0, &m_counter[i*BS+off]);
         store_be(b1, &m_counter[i*BS+off+8]);
         b1 += 1;
         b0 += (b1 == 0); // carry
         }
      }
   else
      {
      for(size_t i = 0; i != ctr_blocks; ++i)
         {
         uint64_t local_counter = counter;
         uint16_t carry = static_cast<uint8_t>(local_counter);
         for(size_t j = 0; (carry || local_counter) && j != ctr_size; ++j)
            {
            const size_t off = i*BS + (BS-1-j);
            const uint16_t cnt = static_cast<uint16_t>(m_counter[off]) + carry;
            m_counter[off] = static_cast<uint8_t>(cnt);
            local_counter = (local_counter >> 8);
            carry = (cnt >> 8) + static_cast<uint8_t>(local_counter);
            }
         }
      }
   }

void CTR_BE::seek(uint64_t offset)
   {
   verify_key_set(m_iv.empty() == false);

   const uint64_t base_counter = m_ctr_blocks * (offset / m_counter.size());

   zeroise(m_counter);
   buffer_insert(m_counter, 0, m_iv);

   const size_t BS = m_block_size;

   // Set m_counter blocks to IV, IV + 1, ... IV + n

   if(m_ctr_size == 4 && BS >= 8)
      {
      const uint32_t low32 = load_be<uint32_t>(&m_counter[BS-4], 0);

      if(m_ctr_blocks >= 4 && is_power_of_2(m_ctr_blocks))
         {
         size_t written = 1;
         while(written < m_ctr_blocks)
            {
            copy_mem(&m_counter[written*BS], &m_counter[0], BS*written);
            written *= 2;
            }
         }
      else
         {
         for(size_t i = 1; i != m_ctr_blocks; ++i)
            {
            copy_mem(&m_counter[i*BS], &m_counter[0], BS - 4);
            }
         }

      for(size_t i = 1; i != m_ctr_blocks; ++i)
         {
         const uint32_t c = static_cast<uint32_t>(low32 + i);
         store_be(c, &m_counter[(BS-4)+i*BS]);
         }
      }
   else
      {
      // do everything sequentially:
      for(size_t i = 1; i != m_ctr_blocks; ++i)
         {
         buffer_insert(m_counter, i*BS, &m_counter[(i-1)*BS], BS);

         for(size_t j = 0; j != m_ctr_size; ++j)
            if(++m_counter[i*BS + (BS - 1 - j)])
               break;
         }
      }

   if(base_counter > 0)
      add_counter(base_counter);

   m_cipher->encrypt_n(m_counter.data(), m_pad.data(), m_ctr_blocks);
   m_pad_pos = offset % m_counter.size();
   }
}
