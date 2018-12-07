/*
* Merkle-Damgard Hash Function
* (C) 1999-2008,2018 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/mdx_hash.h>
#include <botan/exceptn.h>
#include <botan/loadstor.h>

namespace Botan {

/*
* MDx_HashFunction Constructor
*/
MDx_HashFunction::MDx_HashFunction(size_t block_len,
                                   bool byte_big_endian,
                                   bool bit_big_endian,
                                   uint8_t cnt_size) :
   m_pad_char(bit_big_endian == true ? 0x80 : 0x01),
   m_counter_size(cnt_size),
   m_count_big_endian(byte_big_endian),
   m_block_len(block_len),
   m_count(0),
   m_buffer(m_block_len),
   m_position(0)
   {
   if(m_counter_size < 8 || m_counter_size > m_block_len)
      throw Invalid_State("MDx_HashFunction invalid counter length");
   }

/*
* Clear memory of sensitive data
*/
void MDx_HashFunction::clear()
   {
   zeroise(m_buffer);
   m_count = m_position = 0;
   }

/*
* Update the hash
*/
void MDx_HashFunction::add_data(const uint8_t input[], size_t length)
   {
   m_count += length;

   if(m_position)
      {
      buffer_insert(m_buffer, m_position, input, length);

      if(m_position + length >= m_block_len)
         {
         compress_n(m_buffer.data(), 1);
         input += (m_block_len - m_position);
         length -= (m_block_len - m_position);
         m_position = 0;
         }
      }

   const size_t full_blocks = length / m_block_len;
   const size_t remaining   = length % m_block_len;

   if(full_blocks > 0)
      {
      compress_n(input, full_blocks);
      }

   buffer_insert(m_buffer, m_position, input + full_blocks * m_block_len, remaining);
   m_position += remaining;
   }

/*
* Finalize a hash
*/
void MDx_HashFunction::final_result(uint8_t output[])
   {
   clear_mem(&m_buffer[m_position], m_block_len - m_position);
   m_buffer[m_position] = m_pad_char;

   if(m_position >= m_block_len - m_counter_size)
      {
      compress_n(m_buffer.data(), 1);
      zeroise(m_buffer);
      }

   write_count(&m_buffer[m_block_len - m_counter_size]);

   compress_n(m_buffer.data(), 1);
   copy_out(output);
   clear();
   }

/*
* Write the count bits to the buffer
*/
void MDx_HashFunction::write_count(uint8_t out[])
   {
   BOTAN_ASSERT_NOMSG(m_counter_size <= output_length());
   BOTAN_ASSERT_NOMSG(m_counter_size >= 8);

   const uint64_t bit_count = m_count * 8;

   if(m_count_big_endian)
      store_be(bit_count, out + m_counter_size - 8);
   else
      store_le(bit_count, out + m_counter_size - 8);
   }

}
