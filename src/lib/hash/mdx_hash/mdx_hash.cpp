/*
* Merkle-Damgard Hash Function
* (C) 1999-2008 Jack Lloyd
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
                                   bool byte_end,
                                   bool bit_end,
                                   size_t cnt_size) :
   m_buffer(block_len),
   BIG_BYTE_ENDIAN(byte_end),
   BIG_BIT_ENDIAN(bit_end),
   COUNT_SIZE(cnt_size)
   {
   m_count = m_position = 0;
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

      if(m_position + length >= m_buffer.size())
         {
         compress_n(m_buffer.data(), 1);
         input += (m_buffer.size() - m_position);
         length -= (m_buffer.size() - m_position);
         m_position = 0;
         }
      }

   const size_t full_blocks = length / m_buffer.size();
   const size_t remaining   = length % m_buffer.size();

   if(full_blocks)
      compress_n(input, full_blocks);

   buffer_insert(m_buffer, m_position, input + full_blocks * m_buffer.size(), remaining);
   m_position += remaining;
   }

/*
* Finalize a hash
*/
void MDx_HashFunction::final_result(uint8_t output[])
   {
   m_buffer[m_position] = (BIG_BIT_ENDIAN ? 0x80 : 0x01);
   for(size_t i = m_position+1; i != m_buffer.size(); ++i)
      m_buffer[i] = 0;

   if(m_position >= m_buffer.size() - COUNT_SIZE)
      {
      compress_n(m_buffer.data(), 1);
      zeroise(m_buffer);
      }

   write_count(&m_buffer[m_buffer.size() - COUNT_SIZE]);

   compress_n(m_buffer.data(), 1);
   copy_out(output);
   clear();
   }

/*
* Write the count bits to the buffer
*/
void MDx_HashFunction::write_count(uint8_t out[])
   {
   if(COUNT_SIZE < 8)
      throw Invalid_State("MDx_HashFunction::write_count: COUNT_SIZE < 8");
   if(COUNT_SIZE >= output_length() || COUNT_SIZE >= hash_block_size())
      throw Invalid_Argument("MDx_HashFunction: COUNT_SIZE is too big");

   const uint64_t bit_count = m_count * 8;

   if(BIG_BYTE_ENDIAN)
      store_be(bit_count, out + COUNT_SIZE - 8);
   else
      store_le(bit_count, out + COUNT_SIZE - 8);
   }

}
