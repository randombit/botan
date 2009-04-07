/**
* Merkle-Damgard Hash Function
* (C) 1999-2008 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/mdx_hash.h>
#include <botan/exceptn.h>
#include <botan/loadstor.h>

namespace Botan {

/**
* MDx_HashFunction Constructor
*/
MDx_HashFunction::MDx_HashFunction(u32bit hash_len, u32bit block_len,
                                   bool byte_end, bool bit_end,
                                   u32bit cnt_size) :
   HashFunction(hash_len, block_len), buffer(block_len),
   BIG_BYTE_ENDIAN(byte_end), BIG_BIT_ENDIAN(bit_end), COUNT_SIZE(cnt_size)
   {
   if(COUNT_SIZE >= OUTPUT_LENGTH || COUNT_SIZE >= HASH_BLOCK_SIZE)
      throw Invalid_Argument("MDx_HashFunction: COUNT_SIZE is too big");
   count = position = 0;
   }

/**
* Clear memory of sensitive data
*/
void MDx_HashFunction::clear() throw()
   {
   buffer.clear();
   count = position = 0;
   }

/**
* Update the hash
*/
void MDx_HashFunction::add_data(const byte input[], u32bit length)
   {
   count += length;

   if(position)
      {
      buffer.copy(position, input, length);

      if(position + length >= HASH_BLOCK_SIZE)
         {
         compress_n(buffer.begin(), 1);
         input += (HASH_BLOCK_SIZE - position);
         length -= (HASH_BLOCK_SIZE - position);
         position = 0;
         }
      }

   const u32bit full_blocks = length / HASH_BLOCK_SIZE;
   const u32bit remaining   = length % HASH_BLOCK_SIZE;

   if(full_blocks)
      compress_n(input, full_blocks);

   buffer.copy(position, input + full_blocks * HASH_BLOCK_SIZE, remaining);
   position += remaining;
   }

/**
* Finalize a hash
*/
void MDx_HashFunction::final_result(byte output[])
   {
   buffer[position] = (BIG_BIT_ENDIAN ? 0x80 : 0x01);
   for(u32bit j = position+1; j != HASH_BLOCK_SIZE; ++j)
      buffer[j] = 0;

   if(position >= HASH_BLOCK_SIZE - COUNT_SIZE)
      {
      compress_n(buffer, 1);
      buffer.clear();
      }

   write_count(buffer + HASH_BLOCK_SIZE - COUNT_SIZE);

   compress_n(buffer, 1);
   copy_out(output);
   clear();
   }

/**
* Write the count bits to the buffer
*/
void MDx_HashFunction::write_count(byte out[])
   {
   if(COUNT_SIZE < 8)
      throw Invalid_State("MDx_HashFunction::write_count: COUNT_SIZE < 8");

   const u64bit bit_count = count * 8;

   if(BIG_BYTE_ENDIAN)
      store_be(bit_count, out + COUNT_SIZE - 8);
   else
      store_le(bit_count, out + COUNT_SIZE - 8);
   }

}
