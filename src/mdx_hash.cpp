/*************************************************
* MDx Hash Function Source File                  *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#include <botan/mdx_hash.h>
#include <botan/bit_ops.h>

namespace Botan {

/*************************************************
* MDx_HashFunction Constructor                   *
*************************************************/
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

/*************************************************
* Clear memory of sensitive data                 *
*************************************************/
void MDx_HashFunction::clear() throw()
   {
   buffer.clear();
   count = position = 0;
   }

/*************************************************
* Update the hash                                *
*************************************************/
void MDx_HashFunction::add_data(const byte input[], u32bit length)
   {
   count += length;

   if(position)
      {
      buffer.copy(position, input, length);

      if(position + length >= HASH_BLOCK_SIZE)
         {
         hash(buffer.begin());
         input += (HASH_BLOCK_SIZE - position);
         length -= (HASH_BLOCK_SIZE - position);
         position = 0;
         }
      }

   while(length >= HASH_BLOCK_SIZE)
      {
      hash(input);
      input += HASH_BLOCK_SIZE;
      length -= HASH_BLOCK_SIZE;
      }

   buffer.copy(position, input, length);

   position += length;
   }

/*************************************************
* Finalize a Hash                                *
*************************************************/
void MDx_HashFunction::final_result(byte output[])
   {
   buffer[position] = (BIG_BIT_ENDIAN ? 0x80 : 0x01);
   for(u32bit j = position+1; j != HASH_BLOCK_SIZE; ++j)
      buffer[j] = 0;
   if(position >= HASH_BLOCK_SIZE - COUNT_SIZE)
      {
      hash(buffer);
      buffer.clear();
      }
   write_count(buffer + HASH_BLOCK_SIZE - COUNT_SIZE);

   hash(buffer);
   copy_out(output);
   clear();
   }

/*************************************************
* Write the count bits to the buffer             *
*************************************************/
void MDx_HashFunction::write_count(byte out[])
   {
   if(COUNT_SIZE < 8)
      throw Invalid_State("MDx_HashFunction::write_count: COUNT_SIZE < 8");
   for(u32bit j = 0; j != 8; ++j)
      {
      const u32bit choose = (BIG_BYTE_ENDIAN ? (j % 8) : (7 - (j % 8)));
      out[j+COUNT_SIZE-8] = get_byte(choose, 8 * count);
      }
   }

}
