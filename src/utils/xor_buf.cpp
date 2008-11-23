/**
* XOR operations
* (C) 1999-2008 Jack Lloyd
*/

#include <botan/xor_buf.h>
#include <botan/loadstor.h>

namespace Botan {

/**
* Xor values into buffer
*/
u32bit xor_into_buf(byte buf[], u32bit buf_i, u32bit length,
                    const void* in_void, u32bit in_len)
   {
   const byte* in = static_cast<const byte*>(in_void);

   byte last = 0;
   byte count = 0;

   for(u32bit i = 0; i != in_len; ++i)
      {
      if(in[i] != last)
         {
         buf[buf_i] ^= last;
         buf_i = (buf_i + 1) % length;

         buf[buf_i] ^= count;
         buf_i = (buf_i + 1) % length;

         last = in[i];
         count = 1;
         }
      else
         ++count;
      }

   // final values of last, count are thrown away

   return buf_i;
   }

}
