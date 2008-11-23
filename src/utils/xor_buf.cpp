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

   for(u32bit i = 0; i != in_len; ++i)
      {
      buf[buf_i] ^= in[i];
      buf_i = (buf_i + 1) % length;
      }
   return buf_i;
   }

}
