/*************************************************
* Xor Operations Header File                     *
* (C) 1999-2008 Jack Lloyd                       *
*************************************************/

#ifndef BOTAN_XOR_BUF_H__
#define BOTAN_XOR_BUF_H__

#include <botan/types.h>

namespace Botan {

/*************************************************
* XOR Arrays                                     *
*************************************************/
inline void xor_buf(byte out[], const byte in[], u32bit length)
   {
   while(length >= 8)
      {
#if BOTAN_UNALIGNED_LOADSTOR_OK
      *reinterpret_cast<u64bit*>(out) ^= *reinterpret_cast<const u64bit*>(in);
#else
      out[0] ^= in[0]; out[1] ^= in[1];
      out[2] ^= in[2]; out[3] ^= in[3];
      out[4] ^= in[4]; out[5] ^= in[5];
      out[6] ^= in[6]; out[7] ^= in[7];
#endif

      out += 8; in += 8; length -= 8;
      }
   for(u32bit j = 0; j != length; ++j)
      out[j] ^= in[j];
   }

/*************************************************
* XOR Arrays                                     *
*************************************************/
inline void xor_buf(byte out[],
                    const byte in[],
                    const byte in2[],
                    u32bit length)
   {
   while(length >= 8)
      {
#if BOTAN_UNALIGNED_LOADSTOR_OK
      *reinterpret_cast<u64bit*>(out) =
         *reinterpret_cast<const u64bit*>(in) ^
         *reinterpret_cast<const u64bit*>(in2);
#else
      out[0] = in[0] ^ in2[0]; out[1] = in[1] ^ in2[1];
      out[2] = in[2] ^ in2[2]; out[3] = in[3] ^ in2[3];
      out[4] = in[4] ^ in2[4]; out[5] = in[5] ^ in2[5];
      out[6] = in[6] ^ in2[6]; out[7] = in[7] ^ in2[7];
#endif

      in += 8; in2 += 8; out += 8; length -= 8;
      }

   for(u32bit j = 0; j != length; ++j)
      out[j] = in[j] ^ in2[j];
   }

}

#endif
