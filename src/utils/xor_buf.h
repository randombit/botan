/*
* XOR operations
* (C) 1999-2008 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_XOR_BUF_H__
#define BOTAN_XOR_BUF_H__

#include <botan/types.h>

namespace Botan {

/**
* XOR arrays. Postcondition out[i] = in[i] ^ out[i] forall i = 0...length
* @param out the input/output buffer
* @param in the read-only input buffer
* @param length the length of the buffers
*/
inline void xor_buf(byte out[], const byte in[], size_t length)
   {
   while(length >= 8)
      {
#if BOTAN_TARGET_UNALIGNED_MEMORY_ACCESS_OK
      *reinterpret_cast<u64bit*>(out) ^= *reinterpret_cast<const u64bit*>(in);
#else
      out[0] ^= in[0]; out[1] ^= in[1];
      out[2] ^= in[2]; out[3] ^= in[3];
      out[4] ^= in[4]; out[5] ^= in[5];
      out[6] ^= in[6]; out[7] ^= in[7];
#endif

      out += 8; in += 8; length -= 8;
      }

   for(size_t i = 0; i != length; ++i)
      out[i] ^= in[i];
   }

/**
* XOR arrays. Postcondition out[i] = in[i] ^ in2[i] forall i = 0...length
* @param out the output buffer
* @param in the first input buffer
* @param in2 the second output buffer
* @param length the length of the three buffers
*/
inline void xor_buf(byte out[],
                    const byte in[],
                    const byte in2[],
                    size_t length)
   {
   while(length >= 8)
      {
#if BOTAN_TARGET_UNALIGNED_MEMORY_ACCESS_OK
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

   for(size_t i = 0; i != length; ++i)
      out[i] = in[i] ^ in2[i];
   }

}

#endif
