/*
* SHA-160 (SSE2)
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/sha1_sse2.h>

namespace Botan {

/*
* SHA-160 Compression Function
*/
void SHA_160_SSE2::compress_n(const byte input[], u32bit blocks)
   {
   for(u32bit i = 0; i != blocks; ++i)
      {
      botan_sha1_sse2_compress(digest, reinterpret_cast<const u32bit*>(input));
      input += HASH_BLOCK_SIZE;
      }
   }

}
