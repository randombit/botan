/*************************************************
* SHA-160 (SSE2) Source File                     *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#include <botan/sha1_sse2.h>

namespace Botan {

extern "C" void botan_sha1_sse2_compress(u32bit[5], const byte[64]);

/*************************************************
* SHA-160 Compression Function                   *
*************************************************/
void SHA_160_SSE2::hash(const byte input[])
   {
   botan_sha1_sse2_compress(digest, input);
   }

}
