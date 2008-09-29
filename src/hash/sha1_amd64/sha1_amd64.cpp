/*************************************************
* SHA-160 Source File                            *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#include <botan/sha1_amd64.h>

namespace Botan {

namespace {

extern "C"
void botan_sha160_amd64_compress(u32bit[5], const byte[64], u32bit[80]);

}

/*************************************************
* SHA-160 Compression Function                   *
*************************************************/
void SHA_160_AMD64::hash(const byte input[])
   {
   botan_sha160_amd64_compress(digest, input, W);
   }

}
