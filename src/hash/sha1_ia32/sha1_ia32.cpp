/*************************************************
* SHA-160 (IA-32) Source File                    *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#include <botan/sha1_ia32.h>
#include <botan/loadstor.h>

namespace Botan {

namespace {

extern "C"
void botan_sha160_ia32_compress(u32bit[5], const byte[64], u32bit[81]);

}

/*************************************************
* SHA-160 Compression Function                   *
*************************************************/
void SHA_160_IA32::hash(const byte input[])
   {
   botan_sha160_ia32_compress(digest, input, W);
   }

}
