/*
* MD5 (IA-32)
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/md5_ia32.h>
#include <botan/loadstor.h>

namespace Botan {

namespace {

extern "C"
void botan_md5_ia32_compress(u32bit[4], const byte[64], u32bit[16]);

}

/*
* MD5 Compression Function
*/
void MD5_IA32::compress_n(const byte input[], u32bit blocks)
   {
   for(u32bit i = 0; i != blocks; ++i)
      {
      botan_md5_ia32_compress(digest, input, M);
      input += HASH_BLOCK_SIZE;
      }
   }

}
