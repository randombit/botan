/*
* MD5 (x86-32)
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/hash_util.h>
#include <botan/md5_x86_32.h>

namespace Botan {

BOTAN_REGISTER_NAMED_T_NOARGS(HashFunction, MD5_X86_32, "MD5", "x86-32");

namespace {

extern "C"
void botan_md5_x86_32_compress(u32bit[4], const byte[64], u32bit[16]);

}

/*
* MD5 Compression Function
*/
void MD5_X86_32::compress_n(const byte input[], size_t blocks)
   {
   for(size_t i = 0; i != blocks; ++i)
      {
      botan_md5_x86_32_compress(&digest[0], input, &M[0]);
      input += hash_block_size();
      }
   }

}
