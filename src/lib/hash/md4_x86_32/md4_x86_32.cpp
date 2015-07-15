/*
* MD4 (x86-32)
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/hash_utils.h>
#include <botan/md4_x86_32.h>

namespace Botan {

BOTAN_REGISTER_NAMED_T_NOARGS(HashFunction, MD4_X86_32, "MD4", "x86-32")

/**
* MD4 compression function in x86-32 asm
* @param digest the current digest
* @param input the input block
* @param M the message buffer
*/
extern "C" void botan_md4_x86_32_compress(u32bit digest[4],
                                        const byte input[64],
                                        u32bit M[16]);

/*
* MD4 Compression Function
*/
void MD4_X86_32::compress_n(const byte input[], size_t blocks)
   {
   for(size_t i = 0; i != blocks; ++i)
      {
      botan_md4_x86_32_compress(digest.data(), input, M.data());
      input += hash_block_size();
      }
   }

}
