/*
* MD4 (IA-32)
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/md4_ia32.h>

namespace Botan {

/**
* MD4 compression function in IA-32 asm
* @param digest the current digest
* @param input the input block
* @param M the message buffer
*/
extern "C" void botan_md4_ia32_compress(u32bit digest[4],
                                        const byte input[64],
                                        u32bit M[16]);

/*
* MD4 Compression Function
*/
void MD4_IA32::compress_n(const byte input[], size_t blocks)
   {
   for(size_t i = 0; i != blocks; ++i)
      {
      botan_md4_ia32_compress(digest, input, M);
      input += hash_block_size();
      }
   }

}
