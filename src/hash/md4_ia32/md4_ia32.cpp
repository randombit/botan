/*************************************************
* MD4 (IA-32) Source File                        *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#include <botan/md4_ia32.h>
#include <botan/loadstor.h>

namespace Botan {

extern "C" void botan_md4_ia32_compress(u32bit[4], const byte[64], u32bit[16]);

/*************************************************
* MD4 Compression Function                       *
*************************************************/
void MD4_IA32::hash(const byte input[])
   {
   botan_md4_ia32_compress(digest, input, M);
   }

}
