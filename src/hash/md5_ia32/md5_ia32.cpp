/*************************************************
* MD5 (IA-32) Source File                        *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#include <botan/md5_ia32.h>
#include <botan/loadstor.h>

namespace Botan {

namespace {

extern "C"
void botan_md5_ia32_compress(u32bit[4], const byte[64], u32bit[16]);

}

/*************************************************
* MD5 Compression Function                       *
*************************************************/
void MD5_IA32::hash(const byte input[])
   {
   botan_md5_ia32_compress(digest, input, M);
   }

/*************************************************
* Copy out the digest                            *
*************************************************/
void MD5_IA32::copy_out(byte output[])
   {
   for(u32bit j = 0; j != OUTPUT_LENGTH; j += 4)
      store_le(digest[j/4], output + j);
   }

/*************************************************
* Clear memory of sensitive data                 *
*************************************************/
void MD5_IA32::clear() throw()
   {
   MDx_HashFunction::clear();
   M.clear();
   digest[0] = 0x67452301;
   digest[1] = 0xEFCDAB89;
   digest[2] = 0x98BADCFE;
   digest[3] = 0x10325476;
   }

}
