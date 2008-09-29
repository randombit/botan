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

/*************************************************
* Copy out the digest                            *
*************************************************/
void SHA_160_IA32::copy_out(byte output[])
   {
   for(u32bit j = 0; j != OUTPUT_LENGTH; ++j)
      output[j] = get_byte(j % 4, digest[j/4]);
   }

/*************************************************
* Clear memory of sensitive data                 *
*************************************************/
void SHA_160_IA32::clear() throw()
   {
   MDx_HashFunction::clear();
   W.clear();
   digest[0] = 0x67452301;
   digest[1] = 0xEFCDAB89;
   digest[2] = 0x98BADCFE;
   digest[3] = 0x10325476;
   digest[4] = 0xC3D2E1F0;
   }

}
