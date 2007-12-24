/*************************************************
* MD5 Source File                                *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#include <botan/md5.h>
#include <botan/loadstor.h>

namespace Botan {

extern "C" void md5_core(u32bit[4], const byte[64], u32bit[16]);

/*************************************************
* MD5 Compression Function                       *
*************************************************/
void MD5::hash(const byte input[])
   {
   md5_core(digest, input, M);
   }

/*************************************************
* Copy out the digest                            *
*************************************************/
void MD5::copy_out(byte output[])
   {
   for(u32bit j = 0; j != OUTPUT_LENGTH; ++j)
      output[j] = get_byte(3 - (j % 4), digest[j/4]);
   }

/*************************************************
* Clear memory of sensitive data                 *
*************************************************/
void MD5::clear() throw()
   {
   MDx_HashFunction::clear();
   M.clear();
   digest[0] = 0x67452301;
   digest[1] = 0xEFCDAB89;
   digest[2] = 0x98BADCFE;
   digest[3] = 0x10325476;
   }

}
