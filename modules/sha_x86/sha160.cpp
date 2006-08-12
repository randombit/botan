/*************************************************
* SHA-160 Source File                            *
* (C) 1999-2006 The Botan Project                *
*************************************************/

#include <botan/sha160.h>
#include <botan/bit_ops.h>

namespace Botan {

namespace {

/*************************************************
* SHA-160 F1 Function                            *
*************************************************/
inline void F1(u32bit A, u32bit& B, u32bit C, u32bit D, u32bit& E, u32bit msg)
   {
   E += (D ^ (B & (C ^ D))) + msg + 0x5A827999 + rotate_left(A, 5);
   B  = rotate_left(B, 30);
   }

/*************************************************
* SHA-160 F2 Function                            *
*************************************************/
inline void F2(u32bit A, u32bit& B, u32bit C, u32bit D, u32bit& E, u32bit msg)
   {
   E += (B ^ C ^ D) + msg + 0x6ED9EBA1 + rotate_left(A, 5);
   B  = rotate_left(B, 30);
   }

/*************************************************
* SHA-160 F3 Function                            *
*************************************************/
inline void F3(u32bit A, u32bit& B, u32bit C, u32bit D, u32bit& E, u32bit msg)
   {
   E += ((B & C) | ((B | C) & D)) + msg + 0x8F1BBCDC + rotate_left(A, 5);
   B  = rotate_left(B, 30);
   }

/*************************************************
* SHA-160 F4 Function                            *
*************************************************/
inline void F4(u32bit A, u32bit& B, u32bit C, u32bit D, u32bit& E, u32bit msg)
   {
   E += (B ^ C ^ D) + msg + 0xCA62C1D6 + rotate_left(A, 5);
   B  = rotate_left(B, 30);
   }

}

extern "C" void sha160_core(u32bit[5], const byte[64], u32bit[80]);

/*************************************************
* SHA-160 Compression Function                   *
*************************************************/
void SHA_160::hash(const byte input[])
   {
   sha160_core(digest, input, W);
   }

/*************************************************
* Copy out the digest                            *
*************************************************/
void SHA_160::copy_out(byte output[])
   {
   for(u32bit j = 0; j != OUTPUT_LENGTH; ++j)
      output[j] = get_byte(j % 4, digest[j/4]);
   }

/*************************************************
* Clear memory of sensitive data                 *
*************************************************/
void SHA_160::clear() throw()
   {
   MDx_HashFunction::clear();
   digest[0] = 0x67452301;
   digest[1] = 0xEFCDAB89;
   digest[2] = 0x98BADCFE;
   digest[3] = 0x10325476;
   digest[4] = 0xC3D2E1F0;
   }

}
