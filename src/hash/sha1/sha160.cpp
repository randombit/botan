/*
* SHA-160
* (C) 1999-2008,2011 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/sha160.h>
#include <botan/loadstor.h>
#include <botan/rotate.h>

namespace Botan {

namespace SHA1_F {

namespace {

/*
* SHA-160 F1 Function
*/
inline void F1(u32bit A, u32bit& B, u32bit C, u32bit D, u32bit& E, u32bit msg)
   {
   E += (D ^ (B & (C ^ D))) + msg + 0x5A827999 + rotate_left(A, 5);
   B  = rotate_left(B, 30);
   }

/*
* SHA-160 F2 Function
*/
inline void F2(u32bit A, u32bit& B, u32bit C, u32bit D, u32bit& E, u32bit msg)
   {
   E += (B ^ C ^ D) + msg + 0x6ED9EBA1 + rotate_left(A, 5);
   B  = rotate_left(B, 30);
   }

/*
* SHA-160 F3 Function
*/
inline void F3(u32bit A, u32bit& B, u32bit C, u32bit D, u32bit& E, u32bit msg)
   {
   E += ((B & C) | ((B | C) & D)) + msg + 0x8F1BBCDC + rotate_left(A, 5);
   B  = rotate_left(B, 30);
   }

/*
* SHA-160 F4 Function
*/
inline void F4(u32bit A, u32bit& B, u32bit C, u32bit D, u32bit& E, u32bit msg)
   {
   E += (B ^ C ^ D) + msg + 0xCA62C1D6 + rotate_left(A, 5);
   B  = rotate_left(B, 30);
   }

}

}

/*
* SHA-160 Compression Function
*/
void SHA_160::compress_n(const byte input[], size_t blocks)
   {

   u32bit A = digest[0], B = digest[1], C = digest[2],
          D = digest[3], E = digest[4];

   for(size_t i = 0; i != blocks; ++i)
      {
      load_be(&W[0], input, 16);

      for(size_t j = 16; j != 80; j += 8)
         {
         W[j  ] = rotate_left((W[j-3] ^ W[j-8] ^ W[j-14] ^ W[j-16]), 1);
         W[j+1] = rotate_left((W[j-2] ^ W[j-7] ^ W[j-13] ^ W[j-15]), 1);
         W[j+2] = rotate_left((W[j-1] ^ W[j-6] ^ W[j-12] ^ W[j-14]), 1);
         W[j+3] = rotate_left((W[j  ] ^ W[j-5] ^ W[j-11] ^ W[j-13]), 1);
         W[j+4] = rotate_left((W[j+1] ^ W[j-4] ^ W[j-10] ^ W[j-12]), 1);
         W[j+5] = rotate_left((W[j+2] ^ W[j-3] ^ W[j- 9] ^ W[j-11]), 1);
         W[j+6] = rotate_left((W[j+3] ^ W[j-2] ^ W[j- 8] ^ W[j-10]), 1);
         W[j+7] = rotate_left((W[j+4] ^ W[j-1] ^ W[j- 7] ^ W[j- 9]), 1);
         }

      SHA1_F::F1(A, B, C, D, E, W[ 0]);   SHA1_F::F1(E, A, B, C, D, W[ 1]);
      SHA1_F::F1(D, E, A, B, C, W[ 2]);   SHA1_F::F1(C, D, E, A, B, W[ 3]);
      SHA1_F::F1(B, C, D, E, A, W[ 4]);   SHA1_F::F1(A, B, C, D, E, W[ 5]);
      SHA1_F::F1(E, A, B, C, D, W[ 6]);   SHA1_F::F1(D, E, A, B, C, W[ 7]);
      SHA1_F::F1(C, D, E, A, B, W[ 8]);   SHA1_F::F1(B, C, D, E, A, W[ 9]);
      SHA1_F::F1(A, B, C, D, E, W[10]);   SHA1_F::F1(E, A, B, C, D, W[11]);
      SHA1_F::F1(D, E, A, B, C, W[12]);   SHA1_F::F1(C, D, E, A, B, W[13]);
      SHA1_F::F1(B, C, D, E, A, W[14]);   SHA1_F::F1(A, B, C, D, E, W[15]);
      SHA1_F::F1(E, A, B, C, D, W[16]);   SHA1_F::F1(D, E, A, B, C, W[17]);
      SHA1_F::F1(C, D, E, A, B, W[18]);   SHA1_F::F1(B, C, D, E, A, W[19]);

      SHA1_F::F2(A, B, C, D, E, W[20]);   SHA1_F::F2(E, A, B, C, D, W[21]);
      SHA1_F::F2(D, E, A, B, C, W[22]);   SHA1_F::F2(C, D, E, A, B, W[23]);
      SHA1_F::F2(B, C, D, E, A, W[24]);   SHA1_F::F2(A, B, C, D, E, W[25]);
      SHA1_F::F2(E, A, B, C, D, W[26]);   SHA1_F::F2(D, E, A, B, C, W[27]);
      SHA1_F::F2(C, D, E, A, B, W[28]);   SHA1_F::F2(B, C, D, E, A, W[29]);
      SHA1_F::F2(A, B, C, D, E, W[30]);   SHA1_F::F2(E, A, B, C, D, W[31]);
      SHA1_F::F2(D, E, A, B, C, W[32]);   SHA1_F::F2(C, D, E, A, B, W[33]);
      SHA1_F::F2(B, C, D, E, A, W[34]);   SHA1_F::F2(A, B, C, D, E, W[35]);
      SHA1_F::F2(E, A, B, C, D, W[36]);   SHA1_F::F2(D, E, A, B, C, W[37]);
      SHA1_F::F2(C, D, E, A, B, W[38]);   SHA1_F::F2(B, C, D, E, A, W[39]);

      SHA1_F::F3(A, B, C, D, E, W[40]);   SHA1_F::F3(E, A, B, C, D, W[41]);
      SHA1_F::F3(D, E, A, B, C, W[42]);   SHA1_F::F3(C, D, E, A, B, W[43]);
      SHA1_F::F3(B, C, D, E, A, W[44]);   SHA1_F::F3(A, B, C, D, E, W[45]);
      SHA1_F::F3(E, A, B, C, D, W[46]);   SHA1_F::F3(D, E, A, B, C, W[47]);
      SHA1_F::F3(C, D, E, A, B, W[48]);   SHA1_F::F3(B, C, D, E, A, W[49]);
      SHA1_F::F3(A, B, C, D, E, W[50]);   SHA1_F::F3(E, A, B, C, D, W[51]);
      SHA1_F::F3(D, E, A, B, C, W[52]);   SHA1_F::F3(C, D, E, A, B, W[53]);
      SHA1_F::F3(B, C, D, E, A, W[54]);   SHA1_F::F3(A, B, C, D, E, W[55]);
      SHA1_F::F3(E, A, B, C, D, W[56]);   SHA1_F::F3(D, E, A, B, C, W[57]);
      SHA1_F::F3(C, D, E, A, B, W[58]);   SHA1_F::F3(B, C, D, E, A, W[59]);

      SHA1_F::F4(A, B, C, D, E, W[60]);   SHA1_F::F4(E, A, B, C, D, W[61]);
      SHA1_F::F4(D, E, A, B, C, W[62]);   SHA1_F::F4(C, D, E, A, B, W[63]);
      SHA1_F::F4(B, C, D, E, A, W[64]);   SHA1_F::F4(A, B, C, D, E, W[65]);
      SHA1_F::F4(E, A, B, C, D, W[66]);   SHA1_F::F4(D, E, A, B, C, W[67]);
      SHA1_F::F4(C, D, E, A, B, W[68]);   SHA1_F::F4(B, C, D, E, A, W[69]);
      SHA1_F::F4(A, B, C, D, E, W[70]);   SHA1_F::F4(E, A, B, C, D, W[71]);
      SHA1_F::F4(D, E, A, B, C, W[72]);   SHA1_F::F4(C, D, E, A, B, W[73]);
      SHA1_F::F4(B, C, D, E, A, W[74]);   SHA1_F::F4(A, B, C, D, E, W[75]);
      SHA1_F::F4(E, A, B, C, D, W[76]);   SHA1_F::F4(D, E, A, B, C, W[77]);
      SHA1_F::F4(C, D, E, A, B, W[78]);   SHA1_F::F4(B, C, D, E, A, W[79]);

      A = (digest[0] += A);
      B = (digest[1] += B);
      C = (digest[2] += C);
      D = (digest[3] += D);
      E = (digest[4] += E);

      input += hash_block_size();
      }
   }

/*
* Copy out the digest
*/
void SHA_160::copy_out(byte output[])
   {
   for(size_t i = 0; i != output_length(); i += 4)
      store_be(digest[i/4], output + i);
   }

/*
* Clear memory of sensitive data
*/
void SHA_160::clear()
   {
   MDx_HashFunction::clear();
   zeroise(W);
   digest[0] = 0x67452301;
   digest[1] = 0xEFCDAB89;
   digest[2] = 0x98BADCFE;
   digest[3] = 0x10325476;
   digest[4] = 0xC3D2E1F0;
   }

}
