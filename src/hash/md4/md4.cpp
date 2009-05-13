/*
* MD4
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/md4.h>
#include <botan/loadstor.h>
#include <botan/rotate.h>

namespace Botan {

namespace {

/*
* MD4 FF Function
*/
inline void FF(u32bit& A, u32bit B, u32bit C, u32bit D, u32bit M, byte S)
   {
   A += (D ^ (B & (C ^ D))) + M;
   A  = rotate_left(A, S);
   }

/*
* MD4 GG Function
*/
inline void GG(u32bit& A, u32bit B, u32bit C, u32bit D, u32bit M, byte S)
   {
   A += ((B & C) | (D & (B | C))) + M + 0x5A827999;
   A  = rotate_left(A, S);
   }

/*
* MD4 HH Function
*/
inline void HH(u32bit& A, u32bit B, u32bit C, u32bit D, u32bit M, byte S)
   {
   A += (B ^ C ^ D) + M + 0x6ED9EBA1;
   A  = rotate_left(A, S);
   }

}

/*
* MD4 Compression Function
*/
void MD4::compress_n(const byte input[], u32bit blocks)
   {
   u32bit A = digest[0], B = digest[1], C = digest[2], D = digest[3];

   for(u32bit i = 0; i != blocks; ++i)
      {
      for(u32bit j = 0; j != 16; ++j)
         M[j] = load_le<u32bit>(input, j);
      input += HASH_BLOCK_SIZE;

      FF(A,B,C,D,M[ 0], 3);   FF(D,A,B,C,M[ 1], 7);   FF(C,D,A,B,M[ 2],11);
      FF(B,C,D,A,M[ 3],19);   FF(A,B,C,D,M[ 4], 3);   FF(D,A,B,C,M[ 5], 7);
      FF(C,D,A,B,M[ 6],11);   FF(B,C,D,A,M[ 7],19);   FF(A,B,C,D,M[ 8], 3);
      FF(D,A,B,C,M[ 9], 7);   FF(C,D,A,B,M[10],11);   FF(B,C,D,A,M[11],19);
      FF(A,B,C,D,M[12], 3);   FF(D,A,B,C,M[13], 7);   FF(C,D,A,B,M[14],11);
      FF(B,C,D,A,M[15],19);

      GG(A,B,C,D,M[ 0], 3);   GG(D,A,B,C,M[ 4], 5);   GG(C,D,A,B,M[ 8], 9);
      GG(B,C,D,A,M[12],13);   GG(A,B,C,D,M[ 1], 3);   GG(D,A,B,C,M[ 5], 5);
      GG(C,D,A,B,M[ 9], 9);   GG(B,C,D,A,M[13],13);   GG(A,B,C,D,M[ 2], 3);
      GG(D,A,B,C,M[ 6], 5);   GG(C,D,A,B,M[10], 9);   GG(B,C,D,A,M[14],13);
      GG(A,B,C,D,M[ 3], 3);   GG(D,A,B,C,M[ 7], 5);   GG(C,D,A,B,M[11], 9);
      GG(B,C,D,A,M[15],13);

      HH(A,B,C,D,M[ 0], 3);   HH(D,A,B,C,M[ 8], 9);   HH(C,D,A,B,M[ 4],11);
      HH(B,C,D,A,M[12],15);   HH(A,B,C,D,M[ 2], 3);   HH(D,A,B,C,M[10], 9);
      HH(C,D,A,B,M[ 6],11);   HH(B,C,D,A,M[14],15);   HH(A,B,C,D,M[ 1], 3);
      HH(D,A,B,C,M[ 9], 9);   HH(C,D,A,B,M[ 5],11);   HH(B,C,D,A,M[13],15);
      HH(A,B,C,D,M[ 3], 3);   HH(D,A,B,C,M[11], 9);   HH(C,D,A,B,M[ 7],11);
      HH(B,C,D,A,M[15],15);

      A = (digest[0] += A);
      B = (digest[1] += B);
      C = (digest[2] += C);
      D = (digest[3] += D);
      }
   }

/*
* Copy out the digest
*/
void MD4::copy_out(byte output[])
   {
   for(u32bit j = 0; j != OUTPUT_LENGTH; j += 4)
      store_le(digest[j/4], output + j);
   }

/*
* Clear memory of sensitive data
*/
void MD4::clear() throw()
   {
   MDx_HashFunction::clear();
   M.clear();
   digest[0] = 0x67452301;
   digest[1] = 0xEFCDAB89;
   digest[2] = 0x98BADCFE;
   digest[3] = 0x10325476;
   }

}
