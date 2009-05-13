/*
* HAS-160
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/has160.h>
#include <botan/loadstor.h>
#include <botan/rotate.h>

namespace Botan {

namespace {

/*
* HAS-160 F1 Function
*/
inline void F1(u32bit A, u32bit& B, u32bit C, u32bit D, u32bit& E,
               u32bit msg, u32bit rot)
   {
   E += rotate_left(A, rot) + (D ^ (B & (C ^ D))) + msg;
   B  = rotate_left(B, 10);
   }

/*
* HAS-160 F2 Function
*/
inline void F2(u32bit A, u32bit& B, u32bit C, u32bit D, u32bit& E,
               u32bit msg, u32bit rot)
   {
   E += rotate_left(A, rot) + (B ^ C ^ D) + msg + 0x5A827999;
   B  = rotate_left(B, 17);
   }

/*
* HAS-160 F3 Function
*/
inline void F3(u32bit A, u32bit& B, u32bit C, u32bit D, u32bit& E,
               u32bit msg, u32bit rot)
   {
   E += rotate_left(A, rot) + (C ^ (B | ~D)) + msg + 0x6ED9EBA1;
   B  = rotate_left(B, 25);
   }

/*
* HAS-160 F4 Function
*/
inline void F4(u32bit A, u32bit& B, u32bit C, u32bit D, u32bit& E,
               u32bit msg, u32bit rot)
   {
   E += rotate_left(A, rot) + (B ^ C ^ D) + msg + 0x8F1BBCDC;
   B  = rotate_left(B, 30);
   }

}

/*
* HAS-160 Compression Function
*/
void HAS_160::compress_n(const byte input[], u32bit blocks)
   {
   for(u32bit i = 0; i != blocks; ++i)
      {
      for(u32bit j = 0; j != 16; ++j)
         X[j] = load_le<u32bit>(input, j);

      u32bit A = digest[0], B = digest[1], C = digest[2],
         D = digest[3], E = digest[4];

      X[16] = X[ 0] ^ X[ 1] ^ X[ 2] ^ X[ 3];
      X[17] = X[ 4] ^ X[ 5] ^ X[ 6] ^ X[ 7];
      X[18] = X[ 8] ^ X[ 9] ^ X[10] ^ X[11];
      X[19] = X[12] ^ X[13] ^ X[14] ^ X[15];
      F1(A,B,C,D,E,X[18], 5);   F1(E,A,B,C,D,X[ 0],11);
      F1(D,E,A,B,C,X[ 1], 7);   F1(C,D,E,A,B,X[ 2],15);
      F1(B,C,D,E,A,X[ 3], 6);   F1(A,B,C,D,E,X[19],13);
      F1(E,A,B,C,D,X[ 4], 8);   F1(D,E,A,B,C,X[ 5],14);
      F1(C,D,E,A,B,X[ 6], 7);   F1(B,C,D,E,A,X[ 7],12);
      F1(A,B,C,D,E,X[16], 9);   F1(E,A,B,C,D,X[ 8],11);
      F1(D,E,A,B,C,X[ 9], 8);   F1(C,D,E,A,B,X[10],15);
      F1(B,C,D,E,A,X[11], 6);   F1(A,B,C,D,E,X[17],12);
      F1(E,A,B,C,D,X[12], 9);   F1(D,E,A,B,C,X[13],14);
      F1(C,D,E,A,B,X[14], 5);   F1(B,C,D,E,A,X[15],13);

      X[16] = X[ 3] ^ X[ 6] ^ X[ 9] ^ X[12];
      X[17] = X[ 2] ^ X[ 5] ^ X[ 8] ^ X[15];
      X[18] = X[ 1] ^ X[ 4] ^ X[11] ^ X[14];
      X[19] = X[ 0] ^ X[ 7] ^ X[10] ^ X[13];
      F2(A,B,C,D,E,X[18], 5);   F2(E,A,B,C,D,X[ 3],11);
      F2(D,E,A,B,C,X[ 6], 7);   F2(C,D,E,A,B,X[ 9],15);
      F2(B,C,D,E,A,X[12], 6);   F2(A,B,C,D,E,X[19],13);
      F2(E,A,B,C,D,X[15], 8);   F2(D,E,A,B,C,X[ 2],14);
      F2(C,D,E,A,B,X[ 5], 7);   F2(B,C,D,E,A,X[ 8],12);
      F2(A,B,C,D,E,X[16], 9);   F2(E,A,B,C,D,X[11],11);
      F2(D,E,A,B,C,X[14], 8);   F2(C,D,E,A,B,X[ 1],15);
      F2(B,C,D,E,A,X[ 4], 6);   F2(A,B,C,D,E,X[17],12);
      F2(E,A,B,C,D,X[ 7], 9);   F2(D,E,A,B,C,X[10],14);
      F2(C,D,E,A,B,X[13], 5);   F2(B,C,D,E,A,X[ 0],13);

      X[16] = X[ 5] ^ X[ 7] ^ X[12] ^ X[14];
      X[17] = X[ 0] ^ X[ 2] ^ X[ 9] ^ X[11];
      X[18] = X[ 4] ^ X[ 6] ^ X[13] ^ X[15];
      X[19] = X[ 1] ^ X[ 3] ^ X[ 8] ^ X[10];
      F3(A,B,C,D,E,X[18], 5);   F3(E,A,B,C,D,X[12],11);
      F3(D,E,A,B,C,X[ 5], 7);   F3(C,D,E,A,B,X[14],15);
      F3(B,C,D,E,A,X[ 7], 6);   F3(A,B,C,D,E,X[19],13);
      F3(E,A,B,C,D,X[ 0], 8);   F3(D,E,A,B,C,X[ 9],14);
      F3(C,D,E,A,B,X[ 2], 7);   F3(B,C,D,E,A,X[11],12);
      F3(A,B,C,D,E,X[16], 9);   F3(E,A,B,C,D,X[ 4],11);
      F3(D,E,A,B,C,X[13], 8);   F3(C,D,E,A,B,X[ 6],15);
      F3(B,C,D,E,A,X[15], 6);   F3(A,B,C,D,E,X[17],12);
      F3(E,A,B,C,D,X[ 8], 9);   F3(D,E,A,B,C,X[ 1],14);
      F3(C,D,E,A,B,X[10], 5);   F3(B,C,D,E,A,X[ 3],13);

      X[16] = X[ 2] ^ X[ 7] ^ X[ 8] ^ X[13];
      X[17] = X[ 3] ^ X[ 4] ^ X[ 9] ^ X[14];
      X[18] = X[ 0] ^ X[ 5] ^ X[10] ^ X[15];
      X[19] = X[ 1] ^ X[ 6] ^ X[11] ^ X[12];
      F4(A,B,C,D,E,X[18], 5);   F4(E,A,B,C,D,X[ 7],11);
      F4(D,E,A,B,C,X[ 2], 7);   F4(C,D,E,A,B,X[13],15);
      F4(B,C,D,E,A,X[ 8], 6);   F4(A,B,C,D,E,X[19],13);
      F4(E,A,B,C,D,X[ 3], 8);   F4(D,E,A,B,C,X[14],14);
      F4(C,D,E,A,B,X[ 9], 7);   F4(B,C,D,E,A,X[ 4],12);
      F4(A,B,C,D,E,X[16], 9);   F4(E,A,B,C,D,X[15],11);
      F4(D,E,A,B,C,X[10], 8);   F4(C,D,E,A,B,X[ 5],15);
      F4(B,C,D,E,A,X[ 0], 6);   F4(A,B,C,D,E,X[17],12);
      F4(E,A,B,C,D,X[11], 9);   F4(D,E,A,B,C,X[ 6],14);
      F4(C,D,E,A,B,X[ 1], 5);   F4(B,C,D,E,A,X[12],13);

      digest[0] += A; digest[1] += B; digest[2] += C;
      digest[3] += D; digest[4] += E;
      }
   }

/*
* Copy out the digest
*/
void HAS_160::copy_out(byte output[])
   {
   for(u32bit j = 0; j != OUTPUT_LENGTH; j += 4)
      store_le(digest[j/4], output + j);
   }

/*
* Clear memory of sensitive data
*/
void HAS_160::clear() throw()
   {
   MDx_HashFunction::clear();
   X.clear();
   digest[0] = 0x67452301;
   digest[1] = 0xEFCDAB89;
   digest[2] = 0x98BADCFE;
   digest[3] = 0x10325476;
   digest[4] = 0xC3D2E1F0;
   }

}
