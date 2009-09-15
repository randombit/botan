/*
* Blue Midnight Wish 512
* (C) 2009 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/bmw_512.h>
#include <botan/loadstor.h>
#include <botan/rotate.h>

#include <stdio.h>

namespace Botan {

namespace {

inline u64bit S0(u64bit X)
   {
   return (X >> 1) ^ (X << 3) ^ rotate_left(X, 4) ^ rotate_left(X, 37);
   }

inline u64bit S1(u64bit X)
   {
   return (X >> 1) ^ (X << 2) ^ rotate_left(X, 13) ^ rotate_left(X, 43);
   }

inline u64bit S2(u64bit X)
   {
   return (X >> 2) ^ (X << 1) ^ rotate_left(X, 19) ^ rotate_left(X, 53);
   }

inline u64bit S3(u64bit X)
   {
   return (X >> 2) ^ (X << 2) ^ rotate_left(X, 28) ^ rotate_left(X, 59);
   }

inline u64bit S4(u64bit X)
   {
   return (X >> 1) ^ X;
   }
}

void BMW_512::compress_n(const byte input[], u32bit blocks)
   {
   for(u32bit i = 0; i != blocks; ++i)
      {
      u64bit Q[32] = { 0 };
      u64bit M[16] = { 0 };

      for(u32bit j = 0; j != 16; ++j)
         H[j] ^= M[j] = load_le<u64bit>(input, j);
      input += HASH_BLOCK_SIZE;

      Q[ 0] = H[ 5] - H[ 7] + H[10] + H[13] + H[14];
      Q[ 1] = H[ 6] - H[ 8] + H[11] + H[14] - H[15];
      Q[ 2] = H[ 0] + H[ 7] + H[ 9] - H[12] + H[15];
      Q[ 3] = H[ 0] - H[ 1] + H[ 8] - H[10] + H[13];
      Q[ 4] = H[ 1] + H[ 2] + H[ 9] - H[11] - H[14];
      Q[ 5] = H[ 3] - H[ 2] + H[10] - H[12] + H[15];
      Q[ 6] = H[ 4] - H[ 0] - H[ 3] - H[11] + H[13];
      Q[ 7] = H[ 1] - H[ 4] - H[ 5] - H[12] - H[14];
      Q[ 8] = H[ 2] - H[ 5] - H[ 6] + H[13] - H[15];
      Q[ 9] = H[ 0] - H[ 3] + H[ 6] - H[ 7] + H[14];
      Q[10] = H[ 8] - H[ 1] - H[ 4] - H[ 7] + H[15];
      Q[11] = H[ 8] - H[ 0] - H[ 2] - H[ 5] + H[ 9];
      Q[12] = H[ 1] + H[ 3] - H[ 6] - H[ 9] + H[10];
      Q[13] = H[ 2] + H[ 4] + H[ 7] + H[10] + H[11];
      Q[14] = H[ 3] - H[ 5] + H[ 8] - H[11] - H[12];
      Q[15] = H[12] - H[ 4] - H[ 6] - H[ 9] + H[13];

      Q[ 0] = S0(Q[ 0]);
      Q[ 1] = S1(Q[ 1]);
      Q[ 2] = S2(Q[ 2]);
      Q[ 3] = S3(Q[ 3]);
      Q[ 4] = S4(Q[ 4]);
      Q[ 5] = S0(Q[ 5]);
      Q[ 6] = S1(Q[ 6]);
      Q[ 7] = S2(Q[ 7]);
      Q[ 8] = S3(Q[ 8]);
      Q[ 9] = S4(Q[ 9]);
      Q[10] = S0(Q[10]);
      Q[11] = S1(Q[11]);
      Q[12] = S2(Q[12]);
      Q[13] = S3(Q[13]);
      Q[14] = S4(Q[14]);
      Q[15] = S0(Q[15]);

      for(u32bit j = 16; j != 18; ++j)
         {
         Q[j] = S1(Q[j-16]) + S2(Q[j-15]) + S3(Q[j-14]) + S0(Q[j-13]) +
                S1(Q[j-12]) + S2(Q[j-11]) + S3(Q[j-10]) + S0(Q[j- 9]) +
                S1(Q[j- 8]) + S2(Q[j- 7]) + S3(Q[j- 6]) + S0(Q[j- 5]) +
                S1(Q[j- 4]) + S2(Q[j- 3]) + S3(Q[j- 2]) + S0(Q[j- 1]) +
                M[j-16] + M[j-13] - M[j-6] +
                (0x0555555555555555 * j);
         }

      for(u32bit j = 18; j != 32; ++j)
         {
         Q[j] = Q[j-16] + rotate_left(Q[j-15],  5) +
                Q[j-14] + rotate_left(Q[j-13], 11) +
                Q[j-12] + rotate_left(Q[j-11], 27) +
                Q[j-10] + rotate_left(Q[j- 9], 32) +
                Q[j- 8] + rotate_left(Q[j- 7], 37) +
                Q[j- 6] + rotate_left(Q[j- 5], 43) +
                Q[j- 4] + rotate_left(Q[j- 3], 53) +
                (Q[j- 2] >> 2 ^ Q[j- 2]) + S4(Q[j- 1]) +
                M[j-16] + M[(j-13) % 16] - M[(j-6) % 16] +
                (0x0555555555555555 * j);
         }

      u64bit XL = Q[16] ^ Q[17] ^ Q[18] ^ Q[19] ^
                  Q[20] ^ Q[21] ^ Q[22] ^ Q[23];

      u64bit XH = Q[24] ^ Q[25] ^ Q[26] ^ Q[27] ^
                  Q[28] ^ Q[29] ^ Q[30] ^ Q[31];

      XH ^= XL;

      H[ 0] = ((XH <<  5) ^ (Q[16] >> 5) ^ M[0]) + (XL ^ Q[24] ^ Q[0]);
      H[ 1] = ((XH >>  7) ^ (Q[17] << 8) ^ M[1]) + (XL ^ Q[25] ^ Q[1]);
      H[ 2] = ((XH >>  5) ^ (Q[18] << 5) ^ M[2]) + (XL ^ Q[26] ^ Q[2]);
      H[ 3] = ((XH >>  1) ^ (Q[19] << 5) ^ M[3]) + (XL ^ Q[27] ^ Q[3]);
      H[ 4] = ((XH >>  3) ^ (Q[20]     ) ^ M[4]) + (XL ^ Q[28] ^ Q[4]);
      H[ 5] = ((XH <<  6) ^ (Q[21] >> 6) ^ M[5]) + (XL ^ Q[29] ^ Q[5]);
      H[ 6] = ((XH >>  4) ^ (Q[22] << 6) ^ M[6]) + (XL ^ Q[30] ^ Q[6]);
      H[ 7] = ((XH >> 11) ^ (Q[23] << 2) ^ M[7]) + (XL ^ Q[31] ^ Q[7]);

      H[ 8] = rotate_left(H[4],  9) + (XH ^ Q[24] ^ M[ 8]) + ((XL << 8) ^ Q[23] ^ Q[ 8]);
      H[ 9] = rotate_left(H[5], 10) + (XH ^ Q[25] ^ M[ 9]) + ((XL >> 6) ^ Q[16] ^ Q[ 9]);
      H[10] = rotate_left(H[6], 11) + (XH ^ Q[26] ^ M[10]) + ((XL << 6) ^ Q[17] ^ Q[10]);
      H[11] = rotate_left(H[7], 12) + (XH ^ Q[27] ^ M[11]) + ((XL << 4) ^ Q[18] ^ Q[11]);
      H[12] = rotate_left(H[0], 13) + (XH ^ Q[28] ^ M[12]) + ((XL >> 3) ^ Q[19] ^ Q[12]);
      H[13] = rotate_left(H[1], 14) + (XH ^ Q[29] ^ M[13]) + ((XL >> 4) ^ Q[20] ^ Q[13]);
      H[14] = rotate_left(H[2], 15) + (XH ^ Q[30] ^ M[14]) + ((XL >> 7) ^ Q[21] ^ Q[14]);
      H[15] = rotate_left(H[3], 16) + (XH ^ Q[31] ^ M[15]) + ((XL >> 2) ^ Q[22] ^ Q[15]);
      }
   }

/*
* Copy out the digest
*/
void BMW_512::copy_out(byte output[])
   {
   for(u32bit i = 0; i != OUTPUT_LENGTH; i += 8)
      store_le(H[8 + i/8], output + i);
   }

/*
* Clear memory of sensitive data
*/
void BMW_512::clear() throw()
   {
   MDx_HashFunction::clear();
   H[ 0] = 0x8081828384858687;
   H[ 1] = 0x88898A8B8C8D8E8F;
   H[ 2] = 0x9091929394959697;
   H[ 3] = 0x98999A9B9C9D9E9F;
   H[ 4] = 0xA0A1A2A3A4A5A6A7;
   H[ 5] = 0xA8A9AAABACADAEAF;
   H[ 6] = 0xB0B1B2B3B4B5B6B7;
   H[ 7] = 0xB8B9BABBBCBDBEBF;
   H[ 8] = 0xC0C1C2C3C4C5C6C7;
   H[ 9] = 0xC8C9CACBCCCDCECF;
   H[10] = 0xD0D1D2D3D4D5D6D7;
   H[11] = 0xD8D9DADBDCDDDEDF;
   H[12] = 0xE0E1E2E3E4E5E6E7;
   H[13] = 0xE8E9EAEBECEDEEEF;
   H[14] = 0xF0F1F2F3F4F5F6F7;
   H[15] = 0xF8F9FAFBFCFDFEFF;
   }

}
