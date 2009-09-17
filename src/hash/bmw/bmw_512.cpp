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
      for(u32bit j = 0; j != 16; ++j)
         H[j] ^= M[j] = load_le<u64bit>(input, j);
      input += HASH_BLOCK_SIZE;

      H[16] = H[ 5] - H[ 7] + H[10] + H[13] + H[14];
      H[17] = H[ 6] - H[ 8] + H[11] + H[14] - H[15];
      H[18] = H[ 0] + H[ 7] + H[ 9] - H[12] + H[15];
      H[19] = H[ 0] - H[ 1] + H[ 8] - H[10] + H[13];
      H[20] = H[ 1] + H[ 2] + H[ 9] - H[11] - H[14];
      H[21] = H[ 3] - H[ 2] + H[10] - H[12] + H[15];
      H[22] = H[ 4] - H[ 0] - H[ 3] - H[11] + H[13];
      H[23] = H[ 1] - H[ 4] - H[ 5] - H[12] - H[14];
      H[24] = H[ 2] - H[ 5] - H[ 6] + H[13] - H[15];
      H[25] = H[ 0] - H[ 3] + H[ 6] - H[ 7] + H[14];
      H[26] = H[ 8] - H[ 1] - H[ 4] - H[ 7] + H[15];
      H[27] = H[ 8] - H[ 0] - H[ 2] - H[ 5] + H[ 9];
      H[28] = H[ 1] + H[ 3] - H[ 6] - H[ 9] + H[10];
      H[29] = H[ 2] + H[ 4] + H[ 7] + H[10] + H[11];
      H[30] = H[ 3] - H[ 5] + H[ 8] - H[11] - H[12];
      H[31] = H[12] - H[ 4] - H[ 6] - H[ 9] + H[13];

      H[ 0] = S0(H[16]);
      H[ 1] = S1(H[17]);
      H[ 2] = S2(H[18]);
      H[ 3] = S3(H[19]);
      H[ 4] = S4(H[20]);
      H[ 5] = S0(H[21]);
      H[ 6] = S1(H[22]);
      H[ 7] = S2(H[23]);
      H[ 8] = S3(H[24]);
      H[ 9] = S4(H[25]);
      H[10] = S0(H[26]);
      H[11] = S1(H[27]);
      H[12] = S2(H[28]);
      H[13] = S3(H[29]);
      H[14] = S4(H[30]);
      H[15] = S0(H[31]);

      for(u32bit j = 16; j != 18; ++j)
         {
         H[j] = S1(H[j-16]) + S2(H[j-15]) + S3(H[j-14]) + S0(H[j-13]) +
                S1(H[j-12]) + S2(H[j-11]) + S3(H[j-10]) + S0(H[j- 9]) +
                S1(H[j- 8]) + S2(H[j- 7]) + S3(H[j- 6]) + S0(H[j- 5]) +
                S1(H[j- 4]) + S2(H[j- 3]) + S3(H[j- 2]) + S0(H[j- 1]) +
                M[j-16] + M[j-13] - M[j-6] +
                (0x0555555555555555 * j);
         }

      for(u32bit j = 18; j != 32; ++j)
         {
         H[j] = H[j-16] + rotate_left(H[j-15],  5) +
                H[j-14] + rotate_left(H[j-13], 11) +
                H[j-12] + rotate_left(H[j-11], 27) +
                H[j-10] + rotate_left(H[j- 9], 32) +
                H[j- 8] + rotate_left(H[j- 7], 37) +
                H[j- 6] + rotate_left(H[j- 5], 43) +
                H[j- 4] + rotate_left(H[j- 3], 53) +
                (H[j- 2] >> 2 ^ H[j- 2]) + S4(H[j- 1]) +
                M[j-16] + M[(j-13) % 16] - M[(j-6) % 16] +
                (0x0555555555555555 * j);
         }

      u64bit XL = H[16] ^ H[17] ^ H[18] ^ H[19] ^
                  H[20] ^ H[21] ^ H[22] ^ H[23];

      u64bit XH = H[24] ^ H[25] ^ H[26] ^ H[27] ^
                  H[28] ^ H[29] ^ H[30] ^ H[31];

      XH ^= XL;

      H[ 0] = ((XH <<  5) ^ (H[16] >> 5) ^ M[0]) + (XL ^ H[24] ^ H[0]);
      H[ 1] = ((XH >>  7) ^ (H[17] << 8) ^ M[1]) + (XL ^ H[25] ^ H[1]);
      H[ 2] = ((XH >>  5) ^ (H[18] << 5) ^ M[2]) + (XL ^ H[26] ^ H[2]);
      H[ 3] = ((XH >>  1) ^ (H[19] << 5) ^ M[3]) + (XL ^ H[27] ^ H[3]);
      H[ 4] = ((XH >>  3) ^ (H[20]     ) ^ M[4]) + (XL ^ H[28] ^ H[4]);
      H[ 5] = ((XH <<  6) ^ (H[21] >> 6) ^ M[5]) + (XL ^ H[29] ^ H[5]);
      H[ 6] = ((XH >>  4) ^ (H[22] << 6) ^ M[6]) + (XL ^ H[30] ^ H[6]);
      H[ 7] = ((XH >> 11) ^ (H[23] << 2) ^ M[7]) + (XL ^ H[31] ^ H[7]);

      H[ 8] = rotate_left(H[4],  9) + (XH ^ H[24] ^ M[ 8]) + ((XL << 8) ^ H[23] ^ H[ 8]);
      H[ 9] = rotate_left(H[5], 10) + (XH ^ H[25] ^ M[ 9]) + ((XL >> 6) ^ H[16] ^ H[ 9]);
      H[10] = rotate_left(H[6], 11) + (XH ^ H[26] ^ M[10]) + ((XL << 6) ^ H[17] ^ H[10]);
      H[11] = rotate_left(H[7], 12) + (XH ^ H[27] ^ M[11]) + ((XL << 4) ^ H[18] ^ H[11]);
      H[12] = rotate_left(H[0], 13) + (XH ^ H[28] ^ M[12]) + ((XL >> 3) ^ H[19] ^ H[12]);
      H[13] = rotate_left(H[1], 14) + (XH ^ H[29] ^ M[13]) + ((XL >> 4) ^ H[20] ^ H[13]);
      H[14] = rotate_left(H[2], 15) + (XH ^ H[30] ^ M[14]) + ((XL >> 7) ^ H[21] ^ H[14]);
      H[15] = rotate_left(H[3], 16) + (XH ^ H[31] ^ M[15]) + ((XL >> 2) ^ H[22] ^ H[15]);
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
   M.clear();

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
