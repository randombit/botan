/*
* Blue Midnight Wish 512 (Round 2 tweaked)
* (C) 2009 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/bmw_512.h>
#include <botan/loadstor.h>
#include <botan/rotate.h>

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

/**
* Blue Midnight Wish 512 compression function
*/
void BMW_512_compress(u64bit H[16], const u64bit M[16], u64bit Q[32])
   {
   const size_t EXPAND_1_ROUNDS = 2;

   for(size_t i = 0; i != 16; ++i)
      Q[i] = H[i] ^ M[i];

   Q[16] = Q[ 5] - Q[ 7] + Q[10] + Q[13] + Q[14];
   Q[17] = Q[ 6] - Q[ 8] + Q[11] + Q[14] - Q[15];
   Q[18] = Q[ 0] + Q[ 7] + Q[ 9] - Q[12] + Q[15];
   Q[19] = Q[ 0] - Q[ 1] + Q[ 8] - Q[10] + Q[13];
   Q[20] = Q[ 1] + Q[ 2] + Q[ 9] - Q[11] - Q[14];
   Q[21] = Q[ 3] - Q[ 2] + Q[10] - Q[12] + Q[15];
   Q[22] = Q[ 4] - Q[ 0] - Q[ 3] - Q[11] + Q[13];
   Q[23] = Q[ 1] - Q[ 4] - Q[ 5] - Q[12] - Q[14];
   Q[24] = Q[ 2] - Q[ 5] - Q[ 6] + Q[13] - Q[15];
   Q[25] = Q[ 0] - Q[ 3] + Q[ 6] - Q[ 7] + Q[14];
   Q[26] = Q[ 8] - Q[ 1] - Q[ 4] - Q[ 7] + Q[15];
   Q[27] = Q[ 8] - Q[ 0] - Q[ 2] - Q[ 5] + Q[ 9];
   Q[28] = Q[ 1] + Q[ 3] - Q[ 6] - Q[ 9] + Q[10];
   Q[29] = Q[ 2] + Q[ 4] + Q[ 7] + Q[10] + Q[11];
   Q[30] = Q[ 3] - Q[ 5] + Q[ 8] - Q[11] - Q[12];
   Q[31] = Q[12] - Q[ 4] - Q[ 6] - Q[ 9] + Q[13];

   Q[ 0] = S0(Q[16]) + H[ 1];
   Q[ 1] = S1(Q[17]) + H[ 2];
   Q[ 2] = S2(Q[18]) + H[ 3];
   Q[ 3] = S3(Q[19]) + H[ 4];
   Q[ 4] = S4(Q[20]) + H[ 5];
   Q[ 5] = S0(Q[21]) + H[ 6];
   Q[ 6] = S1(Q[22]) + H[ 7];
   Q[ 7] = S2(Q[23]) + H[ 8];
   Q[ 8] = S3(Q[24]) + H[ 9];
   Q[ 9] = S4(Q[25]) + H[10];
   Q[10] = S0(Q[26]) + H[11];
   Q[11] = S1(Q[27]) + H[12];
   Q[12] = S2(Q[28]) + H[13];
   Q[13] = S3(Q[29]) + H[14];
   Q[14] = S4(Q[30]) + H[15];
   Q[15] = S0(Q[31]) + H[ 0];

   static const u64bit x55 = 0x0555555555555555;

   for(size_t i = 16; i != 16 + EXPAND_1_ROUNDS; ++i)
      {
      Q[i] = S1(Q[i-16]) + S2(Q[i-15]) + S3(Q[i-14]) + S0(Q[i-13]) +
             S1(Q[i-12]) + S2(Q[i-11]) + S3(Q[i-10]) + S0(Q[i- 9]) +
             S1(Q[i- 8]) + S2(Q[i- 7]) + S3(Q[i- 6]) + S0(Q[i- 5]) +
             S1(Q[i- 4]) + S2(Q[i- 3]) + S3(Q[i- 2]) + S0(Q[i- 1]) +
             ((rotate_left(M[(i-16) % 16], ((i-16)%16) + 1) +
               rotate_left(M[(i-13) % 16], ((i-13)%16) + 1) -
               rotate_left(M[(i- 6) % 16], ((i-6)%16) + 1) +
               (x55 * i)) ^ H[(i-16+7)%16]);
      }

   for(size_t i = 16 + EXPAND_1_ROUNDS; i != 32; ++i)
      {
      Q[i] = Q[i-16] + rotate_left(Q[i-15],  5) +
             Q[i-14] + rotate_left(Q[i-13], 11) +
             Q[i-12] + rotate_left(Q[i-11], 27) +
             Q[i-10] + rotate_left(Q[i- 9], 32) +
             Q[i- 8] + rotate_left(Q[i- 7], 37) +
             Q[i- 6] + rotate_left(Q[i- 5], 43) +
             Q[i- 4] + rotate_left(Q[i- 3], 53) +
             S4(Q[i - 2]) + ((Q[i-1] >> 2) ^ Q[i-1]) +
             ((rotate_left(M[(i-16) % 16], ((i-16)%16 + 1)) +
               rotate_left(M[(i-13) % 16], ((i-13)%16 + 1)) -
               rotate_left(M[(i- 6) % 16], ((i-6)%16 + 1)) +
               (x55 * i)) ^ H[(i-16+7)%16]);
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

void BMW_512::compress_n(const byte input[], size_t blocks)
   {
   for(size_t i = 0; i != blocks; ++i)
      {
      load_le(&M[0], input, M.size());

      BMW_512_compress(&H[0], &M[0], &Q[0]);

      input += hash_block_size();
      }
   }

/*
* Copy out the digest
*/
void BMW_512::copy_out(byte output[])
   {
   u64bit final[16] = {
      0xAAAAAAAAAAAAAAA0uLL,  0xAAAAAAAAAAAAAAA1uLL,
      0xAAAAAAAAAAAAAAA2uLL,  0xAAAAAAAAAAAAAAA3uLL,
      0xAAAAAAAAAAAAAAA4uLL,  0xAAAAAAAAAAAAAAA5uLL,
      0xAAAAAAAAAAAAAAA6uLL,  0xAAAAAAAAAAAAAAA7uLL,
      0xAAAAAAAAAAAAAAA8uLL,  0xAAAAAAAAAAAAAAA9uLL,
      0xAAAAAAAAAAAAAAAAuLL,  0xAAAAAAAAAAAAAAABuLL,
      0xAAAAAAAAAAAAAAACuLL,  0xAAAAAAAAAAAAAAADuLL,
      0xAAAAAAAAAAAAAAAEuLL,  0xAAAAAAAAAAAAAAAFuLL };

   BMW_512_compress(final, &H[0], &Q[0]);

   for(size_t i = 0; i != output_length(); i += 8)
      store_le(final[8 + i/8], output + i);
   }

/*
* Clear memory of sensitive data
*/
void BMW_512::clear()
   {
   MDx_HashFunction::clear();
   zeroise(M);
   zeroise(Q);

   H[ 0] = 0x8081828384858687uLL;
   H[ 1] = 0x88898A8B8C8D8E8FuLL;
   H[ 2] = 0x9091929394959697uLL;
   H[ 3] = 0x98999A9B9C9D9E9FuLL;
   H[ 4] = 0xA0A1A2A3A4A5A6A7uLL;
   H[ 5] = 0xA8A9AAABACADAEAFuLL;
   H[ 6] = 0xB0B1B2B3B4B5B6B7uLL;
   H[ 7] = 0xB8B9BABBBCBDBEBFuLL;
   H[ 8] = 0xC0C1C2C3C4C5C6C7uLL;
   H[ 9] = 0xC8C9CACBCCCDCECFuLL;
   H[10] = 0xD0D1D2D3D4D5D6D7uLL;
   H[11] = 0xD8D9DADBDCDDDEDFuLL;
   H[12] = 0xE0E1E2E3E4E5E6E7uLL;
   H[13] = 0xE8E9EAEBECEDEEEFuLL;
   H[14] = 0xF0F1F2F3F4F5F6F7uLL;
   H[15] = 0xF8F9FAFBFCFDFEFFuLL;
   }

}
