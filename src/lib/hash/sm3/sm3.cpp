/*
* SM3
* (C) 2017 Ribose Inc.
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/sm3.h>

namespace Botan {

namespace {

const uint32_t SM3_IV[] = {
   0x7380166fUL, 0x4914b2b9UL, 0x172442d7UL, 0xda8a0600UL,
   0xa96f30bcUL, 0x163138aaUL, 0xe38dee4dUL, 0xb0fb0e4eUL
};

const uint32_t SM3_TJ_0_15 = 0x79cc4519;
const uint32_t SM3_TJ_16_63 = 0x7a879d8a;

inline uint32_t P0(uint32_t X)
   {
   return X ^ rotate_left(X, 9) ^ rotate_left(X, 17);
   }

inline uint32_t P1(uint32_t X)
   {
   return X ^ rotate_left(X, 15) ^ rotate_left(X, 23);
   }

inline uint32_t FF0(uint32_t X, uint32_t Y, uint32_t Z)
   {
   return X ^ Y ^ Z;
   }

inline uint32_t FF1(uint32_t X, uint32_t Y, uint32_t Z)
   {
   return (X & Y) | (X & Z) | (Y & Z);
   }

inline uint32_t GG0(uint32_t X, uint32_t Y, uint32_t Z)
   {
   return X ^ Y ^ Z;
   }

inline uint32_t GG1(uint32_t X, uint32_t Y, uint32_t Z)
   {
   return (X & Y) | (~X & Z);
   }

}

/*
* SM3 Compression Function
*/
void SM3::compress_n(const uint8_t input[], size_t blocks)
   {
   uint32_t A = m_digest[0], B = m_digest[1], C = m_digest[2], D = m_digest[3],
            E = m_digest[4], F = m_digest[5], G = m_digest[6], H = m_digest[7];
   uint32_t W[68], W1[64];
   uint32_t SS1, SS2, TT1, TT2, T[64];

   for(size_t i = 0; i != blocks; ++i)
      {

      // Message Extension (a)
      W[ 0] = load_be<uint32_t>(input, 0);
      W[ 1] = load_be<uint32_t>(input, 1);
      W[ 2] = load_be<uint32_t>(input, 2);
      W[ 3] = load_be<uint32_t>(input, 3);
      W[ 4] = load_be<uint32_t>(input, 4);
      W[ 5] = load_be<uint32_t>(input, 5);
      W[ 6] = load_be<uint32_t>(input, 6);
      W[ 7] = load_be<uint32_t>(input, 7);
      W[ 8] = load_be<uint32_t>(input, 8);
      W[ 9] = load_be<uint32_t>(input, 9);
      W[10] = load_be<uint32_t>(input, 10);
      W[11] = load_be<uint32_t>(input, 11);
      W[12] = load_be<uint32_t>(input, 12);
      W[13] = load_be<uint32_t>(input, 13);
      W[14] = load_be<uint32_t>(input, 14);
      W[15] = load_be<uint32_t>(input, 15);

      // Message Extension (b)
      W[16] = P1(W[ 0] ^ W[ 7] ^ rotate_left(W[13], 15)) ^ rotate_left(W[ 3], 7) ^ W[10];
      W[17] = P1(W[ 1] ^ W[ 8] ^ rotate_left(W[14], 15)) ^ rotate_left(W[ 4], 7) ^ W[11];
      W[18] = P1(W[ 2] ^ W[ 9] ^ rotate_left(W[15], 15)) ^ rotate_left(W[ 5], 7) ^ W[12];
      W[19] = P1(W[ 3] ^ W[10] ^ rotate_left(W[16], 15)) ^ rotate_left(W[ 6], 7) ^ W[13];
      W[20] = P1(W[ 4] ^ W[11] ^ rotate_left(W[17], 15)) ^ rotate_left(W[ 7], 7) ^ W[14];
      W[21] = P1(W[ 5] ^ W[12] ^ rotate_left(W[18], 15)) ^ rotate_left(W[ 8], 7) ^ W[15];
      W[22] = P1(W[ 6] ^ W[13] ^ rotate_left(W[19], 15)) ^ rotate_left(W[ 9], 7) ^ W[16];
      W[23] = P1(W[ 7] ^ W[14] ^ rotate_left(W[20], 15)) ^ rotate_left(W[10], 7) ^ W[17];
      W[24] = P1(W[ 8] ^ W[15] ^ rotate_left(W[21], 15)) ^ rotate_left(W[11], 7) ^ W[18];
      W[25] = P1(W[ 9] ^ W[16] ^ rotate_left(W[22], 15)) ^ rotate_left(W[12], 7) ^ W[19];
      W[26] = P1(W[10] ^ W[17] ^ rotate_left(W[23], 15)) ^ rotate_left(W[13], 7) ^ W[20];
      W[27] = P1(W[11] ^ W[18] ^ rotate_left(W[24], 15)) ^ rotate_left(W[14], 7) ^ W[21];
      W[28] = P1(W[12] ^ W[19] ^ rotate_left(W[25], 15)) ^ rotate_left(W[15], 7) ^ W[22];
      W[29] = P1(W[13] ^ W[20] ^ rotate_left(W[26], 15)) ^ rotate_left(W[16], 7) ^ W[23];
      W[30] = P1(W[14] ^ W[21] ^ rotate_left(W[27], 15)) ^ rotate_left(W[17], 7) ^ W[24];
      W[31] = P1(W[15] ^ W[22] ^ rotate_left(W[28], 15)) ^ rotate_left(W[18], 7) ^ W[25];
      W[32] = P1(W[16] ^ W[23] ^ rotate_left(W[29], 15)) ^ rotate_left(W[19], 7) ^ W[26];
      W[33] = P1(W[17] ^ W[24] ^ rotate_left(W[30], 15)) ^ rotate_left(W[20], 7) ^ W[27];
      W[34] = P1(W[18] ^ W[25] ^ rotate_left(W[31], 15)) ^ rotate_left(W[21], 7) ^ W[28];
      W[35] = P1(W[19] ^ W[26] ^ rotate_left(W[32], 15)) ^ rotate_left(W[22], 7) ^ W[29];
      W[36] = P1(W[20] ^ W[27] ^ rotate_left(W[33], 15)) ^ rotate_left(W[23], 7) ^ W[30];
      W[37] = P1(W[21] ^ W[28] ^ rotate_left(W[34], 15)) ^ rotate_left(W[24], 7) ^ W[31];
      W[38] = P1(W[22] ^ W[29] ^ rotate_left(W[35], 15)) ^ rotate_left(W[25], 7) ^ W[32];
      W[39] = P1(W[23] ^ W[30] ^ rotate_left(W[36], 15)) ^ rotate_left(W[26], 7) ^ W[33];
      W[40] = P1(W[24] ^ W[31] ^ rotate_left(W[37], 15)) ^ rotate_left(W[27], 7) ^ W[34];
      W[41] = P1(W[25] ^ W[32] ^ rotate_left(W[38], 15)) ^ rotate_left(W[28], 7) ^ W[35];
      W[42] = P1(W[26] ^ W[33] ^ rotate_left(W[39], 15)) ^ rotate_left(W[29], 7) ^ W[36];
      W[43] = P1(W[27] ^ W[34] ^ rotate_left(W[40], 15)) ^ rotate_left(W[30], 7) ^ W[37];
      W[44] = P1(W[28] ^ W[35] ^ rotate_left(W[41], 15)) ^ rotate_left(W[31], 7) ^ W[38];
      W[45] = P1(W[29] ^ W[36] ^ rotate_left(W[42], 15)) ^ rotate_left(W[32], 7) ^ W[39];
      W[46] = P1(W[30] ^ W[37] ^ rotate_left(W[43], 15)) ^ rotate_left(W[33], 7) ^ W[40];
      W[47] = P1(W[31] ^ W[38] ^ rotate_left(W[44], 15)) ^ rotate_left(W[34], 7) ^ W[41];
      W[48] = P1(W[32] ^ W[39] ^ rotate_left(W[45], 15)) ^ rotate_left(W[35], 7) ^ W[42];
      W[49] = P1(W[33] ^ W[40] ^ rotate_left(W[46], 15)) ^ rotate_left(W[36], 7) ^ W[43];
      W[50] = P1(W[34] ^ W[41] ^ rotate_left(W[47], 15)) ^ rotate_left(W[37], 7) ^ W[44];
      W[51] = P1(W[35] ^ W[42] ^ rotate_left(W[48], 15)) ^ rotate_left(W[38], 7) ^ W[45];
      W[52] = P1(W[36] ^ W[43] ^ rotate_left(W[49], 15)) ^ rotate_left(W[39], 7) ^ W[46];
      W[53] = P1(W[37] ^ W[44] ^ rotate_left(W[50], 15)) ^ rotate_left(W[40], 7) ^ W[47];
      W[54] = P1(W[38] ^ W[45] ^ rotate_left(W[51], 15)) ^ rotate_left(W[41], 7) ^ W[48];
      W[55] = P1(W[39] ^ W[46] ^ rotate_left(W[52], 15)) ^ rotate_left(W[42], 7) ^ W[49];
      W[56] = P1(W[40] ^ W[47] ^ rotate_left(W[53], 15)) ^ rotate_left(W[43], 7) ^ W[50];
      W[57] = P1(W[41] ^ W[48] ^ rotate_left(W[54], 15)) ^ rotate_left(W[44], 7) ^ W[51];
      W[58] = P1(W[42] ^ W[49] ^ rotate_left(W[55], 15)) ^ rotate_left(W[45], 7) ^ W[52];
      W[59] = P1(W[43] ^ W[50] ^ rotate_left(W[56], 15)) ^ rotate_left(W[46], 7) ^ W[53];
      W[60] = P1(W[44] ^ W[51] ^ rotate_left(W[57], 15)) ^ rotate_left(W[47], 7) ^ W[54];
      W[61] = P1(W[45] ^ W[52] ^ rotate_left(W[58], 15)) ^ rotate_left(W[48], 7) ^ W[55];
      W[62] = P1(W[46] ^ W[53] ^ rotate_left(W[59], 15)) ^ rotate_left(W[49], 7) ^ W[56];
      W[63] = P1(W[47] ^ W[54] ^ rotate_left(W[60], 15)) ^ rotate_left(W[50], 7) ^ W[57];
      W[64] = P1(W[48] ^ W[55] ^ rotate_left(W[61], 15)) ^ rotate_left(W[51], 7) ^ W[58];
      W[65] = P1(W[49] ^ W[56] ^ rotate_left(W[62], 15)) ^ rotate_left(W[52], 7) ^ W[59];
      W[66] = P1(W[50] ^ W[57] ^ rotate_left(W[63], 15)) ^ rotate_left(W[53], 7) ^ W[60];
      W[67] = P1(W[51] ^ W[58] ^ rotate_left(W[64], 15)) ^ rotate_left(W[54], 7) ^ W[61];

      // Message Extension (c)
      W1[ 0] = W[ 0] ^ W[ 4];
      W1[ 1] = W[ 1] ^ W[ 5];
      W1[ 2] = W[ 2] ^ W[ 6];
      W1[ 3] = W[ 3] ^ W[ 7];
      W1[ 4] = W[ 4] ^ W[ 8];
      W1[ 5] = W[ 5] ^ W[ 9];
      W1[ 6] = W[ 6] ^ W[10];
      W1[ 7] = W[ 7] ^ W[11];
      W1[ 8] = W[ 8] ^ W[12];
      W1[ 9] = W[ 9] ^ W[13];
      W1[10] = W[10] ^ W[14];
      W1[11] = W[11] ^ W[15];
      W1[12] = W[12] ^ W[16];
      W1[13] = W[13] ^ W[17];
      W1[14] = W[14] ^ W[18];
      W1[15] = W[15] ^ W[19];
      W1[16] = W[16] ^ W[20];
      W1[17] = W[17] ^ W[21];
      W1[18] = W[18] ^ W[22];
      W1[19] = W[19] ^ W[23];
      W1[20] = W[20] ^ W[24];
      W1[21] = W[21] ^ W[25];
      W1[22] = W[22] ^ W[26];
      W1[23] = W[23] ^ W[27];
      W1[24] = W[24] ^ W[28];
      W1[25] = W[25] ^ W[29];
      W1[26] = W[26] ^ W[30];
      W1[27] = W[27] ^ W[31];
      W1[28] = W[28] ^ W[32];
      W1[29] = W[29] ^ W[33];
      W1[30] = W[30] ^ W[34];
      W1[31] = W[31] ^ W[35];
      W1[32] = W[32] ^ W[36];
      W1[33] = W[33] ^ W[37];
      W1[34] = W[34] ^ W[38];
      W1[35] = W[35] ^ W[39];
      W1[36] = W[36] ^ W[40];
      W1[37] = W[37] ^ W[41];
      W1[38] = W[38] ^ W[42];
      W1[39] = W[39] ^ W[43];
      W1[40] = W[40] ^ W[44];
      W1[41] = W[41] ^ W[45];
      W1[42] = W[42] ^ W[46];
      W1[43] = W[43] ^ W[47];
      W1[44] = W[44] ^ W[48];
      W1[45] = W[45] ^ W[49];
      W1[46] = W[46] ^ W[50];
      W1[47] = W[47] ^ W[51];
      W1[48] = W[48] ^ W[52];
      W1[49] = W[49] ^ W[53];
      W1[50] = W[50] ^ W[54];
      W1[51] = W[51] ^ W[55];
      W1[52] = W[52] ^ W[56];
      W1[53] = W[53] ^ W[57];
      W1[54] = W[54] ^ W[58];
      W1[55] = W[55] ^ W[59];
      W1[56] = W[56] ^ W[60];
      W1[57] = W[57] ^ W[61];
      W1[58] = W[58] ^ W[62];
      W1[59] = W[59] ^ W[63];
      W1[60] = W[60] ^ W[64];
      W1[61] = W[61] ^ W[65];
      W1[62] = W[62] ^ W[66];
      W1[63] = W[63] ^ W[67];

      for (size_t j = 0; j < 16; j++)
         {
         T[j] = SM3_TJ_0_15;
         SS1 = rotate_left(rotate_left(A, 12) + E + rotate_left(T[j], j), 7);
         SS2 = SS1 ^ rotate_left(A, 12);
         TT1 = FF0(A, B, C) + D + SS2 + W1[j];
         TT2 = GG0(E, F, G) + H + SS1 + W[j];
         D = C;
         C = rotate_left(B, 9);
         B = A;
         A = TT1;
         H = G;
         G = rotate_left(F, 19);
         F = E;
         E = P0(TT2);
         }

      for (size_t j = 16; j < 64; j++)
         {
         T[j] = SM3_TJ_16_63;
         SS1 = rotate_left(rotate_left(A, 12) + E + rotate_left(T[j], j), 7);
         SS2 = SS1 ^ rotate_left(A, 12);
         TT1 = FF1(A, B, C) + D + SS2 + W1[j];
         TT2 = GG1(E, F, G) + H + SS1 + W[j];
         D = C;
         C = rotate_left(B, 9);
         B = A;
         A = TT1;
         H = G;
         G = rotate_left(F, 19);
         F = E;
         E = P0(TT2);
         }

      A = (m_digest[0] ^= A);
      B = (m_digest[1] ^= B);
      C = (m_digest[2] ^= C);
      D = (m_digest[3] ^= D);
      E = (m_digest[4] ^= E);
      F = (m_digest[5] ^= F);
      G = (m_digest[6] ^= G);
      H = (m_digest[7] ^= H);

      input += hash_block_size();
      }
   }

/*
* Copy out the digest
*/
void SM3::copy_out(uint8_t output[])
   {
   copy_out_vec_be(output, output_length(), m_digest);
   }

/*
* Clear memory of sensitive data
*/
void SM3::clear()
   {
   MDx_HashFunction::clear();
   std::copy(std::begin(SM3_IV), std::end(SM3_IV), m_digest.begin());
   }

}
