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
   uint32_t W[68], W1[64];
   uint32_t SS1, SS2, TT1, TT2, T[64];

   for(size_t i = 0; i != blocks; ++i)
      {
      uint32_t A = m_digest[0], B = m_digest[1], C = m_digest[2], D = m_digest[3],
               E = m_digest[4], F = m_digest[5], G = m_digest[6], H = m_digest[7];

      load_be(m_M.data(), input, m_M.size());

      // Message Extension (a)
      for (size_t j = 0; j < 16; j++)
         {
         W[j] = m_M[j];
         }
      // Message Extension (b)
      for (size_t j = 16; j < 68; j++)
         {
         W[j] = P1(W[j-16] ^ W[j-9] ^ rotate_left(W[j-3], 15)) ^ rotate_left(W[j-13], 7) ^ W[j-6];
         }
      // Message Extension (c)
      for (size_t j = 0; j < 64; j++)
         {
         W1[j] = W[j] ^ W[j+4];
         }

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

      m_digest[0] ^= A;
      m_digest[1] ^= B;
      m_digest[2] ^= C;
      m_digest[3] ^= D;
      m_digest[4] ^= E;
      m_digest[5] ^= F;
      m_digest[6] ^= G;
      m_digest[7] ^= H;

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
   zeroise(m_M);
   std::copy(std::begin(SM3_IV), std::end(SM3_IV), m_digest.begin());
   }

}
