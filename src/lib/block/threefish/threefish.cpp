/*
* Threefish-512
* (C) 2013,2014 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/threefish.h>
#include <botan/loadstor.h>

namespace Botan {

#define THREEFISH_ROUND(X0,X1,X2,X3,X4,X5,X6,X7,ROT1,ROT2,ROT3,ROT4) \
   do {                                                              \
      X0 += X4;                                                      \
      X1 += X5;                                                      \
      X2 += X6;                                                      \
      X3 += X7;                                                      \
      X4 = rotate_left(X4, ROT1);                                    \
      X5 = rotate_left(X5, ROT2);                                    \
      X6 = rotate_left(X6, ROT3);                                    \
      X7 = rotate_left(X7, ROT4);                                    \
      X4 ^= X0;                                                      \
      X5 ^= X1;                                                      \
      X6 ^= X2;                                                      \
      X7 ^= X3;                                                      \
   } while(0)

#define THREEFISH_INJECT_KEY(r)              \
   do {                                      \
      X0 += m_K[(r  ) % 9];                  \
      X1 += m_K[(r+1) % 9];                  \
      X2 += m_K[(r+2) % 9];                  \
      X3 += m_K[(r+3) % 9];                  \
      X4 += m_K[(r+4) % 9];                  \
      X5 += m_K[(r+5) % 9] + m_T[(r  ) % 3]; \
      X6 += m_K[(r+6) % 9] + m_T[(r+1) % 3]; \
      X7 += m_K[(r+7) % 9] + (r);            \
   } while(0)

#define THREEFISH_ENC_8_ROUNDS(R1,R2)                         \
   do {                                                       \
      THREEFISH_ROUND(X0,X2,X4,X6, X1,X3,X5,X7, 46,36,19,37); \
      THREEFISH_ROUND(X2,X4,X6,X0, X1,X7,X5,X3, 33,27,14,42); \
      THREEFISH_ROUND(X4,X6,X0,X2, X1,X3,X5,X7, 17,49,36,39); \
      THREEFISH_ROUND(X6,X0,X2,X4, X1,X7,X5,X3, 44, 9,54,56); \
      THREEFISH_INJECT_KEY(R1);                               \
                                                              \
      THREEFISH_ROUND(X0,X2,X4,X6, X1,X3,X5,X7, 39,30,34,24); \
      THREEFISH_ROUND(X2,X4,X6,X0, X1,X7,X5,X3, 13,50,10,17); \
      THREEFISH_ROUND(X4,X6,X0,X2, X1,X3,X5,X7, 25,29,39,43); \
      THREEFISH_ROUND(X6,X0,X2,X4, X1,X7,X5,X3,  8,35,56,22); \
      THREEFISH_INJECT_KEY(R2);                               \
   } while(0)

void Threefish_512::skein_feedfwd(const secure_vector<u64bit>& M,
                                  const secure_vector<u64bit>& T)
   {
   BOTAN_ASSERT(m_K.size() == 9, "Key was set");
   BOTAN_ASSERT(M.size() == 8, "Single block");

   m_T[0] = T[0];
   m_T[1] = T[1];
   m_T[2] = T[0] ^ T[1];

   u64bit X0 = M[0];
   u64bit X1 = M[1];
   u64bit X2 = M[2];
   u64bit X3 = M[3];
   u64bit X4 = M[4];
   u64bit X5 = M[5];
   u64bit X6 = M[6];
   u64bit X7 = M[7];

   THREEFISH_INJECT_KEY(0);

   THREEFISH_ENC_8_ROUNDS(1,2);
   THREEFISH_ENC_8_ROUNDS(3,4);
   THREEFISH_ENC_8_ROUNDS(5,6);
   THREEFISH_ENC_8_ROUNDS(7,8);
   THREEFISH_ENC_8_ROUNDS(9,10);
   THREEFISH_ENC_8_ROUNDS(11,12);
   THREEFISH_ENC_8_ROUNDS(13,14);
   THREEFISH_ENC_8_ROUNDS(15,16);
   THREEFISH_ENC_8_ROUNDS(17,18);

   m_K[0] = M[0] ^ X0;
   m_K[1] = M[1] ^ X1;
   m_K[2] = M[2] ^ X2;
   m_K[3] = M[3] ^ X3;
   m_K[4] = M[4] ^ X4;
   m_K[5] = M[5] ^ X5;
   m_K[6] = M[6] ^ X6;
   m_K[7] = M[7] ^ X7;

   m_K[8] = m_K[0] ^ m_K[1] ^ m_K[2] ^ m_K[3] ^
            m_K[4] ^ m_K[5] ^ m_K[6] ^ m_K[7] ^ 0x1BD11BDAA9FC1A22;
   }

void Threefish_512::encrypt_n(const byte in[], byte out[], size_t blocks) const
   {
   BOTAN_ASSERT(m_K.size() == 9, "Key was set");
   BOTAN_ASSERT(m_T.size() == 3, "Tweak was set");

   for(size_t i = 0; i != blocks; ++i)
      {
      u64bit X0 = load_le<u64bit>(in, 0);
      u64bit X1 = load_le<u64bit>(in, 1);
      u64bit X2 = load_le<u64bit>(in, 2);
      u64bit X3 = load_le<u64bit>(in, 3);
      u64bit X4 = load_le<u64bit>(in, 4);
      u64bit X5 = load_le<u64bit>(in, 5);
      u64bit X6 = load_le<u64bit>(in, 6);
      u64bit X7 = load_le<u64bit>(in, 7);

      THREEFISH_INJECT_KEY(0);

      THREEFISH_ENC_8_ROUNDS(1,2);
      THREEFISH_ENC_8_ROUNDS(3,4);
      THREEFISH_ENC_8_ROUNDS(5,6);
      THREEFISH_ENC_8_ROUNDS(7,8);
      THREEFISH_ENC_8_ROUNDS(9,10);
      THREEFISH_ENC_8_ROUNDS(11,12);
      THREEFISH_ENC_8_ROUNDS(13,14);
      THREEFISH_ENC_8_ROUNDS(15,16);
      THREEFISH_ENC_8_ROUNDS(17,18);

      store_le(out, X0, X1, X2, X3, X4, X5, X6, X7);

      in += 64;
      out += 64;
      }
   }

#undef THREEFISH_ENC_8_ROUNDS
#undef THREEFISH_INJECT_KEY
#undef THREEFISH_ROUND

void Threefish_512::decrypt_n(const byte in[], byte out[], size_t blocks) const
   {
   BOTAN_ASSERT(m_K.size() == 9, "Key was set");
   BOTAN_ASSERT(m_T.size() == 3, "Tweak was set");

#define THREEFISH_ROUND(X0,X1,X2,X3,X4,X5,X6,X7,ROT1,ROT2,ROT3,ROT4) \
   do {                                                              \
      X4 ^= X0;                                                      \
      X5 ^= X1;                                                      \
      X6 ^= X2;                                                      \
      X7 ^= X3;                                                      \
      X4 = rotate_right(X4, ROT1);                                   \
      X5 = rotate_right(X5, ROT2);                                   \
      X6 = rotate_right(X6, ROT3);                                   \
      X7 = rotate_right(X7, ROT4);                                   \
      X0 -= X4;                                                      \
      X1 -= X5;                                                      \
      X2 -= X6;                                                      \
      X3 -= X7;                                                      \
   } while(0)

#define THREEFISH_INJECT_KEY(r)              \
   do {                                      \
      X0 -= m_K[(r  ) % 9];                  \
      X1 -= m_K[(r+1) % 9];                  \
      X2 -= m_K[(r+2) % 9];                  \
      X3 -= m_K[(r+3) % 9];                  \
      X4 -= m_K[(r+4) % 9];                  \
      X5 -= m_K[(r+5) % 9] + m_T[(r  ) % 3]; \
      X6 -= m_K[(r+6) % 9] + m_T[(r+1) % 3]; \
      X7 -= m_K[(r+7) % 9] + (r);            \
   } while(0)

#define THREEFISH_DEC_8_ROUNDS(R1,R2)                         \
   do {                                                       \
      THREEFISH_ROUND(X6,X0,X2,X4, X1,X7,X5,X3,  8,35,56,22); \
      THREEFISH_ROUND(X4,X6,X0,X2, X1,X3,X5,X7, 25,29,39,43); \
      THREEFISH_ROUND(X2,X4,X6,X0, X1,X7,X5,X3, 13,50,10,17); \
      THREEFISH_ROUND(X0,X2,X4,X6, X1,X3,X5,X7, 39,30,34,24); \
      THREEFISH_INJECT_KEY(R1);                               \
                                                              \
      THREEFISH_ROUND(X6,X0,X2,X4, X1,X7,X5,X3, 44, 9,54,56); \
      THREEFISH_ROUND(X4,X6,X0,X2, X1,X3,X5,X7, 17,49,36,39); \
      THREEFISH_ROUND(X2,X4,X6,X0, X1,X7,X5,X3, 33,27,14,42); \
      THREEFISH_ROUND(X0,X2,X4,X6, X1,X3,X5,X7, 46,36,19,37); \
      THREEFISH_INJECT_KEY(R2);                               \
   } while(0)

   for(size_t i = 0; i != blocks; ++i)
      {
      u64bit X0 = load_le<u64bit>(in, 0);
      u64bit X1 = load_le<u64bit>(in, 1);
      u64bit X2 = load_le<u64bit>(in, 2);
      u64bit X3 = load_le<u64bit>(in, 3);
      u64bit X4 = load_le<u64bit>(in, 4);
      u64bit X5 = load_le<u64bit>(in, 5);
      u64bit X6 = load_le<u64bit>(in, 6);
      u64bit X7 = load_le<u64bit>(in, 7);

      THREEFISH_INJECT_KEY(18);

      THREEFISH_DEC_8_ROUNDS(17,16);
      THREEFISH_DEC_8_ROUNDS(15,14);
      THREEFISH_DEC_8_ROUNDS(13,12);
      THREEFISH_DEC_8_ROUNDS(11,10);
      THREEFISH_DEC_8_ROUNDS(9,8);
      THREEFISH_DEC_8_ROUNDS(7,6);
      THREEFISH_DEC_8_ROUNDS(5,4);
      THREEFISH_DEC_8_ROUNDS(3,2);
      THREEFISH_DEC_8_ROUNDS(1,0);

      store_le(out, X0, X1, X2, X3, X4, X5, X6, X7);

      in += 64;
      out += 64;
      }

#undef THREEFISH_DEC_8_ROUNDS
#undef THREEFISH_INJECT_KEY
#undef THREEFISH_ROUND
   }

void Threefish_512::set_tweak(const byte tweak[], size_t len)
   {
   if(len != 16)
      throw Exception("Threefish-512 requires 128 bit tweak");
   m_T.resize(3);
   m_T[0] = load_le<u64bit>(tweak, 0);
   m_T[1] = load_le<u64bit>(tweak, 1);
   m_T[2] = m_T[0] ^ m_T[1];
   }

void Threefish_512::key_schedule(const byte key[], size_t)
   {
   // todo: define key schedule for smaller keys
   m_K.resize(9);

   for(size_t i = 0; i != 8; ++i)
      m_K[i] = load_le<u64bit>(key, i);

   m_K[8] = m_K[0] ^ m_K[1] ^ m_K[2] ^ m_K[3] ^
            m_K[4] ^ m_K[5] ^ m_K[6] ^ m_K[7] ^ 0x1BD11BDAA9FC1A22;

   // Reset tweak to all zeros on key reset
   m_T.resize(3);
   zeroise(m_T);
   }

void Threefish_512::clear()
   {
   zap(m_K);
   zap(m_T);
   }

}
