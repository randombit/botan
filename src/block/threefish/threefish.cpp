/*
* Threefish-512
* (C) 2013 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/threefish.h>
#include <botan/rotate.h>
#include <botan/loadstor.h>

namespace Botan {

secure_vector<byte> Threefish_512::start(const byte tweak[], size_t tweak_len)
   {
   if(!valid_nonce_length(tweak_len))
      throw Invalid_IV_Length(name(), tweak_len);

   m_T.resize(3);

   m_T[0] = load_le<u64bit>(tweak, 0);
   m_T[1] = load_le<u64bit>(tweak, 1);
   m_T[2] = m_T[0] ^ m_T[1];

   return secure_vector<byte>();
   }

void Threefish_512::full_inplace_update(byte* buf, size_t sz)
   {
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

#define THREEFISH_8_ROUNDS(R1,R2)                             \
   do {                                                       \
      THREEFISH_ROUND(X0,X2,X4,X6, X1,X3,X5,X7, 46,36,19,37); \
      THREEFISH_ROUND(X2,X4,X6,X0, X1,X7,X5,X3, 33,27,14,42); \
      THREEFISH_ROUND(X4,X6,X0,X2, X1,X3,X5,X7, 17,49,36,39); \
      THREEFISH_ROUND(X6,X0,X2,X4, X1,X7,X5,X3, 44, 9,54,56); \
                                                              \
      THREEFISH_INJECT_KEY(R1);                               \
                                                              \
      THREEFISH_ROUND(X0,X2,X4,X6, X1,X3,X5,X7, 39,30,34,24); \
      THREEFISH_ROUND(X2,X4,X6,X0, X1,X7,X5,X3, 13,50,10,17); \
      THREEFISH_ROUND(X4,X6,X0,X2, X1,X3,X5,X7, 25,29,39,43); \
      THREEFISH_ROUND(X6,X0,X2,X4, X1,X7,X5,X3,  8,35,56,22); \
                                                              \
      THREEFISH_INJECT_KEY(R2);                               \
   } while(0)

   while(sz)
      {
      u64bit X0 = load_le<u64bit>(buf, 0);
      u64bit X1 = load_le<u64bit>(buf, 1);
      u64bit X2 = load_le<u64bit>(buf, 2);
      u64bit X3 = load_le<u64bit>(buf, 3);
      u64bit X4 = load_le<u64bit>(buf, 4);
      u64bit X5 = load_le<u64bit>(buf, 5);
      u64bit X6 = load_le<u64bit>(buf, 6);
      u64bit X7 = load_le<u64bit>(buf, 7);

      THREEFISH_INJECT_KEY(0);

      THREEFISH_8_ROUNDS(1,2);
      THREEFISH_8_ROUNDS(3,4);
      THREEFISH_8_ROUNDS(5,6);
      THREEFISH_8_ROUNDS(7,8);
      THREEFISH_8_ROUNDS(9,10);
      THREEFISH_8_ROUNDS(11,12);
      THREEFISH_8_ROUNDS(13,14);
      THREEFISH_8_ROUNDS(15,16);
      THREEFISH_8_ROUNDS(17,18);

      store_le(buf, X0, X1, X2, X3, X4, X5, X6, X7);

      buf += 64;
      sz -= 64;
      }

#undef THREEFISH_8_ROUNDS
#undef THREEFISH_INJECT_KEY
#undef THREEFISH_ROUND
   }

void Threefish_512::update(secure_vector<byte>& buf, size_t offset)
   {
   BOTAN_ASSERT(m_K.size() == 9, "Key was set");
   BOTAN_ASSERT(m_T.size() == 3, "Tweak was set");

   const size_t sz = buf.size() - offset;
   BOTAN_ASSERT(sz % block_size() == 0, "Block sized input");

   full_inplace_update(&buf[offset], sz);
   }

Key_Length_Specification Threefish_512::key_spec() const
   {
   return Key_Length_Specification(64);
   }

void Threefish_512::key_schedule(const byte key[], size_t)
   {
   // todo: define key schedule for smaller keys
   m_K.resize(9);

   for(size_t i = 0; i != 8; ++i)
      m_K[i] = load_le<u64bit>(key, i);

   m_K[8] = m_K[0] ^ m_K[1] ^ m_K[2] ^ m_K[3] ^
            m_K[4] ^ m_K[5] ^ m_K[6] ^ m_K[7] ^ 0x1BD11BDAA9FC1A22;
   }

void Threefish_512::finish(secure_vector<byte>& blocks, size_t offset)
   {
   update(blocks, offset);
   m_T.clear();
   }

size_t Threefish_512::output_length(size_t input_length) const
   {
   if(input_length % update_granularity() == 0)
      throw std::invalid_argument("Threefish - invalid input length " + std::to_string(input_length));

   return input_length;
   }

size_t Threefish_512::update_granularity() const
   {
   return block_size();
   }

size_t Threefish_512::minimum_final_size() const
   {
   return 0;
   }

size_t Threefish_512::default_nonce_length() const
   {
   // todo: define encoding for smaller nonces
   return 16;
   }

bool Threefish_512::valid_nonce_length(size_t nonce_len) const
   {
   return default_nonce_length() == nonce_len;
   }

void Threefish_512::clear()
   {
   zeroise(m_K);
   zeroise(m_T);
   }

}
