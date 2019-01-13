/*
* XTEA
* (C) 1999-2009,2016 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/xtea.h>
#include <botan/loadstor.h>

namespace Botan {

/*
* XTEA Encryption
*/
void XTEA::encrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const
   {
   verify_key_set(m_EK.empty() == false);

   const uint32_t* EK = &m_EK[0];

   const size_t blocks4 = blocks / 4;
   const size_t blocks_left = blocks % 4;

   BOTAN_PARALLEL_FOR(size_t i = 0; i < blocks4; i++)
      {
      uint32_t L0, R0, L1, R1, L2, R2, L3, R3;
      load_be(in + 4*BLOCK_SIZE*i, L0, R0, L1, R1, L2, R2, L3, R3);

      for(size_t r = 0; r != 32; ++r)
         {
         L0 += (((R0 << 4) ^ (R0 >> 5)) + R0) ^ EK[2*r];
         L1 += (((R1 << 4) ^ (R1 >> 5)) + R1) ^ EK[2*r];
         L2 += (((R2 << 4) ^ (R2 >> 5)) + R2) ^ EK[2*r];
         L3 += (((R3 << 4) ^ (R3 >> 5)) + R3) ^ EK[2*r];

         R0 += (((L0 << 4) ^ (L0 >> 5)) + L0) ^ EK[2*r+1];
         R1 += (((L1 << 4) ^ (L1 >> 5)) + L1) ^ EK[2*r+1];
         R2 += (((L2 << 4) ^ (L2 >> 5)) + L2) ^ EK[2*r+1];
         R3 += (((L3 << 4) ^ (L3 >> 5)) + L3) ^ EK[2*r+1];
         }

      store_be(out + 4*BLOCK_SIZE*i, L0, R0, L1, R1, L2, R2, L3, R3);
      }

   BOTAN_PARALLEL_FOR(size_t i = 0; i < blocks_left; ++i)
      {
      uint32_t L, R;
      load_be(in + BLOCK_SIZE*(4*blocks4+i), L, R);

      for(size_t r = 0; r != 32; ++r)
         {
         L += (((R << 4) ^ (R >> 5)) + R) ^ EK[2*r];
         R += (((L << 4) ^ (L >> 5)) + L) ^ EK[2*r+1];
         }

      store_be(out + BLOCK_SIZE*(4*blocks4+i), L, R);
      }
   }

/*
* XTEA Decryption
*/
void XTEA::decrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const
   {
   verify_key_set(m_EK.empty() == false);

   const uint32_t* EK = &m_EK[0];

   const size_t blocks4 = blocks / 4;
   const size_t blocks_left = blocks % 4;

   BOTAN_PARALLEL_FOR(size_t i = 0; i < blocks4; i++)
      {
      uint32_t L0, R0, L1, R1, L2, R2, L3, R3;
      load_be(in + 4*BLOCK_SIZE*i, L0, R0, L1, R1, L2, R2, L3, R3);

      for(size_t r = 0; r != 32; ++r)
         {
         R0 -= (((L0 << 4) ^ (L0 >> 5)) + L0) ^ EK[63 - 2*r];
         R1 -= (((L1 << 4) ^ (L1 >> 5)) + L1) ^ EK[63 - 2*r];
         R2 -= (((L2 << 4) ^ (L2 >> 5)) + L2) ^ EK[63 - 2*r];
         R3 -= (((L3 << 4) ^ (L3 >> 5)) + L3) ^ EK[63 - 2*r];

         L0 -= (((R0 << 4) ^ (R0 >> 5)) + R0) ^ EK[62 - 2*r];
         L1 -= (((R1 << 4) ^ (R1 >> 5)) + R1) ^ EK[62 - 2*r];
         L2 -= (((R2 << 4) ^ (R2 >> 5)) + R2) ^ EK[62 - 2*r];
         L3 -= (((R3 << 4) ^ (R3 >> 5)) + R3) ^ EK[62 - 2*r];
         }

      store_be(out + 4*BLOCK_SIZE*i, L0, R0, L1, R1, L2, R2, L3, R3);
      }

   BOTAN_PARALLEL_FOR(size_t i = 0; i < blocks_left; ++i)
      {
      uint32_t L, R;
      load_be(in + BLOCK_SIZE*(4*blocks4+i), L, R);

      for(size_t r = 0; r != 32; ++r)
         {
         R -= (((L << 4) ^ (L >> 5)) + L) ^ m_EK[63 - 2*r];
         L -= (((R << 4) ^ (R >> 5)) + R) ^ m_EK[62 - 2*r];
         }

      store_be(out + BLOCK_SIZE*(4*blocks4+i), L, R);
      }
   }

/*
* XTEA Key Schedule
*/
void XTEA::key_schedule(const uint8_t key[], size_t)
   {
   m_EK.resize(64);

   secure_vector<uint32_t> UK(4);
   for(size_t i = 0; i != 4; ++i)
      UK[i] = load_be<uint32_t>(key, i);

   uint32_t D = 0;
   for(size_t i = 0; i != 64; i += 2)
      {
      m_EK[i  ] = D + UK[D % 4];
      D += 0x9E3779B9;
      m_EK[i+1] = D + UK[(D >> 11) % 4];
      }
   }

void XTEA::clear()
   {
   zap(m_EK);
   }

}
