/*
* XTEA
* (C) 1999-2009 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/xtea.h>
#include <botan/loadstor.h>

namespace Botan {

namespace {

void xtea_encrypt_4(const byte in[32], byte out[32], const u32bit EK[64])
   {
   u32bit L0, R0, L1, R1, L2, R2, L3, R3;
   load_be(in, L0, R0, L1, R1, L2, R2, L3, R3);

   for(size_t i = 0; i != 32; ++i)
      {
      L0 += (((R0 << 4) ^ (R0 >> 5)) + R0) ^ EK[2*i];
      L1 += (((R1 << 4) ^ (R1 >> 5)) + R1) ^ EK[2*i];
      L2 += (((R2 << 4) ^ (R2 >> 5)) + R2) ^ EK[2*i];
      L3 += (((R3 << 4) ^ (R3 >> 5)) + R3) ^ EK[2*i];

      R0 += (((L0 << 4) ^ (L0 >> 5)) + L0) ^ EK[2*i+1];
      R1 += (((L1 << 4) ^ (L1 >> 5)) + L1) ^ EK[2*i+1];
      R2 += (((L2 << 4) ^ (L2 >> 5)) + L2) ^ EK[2*i+1];
      R3 += (((L3 << 4) ^ (L3 >> 5)) + L3) ^ EK[2*i+1];
      }

   store_be(out, L0, R0, L1, R1, L2, R2, L3, R3);
   }

void xtea_decrypt_4(const byte in[32], byte out[32], const u32bit EK[64])
   {
   u32bit L0, R0, L1, R1, L2, R2, L3, R3;
   load_be(in, L0, R0, L1, R1, L2, R2, L3, R3);

   for(size_t i = 0; i != 32; ++i)
      {
      R0 -= (((L0 << 4) ^ (L0 >> 5)) + L0) ^ EK[63 - 2*i];
      R1 -= (((L1 << 4) ^ (L1 >> 5)) + L1) ^ EK[63 - 2*i];
      R2 -= (((L2 << 4) ^ (L2 >> 5)) + L2) ^ EK[63 - 2*i];
      R3 -= (((L3 << 4) ^ (L3 >> 5)) + L3) ^ EK[63 - 2*i];

      L0 -= (((R0 << 4) ^ (R0 >> 5)) + R0) ^ EK[62 - 2*i];
      L1 -= (((R1 << 4) ^ (R1 >> 5)) + R1) ^ EK[62 - 2*i];
      L2 -= (((R2 << 4) ^ (R2 >> 5)) + R2) ^ EK[62 - 2*i];
      L3 -= (((R3 << 4) ^ (R3 >> 5)) + R3) ^ EK[62 - 2*i];
      }

   store_be(out, L0, R0, L1, R1, L2, R2, L3, R3);
   }

}

/*
* XTEA Encryption
*/
void XTEA::encrypt_n(const byte in[], byte out[], size_t blocks) const
   {
   while(blocks >= 4)
      {
      xtea_encrypt_4(in, out, &(this->m_EK[0]));
      in += 4 * BLOCK_SIZE;
      out += 4 * BLOCK_SIZE;
      blocks -= 4;
      }

   for(size_t i = 0; i != blocks; ++i)
      {
      u32bit L = load_be<u32bit>(in, 0);
      u32bit R = load_be<u32bit>(in, 1);

      for(size_t j = 0; j != 32; ++j)
         {
         L += (((R << 4) ^ (R >> 5)) + R) ^ m_EK[2*j];
         R += (((L << 4) ^ (L >> 5)) + L) ^ m_EK[2*j+1];
         }

      store_be(out, L, R);

      in += BLOCK_SIZE;
      out += BLOCK_SIZE;
      }
   }

/*
* XTEA Decryption
*/
void XTEA::decrypt_n(const byte in[], byte out[], size_t blocks) const
   {
   while(blocks >= 4)
      {
      xtea_decrypt_4(in, out, &(this->m_EK[0]));
      in += 4 * BLOCK_SIZE;
      out += 4 * BLOCK_SIZE;
      blocks -= 4;
      }

   for(size_t i = 0; i != blocks; ++i)
      {
      u32bit L = load_be<u32bit>(in, 0);
      u32bit R = load_be<u32bit>(in, 1);

      for(size_t j = 0; j != 32; ++j)
         {
         R -= (((L << 4) ^ (L >> 5)) + L) ^ m_EK[63 - 2*j];
         L -= (((R << 4) ^ (R >> 5)) + R) ^ m_EK[62 - 2*j];
         }

      store_be(out, L, R);

      in += BLOCK_SIZE;
      out += BLOCK_SIZE;
      }
   }

/*
* XTEA Key Schedule
*/
void XTEA::key_schedule(const byte key[], size_t)
   {
   m_EK.resize(64);

   secure_vector<u32bit> UK(4);
   for(size_t i = 0; i != 4; ++i)
      UK[i] = load_be<u32bit>(key, i);

   u32bit D = 0;
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
