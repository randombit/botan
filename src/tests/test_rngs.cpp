/*
* (C) 2023 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "test_rng.h"

#if defined(BOTAN_HAS_AES)
  #include <botan/internal/loadstor.h>
#endif

namespace Botan_Tests {

#if defined(BOTAN_HAS_AES)

void CTR_DRBG_AES256::clear()
   {
   const uint8_t zeros[32] = { 0 };
   m_cipher->set_key(zeros, 32);
   m_V0 = 0;
   m_V1 = 0;
   }

void CTR_DRBG_AES256::add_entropy(const uint8_t seed_material[], size_t len)
   {
   if(len != 48)
      throw Test_Error("CTR_DRBG(AES-256) assumes 48 byte input");

   clear();
   update(seed_material);
   }

void CTR_DRBG_AES256::randomize(uint8_t out[], size_t len)
   {
   const size_t full_blocks = len / 16;
   const size_t leftover_bytes = len % 16;

   for(size_t i = 0; i != full_blocks; ++i)
      incr_V_into(out + 16*i);

   m_cipher->encrypt_n(out, out, full_blocks);

   if(leftover_bytes > 0)
      {
      uint8_t block[16];
      incr_V_into(block);
      m_cipher->encrypt(block);
      Botan::copy_mem(out + full_blocks * 16, block, leftover_bytes);
      }

   update(nullptr);
   }

CTR_DRBG_AES256::CTR_DRBG_AES256(const std::vector<uint8_t>& seed)
   {
   m_cipher = Botan::BlockCipher::create_or_throw("AES-256");
   add_entropy(seed.data(), seed.size());
   }

void CTR_DRBG_AES256::incr_V_into(uint8_t output[16])
   {
   m_V1 += 1;
   if(m_V1 == 0)
      m_V0 += 1;

   Botan::store_be<uint64_t>(output, m_V0, m_V1);
   }

void CTR_DRBG_AES256::update(const uint8_t provided_data[])
   {
   uint8_t temp[3*16] = { 0 };

   for(size_t i = 0; i != 3; ++i)
      {
      incr_V_into(temp + 16*i);
      }

   m_cipher->encrypt_n(temp, temp, 3);

   if(provided_data)
      {
      for(size_t i = 0; i != 48; i++)
         temp[i] ^= provided_data[i];
      }

   m_cipher->set_key(temp, 32);

   m_V0 = Botan::load_be<uint64_t>(temp + 32, 0);
   m_V1 = Botan::load_be<uint64_t>(temp + 32, 1);
   }

#endif

}
