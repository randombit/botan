/*
* (C) 2023 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "test_rng.h"

#if defined(BOTAN_HAS_AES)
   #include <botan/internal/loadstor.h>
#endif

#include <array>

namespace Botan_Tests {

#if defined(BOTAN_HAS_AES)

void CTR_DRBG_AES256::clear() {
   const uint8_t zeros[32] = {0};
   m_cipher->set_key(zeros, 32);
   m_V0 = 0;
   m_V1 = 0;
}

void CTR_DRBG_AES256::fill_bytes_with_input(std::span<uint8_t> output, std::span<const uint8_t> input) {
   if(!input.empty()) {
      if(input.size() != 48) {
         throw Test_Error("CTR_DRBG(AES-256) assumes 48 byte input");
      }

      clear();
      update(input);
   }

   if(!output.empty()) {
      const size_t full_blocks = output.size() / 16;
      const size_t leftover_bytes = output.size() % 16;

      for(size_t i = 0; i != full_blocks; ++i) {
         incr_V_into(output.subspan(i * 16, 16));
      }

      m_cipher->encrypt_n(output.data(), output.data(), full_blocks);

      if(leftover_bytes > 0) {
         uint8_t block[16];
         incr_V_into(block);
         m_cipher->encrypt(block);
         Botan::copy_mem(output.subspan(full_blocks * 16).data(), block, leftover_bytes);
      }

      update({});
   }
}

CTR_DRBG_AES256::CTR_DRBG_AES256(std::span<const uint8_t> seed) {
   m_cipher = Botan::BlockCipher::create_or_throw("AES-256");
   add_entropy(seed);
}

void CTR_DRBG_AES256::incr_V_into(std::span<uint8_t> output) {
   BOTAN_ASSERT_NOMSG(output.size() == 16);

   m_V1 += 1;
   if(m_V1 == 0) {
      m_V0 += 1;
   }

   Botan::store_be<uint64_t>(output.data(), m_V0, m_V1);
}

void CTR_DRBG_AES256::update(std::span<const uint8_t> provided_data) {
   std::array<uint8_t, 3 * 16> temp = {0};

   std::span<uint8_t> t(temp);
   for(size_t i = 0; i != 3; ++i) {
      incr_V_into(t.subspan(16 * i, 16));
   }

   m_cipher->encrypt_n(temp.data(), temp.data(), 3);

   if(!provided_data.empty()) {
      BOTAN_ASSERT_NOMSG(provided_data.size() == temp.size());
      for(size_t i = 0; i != provided_data.size(); i++) {
         temp[i] ^= provided_data[i];
      }
   }

   m_cipher->set_key(temp.data(), 32);  // TODO: adapt after GH #3297

   m_V0 = Botan::load_be<uint64_t>(temp.data() + 32, 0);
   m_V1 = Botan::load_be<uint64_t>(temp.data() + 32, 1);
}

#endif

}  // namespace Botan_Tests
