/*
* (C) 2023 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "test_rng.h"

#include <botan/hex.h>
#include <array>

#if defined(BOTAN_HAS_CTR_DRBG) && defined(BOTAN_HAS_AES)
   #include <botan/internal/ctr_drbg_nodf.h>
#endif

namespace Botan_Tests {

uint8_t Fixed_Output_RNG::random() {
   if(m_buf_pos >= m_buf.size()) {
      if(m_fallback.has_value()) {
         return m_fallback.value()->next_byte();
      } else {
         throw Test_Error("Fixed output RNG ran out of bytes, test bug?");
      }
   }

   const uint8_t out = m_buf[m_buf_pos];
   m_buf_pos += 1;
   return out;
}

Fixed_Output_RNG::Fixed_Output_RNG(const std::string& in_str) {
   std::vector<uint8_t> in = Botan::hex_decode(in_str);
   m_buf.insert(m_buf.end(), in.begin(), in.end());
}

Fixed_Output_RNG::Fixed_Output_RNG(RandomNumberGenerator& rng, size_t len) {
   std::vector<uint8_t> output;
   rng.random_vec(output, len);
   m_buf.insert(m_buf.end(), output.begin(), output.end());
}

#if defined(BOTAN_HAS_CTR_DRBG) && defined(BOTAN_HAS_AES)

std::unique_ptr<Botan::RandomNumberGenerator> make_pqc_kat_drbg(std::span<const uint8_t> seed) {
   auto drbg = Botan::CTR_DRBG_Without_DF::create("AES-256");
   drbg->initialize_with(seed);
   return drbg;
}

#endif

}  // namespace Botan_Tests
