/*
* SHA-256 using CPU instructions in ARMv8
*
* Contributed by Jeffrey Walton. Based on public domain code by
* Johannes Schneiders, Skip Hovsmith and Barry O'Rourke.
*
* Further changes (C) 2020,2025 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/sha2_32.h>

#include <botan/internal/isa_extn.h>
#include <botan/internal/simd_4x32.h>
#include <botan/internal/stack_scrubbing.h>
#include <arm_neon.h>

namespace Botan {

namespace {

inline BOTAN_FN_ISA_SHA2 SIMD_4x32 aarch64_sha256_expand_w(const SIMD_4x32 w0,
                                                           const SIMD_4x32 w1,
                                                           const SIMD_4x32 w2,
                                                           const SIMD_4x32 w3) {
   return SIMD_4x32(vsha256su1q_u32(vsha256su0q_u32(w0.raw(), w1.raw()), w2.raw(), w3.raw()));
}

inline BOTAN_FN_ISA_SHA2 void aarch64_sha256_update(SIMD_4x32& s0,
                                                    SIMD_4x32& s1,
                                                    const SIMD_4x32 w,
                                                    const uint32_t K[4]) {
   auto w_k = w + SIMD_4x32::load_le(K);
   auto t = vsha256hq_u32(s0.raw(), s1.raw(), w_k.raw());
   s1 = SIMD_4x32(vsha256h2q_u32(s1.raw(), s0.raw(), w_k.raw()));
   s0 = SIMD_4x32(t);
}

}  // namespace

/*
* SHA-256 using CPU instructions in ARMv8
*/
//static
void BOTAN_FN_ISA_SHA2 BOTAN_SCRUB_STACK_AFTER_RETURN SHA_256::compress_digest_armv8(digest_type& digest,
                                                                                     std::span<const uint8_t> input8,
                                                                                     size_t blocks) {
   alignas(64) static const uint32_t K[] = {
      0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
      0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3, 0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
      0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
      0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
      0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13, 0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
      0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
      0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
      0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208, 0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
   };

   // Load initial values
   SIMD_4x32 s0 = SIMD_4x32::load_le(&digest[0]);  // NOLINT(*-container-data-pointer)
   SIMD_4x32 s1 = SIMD_4x32::load_le(&digest[4]);

   const uint32_t* input32 = reinterpret_cast<const uint32_t*>(input8.data());

   while(blocks > 0) {
      const auto s0_save = s0;
      const auto s1_save = s1;

      auto w0 = SIMD_4x32::load_be(input32);
      auto w1 = SIMD_4x32::load_be(input32 + 4);
      auto w2 = SIMD_4x32::load_be(input32 + 8);
      auto w3 = SIMD_4x32::load_be(input32 + 12);

      for(size_t r = 0; r != 48; r += 16) {
         aarch64_sha256_update(s0, s1, w0, &K[r]);
         w0 = aarch64_sha256_expand_w(w0, w1, w2, w3);

         aarch64_sha256_update(s0, s1, w1, &K[r + 4 * 1]);
         w1 = aarch64_sha256_expand_w(w1, w2, w3, w0);

         aarch64_sha256_update(s0, s1, w2, &K[r + 4 * 2]);
         w2 = aarch64_sha256_expand_w(w2, w3, w0, w1);

         aarch64_sha256_update(s0, s1, w3, &K[r + 4 * 3]);
         w3 = aarch64_sha256_expand_w(w3, w0, w1, w2);
      }

      aarch64_sha256_update(s0, s1, w0, &K[4 * 12]);
      aarch64_sha256_update(s0, s1, w1, &K[4 * 13]);
      aarch64_sha256_update(s0, s1, w2, &K[4 * 14]);
      aarch64_sha256_update(s0, s1, w3, &K[4 * 15]);

      s0 += s0_save;
      s1 += s1_save;

      input32 += 64 / 4;
      blocks--;
   }

   s0.store_le(&digest[0]);  // NOLINT(*-container-data-pointer)
   s1.store_le(&digest[4]);
}

}  // namespace Botan
