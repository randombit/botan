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
#include <botan/internal/sha2_32_f.h>
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
         aarch64_sha256_update(s0, s1, w0, &SHA256_K[r]);
         w0 = aarch64_sha256_expand_w(w0, w1, w2, w3);

         aarch64_sha256_update(s0, s1, w1, &SHA256_K[r + 4 * 1]);
         w1 = aarch64_sha256_expand_w(w1, w2, w3, w0);

         aarch64_sha256_update(s0, s1, w2, &SHA256_K[r + 4 * 2]);
         w2 = aarch64_sha256_expand_w(w2, w3, w0, w1);

         aarch64_sha256_update(s0, s1, w3, &SHA256_K[r + 4 * 3]);
         w3 = aarch64_sha256_expand_w(w3, w0, w1, w2);
      }

      aarch64_sha256_update(s0, s1, w0, &SHA256_K[4 * 12]);
      aarch64_sha256_update(s0, s1, w1, &SHA256_K[4 * 13]);
      aarch64_sha256_update(s0, s1, w2, &SHA256_K[4 * 14]);
      aarch64_sha256_update(s0, s1, w3, &SHA256_K[4 * 15]);

      s0 += s0_save;
      s1 += s1_save;

      input32 += 64 / 4;
      blocks--;
   }

   s0.store_le(&digest[0]);  // NOLINT(*-container-data-pointer)
   s1.store_le(&digest[4]);
}

}  // namespace Botan
