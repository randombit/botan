/*
* (C) 2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/hash_engine_sha2_32.h>

#include <botan/assert.h>
#include <botan/internal/isa_extn.h>
#include <botan/internal/sha2_32_f.h>
#include <arm_neon.h>

namespace Botan {

namespace {

constexpr size_t SHA256_STREAMS = SHA2_32_ARMV8_STREAMS;

/**
* Load or store 4 state words of one lane, which are spaced a lane
* stride apart. Used only once per call, outside the block loop.
*/
BOTAN_FN_ISA_SHA2 BOTAN_FORCE_INLINE uint32x4_t sha256_gather4(const uint32_t* p, size_t stride) {
   uint32x4_t v = vdupq_n_u32(0);
   v = vld1q_lane_u32(p, v, 0);
   v = vld1q_lane_u32(p + stride, v, 1);
   v = vld1q_lane_u32(p + 2 * stride, v, 2);
   v = vld1q_lane_u32(p + 3 * stride, v, 3);
   return v;
}

BOTAN_FN_ISA_SHA2 BOTAN_FORCE_INLINE void sha256_scatter4(uint32_t* p, size_t stride, uint32x4_t v) {
   vst1q_lane_u32(p, v, 0);
   vst1q_lane_u32(p + stride, v, 1);
   vst1q_lane_u32(p + 2 * stride, v, 2);
   vst1q_lane_u32(p + 3 * stride, v, 3);
}

BOTAN_FN_ISA_SHA2 BOTAN_FORCE_INLINE uint32x4_t sha256_expand_w(uint32x4_t w0,
                                                                uint32x4_t w1,
                                                                uint32x4_t w2,
                                                                uint32x4_t w3) {
   return vsha256su1q_u32(vsha256su0q_u32(w0, w1), w2, w3);
}

BOTAN_FN_ISA_SHA2 BOTAN_FORCE_INLINE void sha256_update(uint32x4_t& s0, uint32x4_t& s1, uint32x4_t w, uint32x4_t k) {
   const uint32x4_t w_k = vaddq_u32(w, k);
   const uint32x4_t t = vsha256hq_u32(s0, s1, w_k);
   s1 = vsha256h2q_u32(s1, s0, w_k);
   s0 = t;
}

BOTAN_FN_ISA_SHA2 BOTAN_FORCE_INLINE uint32x4_t sha256_load_w(const uint8_t* const* blocks,
                                                              size_t n,
                                                              size_t l,
                                                              size_t off) {
   return vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(blocks[l] + 64 * n + off)));
}

}  // namespace

BOTAN_FN_ISA_SHA2 void sha2_32_mb_compress_armv8(uint8_t* states, const uint8_t* const* blocks, size_t nblocks) {
   uint32_t* states32 = reinterpret_cast<uint32_t*>(states);

   // The state is stored word-major across the lanes; the running state
   // lives in S0/S1 across blocks, with a snapshot taken for the final add
   uint32x4_t S0[SHA256_STREAMS];
   uint32x4_t S1[SHA256_STREAMS];
   for(size_t l = 0; l != SHA256_STREAMS; ++l) {
      S0[l] = sha256_gather4(states32 + l, SHA256_STREAMS);
      S1[l] = sha256_gather4(states32 + 4 * SHA256_STREAMS + l, SHA256_STREAMS);
   }

   for(size_t n = 0; n != nblocks; ++n) {
      uint32x4_t W0[SHA256_STREAMS];
      uint32x4_t W1[SHA256_STREAMS];
      uint32x4_t W2[SHA256_STREAMS];
      uint32x4_t W3[SHA256_STREAMS];
      uint32x4_t I0[SHA256_STREAMS];
      uint32x4_t I1[SHA256_STREAMS];

      for(size_t l = 0; l != SHA256_STREAMS; ++l) {
         I0[l] = S0[l];
         I1[l] = S1[l];
         W0[l] = sha256_load_w(blocks, n, l, 0);
         W1[l] = sha256_load_w(blocks, n, l, 16);
         W2[l] = sha256_load_w(blocks, n, l, 32);
         W3[l] = sha256_load_w(blocks, n, l, 48);
      }

      for(size_t r = 0; r != 48; r += 16) {
         const uint32x4_t k0 = vld1q_u32(&SHA256_K[r]);
         for(size_t l = 0; l != SHA256_STREAMS; ++l) {
            sha256_update(S0[l], S1[l], W0[l], k0);
            W0[l] = sha256_expand_w(W0[l], W1[l], W2[l], W3[l]);
         }

         const uint32x4_t k1 = vld1q_u32(&SHA256_K[r + 4]);
         for(size_t l = 0; l != SHA256_STREAMS; ++l) {
            sha256_update(S0[l], S1[l], W1[l], k1);
            W1[l] = sha256_expand_w(W1[l], W2[l], W3[l], W0[l]);
         }

         const uint32x4_t k2 = vld1q_u32(&SHA256_K[r + 8]);
         for(size_t l = 0; l != SHA256_STREAMS; ++l) {
            sha256_update(S0[l], S1[l], W2[l], k2);
            W2[l] = sha256_expand_w(W2[l], W3[l], W0[l], W1[l]);
         }

         const uint32x4_t k3 = vld1q_u32(&SHA256_K[r + 12]);
         for(size_t l = 0; l != SHA256_STREAMS; ++l) {
            sha256_update(S0[l], S1[l], W3[l], k3);
            W3[l] = sha256_expand_w(W3[l], W0[l], W1[l], W2[l]);
         }
      }

      for(size_t g = 0; g != 4; ++g) {
         const uint32x4_t k = vld1q_u32(&SHA256_K[48 + 4 * g]);
         for(size_t l = 0; l != SHA256_STREAMS; ++l) {
            sha256_update(S0[l], S1[l], (g == 0) ? W0[l] : (g == 1) ? W1[l] : (g == 2) ? W2[l] : W3[l], k);
         }
      }

      for(size_t l = 0; l != SHA256_STREAMS; ++l) {
         S0[l] = vaddq_u32(S0[l], I0[l]);
         S1[l] = vaddq_u32(S1[l], I1[l]);
      }
   }

   for(size_t l = 0; l != SHA256_STREAMS; ++l) {
      sha256_scatter4(states32 + l, SHA256_STREAMS, S0[l]);
      sha256_scatter4(states32 + 4 * SHA256_STREAMS + l, SHA256_STREAMS, S1[l]);
   }
}

BOTAN_FN_ISA_SHA2 void sha2_32_mb_extract_armv8(const uint8_t* states, uint8_t* digests) {
   const uint32_t* states32 = reinterpret_cast<const uint32_t*>(states);

   for(size_t l = 0; l != SHA256_STREAMS; ++l) {
      const uint32x4_t lo = sha256_gather4(states32 + l, SHA256_STREAMS);
      const uint32x4_t hi = sha256_gather4(states32 + 4 * SHA256_STREAMS + l, SHA256_STREAMS);
      vst1q_u8(digests + 32 * l, vrev32q_u8(vreinterpretq_u8_u32(lo)));
      vst1q_u8(digests + 32 * l + 16, vrev32q_u8(vreinterpretq_u8_u32(hi)));
   }
}

}  // namespace Botan
