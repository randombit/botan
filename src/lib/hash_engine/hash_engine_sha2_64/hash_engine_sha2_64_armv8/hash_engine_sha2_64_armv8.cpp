/*
* (C) 2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/hash_engine_sha2_64.h>

#include <botan/assert.h>
#include <botan/internal/isa_extn.h>
#include <botan/internal/sha2_64_f.h>
#include <arm_neon.h>

namespace Botan {

namespace {

constexpr size_t SHA512_STREAMS = SHA2_64_ARMV8_STREAMS;

/**
* Load or store one register pair of one lane, the two words spaced a
* lane stride apart. Used only once per call, outside the block loop.
*/
BOTAN_FN_ISA_SHA512 BOTAN_FORCE_INLINE uint64x2_t sha512_gather2(const uint64_t* p, size_t stride) {
   uint64x2_t v = vdupq_n_u64(0);
   v = vld1q_lane_u64(p, v, 0);
   v = vld1q_lane_u64(p + stride, v, 1);
   return v;
}

BOTAN_FN_ISA_SHA512 BOTAN_FORCE_INLINE void sha512_scatter2(uint64_t* p, size_t stride, uint64x2_t v) {
   vst1q_lane_u64(p, v, 0);
   vst1q_lane_u64(p + stride, v, 1);
}

/**
* One quad of two rounds for the stream held in S (as the four register
* pairs ab/cd/ef/gh), with the register roles rotating each step. J is
* the global step number 0..39; steps below 32 also expand the message
* schedule.
*/
template <size_t J>
BOTAN_FN_ISA_SHA512 BOTAN_FORCE_INLINE void sha512_step(uint64x2_t S[4], uint64x2_t M[8], uint64x2_t k) {
   constexpr size_t s0 = (4 - (J % 4)) % 4;
   constexpr size_t s1 = (s0 + 1) % 4;
   constexpr size_t s2 = (s0 + 2) % 4;
   constexpr size_t s3 = (s0 + 3) % 4;
   constexpr size_t m = J % 8;

   const uint64x2_t msg_k = vaddq_u64(M[m], k);
   const uint64x2_t t0 = vaddq_u64(vextq_u64(msg_k, msg_k, 1), S[s3]);
   const uint64x2_t t1 = vsha512hq_u64(t0, vextq_u64(S[s2], S[s3], 1), vextq_u64(S[s1], S[s2], 1));
   S[s3] = vsha512h2q_u64(t1, S[s1], S[s0]);
   S[s1] = vaddq_u64(S[s1], t1);

   if constexpr(J < 32) {
      M[m] = vsha512su1q_u64(
         vsha512su0q_u64(M[m], M[(m + 1) % 8]), M[(m + 7) % 8], vextq_u64(M[(m + 4) % 8], M[(m + 5) % 8], 1));
   }
}

template <size_t J>
BOTAN_FN_ISA_SHA512 BOTAN_FORCE_INLINE void sha512_steps(uint64x2_t S[SHA512_STREAMS][4],
                                                         uint64x2_t M[SHA512_STREAMS][8]) {
   const uint64x2_t k = vld1q_u64(&SHA512_K[2 * J]);
   for(size_t l = 0; l != SHA512_STREAMS; ++l) {
      sha512_step<J>(S[l], M[l], k);
   }
}

BOTAN_FN_ISA_SHA512 BOTAN_FORCE_INLINE uint64x2_t sha512_load_w(const uint8_t* const* blocks,
                                                                size_t n,
                                                                size_t l,
                                                                size_t off) {
   return vreinterpretq_u64_u8(vrev64q_u8(vld1q_u8(blocks[l] + 128 * n + off)));
}

template <size_t J0>
BOTAN_FN_ISA_SHA512 BOTAN_FORCE_INLINE void sha512_step_group(uint64x2_t S[SHA512_STREAMS][4],
                                                              uint64x2_t M[SHA512_STREAMS][8]) {
   sha512_steps<J0 + 0>(S, M);
   sha512_steps<J0 + 1>(S, M);
   sha512_steps<J0 + 2>(S, M);
   sha512_steps<J0 + 3>(S, M);
   sha512_steps<J0 + 4>(S, M);
   sha512_steps<J0 + 5>(S, M);
   sha512_steps<J0 + 6>(S, M);
   sha512_steps<J0 + 7>(S, M);
}

}  // namespace

BOTAN_FN_ISA_SHA512 void sha2_64_mb_compress_armv8(uint8_t* states, const uint8_t* const* blocks, size_t nblocks) {
   uint64_t* states64 = reinterpret_cast<uint64_t*>(states);

   // The state is stored word-major across the lanes
   uint64x2_t st[SHA512_STREAMS][4];
   for(size_t l = 0; l != SHA512_STREAMS; ++l) {
      for(size_t p = 0; p != 4; ++p) {
         st[l][p] = sha512_gather2(states64 + 2 * p * SHA512_STREAMS + l, SHA512_STREAMS);
      }
   }

   for(size_t n = 0; n != nblocks; ++n) {
      uint64x2_t S[SHA512_STREAMS][4];
      uint64x2_t M[SHA512_STREAMS][8];

      for(size_t l = 0; l != SHA512_STREAMS; ++l) {
         for(size_t p = 0; p != 4; ++p) {
            S[l][p] = st[l][p];
         }
         for(size_t w = 0; w != 8; ++w) {
            M[l][w] = sha512_load_w(blocks, n, l, 16 * w);
         }
      }

      sha512_step_group<0>(S, M);
      sha512_step_group<8>(S, M);
      sha512_step_group<16>(S, M);
      sha512_step_group<24>(S, M);
      sha512_step_group<32>(S, M);

      for(size_t l = 0; l != SHA512_STREAMS; ++l) {
         for(size_t p = 0; p != 4; ++p) {
            st[l][p] = vaddq_u64(st[l][p], S[l][p]);
         }
      }
   }

   for(size_t l = 0; l != SHA512_STREAMS; ++l) {
      for(size_t p = 0; p != 4; ++p) {
         sha512_scatter2(states64 + 2 * p * SHA512_STREAMS + l, SHA512_STREAMS, st[l][p]);
      }
   }
}

BOTAN_FN_ISA_SHA512 void sha2_64_mb_extract_armv8(const uint8_t* states, uint8_t* digests) {
   const uint64_t* states64 = reinterpret_cast<const uint64_t*>(states);

   for(size_t l = 0; l != SHA512_STREAMS; ++l) {
      for(size_t p = 0; p != 4; ++p) {
         const uint64x2_t v = sha512_gather2(states64 + 2 * p * SHA512_STREAMS + l, SHA512_STREAMS);
         vst1q_u8(digests + 64 * l + 16 * p, vrev64q_u8(vreinterpretq_u8_u64(v)));
      }
   }
}

}  // namespace Botan
