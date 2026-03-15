/*
* (C) 2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/sm3.h>

#include <botan/internal/isa_extn.h>
#include <arm_neon.h>

namespace Botan {

namespace {

// clang-format off
alignas(64) const uint32_t SM3_TJ[64] = {
   0x79CC4519, 0xF3988A32, 0xE7311465, 0xCE6228CB,
   0x9CC45197, 0x3988A32F, 0x7311465E, 0xE6228CBC,
   0xCC451979, 0x988A32F3, 0x311465E7, 0x6228CBCE,
   0xC451979C, 0x88A32F39, 0x11465E73, 0x228CBCE6,
   0x9D8A7A87, 0x3B14F50F, 0x7629EA1E, 0xEC53D43C,
   0xD8A7A879, 0xB14F50F3, 0x629EA1E7, 0xC53D43CE,
   0x8A7A879D, 0x14F50F3B, 0x29EA1E76, 0x53D43CEC,
   0xA7A879D8, 0x4F50F3B1, 0x9EA1E762, 0x3D43CEC5,
   0x7A879D8A, 0xF50F3B14, 0xEA1E7629, 0xD43CEC53,
   0xA879D8A7, 0x50F3B14F, 0xA1E7629E, 0x43CEC53D,
   0x879D8A7A, 0x0F3B14F5, 0x1E7629EA, 0x3CEC53D4,
   0x79D8A7A8, 0xF3B14F50, 0xE7629EA1, 0xCEC53D43,
   0x9D8A7A87, 0x3B14F50F, 0x7629EA1E, 0xEC53D43C,
   0xD8A7A879, 0xB14F50F3, 0x629EA1E7, 0xC53D43CE,
   0x8A7A879D, 0x14F50F3B, 0x29EA1E76, 0x53D43CEC,
   0xA7A879D8, 0x4F50F3B1, 0x9EA1E762, 0x3D43CEC5,
};

// clang-format on

// The SM3 instructions expect the state words in reverse order (why??)
BOTAN_FORCE_INLINE BOTAN_FN_ISA_SM3 uint32x4_t sm3_reverse_words(uint32x4_t v) {
   v = vrev64q_u32(v);
   return vextq_u32(v, v, 2);
}

BOTAN_FORCE_INLINE BOTAN_FN_ISA_SM3 uint32x4_t sm3_tj(size_t round) {
   // vsm3ss1q expects the constant to be in the top word
   return vsetq_lane_u32(SM3_TJ[round], vdupq_n_u32(0), 3);
}

BOTAN_FORCE_INLINE BOTAN_FN_ISA_SM3 void sm3_x4_r1(
   uint32x4_t& S0, uint32x4_t& S1, uint32x4_t w, uint32x4_t w_prime, size_t round) {
   auto t = vsm3ss1q_u32(S0, S1, sm3_tj(round));
   S0 = vsm3tt1aq_u32(S0, t, w_prime, 0);
   S1 = vsm3tt2aq_u32(S1, t, w, 0);

   t = vsm3ss1q_u32(S0, S1, sm3_tj(round + 1));
   S0 = vsm3tt1aq_u32(S0, t, w_prime, 1);
   S1 = vsm3tt2aq_u32(S1, t, w, 1);

   t = vsm3ss1q_u32(S0, S1, sm3_tj(round + 2));
   S0 = vsm3tt1aq_u32(S0, t, w_prime, 2);
   S1 = vsm3tt2aq_u32(S1, t, w, 2);

   t = vsm3ss1q_u32(S0, S1, sm3_tj(round + 3));
   S0 = vsm3tt1aq_u32(S0, t, w_prime, 3);
   S1 = vsm3tt2aq_u32(S1, t, w, 3);
}

BOTAN_FORCE_INLINE BOTAN_FN_ISA_SM3 void sm3_x4_r2(
   uint32x4_t& S0, uint32x4_t& S1, uint32x4_t w, uint32x4_t w_prime, size_t round) {
   auto t = vsm3ss1q_u32(S0, S1, sm3_tj(round));
   S0 = vsm3tt1bq_u32(S0, t, w_prime, 0);
   S1 = vsm3tt2bq_u32(S1, t, w, 0);

   t = vsm3ss1q_u32(S0, S1, sm3_tj(round + 1));
   S0 = vsm3tt1bq_u32(S0, t, w_prime, 1);
   S1 = vsm3tt2bq_u32(S1, t, w, 1);

   t = vsm3ss1q_u32(S0, S1, sm3_tj(round + 2));
   S0 = vsm3tt1bq_u32(S0, t, w_prime, 2);
   S1 = vsm3tt2bq_u32(S1, t, w, 2);

   t = vsm3ss1q_u32(S0, S1, sm3_tj(round + 3));
   S0 = vsm3tt1bq_u32(S0, t, w_prime, 3);
   S1 = vsm3tt2bq_u32(S1, t, w, 3);
}

BOTAN_FORCE_INLINE BOTAN_FN_ISA_SM3 void sm3_msg_expand(uint32x4_t& w0,
                                                        const uint32x4_t& w1,
                                                        const uint32x4_t& w2,
                                                        const uint32x4_t& w3) {
   const uint32x4_t w7_10 = vextq_u32(w1, w2, 3);
   const uint32x4_t w3_6 = vextq_u32(w0, w1, 3);
   const uint32x4_t w10_13 = vextq_u32(w2, w3, 2);

   uint32x4_t t = vsm3partw1q_u32(w0, w7_10, w3);
   w0 = vsm3partw2q_u32(t, w10_13, w3_6);
}

}  // namespace

void BOTAN_FN_ISA_SM3 SM3::compress_digest_armv8(digest_type& digest, std::span<const uint8_t> input, size_t blocks) {
   uint32x4_t S0 = sm3_reverse_words(vld1q_u32(&digest[0]));  // NOLINT(*-container-data-pointer)
   uint32x4_t S1 = sm3_reverse_words(vld1q_u32(&digest[4]));

   const uint8_t* data = input.data();

   while(blocks > 0) {
      const uint32x4_t S0_save = S0;
      const uint32x4_t S1_save = S1;

      uint32x4_t W0 = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(data)));
      uint32x4_t W1 = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(data + 16)));
      uint32x4_t W2 = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(data + 32)));
      uint32x4_t W3 = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(data + 48)));

      data += block_bytes;
      blocks -= 1;

      sm3_x4_r1(S0, S1, W0, veorq_u32(W0, W1), 0);
      sm3_msg_expand(W0, W1, W2, W3);

      sm3_x4_r1(S0, S1, W1, veorq_u32(W1, W2), 4);
      sm3_msg_expand(W1, W2, W3, W0);

      sm3_x4_r1(S0, S1, W2, veorq_u32(W2, W3), 8);
      sm3_msg_expand(W2, W3, W0, W1);

      sm3_x4_r1(S0, S1, W3, veorq_u32(W3, W0), 12);
      sm3_msg_expand(W3, W0, W1, W2);

      sm3_x4_r2(S0, S1, W0, veorq_u32(W0, W1), 16);
      sm3_msg_expand(W0, W1, W2, W3);

      sm3_x4_r2(S0, S1, W1, veorq_u32(W1, W2), 20);
      sm3_msg_expand(W1, W2, W3, W0);

      sm3_x4_r2(S0, S1, W2, veorq_u32(W2, W3), 24);
      sm3_msg_expand(W2, W3, W0, W1);

      sm3_x4_r2(S0, S1, W3, veorq_u32(W3, W0), 28);
      sm3_msg_expand(W3, W0, W1, W2);

      sm3_x4_r2(S0, S1, W0, veorq_u32(W0, W1), 32);
      sm3_msg_expand(W0, W1, W2, W3);

      sm3_x4_r2(S0, S1, W1, veorq_u32(W1, W2), 36);
      sm3_msg_expand(W1, W2, W3, W0);

      sm3_x4_r2(S0, S1, W2, veorq_u32(W2, W3), 40);
      sm3_msg_expand(W2, W3, W0, W1);

      sm3_x4_r2(S0, S1, W3, veorq_u32(W3, W0), 44);
      sm3_msg_expand(W3, W0, W1, W2);

      sm3_x4_r2(S0, S1, W0, veorq_u32(W0, W1), 48);
      sm3_msg_expand(W0, W1, W2, W3);

      sm3_x4_r2(S0, S1, W1, veorq_u32(W1, W2), 52);
      sm3_x4_r2(S0, S1, W2, veorq_u32(W2, W3), 56);
      sm3_x4_r2(S0, S1, W3, veorq_u32(W3, W0), 60);

      S0 = veorq_u32(S0, S0_save);
      S1 = veorq_u32(S1, S1_save);
   }

   vst1q_u32(&digest[0], sm3_reverse_words(S0));  // NOLINT(*-container-data-pointer)
   vst1q_u32(&digest[4], sm3_reverse_words(S1));
}

}  // namespace Botan
