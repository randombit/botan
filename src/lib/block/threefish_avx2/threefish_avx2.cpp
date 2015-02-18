/*
* Threefish-512 using AVX2
* (C) 2013 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/block_utils.h>
#include <botan/threefish_avx2.h>
#include <botan/cpuid.h>
#include <immintrin.h>

namespace Botan {

BOTAN_REGISTER_BLOCK_CIPHER_NOARGS_IF(CPUID::has_avx2(), Threefish_512_AVX2, "Threefish-512", "avx2", 64);

namespace {

inline void interleave_epi64(__m256i& X0, __m256i& X1)
   {
   // interleave X0 and X1 qwords
   // (X0,X1,X2,X3),(X4,X5,X6,X7) -> (X0,X2,X4,X6),(X1,X3,X5,X7)

   const __m256i T0 = _mm256_unpacklo_epi64(X0, X1);
   const __m256i T1 = _mm256_unpackhi_epi64(X0, X1);

   X0 = _mm256_permute4x64_epi64(T0, _MM_SHUFFLE(3,1,2,0));
   X1 = _mm256_permute4x64_epi64(T1, _MM_SHUFFLE(3,1,2,0));
   }

inline void deinterleave_epi64(__m256i& X0, __m256i& X1)
   {
   const __m256i T0 = _mm256_permute4x64_epi64(X0, _MM_SHUFFLE(3,1,2,0));
   const __m256i T1 = _mm256_permute4x64_epi64(X1, _MM_SHUFFLE(3,1,2,0));

   X0 = _mm256_unpacklo_epi64(T0, T1);
   X1 = _mm256_unpackhi_epi64(T0, T1);
   }

}

void Threefish_512_AVX2::encrypt_n(const byte in[], byte out[], size_t blocks) const
   {
   const u64bit* K = &get_K()[0];
   const u64bit* T_64 = &get_T()[0];

   const __m256i ROTATE_1 = _mm256_set_epi64x(37,19,36,46);
   const __m256i ROTATE_2 = _mm256_set_epi64x(42,14,27,33);
   const __m256i ROTATE_3 = _mm256_set_epi64x(39,36,49,17);
   const __m256i ROTATE_4 = _mm256_set_epi64x(56,54, 9,44);
   const __m256i ROTATE_5 = _mm256_set_epi64x(24,34,30,39);
   const __m256i ROTATE_6 = _mm256_set_epi64x(17,10,50,13);
   const __m256i ROTATE_7 = _mm256_set_epi64x(43,39,29,25);
   const __m256i ROTATE_8 = _mm256_set_epi64x(22,56,35, 8);

#define THREEFISH_ROUND(X0, X1, SHL)                                                \
   do {                                                                             \
      const __m256i SHR = _mm256_sub_epi64(_mm256_set1_epi64x(64), SHL);            \
      X0 = _mm256_add_epi64(X0, X1);                                                \
      X1 = _mm256_or_si256(_mm256_sllv_epi64(X1, SHL), _mm256_srlv_epi64(X1, SHR)); \
      X1 = _mm256_xor_si256(X1, X0);                                                \
      X0 = _mm256_permute4x64_epi64(X0, _MM_SHUFFLE(0, 3, 2, 1));                   \
      X1 = _mm256_permute4x64_epi64(X1, _MM_SHUFFLE(1, 2, 3, 0));                   \
   } while(0)

#define THREEFISH_ROUND_2(X0, X1, X2, X3, SHL)                           \
   do {                                                                             \
      const __m256i SHR = _mm256_sub_epi64(_mm256_set1_epi64x(64), SHL);            \
      X0 = _mm256_add_epi64(X0, X1);                                                \
      X2 = _mm256_add_epi64(X2, X3);                                                \
      X1 = _mm256_or_si256(_mm256_sllv_epi64(X1, SHL), _mm256_srlv_epi64(X1, SHR)); \
      X3 = _mm256_or_si256(_mm256_sllv_epi64(X3, SHL), _mm256_srlv_epi64(X3, SHR)); \
      X1 = _mm256_xor_si256(X1, X0);                                                \
      X3 = _mm256_xor_si256(X3, X2);                                                \
      X0 = _mm256_permute4x64_epi64(X0, _MM_SHUFFLE(0, 3, 2, 1));                   \
      X2 = _mm256_permute4x64_epi64(X2, _MM_SHUFFLE(0, 3, 2, 1));                   \
      X1 = _mm256_permute4x64_epi64(X1, _MM_SHUFFLE(1, 2, 3, 0));                   \
      X3 = _mm256_permute4x64_epi64(X3, _MM_SHUFFLE(1, 2, 3, 0));                   \
   } while(0)

#define THREEFISH_INJECT_KEY(X0, X1, R, K0, K1, T0I, T1I)                        \
   do {                                                                          \
      const __m256i T0 = _mm256_permute4x64_epi64(T, _MM_SHUFFLE(T0I, 0, 0, 0)); \
      const __m256i T1 = _mm256_permute4x64_epi64(T, _MM_SHUFFLE(0, T1I, 0, 0)); \
      X0 = _mm256_add_epi64(X0, K0);                                             \
      X1 = _mm256_add_epi64(X1, K1);                                             \
      X1 = _mm256_add_epi64(X1, R);                                              \
      X0 = _mm256_add_epi64(X0, T0);                                             \
      X1 = _mm256_add_epi64(X1, T1);                                             \
      R = _mm256_add_epi64(R, ONE);                                              \
   } while(0)

#define THREEFISH_INJECT_KEY_2(X0, X1, X2, X3, R, K0, K1, T0I, T1I)              \
   do {                                                                          \
      const __m256i T0 = _mm256_permute4x64_epi64(T, _MM_SHUFFLE(T0I, 0, 0, 0)); \
      __m256i T1 = _mm256_permute4x64_epi64(T, _MM_SHUFFLE(0, T1I, 0, 0)); \
      X0 = _mm256_add_epi64(X0, K0);                                             \
      X2 = _mm256_add_epi64(X2, K0);                                             \
      X1 = _mm256_add_epi64(X1, K1);                                             \
      X3 = _mm256_add_epi64(X3, K1);                                             \
      T1 = _mm256_add_epi64(T1, R);                                              \
      X0 = _mm256_add_epi64(X0, T0);                                             \
      X2 = _mm256_add_epi64(X2, T0);                                             \
      X1 = _mm256_add_epi64(X1, T1);                                             \
      X3 = _mm256_add_epi64(X3, T1);                                             \
      R = _mm256_add_epi64(R, ONE);                                              \
   } while(0)

#define THREEFISH_ENC_8_ROUNDS(X0, X1, R, K1, K2, K3, T0, T1, T2)        \
   do {                                                        \
      THREEFISH_ROUND(X0, X1, ROTATE_1);                       \
      THREEFISH_ROUND(X0, X1, ROTATE_2);                       \
      THREEFISH_ROUND(X0, X1, ROTATE_3);                       \
      THREEFISH_ROUND(X0, X1, ROTATE_4);                       \
      THREEFISH_INJECT_KEY(X0, X1, R, K1, K2, T0, T1);         \
                                                               \
      THREEFISH_ROUND(X0, X1, ROTATE_5);                       \
      THREEFISH_ROUND(X0, X1, ROTATE_6);                       \
      THREEFISH_ROUND(X0, X1, ROTATE_7);                       \
      THREEFISH_ROUND(X0, X1, ROTATE_8);                       \
      THREEFISH_INJECT_KEY(X0, X1, R, K2, K3, T2, T0);         \
   } while(0)

#define THREEFISH_ENC_2_8_ROUNDS(X0, X1, X2, X3, R, K1, K2, K3, T0, T1, T2) \
   do {                                                                  \
      THREEFISH_ROUND_2(X0, X1, X2, X3, ROTATE_1);                       \
      THREEFISH_ROUND_2(X0, X1, X2, X3, ROTATE_2);                       \
      THREEFISH_ROUND_2(X0, X1, X2, X3, ROTATE_3);                       \
      THREEFISH_ROUND_2(X0, X1, X2, X3, ROTATE_4);                       \
      THREEFISH_INJECT_KEY_2(X0, X1, X2, X3, R, K1, K2, T0, T1);         \
                                                                         \
      THREEFISH_ROUND_2(X0, X1, X2, X3, ROTATE_5);                       \
      THREEFISH_ROUND_2(X0, X1, X2, X3, ROTATE_6);                       \
      THREEFISH_ROUND_2(X0, X1, X2, X3, ROTATE_7);                       \
      THREEFISH_ROUND_2(X0, X1, X2, X3, ROTATE_8);                       \
      THREEFISH_INJECT_KEY_2(X0, X1, X2, X3, R, K2, K3, T2, T0);         \
   } while(0)

   /*
   v1.0 key schedule: 9 ymm registers (only need 2 or 3)
   (0,1,2,3),(4,5,6,7) [8]
   then mutating with vpermq
   */
   const __m256i K0 = _mm256_set_epi64x(K[6], K[4], K[2], K[0]);
   const __m256i K1 = _mm256_set_epi64x(K[7], K[5], K[3], K[1]);
   const __m256i K2 = _mm256_set_epi64x(K[8], K[6], K[4], K[2]);
   const __m256i K3 = _mm256_set_epi64x(K[0], K[7], K[5], K[3]);
   const __m256i K4 = _mm256_set_epi64x(K[1], K[8], K[6], K[4]);
   const __m256i K5 = _mm256_set_epi64x(K[2], K[0], K[7], K[5]);
   const __m256i K6 = _mm256_set_epi64x(K[3], K[1], K[8], K[6]);
   const __m256i K7 = _mm256_set_epi64x(K[4], K[2], K[0], K[7]);
   const __m256i K8 = _mm256_set_epi64x(K[5], K[3], K[1], K[8]);

   const __m256i ONE = _mm256_set_epi64x(1, 0, 0, 0);

   const __m256i* in_mm = reinterpret_cast<const __m256i*>(in);
   __m256i* out_mm = reinterpret_cast<__m256i*>(out);

   while(blocks >= 2)
      {
      __m256i X0 = _mm256_loadu_si256(in_mm++);
      __m256i X1 = _mm256_loadu_si256(in_mm++);
      __m256i X2 = _mm256_loadu_si256(in_mm++);
      __m256i X3 = _mm256_loadu_si256(in_mm++);

      const __m256i T = _mm256_set_epi64x(T_64[0], T_64[1], T_64[2], 0);

      __m256i R = _mm256_set_epi64x(0, 0, 0, 0);

      interleave_epi64(X0, X1);
      interleave_epi64(X2, X3);

      THREEFISH_INJECT_KEY_2(X0, X1, X2, X3, R, K0, K1, 2, 3);

      THREEFISH_ENC_2_8_ROUNDS(X0, X1, X2, X3, R, K1,K2,K3, 1, 2, 3);
      THREEFISH_ENC_2_8_ROUNDS(X0, X1, X2, X3, R, K3,K4,K5, 2, 3, 1);
      THREEFISH_ENC_2_8_ROUNDS(X0, X1, X2, X3, R, K5,K6,K7, 3, 1, 2);

      THREEFISH_ENC_2_8_ROUNDS(X0, X1, X2, X3, R, K7,K8,K0, 1, 2, 3);
      THREEFISH_ENC_2_8_ROUNDS(X0, X1, X2, X3, R, K0,K1,K2, 2, 3, 1);
      THREEFISH_ENC_2_8_ROUNDS(X0, X1, X2, X3, R, K2,K3,K4, 3, 1, 2);

      THREEFISH_ENC_2_8_ROUNDS(X0, X1, X2, X3, R, K4,K5,K6, 1, 2, 3);
      THREEFISH_ENC_2_8_ROUNDS(X0, X1, X2, X3, R, K6,K7,K8, 2, 3, 1);
      THREEFISH_ENC_2_8_ROUNDS(X0, X1, X2, X3, R, K8,K0,K1, 3, 1, 2);

      deinterleave_epi64(X0, X1);
      deinterleave_epi64(X2, X3);

      _mm256_storeu_si256(out_mm++, X0);
      _mm256_storeu_si256(out_mm++, X1);
      _mm256_storeu_si256(out_mm++, X2);
      _mm256_storeu_si256(out_mm++, X3);

      blocks -= 2;
      }

   for(size_t i = 0; i != blocks; ++i)
      {
      __m256i X0 = _mm256_loadu_si256(in_mm++);
      __m256i X1 = _mm256_loadu_si256(in_mm++);

      const __m256i T = _mm256_set_epi64x(T_64[0], T_64[1], T_64[2], 0);

      __m256i R = _mm256_set_epi64x(0, 0, 0, 0);

      interleave_epi64(X0, X1);

      THREEFISH_INJECT_KEY(X0, X1, R, K0, K1, 2, 3);

      THREEFISH_ENC_8_ROUNDS(X0, X1, R, K1,K2,K3, 1, 2, 3);
      THREEFISH_ENC_8_ROUNDS(X0, X1, R, K3,K4,K5, 2, 3, 1);
      THREEFISH_ENC_8_ROUNDS(X0, X1, R, K5,K6,K7, 3, 1, 2);

      THREEFISH_ENC_8_ROUNDS(X0, X1, R, K7,K8,K0, 1, 2, 3);
      THREEFISH_ENC_8_ROUNDS(X0, X1, R, K0,K1,K2, 2, 3, 1);
      THREEFISH_ENC_8_ROUNDS(X0, X1, R, K2,K3,K4, 3, 1, 2);

      THREEFISH_ENC_8_ROUNDS(X0, X1, R, K4,K5,K6, 1, 2, 3);
      THREEFISH_ENC_8_ROUNDS(X0, X1, R, K6,K7,K8, 2, 3, 1);
      THREEFISH_ENC_8_ROUNDS(X0, X1, R, K8,K0,K1, 3, 1, 2);

      deinterleave_epi64(X0, X1);

      _mm256_storeu_si256(out_mm++, X0);
      _mm256_storeu_si256(out_mm++, X1);
      }

#undef THREEFISH_ENC_8_ROUNDS
#undef THREEFISH_ROUND
#undef THREEFISH_INJECT_KEY
#undef THREEFISH_ENC_2_8_ROUNDS
#undef THREEFISH_ROUND_2
#undef THREEFISH_INJECT_KEY_2
   }

void Threefish_512_AVX2::decrypt_n(const byte in[], byte out[], size_t blocks) const
   {
   const u64bit* K = &get_K()[0];
   const u64bit* T_64 = &get_T()[0];

   const __m256i ROTATE_1 = _mm256_set_epi64x(37,19,36,46);
   const __m256i ROTATE_2 = _mm256_set_epi64x(42,14,27,33);
   const __m256i ROTATE_3 = _mm256_set_epi64x(39,36,49,17);
   const __m256i ROTATE_4 = _mm256_set_epi64x(56,54, 9,44);
   const __m256i ROTATE_5 = _mm256_set_epi64x(24,34,30,39);
   const __m256i ROTATE_6 = _mm256_set_epi64x(17,10,50,13);
   const __m256i ROTATE_7 = _mm256_set_epi64x(43,39,29,25);
   const __m256i ROTATE_8 = _mm256_set_epi64x(22,56,35, 8);

#define THREEFISH_ROUND(X0, X1, SHR)                                                \
   do {                                                                             \
      const __m256i SHL = _mm256_sub_epi64(_mm256_set1_epi64x(64), SHR);            \
      X0 = _mm256_permute4x64_epi64(X0, _MM_SHUFFLE(2, 1, 0, 3));                   \
      X1 = _mm256_permute4x64_epi64(X1, _MM_SHUFFLE(1, 2, 3, 0));                   \
      X1 = _mm256_xor_si256(X1, X0);                                                \
      X1 = _mm256_or_si256(_mm256_sllv_epi64(X1, SHL), _mm256_srlv_epi64(X1, SHR)); \
      X0 = _mm256_sub_epi64(X0, X1);                                                \
   } while(0)

#define THREEFISH_INJECT_KEY(X0, X1, R, K0, K1, T0I, T1I)                \
   do {                                                                          \
      const __m256i T0 = _mm256_permute4x64_epi64(T, _MM_SHUFFLE(T0I, 0, 0, 0)); \
      const __m256i T1 = _mm256_permute4x64_epi64(T, _MM_SHUFFLE(0, T1I, 0, 0)); \
      X0 = _mm256_sub_epi64(X0, K0);                                             \
      X1 = _mm256_sub_epi64(X1, K1);                                             \
      X1 = _mm256_sub_epi64(X1, R);                                              \
      R = _mm256_sub_epi64(R, ONE);                                              \
      X0 = _mm256_sub_epi64(X0, T0);                                             \
      X1 = _mm256_sub_epi64(X1, T1);                                             \
   } while(0)

#define THREEFISH_DEC_8_ROUNDS(X0, X1, R, K1, K2, K3, T0, T1, T2)   \
   do {                                                      \
      THREEFISH_INJECT_KEY(X0, X1, R, K2, K3, T2, T0);       \
      THREEFISH_ROUND(X0, X1, ROTATE_8);                     \
      THREEFISH_ROUND(X0, X1, ROTATE_7);                     \
      THREEFISH_ROUND(X0, X1, ROTATE_6);                     \
      THREEFISH_ROUND(X0, X1, ROTATE_5);                     \
                                                             \
      THREEFISH_INJECT_KEY(X0, X1, R, K1, K2, T0, T1);       \
      THREEFISH_ROUND(X0, X1, ROTATE_4);                     \
      THREEFISH_ROUND(X0, X1, ROTATE_3);                     \
      THREEFISH_ROUND(X0, X1, ROTATE_2);                     \
      THREEFISH_ROUND(X0, X1, ROTATE_1);                     \
   } while(0)

   /*
   v1.0 key schedule: 9 ymm registers (only need 2 or 3)
   (0,1,2,3),(4,5,6,7) [8]
   then mutating with vpermq
   */
   const __m256i K0 = _mm256_set_epi64x(K[6], K[4], K[2], K[0]);
   const __m256i K1 = _mm256_set_epi64x(K[7], K[5], K[3], K[1]);
   const __m256i K2 = _mm256_set_epi64x(K[8], K[6], K[4], K[2]);
   const __m256i K3 = _mm256_set_epi64x(K[0], K[7], K[5], K[3]);
   const __m256i K4 = _mm256_set_epi64x(K[1], K[8], K[6], K[4]);
   const __m256i K5 = _mm256_set_epi64x(K[2], K[0], K[7], K[5]);
   const __m256i K6 = _mm256_set_epi64x(K[3], K[1], K[8], K[6]);
   const __m256i K7 = _mm256_set_epi64x(K[4], K[2], K[0], K[7]);
   const __m256i K8 = _mm256_set_epi64x(K[5], K[3], K[1], K[8]);

   const __m256i ONE = _mm256_set_epi64x(1, 0, 0, 0);

   const __m256i* in_mm = reinterpret_cast<const __m256i*>(in);
   __m256i* out_mm = reinterpret_cast<__m256i*>(out);

   for(size_t i = 0; i != blocks; ++i)
      {
      __m256i X0 = _mm256_loadu_si256(in_mm++);
      __m256i X1 = _mm256_loadu_si256(in_mm++);

      const __m256i T = _mm256_set_epi64x(T_64[0], T_64[1], T_64[2], 0);

      __m256i R = _mm256_set_epi64x(18, 0, 0, 0);

      interleave_epi64(X0, X1);

      THREEFISH_DEC_8_ROUNDS(X0, X1, R, K8,K0,K1, 3, 1, 2);
      THREEFISH_DEC_8_ROUNDS(X0, X1, R, K6,K7,K8, 2, 3, 1);
      THREEFISH_DEC_8_ROUNDS(X0, X1, R, K4,K5,K6, 1, 2, 3);
      THREEFISH_DEC_8_ROUNDS(X0, X1, R, K2,K3,K4, 3, 1, 2);
      THREEFISH_DEC_8_ROUNDS(X0, X1, R, K0,K1,K2, 2, 3, 1);
      THREEFISH_DEC_8_ROUNDS(X0, X1, R, K7,K8,K0, 1, 2, 3);
      THREEFISH_DEC_8_ROUNDS(X0, X1, R, K5,K6,K7, 3, 1, 2);
      THREEFISH_DEC_8_ROUNDS(X0, X1, R, K3,K4,K5, 2, 3, 1);
      THREEFISH_DEC_8_ROUNDS(X0, X1, R, K1,K2,K3, 1, 2, 3);

      THREEFISH_INJECT_KEY(X0, X1, R, K0, K1, 2, 3);

      deinterleave_epi64(X0, X1);

      _mm256_storeu_si256(out_mm++, X0);
      _mm256_storeu_si256(out_mm++, X1);
      }

#undef THREEFISH_DEC_8_ROUNDS
#undef THREEFISH_ROUND
#undef THREEFISH_INJECT_KEY
#undef THREEFISH_DEC_2_8_ROUNDS
#undef THREEFISH_ROUND_2
#undef THREEFISH_INJECT_KEY_2
   }

}
