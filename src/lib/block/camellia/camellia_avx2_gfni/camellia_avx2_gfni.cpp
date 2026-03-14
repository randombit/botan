/*
* (C) 2025,2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/camellia.h>

#include <botan/mem_ops.h>
#include <botan/internal/simd_4x64.h>
#include <botan/internal/simd_avx2_gfni.h>

namespace Botan {

namespace Camellia_AVX2_GFNI {

/*
* This follows exactly the approach used in the AVX-512+GFNI implementation
* with only minor complications due to missing rotate and masked operations.
*/

namespace {

constexpr uint64_t pre123_a = gfni_matrix(R"(
   1 1 1 0 1 1 0 1
   0 0 1 1 0 0 1 0
   1 1 0 1 0 0 0 0
   1 0 1 1 0 0 1 1
   0 0 0 0 1 1 0 0
   1 0 1 0 0 1 0 0
   0 0 1 0 1 1 0 0
   1 0 0 0 0 1 1 0)");

constexpr uint64_t pre4_a = gfni_matrix(R"(
   1 1 0 1 1 0 1 1
   0 1 1 0 0 1 0 0
   1 0 1 0 0 0 0 1
   0 1 1 0 0 1 1 1
   0 0 0 1 1 0 0 0
   0 1 0 0 1 0 0 1
   0 1 0 1 1 0 0 0
   0 0 0 0 1 1 0 1)");

constexpr uint8_t pre_c = 0b01000101;

constexpr uint64_t post2_a = gfni_matrix(R"(
   0 0 0 1 1 1 0 0
   0 0 0 0 0 0 0 1
   0 1 1 0 0 1 1 0
   1 0 1 1 1 1 1 0
   0 0 0 1 1 0 1 1
   1 0 0 0 1 1 1 0
   0 1 0 1 1 1 1 0
   0 1 1 1 1 1 1 1)");

constexpr uint64_t post3_a = gfni_matrix(R"(
   0 1 1 0 0 1 1 0
   1 0 1 1 1 1 1 0
   0 0 0 1 1 0 1 1
   1 0 0 0 1 1 1 0
   0 1 0 1 1 1 1 0
   0 1 1 1 1 1 1 1
   0 0 0 1 1 1 0 0
   0 0 0 0 0 0 0 1)");

constexpr uint64_t post14_a = gfni_matrix(R"(
   0 0 0 0 0 0 0 1
   0 1 1 0 0 1 1 0
   1 0 1 1 1 1 1 0
   0 0 0 1 1 0 1 1
   1 0 0 0 1 1 1 0
   0 1 0 1 1 1 1 0
   0 1 1 1 1 1 1 1
   0 0 0 1 1 1 0 0)");

// NOLINTBEGIN(portability-simd-intrinsics)

BOTAN_FORCE_INLINE BOTAN_FN_ISA_AVX2_GFNI SIMD_4x64 camellia_f(SIMD_4x64 x) {
   const __m256i xr = x.raw();

   // Compute S1(x), S2(x), S3(x), S4(x) for all bytes
   const auto y123 = _mm256_gf2p8affine_epi64_epi8(xr, _mm256_set1_epi64x(pre123_a), pre_c);
   const auto y4 = _mm256_gf2p8affine_epi64_epi8(xr, _mm256_set1_epi64x(pre4_a), pre_c);

   const auto s1 = _mm256_gf2p8affineinv_epi64_epi8(y123, _mm256_set1_epi64x(post14_a), 0x6E);
   const auto s2 = _mm256_gf2p8affineinv_epi64_epi8(y123, _mm256_set1_epi64x(post2_a), 0xDC);
   const auto s3 = _mm256_gf2p8affineinv_epi64_epi8(y123, _mm256_set1_epi64x(post3_a), 0x37);
   const auto s4 = _mm256_gf2p8affineinv_epi64_epi8(y4, _mm256_set1_epi64x(post14_a), 0x6E);

   // Blend to find correct S(x) for each byte position

   const auto mask_s2 = _mm256_set1_epi64x(0x00FF0000FF000000);
   const auto mask_s3 = _mm256_set1_epi64x(0x0000FF0000FF0000);
   const auto mask_s4 = _mm256_set1_epi64x(0x000000FF0000FF00);

   auto sx = s1;
   sx = _mm256_blendv_epi8(sx, s2, mask_s2);
   sx = _mm256_blendv_epi8(sx, s3, mask_s3);
   sx = _mm256_blendv_epi8(sx, s4, mask_s4);

   // Linear mixing layer
   const auto P1 = _mm256_set_epi64x(0x0808080908080809, 0x0000000100000001, 0x0808080908080809, 0x0000000100000001);
   const auto P2 = _mm256_set_epi64x(0x09090A0A09090A0A, 0x0101020201010202, 0x09090A0A09090A0A, 0x0101020201010202);
   const auto P3 = _mm256_set_epi64x(0x0A0B0B0B0A0B0B0B, 0x0203030302030303, 0x0A0B0B0B0A0B0B0B, 0x0203030302030303);
   const auto P4 = _mm256_set_epi64x(0x0C0C0D0C0E0D0C0C, 0x0404050406050404, 0x0C0C0D0C0E0D0C0C, 0x0404050406050404);
   const auto P5 = _mm256_set_epi64x(0x0D0E0E0D0F0E0D0F, 0x0506060507060507, 0x0D0E0E0D0F0E0D0F, 0x0506060507060507);
   const auto P6 = _mm256_set_epi64x(0x0F0F0F0EFFFFFFFF, 0x07070706FFFFFFFF, 0x0F0F0F0EFFFFFFFF, 0x07070706FFFFFFFF);

   const auto t1 = SIMD_4x64(_mm256_shuffle_epi8(sx, P1));
   const auto t2 = SIMD_4x64(_mm256_shuffle_epi8(sx, P2));
   const auto t3 = SIMD_4x64(_mm256_shuffle_epi8(sx, P3));
   const auto t4 = SIMD_4x64(_mm256_shuffle_epi8(sx, P4));
   const auto t5 = SIMD_4x64(_mm256_shuffle_epi8(sx, P5));
   const auto t6 = SIMD_4x64(_mm256_shuffle_epi8(sx, P6));

   return (t1 ^ t2 ^ t3 ^ t4 ^ t5 ^ t6);
}

BOTAN_FORCE_INLINE BOTAN_FN_ISA_AVX2 void load_and_deinterleave(const uint8_t in[], SIMD_4x64& L, SIMD_4x64& R) {
   auto A = SIMD_4x64::load_be(in);
   auto B = SIMD_4x64::load_be(in + 32);

   auto Ap = _mm256_permute4x64_epi64(A.raw(), 0b11'01'10'00);  // [L[0], L[1], R[0], R[1]]
   auto Bp = _mm256_permute4x64_epi64(B.raw(), 0b11'01'10'00);  // [L[2], L[3], R[2], R[3]]

   L = SIMD_4x64(_mm256_permute2x128_si256(Ap, Bp, 0x20));  // [L[0], L[1], L[2], L[3]]
   R = SIMD_4x64(_mm256_permute2x128_si256(Ap, Bp, 0x31));  // [R[0], R[1], R[2], R[3]]
}

BOTAN_FORCE_INLINE BOTAN_FN_ISA_AVX2 void interleave_and_store(uint8_t out[], SIMD_4x64 L, SIMD_4x64 R) {
   auto T1 = _mm256_permute2x128_si256(R.raw(), L.raw(), 0x20);  // [R[0], R[1], L[0], L[1]]
   auto T2 = _mm256_permute2x128_si256(R.raw(), L.raw(), 0x31);  // [R[2], R[3], L[2], L[3]]

   auto A = SIMD_4x64(_mm256_permute4x64_epi64(T1, 0b11'01'10'00));  // [R[0], L[0], R[1], L[1]]
   auto B = SIMD_4x64(_mm256_permute4x64_epi64(T2, 0b11'01'10'00));  // [R[2], L[2], R[3], L[3]]

   A.store_be(out);
   B.store_be(out + 32);
}

/*
* 32-bit rotate on SIMD_4x64 helper for FL/FLINV
*/
BOTAN_FORCE_INLINE BOTAN_FN_ISA_AVX2 SIMD_4x64 rotl32_1(SIMD_4x64 t) {
   return SIMD_4x64(_mm256_or_si256(_mm256_slli_epi32(t.raw(), 1), _mm256_srli_epi32(t.raw(), 31)));
}

// NOLINTEND(portability-simd-intrinsics)

BOTAN_FORCE_INLINE BOTAN_FN_ISA_AVX2 SIMD_4x64 FL_4(SIMD_4x64 v, uint64_t K) {
   const uint32_t k1 = static_cast<uint32_t>(K >> 32);
   const uint32_t k2 = static_cast<uint32_t>(K & 0xFFFFFFFF);

   auto x1 = v.shr<32>();
   auto x2 = v & SIMD_4x64::splat(0xFFFFFFFF);

   x2 ^= rotl32_1(x1 & SIMD_4x64::splat(k1));
   x1 ^= (x2 | SIMD_4x64::splat(k2));

   return x1.shl<32>() | x2;
}

BOTAN_FORCE_INLINE BOTAN_FN_ISA_AVX2 SIMD_4x64 FLINV_4(SIMD_4x64 v, uint64_t K) {
   const uint32_t k1 = static_cast<uint32_t>(K >> 32);
   const uint32_t k2 = static_cast<uint32_t>(K & 0xFFFFFFFF);

   auto x1 = v.shr<32>();
   auto x2 = v & SIMD_4x64::splat(0xFFFFFFFF);

   x1 ^= (x2 | SIMD_4x64::splat(k2));
   x2 ^= rotl32_1(x1 & SIMD_4x64::splat(k1));

   return x1.shl<32>() | x2;
}

// Helpers for 6 round iterations

BOTAN_FORCE_INLINE BOTAN_FN_ISA_AVX2_GFNI void six_e_rounds(SIMD_4x64& L, SIMD_4x64& R, std::span<const uint64_t> SK) {
   R ^= camellia_f(L ^ SIMD_4x64::splat(SK[0]));
   L ^= camellia_f(R ^ SIMD_4x64::splat(SK[1]));
   R ^= camellia_f(L ^ SIMD_4x64::splat(SK[2]));
   L ^= camellia_f(R ^ SIMD_4x64::splat(SK[3]));
   R ^= camellia_f(L ^ SIMD_4x64::splat(SK[4]));
   L ^= camellia_f(R ^ SIMD_4x64::splat(SK[5]));
}

BOTAN_FORCE_INLINE BOTAN_FN_ISA_AVX2_GFNI void six_d_rounds(SIMD_4x64& L, SIMD_4x64& R, std::span<const uint64_t> SK) {
   R ^= camellia_f(L ^ SIMD_4x64::splat(SK[5]));
   L ^= camellia_f(R ^ SIMD_4x64::splat(SK[4]));
   R ^= camellia_f(L ^ SIMD_4x64::splat(SK[3]));
   L ^= camellia_f(R ^ SIMD_4x64::splat(SK[2]));
   R ^= camellia_f(L ^ SIMD_4x64::splat(SK[1]));
   L ^= camellia_f(R ^ SIMD_4x64::splat(SK[0]));
}

BOTAN_FN_ISA_AVX2_GFNI
void camellia_encrypt_x4_18r(const uint8_t in[], uint8_t out[], std::span<const uint64_t> SK) {
   SIMD_4x64 L;
   SIMD_4x64 R;
   load_and_deinterleave(in, L, R);

   L ^= SIMD_4x64::splat(SK[0]);
   R ^= SIMD_4x64::splat(SK[1]);

   six_e_rounds(L, R, SK.subspan(2));

   L = FL_4(L, SK[8]);
   R = FLINV_4(R, SK[9]);

   six_e_rounds(L, R, SK.subspan(10));

   L = FL_4(L, SK[16]);
   R = FLINV_4(R, SK[17]);

   six_e_rounds(L, R, SK.subspan(18));

   R ^= SIMD_4x64::splat(SK[24]);
   L ^= SIMD_4x64::splat(SK[25]);

   interleave_and_store(out, L, R);
}

BOTAN_FN_ISA_AVX2_GFNI
void camellia_decrypt_x4_18r(const uint8_t in[], uint8_t out[], std::span<const uint64_t> SK) {
   SIMD_4x64 L;
   SIMD_4x64 R;
   load_and_deinterleave(in, L, R);

   R ^= SIMD_4x64::splat(SK[25]);
   L ^= SIMD_4x64::splat(SK[24]);

   six_d_rounds(L, R, SK.subspan(18));

   L = FL_4(L, SK[17]);
   R = FLINV_4(R, SK[16]);

   six_d_rounds(L, R, SK.subspan(10));

   L = FL_4(L, SK[9]);
   R = FLINV_4(R, SK[8]);

   six_d_rounds(L, R, SK.subspan(2));

   L ^= SIMD_4x64::splat(SK[1]);
   R ^= SIMD_4x64::splat(SK[0]);

   interleave_and_store(out, L, R);
}

BOTAN_FN_ISA_AVX2_GFNI
void camellia_encrypt_x4_24r(const uint8_t in[], uint8_t out[], std::span<const uint64_t> SK) {
   SIMD_4x64 L;
   SIMD_4x64 R;
   load_and_deinterleave(in, L, R);

   L ^= SIMD_4x64::splat(SK[0]);
   R ^= SIMD_4x64::splat(SK[1]);

   six_e_rounds(L, R, SK.subspan(2));

   L = FL_4(L, SK[8]);
   R = FLINV_4(R, SK[9]);

   six_e_rounds(L, R, SK.subspan(10));

   L = FL_4(L, SK[16]);
   R = FLINV_4(R, SK[17]);

   six_e_rounds(L, R, SK.subspan(18));

   L = FL_4(L, SK[24]);
   R = FLINV_4(R, SK[25]);

   six_e_rounds(L, R, SK.subspan(26));

   R ^= SIMD_4x64::splat(SK[32]);
   L ^= SIMD_4x64::splat(SK[33]);

   interleave_and_store(out, L, R);
}

BOTAN_FN_ISA_AVX2_GFNI
void camellia_decrypt_x4_24r(const uint8_t in[], uint8_t out[], std::span<const uint64_t> SK) {
   SIMD_4x64 L;
   SIMD_4x64 R;
   load_and_deinterleave(in, L, R);

   R ^= SIMD_4x64::splat(SK[33]);
   L ^= SIMD_4x64::splat(SK[32]);

   six_d_rounds(L, R, SK.subspan(26));

   L = FL_4(L, SK[25]);
   R = FLINV_4(R, SK[24]);

   six_d_rounds(L, R, SK.subspan(18));

   L = FL_4(L, SK[17]);
   R = FLINV_4(R, SK[16]);

   six_d_rounds(L, R, SK.subspan(10));

   L = FL_4(L, SK[9]);
   R = FLINV_4(R, SK[8]);

   six_d_rounds(L, R, SK.subspan(2));

   L ^= SIMD_4x64::splat(SK[1]);
   R ^= SIMD_4x64::splat(SK[0]);

   interleave_and_store(out, L, R);
}

}  // namespace

}  // namespace Camellia_AVX2_GFNI

// static
void BOTAN_FN_ISA_AVX2_GFNI Camellia_128::avx2_gfni_encrypt(const uint8_t in[],
                                                            uint8_t out[],
                                                            size_t blocks,
                                                            std::span<const uint64_t> SK) {
   while(blocks >= 4) {
      Camellia_AVX2_GFNI::camellia_encrypt_x4_18r(in, out, SK);
      in += 4 * 16;
      out += 4 * 16;
      blocks -= 4;
   }

   if(blocks > 0) {
      uint8_t ibuf[4 * 16] = {0};
      uint8_t obuf[4 * 16] = {0};
      copy_mem(ibuf, in, blocks * 16);
      Camellia_AVX2_GFNI::camellia_encrypt_x4_18r(ibuf, obuf, SK);
      copy_mem(out, obuf, blocks * 16);
   }
}

// static
void BOTAN_FN_ISA_AVX2_GFNI Camellia_128::avx2_gfni_decrypt(const uint8_t in[],
                                                            uint8_t out[],
                                                            size_t blocks,
                                                            std::span<const uint64_t> SK) {
   while(blocks >= 4) {
      Camellia_AVX2_GFNI::camellia_decrypt_x4_18r(in, out, SK);
      in += 4 * 16;
      out += 4 * 16;
      blocks -= 4;
   }

   if(blocks > 0) {
      uint8_t ibuf[4 * 16] = {0};
      uint8_t obuf[4 * 16] = {0};
      copy_mem(ibuf, in, blocks * 16);
      Camellia_AVX2_GFNI::camellia_decrypt_x4_18r(ibuf, obuf, SK);
      copy_mem(out, obuf, blocks * 16);
   }
}

// static
void BOTAN_FN_ISA_AVX2_GFNI Camellia_192::avx2_gfni_encrypt(const uint8_t in[],
                                                            uint8_t out[],
                                                            size_t blocks,
                                                            std::span<const uint64_t> SK) {
   while(blocks >= 4) {
      Camellia_AVX2_GFNI::camellia_encrypt_x4_24r(in, out, SK);
      in += 4 * 16;
      out += 4 * 16;
      blocks -= 4;
   }

   if(blocks > 0) {
      uint8_t ibuf[4 * 16] = {0};
      uint8_t obuf[4 * 16] = {0};
      copy_mem(ibuf, in, blocks * 16);
      Camellia_AVX2_GFNI::camellia_encrypt_x4_24r(ibuf, obuf, SK);
      copy_mem(out, obuf, blocks * 16);
   }
}

// static
void BOTAN_FN_ISA_AVX2_GFNI Camellia_192::avx2_gfni_decrypt(const uint8_t in[],
                                                            uint8_t out[],
                                                            size_t blocks,
                                                            std::span<const uint64_t> SK) {
   while(blocks >= 4) {
      Camellia_AVX2_GFNI::camellia_decrypt_x4_24r(in, out, SK);
      in += 4 * 16;
      out += 4 * 16;
      blocks -= 4;
   }

   if(blocks > 0) {
      uint8_t ibuf[4 * 16] = {0};
      uint8_t obuf[4 * 16] = {0};
      copy_mem(ibuf, in, blocks * 16);
      Camellia_AVX2_GFNI::camellia_decrypt_x4_24r(ibuf, obuf, SK);
      copy_mem(out, obuf, blocks * 16);
   }
}

// static
void BOTAN_FN_ISA_AVX2_GFNI Camellia_256::avx2_gfni_encrypt(const uint8_t in[],
                                                            uint8_t out[],
                                                            size_t blocks,
                                                            std::span<const uint64_t> SK) {
   while(blocks >= 4) {
      Camellia_AVX2_GFNI::camellia_encrypt_x4_24r(in, out, SK);
      in += 4 * 16;
      out += 4 * 16;
      blocks -= 4;
   }

   if(blocks > 0) {
      uint8_t ibuf[4 * 16] = {0};
      uint8_t obuf[4 * 16] = {0};
      copy_mem(ibuf, in, blocks * 16);
      Camellia_AVX2_GFNI::camellia_encrypt_x4_24r(ibuf, obuf, SK);
      copy_mem(out, obuf, blocks * 16);
   }
}

// static
void BOTAN_FN_ISA_AVX2_GFNI Camellia_256::avx2_gfni_decrypt(const uint8_t in[],
                                                            uint8_t out[],
                                                            size_t blocks,
                                                            std::span<const uint64_t> SK) {
   while(blocks >= 4) {
      Camellia_AVX2_GFNI::camellia_decrypt_x4_24r(in, out, SK);
      in += 4 * 16;
      out += 4 * 16;
      blocks -= 4;
   }

   if(blocks > 0) {
      uint8_t ibuf[4 * 16] = {0};
      uint8_t obuf[4 * 16] = {0};
      copy_mem(ibuf, in, blocks * 16);
      Camellia_AVX2_GFNI::camellia_decrypt_x4_24r(ibuf, obuf, SK);
      copy_mem(out, obuf, blocks * 16);
   }
}

}  // namespace Botan
