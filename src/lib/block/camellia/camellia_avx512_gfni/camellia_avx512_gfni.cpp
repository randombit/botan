/*
* (C) 2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/camellia.h>

#include <botan/mem_ops.h>
#include <botan/internal/isa_extn.h>
#include <botan/internal/simd_8x64.h>
#include <botan/internal/simd_avx2_gfni.h>

namespace Botan {

namespace Camellia_AVX512 {

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

BOTAN_FORCE_INLINE BOTAN_FN_ISA_AVX512_GFNI SIMD_8x64 camellia_f(SIMD_8x64 x) {
   const __m512i xr = x.raw();

   /*
   * Camellia sends different bytes of each word through different sboxes; we
   * resolve this like cavemen by computing all 4 S-box variants over the full
   * vector in parallel, then blending the results.
   */

   // Compute S1(x), S2(x), S3(x), S4(x) for all bytes
   const __m512i y123 = _mm512_gf2p8affine_epi64_epi8(xr, _mm512_set1_epi64(pre123_a), pre_c);
   const __m512i y4 = _mm512_gf2p8affine_epi64_epi8(xr, _mm512_set1_epi64(pre4_a), pre_c);

   const __m512i s1 = _mm512_gf2p8affineinv_epi64_epi8(y123, _mm512_set1_epi64(post14_a), 0x6E);
   const __m512i s2 = _mm512_gf2p8affineinv_epi64_epi8(y123, _mm512_set1_epi64(post2_a), 0xDC);
   const __m512i s3 = _mm512_gf2p8affineinv_epi64_epi8(y123, _mm512_set1_epi64(post3_a), 0x37);
   const __m512i s4 = _mm512_gf2p8affineinv_epi64_epi8(y4, _mm512_set1_epi64(post14_a), 0x6E);

   // Blend to find correct S(x) for each byte position

   auto sx = s1;
   sx = _mm512_mask_blend_epi8(__mmask64(0x4848484848484848), sx, s2);  // s2 at bytes {3,6}
   sx = _mm512_mask_blend_epi8(__mmask64(0x2424242424242424), sx, s3);  // s3 at bytes {2,5}
   sx = _mm512_mask_blend_epi8(__mmask64(0x1212121212121212), sx, s4);  // s4 at bytes {1,4}

   // Linear mixing layer
   const auto P1 = _mm512_set_epi64(0x0808080908080809,
                                    0x0000000100000001,
                                    0x0808080908080809,
                                    0x0000000100000001,
                                    0x0808080908080809,
                                    0x0000000100000001,
                                    0x0808080908080809,
                                    0x0000000100000001);
   const auto P2 = _mm512_set_epi64(0x09090A0A09090A0A,
                                    0x0101020201010202,
                                    0x09090A0A09090A0A,
                                    0x0101020201010202,
                                    0x09090A0A09090A0A,
                                    0x0101020201010202,
                                    0x09090A0A09090A0A,
                                    0x0101020201010202);
   const auto P3 = _mm512_set_epi64(0x0A0B0B0B0A0B0B0B,
                                    0x0203030302030303,
                                    0x0A0B0B0B0A0B0B0B,
                                    0x0203030302030303,
                                    0x0A0B0B0B0A0B0B0B,
                                    0x0203030302030303,
                                    0x0A0B0B0B0A0B0B0B,
                                    0x0203030302030303);
   const auto P4 = _mm512_set_epi64(0x0C0C0D0C0E0D0C0C,
                                    0x0404050406050404,
                                    0x0C0C0D0C0E0D0C0C,
                                    0x0404050406050404,
                                    0x0C0C0D0C0E0D0C0C,
                                    0x0404050406050404,
                                    0x0C0C0D0C0E0D0C0C,
                                    0x0404050406050404);
   const auto P5 = _mm512_set_epi64(0x0D0E0E0D0F0E0D0F,
                                    0x0506060507060507,
                                    0x0D0E0E0D0F0E0D0F,
                                    0x0506060507060507,
                                    0x0D0E0E0D0F0E0D0F,
                                    0x0506060507060507,
                                    0x0D0E0E0D0F0E0D0F,
                                    0x0506060507060507);
   const auto P6 = _mm512_set_epi64(0x0F0F0F0EFFFFFFFF,
                                    0x07070706FFFFFFFF,
                                    0x0F0F0F0EFFFFFFFF,
                                    0x07070706FFFFFFFF,
                                    0x0F0F0F0EFFFFFFFF,
                                    0x07070706FFFFFFFF,
                                    0x0F0F0F0EFFFFFFFF,
                                    0x07070706FFFFFFFF);

   const auto t1 = SIMD_8x64(_mm512_shuffle_epi8(sx, P1));
   const auto t2 = SIMD_8x64(_mm512_shuffle_epi8(sx, P2));
   const auto t3 = SIMD_8x64(_mm512_shuffle_epi8(sx, P3));
   const auto t4 = SIMD_8x64(_mm512_shuffle_epi8(sx, P4));
   const auto t5 = SIMD_8x64(_mm512_shuffle_epi8(sx, P5));
   const auto t6 = SIMD_8x64(_mm512_shuffle_epi8(sx, P6));

   return (t1 ^ t2 ^ t3 ^ t4 ^ t5 ^ t6);
}

BOTAN_FORCE_INLINE BOTAN_FN_ISA_AVX512 SIMD_8x64 FL_8(SIMD_8x64 v, uint64_t K) {
   const auto Kv = _mm512_set1_epi64(K);
   auto vr = v.raw();

   // x2 ^= rotl<1>(x1 & k1): AND, rotate 32-bit elements, shift high->low, XOR
   vr = _mm512_xor_si512(vr, _mm512_srli_epi64(_mm512_rol_epi32(_mm512_and_si512(vr, Kv), 1), 32));

   // x1 ^= (x2 | k2): OR, shift low->high, XOR
   vr = _mm512_xor_si512(vr, _mm512_slli_epi64(_mm512_or_si512(vr, Kv), 32));

   return SIMD_8x64(vr);
}

BOTAN_FORCE_INLINE BOTAN_FN_ISA_AVX512 SIMD_8x64 FLINV_8(SIMD_8x64 v, uint64_t K) {
   const auto Kv = _mm512_set1_epi64(K);
   auto vr = v.raw();

   // x1 ^= (x2 | k2): OR, shift low->high, XOR
   vr = _mm512_xor_si512(vr, _mm512_slli_epi64(_mm512_or_si512(vr, Kv), 32));

   // x2 ^= rotl<1>(x1 & k1): AND, rotate 32-bit elements, shift high->low, XOR
   vr = _mm512_xor_si512(vr, _mm512_srli_epi64(_mm512_rol_epi32(_mm512_and_si512(vr, Kv), 1), 32));

   return SIMD_8x64(vr);
}

/*
* Load 8 blocks, byte-swap, and deinterleave into L (even) and R (odd) halves
*/
BOTAN_FORCE_INLINE BOTAN_FN_ISA_AVX512 void load_and_deinterleave(const uint8_t in[], SIMD_8x64& L, SIMD_8x64& R) {
   const auto idx_l = _mm512_set_epi64(0x0E, 0x0C, 0x0A, 0x08, 0x06, 0x04, 0x02, 0x00);
   const auto idx_r = _mm512_set_epi64(0x0F, 0x0D, 0x0B, 0x09, 0x07, 0x05, 0x03, 0x01);

   auto A = SIMD_8x64::load_be(in);
   auto B = SIMD_8x64::load_be(in + 64);

   L = SIMD_8x64(_mm512_permutex2var_epi64(A.raw(), idx_l, B.raw()));
   R = SIMD_8x64(_mm512_permutex2var_epi64(A.raw(), idx_r, B.raw()));
}

/*
* Interleave R/L halves (note swap), byte-swap, and store 8 blocks
*/
BOTAN_FORCE_INLINE BOTAN_FN_ISA_AVX512 void interleave_and_store(uint8_t out[], SIMD_8x64 L, SIMD_8x64 R) {
   const auto idx_lo = _mm512_set_epi64(0x0B, 0x03, 0x0A, 0x02, 0x09, 0x01, 0x08, 0x00);
   const auto idx_hi = _mm512_set_epi64(0x0F, 0x07, 0x0E, 0x06, 0x0D, 0x05, 0x0C, 0x04);

   auto A = SIMD_8x64(_mm512_permutex2var_epi64(R.raw(), idx_lo, L.raw()));
   auto B = SIMD_8x64(_mm512_permutex2var_epi64(R.raw(), idx_hi, L.raw()));

   A.store_be(out);
   B.store_be(out + 64);
}

// NOLINTEND(portability-simd-intrinsics)

// Helpers for 6 round iterations

BOTAN_FORCE_INLINE BOTAN_FN_ISA_AVX512_GFNI void six_e_rounds(SIMD_8x64& L,
                                                              SIMD_8x64& R,
                                                              std::span<const uint64_t> SK) {
   R ^= camellia_f(L ^ SIMD_8x64::splat(SK[0]));
   L ^= camellia_f(R ^ SIMD_8x64::splat(SK[1]));
   R ^= camellia_f(L ^ SIMD_8x64::splat(SK[2]));
   L ^= camellia_f(R ^ SIMD_8x64::splat(SK[3]));
   R ^= camellia_f(L ^ SIMD_8x64::splat(SK[4]));
   L ^= camellia_f(R ^ SIMD_8x64::splat(SK[5]));
}

BOTAN_FORCE_INLINE BOTAN_FN_ISA_AVX512_GFNI void six_d_rounds(SIMD_8x64& L,
                                                              SIMD_8x64& R,
                                                              std::span<const uint64_t> SK) {
   R ^= camellia_f(L ^ SIMD_8x64::splat(SK[5]));
   L ^= camellia_f(R ^ SIMD_8x64::splat(SK[4]));
   R ^= camellia_f(L ^ SIMD_8x64::splat(SK[3]));
   L ^= camellia_f(R ^ SIMD_8x64::splat(SK[2]));
   R ^= camellia_f(L ^ SIMD_8x64::splat(SK[1]));
   L ^= camellia_f(R ^ SIMD_8x64::splat(SK[0]));
}

BOTAN_FORCE_INLINE BOTAN_FN_ISA_AVX512_GFNI void six_e_rounds_x2(
   SIMD_8x64& L1, SIMD_8x64& R1, SIMD_8x64& L2, SIMD_8x64& R2, std::span<const uint64_t> SK) {
   const auto K0 = SIMD_8x64::splat(SK[0]);
   const auto K1 = SIMD_8x64::splat(SK[1]);
   const auto K2 = SIMD_8x64::splat(SK[2]);
   const auto K3 = SIMD_8x64::splat(SK[3]);
   const auto K4 = SIMD_8x64::splat(SK[4]);
   const auto K5 = SIMD_8x64::splat(SK[5]);

   R1 ^= camellia_f(L1 ^ K0);
   R2 ^= camellia_f(L2 ^ K0);
   L1 ^= camellia_f(R1 ^ K1);
   L2 ^= camellia_f(R2 ^ K1);
   R1 ^= camellia_f(L1 ^ K2);
   R2 ^= camellia_f(L2 ^ K2);
   L1 ^= camellia_f(R1 ^ K3);
   L2 ^= camellia_f(R2 ^ K3);
   R1 ^= camellia_f(L1 ^ K4);
   R2 ^= camellia_f(L2 ^ K4);
   L1 ^= camellia_f(R1 ^ K5);
   L2 ^= camellia_f(R2 ^ K5);
}

BOTAN_FORCE_INLINE BOTAN_FN_ISA_AVX512_GFNI void six_d_rounds_x2(
   SIMD_8x64& L1, SIMD_8x64& R1, SIMD_8x64& L2, SIMD_8x64& R2, std::span<const uint64_t> SK) {
   const auto K0 = SIMD_8x64::splat(SK[0]);
   const auto K1 = SIMD_8x64::splat(SK[1]);
   const auto K2 = SIMD_8x64::splat(SK[2]);
   const auto K3 = SIMD_8x64::splat(SK[3]);
   const auto K4 = SIMD_8x64::splat(SK[4]);
   const auto K5 = SIMD_8x64::splat(SK[5]);

   R1 ^= camellia_f(L1 ^ K5);
   R2 ^= camellia_f(L2 ^ K5);
   L1 ^= camellia_f(R1 ^ K4);
   L2 ^= camellia_f(R2 ^ K4);
   R1 ^= camellia_f(L1 ^ K3);
   R2 ^= camellia_f(L2 ^ K3);
   L1 ^= camellia_f(R1 ^ K2);
   L2 ^= camellia_f(R2 ^ K2);
   R1 ^= camellia_f(L1 ^ K1);
   R2 ^= camellia_f(L2 ^ K1);
   L1 ^= camellia_f(R1 ^ K0);
   L2 ^= camellia_f(R2 ^ K0);
}

BOTAN_FN_ISA_AVX512_GFNI
void camellia_encrypt_x16_18r(const uint8_t in[], uint8_t out[], std::span<const uint64_t> SK) {
   SIMD_8x64 L1;
   SIMD_8x64 R1;
   SIMD_8x64 L2;
   SIMD_8x64 R2;
   load_and_deinterleave(in, L1, R1);
   load_and_deinterleave(in + 128, L2, R2);

   const auto K0 = SIMD_8x64::splat(SK[0]);
   const auto K1 = SIMD_8x64::splat(SK[1]);
   L1 ^= K0;
   L2 ^= K0;
   R1 ^= K1;
   R2 ^= K1;

   six_e_rounds_x2(L1, R1, L2, R2, SK.subspan(2));

   L1 = FL_8(L1, SK[8]);
   L2 = FL_8(L2, SK[8]);
   R1 = FLINV_8(R1, SK[9]);
   R2 = FLINV_8(R2, SK[9]);

   six_e_rounds_x2(L1, R1, L2, R2, SK.subspan(10));

   L1 = FL_8(L1, SK[16]);
   L2 = FL_8(L2, SK[16]);
   R1 = FLINV_8(R1, SK[17]);
   R2 = FLINV_8(R2, SK[17]);

   six_e_rounds_x2(L1, R1, L2, R2, SK.subspan(18));

   const auto K24 = SIMD_8x64::splat(SK[24]);
   const auto K25 = SIMD_8x64::splat(SK[25]);
   R1 ^= K24;
   R2 ^= K24;
   L1 ^= K25;
   L2 ^= K25;

   interleave_and_store(out, L1, R1);
   interleave_and_store(out + 128, L2, R2);
}

BOTAN_FN_ISA_AVX512_GFNI
void camellia_decrypt_x16_18r(const uint8_t in[], uint8_t out[], std::span<const uint64_t> SK) {
   SIMD_8x64 L1;
   SIMD_8x64 R1;
   SIMD_8x64 L2;
   SIMD_8x64 R2;
   load_and_deinterleave(in, L1, R1);
   load_and_deinterleave(in + 128, L2, R2);

   const auto K25 = SIMD_8x64::splat(SK[25]);
   const auto K24 = SIMD_8x64::splat(SK[24]);
   R1 ^= K25;
   R2 ^= K25;
   L1 ^= K24;
   L2 ^= K24;

   six_d_rounds_x2(L1, R1, L2, R2, SK.subspan(18));

   L1 = FL_8(L1, SK[17]);
   L2 = FL_8(L2, SK[17]);
   R1 = FLINV_8(R1, SK[16]);
   R2 = FLINV_8(R2, SK[16]);

   six_d_rounds_x2(L1, R1, L2, R2, SK.subspan(10));

   L1 = FL_8(L1, SK[9]);
   L2 = FL_8(L2, SK[9]);
   R1 = FLINV_8(R1, SK[8]);
   R2 = FLINV_8(R2, SK[8]);

   six_d_rounds_x2(L1, R1, L2, R2, SK.subspan(2));

   const auto K1 = SIMD_8x64::splat(SK[1]);
   const auto K0 = SIMD_8x64::splat(SK[0]);
   L1 ^= K1;
   L2 ^= K1;
   R1 ^= K0;
   R2 ^= K0;

   interleave_and_store(out, L1, R1);
   interleave_and_store(out + 128, L2, R2);
}

BOTAN_FN_ISA_AVX512_GFNI
void camellia_encrypt_x16_24r(const uint8_t in[], uint8_t out[], std::span<const uint64_t> SK) {
   SIMD_8x64 L1;
   SIMD_8x64 R1;
   SIMD_8x64 L2;
   SIMD_8x64 R2;
   load_and_deinterleave(in, L1, R1);
   load_and_deinterleave(in + 128, L2, R2);

   const auto K0 = SIMD_8x64::splat(SK[0]);
   const auto K1 = SIMD_8x64::splat(SK[1]);
   L1 ^= K0;
   L2 ^= K0;
   R1 ^= K1;
   R2 ^= K1;

   six_e_rounds_x2(L1, R1, L2, R2, SK.subspan(2));

   L1 = FL_8(L1, SK[8]);
   L2 = FL_8(L2, SK[8]);
   R1 = FLINV_8(R1, SK[9]);
   R2 = FLINV_8(R2, SK[9]);

   six_e_rounds_x2(L1, R1, L2, R2, SK.subspan(10));

   L1 = FL_8(L1, SK[16]);
   L2 = FL_8(L2, SK[16]);
   R1 = FLINV_8(R1, SK[17]);
   R2 = FLINV_8(R2, SK[17]);

   six_e_rounds_x2(L1, R1, L2, R2, SK.subspan(18));

   L1 = FL_8(L1, SK[24]);
   L2 = FL_8(L2, SK[24]);
   R1 = FLINV_8(R1, SK[25]);
   R2 = FLINV_8(R2, SK[25]);

   six_e_rounds_x2(L1, R1, L2, R2, SK.subspan(26));

   const auto K32 = SIMD_8x64::splat(SK[32]);
   const auto K33 = SIMD_8x64::splat(SK[33]);
   R1 ^= K32;
   R2 ^= K32;
   L1 ^= K33;
   L2 ^= K33;

   interleave_and_store(out, L1, R1);
   interleave_and_store(out + 128, L2, R2);
}

BOTAN_FN_ISA_AVX512_GFNI
void camellia_decrypt_x16_24r(const uint8_t in[], uint8_t out[], std::span<const uint64_t> SK) {
   SIMD_8x64 L1;
   SIMD_8x64 R1;
   SIMD_8x64 L2;
   SIMD_8x64 R2;
   load_and_deinterleave(in, L1, R1);
   load_and_deinterleave(in + 128, L2, R2);

   const auto K33 = SIMD_8x64::splat(SK[33]);
   const auto K32 = SIMD_8x64::splat(SK[32]);
   R1 ^= K33;
   R2 ^= K33;
   L1 ^= K32;
   L2 ^= K32;

   six_d_rounds_x2(L1, R1, L2, R2, SK.subspan(26));

   L1 = FL_8(L1, SK[25]);
   L2 = FL_8(L2, SK[25]);
   R1 = FLINV_8(R1, SK[24]);
   R2 = FLINV_8(R2, SK[24]);

   six_d_rounds_x2(L1, R1, L2, R2, SK.subspan(18));

   L1 = FL_8(L1, SK[17]);
   L2 = FL_8(L2, SK[17]);
   R1 = FLINV_8(R1, SK[16]);
   R2 = FLINV_8(R2, SK[16]);

   six_d_rounds_x2(L1, R1, L2, R2, SK.subspan(10));

   L1 = FL_8(L1, SK[9]);
   L2 = FL_8(L2, SK[9]);
   R1 = FLINV_8(R1, SK[8]);
   R2 = FLINV_8(R2, SK[8]);

   six_d_rounds_x2(L1, R1, L2, R2, SK.subspan(2));

   const auto K1 = SIMD_8x64::splat(SK[1]);
   const auto K0 = SIMD_8x64::splat(SK[0]);
   L1 ^= K1;
   L2 ^= K1;
   R1 ^= K0;
   R2 ^= K0;

   interleave_and_store(out, L1, R1);
   interleave_and_store(out + 128, L2, R2);
}

BOTAN_FN_ISA_AVX512_GFNI
void camellia_encrypt_x8_18r(const uint8_t in[], uint8_t out[], std::span<const uint64_t> SK) {
   SIMD_8x64 L;
   SIMD_8x64 R;
   load_and_deinterleave(in, L, R);

   L ^= SIMD_8x64::splat(SK[0]);
   R ^= SIMD_8x64::splat(SK[1]);

   six_e_rounds(L, R, SK.subspan(2));

   L = FL_8(L, SK[8]);
   R = FLINV_8(R, SK[9]);

   six_e_rounds(L, R, SK.subspan(10));

   L = FL_8(L, SK[16]);
   R = FLINV_8(R, SK[17]);

   six_e_rounds(L, R, SK.subspan(18));

   R ^= SIMD_8x64::splat(SK[24]);
   L ^= SIMD_8x64::splat(SK[25]);

   interleave_and_store(out, L, R);
}

BOTAN_FN_ISA_AVX512_GFNI
void camellia_decrypt_x8_18r(const uint8_t in[], uint8_t out[], std::span<const uint64_t> SK) {
   SIMD_8x64 L;
   SIMD_8x64 R;
   load_and_deinterleave(in, L, R);

   R ^= SIMD_8x64::splat(SK[25]);
   L ^= SIMD_8x64::splat(SK[24]);

   six_d_rounds(L, R, SK.subspan(18));

   L = FL_8(L, SK[17]);
   R = FLINV_8(R, SK[16]);

   six_d_rounds(L, R, SK.subspan(10));

   L = FL_8(L, SK[9]);
   R = FLINV_8(R, SK[8]);

   six_d_rounds(L, R, SK.subspan(2));

   L ^= SIMD_8x64::splat(SK[1]);
   R ^= SIMD_8x64::splat(SK[0]);

   interleave_and_store(out, L, R);
}

BOTAN_FN_ISA_AVX512_GFNI
void camellia_encrypt_x8_24r(const uint8_t in[], uint8_t out[], std::span<const uint64_t> SK) {
   SIMD_8x64 L;
   SIMD_8x64 R;
   load_and_deinterleave(in, L, R);

   L ^= SIMD_8x64::splat(SK[0]);
   R ^= SIMD_8x64::splat(SK[1]);

   six_e_rounds(L, R, SK.subspan(2));

   L = FL_8(L, SK[8]);
   R = FLINV_8(R, SK[9]);

   six_e_rounds(L, R, SK.subspan(10));

   L = FL_8(L, SK[16]);
   R = FLINV_8(R, SK[17]);

   six_e_rounds(L, R, SK.subspan(18));

   L = FL_8(L, SK[24]);
   R = FLINV_8(R, SK[25]);

   six_e_rounds(L, R, SK.subspan(26));

   R ^= SIMD_8x64::splat(SK[32]);
   L ^= SIMD_8x64::splat(SK[33]);

   interleave_and_store(out, L, R);
}

BOTAN_FN_ISA_AVX512_GFNI
void camellia_decrypt_x8_24r(const uint8_t in[], uint8_t out[], std::span<const uint64_t> SK) {
   SIMD_8x64 L;
   SIMD_8x64 R;
   load_and_deinterleave(in, L, R);

   R ^= SIMD_8x64::splat(SK[33]);
   L ^= SIMD_8x64::splat(SK[32]);

   six_d_rounds(L, R, SK.subspan(26));

   L = FL_8(L, SK[25]);
   R = FLINV_8(R, SK[24]);

   six_d_rounds(L, R, SK.subspan(18));

   L = FL_8(L, SK[17]);
   R = FLINV_8(R, SK[16]);

   six_d_rounds(L, R, SK.subspan(10));

   L = FL_8(L, SK[9]);
   R = FLINV_8(R, SK[8]);

   six_d_rounds(L, R, SK.subspan(2));

   L ^= SIMD_8x64::splat(SK[1]);
   R ^= SIMD_8x64::splat(SK[0]);

   interleave_and_store(out, L, R);
}

}  // namespace

}  // namespace Camellia_AVX512

// static
void BOTAN_FN_ISA_AVX512_GFNI Camellia_128::avx512_gfni_encrypt(const uint8_t in[],
                                                                uint8_t out[],
                                                                size_t blocks,
                                                                std::span<const uint64_t> SK) {
   while(blocks >= 16) {
      Camellia_AVX512::camellia_encrypt_x16_18r(in, out, SK);
      in += 16 * 16;
      out += 16 * 16;
      blocks -= 16;
   }

   while(blocks >= 8) {
      Camellia_AVX512::camellia_encrypt_x8_18r(in, out, SK);
      in += 8 * 16;
      out += 8 * 16;
      blocks -= 8;
   }

   if(blocks > 0) {
      uint8_t ibuf[8 * 16] = {0};
      uint8_t obuf[8 * 16] = {0};
      copy_mem(ibuf, in, blocks * 16);
      Camellia_AVX512::camellia_encrypt_x8_18r(ibuf, obuf, SK);
      copy_mem(out, obuf, blocks * 16);
   }
}

// static
void BOTAN_FN_ISA_AVX512_GFNI Camellia_128::avx512_gfni_decrypt(const uint8_t in[],
                                                                uint8_t out[],
                                                                size_t blocks,
                                                                std::span<const uint64_t> SK) {
   while(blocks >= 16) {
      Camellia_AVX512::camellia_decrypt_x16_18r(in, out, SK);
      in += 16 * 16;
      out += 16 * 16;
      blocks -= 16;
   }

   while(blocks >= 8) {
      Camellia_AVX512::camellia_decrypt_x8_18r(in, out, SK);
      in += 8 * 16;
      out += 8 * 16;
      blocks -= 8;
   }

   if(blocks > 0) {
      uint8_t ibuf[8 * 16] = {0};
      uint8_t obuf[8 * 16] = {0};
      copy_mem(ibuf, in, blocks * 16);
      Camellia_AVX512::camellia_decrypt_x8_18r(ibuf, obuf, SK);
      copy_mem(out, obuf, blocks * 16);
   }
}

// static
void BOTAN_FN_ISA_AVX512_GFNI Camellia_192::avx512_gfni_encrypt(const uint8_t in[],
                                                                uint8_t out[],
                                                                size_t blocks,
                                                                std::span<const uint64_t> SK) {
   while(blocks >= 16) {
      Camellia_AVX512::camellia_encrypt_x16_24r(in, out, SK);
      in += 16 * 16;
      out += 16 * 16;
      blocks -= 16;
   }

   while(blocks >= 8) {
      Camellia_AVX512::camellia_encrypt_x8_24r(in, out, SK);
      in += 8 * 16;
      out += 8 * 16;
      blocks -= 8;
   }

   if(blocks > 0) {
      uint8_t ibuf[8 * 16] = {0};
      uint8_t obuf[8 * 16] = {0};
      copy_mem(ibuf, in, blocks * 16);
      Camellia_AVX512::camellia_encrypt_x8_24r(ibuf, obuf, SK);
      copy_mem(out, obuf, blocks * 16);
   }
}

// static
void BOTAN_FN_ISA_AVX512_GFNI Camellia_192::avx512_gfni_decrypt(const uint8_t in[],
                                                                uint8_t out[],
                                                                size_t blocks,
                                                                std::span<const uint64_t> SK) {
   while(blocks >= 16) {
      Camellia_AVX512::camellia_decrypt_x16_24r(in, out, SK);
      in += 16 * 16;
      out += 16 * 16;
      blocks -= 16;
   }

   while(blocks >= 8) {
      Camellia_AVX512::camellia_decrypt_x8_24r(in, out, SK);
      in += 8 * 16;
      out += 8 * 16;
      blocks -= 8;
   }

   if(blocks > 0) {
      uint8_t ibuf[8 * 16] = {0};
      uint8_t obuf[8 * 16] = {0};
      copy_mem(ibuf, in, blocks * 16);
      Camellia_AVX512::camellia_decrypt_x8_24r(ibuf, obuf, SK);
      copy_mem(out, obuf, blocks * 16);
   }
}

// static
void BOTAN_FN_ISA_AVX512_GFNI Camellia_256::avx512_gfni_encrypt(const uint8_t in[],
                                                                uint8_t out[],
                                                                size_t blocks,
                                                                std::span<const uint64_t> SK) {
   while(blocks >= 16) {
      Camellia_AVX512::camellia_encrypt_x16_24r(in, out, SK);
      in += 16 * 16;
      out += 16 * 16;
      blocks -= 16;
   }

   while(blocks >= 8) {
      Camellia_AVX512::camellia_encrypt_x8_24r(in, out, SK);
      in += 8 * 16;
      out += 8 * 16;
      blocks -= 8;
   }

   if(blocks > 0) {
      uint8_t ibuf[8 * 16] = {0};
      uint8_t obuf[8 * 16] = {0};
      copy_mem(ibuf, in, blocks * 16);
      Camellia_AVX512::camellia_encrypt_x8_24r(ibuf, obuf, SK);
      copy_mem(out, obuf, blocks * 16);
   }
}

// static
void BOTAN_FN_ISA_AVX512_GFNI Camellia_256::avx512_gfni_decrypt(const uint8_t in[],
                                                                uint8_t out[],
                                                                size_t blocks,
                                                                std::span<const uint64_t> SK) {
   while(blocks >= 16) {
      Camellia_AVX512::camellia_decrypt_x16_24r(in, out, SK);
      in += 16 * 16;
      out += 16 * 16;
      blocks -= 16;
   }

   while(blocks >= 8) {
      Camellia_AVX512::camellia_decrypt_x8_24r(in, out, SK);
      in += 8 * 16;
      out += 8 * 16;
      blocks -= 8;
   }

   if(blocks > 0) {
      uint8_t ibuf[8 * 16] = {0};
      uint8_t obuf[8 * 16] = {0};
      copy_mem(ibuf, in, blocks * 16);
      Camellia_AVX512::camellia_decrypt_x8_24r(ibuf, obuf, SK);
      copy_mem(out, obuf, blocks * 16);
   }
}

}  // namespace Botan
