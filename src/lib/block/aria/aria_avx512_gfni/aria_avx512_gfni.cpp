/*
* (C) 2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/aria.h>

#include <botan/mem_ops.h>
#include <botan/internal/isa_extn.h>
#include <botan/internal/simd_avx2_gfni.h>
#include <botan/internal/simd_avx512.h>

namespace Botan {

namespace ARIA_AVX512 {

namespace {

/*
* ARIA has two S-boxes pairs S1/X1 (the Rijndael sbox and its inverse)
* and S2/X2 (another sbox and its inverse), all of which can be described
* as an affine transformation applied to an inversion in GF(2^8)
*
* A very helpful reference for this implementation was
*
* "AVX-Based Acceleration of ARIA Block Cipher Algorithm"
* by Yoo, Kivilinna, Cho.
* IEEE Access, Vol. 11, 2023 (DOI: 10.1109/ACCESS.2023.3298026)
* <https://ieeexplore.ieee.org/stamp/stamp.jsp?arnumber=10190597>
*
* The paper describes the sbox decompositions (Section IV. A. 1.)
*
*   S1(x) = A_S1(inv(x))        -> affineinv(AFF_S1, x, 0x63)
*   S2(x) = A_S2(inv(x))        -> affineinv(AFF_S2, x, 0xE2)
*   X1(x) = inv(A_{S1^-1}(x))   -> affine(AFF_X1, x, 0x05) then affineinv(I, y, 0)
*   X2(x) = inv(A_{S2^-1}(x))   -> affine(AFF_X2, x, 0x2C) then affineinv(I, y, 0)
*
* where inv(x) = x^-1 in GF(2^8), implemented by the GFNI affineinv instruction
* and the AFF_* matrixes are the constants following.
*
* The approach used here diverges from the implementation described in the
* paper; they used AVX-512 to compute 64 blocks in parallel. This implementation
* instead takes advantage of the fact that AVX-512/GFNI can use 4 different GFNI
* affine constants in a single call, and so needs only 16 block chunks. This
* leads to less register pressure and (imo) a simpler implementation, albeit likely
* giving up some performance with larger input sizes.
*/

constexpr uint64_t AFF_S1 = gfni_matrix(R"(
   1 0 0 0 1 1 1 1
   1 1 0 0 0 1 1 1
   1 1 1 0 0 0 1 1
   1 1 1 1 0 0 0 1
   1 1 1 1 1 0 0 0
   0 1 1 1 1 1 0 0
   0 0 1 1 1 1 1 0
   0 0 0 1 1 1 1 1)");

constexpr uint64_t AFF_S2 = gfni_matrix(R"(
   0 1 0 1 0 1 1 1
   0 0 1 1 1 1 1 1
   1 1 1 0 1 1 0 1
   1 1 0 0 0 0 1 1
   0 1 0 0 0 0 1 1
   1 1 0 0 1 1 1 0
   0 1 1 0 0 0 1 1
   1 1 1 1 0 1 1 0)");

constexpr uint64_t AFF_X1 = gfni_matrix(R"(
   0 0 1 0 0 1 0 1
   1 0 0 1 0 0 1 0
   0 1 0 0 1 0 0 1
   1 0 1 0 0 1 0 0
   0 1 0 1 0 0 1 0
   0 0 1 0 1 0 0 1
   1 0 0 1 0 1 0 0
   0 1 0 0 1 0 1 0)");

constexpr uint64_t AFF_X2 = gfni_matrix(R"(
   0 0 0 1 1 0 0 0
   0 0 1 0 0 1 1 0
   0 0 0 0 1 0 1 0
   1 1 1 0 0 0 1 1
   1 1 1 0 1 1 0 0
   0 1 1 0 1 0 1 1
   1 0 1 1 1 1 0 1
   1 0 0 1 0 0 1 1)");

// GFNI identity matrix
constexpr uint64_t IDENTITY = gfni_matrix(R"(
   1 0 0 0 0 0 0 0
   0 1 0 0 0 0 0 0
   0 0 1 0 0 0 0 0
   0 0 0 1 0 0 0 0
   0 0 0 0 1 0 0 0
   0 0 0 0 0 1 0 0
   0 0 0 0 0 0 1 0
   0 0 0 0 0 0 0 1)");

BOTAN_FORCE_INLINE BOTAN_FN_ISA_AVX512_GFNI SIMD_16x32
apply_aria_sbox(SIMD_16x32 x, __m512i pre_mat, __m512i pre_const, __m512i post_mat, __m512i post_const) {
   /*
   * After transposing the blocks, we have 4 16-word registers where register 0 contains
   * all of the first words of the block, etc.
   *
   * However ARIA wants to send adjacent bytes of each word through the 4 different
   * sboxes (either S1||S2||X1||X2 for "FE rounds" or X1||X2||S1||S2 for "FO rounds").
   * This is handled here by using a permutation to send the 16 first bytes into the
   * first zmm lane, the 16 second bytes in the second zmm lane, etc. GFNI lets you
   * specify different affine matrices for each lane so we can then compute all 4 sboxes
   * with a single sequence. We cannot make use of GFNI's builtin XOR/add instruction,
   * since we need to use different constants for each lane, but this just requires an
   * extra XOR instruction after the GFNI instructions.
   */

   const __m512i fwd_perm = _mm512_set_epi64(0x3F3B37332F2B2723,
                                             0x1F1B17130F0B0703,
                                             0x3E3A36322E2A2622,
                                             0x1E1A16120E0A0602,
                                             0x3D3935312D292521,
                                             0x1D1915110D090501,
                                             0x3C3834302C282420,
                                             0x1C1814100C080400);

   const __m512i inv_perm = _mm512_set_epi64(0x3F2F1F0F3E2E1E0E,
                                             0x3D2D1D0D3C2C1C0C,
                                             0x3B2B1B0B3A2A1A0A,
                                             0x3929190938281808,
                                             0x3727170736261606,
                                             0x3525150534241404,
                                             0x3323130332221202,
                                             0x3121110130201000);

   // Permute to align bytes into the 128-bit sbox lanes
   __m512i v = _mm512_permutexvar_epi8(fwd_perm, x.raw());

   // The sbox magic
   v = _mm512_xor_si512(_mm512_gf2p8affine_epi64_epi8(v, pre_mat, 0), pre_const);
   v = _mm512_xor_si512(_mm512_gf2p8affineinv_epi64_epi8(v, post_mat, 0), post_const);

   // Permute back to standard ordering
   v = _mm512_permutexvar_epi8(inv_perm, v);
   return SIMD_16x32(v);
}

BOTAN_FORCE_INLINE BOTAN_FN_ISA_AVX512_GFNI SIMD_16x32 apply_fo_sbox(SIMD_16x32 x) {
   /*
   * FO is S1 || S2 || X1 || X2
   *
   * S1/S2 requires the affine transformation after the inversion, likewise X1/X2 requires
   * the affine transformation before the inversion. So half of the matrices in use for
   * each instruction are the identity.
   */
   const __m512i fo_pre_mat = _mm512_set_epi64(IDENTITY, IDENTITY, IDENTITY, IDENTITY, AFF_X1, AFF_X1, AFF_X2, AFF_X2);

   const __m512i fo_post_mat = _mm512_set_epi64(AFF_S1, AFF_S1, AFF_S2, AFF_S2, IDENTITY, IDENTITY, IDENTITY, IDENTITY);

   const __m512i fo_pre_const = _mm512_set_epi64(0x0000000000000000,
                                                 0x0000000000000000,
                                                 0x0000000000000000,
                                                 0x0000000000000000,
                                                 0x0505050505050505,
                                                 0x0505050505050505,
                                                 0x2C2C2C2C2C2C2C2C,
                                                 0x2C2C2C2C2C2C2C2C);

   const __m512i fo_post_const = _mm512_set_epi64(0x6363636363636363,
                                                  0x6363636363636363,
                                                  0xE2E2E2E2E2E2E2E2,
                                                  0xE2E2E2E2E2E2E2E2,
                                                  0x0000000000000000,
                                                  0x0000000000000000,
                                                  0x0000000000000000,
                                                  0x0000000000000000);

   return apply_aria_sbox(x, fo_pre_mat, fo_pre_const, fo_post_mat, fo_post_const);
}

BOTAN_FORCE_INLINE BOTAN_FN_ISA_AVX512_GFNI SIMD_16x32 apply_fe_sbox(SIMD_16x32 x) {
   const __m512i fe_pre_mat = _mm512_set_epi64(AFF_X1, AFF_X1, AFF_X2, AFF_X2, IDENTITY, IDENTITY, IDENTITY, IDENTITY);

   const __m512i fe_post_mat = _mm512_set_epi64(IDENTITY, IDENTITY, IDENTITY, IDENTITY, AFF_S1, AFF_S1, AFF_S2, AFF_S2);

   const __m512i fe_pre_const = _mm512_set_epi64(0x0505050505050505,
                                                 0x0505050505050505,
                                                 0x2C2C2C2C2C2C2C2C,
                                                 0x2C2C2C2C2C2C2C2C,
                                                 0x0000000000000000,
                                                 0x0000000000000000,
                                                 0x0000000000000000,
                                                 0x0000000000000000);

   const __m512i fe_post_const = _mm512_set_epi64(0x0000000000000000,
                                                  0x0000000000000000,
                                                  0x0000000000000000,
                                                  0x0000000000000000,
                                                  0x6363636363636363,
                                                  0x6363636363636363,
                                                  0xE2E2E2E2E2E2E2E2,
                                                  0xE2E2E2E2E2E2E2E2);

   return apply_aria_sbox(x, fe_pre_mat, fe_pre_const, fe_post_mat, fe_post_const);
}

BOTAN_FN_ISA_AVX512 BOTAN_FORCE_INLINE SIMD_16x32 swap_abcd_badc(SIMD_16x32 x) {
   // Why you no 16-bit rotate Intel?

   const __m512i rol16 = _mm512_set_epi64(0x0E0F0C0D0A0B0809,
                                          0x0607040502030001,
                                          0x0E0F0C0D0A0B0809,
                                          0x0607040502030001,
                                          0x0E0F0C0D0A0B0809,
                                          0x0607040502030001,
                                          0x0E0F0C0D0A0B0809,
                                          0x0607040502030001);

   return SIMD_16x32(_mm512_shuffle_epi8(x.raw(), rol16));
}

/*
* This applies mixing in much the same way as the M1/M2/M3/M4 constants in the
* scalar/table version in aria.cpp (ARIA_F1/ARIA_F2)
*
* Notice that the constants are rotational and each has the property that it
* maps the byte into all 3 of the other bytes, ie byte 0 goes into bytes 1,2,3,
* then byte 1 goes into bytes 0,2,3, ....
*
* This is neatly handled by XORing together rotations of the words
*/
BOTAN_FORCE_INLINE BOTAN_FN_ISA_AVX512 SIMD_16x32 aria_fo_m(SIMD_16x32 x) {
   return x.rotl<8>() ^ x.rotl<16>() ^ x.rotl<24>();
}

BOTAN_FORCE_INLINE BOTAN_FN_ISA_AVX512 SIMD_16x32 aria_fe_m(SIMD_16x32 x) {
   return x ^ x.rotl<8>() ^ x.rotl<24>();
}

BOTAN_FORCE_INLINE BOTAN_FN_ISA_AVX512 void aria_mix(SIMD_16x32& B0, SIMD_16x32& B1, SIMD_16x32& B2, SIMD_16x32& B3) {
   B1 ^= B2;
   B2 ^= B3;
   B0 ^= B1;
   B3 ^= B1;
   B2 ^= B0;
   B1 ^= B2;
}

BOTAN_FORCE_INLINE BOTAN_FN_ISA_AVX512_GFNI void aria_fo(SIMD_16x32& B0,
                                                         SIMD_16x32& B1,
                                                         SIMD_16x32& B2,
                                                         SIMD_16x32& B3) {
   B0 = aria_fo_m(apply_fo_sbox(B0));
   B1 = aria_fo_m(apply_fo_sbox(B1));
   B2 = aria_fo_m(apply_fo_sbox(B2));
   B3 = aria_fo_m(apply_fo_sbox(B3));

   aria_mix(B0, B1, B2, B3);

   B1 = swap_abcd_badc(B1);
   B2 = B2.rotl<16>();
   B3 = B3.bswap();

   aria_mix(B0, B1, B2, B3);
}

BOTAN_FORCE_INLINE BOTAN_FN_ISA_AVX512_GFNI void aria_fe(SIMD_16x32& B0,
                                                         SIMD_16x32& B1,
                                                         SIMD_16x32& B2,
                                                         SIMD_16x32& B3) {
   B0 = aria_fe_m(apply_fe_sbox(B0));
   B1 = aria_fe_m(apply_fe_sbox(B1));
   B2 = aria_fe_m(apply_fe_sbox(B2));
   B3 = aria_fe_m(apply_fe_sbox(B3));

   aria_mix(B0, B1, B2, B3);

   B3 = swap_abcd_badc(B3);
   B0 = B0.rotl<16>();
   B1 = B1.bswap();

   aria_mix(B0, B1, B2, B3);
}

/*
* 16-wide ARIA block processing
*/
BOTAN_FN_ISA_AVX512_GFNI
void transform_16(const uint8_t in[], uint8_t out[], std::span<const uint32_t> KS) {
   const size_t ROUNDS = (KS.size() / 4) - 1;

   BOTAN_ASSERT_NOMSG(ROUNDS == 12 || ROUNDS == 14 || ROUNDS == 16);

   SIMD_16x32 B0 = SIMD_16x32::load_be(in);
   SIMD_16x32 B1 = SIMD_16x32::load_be(in + 64);
   SIMD_16x32 B2 = SIMD_16x32::load_be(in + 128);
   SIMD_16x32 B3 = SIMD_16x32::load_be(in + 192);

   SIMD_16x32::transpose(B0, B1, B2, B3);

   for(size_t r = 0; r != ROUNDS; r += 2) {
      B0 ^= SIMD_16x32::splat(KS[4 * r]);
      B1 ^= SIMD_16x32::splat(KS[4 * r + 1]);
      B2 ^= SIMD_16x32::splat(KS[4 * r + 2]);
      B3 ^= SIMD_16x32::splat(KS[4 * r + 3]);
      aria_fo(B0, B1, B2, B3);

      B0 ^= SIMD_16x32::splat(KS[4 * r + 4]);
      B1 ^= SIMD_16x32::splat(KS[4 * r + 5]);
      B2 ^= SIMD_16x32::splat(KS[4 * r + 6]);
      B3 ^= SIMD_16x32::splat(KS[4 * r + 7]);

      if(r != ROUNDS - 2) {
         aria_fe(B0, B1, B2, B3);
      }
   }

   B0 = apply_fe_sbox(B0) ^ SIMD_16x32::splat(KS[4 * ROUNDS]);
   B1 = apply_fe_sbox(B1) ^ SIMD_16x32::splat(KS[4 * ROUNDS + 1]);
   B2 = apply_fe_sbox(B2) ^ SIMD_16x32::splat(KS[4 * ROUNDS + 2]);
   B3 = apply_fe_sbox(B3) ^ SIMD_16x32::splat(KS[4 * ROUNDS + 3]);

   SIMD_16x32::transpose(B0, B1, B2, B3);

   B0.store_be(out);
   B1.store_be(out + 64);
   B2.store_be(out + 128);
   B3.store_be(out + 192);
}

void BOTAN_FN_ISA_AVX512_GFNI aria_transform(const uint8_t in[],
                                             uint8_t out[],
                                             size_t blocks,
                                             std::span<const uint32_t> KS) {
   while(blocks >= 16) {
      ARIA_AVX512::transform_16(in, out, KS);
      in += 16 * 16;
      out += 16 * 16;
      blocks -= 16;
   }

   if(blocks > 0) {
      uint8_t ibuf[16 * 16] = {0};
      uint8_t obuf[16 * 16] = {0};
      copy_mem(ibuf, in, blocks * 16);
      ARIA_AVX512::transform_16(ibuf, obuf, KS);
      copy_mem(out, obuf, blocks * 16);
   }
}

}  // namespace

}  // namespace ARIA_AVX512

void BOTAN_FN_ISA_AVX512_GFNI ARIA_128::aria_avx512_gfni_encrypt(const uint8_t in[],
                                                                 uint8_t out[],
                                                                 size_t blocks) const {
   ARIA_AVX512::aria_transform(in, out, blocks, m_ERK);
}

void BOTAN_FN_ISA_AVX512_GFNI ARIA_128::aria_avx512_gfni_decrypt(const uint8_t in[],
                                                                 uint8_t out[],
                                                                 size_t blocks) const {
   ARIA_AVX512::aria_transform(in, out, blocks, m_DRK);
}

void BOTAN_FN_ISA_AVX512_GFNI ARIA_192::aria_avx512_gfni_encrypt(const uint8_t in[],
                                                                 uint8_t out[],
                                                                 size_t blocks) const {
   ARIA_AVX512::aria_transform(in, out, blocks, m_ERK);
}

void BOTAN_FN_ISA_AVX512_GFNI ARIA_192::aria_avx512_gfni_decrypt(const uint8_t in[],
                                                                 uint8_t out[],
                                                                 size_t blocks) const {
   ARIA_AVX512::aria_transform(in, out, blocks, m_DRK);
}

void BOTAN_FN_ISA_AVX512_GFNI ARIA_256::aria_avx512_gfni_encrypt(const uint8_t in[],
                                                                 uint8_t out[],
                                                                 size_t blocks) const {
   ARIA_AVX512::aria_transform(in, out, blocks, m_ERK);
}

void BOTAN_FN_ISA_AVX512_GFNI ARIA_256::aria_avx512_gfni_decrypt(const uint8_t in[],
                                                                 uint8_t out[],
                                                                 size_t blocks) const {
   ARIA_AVX512::aria_transform(in, out, blocks, m_DRK);
}

}  // namespace Botan
