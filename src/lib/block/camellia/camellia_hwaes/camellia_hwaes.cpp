/*
* (C) 2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/camellia.h>

#include <botan/mem_ops.h>
#include <botan/internal/simd_hwaes.h>

namespace Botan {

namespace Camellia_HWAES {

namespace {

/* Helpers for 64-bit operations on SIMD_4x32 */

BOTAN_FORCE_INLINE BOTAN_FN_ISA_HWAES SIMD_4x32 load_be64(const uint8_t* in) {
   const auto bswap64 = SIMD_4x32(0x04050607, 0x00010203, 0x0C0D0E0F, 0x08090A0B);
   return SIMD_4x32::byte_shuffle(SIMD_4x32::load_le(in), bswap64);
}

BOTAN_FORCE_INLINE BOTAN_FN_ISA_HWAES void store_be64(uint8_t* out, SIMD_4x32 v) {
   const auto bswap64 = SIMD_4x32(0x04050607, 0x00010203, 0x0C0D0E0F, 0x08090A0B);
   SIMD_4x32::byte_shuffle(v, bswap64).store_le(out);
}

BOTAN_FORCE_INLINE BOTAN_FN_ISA_HWAES SIMD_4x32 splat64(uint64_t v) {
   const uint32_t lo = static_cast<uint32_t>(v);
   const uint32_t hi = static_cast<uint32_t>(v >> 32);
   return SIMD_4x32(lo, hi, lo, hi);
}

/* The Camellia round function */
BOTAN_FORCE_INLINE BOTAN_FN_ISA_HWAES SIMD_4x32 camellia_f(SIMD_4x32 x) {
   // Pre-affine shared by S1/S2/S3
   constexpr uint64_t pre123_a = gfni_matrix(R"(
      1 1 1 0 1 1 0 1
      0 0 1 1 0 0 1 0
      1 1 0 1 0 0 0 0
      1 0 1 1 0 0 1 1
      0 0 0 0 1 1 0 0
      1 0 1 0 0 1 0 0
      0 0 1 0 1 1 0 0
      1 0 0 0 0 1 1 0)");

   // Pre-affine for S4
   constexpr uint64_t pre4_a = gfni_matrix(R"(
      1 1 0 1 1 0 1 1
      0 1 1 0 0 1 0 0
      1 0 1 0 0 0 0 1
      0 1 1 0 0 1 1 1
      0 0 0 1 1 0 0 0
      0 1 0 0 1 0 0 1
      0 1 0 1 1 0 0 0
      0 0 0 0 1 1 0 1)");

   constexpr uint8_t pre_c = 0x45;

   // Post-affine for S1 and S4
   constexpr uint64_t post14_a = gfni_matrix(R"(
      0 0 0 0 0 0 0 1
      0 1 1 0 0 1 1 0
      1 0 1 1 1 1 1 0
      0 0 0 1 1 0 1 1
      1 0 0 0 1 1 1 0
      0 1 0 1 1 1 1 0
      0 1 1 1 1 1 1 1
      0 0 0 1 1 1 0 0)");
   constexpr uint8_t post14_c = 0x6E;

   // Post-affine for S2
   constexpr uint64_t post2_a = gfni_matrix(R"(
      0 0 0 1 1 1 0 0
      0 0 0 0 0 0 0 1
      0 1 1 0 0 1 1 0
      1 0 1 1 1 1 1 0
      0 0 0 1 1 0 1 1
      1 0 0 0 1 1 1 0
      0 1 0 1 1 1 1 0
      0 1 1 1 1 1 1 1)");
   constexpr uint8_t post2_c = 0xDC;

   // Post-affine for S3
   constexpr uint64_t post3_a = gfni_matrix(R"(
      0 1 1 0 0 1 1 0
      1 0 1 1 1 1 1 0
      0 0 0 1 1 0 1 1
      1 0 0 0 1 1 1 0
      0 1 0 1 1 1 1 0
      0 1 1 1 1 1 1 1
      0 0 0 1 1 1 0 0
      0 0 0 0 0 0 0 1)");
   constexpr uint8_t post3_c = 0x37;

   constexpr auto PRE123 = Gf2AffineTransformation(pre123_a, pre_c);
   constexpr auto PRE4 = Gf2AffineTransformation(pre4_a, pre_c);
   constexpr auto POST14 = Gf2AffineTransformation::post_sbox(post14_a, post14_c);
   constexpr auto POST2 = Gf2AffineTransformation::post_sbox(post2_a, post2_c);
   constexpr auto POST3 = Gf2AffineTransformation::post_sbox(post3_a, post3_c);

   const auto mask_s2 = SIMD_4x32(0xFF000000, 0x00FF0000, 0xFF000000, 0x00FF0000);
   const auto mask_s3 = SIMD_4x32(0x00FF0000, 0x0000FF00, 0x00FF0000, 0x0000FF00);
   const auto mask_s4 = SIMD_4x32(0x0000FF00, 0x000000FF, 0x0000FF00, 0x000000FF);

   const auto pre123 = PRE123.affine_transform(x);
   const auto pre4 = PRE4.affine_transform(x);

   const auto sub = hw_aes_sbox(SIMD_4x32::byte_blend(mask_s4, pre4, pre123));

   const auto s14 = POST14.affine_transform(sub);
   const auto s2 = POST2.affine_transform(sub);
   const auto s3 = POST3.affine_transform(sub);

   // Final merged Sbox output for all bytes
   const auto sbox = SIMD_4x32::byte_blend(mask_s3, s3, SIMD_4x32::byte_blend(mask_s2, s2, s14));

   // The linear mixing step
   const auto P1 = SIMD_4x32(0x00000001, 0x00000001, 0x08080809, 0x08080809);
   const auto P2 = SIMD_4x32(0x01010202, 0x01010202, 0x09090A0A, 0x09090A0A);
   const auto P3 = SIMD_4x32(0x02030303, 0x02030303, 0x0A0B0B0B, 0x0A0B0B0B);
   const auto P4 = SIMD_4x32(0x06050404, 0x04040504, 0x0E0D0C0C, 0x0C0C0D0C);
   const auto P5 = SIMD_4x32(0x07060507, 0x05060605, 0x0F0E0D0F, 0x0D0E0E0D);
   const auto P6 = SIMD_4x32(0xFFFFFFFF, 0x07070706, 0xFFFFFFFF, 0x0F0F0F0E);

   const auto sxp1 = SIMD_4x32::byte_shuffle(sbox, P1);
   const auto sxp2 = SIMD_4x32::byte_shuffle(sbox, P2);
   const auto sxp3 = SIMD_4x32::byte_shuffle(sbox, P3);
   const auto sxp4 = SIMD_4x32::byte_shuffle(sbox, P4);
   const auto sxp5 = SIMD_4x32::byte_shuffle(sbox, P5);
   const auto sxp6 = SIMD_4x32::byte_shuffle(sbox, P6);

   return (sxp1 ^ sxp2 ^ sxp3 ^ sxp4 ^ sxp5 ^ sxp6);
}

/*
* FL and FL-inverse operate on 32-bit sub-halves within each 64-bit element.
* We use byte_shuffle to broadcast each 32-bit half, then recombine with byte_blend.
*/
BOTAN_FORCE_INLINE BOTAN_FN_ISA_HWAES SIMD_4x32 FL_2(SIMD_4x32 v, uint64_t K) {
   const uint32_t k1 = static_cast<uint32_t>(K >> 32);
   const uint32_t k2 = static_cast<uint32_t>(K);

   // Broadcast upper/lower 32-bit halves of each 64-bit element
   const auto shuf_hi = SIMD_4x32(0x07060504, 0x07060504, 0x0F0E0D0C, 0x0F0E0D0C);
   const auto shuf_lo = SIMD_4x32(0x03020100, 0x03020100, 0x0B0A0908, 0x0B0A0908);

   auto x1 = SIMD_4x32::byte_shuffle(v, shuf_hi);
   auto x2 = SIMD_4x32::byte_shuffle(v, shuf_lo);

   x2 ^= (x1 & SIMD_4x32::splat(k1)).rotl<1>();
   x1 ^= x2 | SIMD_4x32::splat(k2);

   // Recombine: lo from x2, hi from x1
   const auto mask_hi = SIMD_4x32(0x00000000, 0xFFFFFFFF, 0x00000000, 0xFFFFFFFF);
   return SIMD_4x32::byte_blend(mask_hi, x1, x2);
}

BOTAN_FORCE_INLINE BOTAN_FN_ISA_HWAES SIMD_4x32 FLINV_2(SIMD_4x32 v, uint64_t K) {
   const uint32_t k1 = static_cast<uint32_t>(K >> 32);
   const uint32_t k2 = static_cast<uint32_t>(K);

   const auto shuf_hi = SIMD_4x32(0x07060504, 0x07060504, 0x0F0E0D0C, 0x0F0E0D0C);
   const auto shuf_lo = SIMD_4x32(0x03020100, 0x03020100, 0x0B0A0908, 0x0B0A0908);

   auto x1 = SIMD_4x32::byte_shuffle(v, shuf_hi);
   auto x2 = SIMD_4x32::byte_shuffle(v, shuf_lo);

   x1 ^= x2 | SIMD_4x32::splat(k2);
   x2 ^= (x1 & SIMD_4x32::splat(k1)).rotl<1>();

   const auto mask_hi = SIMD_4x32(0x00000000, 0xFFFFFFFF, 0x00000000, 0xFFFFFFFF);
   return SIMD_4x32::byte_blend(mask_hi, x1, x2);
}

BOTAN_FORCE_INLINE BOTAN_FN_ISA_HWAES void load_and_deinterleave(const uint8_t in[], SIMD_4x32& L, SIMD_4x32& R) {
   const auto A = load_be64(in);       // block 0: [L0, R0]
   const auto B = load_be64(in + 16);  // block 1: [L1, R1]
   const auto mask_upper = SIMD_4x32(0x00000000, 0x00000000, 0xFFFFFFFF, 0xFFFFFFFF);
   L = SIMD_4x32::byte_blend(mask_upper, B.swap_halves(), A);  // [L0, L1]
   R = SIMD_4x32::byte_blend(mask_upper, B, A.swap_halves());  // [R0, R1]
}

BOTAN_FORCE_INLINE BOTAN_FN_ISA_HWAES void interleave_and_store(uint8_t out[], SIMD_4x32 L, SIMD_4x32 R) {
   // Camellia output swaps L and R
   const auto mask_upper = SIMD_4x32(0x00000000, 0x00000000, 0xFFFFFFFF, 0xFFFFFFFF);
   const auto A = SIMD_4x32::byte_blend(mask_upper, L.swap_halves(), R);  // [R0, L0]
   const auto B = SIMD_4x32::byte_blend(mask_upper, L, R.swap_halves());  // [R1, L1]
   store_be64(out, A);
   store_be64(out + 16, B);
}

BOTAN_FORCE_INLINE BOTAN_FN_ISA_HWAES void six_e_rounds(SIMD_4x32& L, SIMD_4x32& R, const uint64_t SK[]) {
   R ^= camellia_f(L ^ splat64(SK[0]));
   L ^= camellia_f(R ^ splat64(SK[1]));
   R ^= camellia_f(L ^ splat64(SK[2]));
   L ^= camellia_f(R ^ splat64(SK[3]));
   R ^= camellia_f(L ^ splat64(SK[4]));
   L ^= camellia_f(R ^ splat64(SK[5]));
}

BOTAN_FORCE_INLINE BOTAN_FN_ISA_HWAES void six_d_rounds(SIMD_4x32& L, SIMD_4x32& R, const uint64_t SK[]) {
   R ^= camellia_f(L ^ splat64(SK[5]));
   L ^= camellia_f(R ^ splat64(SK[4]));
   R ^= camellia_f(L ^ splat64(SK[3]));
   L ^= camellia_f(R ^ splat64(SK[2]));
   R ^= camellia_f(L ^ splat64(SK[1]));
   L ^= camellia_f(R ^ splat64(SK[0]));
}

BOTAN_FN_ISA_HWAES void camellia_encrypt_x2_18r(const uint8_t in[], uint8_t out[], std::span<const uint64_t> SK) {
   SIMD_4x32 L;
   SIMD_4x32 R;
   load_and_deinterleave(in, L, R);

   L ^= splat64(SK[0]);
   R ^= splat64(SK[1]);

   six_e_rounds(L, R, &SK[2]);
   L = FL_2(L, SK[8]);
   R = FLINV_2(R, SK[9]);
   six_e_rounds(L, R, &SK[10]);
   L = FL_2(L, SK[16]);
   R = FLINV_2(R, SK[17]);
   six_e_rounds(L, R, &SK[18]);

   R ^= splat64(SK[24]);
   L ^= splat64(SK[25]);

   interleave_and_store(out, L, R);
}

BOTAN_FN_ISA_HWAES void camellia_decrypt_x2_18r(const uint8_t in[], uint8_t out[], std::span<const uint64_t> SK) {
   SIMD_4x32 L;
   SIMD_4x32 R;
   load_and_deinterleave(in, L, R);

   R ^= splat64(SK[25]);
   L ^= splat64(SK[24]);

   six_d_rounds(L, R, &SK[18]);
   L = FL_2(L, SK[17]);
   R = FLINV_2(R, SK[16]);
   six_d_rounds(L, R, &SK[10]);
   L = FL_2(L, SK[9]);
   R = FLINV_2(R, SK[8]);
   six_d_rounds(L, R, &SK[2]);

   L ^= splat64(SK[1]);
   R ^= splat64(SK[0]);

   interleave_and_store(out, L, R);
}

BOTAN_FN_ISA_HWAES void camellia_encrypt_x2_24r(const uint8_t in[], uint8_t out[], std::span<const uint64_t> SK) {
   SIMD_4x32 L;
   SIMD_4x32 R;
   load_and_deinterleave(in, L, R);

   L ^= splat64(SK[0]);
   R ^= splat64(SK[1]);

   six_e_rounds(L, R, &SK[2]);
   L = FL_2(L, SK[8]);
   R = FLINV_2(R, SK[9]);
   six_e_rounds(L, R, &SK[10]);
   L = FL_2(L, SK[16]);
   R = FLINV_2(R, SK[17]);
   six_e_rounds(L, R, &SK[18]);
   L = FL_2(L, SK[24]);
   R = FLINV_2(R, SK[25]);
   six_e_rounds(L, R, &SK[26]);

   R ^= splat64(SK[32]);
   L ^= splat64(SK[33]);

   interleave_and_store(out, L, R);
}

BOTAN_FN_ISA_HWAES void camellia_decrypt_x2_24r(const uint8_t in[], uint8_t out[], std::span<const uint64_t> SK) {
   SIMD_4x32 L;
   SIMD_4x32 R;
   load_and_deinterleave(in, L, R);

   R ^= splat64(SK[33]);
   L ^= splat64(SK[32]);

   six_d_rounds(L, R, &SK[26]);
   L = FL_2(L, SK[25]);
   R = FLINV_2(R, SK[24]);
   six_d_rounds(L, R, &SK[18]);
   L = FL_2(L, SK[17]);
   R = FLINV_2(R, SK[16]);
   six_d_rounds(L, R, &SK[10]);
   L = FL_2(L, SK[9]);
   R = FLINV_2(R, SK[8]);
   six_d_rounds(L, R, &SK[2]);

   L ^= splat64(SK[1]);
   R ^= splat64(SK[0]);

   interleave_and_store(out, L, R);
}

}  // namespace

}  // namespace Camellia_HWAES

// static
void BOTAN_FN_ISA_HWAES Camellia_128::hwaes_encrypt(const uint8_t in[],
                                                    uint8_t out[],
                                                    size_t blocks,
                                                    std::span<const uint64_t> SK) {
   while(blocks >= 2) {
      Camellia_HWAES::camellia_encrypt_x2_18r(in, out, SK);
      in += 2 * 16;
      out += 2 * 16;
      blocks -= 2;
   }

   if(blocks > 0) {
      uint8_t ibuf[2 * 16] = {0};
      uint8_t obuf[2 * 16] = {0};
      copy_mem(ibuf, in, 16);
      Camellia_HWAES::camellia_encrypt_x2_18r(ibuf, obuf, SK);
      copy_mem(out, obuf, 16);
   }
}

// static
void BOTAN_FN_ISA_HWAES Camellia_128::hwaes_decrypt(const uint8_t in[],
                                                    uint8_t out[],
                                                    size_t blocks,
                                                    std::span<const uint64_t> SK) {
   while(blocks >= 2) {
      Camellia_HWAES::camellia_decrypt_x2_18r(in, out, SK);
      in += 2 * 16;
      out += 2 * 16;
      blocks -= 2;
   }

   if(blocks > 0) {
      uint8_t ibuf[2 * 16] = {0};
      uint8_t obuf[2 * 16] = {0};
      copy_mem(ibuf, in, 16);
      Camellia_HWAES::camellia_decrypt_x2_18r(ibuf, obuf, SK);
      copy_mem(out, obuf, 16);
   }
}

// static
void BOTAN_FN_ISA_HWAES Camellia_192::hwaes_encrypt(const uint8_t in[],
                                                    uint8_t out[],
                                                    size_t blocks,
                                                    std::span<const uint64_t> SK) {
   while(blocks >= 2) {
      Camellia_HWAES::camellia_encrypt_x2_24r(in, out, SK);
      in += 2 * 16;
      out += 2 * 16;
      blocks -= 2;
   }

   if(blocks > 0) {
      uint8_t ibuf[2 * 16] = {0};
      uint8_t obuf[2 * 16] = {0};
      copy_mem(ibuf, in, 16);
      Camellia_HWAES::camellia_encrypt_x2_24r(ibuf, obuf, SK);
      copy_mem(out, obuf, 16);
   }
}

// static
void BOTAN_FN_ISA_HWAES Camellia_192::hwaes_decrypt(const uint8_t in[],
                                                    uint8_t out[],
                                                    size_t blocks,
                                                    std::span<const uint64_t> SK) {
   while(blocks >= 2) {
      Camellia_HWAES::camellia_decrypt_x2_24r(in, out, SK);
      in += 2 * 16;
      out += 2 * 16;
      blocks -= 2;
   }

   if(blocks > 0) {
      uint8_t ibuf[2 * 16] = {0};
      uint8_t obuf[2 * 16] = {0};
      copy_mem(ibuf, in, 16);
      Camellia_HWAES::camellia_decrypt_x2_24r(ibuf, obuf, SK);
      copy_mem(out, obuf, 16);
   }
}

// static
void BOTAN_FN_ISA_HWAES Camellia_256::hwaes_encrypt(const uint8_t in[],
                                                    uint8_t out[],
                                                    size_t blocks,
                                                    std::span<const uint64_t> SK) {
   while(blocks >= 2) {
      Camellia_HWAES::camellia_encrypt_x2_24r(in, out, SK);
      in += 2 * 16;
      out += 2 * 16;
      blocks -= 2;
   }

   if(blocks > 0) {
      uint8_t ibuf[2 * 16] = {0};
      uint8_t obuf[2 * 16] = {0};
      copy_mem(ibuf, in, 16);
      Camellia_HWAES::camellia_encrypt_x2_24r(ibuf, obuf, SK);
      copy_mem(out, obuf, 16);
   }
}

// static
void BOTAN_FN_ISA_HWAES Camellia_256::hwaes_decrypt(const uint8_t in[],
                                                    uint8_t out[],
                                                    size_t blocks,
                                                    std::span<const uint64_t> SK) {
   while(blocks >= 2) {
      Camellia_HWAES::camellia_decrypt_x2_24r(in, out, SK);
      in += 2 * 16;
      out += 2 * 16;
      blocks -= 2;
   }

   if(blocks > 0) {
      uint8_t ibuf[2 * 16] = {0};
      uint8_t obuf[2 * 16] = {0};
      copy_mem(ibuf, in, 16);
      Camellia_HWAES::camellia_decrypt_x2_24r(ibuf, obuf, SK);
      copy_mem(out, obuf, 16);
   }
}

}  // namespace Botan
