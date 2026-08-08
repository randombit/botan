/*
* (C) 2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_SIMD_HWAES_H_
#define BOTAN_SIMD_HWAES_H_

#include <botan/internal/gfni_utils.h>
#include <botan/internal/isa_extn.h>
#include <botan/internal/simd_4x32.h>
#include <wmmintrin.h>

namespace Botan {

/**
* Apply the AES S-box to each byte of the input vector.
*/
inline SIMD_4x32 BOTAN_FN_ISA_HWAES hw_aes_sbox(SIMD_4x32 x) {
   // Undo the ShiftRows with a byte shuffle implementing InvShiftRows
   const auto inv_sr = SIMD_4x32(0x070A0D00, 0x0B0E0104, 0x0F020508, 0x0306090C);

#if defined(BOTAN_TARGET_ARCH_IS_X86_FAMILY)
   auto enc = SIMD_4x32(_mm_aesenclast_si128(x.raw(), _mm_setzero_si128()));
#elif defined(BOTAN_TARGET_ARCH_IS_ARM64)
   auto enc = SIMD_4x32(vreinterpretq_u32_u8(vaeseq_u8(vreinterpretq_u8_u32(x.raw()), vdupq_n_u8(0))));
#else
   #error "hw_aes_sbox not implemented for this architecture"
#endif

   return SIMD_4x32::byte_shuffle(enc, inv_sr);
}

/**
* Apply the AES inverse S-box to each byte of the input vector.
*/
inline SIMD_4x32 BOTAN_FN_ISA_HWAES hw_aes_inv_sbox(SIMD_4x32 x) {
   // Undo the InvShiftRows with a byte shuffle implementing ShiftRows
   const auto sr = SIMD_4x32(0x0F0A0500, 0x030E0904, 0x07020D08, 0x0B06010C);

#if defined(BOTAN_TARGET_ARCH_IS_X86_FAMILY)
   auto dec = SIMD_4x32(_mm_aesdeclast_si128(x.raw(), _mm_setzero_si128()));
#elif defined(BOTAN_TARGET_ARCH_IS_ARM64)
   auto dec = SIMD_4x32(vreinterpretq_u32_u8(vaesdq_u8(vreinterpretq_u8_u32(x.raw()), vdupq_n_u8(0))));
#else
   #error "hw_aes_inv_sbox not implemented for this architecture"
#endif

   return SIMD_4x32::byte_shuffle(dec, sr);
}

namespace detail {

/*
* GF(2) matrix-vector multiply: returns M*x where M is a GFNI matrix
* and x is an 8-bit vector. Both use GFNI bit numbering convention.
*/
consteval uint8_t gf2_mat_vec(uint64_t M, uint8_t x) {
   uint8_t result = 0;
   for(size_t i = 0; i != 8; ++i) {
      uint8_t bit = 0;
      for(size_t j = 0; j != 8; ++j) {
         if(((M >> (56 - 8 * i + j)) & 1) == 1) {
            bit ^= (x >> j) & 1;
         }
      }
      result |= bit << i;
   }
   return result;
}

/*
* GF(2) 8x8 matrix multiplication: returns A*B in GFNI format.
*/
consteval uint64_t gf2_mat_mul(uint64_t A, uint64_t B) {
   uint64_t result = 0;
   for(size_t i = 0; i != 8; ++i) {
      for(size_t j = 0; j != 8; ++j) {
         uint8_t bit = 0;
         for(size_t k = 0; k != 8; ++k) {
            auto a_ik = static_cast<uint8_t>((A >> (56 - 8 * i + k)) & 1);
            auto b_kj = static_cast<uint8_t>((B >> (56 - 8 * k + j)) & 1);
            bit ^= a_ik & b_kj;
         }
         if(bit != 0) {
            result |= uint64_t(1) << (56 - 8 * i + j);
         }
      }
   }
   return result;
}

// AES affine matrix in GFNI format
constexpr uint64_t AES_AFF = gfni_matrix(R"(
   1 0 0 0 1 1 1 1
   1 1 0 0 0 1 1 1
   1 1 1 0 0 0 1 1
   1 1 1 1 0 0 0 1
   1 1 1 1 1 0 0 0
   0 1 1 1 1 1 0 0
   0 0 1 1 1 1 1 0
   0 0 0 1 1 1 1 1)");
constexpr uint8_t AES_C = 0x63;

// AES inverse affine matrix in GFNI format
constexpr uint64_t AES_AFF_INV = gfni_matrix(R"(
   0 0 1 0 0 1 0 1
   1 0 0 1 0 0 1 0
   0 1 0 0 1 0 0 1
   1 0 1 0 0 1 0 0
   0 1 0 1 0 0 1 0
   0 0 1 0 1 0 0 1
   1 0 0 1 0 1 0 0
   0 1 0 0 1 0 1 0)");
constexpr uint8_t AES_C_INV = 0x05;

}  // namespace detail

/**
* Lookup tables for GF(2) affine transformations
*/
class Gf2AffineTransformation final {
   public:
      consteval Gf2AffineTransformation(uint64_t M, uint8_t c) : lo{}, hi{} {
         for(size_t i = 0; i != 16; ++i) {
            // Low nibble table includes the constant addition
            const uint8_t lo_val = detail::gf2_mat_vec(M, static_cast<uint8_t>(i)) ^ c;
            const uint8_t hi_val = detail::gf2_mat_vec(M, static_cast<uint8_t>(i << 4));

            lo[i / 4] |= static_cast<uint32_t>(lo_val) << (8 * (i % 4));
            hi[i / 4] |= static_cast<uint32_t>(hi_val) << (8 * (i % 4));
         }
      }

      /**
      * Derive tables used for computing an affine transform after the application of an
      * AES sbox.
      */
      static consteval Gf2AffineTransformation post_sbox(uint64_t M, uint8_t c) {
         const auto comb_M = detail::gf2_mat_mul(M, detail::AES_AFF_INV);
         const auto comb_c = static_cast<uint8_t>(detail::gf2_mat_vec(comb_M, detail::AES_C) ^ c);
         return Gf2AffineTransformation(comb_M, comb_c);
      }

      /**
      * Derive tables used for computing an affine transform after the application of an
      * AES inverse sbox.
      */
      static consteval Gf2AffineTransformation post_inv_sbox(uint64_t M, uint8_t c) {
         const auto comb_mat = detail::gf2_mat_mul(detail::AES_AFF, M);
         const auto comb_c = detail::gf2_mat_vec(detail::AES_AFF, static_cast<uint8_t>(c ^ detail::AES_C_INV));
         return Gf2AffineTransformation(comb_mat, comb_c);
      }

      inline SIMD_4x32 BOTAN_FN_ISA_HWAES affine_transform(SIMD_4x32 x) const {
         const SIMD_4x32 tbl_lo(lo[0], lo[1], lo[2], lo[3]);
         const SIMD_4x32 tbl_hi(hi[0], hi[1], hi[2], hi[3]);
         const auto lo_mask = SIMD_4x32::splat_u8(0x0F);

         return SIMD_4x32::byte_shuffle(tbl_lo, lo_mask & x) ^ SIMD_4x32::byte_shuffle(tbl_hi, lo_mask & x.shr<4>());
      }

   private:
      uint32_t lo[4];
      uint32_t hi[4];
};

}  // namespace Botan

#endif
