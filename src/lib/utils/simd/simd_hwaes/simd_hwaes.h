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

#if defined(BOTAN_SIMD_USE_SSSE3)
   #include <wmmintrin.h>
#endif

#if defined(BOTAN_TARGET_ARCH_IS_PPC64)
   #include <bit>
#endif

namespace Botan {

#if defined(BOTAN_TARGET_ARCH_IS_PPC64)

namespace detail {

   // The vector type taken by the POWER crypto builtins differs between compilers
   #if defined(__clang__)
using HwAesVec = __vector unsigned char;
   #else
using HwAesVec = __vector unsigned long long;
   #endif

inline HwAesVec BOTAN_FN_ISA_HWAES hw_aes_vec(SIMD_4x32 x) {
   return reinterpret_cast<HwAesVec>(x.raw());
}

inline SIMD_4x32 BOTAN_FN_ISA_HWAES hw_aes_simd(HwAesVec x) {
   return SIMD_4x32(reinterpret_cast<__vector unsigned int>(x));
}

// POWER numbers the AES state bytes from the most significant end of the register
inline __vector unsigned char BOTAN_FN_ISA_HWAES hw_aes_state_order(__vector unsigned char v) {
   if constexpr(std::endian::native == std::endian::little) {
      const __vector unsigned char rev = {15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0};
      return vec_perm(v, v, rev);
   } else {
      return v;
   }
}

}  // namespace detail

#endif

/**
* Apply the AES S-box to each byte of the input vector.
*/
inline SIMD_4x32 BOTAN_FN_ISA_HWAES hw_aes_sbox(SIMD_4x32 x) {
#if defined(BOTAN_TARGET_ARCH_IS_PPC64)
   // vsbox is SubBytes alone so no shuffle is required
   return detail::hw_aes_simd(__builtin_crypto_vsbox(detail::hw_aes_vec(x)));
#else
   // Undo the ShiftRows with a byte shuffle implementing InvShiftRows
   const auto inv_sr = SIMD_4x32(0x070A0D00, 0x0B0E0104, 0x0F020508, 0x0306090C);

   #if defined(BOTAN_TARGET_ARCH_IS_X86_FAMILY)
   const auto enc = SIMD_4x32(_mm_aesenclast_si128(x.raw(), _mm_setzero_si128()));
   #elif defined(BOTAN_TARGET_ARCH_IS_ARM64)
   const auto enc = SIMD_4x32(vreinterpretq_u32_u8(vaeseq_u8(vreinterpretq_u8_u32(x.raw()), vdupq_n_u8(0))));
   #else
      #error "hw_aes_sbox not implemented for this architecture"
   #endif

   return SIMD_4x32::byte_shuffle(enc, inv_sr);
#endif
}

/**
* Apply the AES inverse S-box to each byte of the input vector.
*/
inline SIMD_4x32 BOTAN_FN_ISA_HWAES hw_aes_inv_sbox(SIMD_4x32 x) {
#if defined(BOTAN_TARGET_ARCH_IS_PPC64)
   /*
   * Undo the InvShiftRows with a byte shuffle implementing ShiftRows. POWER
   * numbers the AES state bytes starting from the most significant byte of the
   * register, so the indices differ from x86/ARM and depend on endianness.
   */
   const auto sr = (std::endian::native == std::endian::little)
                      ? SIMD_4x32(0x030E0904, 0x07020D08, 0x0B06010C, 0x0F0A0500)
                      : SIMD_4x32(0x0306090C, 0x070A0D00, 0x0B0E0104, 0x0F020508);
#else
   // Undo the InvShiftRows with a byte shuffle implementing ShiftRows
   const auto sr = SIMD_4x32(0x0F0A0500, 0x030E0904, 0x07020D08, 0x0B06010C);
#endif

#if defined(BOTAN_TARGET_ARCH_IS_X86_FAMILY)
   const auto dec = SIMD_4x32(_mm_aesdeclast_si128(x.raw(), _mm_setzero_si128()));
#elif defined(BOTAN_TARGET_ARCH_IS_ARM64)
   const auto dec = SIMD_4x32(vreinterpretq_u32_u8(vaesdq_u8(vreinterpretq_u8_u32(x.raw()), vdupq_n_u8(0))));
#elif defined(BOTAN_TARGET_ARCH_IS_PPC64)
   const auto dec =
      detail::hw_aes_simd(__builtin_crypto_vncipherlast(detail::hw_aes_vec(x), detail::hw_aes_vec(SIMD_4x32())));
#else
   #error "hw_aes_inv_sbox not implemented for this architecture"
#endif

   return SIMD_4x32::byte_shuffle(dec, sr);
}

/**
* Compute SubBytes(x) ^ k for a vector x whose four 32-bit words are all equal
*
* ShiftRows is the identity on such a vector, so this is exactly what the final
* round instruction computes. The AES key schedule uses it to apply SubWord to a
* broadcast word, with k carrying the round constant.
*/
inline SIMD_4x32 BOTAN_FN_ISA_HWAES hw_aes_sbox_splat(SIMD_4x32 x, SIMD_4x32 k) {
#if defined(BOTAN_TARGET_ARCH_IS_X86_FAMILY)
   return SIMD_4x32(_mm_aesenclast_si128(x.raw(), k.raw()));
#elif defined(BOTAN_TARGET_ARCH_IS_ARM64)
   // AESE adds its key before SubBytes so k is added afterwards instead
   return SIMD_4x32(vreinterpretq_u32_u8(vaeseq_u8(vreinterpretq_u8_u32(x.raw()), vdupq_n_u8(0)))) ^ k;
#elif defined(BOTAN_TARGET_ARCH_IS_PPC64)
   return detail::hw_aes_simd(__builtin_crypto_vcipherlast(detail::hw_aes_vec(x), detail::hw_aes_vec(k)));
#else
   #error "hw_aes_sbox_splat not implemented for this architecture"
#endif
}

/**
* True if the round instructions add the round key before SubBytes, as on
* ARMv8, rather than after MixColumns as on x86 and POWER
*/
#if defined(BOTAN_TARGET_ARCH_IS_ARM64)
constexpr bool HwAesKeyFirst = true;
#else
constexpr bool HwAesKeyFirst = false;
#endif

/**
* Load a block in the byte order the AES round instructions operate on
*/
inline SIMD_4x32 BOTAN_FN_ISA_HWAES hw_aes_load_block(const uint8_t in[16]) {
#if defined(BOTAN_TARGET_ARCH_IS_PPC64)
   return SIMD_4x32(reinterpret_cast<__vector unsigned int>(detail::hw_aes_state_order(vec_xl(0, in))));
#else
   return SIMD_4x32::load_le(in);
#endif
}

/**
* Store a block produced by the AES round instructions
*/
inline void BOTAN_FN_ISA_HWAES hw_aes_store_block(SIMD_4x32 B, uint8_t out[16]) {
#if defined(BOTAN_TARGET_ARCH_IS_PPC64)
   vec_xst(detail::hw_aes_state_order(reinterpret_cast<__vector unsigned char>(B.raw())), 0, out);
#else
   B.store_le(out);
#endif
}

/**
* One encryption round, adding the round key where HwAesKeyFirst says
*/
inline SIMD_4x32 BOTAN_FN_ISA_HWAES hw_aes_enc_round(SIMD_4x32 B, SIMD_4x32 K) {
#if defined(BOTAN_TARGET_ARCH_IS_X86_FAMILY)
   return SIMD_4x32(_mm_aesenc_si128(B.raw(), K.raw()));
#elif defined(BOTAN_TARGET_ARCH_IS_ARM64)
   return SIMD_4x32(
      vreinterpretq_u32_u8(vaesmcq_u8(vaeseq_u8(vreinterpretq_u8_u32(B.raw()), vreinterpretq_u8_u32(K.raw())))));
#elif defined(BOTAN_TARGET_ARCH_IS_PPC64)
   return detail::hw_aes_simd(__builtin_crypto_vcipher(detail::hw_aes_vec(B), detail::hw_aes_vec(K)));
#else
   #error "hw_aes_enc_round not implemented for this architecture"
#endif
}

/**
* The final encryption round, which omits MixColumns
*/
inline SIMD_4x32 BOTAN_FN_ISA_HWAES hw_aes_enc_last_round(SIMD_4x32 B, SIMD_4x32 K) {
#if defined(BOTAN_TARGET_ARCH_IS_X86_FAMILY)
   return SIMD_4x32(_mm_aesenclast_si128(B.raw(), K.raw()));
#elif defined(BOTAN_TARGET_ARCH_IS_ARM64)
   return SIMD_4x32(vreinterpretq_u32_u8(vaeseq_u8(vreinterpretq_u8_u32(B.raw()), vreinterpretq_u8_u32(K.raw()))));
#elif defined(BOTAN_TARGET_ARCH_IS_PPC64)
   return detail::hw_aes_simd(__builtin_crypto_vcipherlast(detail::hw_aes_vec(B), detail::hw_aes_vec(K)));
#else
   #error "hw_aes_enc_last_round not implemented for this architecture"
#endif
}

/**
* One decryption round, taking a round key prepared by hw_aes_dec_round_key
*/
inline SIMD_4x32 BOTAN_FN_ISA_HWAES hw_aes_dec_round(SIMD_4x32 B, SIMD_4x32 K) {
#if defined(BOTAN_TARGET_ARCH_IS_X86_FAMILY)
   return SIMD_4x32(_mm_aesdec_si128(B.raw(), K.raw()));
#elif defined(BOTAN_TARGET_ARCH_IS_ARM64)
   return SIMD_4x32(
      vreinterpretq_u32_u8(vaesimcq_u8(vaesdq_u8(vreinterpretq_u8_u32(B.raw()), vreinterpretq_u8_u32(K.raw())))));
#elif defined(BOTAN_TARGET_ARCH_IS_PPC64)
   return detail::hw_aes_simd(__builtin_crypto_vncipher(detail::hw_aes_vec(B), detail::hw_aes_vec(K)));
#else
   #error "hw_aes_dec_round not implemented for this architecture"
#endif
}

/**
* The final decryption round, which omits InvMixColumns
*/
inline SIMD_4x32 BOTAN_FN_ISA_HWAES hw_aes_dec_last_round(SIMD_4x32 B, SIMD_4x32 K) {
#if defined(BOTAN_TARGET_ARCH_IS_X86_FAMILY)
   return SIMD_4x32(_mm_aesdeclast_si128(B.raw(), K.raw()));
#elif defined(BOTAN_TARGET_ARCH_IS_ARM64)
   return SIMD_4x32(vreinterpretq_u32_u8(vaesdq_u8(vreinterpretq_u8_u32(B.raw()), vreinterpretq_u8_u32(K.raw()))));
#elif defined(BOTAN_TARGET_ARCH_IS_PPC64)
   return detail::hw_aes_simd(__builtin_crypto_vncipherlast(detail::hw_aes_vec(B), detail::hw_aes_vec(K)));
#else
   #error "hw_aes_dec_last_round not implemented for this architecture"
#endif
}

/**
* Convert an inner encryption round key to the form hw_aes_dec_round takes
*
* x86 and ARMv8 implement the equivalent inverse cipher, which needs
* InvMixColumns applied to the inner round keys. POWER's vncipher implements
* the standard inverse cipher and takes the encryption round keys unchanged.
*/
inline SIMD_4x32 BOTAN_FN_ISA_HWAES hw_aes_dec_round_key(SIMD_4x32 K) {
#if defined(BOTAN_TARGET_ARCH_IS_X86_FAMILY)
   return SIMD_4x32(_mm_aesimc_si128(K.raw()));
#elif defined(BOTAN_TARGET_ARCH_IS_ARM64)
   return SIMD_4x32(vreinterpretq_u32_u8(vaesimcq_u8(vreinterpretq_u8_u32(K.raw()))));
#elif defined(BOTAN_TARGET_ARCH_IS_PPC64)
   return K;
#else
   #error "hw_aes_dec_round_key not implemented for this architecture"
#endif
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
