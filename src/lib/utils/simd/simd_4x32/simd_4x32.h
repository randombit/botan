/*
* Lightweight wrappers for SIMD (4x32 bit) operations
* (C) 2009,2011,2016,2017,2019,2025 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_SIMD_4X32_H_
#define BOTAN_SIMD_4X32_H_

#include <botan/compiler.h>
#include <botan/types.h>
#include <botan/internal/isa_extn.h>
#include <botan/internal/target_info.h>
#include <span>

#if defined(BOTAN_TARGET_ARCH_SUPPORTS_SSSE3)
   #include <emmintrin.h>
   #include <tmmintrin.h>
   #define BOTAN_SIMD_USE_SSSE3

#elif defined(BOTAN_TARGET_ARCH_SUPPORTS_ALTIVEC)
   #include <botan/internal/loadstor.h>
   #include <altivec.h>
   #undef vector
   #undef bool
   #define BOTAN_SIMD_USE_ALTIVEC
   #ifdef __VSX__
      #define BOTAN_SIMD_USE_VSX
   #endif

#elif defined(BOTAN_TARGET_ARCH_SUPPORTS_NEON)
   #include <arm_neon.h>
   #include <bit>
   #define BOTAN_SIMD_USE_NEON

#elif defined(BOTAN_TARGET_ARCH_SUPPORTS_LSX)
   #include <lsxintrin.h>
   #define BOTAN_SIMD_USE_LSX

#else
   #error "No SIMD instruction set enabled"
#endif

namespace Botan {

#if defined(BOTAN_SIMD_USE_SSSE3) || defined(BOTAN_SIMD_USE_LSX)
using native_simd_type = __m128i;
#elif defined(BOTAN_SIMD_USE_ALTIVEC)
using native_simd_type = __vector unsigned int;
#elif defined(BOTAN_SIMD_USE_NEON)
using native_simd_type = uint32x4_t;
#endif

// NOLINTBEGIN(portability-simd-intrinsics)

/**
* 4x32 bit SIMD register
*
* This class is not a general purpose SIMD type, and only offers instructions
* needed for evaluation of specific crypto primitives. For example it does not
* currently have equality operators of any kind.
*
* Implemented for SSE2, VMX (Altivec), ARMv7/Aarch64 NEON, and LoongArch LSX
*/
class SIMD_4x32 final {
   public:
      SIMD_4x32& operator=(const SIMD_4x32& other) = default;
      SIMD_4x32(const SIMD_4x32& other) = default;

      SIMD_4x32& operator=(SIMD_4x32&& other) = default;
      SIMD_4x32(SIMD_4x32&& other) = default;

      ~SIMD_4x32() = default;

      /* NOLINTBEGIN(*-prefer-member-initializer) */

      /**
      * Zero initialize SIMD register with 4 32-bit elements
      */
      SIMD_4x32() noexcept {
#if defined(BOTAN_SIMD_USE_SSSE3)
         m_simd = _mm_setzero_si128();
#elif defined(BOTAN_SIMD_USE_ALTIVEC)
         m_simd = vec_splat_u32(0);
#elif defined(BOTAN_SIMD_USE_NEON)
         m_simd = vdupq_n_u32(0);
#elif defined(BOTAN_SIMD_USE_LSX)
         m_simd = __lsx_vldi(0);
#endif
      }

      /**
      * Load SIMD register with 4 32-bit elements
      */
      SIMD_4x32(uint32_t B0, uint32_t B1, uint32_t B2, uint32_t B3) noexcept {
#if defined(BOTAN_SIMD_USE_SSSE3)
         m_simd = _mm_set_epi32(B3, B2, B1, B0);
#elif defined(BOTAN_SIMD_USE_ALTIVEC)
         __vector unsigned int val = {B0, B1, B2, B3};
         m_simd = val;
#elif defined(BOTAN_SIMD_USE_NEON)
         // Better way to do this?
         const uint32_t B[4] = {B0, B1, B2, B3};
         m_simd = vld1q_u32(B);
#elif defined(BOTAN_SIMD_USE_LSX)
         // Better way to do this?
         const uint32_t B[4] = {B0, B1, B2, B3};
         m_simd = __lsx_vld(B, 0);
#endif
      }

      /* NOLINTEND(*-prefer-member-initializer) */

      /**
      * Load SIMD register with one 32-bit element repeated
      */
      static SIMD_4x32 splat(uint32_t B) noexcept {
#if defined(BOTAN_SIMD_USE_SSSE3)
         return SIMD_4x32(_mm_set1_epi32(B));
#elif defined(BOTAN_SIMD_USE_NEON)
         return SIMD_4x32(vdupq_n_u32(B));
#elif defined(BOTAN_SIMD_USE_LSX)
         return SIMD_4x32(__lsx_vreplgr2vr_w(B));
#else
         return SIMD_4x32(B, B, B, B);
#endif
      }

      /**
      * Load SIMD register with one 8-bit element repeated
      */
      static SIMD_4x32 splat_u8(uint8_t B) noexcept {
#if defined(BOTAN_SIMD_USE_SSSE3)
         return SIMD_4x32(_mm_set1_epi8(B));
#elif defined(BOTAN_SIMD_USE_NEON)
         return SIMD_4x32(vreinterpretq_u32_u8(vdupq_n_u8(B)));
#elif defined(BOTAN_SIMD_USE_LSX)
         return SIMD_4x32(__lsx_vreplgr2vr_b(B));
#else
         const uint32_t B4 = make_uint32(B, B, B, B);
         return SIMD_4x32(B4, B4, B4, B4);
#endif
      }

      /**
      * Load a SIMD register with little-endian convention
      */
      static SIMD_4x32 load_le(const void* in) noexcept {
#if defined(BOTAN_SIMD_USE_SSSE3)
         return SIMD_4x32(_mm_loadu_si128(reinterpret_cast<const __m128i*>(in)));
#elif defined(BOTAN_SIMD_USE_ALTIVEC)
         uint32_t R0 = Botan::load_le<uint32_t>(reinterpret_cast<const uint8_t*>(in), 0);
         uint32_t R1 = Botan::load_le<uint32_t>(reinterpret_cast<const uint8_t*>(in), 1);
         uint32_t R2 = Botan::load_le<uint32_t>(reinterpret_cast<const uint8_t*>(in), 2);
         uint32_t R3 = Botan::load_le<uint32_t>(reinterpret_cast<const uint8_t*>(in), 3);
         __vector unsigned int val = {R0, R1, R2, R3};
         return SIMD_4x32(val);
#elif defined(BOTAN_SIMD_USE_NEON)
         SIMD_4x32 l(vld1q_u32(static_cast<const uint32_t*>(in)));
         if constexpr(std::endian::native == std::endian::big) {
            return l.bswap();
         } else {
            return l;
         }
#elif defined(BOTAN_SIMD_USE_LSX)
         return SIMD_4x32(__lsx_vld(in, 0));
#endif
      }

      /**
      * Load a SIMD register with big-endian convention
      */
      static SIMD_4x32 BOTAN_FN_ISA_SIMD_4X32 load_be(const void* in) noexcept {
#if defined(BOTAN_SIMD_USE_SSSE3) || defined(BOTAN_SIMD_USE_LSX)
         return load_le(in).bswap();

#elif defined(BOTAN_SIMD_USE_ALTIVEC)
         uint32_t R0 = Botan::load_be<uint32_t>(reinterpret_cast<const uint8_t*>(in), 0);
         uint32_t R1 = Botan::load_be<uint32_t>(reinterpret_cast<const uint8_t*>(in), 1);
         uint32_t R2 = Botan::load_be<uint32_t>(reinterpret_cast<const uint8_t*>(in), 2);
         uint32_t R3 = Botan::load_be<uint32_t>(reinterpret_cast<const uint8_t*>(in), 3);
         __vector unsigned int val = {R0, R1, R2, R3};
         return SIMD_4x32(val);

#elif defined(BOTAN_SIMD_USE_NEON)
         SIMD_4x32 l(vld1q_u32(static_cast<const uint32_t*>(in)));
         if constexpr(std::endian::native == std::endian::little) {
            return l.bswap();
         } else {
            return l;
         }
#endif
      }

      static SIMD_4x32 load_le(std::span<const uint8_t, 16> in) { return SIMD_4x32::load_le(in.data()); }

      static SIMD_4x32 load_be(std::span<const uint8_t, 16> in) { return SIMD_4x32::load_be(in.data()); }

      void store_le(uint32_t out[4]) const noexcept { this->store_le(reinterpret_cast<uint8_t*>(out)); }

      void store_be(uint32_t out[4]) const noexcept { this->store_be(reinterpret_cast<uint8_t*>(out)); }

      void store_le(uint64_t out[2]) const noexcept { this->store_le(reinterpret_cast<uint8_t*>(out)); }

      /**
      * Load a SIMD register with little-endian convention
      */
      void store_le(uint8_t out[]) const noexcept {
#if defined(BOTAN_SIMD_USE_SSSE3)

         _mm_storeu_si128(reinterpret_cast<__m128i*>(out), raw());

#elif defined(BOTAN_SIMD_USE_ALTIVEC)

         union {
               __vector unsigned int V;
               uint32_t R[4];
         } vec{};

         // NOLINTNEXTLINE(*-union-access)
         vec.V = raw();
         // NOLINTNEXTLINE(*-union-access)
         Botan::store_le(out, vec.R[0], vec.R[1], vec.R[2], vec.R[3]);

#elif defined(BOTAN_SIMD_USE_NEON)
         if constexpr(std::endian::native == std::endian::little) {
            vst1q_u8(out, vreinterpretq_u8_u32(m_simd));
         } else {
            vst1q_u8(out, vreinterpretq_u8_u32(bswap().m_simd));
         }
#elif defined(BOTAN_SIMD_USE_LSX)
         __lsx_vst(raw(), out, 0);
#endif
      }

      /**
      * Load a SIMD register with big-endian convention
      */
      BOTAN_FN_ISA_SIMD_4X32 void store_be(uint8_t out[]) const noexcept {
#if defined(BOTAN_SIMD_USE_SSSE3) || defined(BOTAN_SIMD_USE_LSX)

         bswap().store_le(out);

#elif defined(BOTAN_SIMD_USE_ALTIVEC)

         union {
               __vector unsigned int V;
               uint32_t R[4];
         } vec{};

         // NOLINTNEXTLINE(*-union-access)
         vec.V = m_simd;
         // NOLINTNEXTLINE(*-union-access)
         Botan::store_be(out, vec.R[0], vec.R[1], vec.R[2], vec.R[3]);

#elif defined(BOTAN_SIMD_USE_NEON)
         if constexpr(std::endian::native == std::endian::little) {
            vst1q_u8(out, vreinterpretq_u8_u32(bswap().m_simd));
         } else {
            vst1q_u8(out, vreinterpretq_u8_u32(m_simd));
         }
#endif
      }

      void store_be(std::span<uint8_t, 16> out) const { this->store_be(out.data()); }

      void store_le(std::span<uint8_t, 16> out) const { this->store_le(out.data()); }

      /*
      * This is used for SHA-2/SHACAL2
      */
      SIMD_4x32 sigma0() const noexcept {
#if BOTAN_COMPILER_HAS_BUILTIN(__builtin_crypto_vshasigmaw) && defined(_ARCH_PWR8)
         return SIMD_4x32(__builtin_crypto_vshasigmaw(raw(), 1, 0));
#else
         const SIMD_4x32 r1 = this->rotr<2>();
         const SIMD_4x32 r2 = this->rotr<13>();
         const SIMD_4x32 r3 = this->rotr<22>();
         return (r1 ^ r2 ^ r3);
#endif
      }

      /*
      * This is used for SHA-2/SHACAL2
      */
      SIMD_4x32 sigma1() const noexcept {
#if BOTAN_COMPILER_HAS_BUILTIN(__builtin_crypto_vshasigmaw) && defined(_ARCH_PWR8)
         return SIMD_4x32(__builtin_crypto_vshasigmaw(raw(), 1, 0xF));
#else
         const SIMD_4x32 r1 = this->rotr<6>();
         const SIMD_4x32 r2 = this->rotr<11>();
         const SIMD_4x32 r3 = this->rotr<25>();
         return (r1 ^ r2 ^ r3);
#endif
      }

      /**
      * Left rotation by a compile time constant
      */
      template <size_t ROT>
      BOTAN_FN_ISA_SIMD_4X32 SIMD_4x32 rotl() const noexcept
         requires(ROT > 0 && ROT < 32)
      {
#if defined(BOTAN_SIMD_USE_SSSE3)
         if constexpr(ROT == 8) {
            const auto shuf_rotl_8 = _mm_set_epi64x(0x0e0d0c0f0a09080b, 0x0605040702010003);
            return SIMD_4x32(_mm_shuffle_epi8(raw(), shuf_rotl_8));
         } else if constexpr(ROT == 16) {
            const auto shuf_rotl_16 = _mm_set_epi64x(0x0d0c0f0e09080b0a, 0x0504070601000302);
            return SIMD_4x32(_mm_shuffle_epi8(raw(), shuf_rotl_16));
         } else if constexpr(ROT == 24) {
            const auto shuf_rotl_24 = _mm_set_epi64x(0x0c0f0e0d080b0a09, 0x0407060500030201);
            return SIMD_4x32(_mm_shuffle_epi8(raw(), shuf_rotl_24));
         } else {
            return SIMD_4x32(_mm_or_si128(_mm_slli_epi32(raw(), static_cast<int>(ROT)),
                                          _mm_srli_epi32(raw(), static_cast<int>(32 - ROT))));
         }

#elif defined(BOTAN_SIMD_USE_ALTIVEC)

         const unsigned int r = static_cast<unsigned int>(ROT);
         __vector unsigned int rot = {r, r, r, r};
         return SIMD_4x32(vec_rl(m_simd, rot));

#elif defined(BOTAN_SIMD_USE_NEON)

   #if defined(BOTAN_TARGET_ARCH_IS_ARM64)

         if constexpr(ROT == 8) {
            const uint8_t maskb[16] = {3, 0, 1, 2, 7, 4, 5, 6, 11, 8, 9, 10, 15, 12, 13, 14};
            const uint8x16_t mask = vld1q_u8(maskb);
            return SIMD_4x32(vreinterpretq_u32_u8(vqtbl1q_u8(vreinterpretq_u8_u32(m_simd), mask)));
         } else if constexpr(ROT == 16) {
            return SIMD_4x32(vreinterpretq_u32_u16(vrev32q_u16(vreinterpretq_u16_u32(m_simd))));
         }
   #endif
         return SIMD_4x32(
            vorrq_u32(vshlq_n_u32(m_simd, static_cast<int>(ROT)), vshrq_n_u32(m_simd, static_cast<int>(32 - ROT))));
#elif defined(BOTAN_SIMD_USE_LSX)
         return SIMD_4x32(__lsx_vrotri_w(raw(), 32 - ROT));
#endif
      }

      /**
      * Right rotation by a compile time constant
      */
      template <size_t ROT>
      SIMD_4x32 rotr() const noexcept {
         return this->rotl<32 - ROT>();
      }

      /**
      * Add elements of a SIMD vector
      */
      SIMD_4x32 operator+(const SIMD_4x32& other) const noexcept {
         SIMD_4x32 retval(*this);
         retval += other;
         return retval;
      }

      /**
      * Subtract elements of a SIMD vector
      */
      SIMD_4x32 operator-(const SIMD_4x32& other) const noexcept {
         SIMD_4x32 retval(*this);
         retval -= other;
         return retval;
      }

      /**
      * XOR elements of a SIMD vector
      */
      SIMD_4x32 operator^(const SIMD_4x32& other) const noexcept {
         SIMD_4x32 retval(*this);
         retval ^= other;
         return retval;
      }

      /**
      * Binary OR elements of a SIMD vector
      */
      SIMD_4x32 operator|(const SIMD_4x32& other) const noexcept {
         SIMD_4x32 retval(*this);
         retval |= other;
         return retval;
      }

      /**
      * Binary AND elements of a SIMD vector
      */
      SIMD_4x32 operator&(const SIMD_4x32& other) const noexcept {
         SIMD_4x32 retval(*this);
         retval &= other;
         return retval;
      }

      void operator+=(const SIMD_4x32& other) noexcept {
#if defined(BOTAN_SIMD_USE_SSSE3)
         m_simd = _mm_add_epi32(m_simd, other.m_simd);
#elif defined(BOTAN_SIMD_USE_ALTIVEC)
         m_simd = vec_add(m_simd, other.m_simd);
#elif defined(BOTAN_SIMD_USE_NEON)
         m_simd = vaddq_u32(m_simd, other.m_simd);
#elif defined(BOTAN_SIMD_USE_LSX)
         m_simd = __lsx_vadd_w(m_simd, other.m_simd);
#endif
      }

      void operator-=(const SIMD_4x32& other) noexcept {
#if defined(BOTAN_SIMD_USE_SSSE3)
         m_simd = _mm_sub_epi32(m_simd, other.m_simd);
#elif defined(BOTAN_SIMD_USE_ALTIVEC)
         m_simd = vec_sub(m_simd, other.m_simd);
#elif defined(BOTAN_SIMD_USE_NEON)
         m_simd = vsubq_u32(m_simd, other.m_simd);
#elif defined(BOTAN_SIMD_USE_LSX)
         m_simd = __lsx_vsub_w(m_simd, other.m_simd);
#endif
      }

      void operator^=(const SIMD_4x32& other) noexcept {
#if defined(BOTAN_SIMD_USE_SSSE3)
         m_simd = _mm_xor_si128(m_simd, other.m_simd);
#elif defined(BOTAN_SIMD_USE_ALTIVEC)
         m_simd = vec_xor(m_simd, other.m_simd);
#elif defined(BOTAN_SIMD_USE_NEON)
         m_simd = veorq_u32(m_simd, other.m_simd);
#elif defined(BOTAN_SIMD_USE_LSX)
         m_simd = __lsx_vxor_v(m_simd, other.m_simd);
#endif
      }

      void operator^=(uint32_t other) noexcept { *this ^= SIMD_4x32::splat(other); }

      void operator|=(const SIMD_4x32& other) noexcept {
#if defined(BOTAN_SIMD_USE_SSSE3)
         m_simd = _mm_or_si128(m_simd, other.m_simd);
#elif defined(BOTAN_SIMD_USE_ALTIVEC)
         m_simd = vec_or(m_simd, other.m_simd);
#elif defined(BOTAN_SIMD_USE_NEON)
         m_simd = vorrq_u32(m_simd, other.m_simd);
#elif defined(BOTAN_SIMD_USE_LSX)
         m_simd = __lsx_vor_v(m_simd, other.m_simd);
#endif
      }

      void operator&=(const SIMD_4x32& other) noexcept {
#if defined(BOTAN_SIMD_USE_SSSE3)
         m_simd = _mm_and_si128(m_simd, other.m_simd);
#elif defined(BOTAN_SIMD_USE_ALTIVEC)
         m_simd = vec_and(m_simd, other.m_simd);
#elif defined(BOTAN_SIMD_USE_NEON)
         m_simd = vandq_u32(m_simd, other.m_simd);
#elif defined(BOTAN_SIMD_USE_LSX)
         m_simd = __lsx_vand_v(m_simd, other.m_simd);
#endif
      }

      template <int SHIFT>
      SIMD_4x32 shl() const noexcept
         requires(SHIFT > 0 && SHIFT < 32)
      {
#if defined(BOTAN_SIMD_USE_SSSE3)
         return SIMD_4x32(_mm_slli_epi32(m_simd, SHIFT));

#elif defined(BOTAN_SIMD_USE_ALTIVEC)
         const unsigned int s = static_cast<unsigned int>(SHIFT);
         const __vector unsigned int shifts = {s, s, s, s};
         return SIMD_4x32(vec_sl(m_simd, shifts));
#elif defined(BOTAN_SIMD_USE_NEON)
         return SIMD_4x32(vshlq_n_u32(m_simd, SHIFT));
#elif defined(BOTAN_SIMD_USE_LSX)
         return SIMD_4x32(__lsx_vslli_w(m_simd, SHIFT));
#endif
      }

      template <int SHIFT>
      SIMD_4x32 shr() const noexcept {
#if defined(BOTAN_SIMD_USE_SSSE3)
         return SIMD_4x32(_mm_srli_epi32(m_simd, SHIFT));

#elif defined(BOTAN_SIMD_USE_ALTIVEC)
         const unsigned int s = static_cast<unsigned int>(SHIFT);
         const __vector unsigned int shifts = {s, s, s, s};
         return SIMD_4x32(vec_sr(m_simd, shifts));
#elif defined(BOTAN_SIMD_USE_NEON)
         return SIMD_4x32(vshrq_n_u32(m_simd, SHIFT));
#elif defined(BOTAN_SIMD_USE_LSX)
         return SIMD_4x32(__lsx_vsrli_w(m_simd, SHIFT));
#endif
      }

      SIMD_4x32 operator~() const noexcept {
#if defined(BOTAN_SIMD_USE_SSSE3)
         return SIMD_4x32(_mm_xor_si128(m_simd, _mm_set1_epi32(0xFFFFFFFF)));
#elif defined(BOTAN_SIMD_USE_ALTIVEC)
         return SIMD_4x32(vec_nor(m_simd, m_simd));
#elif defined(BOTAN_SIMD_USE_NEON)
         return SIMD_4x32(vmvnq_u32(m_simd));
#elif defined(BOTAN_SIMD_USE_LSX)
         return SIMD_4x32(__lsx_vnor_v(m_simd, m_simd));
#endif
      }

      // (~reg) & other
      SIMD_4x32 andc(const SIMD_4x32& other) const noexcept {
#if defined(BOTAN_SIMD_USE_SSSE3)
         return SIMD_4x32(_mm_andnot_si128(m_simd, other.m_simd));
#elif defined(BOTAN_SIMD_USE_ALTIVEC)
         /*
         AltiVec does arg1 & ~arg2 rather than SSE's ~arg1 & arg2
         so swap the arguments
         */
         return SIMD_4x32(vec_andc(other.m_simd, m_simd));
#elif defined(BOTAN_SIMD_USE_NEON)
         // NEON is also a & ~b
         return SIMD_4x32(vbicq_u32(other.m_simd, m_simd));
#elif defined(BOTAN_SIMD_USE_LSX)
         // LSX is ~a & b
         return SIMD_4x32(__lsx_vandn_v(m_simd, other.m_simd));
#endif
      }

      /**
      * Return copy *this with each word byte swapped
      */
      BOTAN_FN_ISA_SIMD_4X32 SIMD_4x32 bswap() const noexcept {
#if defined(BOTAN_SIMD_USE_SSSE3)
         const auto idx = _mm_set_epi8(12, 13, 14, 15, 8, 9, 10, 11, 4, 5, 6, 7, 0, 1, 2, 3);

         return SIMD_4x32(_mm_shuffle_epi8(raw(), idx));
#elif defined(BOTAN_SIMD_USE_ALTIVEC)
   #ifdef BOTAN_SIMD_USE_VSX
         return SIMD_4x32(vec_revb(m_simd));
   #else
         const __vector unsigned char rev[1] = {
            {3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12},
         };

         return SIMD_4x32(vec_perm(m_simd, m_simd, rev[0]));
   #endif

#elif defined(BOTAN_SIMD_USE_NEON)
         return SIMD_4x32(vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(m_simd))));
#elif defined(BOTAN_SIMD_USE_LSX)
         return SIMD_4x32(__lsx_vshuf4i_b(m_simd, 0b00011011));
#endif
      }

      template <size_t I>
      SIMD_4x32 shift_elems_left() const noexcept
         requires(I <= 3)
      {
#if defined(BOTAN_SIMD_USE_SSSE3)
         return SIMD_4x32(_mm_slli_si128(raw(), 4 * I));
#elif defined(BOTAN_SIMD_USE_NEON)
         return SIMD_4x32(vextq_u32(vdupq_n_u32(0), raw(), 4 - I));
#elif defined(BOTAN_SIMD_USE_ALTIVEC)
         const __vector unsigned int zero = vec_splat_u32(0);

         const __vector unsigned char shuf[3] = {
            {16, 17, 18, 19, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11},
            {16, 17, 18, 19, 20, 21, 22, 23, 0, 1, 2, 3, 4, 5, 6, 7},
            {16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 0, 1, 2, 3},
         };

         return SIMD_4x32(vec_perm(raw(), zero, shuf[I - 1]));
#elif defined(BOTAN_SIMD_USE_LSX)
         return SIMD_4x32(__lsx_vbsll_v(raw(), 4 * I));
#endif
      }

      template <size_t I>
      SIMD_4x32 shift_elems_right() const noexcept
         requires(I <= 3)
      {
#if defined(BOTAN_SIMD_USE_SSSE3)
         return SIMD_4x32(_mm_srli_si128(raw(), 4 * I));
#elif defined(BOTAN_SIMD_USE_NEON)
         return SIMD_4x32(vextq_u32(raw(), vdupq_n_u32(0), I));
#elif defined(BOTAN_SIMD_USE_ALTIVEC)
         const __vector unsigned int zero = vec_splat_u32(0);

         const __vector unsigned char shuf[3] = {
            {4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19},
            {8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23},
            {12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27},
         };

         return SIMD_4x32(vec_perm(raw(), zero, shuf[I - 1]));
#elif defined(BOTAN_SIMD_USE_LSX)
         return SIMD_4x32(__lsx_vbsrl_v(raw(), 4 * I));
#endif
      }

      /**
      * 4x4 Transposition on SIMD registers
      */
      static void transpose(SIMD_4x32& B0, SIMD_4x32& B1, SIMD_4x32& B2, SIMD_4x32& B3) noexcept {
#if defined(BOTAN_SIMD_USE_SSSE3)
         const __m128i T0 = _mm_unpacklo_epi32(B0.m_simd, B1.m_simd);
         const __m128i T1 = _mm_unpacklo_epi32(B2.m_simd, B3.m_simd);
         const __m128i T2 = _mm_unpackhi_epi32(B0.m_simd, B1.m_simd);
         const __m128i T3 = _mm_unpackhi_epi32(B2.m_simd, B3.m_simd);

         B0.m_simd = _mm_unpacklo_epi64(T0, T1);
         B1.m_simd = _mm_unpackhi_epi64(T0, T1);
         B2.m_simd = _mm_unpacklo_epi64(T2, T3);
         B3.m_simd = _mm_unpackhi_epi64(T2, T3);
#elif defined(BOTAN_SIMD_USE_ALTIVEC)
         const __vector unsigned int T0 = vec_mergeh(B0.m_simd, B2.m_simd);
         const __vector unsigned int T1 = vec_mergeh(B1.m_simd, B3.m_simd);
         const __vector unsigned int T2 = vec_mergel(B0.m_simd, B2.m_simd);
         const __vector unsigned int T3 = vec_mergel(B1.m_simd, B3.m_simd);

         B0.m_simd = vec_mergeh(T0, T1);
         B1.m_simd = vec_mergel(T0, T1);
         B2.m_simd = vec_mergeh(T2, T3);
         B3.m_simd = vec_mergel(T2, T3);

#elif defined(BOTAN_SIMD_USE_NEON) && defined(BOTAN_TARGET_ARCH_IS_ARM32)
         const uint32x4x2_t T0 = vzipq_u32(B0.m_simd, B2.m_simd);
         const uint32x4x2_t T1 = vzipq_u32(B1.m_simd, B3.m_simd);
         const uint32x4x2_t O0 = vzipq_u32(T0.val[0], T1.val[0]);
         const uint32x4x2_t O1 = vzipq_u32(T0.val[1], T1.val[1]);

         B0.m_simd = O0.val[0];
         B1.m_simd = O0.val[1];
         B2.m_simd = O1.val[0];
         B3.m_simd = O1.val[1];

#elif defined(BOTAN_SIMD_USE_NEON) && defined(BOTAN_TARGET_ARCH_IS_ARM64)
         const uint32x4_t T0 = vzip1q_u32(B0.m_simd, B2.m_simd);
         const uint32x4_t T2 = vzip2q_u32(B0.m_simd, B2.m_simd);
         const uint32x4_t T1 = vzip1q_u32(B1.m_simd, B3.m_simd);
         const uint32x4_t T3 = vzip2q_u32(B1.m_simd, B3.m_simd);

         B0.m_simd = vzip1q_u32(T0, T1);
         B1.m_simd = vzip2q_u32(T0, T1);
         B2.m_simd = vzip1q_u32(T2, T3);
         B3.m_simd = vzip2q_u32(T2, T3);
#elif defined(BOTAN_SIMD_USE_LSX)
         const __m128i T0 = __lsx_vilvl_w(B2.raw(), B0.raw());
         const __m128i T1 = __lsx_vilvh_w(B2.raw(), B0.raw());
         const __m128i T2 = __lsx_vilvl_w(B3.raw(), B1.raw());
         const __m128i T3 = __lsx_vilvh_w(B3.raw(), B1.raw());
         B0.m_simd = __lsx_vilvl_w(T2, T0);
         B1.m_simd = __lsx_vilvh_w(T2, T0);
         B2.m_simd = __lsx_vilvl_w(T3, T1);
         B3.m_simd = __lsx_vilvh_w(T3, T1);
#endif
      }

      static inline SIMD_4x32 choose(const SIMD_4x32& mask, const SIMD_4x32& a, const SIMD_4x32& b) noexcept {
#if defined(BOTAN_SIMD_USE_ALTIVEC)
         return SIMD_4x32(vec_sel(b.raw(), a.raw(), mask.raw()));
#elif defined(BOTAN_SIMD_USE_NEON)
         return SIMD_4x32(vbslq_u32(mask.raw(), a.raw(), b.raw()));
#elif defined(BOTAN_SIMD_USE_LSX)
         return SIMD_4x32(__lsx_vbitsel_v(b.raw(), a.raw(), mask.raw()));
#else
         return (mask & a) ^ mask.andc(b);
#endif
      }

      static inline SIMD_4x32 majority(const SIMD_4x32& x, const SIMD_4x32& y, const SIMD_4x32& z) noexcept {
         return SIMD_4x32::choose(x ^ y, z, y);
      }

      /**
      * Byte shuffle
      *
      * This function assumes that each byte of idx is <= 16; it may produce incorrect
      * results if this does not hold.
      */
      static inline SIMD_4x32 BOTAN_FN_ISA_SIMD_4X32 byte_shuffle(const SIMD_4x32& tbl, const SIMD_4x32& idx) {
#if defined(BOTAN_SIMD_USE_SSSE3)
         return SIMD_4x32(_mm_shuffle_epi8(tbl.raw(), idx.raw()));
#elif defined(BOTAN_SIMD_USE_NEON)
         const uint8x16_t tbl8 = vreinterpretq_u8_u32(tbl.raw());
         const uint8x16_t idx8 = vreinterpretq_u8_u32(idx.raw());

   #if defined(BOTAN_TARGET_ARCH_IS_ARM32)
         const uint8x8x2_t tbl2 = {vget_low_u8(tbl8), vget_high_u8(tbl8)};

         return SIMD_4x32(
            vreinterpretq_u32_u8(vcombine_u8(vtbl2_u8(tbl2, vget_low_u8(idx8)), vtbl2_u8(tbl2, vget_high_u8(idx8)))));
   #else
         return SIMD_4x32(vreinterpretq_u32_u8(vqtbl1q_u8(tbl8, idx8)));
   #endif

#elif defined(BOTAN_SIMD_USE_ALTIVEC)
         const auto r = vec_perm(reinterpret_cast<__vector signed char>(tbl.raw()),
                                 reinterpret_cast<__vector signed char>(tbl.raw()),
                                 reinterpret_cast<__vector unsigned char>(idx.raw()));
         return SIMD_4x32(reinterpret_cast<__vector unsigned int>(r));
#elif defined(BOTAN_SIMD_USE_LSX)
         return SIMD_4x32(__lsx_vshuf_b(tbl.raw(), tbl.raw(), idx.raw()));
#endif
      }

      /**
      * Byte shuffle with masking
      *
      * If the index is >= 128 then the output byte is set to zero.
      *
      * Warning: for indices between 16 and 128 this function may have different
      * behaviors depending on the CPU; possibly the output is zero, tbl[idx % 16],
      * or even undefined.
      */
      inline static SIMD_4x32 BOTAN_FN_ISA_SIMD_4X32 masked_byte_shuffle(const SIMD_4x32& tbl, const SIMD_4x32& idx) {
#if defined(BOTAN_SIMD_USE_ALTIVEC)
         const auto zero = vec_splat_s8(0x00);
         const auto mask = vec_cmplt(reinterpret_cast<__vector signed char>(idx.raw()), zero);
         const auto r = vec_perm(reinterpret_cast<__vector signed char>(tbl.raw()),
                                 reinterpret_cast<__vector signed char>(tbl.raw()),
                                 reinterpret_cast<__vector unsigned char>(idx.raw()));
         return SIMD_4x32(reinterpret_cast<__vector unsigned int>(vec_sel(r, zero, mask)));
#elif defined(BOTAN_SIMD_USE_LSX)
         /*
         * The behavior of vshuf.b unfortunately differs among microarchitectures
         * when the index is larger than the available elements. In LA664 CPUs,
         * larger indices result in a zero byte, which is exactly what we want.
         * Unfortunately on LA464 machines, the output is instead undefined.
         *
         * So we must use a slower sequence that handles the larger indices.
         * If we had a way of knowing at compile time that we are on an LA664
         * or later, we could use __lsx_vshuf_b without the comparison or select.
         */
         const auto zero = __lsx_vldi(0);
         const auto r = __lsx_vshuf_b(zero, tbl.raw(), idx.raw());
         const auto mask = __lsx_vslti_bu(idx.raw(), 16);
         return SIMD_4x32(__lsx_vbitsel_v(zero, r, mask));
#else
         // ARM and x86 byte shuffles have the behavior we want for out of range idx
         return SIMD_4x32::byte_shuffle(tbl, idx);
#endif
      }

      static inline SIMD_4x32 BOTAN_FN_ISA_SIMD_4X32 alignr4(const SIMD_4x32& a, const SIMD_4x32& b) {
#if defined(BOTAN_SIMD_USE_SSSE3)
         return SIMD_4x32(_mm_alignr_epi8(a.raw(), b.raw(), 4));
#elif defined(BOTAN_SIMD_USE_NEON)
         return SIMD_4x32(vextq_u32(b.raw(), a.raw(), 1));
#elif defined(BOTAN_SIMD_USE_ALTIVEC)
         const __vector unsigned char mask = {4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19};
         return SIMD_4x32(vec_perm(b.raw(), a.raw(), mask));
#elif defined(BOTAN_SIMD_USE_LSX)
         const auto mask = SIMD_4x32(0x07060504, 0x0B0A0908, 0x0F0E0D0C, 0x13121110);
         return SIMD_4x32(__lsx_vshuf_b(a.raw(), b.raw(), mask.raw()));
#endif
      }

      static inline SIMD_4x32 BOTAN_FN_ISA_SIMD_4X32 alignr8(const SIMD_4x32& a, const SIMD_4x32& b) {
#if defined(BOTAN_SIMD_USE_SSSE3)
         return SIMD_4x32(_mm_alignr_epi8(a.raw(), b.raw(), 8));
#elif defined(BOTAN_SIMD_USE_NEON)
         return SIMD_4x32(vextq_u32(b.raw(), a.raw(), 2));
#elif defined(BOTAN_SIMD_USE_ALTIVEC)
         const __vector unsigned char mask = {8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23};
         return SIMD_4x32(vec_perm(b.raw(), a.raw(), mask));
#elif defined(BOTAN_SIMD_USE_LSX)
         return SIMD_4x32(__lsx_vshuf4i_d(a.raw(), b.raw(), 0b0011));
#endif
      }

      native_simd_type raw() const noexcept { return m_simd; }

      explicit SIMD_4x32(native_simd_type x) noexcept : m_simd(x) {}

   private:
      native_simd_type m_simd;
};

// NOLINTEND(portability-simd-intrinsics)

template <size_t R>
inline SIMD_4x32 BOTAN_FN_ISA_SIMD_4X32 rotl(SIMD_4x32 input) {
   return input.rotl<R>();
}

template <size_t R>
inline SIMD_4x32 BOTAN_FN_ISA_SIMD_4X32 rotr(SIMD_4x32 input) {
   return input.rotr<R>();
}

// For Serpent:
template <size_t S>
inline SIMD_4x32 shl(SIMD_4x32 input) {
   return input.shl<S>();
}

}  // namespace Botan

#endif
