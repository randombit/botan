/*
* (C) 2018 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/serpent.h>
#include <botan/internal/serpent_sbox.h>
#include <immintrin.h>

namespace Botan {

namespace {

class SIMD_8x32 final
   {
   public:

      SIMD_8x32& operator=(const SIMD_8x32& other) = default;
      SIMD_8x32(const SIMD_8x32& other) = default;

#if !defined(BOTAN_BUILD_COMPILER_IS_MSVC_2013)
      SIMD_8x32& operator=(SIMD_8x32&& other) = default;
      SIMD_8x32(SIMD_8x32&& other) = default;
#endif

      SIMD_8x32()
         {
         m_avx2 = _mm256_setzero_si256();
         }

      /**
      * Load SIMD register with 8 32-bit elements
      */
      explicit SIMD_8x32(const uint32_t B[8])
         {
         m_avx2 = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(B));
         }

      /**
      * Load SIMD register with one 32-bit element repeated
      */
      static SIMD_8x32 splat(uint32_t B)
         {
         return SIMD_8x32(_mm256_set1_epi32(B));
         }

      /**
      * Load a SIMD register with little-endian convention
      */
      static SIMD_8x32 load_le(const uint8_t* in)
         {
         return SIMD_8x32(_mm256_loadu_si256(reinterpret_cast<const __m256i*>(in)));
         }

      /**
      * Load a SIMD register with big-endian convention
      */
      static SIMD_8x32 load_be(const uint8_t* in)
         {
         return load_le(in).bswap();
         }

      /**
      * Load a SIMD register with little-endian convention
      */
      void store_le(uint8_t out[]) const
         {
         _mm256_storeu_si256(reinterpret_cast<__m256i*>(out), m_avx2);
         }

      /**
      * Load a SIMD register with big-endian convention
      */
      void store_be(uint8_t out[]) const
         {
         bswap().store_le(out);
         }

      /**
      * Left rotation by a compile time constant
      */
      template<size_t ROT>
      SIMD_8x32 rotl() const
         {
         static_assert(ROT > 0 && ROT < 32, "Invalid rotation constant");

         return SIMD_8x32(_mm256_or_si256(_mm256_slli_epi32(m_avx2, static_cast<int>(ROT)),
                                          _mm256_srli_epi32(m_avx2, static_cast<int>(32-ROT))));
         }

      /**
      * Right rotation by a compile time constant
      */
      template<size_t ROT>
      SIMD_8x32 rotr() const
         {
         return this->rotl<32-ROT>();
         }

      /**
      * Add elements of a SIMD vector
      */
      SIMD_8x32 operator+(const SIMD_8x32& other) const
         {
         SIMD_8x32 retval(*this);
         retval += other;
         return retval;
         }

      /**
      * Subtract elements of a SIMD vector
      */
      SIMD_8x32 operator-(const SIMD_8x32& other) const
         {
         SIMD_8x32 retval(*this);
         retval -= other;
         return retval;
         }

      /**
      * XOR elements of a SIMD vector
      */
      SIMD_8x32 operator^(const SIMD_8x32& other) const
         {
         SIMD_8x32 retval(*this);
         retval ^= other;
         return retval;
         }

      /**
      * Binary OR elements of a SIMD vector
      */
      SIMD_8x32 operator|(const SIMD_8x32& other) const
         {
         SIMD_8x32 retval(*this);
         retval |= other;
         return retval;
         }

      /**
      * Binary AND elements of a SIMD vector
      */
      SIMD_8x32 operator&(const SIMD_8x32& other) const
         {
         SIMD_8x32 retval(*this);
         retval &= other;
         return retval;
         }

      void operator+=(const SIMD_8x32& other)
         {
         m_avx2 = _mm256_add_epi32(m_avx2, other.m_avx2);
         }

      void operator-=(const SIMD_8x32& other)
         {
         m_avx2 = _mm256_sub_epi32(m_avx2, other.m_avx2);
         }

      void operator^=(const SIMD_8x32& other)
         {
         m_avx2 = _mm256_xor_si256(m_avx2, other.m_avx2);
         }

      void operator|=(const SIMD_8x32& other)
         {
         m_avx2 = _mm256_or_si256(m_avx2, other.m_avx2);
         }

      void operator&=(const SIMD_8x32& other)
         {
         m_avx2 = _mm256_and_si256(m_avx2, other.m_avx2);
         }

      template<int SHIFT> SIMD_8x32 shl() const
         {
         return SIMD_8x32(_mm256_slli_epi32(m_avx2, SHIFT));
         }

      template<int SHIFT> SIMD_8x32 shr() const
         {
         return SIMD_8x32(_mm256_srli_epi32(m_avx2, SHIFT));
         }

      SIMD_8x32 operator~() const
         {
         return SIMD_8x32(_mm256_xor_si256(m_avx2, _mm256_set1_epi32(0xFFFFFFFF)));
         }

      // (~reg) & other
      SIMD_8x32 andc(const SIMD_8x32& other) const
         {
         return SIMD_8x32(_mm256_andnot_si256(m_avx2, other.m_avx2));
         }

      /**
      * Return copy *this with each word byte swapped
      */
      SIMD_8x32 bswap() const
         {
         const uint8_t BSWAP_MASK[32] = { 3, 2, 1, 0,
                                          7, 6, 5, 4,
                                          11, 10, 9, 8,
                                          15, 14, 13, 12,
                                          19, 18, 17, 16,
                                          23, 22, 21, 20,
                                          27, 26, 25, 24,
                                          31, 30, 29, 28 };

         const __m256i bswap = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(BSWAP_MASK));

         const __m256i output = _mm256_shuffle_epi8(m_avx2, bswap);

         return SIMD_8x32(output);
         }

      static void transpose(SIMD_8x32& B0, SIMD_8x32& B1,
                            SIMD_8x32& B2, SIMD_8x32& B3)
         {
         const __m256i T0 = _mm256_unpacklo_epi32(B0.m_avx2, B1.m_avx2);
         const __m256i T1 = _mm256_unpacklo_epi32(B2.m_avx2, B3.m_avx2);
         const __m256i T2 = _mm256_unpackhi_epi32(B0.m_avx2, B1.m_avx2);
         const __m256i T3 = _mm256_unpackhi_epi32(B2.m_avx2, B3.m_avx2);

         B0.m_avx2 = _mm256_unpacklo_epi64(T0, T1);
         B1.m_avx2 = _mm256_unpackhi_epi64(T0, T1);
         B2.m_avx2 = _mm256_unpacklo_epi64(T2, T3);
         B3.m_avx2 = _mm256_unpackhi_epi64(T2, T3);
         }

      static void transpose_out(SIMD_8x32& B0, SIMD_8x32& B1,
                                SIMD_8x32& B2, SIMD_8x32& B3)
         {
         /*
         SIMD_4x32::transpose(B0.m_lo, B1.m_lo, B2.m_lo, B3.m_lo);
         SIMD_4x32::transpose(B0.m_hi, B1.m_hi, B2.m_hi, B3.m_hi);
         SIMD_8x32 T0 = SIMD_8x32(B0.m_lo, B1.m_lo);
         SIMD_8x32 T1 = SIMD_8x32(B2.m_lo, B3.m_lo);
         SIMD_8x32 T2 = SIMD_8x32(B0.m_hi, B1.m_hi);
         SIMD_8x32 T3 = SIMD_8x32(B2.m_hi, B3.m_hi);

         B0 = T0;
         B1 = T1;
         B2 = T2;
         B3 = T3;
         */
         const __m256i T0 = _mm256_unpacklo_epi32(B0.m_avx2, B1.m_avx2);
         const __m256i T1 = _mm256_unpacklo_epi32(B2.m_avx2, B3.m_avx2);
         const __m256i T2 = _mm256_unpackhi_epi32(B0.m_avx2, B1.m_avx2);
         const __m256i T3 = _mm256_unpackhi_epi32(B2.m_avx2, B3.m_avx2);

         B0.m_avx2 = _mm256_unpacklo_epi64(T0, T1);
         B1.m_avx2 = _mm256_unpackhi_epi64(T0, T1);
         B2.m_avx2 = _mm256_unpacklo_epi64(T2, T3);
         B3.m_avx2 = _mm256_unpackhi_epi64(T2, T3);
         }
   private:
      SIMD_8x32(__m256i x) : m_avx2(x) {}

      __m256i m_avx2;
   };

}

#define key_xor(round, B0, B1, B2, B3)                             \
   do {                                                            \
      B0 ^= SIMD_8x32::splat(m_round_key[4*round  ]);              \
      B1 ^= SIMD_8x32::splat(m_round_key[4*round+1]);              \
      B2 ^= SIMD_8x32::splat(m_round_key[4*round+2]);              \
      B3 ^= SIMD_8x32::splat(m_round_key[4*round+3]);              \
   } while(0)

/*
* Serpent's linear transformations
*/
#define transform(B0, B1, B2, B3)                                  \
   do {                                                            \
      B0 = B0.rotl<13>();                                          \
      B2 = B2.rotl<3>();                                           \
      B1 ^= B0 ^ B2;                                               \
      B3 ^= B2 ^ B0.shl<3>();                                      \
      B1 = B1.rotl<1>();                                           \
      B3 = B3.rotl<7>();                                           \
      B0 ^= B1 ^ B3;                                               \
      B2 ^= B3 ^ B1.shl<7>();                                      \
      B0 = B0.rotl<5>();                                           \
      B2 = B2.rotl<22>();                                          \
   } while(0)

#define i_transform(B0, B1, B2, B3)                                \
   do {                                                            \
      B2 = B2.rotr<22>();                                          \
      B0 = B0.rotr<5>();                                           \
      B2 ^= B3 ^ B1.shl<7>();                                      \
      B0 ^= B1 ^ B3;                                               \
      B3 = B3.rotr<7>();                                           \
      B1 = B1.rotr<1>();                                           \
      B3 ^= B2 ^ B0.shl<3>();                                      \
      B1 ^= B0 ^ B2;                                               \
      B2 = B2.rotr<3>();                                           \
      B0 = B0.rotr<13>();                                          \
   } while(0)

void Serpent::avx2_encrypt_8(const uint8_t in[64], uint8_t out[64]) const
   {
   SIMD_8x32 B0 = SIMD_8x32::load_le(in);
   SIMD_8x32 B1 = SIMD_8x32::load_le(in + 32);
   SIMD_8x32 B2 = SIMD_8x32::load_le(in + 64);
   SIMD_8x32 B3 = SIMD_8x32::load_le(in + 96);

   SIMD_8x32::transpose(B0, B1, B2, B3);

   key_xor( 0,B0,B1,B2,B3); SBoxE1(B0,B1,B2,B3); transform(B0,B1,B2,B3);
   key_xor( 1,B0,B1,B2,B3); SBoxE2(B0,B1,B2,B3); transform(B0,B1,B2,B3);
   key_xor( 2,B0,B1,B2,B3); SBoxE3(B0,B1,B2,B3); transform(B0,B1,B2,B3);
   key_xor( 3,B0,B1,B2,B3); SBoxE4(B0,B1,B2,B3); transform(B0,B1,B2,B3);
   key_xor( 4,B0,B1,B2,B3); SBoxE5(B0,B1,B2,B3); transform(B0,B1,B2,B3);
   key_xor( 5,B0,B1,B2,B3); SBoxE6(B0,B1,B2,B3); transform(B0,B1,B2,B3);
   key_xor( 6,B0,B1,B2,B3); SBoxE7(B0,B1,B2,B3); transform(B0,B1,B2,B3);
   key_xor( 7,B0,B1,B2,B3); SBoxE8(B0,B1,B2,B3); transform(B0,B1,B2,B3);
   key_xor( 8,B0,B1,B2,B3); SBoxE1(B0,B1,B2,B3); transform(B0,B1,B2,B3);
   key_xor( 9,B0,B1,B2,B3); SBoxE2(B0,B1,B2,B3); transform(B0,B1,B2,B3);
   key_xor(10,B0,B1,B2,B3); SBoxE3(B0,B1,B2,B3); transform(B0,B1,B2,B3);
   key_xor(11,B0,B1,B2,B3); SBoxE4(B0,B1,B2,B3); transform(B0,B1,B2,B3);
   key_xor(12,B0,B1,B2,B3); SBoxE5(B0,B1,B2,B3); transform(B0,B1,B2,B3);
   key_xor(13,B0,B1,B2,B3); SBoxE6(B0,B1,B2,B3); transform(B0,B1,B2,B3);
   key_xor(14,B0,B1,B2,B3); SBoxE7(B0,B1,B2,B3); transform(B0,B1,B2,B3);
   key_xor(15,B0,B1,B2,B3); SBoxE8(B0,B1,B2,B3); transform(B0,B1,B2,B3);
   key_xor(16,B0,B1,B2,B3); SBoxE1(B0,B1,B2,B3); transform(B0,B1,B2,B3);
   key_xor(17,B0,B1,B2,B3); SBoxE2(B0,B1,B2,B3); transform(B0,B1,B2,B3);
   key_xor(18,B0,B1,B2,B3); SBoxE3(B0,B1,B2,B3); transform(B0,B1,B2,B3);
   key_xor(19,B0,B1,B2,B3); SBoxE4(B0,B1,B2,B3); transform(B0,B1,B2,B3);
   key_xor(20,B0,B1,B2,B3); SBoxE5(B0,B1,B2,B3); transform(B0,B1,B2,B3);
   key_xor(21,B0,B1,B2,B3); SBoxE6(B0,B1,B2,B3); transform(B0,B1,B2,B3);
   key_xor(22,B0,B1,B2,B3); SBoxE7(B0,B1,B2,B3); transform(B0,B1,B2,B3);
   key_xor(23,B0,B1,B2,B3); SBoxE8(B0,B1,B2,B3); transform(B0,B1,B2,B3);
   key_xor(24,B0,B1,B2,B3); SBoxE1(B0,B1,B2,B3); transform(B0,B1,B2,B3);
   key_xor(25,B0,B1,B2,B3); SBoxE2(B0,B1,B2,B3); transform(B0,B1,B2,B3);
   key_xor(26,B0,B1,B2,B3); SBoxE3(B0,B1,B2,B3); transform(B0,B1,B2,B3);
   key_xor(27,B0,B1,B2,B3); SBoxE4(B0,B1,B2,B3); transform(B0,B1,B2,B3);
   key_xor(28,B0,B1,B2,B3); SBoxE5(B0,B1,B2,B3); transform(B0,B1,B2,B3);
   key_xor(29,B0,B1,B2,B3); SBoxE6(B0,B1,B2,B3); transform(B0,B1,B2,B3);
   key_xor(30,B0,B1,B2,B3); SBoxE7(B0,B1,B2,B3); transform(B0,B1,B2,B3);
   key_xor(31,B0,B1,B2,B3); SBoxE8(B0,B1,B2,B3); key_xor(32,B0,B1,B2,B3);

   SIMD_8x32::transpose(B0, B1, B2, B3);
   B0.store_le(out);
   B1.store_le(out + 32);
   B2.store_le(out + 64);
   B3.store_le(out + 96);
   }

void Serpent::avx2_decrypt_8(const uint8_t in[64], uint8_t out[64]) const
   {
   SIMD_8x32 B0 = SIMD_8x32::load_le(in);
   SIMD_8x32 B1 = SIMD_8x32::load_le(in + 32);
   SIMD_8x32 B2 = SIMD_8x32::load_le(in + 64);
   SIMD_8x32 B3 = SIMD_8x32::load_le(in + 96);

   SIMD_8x32::transpose(B0, B1, B2, B3);

   key_xor(32,B0,B1,B2,B3);  SBoxD8(B0,B1,B2,B3); key_xor(31,B0,B1,B2,B3);
   i_transform(B0,B1,B2,B3); SBoxD7(B0,B1,B2,B3); key_xor(30,B0,B1,B2,B3);
   i_transform(B0,B1,B2,B3); SBoxD6(B0,B1,B2,B3); key_xor(29,B0,B1,B2,B3);
   i_transform(B0,B1,B2,B3); SBoxD5(B0,B1,B2,B3); key_xor(28,B0,B1,B2,B3);
   i_transform(B0,B1,B2,B3); SBoxD4(B0,B1,B2,B3); key_xor(27,B0,B1,B2,B3);
   i_transform(B0,B1,B2,B3); SBoxD3(B0,B1,B2,B3); key_xor(26,B0,B1,B2,B3);
   i_transform(B0,B1,B2,B3); SBoxD2(B0,B1,B2,B3); key_xor(25,B0,B1,B2,B3);
   i_transform(B0,B1,B2,B3); SBoxD1(B0,B1,B2,B3); key_xor(24,B0,B1,B2,B3);

   i_transform(B0,B1,B2,B3); SBoxD8(B0,B1,B2,B3); key_xor(23,B0,B1,B2,B3);
   i_transform(B0,B1,B2,B3); SBoxD7(B0,B1,B2,B3); key_xor(22,B0,B1,B2,B3);
   i_transform(B0,B1,B2,B3); SBoxD6(B0,B1,B2,B3); key_xor(21,B0,B1,B2,B3);
   i_transform(B0,B1,B2,B3); SBoxD5(B0,B1,B2,B3); key_xor(20,B0,B1,B2,B3);
   i_transform(B0,B1,B2,B3); SBoxD4(B0,B1,B2,B3); key_xor(19,B0,B1,B2,B3);
   i_transform(B0,B1,B2,B3); SBoxD3(B0,B1,B2,B3); key_xor(18,B0,B1,B2,B3);
   i_transform(B0,B1,B2,B3); SBoxD2(B0,B1,B2,B3); key_xor(17,B0,B1,B2,B3);
   i_transform(B0,B1,B2,B3); SBoxD1(B0,B1,B2,B3); key_xor(16,B0,B1,B2,B3);

   i_transform(B0,B1,B2,B3); SBoxD8(B0,B1,B2,B3); key_xor(15,B0,B1,B2,B3);
   i_transform(B0,B1,B2,B3); SBoxD7(B0,B1,B2,B3); key_xor(14,B0,B1,B2,B3);
   i_transform(B0,B1,B2,B3); SBoxD6(B0,B1,B2,B3); key_xor(13,B0,B1,B2,B3);
   i_transform(B0,B1,B2,B3); SBoxD5(B0,B1,B2,B3); key_xor(12,B0,B1,B2,B3);
   i_transform(B0,B1,B2,B3); SBoxD4(B0,B1,B2,B3); key_xor(11,B0,B1,B2,B3);
   i_transform(B0,B1,B2,B3); SBoxD3(B0,B1,B2,B3); key_xor(10,B0,B1,B2,B3);
   i_transform(B0,B1,B2,B3); SBoxD2(B0,B1,B2,B3); key_xor( 9,B0,B1,B2,B3);
   i_transform(B0,B1,B2,B3); SBoxD1(B0,B1,B2,B3); key_xor( 8,B0,B1,B2,B3);

   i_transform(B0,B1,B2,B3); SBoxD8(B0,B1,B2,B3); key_xor( 7,B0,B1,B2,B3);
   i_transform(B0,B1,B2,B3); SBoxD7(B0,B1,B2,B3); key_xor( 6,B0,B1,B2,B3);
   i_transform(B0,B1,B2,B3); SBoxD6(B0,B1,B2,B3); key_xor( 5,B0,B1,B2,B3);
   i_transform(B0,B1,B2,B3); SBoxD5(B0,B1,B2,B3); key_xor( 4,B0,B1,B2,B3);
   i_transform(B0,B1,B2,B3); SBoxD4(B0,B1,B2,B3); key_xor( 3,B0,B1,B2,B3);
   i_transform(B0,B1,B2,B3); SBoxD3(B0,B1,B2,B3); key_xor( 2,B0,B1,B2,B3);
   i_transform(B0,B1,B2,B3); SBoxD2(B0,B1,B2,B3); key_xor( 1,B0,B1,B2,B3);
   i_transform(B0,B1,B2,B3); SBoxD1(B0,B1,B2,B3); key_xor( 0,B0,B1,B2,B3);

   SIMD_8x32::transpose(B0, B1, B2, B3);

   B0.store_le(out);
   B1.store_le(out + 32);
   B2.store_le(out + 64);
   B3.store_le(out + 96);
   }

}
