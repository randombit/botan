/**
* (C) 2022 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/argon2.h>
#include <tmmintrin.h>

namespace Botan {

namespace {

class SIMD_2x64 final {
   public:
      SIMD_2x64& operator=(const SIMD_2x64& other) = default;
      SIMD_2x64(const SIMD_2x64& other) = default;

      SIMD_2x64& operator=(SIMD_2x64&& other) = default;
      SIMD_2x64(SIMD_2x64&& other) = default;

      ~SIMD_2x64() = default;

      SIMD_2x64()  // zero initialized
      {
         m_simd = _mm_setzero_si128();
      }

      static SIMD_2x64 load_le(const void* in) {
         return SIMD_2x64(_mm_loadu_si128(reinterpret_cast<const __m128i*>(in)));
      }

      void store_le(uint64_t out[2]) const { this->store_le(reinterpret_cast<uint8_t*>(out)); }

      void store_le(uint8_t out[]) const { _mm_storeu_si128(reinterpret_cast<__m128i*>(out), m_simd); }

      SIMD_2x64 operator+(const SIMD_2x64& other) const {
         SIMD_2x64 retval(*this);
         retval += other;
         return retval;
      }

      SIMD_2x64 operator^(const SIMD_2x64& other) const {
         SIMD_2x64 retval(*this);
         retval ^= other;
         return retval;
      }

      void operator+=(const SIMD_2x64& other) { m_simd = _mm_add_epi64(m_simd, other.m_simd); }

      void operator^=(const SIMD_2x64& other) { m_simd = _mm_xor_si128(m_simd, other.m_simd); }

      template <size_t ROT>
      BOTAN_FUNC_ISA("ssse3")
      SIMD_2x64 rotr() const
         requires(ROT > 0 && ROT < 64)
      {
         if constexpr(ROT == 16) {
            auto tab = _mm_setr_epi8(2, 3, 4, 5, 6, 7, 0, 1, 10, 11, 12, 13, 14, 15, 8, 9);
            return SIMD_2x64(_mm_shuffle_epi8(m_simd, tab));
         } else if constexpr(ROT == 24) {
            auto tab = _mm_setr_epi8(3, 4, 5, 6, 7, 0, 1, 2, 11, 12, 13, 14, 15, 8, 9, 10);
            return SIMD_2x64(_mm_shuffle_epi8(m_simd, tab));
         } else if constexpr(ROT == 32) {
            auto tab = _mm_setr_epi8(4, 5, 6, 7, 0, 1, 2, 3, 12, 13, 14, 15, 8, 9, 10, 11);
            return SIMD_2x64(_mm_shuffle_epi8(m_simd, tab));
         } else {
            return SIMD_2x64(_mm_or_si128(_mm_srli_epi64(m_simd, static_cast<int>(ROT)),
                                          _mm_slli_epi64(m_simd, static_cast<int>(64 - ROT))));
         }
      }

      template <size_t ROT>
      SIMD_2x64 rotl() const {
         return this->rotr<64 - ROT>();
      }

      // Argon2 specific operation
      static SIMD_2x64 mul2_32(SIMD_2x64 x, SIMD_2x64 y) {
         const __m128i m = _mm_mul_epu32(x.m_simd, y.m_simd);
         return SIMD_2x64(_mm_add_epi64(m, m));
      }

      template <size_t T>
      BOTAN_FUNC_ISA("ssse3")
      static SIMD_2x64 alignr(SIMD_2x64 a, SIMD_2x64 b)
         requires(T > 0 && T < 16)
      {
         return SIMD_2x64(_mm_alignr_epi8(a.m_simd, b.m_simd, T));
      }

      // Argon2 specific
      static void twist(SIMD_2x64& B0, SIMD_2x64& B1, SIMD_2x64& C0, SIMD_2x64& C1, SIMD_2x64& D0, SIMD_2x64& D1) {
         SIMD_2x64 T0, T1;

         T0 = SIMD_2x64::alignr<8>(B1, B0);
         T1 = SIMD_2x64::alignr<8>(B0, B1);
         B0 = T0;
         B1 = T1;

         T0 = C0;
         C0 = C1;
         C1 = T0;

         T0 = SIMD_2x64::alignr<8>(D0, D1);
         T1 = SIMD_2x64::alignr<8>(D1, D0);
         D0 = T0;
         D1 = T1;
      }

      // Argon2 specific
      static void untwist(SIMD_2x64& B0, SIMD_2x64& B1, SIMD_2x64& C0, SIMD_2x64& C1, SIMD_2x64& D0, SIMD_2x64& D1) {
         SIMD_2x64 T0, T1;

         T0 = SIMD_2x64::alignr<8>(B0, B1);
         T1 = SIMD_2x64::alignr<8>(B1, B0);
         B0 = T0;
         B1 = T1;

         T0 = C0;
         C0 = C1;
         C1 = T0;

         T0 = SIMD_2x64::alignr<8>(D1, D0);
         T1 = SIMD_2x64::alignr<8>(D0, D1);
         D0 = T0;
         D1 = T1;
      }

      explicit SIMD_2x64(__m128i x) : m_simd(x) {}

   private:
      __m128i m_simd;
};

BOTAN_FORCE_INLINE void blamka_G(SIMD_2x64& A0,
                                 SIMD_2x64& A1,
                                 SIMD_2x64& B0,
                                 SIMD_2x64& B1,
                                 SIMD_2x64& C0,
                                 SIMD_2x64& C1,
                                 SIMD_2x64& D0,
                                 SIMD_2x64& D1) {
   A0 += B0 + SIMD_2x64::mul2_32(A0, B0);
   A1 += B1 + SIMD_2x64::mul2_32(A1, B1);
   D0 ^= A0;
   D1 ^= A1;
   D0 = D0.rotr<32>();
   D1 = D1.rotr<32>();

   C0 += D0 + SIMD_2x64::mul2_32(C0, D0);
   C1 += D1 + SIMD_2x64::mul2_32(C1, D1);
   B0 ^= C0;
   B1 ^= C1;
   B0 = B0.rotr<24>();
   B1 = B1.rotr<24>();

   A0 += B0 + SIMD_2x64::mul2_32(A0, B0);
   A1 += B1 + SIMD_2x64::mul2_32(A1, B1);
   D0 ^= A0;
   D1 ^= A1;
   D0 = D0.rotr<16>();
   D1 = D1.rotr<16>();

   C0 += D0 + SIMD_2x64::mul2_32(C0, D0);
   C1 += D1 + SIMD_2x64::mul2_32(C1, D1);
   B0 ^= C0;
   B1 ^= C1;
   B0 = B0.rotr<63>();
   B1 = B1.rotr<63>();
}

BOTAN_FORCE_INLINE void blamka_R(SIMD_2x64& A0,
                                 SIMD_2x64& A1,
                                 SIMD_2x64& B0,
                                 SIMD_2x64& B1,
                                 SIMD_2x64& C0,
                                 SIMD_2x64& C1,
                                 SIMD_2x64& D0,
                                 SIMD_2x64& D1) {
   blamka_G(A0, A1, B0, B1, C0, C1, D0, D1);

   SIMD_2x64::twist(B0, B1, C0, C1, D0, D1);
   blamka_G(A0, A1, B0, B1, C0, C1, D0, D1);
   SIMD_2x64::untwist(B0, B1, C0, C1, D0, D1);
}

}  // namespace

void Argon2::blamka_ssse3(uint64_t N[128], uint64_t T[128]) {
   for(size_t i = 0; i != 8; ++i) {
      SIMD_2x64 Tv[8];
      for(size_t j = 0; j != 4; ++j) {
         Tv[2 * j] = SIMD_2x64::load_le(&N[16 * i + 4 * j]);
         Tv[2 * j + 1] = SIMD_2x64::load_le(&N[16 * i + 4 * j + 2]);
      }

      blamka_R(Tv[0], Tv[1], Tv[2], Tv[3], Tv[4], Tv[5], Tv[6], Tv[7]);

      for(size_t j = 0; j != 4; ++j) {
         Tv[2 * j].store_le(&T[16 * i + 4 * j]);
         Tv[2 * j + 1].store_le(&T[16 * i + 4 * j + 2]);
      }
   }

   for(size_t i = 0; i != 8; ++i) {
      SIMD_2x64 Tv[8];
      for(size_t j = 0; j != 4; ++j) {
         Tv[2 * j] = SIMD_2x64::load_le(&T[2 * i + 32 * j]);
         Tv[2 * j + 1] = SIMD_2x64::load_le(&T[2 * i + 32 * j + 16]);
      }

      blamka_R(Tv[0], Tv[1], Tv[2], Tv[3], Tv[4], Tv[5], Tv[6], Tv[7]);

      for(size_t j = 0; j != 4; ++j) {
         Tv[2 * j].store_le(&T[2 * i + 32 * j]);
         Tv[2 * j + 1].store_le(&T[2 * i + 32 * j + 16]);
      }
   }

   for(size_t i = 0; i != 128 / 4; ++i) {
      SIMD_2x64 n0 = SIMD_2x64::load_le(&N[4 * i]);
      SIMD_2x64 n1 = SIMD_2x64::load_le(&N[4 * i + 2]);
      SIMD_2x64 t0 = SIMD_2x64::load_le(&T[4 * i]);
      SIMD_2x64 t1 = SIMD_2x64::load_le(&T[4 * i + 2]);

      n0 ^= t0;
      n1 ^= t1;
      n0.store_le(&N[4 * i]);
      n1.store_le(&N[4 * i + 2]);
   }
}

}  // namespace Botan
