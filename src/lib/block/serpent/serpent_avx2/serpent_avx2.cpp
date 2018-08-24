/*
* (C) 2018 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/serpent.h>
#include <botan/internal/serpent_sbox.h>
#include <botan/internal/simd_32.h>

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

      SIMD_8x32() : m_lo(), m_hi()
         {
         }

      SIMD_8x32(const SIMD_4x32& l, const SIMD_4x32& h) : m_lo(l), m_hi(h)
         {
         }

      /**
      * Load SIMD register with 8 32-bit elements
      */
      explicit SIMD_8x32(const uint32_t B[8]) : m_lo(B), m_hi(B + 4)
         {
         }

      /**
      * Load SIMD register with 8 32-bit elements
      */
      SIMD_8x32(uint32_t B0, uint32_t B1, uint32_t B2, uint32_t B3,
                uint32_t B4, uint32_t B5, uint32_t B6, uint32_t B7) :
         m_lo(B0, B1, B2, B3),
         m_hi(B4, B5, B6, B7)
         {
         }

      /**
      * Load SIMD register with one 32-bit element repeated
      */
      static SIMD_8x32 splat(uint32_t B)
         {
         SIMD_4x32 s = SIMD_4x32::splat(B);
         return SIMD_8x32(s, s);
         }

      /**
      * Load a SIMD register with little-endian convention
      */
      static SIMD_8x32 load_le(const uint8_t* in)
         {
         return SIMD_8x32(SIMD_4x32::load_le(in), SIMD_4x32::load_le(in + 16));
         }

      /**
      * Load a SIMD register with big-endian convention
      */
      static SIMD_8x32 load_be(const uint8_t* in)
         {
         return SIMD_8x32(SIMD_4x32::load_be(in), SIMD_4x32::load_be(in + 16));
         }

      /**
      * Load a SIMD register with little-endian convention
      */
      void store_le(uint8_t out[]) const
         {
         m_lo.store_le(out);
         m_hi.store_le(out + 16);
         }

      /**
      * Load a SIMD register with big-endian convention
      */
      void store_be(uint8_t out[]) const
         {
         m_lo.store_be(out);
         m_hi.store_be(out + 16);
         }

      /**
      * Left rotation by a compile time constant
      */
      template<size_t ROT>
      SIMD_8x32 rotl() const
         {
         static_assert(ROT > 0 && ROT < 32, "Invalid rotation constant");
         return SIMD_8x32(m_lo.rotl<ROT>(), m_hi.rotl<ROT>());
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
         m_lo += other.m_lo;
         m_hi += other.m_hi;
         }

      void operator-=(const SIMD_8x32& other)
         {
         m_lo -= other.m_lo;
         m_hi -= other.m_hi;
         }

      void operator^=(const SIMD_8x32& other)
         {
         m_lo ^= other.m_lo;
         m_hi ^= other.m_hi;
         }

      void operator|=(const SIMD_8x32& other)
         {
         m_lo |= other.m_lo;
         m_hi |= other.m_hi;
         }

      void operator&=(const SIMD_8x32& other)
         {
         m_lo &= other.m_lo;
         m_hi &= other.m_hi;
         }

      template<int SHIFT> SIMD_8x32 shl() const
         {
         return SIMD_8x32(m_lo.shl<SHIFT>(), m_hi.shl<SHIFT>());
         }

      template<int SHIFT> SIMD_8x32 shr() const
         {
         return SIMD_8x32(m_lo.shr<SHIFT>(), m_hi.shr<SHIFT>());
         }

      SIMD_8x32 operator~() const
         {
         return SIMD_8x32(~m_lo, ~m_hi);
         }

      // (~reg) & other
      SIMD_8x32 andc(const SIMD_8x32& other) const
         {
         return SIMD_8x32(m_lo.andc(other.m_lo), m_hi.andc(other.m_hi));
         }

      /**
      * Return copy *this with each word byte swapped
      */
      SIMD_8x32 bswap() const
         {
         return SIMD_8x32(m_lo.bswap(), m_hi.bswap());
         }

      static void transpose(SIMD_8x32& B0, SIMD_8x32& B1,
                            SIMD_8x32& B2, SIMD_8x32& B3)
         {
         SIMD_4x32::transpose(B0.m_lo, B1.m_lo, B2.m_lo, B3.m_lo);
         SIMD_4x32::transpose(B0.m_hi, B1.m_hi, B2.m_hi, B3.m_hi);
         }
   public:
      SIMD_4x32 m_lo, m_hi;
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
   SIMD_32 B0 = SIMD_32::load_le(in);
   SIMD_32 B1 = SIMD_32::load_le(in + 16);
   SIMD_32 B2 = SIMD_32::load_le(in + 32);
   SIMD_32 B3 = SIMD_32::load_le(in + 48);

   SIMD_32 C0 = SIMD_32::load_le(in + 64);
   SIMD_32 C1 = SIMD_32::load_le(in + 64 + 16);
   SIMD_32 C2 = SIMD_32::load_le(in + 64 + 32);
   SIMD_32 C3 = SIMD_32::load_le(in + 64 + 48);

   SIMD_32::transpose(B0, B1, B2, B3);
   SIMD_32::transpose(C0, C1, C2, C3);

#if 0
   SIMD_8x32 Z0 = SIMD_8x32::load_le(in);
   SIMD_8x32 Z1 = SIMD_8x32::load_le(in + 32);
   SIMD_8x32 Z2 = SIMD_8x32::load_le(in + 64);
   SIMD_8x32 Z3 = SIMD_8x32::load_le(in + 96);

   SIMD_8x32::transpose(Z0, Z1, Z2, Z3);
   #else
   SIMD_8x32 Z0(B0,C0);
   SIMD_8x32 Z1(B1,C1);
   SIMD_8x32 Z2(B2,C2);
   SIMD_8x32 Z3(B3,C3);
   #endif

   key_xor( 0,Z0,Z1,Z2,Z3); SBoxE1(Z0,Z1,Z2,Z3); transform(Z0,Z1,Z2,Z3);
   key_xor( 1,Z0,Z1,Z2,Z3); SBoxE2(Z0,Z1,Z2,Z3); transform(Z0,Z1,Z2,Z3);
   key_xor( 2,Z0,Z1,Z2,Z3); SBoxE3(Z0,Z1,Z2,Z3); transform(Z0,Z1,Z2,Z3);
   key_xor( 3,Z0,Z1,Z2,Z3); SBoxE4(Z0,Z1,Z2,Z3); transform(Z0,Z1,Z2,Z3);
   key_xor( 4,Z0,Z1,Z2,Z3); SBoxE5(Z0,Z1,Z2,Z3); transform(Z0,Z1,Z2,Z3);
   key_xor( 5,Z0,Z1,Z2,Z3); SBoxE6(Z0,Z1,Z2,Z3); transform(Z0,Z1,Z2,Z3);
   key_xor( 6,Z0,Z1,Z2,Z3); SBoxE7(Z0,Z1,Z2,Z3); transform(Z0,Z1,Z2,Z3);
   key_xor( 7,Z0,Z1,Z2,Z3); SBoxE8(Z0,Z1,Z2,Z3); transform(Z0,Z1,Z2,Z3);

   
   key_xor( 8,Z0,Z1,Z2,Z3); SBoxE1(Z0,Z1,Z2,Z3); transform(Z0,Z1,Z2,Z3);
   key_xor( 9,Z0,Z1,Z2,Z3); SBoxE2(Z0,Z1,Z2,Z3); transform(Z0,Z1,Z2,Z3);
   key_xor(10,Z0,Z1,Z2,Z3); SBoxE3(Z0,Z1,Z2,Z3); transform(Z0,Z1,Z2,Z3);
   key_xor(11,Z0,Z1,Z2,Z3); SBoxE4(Z0,Z1,Z2,Z3); transform(Z0,Z1,Z2,Z3);
   key_xor(12,Z0,Z1,Z2,Z3); SBoxE5(Z0,Z1,Z2,Z3); transform(Z0,Z1,Z2,Z3);
   key_xor(13,Z0,Z1,Z2,Z3); SBoxE6(Z0,Z1,Z2,Z3); transform(Z0,Z1,Z2,Z3);
   key_xor(14,Z0,Z1,Z2,Z3); SBoxE7(Z0,Z1,Z2,Z3); transform(Z0,Z1,Z2,Z3);
   key_xor(15,Z0,Z1,Z2,Z3); SBoxE8(Z0,Z1,Z2,Z3); transform(Z0,Z1,Z2,Z3);

   key_xor(16,Z0,Z1,Z2,Z3); SBoxE1(Z0,Z1,Z2,Z3); transform(Z0,Z1,Z2,Z3);
   key_xor(17,Z0,Z1,Z2,Z3); SBoxE2(Z0,Z1,Z2,Z3); transform(Z0,Z1,Z2,Z3);
   key_xor(18,Z0,Z1,Z2,Z3); SBoxE3(Z0,Z1,Z2,Z3); transform(Z0,Z1,Z2,Z3);
   key_xor(19,Z0,Z1,Z2,Z3); SBoxE4(Z0,Z1,Z2,Z3); transform(Z0,Z1,Z2,Z3);
   key_xor(20,Z0,Z1,Z2,Z3); SBoxE5(Z0,Z1,Z2,Z3); transform(Z0,Z1,Z2,Z3);
   key_xor(21,Z0,Z1,Z2,Z3); SBoxE6(Z0,Z1,Z2,Z3); transform(Z0,Z1,Z2,Z3);
   key_xor(22,Z0,Z1,Z2,Z3); SBoxE7(Z0,Z1,Z2,Z3); transform(Z0,Z1,Z2,Z3);
   key_xor(23,Z0,Z1,Z2,Z3); SBoxE8(Z0,Z1,Z2,Z3); transform(Z0,Z1,Z2,Z3);

   key_xor(24,Z0,Z1,Z2,Z3); SBoxE1(Z0,Z1,Z2,Z3); transform(Z0,Z1,Z2,Z3);
   key_xor(25,Z0,Z1,Z2,Z3); SBoxE2(Z0,Z1,Z2,Z3); transform(Z0,Z1,Z2,Z3);
   key_xor(26,Z0,Z1,Z2,Z3); SBoxE3(Z0,Z1,Z2,Z3); transform(Z0,Z1,Z2,Z3);
   key_xor(27,Z0,Z1,Z2,Z3); SBoxE4(Z0,Z1,Z2,Z3); transform(Z0,Z1,Z2,Z3);
   key_xor(28,Z0,Z1,Z2,Z3); SBoxE5(Z0,Z1,Z2,Z3); transform(Z0,Z1,Z2,Z3);
   key_xor(29,Z0,Z1,Z2,Z3); SBoxE6(Z0,Z1,Z2,Z3); transform(Z0,Z1,Z2,Z3);
   key_xor(30,Z0,Z1,Z2,Z3); SBoxE7(Z0,Z1,Z2,Z3); transform(Z0,Z1,Z2,Z3);
   key_xor(31,Z0,Z1,Z2,Z3); SBoxE8(Z0,Z1,Z2,Z3); key_xor(32,Z0,Z1,Z2,Z3);

   B0 = Z0.m_lo;
   B1 = Z1.m_lo;
   B2 = Z2.m_lo;
   B3 = Z3.m_lo;
   C0 = Z0.m_hi;
   C1 = Z1.m_hi;
   C2 = Z2.m_hi;
   C3 = Z3.m_hi;

   SIMD_32::transpose(B0, B1, B2, B3);
   SIMD_32::transpose(C0, C1, C2, C3);

   B0.store_le(out);
   B1.store_le(out + 16);
   B2.store_le(out + 32);
   B3.store_le(out + 48);

   C0.store_le(out + 64);
   C1.store_le(out + 16 + 64);
   C2.store_le(out + 32 + 64);
   C3.store_le(out + 48 + 64);
   }

/*
* SIMD Serpent Decryption of 4 blocks in parallel
*/
void Serpent::avx2_decrypt_8(const uint8_t in[64], uint8_t out[64]) const
   {

   }

}
