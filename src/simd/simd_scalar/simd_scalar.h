/*
* Scalar emulation of SIMD 32-bit operations
* (C) 2009 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_SIMD_SCALAR_H__
#define BOTAN_SIMD_SCALAR_H__

#include <botan/loadstor.h>
#include <botan/bswap.h>

namespace Botan {

/**
* Fake SIMD, using plain scalar operations
* Often still faster than iterative on superscalar machines
*/
class SIMD_Scalar
   {
   public:
      static bool enabled() { return true; }

      SIMD_Scalar(const u32bit B[4])
         {
         R0 = B[0];
         R1 = B[1];
         R2 = B[2];
         R3 = B[3];
         }

      SIMD_Scalar(u32bit B0, u32bit B1, u32bit B2, u32bit B3)
         {
         R0 = B0;
         R1 = B1;
         R2 = B2;
         R3 = B3;
         }

      SIMD_Scalar(u32bit B)
         {
         R0 = B;
         R1 = B;
         R2 = B;
         R3 = B;
         }

      static SIMD_Scalar load_le(const void* in)
         {
         const byte* in_b = static_cast<const byte*>(in);
         return SIMD_Scalar(Botan::load_le<u32bit>(in_b, 0),
                            Botan::load_le<u32bit>(in_b, 1),
                            Botan::load_le<u32bit>(in_b, 2),
                            Botan::load_le<u32bit>(in_b, 3));
         }

      static SIMD_Scalar load_be(const void* in)
         {
         const byte* in_b = static_cast<const byte*>(in);
         return SIMD_Scalar(Botan::load_be<u32bit>(in_b, 0),
                            Botan::load_be<u32bit>(in_b, 1),
                            Botan::load_be<u32bit>(in_b, 2),
                            Botan::load_be<u32bit>(in_b, 3));
         }

      void store_le(byte out[]) const
         {
         Botan::store_le(out, R0, R1, R2, R3);
         }

      void store_be(byte out[]) const
         {
         Botan::store_be(out, R0, R1, R2, R3);
         }

      void rotate_left(size_t rot)
         {
         R0 = Botan::rotate_left(R0, rot);
         R1 = Botan::rotate_left(R1, rot);
         R2 = Botan::rotate_left(R2, rot);
         R3 = Botan::rotate_left(R3, rot);
         }

      void rotate_right(size_t rot)
         {
         R0 = Botan::rotate_right(R0, rot);
         R1 = Botan::rotate_right(R1, rot);
         R2 = Botan::rotate_right(R2, rot);
         R3 = Botan::rotate_right(R3, rot);
         }

      void operator+=(const SIMD_Scalar& other)
         {
         R0 += other.R0;
         R1 += other.R1;
         R2 += other.R2;
         R3 += other.R3;
         }

      SIMD_Scalar operator+(const SIMD_Scalar& other) const
         {
         return SIMD_Scalar(R0 + other.R0,
                            R1 + other.R1,
                            R2 + other.R2,
                            R3 + other.R3);
         }

      void operator-=(const SIMD_Scalar& other)
         {
         R0 -= other.R0;
         R1 -= other.R1;
         R2 -= other.R2;
         R3 -= other.R3;
         }

      SIMD_Scalar operator-(const SIMD_Scalar& other) const
         {
         return SIMD_Scalar(R0 - other.R0,
                            R1 - other.R1,
                            R2 - other.R2,
                            R3 - other.R3);
         }

      void operator^=(const SIMD_Scalar& other)
         {
         R0 ^= other.R0;
         R1 ^= other.R1;
         R2 ^= other.R2;
         R3 ^= other.R3;
         }

      SIMD_Scalar operator^(const SIMD_Scalar& other) const
         {
         return SIMD_Scalar(R0 ^ other.R0,
                            R1 ^ other.R1,
                            R2 ^ other.R2,
                            R3 ^ other.R3);
         }

      void operator|=(const SIMD_Scalar& other)
         {
         R0 |= other.R0;
         R1 |= other.R1;
         R2 |= other.R2;
         R3 |= other.R3;
         }

      SIMD_Scalar operator&(const SIMD_Scalar& other)
         {
         return SIMD_Scalar(R0 & other.R0,
                            R1 & other.R1,
                            R2 & other.R2,
                            R3 & other.R3);
         }

      void operator&=(const SIMD_Scalar& other)
         {
         R0 &= other.R0;
         R1 &= other.R1;
         R2 &= other.R2;
         R3 &= other.R3;
         }

      SIMD_Scalar operator<<(size_t shift) const
         {
         return SIMD_Scalar(R0 << shift,
                            R1 << shift,
                            R2 << shift,
                            R3 << shift);
         }

      SIMD_Scalar operator>>(size_t shift) const
         {
         return SIMD_Scalar(R0 >> shift,
                            R1 >> shift,
                            R2 >> shift,
                            R3 >> shift);
         }

      SIMD_Scalar operator~() const
         {
         return SIMD_Scalar(~R0, ~R1, ~R2, ~R3);
         }

      // (~reg) & other
      SIMD_Scalar andc(const SIMD_Scalar& other)
         {
         return SIMD_Scalar(~R0 & other.R0,
                            ~R1 & other.R1,
                            ~R2 & other.R2,
                            ~R3 & other.R3);
         }

      SIMD_Scalar bswap() const
         {
         return SIMD_Scalar(reverse_bytes(R0),
                            reverse_bytes(R1),
                            reverse_bytes(R2),
                            reverse_bytes(R3));
         }

      static void transpose(SIMD_Scalar& B0, SIMD_Scalar& B1,
                            SIMD_Scalar& B2, SIMD_Scalar& B3)
         {
         SIMD_Scalar T0(B0.R0, B1.R0, B2.R0, B3.R0);
         SIMD_Scalar T1(B0.R1, B1.R1, B2.R1, B3.R1);
         SIMD_Scalar T2(B0.R2, B1.R2, B2.R2, B3.R2);
         SIMD_Scalar T3(B0.R3, B1.R3, B2.R3, B3.R3);

         B0 = T0;
         B1 = T1;
         B2 = T2;
         B3 = T3;
         }

   private:
      u32bit R0, R1, R2, R3;
   };

}

#endif
