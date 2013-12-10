/*
* Scalar emulation of SIMD
* (C) 2009,2013 Jack Lloyd
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
template<typename T>
class SIMD_4_Scalar
   {
   public:
      static bool enabled() { return true; }

      SIMD_4_Scalar(const T B[4])
         {
         R0 = B[0];
         R1 = B[1];
         R2 = B[2];
         R3 = B[3];
         }

      SIMD_4_Scalar(T B0, T B1, T B2, T B3)
         {
         R0 = B0;
         R1 = B1;
         R2 = B2;
         R3 = B3;
         }

      SIMD_4_Scalar(T B)
         {
         R0 = B;
         R1 = B;
         R2 = B;
         R3 = B;
         }

      static SIMD_4_Scalar<T> load_le(const void* in)
         {
         const byte* in_b = static_cast<const byte*>(in);
         return SIMD_4_Scalar<T>(Botan::load_le<T>(in_b, 0),
                                 Botan::load_le<T>(in_b, 1),
                                 Botan::load_le<T>(in_b, 2),
                                 Botan::load_le<T>(in_b, 3));
         }

      static SIMD_4_Scalar<T> load_be(const void* in)
         {
         const byte* in_b = static_cast<const byte*>(in);
         return SIMD_4_Scalar<T>(Botan::load_be<T>(in_b, 0),
                                 Botan::load_be<T>(in_b, 1),
                                 Botan::load_be<T>(in_b, 2),
                                 Botan::load_be<T>(in_b, 3));
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

      void operator+=(const SIMD_4_Scalar<T>& other)
         {
         R0 += other.R0;
         R1 += other.R1;
         R2 += other.R2;
         R3 += other.R3;
         }

      SIMD_4_Scalar<T> operator+(const SIMD_4_Scalar<T>& other) const
         {
         return SIMD_4_Scalar<T>(R0 + other.R0,
                            R1 + other.R1,
                            R2 + other.R2,
                            R3 + other.R3);
         }

      void operator-=(const SIMD_4_Scalar<T>& other)
         {
         R0 -= other.R0;
         R1 -= other.R1;
         R2 -= other.R2;
         R3 -= other.R3;
         }

      SIMD_4_Scalar<T> operator-(const SIMD_4_Scalar<T>& other) const
         {
         return SIMD_4_Scalar<T>(R0 - other.R0,
                                 R1 - other.R1,
                                 R2 - other.R2,
                                 R3 - other.R3);
         }

      void operator^=(const SIMD_4_Scalar<T>& other)
         {
         R0 ^= other.R0;
         R1 ^= other.R1;
         R2 ^= other.R2;
         R3 ^= other.R3;
         }

      SIMD_4_Scalar<T> operator^(const SIMD_4_Scalar<T>& other) const
         {
         return SIMD_4_Scalar<T>(R0 ^ other.R0,
                            R1 ^ other.R1,
                            R2 ^ other.R2,
                            R3 ^ other.R3);
         }

      void operator|=(const SIMD_4_Scalar<T>& other)
         {
         R0 |= other.R0;
         R1 |= other.R1;
         R2 |= other.R2;
         R3 |= other.R3;
         }

      SIMD_4_Scalar<T> operator&(const SIMD_4_Scalar<T>& other)
         {
         return SIMD_4_Scalar<T>(R0 & other.R0,
                                 R1 & other.R1,
                                 R2 & other.R2,
                                 R3 & other.R3);
         }

      void operator&=(const SIMD_4_Scalar<T>& other)
         {
         R0 &= other.R0;
         R1 &= other.R1;
         R2 &= other.R2;
         R3 &= other.R3;
         }

      SIMD_4_Scalar<T> operator<<(size_t shift) const
         {
         return SIMD_4_Scalar<T>(R0 << shift,
                                 R1 << shift,
                                 R2 << shift,
                                 R3 << shift);
         }

      SIMD_4_Scalar<T> operator>>(size_t shift) const
         {
         return SIMD_4_Scalar<T>(R0 >> shift,
                                 R1 >> shift,
                                 R2 >> shift,
                                 R3 >> shift);
         }

      SIMD_4_Scalar<T> operator~() const
         {
         return SIMD_4_Scalar<T>(~R0, ~R1, ~R2, ~R3);
         }

      // (~reg) & other
      SIMD_4_Scalar<T> andc(const SIMD_4_Scalar<T>& other)
         {
         return SIMD_4_Scalar<T>(~R0 & other.R0,
                                 ~R1 & other.R1,
                                 ~R2 & other.R2,
                                 ~R3 & other.R3);
         }

      SIMD_4_Scalar<T> bswap() const
         {
         return SIMD_4_Scalar<T>(reverse_bytes(R0),
                                 reverse_bytes(R1),
                                 reverse_bytes(R2),
                                 reverse_bytes(R3));
         }

      static void transpose(SIMD_4_Scalar<T>& B0, SIMD_4_Scalar<T>& B1,
                            SIMD_4_Scalar<T>& B2, SIMD_4_Scalar<T>& B3)
         {
         SIMD_4_Scalar<T> T0(B0.R0, B1.R0, B2.R0, B3.R0);
         SIMD_4_Scalar<T> T1(B0.R1, B1.R1, B2.R1, B3.R1);
         SIMD_4_Scalar<T> T2(B0.R2, B1.R2, B2.R2, B3.R2);
         SIMD_4_Scalar<T> T3(B0.R3, B1.R3, B2.R3, B3.R3);

         B0 = T0;
         B1 = T1;
         B2 = T2;
         B3 = T3;
         }

   private:
      T R0, R1, R2, R3;
   };

}

#endif
