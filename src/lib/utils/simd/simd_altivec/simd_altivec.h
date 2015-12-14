/*
* Lightweight wrappers around AltiVec for 32-bit operations
* (C) 2009 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_SIMD_ALTIVEC_H__
#define BOTAN_SIMD_ALTIVEC_H__

#if defined(BOTAN_TARGET_SUPPORTS_ALTIVEC)

#include <botan/loadstor.h>
#include <botan/cpuid.h>

#include <altivec.h>
#undef vector
#undef bool

namespace Botan {

class SIMD_Altivec
   {
   public:
      SIMD_Altivec(const u32bit B[4])
         {
         m_reg = (__vector unsigned int){B[0], B[1], B[2], B[3]};
         }

      SIMD_Altivec(u32bit B0, u32bit B1, u32bit B2, u32bit B3)
         {
         m_reg = (__vector unsigned int){B0, B1, B2, B3};
         }

      SIMD_Altivec(u32bit B)
         {
         m_reg = (__vector unsigned int){B, B, B, B};
         }

      static SIMD_Altivec load_le(const void* in)
         {
         const u32bit* in_32 = static_cast<const u32bit*>(in);

         __vector unsigned int R0 = vec_ld(0, in_32);
         __vector unsigned int R1 = vec_ld(12, in_32);

         __vector unsigned char perm = vec_lvsl(0, in_32);

         perm = vec_xor(perm, vec_splat_u8(3));

         R0 = vec_perm(R0, R1, perm);

         return SIMD_Altivec(R0);
         }

      static SIMD_Altivec load_be(const void* in)
         {
         const u32bit* in_32 = static_cast<const u32bit*>(in);

         __vector unsigned int R0 = vec_ld(0, in_32);
         __vector unsigned int R1 = vec_ld(12, in_32);

         __vector unsigned char perm = vec_lvsl(0, in_32);

         R0 = vec_perm(R0, R1, perm);

         return SIMD_Altivec(R0);
         }

      void store_le(byte out[]) const
         {
         __vector unsigned char perm = vec_lvsl(0, static_cast<u32bit*>(nullptr));

         perm = vec_xor(perm, vec_splat_u8(3));

         union {
            __vector unsigned int V;
            u32bit R[4];
            } vec;

         vec.V = vec_perm(m_reg, m_reg, perm);

         Botan::store_be(out, vec.R[0], vec.R[1], vec.R[2], vec.R[3]);
         }

      void store_be(byte out[]) const
         {
         union {
            __vector unsigned int V;
            u32bit R[4];
            } vec;

         vec.V = m_reg;

         Botan::store_be(out, vec.R[0], vec.R[1], vec.R[2], vec.R[3]);
         }

      void rotate_left(size_t rot)
         {
         const unsigned int r = static_cast<unsigned int>(rot);
         m_reg = vec_rl(m_reg, (__vector unsigned int){r, r, r, r});
         }

      void rotate_right(size_t rot)
         {
         rotate_left(32 - rot);
         }

      void operator+=(const SIMD_Altivec& other)
         {
         m_reg = vec_add(m_reg, other.m_reg);
         }

      SIMD_Altivec operator+(const SIMD_Altivec& other) const
         {
         return vec_add(m_reg, other.m_reg);
         }

      void operator-=(const SIMD_Altivec& other)
         {
         m_reg = vec_sub(m_reg, other.m_reg);
         }

      SIMD_Altivec operator-(const SIMD_Altivec& other) const
         {
         return vec_sub(m_reg, other.m_reg);
         }

      void operator^=(const SIMD_Altivec& other)
         {
         m_reg = vec_xor(m_reg, other.m_reg);
         }

      SIMD_Altivec operator^(const SIMD_Altivec& other) const
         {
         return vec_xor(m_reg, other.m_reg);
         }

      void operator|=(const SIMD_Altivec& other)
         {
         m_reg = vec_or(m_reg, other.m_reg);
         }

      SIMD_Altivec operator&(const SIMD_Altivec& other)
         {
         return vec_and(m_reg, other.m_reg);
         }

      void operator&=(const SIMD_Altivec& other)
         {
         m_reg = vec_and(m_reg, other.m_reg);
         }

      SIMD_Altivec operator<<(size_t shift) const
         {
         const unsigned int s = static_cast<unsigned int>(shift);
         return vec_sl(m_reg, (__vector unsigned int){s, s, s, s});
         }

      SIMD_Altivec operator>>(size_t shift) const
         {
         const unsigned int s = static_cast<unsigned int>(shift);
         return vec_sr(m_reg, (__vector unsigned int){s, s, s, s});
         }

      SIMD_Altivec operator~() const
         {
         return vec_nor(m_reg, m_reg);
         }

      SIMD_Altivec andc(const SIMD_Altivec& other)
         {
         /*
         AltiVec does arg1 & ~arg2 rather than SSE's ~arg1 & arg2
         so swap the arguments
         */
         return vec_andc(other.m_reg, m_reg);
         }

      SIMD_Altivec bswap() const
         {
         __vector unsigned char perm = vec_lvsl(0, static_cast<u32bit*>(nullptr));

         perm = vec_xor(perm, vec_splat_u8(3));

         return SIMD_Altivec(vec_perm(m_reg, m_reg, perm));
         }

      static void transpose(SIMD_Altivec& B0, SIMD_Altivec& B1,
                            SIMD_Altivec& B2, SIMD_Altivec& B3)
         {
         __vector unsigned int T0 = vec_mergeh(B0.m_reg, B2.m_reg);
         __vector unsigned int T1 = vec_mergel(B0.m_reg, B2.m_reg);
         __vector unsigned int T2 = vec_mergeh(B1.m_reg, B3.m_reg);
         __vector unsigned int T3 = vec_mergel(B1.m_reg, B3.m_reg);

         B0.m_reg = vec_mergeh(T0, T2);
         B1.m_reg = vec_mergel(T0, T2);
         B2.m_reg = vec_mergeh(T1, T3);
         B3.m_reg = vec_mergel(T1, T3);
         }

   private:
      SIMD_Altivec(__vector unsigned int input) { m_reg = input; }

      __vector unsigned int m_reg;
   };

}

#endif

#endif
