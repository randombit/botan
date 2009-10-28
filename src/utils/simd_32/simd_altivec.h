/**
* Altivec SIMD
*/

#ifndef BOTAN_SIMD_ALTIVEC_H__
#define BOTAN_SIMD_ALTIVEC_H__

#include <botan/loadstor.h>
#include <altivec.h>
#undef vector

namespace Botan {

class SIMD_Altivec
   {
   public:

      SIMD_Altivec(const u32bit B[4])
         {
         reg = (__vector unsigned int){B[0], B[1], B[2], B[3]};
         }

      SIMD_Altivec(u32bit B0, u32bit B1, u32bit B2, u32bit B3)
         {
         reg = (__vector unsigned int){B0, B1, B2, B3};
         }

      SIMD_Altivec(u32bit B)
         {
         reg = (__vector unsigned int){B, B, B, B};
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
         u32bit* out_32 = reinterpret_cast<u32bit*>(out);

         __vector unsigned char perm = vec_lvsl(0, (int*)0);

         perm = vec_xor(perm, vec_splat_u8(3));

         __vector unsigned int swapped = vec_perm(reg, reg, perm);

         vec_st(swapped, 0, out_32);
         }

      void store_be(byte out[]) const
         {
         u32bit* out_32 = reinterpret_cast<u32bit*>(out);
         vec_st(reg, 0, out_32);
         }

      void rotate_left(u32bit rot)
         {
         __vector unsigned int rot_vec =
            (__vector unsigned int){rot, rot, rot, rot};

         reg = vec_rl(reg, rot_vec);
         }

      void rotate_right(u32bit rot)
         {
         rotate_left(32 - rot);
         }

      void operator+=(const SIMD_Altivec& other)
         {
         reg = vec_add(reg, other.reg);
         }

      SIMD_Altivec operator+(const SIMD_Altivec& other) const
         {
         return vec_add(reg, other.reg);
         }

      void operator-=(const SIMD_Altivec& other)
         {
         reg = vec_sub(reg, other.reg);
         }

      SIMD_Altivec operator-(const SIMD_Altivec& other) const
         {
         return vec_sub(reg, other.reg);
         }

      void operator^=(const SIMD_Altivec& other)
         {
         reg = vec_xor(reg, other.reg);
         }

      SIMD_Altivec operator^(const SIMD_Altivec& other) const
         {
         return vec_xor(reg, other.reg);
         }

      void operator|=(const SIMD_Altivec& other)
         {
         reg = vec_or(reg, other.reg);
         }

      void operator&=(const SIMD_Altivec& other)
         {
         reg = vec_and(reg, other.reg);
         }

      SIMD_Altivec operator<<(u32bit shift) const
         {
         __vector unsigned int shift_vec =
            (__vector unsigned int){shift, shift, shift, shift};

         return vec_sl(reg, shift_vec);
         }

      SIMD_Altivec operator>>(u32bit shift) const
         {
         __vector unsigned int shift_vec =
            (__vector unsigned int){shift, shift, shift, shift};

         return vec_sr(reg, shift_vec);
         }

      SIMD_Altivec operator~() const
         {
         return vec_nor(reg, reg);
         }

      static void transpose(SIMD_Altivec& B0, SIMD_Altivec& B1,
                            SIMD_Altivec& B2, SIMD_Altivec& B3)
         {
         __vector unsigned int T0 = vec_mergeh(B0.reg, B2.reg);
         __vector unsigned int T1 = vec_mergel(B0.reg, B2.reg);
         __vector unsigned int T2 = vec_mergeh(B1.reg, B3.reg);
         __vector unsigned int T3 = vec_mergel(B1.reg, B3.reg);

         B0.reg = vec_mergeh(T0, T2);
         B1.reg = vec_mergel(T0, T2);
         B2.reg = vec_mergeh(T1, T3);
         B3.reg = vec_mergel(T1, T3);
         }

   private:
      SIMD_Altivec(__vector unsigned int input) { reg = input; }

      __vector unsigned int reg;
   };

}

#endif
