/*************************************************
* Lowest Level MPI Algorithms Header File        *
* (C) 1999-2006 Jack Lloyd                       *
*     2006 Luca Piccarreta                       *
*************************************************/

#ifndef BOTAN_MP_ASM_INTERNAL_H__
#define BOTAN_MP_ASM_INTERNAL_H__

#include "mp_asm.h"

#if (BOTAN_MP_WORD_BITS != 32)
  #error BOTAN_MP_WORD_BITS must be 32 for x86 asm
#endif

namespace Botan {

extern "C" {

/*************************************************
* Word Addition                                  *
*************************************************/
inline word word_add(word x, word y, word* carry)
   {
   word z = x + y;
   word c1 = (z < x);
   z += *carry;
   *carry = c1 | (z < *carry);
   return z;
   }

/*************************************************
* Four Word Block Addition, Two Argument         *
*************************************************/
inline word word4_add2(word x[4], const word y[4], word carry)
   {
      __asm {
       mov esi,[y]
       mov edi,[x]
       xor ecx,ecx
       sub ecx,[carry] //force CF=1 iff *carry==1
       mov eax,[edi]
       mov ecx,[edi+4]
       adc eax,[esi]
       adc ecx,[esi+4]
       mov [edi],eax
       mov [edi+4],ecx
       mov eax,[edi+8]
       mov ecx,[edi+12]
       adc eax,[esi+8]
       adc ecx,[esi+12]
       mov [edi+8],eax
       mov [edi+12],ecx
       sbb edx,edx
       neg edx
       mov eax,edx

   }
   }

/*************************************************
* Four Word Block Addition, Three Argument       *
*************************************************/
inline word word4_add3(word z[4], const word x[4], const word y[4], word carry)
   {
       __asm {
       mov esi,[y]
       mov edi,[x]
       xor ecx,ecx
       sub ecx,[carry] //force CF=1 iff *carry==1
       mov ebx,[z]
       mov eax,[edi]
       mov ecx,[edi+4]
       adc eax,[esi]
       adc ecx,[esi+4]
       mov [ebx],eax
       mov [ebx+4],ecx
       mov eax,[edi+8]
       mov ecx,[edi+12]
       adc eax,[esi+8]
       adc ecx,[esi+12]
       mov [ebx+8],eax
       mov [ebx+12],ecx
       sbb edx,edx
       neg edx
       mov eax,edx
       }
   }

/*************************************************
* Word Subtraction                               *
*************************************************/
inline word word_sub(word x, word y, word* carry)
   {
   word t0 = x - y;
   word c1 = (t0 > x);
   word z = t0 - *carry;
   *carry = c1 | (z > t0);
   return z;
   }

/*************************************************
* Four Word Block Subtraction, Two Argument      *
*************************************************/
inline word word4_sub2(word x[4], const word y[4], word carry)
   {
    _asm {
       mov esi,[y]
       mov edi,[x]
       xor ecx,ecx
       sub ecx,[carry] //force CF=1 iff *carry==1
       mov eax,[edi]
       mov ecx,[edi+4]
       sbb eax,[esi]
       sbb ecx,[esi+4]
       mov [edi],eax
       mov [edi+4],ecx
       mov eax,[edi+8]
       mov ecx,[edi+12]
       sbb eax,[esi+8]
       sbb ecx,[esi+12]
       mov [edi+8],eax
       mov [edi+12],ecx
       sbb edx,edx
       neg edx
       mov eax,edx
    }
   }

/*************************************************
* Four Word Block Subtraction, Three Argument    *
*************************************************/
inline word word4_sub3(word z[4], const word x[4],const word y[4], word carry)
   {
       __asm {
       mov esi,[y]
       mov edi,[x]
       xor ecx,ecx
       sub ecx,[carry] //force CF=1 iff *carry==1
       mov ebx,[z]
       mov eax,[edi]
       mov ecx,[edi+4]
       sbb eax,[esi]
       sbb ecx,[esi+4]
       mov [ebx],eax
       mov [ebx+4],ecx
       mov eax,[edi+8]
       mov ecx,[edi+12]
       sbb eax,[esi+8]
       sbb ecx,[esi+12]
       mov [ebx+8],eax
       mov [ebx+12],ecx
       sbb edx,edx
       neg edx
       mov eax,edx
       }
   }

/*************************************************
* Four Word Block Linear Multiplication          *
*************************************************/
inline word word4_linmul2(word x[4], word y, word carry)
{
   __asm
   {
       mov esi,[x]
       mov eax,[esi]        //load a
       mul [y]           //edx(hi):eax(lo)=a*b
       add eax,[carry]      //sum lo carry
       adc edx,0          //sum hi carry
       mov ecx,edx      //store carry
       mov [esi],eax        //load a

       mov eax,[esi+4]        //load a
       mul [y]           //edx(hi):eax(lo)=a*b
       add eax,ecx      //sum lo carry
       adc edx,0          //sum hi carry
       mov ecx,edx      //store carry
       mov [esi+4],eax        //load a

       mov eax,[esi+8]        //load a
       mul [y]           //edx(hi):eax(lo)=a*b
       add eax,ecx      //sum lo carry
       adc edx,0          //sum hi carry
       mov ecx,edx      //store carry
       mov [esi+8],eax        //load a

       mov eax,[esi+12]        //load a
       mul [y]           //edx(hi):eax(lo)=a*b
       add eax,ecx      //sum lo carry
       adc edx,0          //sum hi carry
       mov [esi+12],eax        //load a
       mov eax,edx      //store carry
   }
   }

/*************************************************
* Four Word Block Linear Multiplication          *
*************************************************/
inline word word4_linmul3(word z[4], const word x[4], word y, word carry)
   {
   __asm
   {
       mov edi,[z]
       mov esi,[x]

       mov eax,[esi]        //load a
       mul [y]           //edx(hi):eax(lo)=a*b
       add eax,[carry]    //sum lo carry
       adc edx,0          //sum hi carry
       mov ecx,edx      //store carry
       mov [edi],eax        //load a

       mov eax,[esi+4]        //load a
       mul [y]           //edx(hi):eax(lo)=a*b
       add eax,ecx      //sum lo carry
       adc edx,0          //sum hi carry
       mov ecx,edx      //store carry
       mov [edi+4],eax        //load a

       mov eax,[esi+8]        //load a
       mul [y]           //edx(hi):eax(lo)=a*b
       add eax,ecx      //sum lo carry
       adc edx,0          //sum hi carry
       mov ecx,edx      //store carry
       mov [edi+8],eax        //load a

       mov eax,[esi+12]        //load a
       mul [y]           //edx(hi):eax(lo)=a*b
       add eax,ecx      //sum lo carry
       adc edx,0          //sum hi carry
       mov [edi+12],eax        //load a
       mov eax,edx      //store carry

   }
   }

/*************************************************
* Eight Word Block Multiply-Add                  *
*************************************************/
inline void word8_madd3(word z[], word x, const word y[], word* carry)
   {
   word_madd(x, y[0], z[0], *carry, z + 0, carry);
   word_madd(x, y[1], z[1], *carry, z + 1, carry);
   word_madd(x, y[2], z[2], *carry, z + 2, carry);
   word_madd(x, y[3], z[3], *carry, z + 3, carry);
   word_madd(x, y[4], z[4], *carry, z + 4, carry);
   word_madd(x, y[5], z[5], *carry, z + 5, carry);
   word_madd(x, y[6], z[6], *carry, z + 6, carry);
   word_madd(x, y[7], z[7], *carry, z + 7, carry);
   }

/*************************************************
* Multiply-Add Accumulator                       *
*************************************************/
inline void word3_muladd(word* w2, word* w1, word* w0, word a, word b)
   {
   dword z = (dword)a * b + (*w0);
   *w0 = (word)z;  //lo

   word t1 = (word)(z >> BOTAN_MP_WORD_BITS); //hi
   *w1 += t1; //w1+=lo
   *w2 += (*w1 < t1) ? 1 : 0; //w2+=carry
   }

/*************************************************
* Multiply-Add Accumulator                       *
*************************************************/
inline void word3_muladd_2(word* w2, word* w1, word* w0, word a, word b)
   {
   dword z = (dword)a * b;
   word t0 = (word)z;
   word t1 = (word)(z >> BOTAN_MP_WORD_BITS);

   *w0 += t0;
   *w1 += t1 + ((*w0 < t0) ? 1 : 0);
   *w2 += (*w1 < t1) ? 1 : 0;

   *w0 += t0;
   *w1 += t1 + ((*w0 < t0) ? 1 : 0);
   *w2 += (*w1 < t1) ? 1 : 0;
   }

}

}

#endif
