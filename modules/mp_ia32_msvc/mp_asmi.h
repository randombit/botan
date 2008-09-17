/*************************************************
* Lowest Level MPI Algorithms Header File        *
* (C) 1999-2006 Jack Lloyd                       *
*     2006 Luca Piccarreta                       *
*************************************************/

#ifndef BOTAN_MP_ASM_INTERNAL_H__
#define BOTAN_MP_ASM_INTERNAL_H__

#include "mp_asm.h"

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
inline word word4_addcarry(word x[4], word carry)
   {
    __asm {
       mov edx,[x]
       xor eax,eax
       sub eax,[carry] //force CF=1 iff *carry==1
       adc [edx],0
       mov eax,[esi+4]
       adc [edx+4],0
       mov eax,[esi+8]
       adc [edx+8],0
       mov eax,[esi+12]
       adc [edx+12],0
       sbb eax,eax
       neg eax
       }
   }

/*************************************************
* Four Word Block Addition, Two Argument         *
*************************************************/
inline word word8_add2(word x[4], const word y[4], word carry)
   {
   __asm {
       mov edx,[x]
       mov esi,[y]
       xor eax,eax
       sub eax,[carry] //force CF=1 iff *carry==1
       mov eax,[esi]
       adc [edx],eax
       mov eax,[esi+4]
       adc [edx+4],eax
       mov eax,[esi+8]
       adc [edx+8],eax
       mov eax,[esi+12]
       adc [edx+12],eax
       mov eax,[esi+16]
       adc [edx+16],eax
       mov eax,[esi+20]
       adc [edx+20],eax
       mov eax,[esi+24]
       adc [edx+24],eax
       mov eax,[esi+28]
       adc [edx+28],eax
       sbb eax,eax
       neg eax
      }
   }

/*************************************************
* Four Word Block Addition, Three Argument       *
*************************************************/
inline word word8_add3(word z[4], const word x[4], const word y[4], word carry)
   {
   __asm {
       mov edi,[x]
       mov esi,[y]
       mov ebx,[z]
       xor eax,eax
       sub eax,[carry] //force CF=1 iff *carry==1
       mov eax,[edi]
       adc eax,[esi]
       mov [ebx],eax

       mov eax,[edi+4]
       adc eax,[esi+4]
       mov [ebx+4],eax

       mov eax,[edi+8]
       adc eax,[esi+8]
       mov [ebx+8],eax

       mov eax,[edi+12]
       adc eax,[esi+12]
       mov [ebx+12],eax

       mov eax,[edi+16]
       adc eax,[esi+16]
       mov [ebx+16],eax

       mov eax,[edi+20]
       adc eax,[esi+20]
       mov [ebx+20],eax

       mov eax,[edi+24]
       adc eax,[esi+24]
       mov [ebx+24],eax

       mov eax,[edi+28]
       adc eax,[esi+28]
       mov [ebx+28],eax

       sbb eax,eax
       neg eax
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
inline word word8_sub2(word x[4], const word y[4], word carry)
   {
    _asm {
       mov edi,[x]
       mov esi,[y]
       xor eax,eax
       sub eax,[carry] //force CF=1 iff *carry==1
       mov eax,[edi]
       sbb eax,[esi]
       mov [edi],eax
       mov eax,[edi+4]
       sbb eax,[esi+4]
       mov [edi+4],eax
       mov eax,[edi+8]
       sbb eax,[esi+8]
       mov [edi+8],eax
       mov eax,[edi+12]
       sbb eax,[esi+12]
       mov [edi+12],eax
       mov eax,[edi+16]
       sbb eax,[esi+16]
       mov [edi+16],eax
       mov eax,[edi+20]
       sbb eax,[esi+20]
       mov [edi+20],eax
       mov eax,[edi+24]
       sbb eax,[esi+24]
       mov [edi+24],eax
       mov eax,[edi+28]
       sbb eax,[esi+28]
       mov [edi+28],eax
       sbb eax,eax
       neg eax
    }
   }

/*************************************************
* Four Word Block Subtraction, Three Argument    *
*************************************************/
__forceinline word word8_sub3(word z[8], const word x[8],
                              const word y[8], word carry)
   {
       __asm {
       mov edi,[x]
       mov esi,[y]
       xor eax,eax
       sub eax,[carry] //force CF=1 iff *carry==1
       mov ebx,[z]
       mov eax,[edi]
       sbb eax,[esi]
       mov [ebx],eax
       mov eax,[edi+4]
       sbb eax,[esi+4]
       mov [ebx+4],eax
       mov eax,[edi+8]
       sbb eax,[esi+8]
       mov [ebx+8],eax
       mov eax,[edi+12]
       sbb eax,[esi+12]
       mov [ebx+12],eax
       mov eax,[edi+16]
       sbb eax,[esi+16]
       mov [ebx+16],eax
       mov eax,[edi+20]
       sbb eax,[esi+20]
       mov [ebx+20],eax
       mov eax,[edi+24]
       sbb eax,[esi+24]
       mov [ebx+24],eax
       mov eax,[edi+28]
       sbb eax,[esi+28]
       mov [ebx+28],eax
       sbb eax,eax
       neg eax
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
* Eight Word Block Linear Multiplication          *
*************************************************/
__forceinline word word8_linmul3(word z[4], const word x[4],
                                 word y, word carry)
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
       mov ecx,edx      //store carry
       mov [edi+12],eax        //load a

       mov eax,[esi+16]        //load a
       mul [y]           //edx(hi):eax(lo)=a*b
       add eax,ecx      //sum lo carry
       adc edx,0          //sum hi carry
       mov ecx,edx      //store carry
       mov [edi+16],eax        //load a

       mov eax,[esi+20]        //load a
       mul [y]           //edx(hi):eax(lo)=a*b
       add eax,ecx      //sum lo carry
       adc edx,0          //sum hi carry
       mov ecx,edx      //store carry
       mov [edi+20],eax        //load a

       mov eax,[esi+24]        //load a
       mul [y]           //edx(hi):eax(lo)=a*b
       add eax,ecx      //sum lo carry
       adc edx,0          //sum hi carry
       mov ecx,edx      //store carry
       mov [edi+24],eax        //load a

       mov eax,[esi+28]        //load a
       mul [y]           //edx(hi):eax(lo)=a*b
       add eax,ecx      //sum lo carry
       adc edx,0          //sum hi carry
       mov [edi+28],eax        //load a
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
