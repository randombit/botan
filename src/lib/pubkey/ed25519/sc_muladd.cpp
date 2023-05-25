/*
* Ed25519
* (C) 2017 Ribose Inc
*
* Based on the public domain code from SUPERCOP ref10 by
* Peter Schwabe, Daniel J. Bernstein, Niels Duif, Tanja Lange, Bo-Yin Yang
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/ed25519_internal.h>

namespace Botan {

/*
Input:
  a[0]+256*a[1]+...+256^31*a[31] = a
  b[0]+256*b[1]+...+256^31*b[31] = b
  c[0]+256*c[1]+...+256^31*c[31] = c

Output:
  s[0]+256*s[1]+...+256^31*s[31] = (ab+c) mod l
  where l = 2^252 + 27742317777372353535851937790883648493.
*/

void sc_muladd(uint8_t* s, const uint8_t* a, const uint8_t* b, const uint8_t* c) {
   const int32_t MASK = 0x1fffff;

   const int64_t a0 = MASK & load_3(a);
   const int64_t a1 = MASK & (load_4(a + 2) >> 5);
   const int64_t a2 = MASK & (load_3(a + 5) >> 2);
   const int64_t a3 = MASK & (load_4(a + 7) >> 7);
   const int64_t a4 = MASK & (load_4(a + 10) >> 4);
   const int64_t a5 = MASK & (load_3(a + 13) >> 1);
   const int64_t a6 = MASK & (load_4(a + 15) >> 6);
   const int64_t a7 = MASK & (load_3(a + 18) >> 3);
   const int64_t a8 = MASK & load_3(a + 21);
   const int64_t a9 = MASK & (load_4(a + 23) >> 5);
   const int64_t a10 = MASK & (load_3(a + 26) >> 2);
   const int64_t a11 = (load_4(a + 28) >> 7);
   const int64_t b0 = MASK & load_3(b);
   const int64_t b1 = MASK & (load_4(b + 2) >> 5);
   const int64_t b2 = MASK & (load_3(b + 5) >> 2);
   const int64_t b3 = MASK & (load_4(b + 7) >> 7);
   const int64_t b4 = MASK & (load_4(b + 10) >> 4);
   const int64_t b5 = MASK & (load_3(b + 13) >> 1);
   const int64_t b6 = MASK & (load_4(b + 15) >> 6);
   const int64_t b7 = MASK & (load_3(b + 18) >> 3);
   const int64_t b8 = MASK & load_3(b + 21);
   const int64_t b9 = MASK & (load_4(b + 23) >> 5);
   const int64_t b10 = MASK & (load_3(b + 26) >> 2);
   const int64_t b11 = (load_4(b + 28) >> 7);
   const int64_t c0 = MASK & load_3(c);
   const int64_t c1 = MASK & (load_4(c + 2) >> 5);
   const int64_t c2 = MASK & (load_3(c + 5) >> 2);
   const int64_t c3 = MASK & (load_4(c + 7) >> 7);
   const int64_t c4 = MASK & (load_4(c + 10) >> 4);
   const int64_t c5 = MASK & (load_3(c + 13) >> 1);
   const int64_t c6 = MASK & (load_4(c + 15) >> 6);
   const int64_t c7 = MASK & (load_3(c + 18) >> 3);
   const int64_t c8 = MASK & load_3(c + 21);
   const int64_t c9 = MASK & (load_4(c + 23) >> 5);
   const int64_t c10 = MASK & (load_3(c + 26) >> 2);
   const int64_t c11 = (load_4(c + 28) >> 7);

   int64_t s0 = c0 + a0 * b0;
   int64_t s1 = c1 + a0 * b1 + a1 * b0;
   int64_t s2 = c2 + a0 * b2 + a1 * b1 + a2 * b0;
   int64_t s3 = c3 + a0 * b3 + a1 * b2 + a2 * b1 + a3 * b0;
   int64_t s4 = c4 + a0 * b4 + a1 * b3 + a2 * b2 + a3 * b1 + a4 * b0;
   int64_t s5 = c5 + a0 * b5 + a1 * b4 + a2 * b3 + a3 * b2 + a4 * b1 + a5 * b0;
   int64_t s6 = c6 + a0 * b6 + a1 * b5 + a2 * b4 + a3 * b3 + a4 * b2 + a5 * b1 + a6 * b0;
   int64_t s7 = c7 + a0 * b7 + a1 * b6 + a2 * b5 + a3 * b4 + a4 * b3 + a5 * b2 + a6 * b1 + a7 * b0;
   int64_t s8 = c8 + a0 * b8 + a1 * b7 + a2 * b6 + a3 * b5 + a4 * b4 + a5 * b3 + a6 * b2 + a7 * b1 + a8 * b0;
   int64_t s9 = c9 + a0 * b9 + a1 * b8 + a2 * b7 + a3 * b6 + a4 * b5 + a5 * b4 + a6 * b3 + a7 * b2 + a8 * b1 + a9 * b0;
   int64_t s10 = c10 + a0 * b10 + a1 * b9 + a2 * b8 + a3 * b7 + a4 * b6 + a5 * b5 + a6 * b4 + a7 * b3 + a8 * b2 +
                 a9 * b1 + a10 * b0;
   int64_t s11 = c11 + a0 * b11 + a1 * b10 + a2 * b9 + a3 * b8 + a4 * b7 + a5 * b6 + a6 * b5 + a7 * b4 + a8 * b3 +
                 a9 * b2 + a10 * b1 + a11 * b0;
   int64_t s12 =
      a1 * b11 + a2 * b10 + a3 * b9 + a4 * b8 + a5 * b7 + a6 * b6 + a7 * b5 + a8 * b4 + a9 * b3 + a10 * b2 + a11 * b1;
   int64_t s13 = a2 * b11 + a3 * b10 + a4 * b9 + a5 * b8 + a6 * b7 + a7 * b6 + a8 * b5 + a9 * b4 + a10 * b3 + a11 * b2;
   int64_t s14 = a3 * b11 + a4 * b10 + a5 * b9 + a6 * b8 + a7 * b7 + a8 * b6 + a9 * b5 + a10 * b4 + a11 * b3;
   int64_t s15 = a4 * b11 + a5 * b10 + a6 * b9 + a7 * b8 + a8 * b7 + a9 * b6 + a10 * b5 + a11 * b4;
   int64_t s16 = a5 * b11 + a6 * b10 + a7 * b9 + a8 * b8 + a9 * b7 + a10 * b6 + a11 * b5;
   int64_t s17 = a6 * b11 + a7 * b10 + a8 * b9 + a9 * b8 + a10 * b7 + a11 * b6;
   int64_t s18 = a7 * b11 + a8 * b10 + a9 * b9 + a10 * b8 + a11 * b7;
   int64_t s19 = a8 * b11 + a9 * b10 + a10 * b9 + a11 * b8;
   int64_t s20 = a9 * b11 + a10 * b10 + a11 * b9;
   int64_t s21 = a10 * b11 + a11 * b10;
   int64_t s22 = a11 * b11;
   int64_t s23 = 0;

   carry<21>(s0, s1);
   carry<21>(s2, s3);
   carry<21>(s4, s5);
   carry<21>(s6, s7);
   carry<21>(s8, s9);
   carry<21>(s10, s11);
   carry<21>(s12, s13);
   carry<21>(s14, s15);
   carry<21>(s16, s17);
   carry<21>(s18, s19);
   carry<21>(s20, s21);
   carry<21>(s22, s23);

   carry<21>(s1, s2);
   carry<21>(s3, s4);
   carry<21>(s5, s6);
   carry<21>(s7, s8);
   carry<21>(s9, s10);
   carry<21>(s11, s12);
   carry<21>(s13, s14);
   carry<21>(s15, s16);
   carry<21>(s17, s18);
   carry<21>(s19, s20);
   carry<21>(s21, s22);

   redc_mul(s11, s12, s13, s14, s15, s16, s23);
   redc_mul(s10, s11, s12, s13, s14, s15, s22);
   redc_mul(s9, s10, s11, s12, s13, s14, s21);
   redc_mul(s8, s9, s10, s11, s12, s13, s20);
   redc_mul(s7, s8, s9, s10, s11, s12, s19);
   redc_mul(s6, s7, s8, s9, s10, s11, s18);

   carry<21>(s6, s7);
   carry<21>(s8, s9);
   carry<21>(s10, s11);
   carry<21>(s12, s13);
   carry<21>(s14, s15);
   carry<21>(s16, s17);

   carry<21>(s7, s8);
   carry<21>(s9, s10);
   carry<21>(s11, s12);
   carry<21>(s13, s14);
   carry<21>(s15, s16);

   redc_mul(s5, s6, s7, s8, s9, s10, s17);
   redc_mul(s4, s5, s6, s7, s8, s9, s16);
   redc_mul(s3, s4, s5, s6, s7, s8, s15);
   redc_mul(s2, s3, s4, s5, s6, s7, s14);
   redc_mul(s1, s2, s3, s4, s5, s6, s13);
   redc_mul(s0, s1, s2, s3, s4, s5, s12);

   carry<21>(s0, s1);
   carry<21>(s2, s3);
   carry<21>(s4, s5);
   carry<21>(s6, s7);
   carry<21>(s8, s9);
   carry<21>(s10, s11);

   carry<21>(s1, s2);
   carry<21>(s3, s4);
   carry<21>(s5, s6);
   carry<21>(s7, s8);
   carry<21>(s9, s10);
   carry<21>(s11, s12);

   redc_mul(s0, s1, s2, s3, s4, s5, s12);

   carry0<21>(s0, s1);
   carry0<21>(s1, s2);
   carry0<21>(s2, s3);
   carry0<21>(s3, s4);
   carry0<21>(s4, s5);
   carry0<21>(s5, s6);
   carry0<21>(s6, s7);
   carry0<21>(s7, s8);
   carry0<21>(s8, s9);
   carry0<21>(s9, s10);
   carry0<21>(s10, s11);
   carry0<21>(s11, s12);

   redc_mul(s0, s1, s2, s3, s4, s5, s12);

   carry0<21>(s0, s1);
   carry0<21>(s1, s2);
   carry0<21>(s2, s3);
   carry0<21>(s3, s4);
   carry0<21>(s4, s5);
   carry0<21>(s5, s6);
   carry0<21>(s6, s7);
   carry0<21>(s7, s8);
   carry0<21>(s8, s9);
   carry0<21>(s9, s10);
   carry0<21>(s10, s11);

   s[0] = static_cast<uint8_t>(s0 >> 0);
   s[1] = static_cast<uint8_t>(s0 >> 8);
   s[2] = static_cast<uint8_t>((s0 >> 16) | (s1 << 5));
   s[3] = static_cast<uint8_t>(s1 >> 3);
   s[4] = static_cast<uint8_t>(s1 >> 11);
   s[5] = static_cast<uint8_t>((s1 >> 19) | (s2 << 2));
   s[6] = static_cast<uint8_t>(s2 >> 6);
   s[7] = static_cast<uint8_t>((s2 >> 14) | (s3 << 7));
   s[8] = static_cast<uint8_t>(s3 >> 1);
   s[9] = static_cast<uint8_t>(s3 >> 9);
   s[10] = static_cast<uint8_t>((s3 >> 17) | (s4 << 4));
   s[11] = static_cast<uint8_t>(s4 >> 4);
   s[12] = static_cast<uint8_t>(s4 >> 12);
   s[13] = static_cast<uint8_t>((s4 >> 20) | (s5 << 1));
   s[14] = static_cast<uint8_t>(s5 >> 7);
   s[15] = static_cast<uint8_t>((s5 >> 15) | (s6 << 6));
   s[16] = static_cast<uint8_t>(s6 >> 2);
   s[17] = static_cast<uint8_t>(s6 >> 10);
   s[18] = static_cast<uint8_t>((s6 >> 18) | (s7 << 3));
   s[19] = static_cast<uint8_t>(s7 >> 5);
   s[20] = static_cast<uint8_t>(s7 >> 13);
   s[21] = static_cast<uint8_t>(s8 >> 0);
   s[22] = static_cast<uint8_t>(s8 >> 8);
   s[23] = static_cast<uint8_t>((s8 >> 16) | (s9 << 5));
   s[24] = static_cast<uint8_t>(s9 >> 3);
   s[25] = static_cast<uint8_t>(s9 >> 11);
   s[26] = static_cast<uint8_t>((s9 >> 19) | (s10 << 2));
   s[27] = static_cast<uint8_t>(s10 >> 6);
   s[28] = static_cast<uint8_t>((s10 >> 14) | (s11 << 7));
   s[29] = static_cast<uint8_t>(s11 >> 1);
   s[30] = static_cast<uint8_t>(s11 >> 9);
   s[31] = static_cast<uint8_t>(s11 >> 17);
}

}  // namespace Botan
