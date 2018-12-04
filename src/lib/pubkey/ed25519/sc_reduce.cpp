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
  s[0]+256*s[1]+...+256^63*s[63] = s

Output:
  s[0]+256*s[1]+...+256^31*s[31] = s mod l
  where l = 2^252 + 27742317777372353535851937790883648493.
  Overwrites s in place.
*/

void sc_reduce(uint8_t* s)
   {
   const uint32_t MASK = 0x1fffff;

   int64_t s0 = MASK & load_3(s);
   int64_t s1 = MASK & (load_4(s + 2) >> 5);
   int64_t s2 = MASK & (load_3(s + 5) >> 2);
   int64_t s3 = MASK & (load_4(s + 7) >> 7);
   int64_t s4 = MASK & (load_4(s + 10) >> 4);
   int64_t s5 = MASK & (load_3(s + 13) >> 1);
   int64_t s6 = MASK & (load_4(s + 15) >> 6);
   int64_t s7 = MASK & (load_3(s + 18) >> 3);
   int64_t s8 = MASK & load_3(s + 21);
   int64_t s9 = MASK & (load_4(s + 23) >> 5);
   int64_t s10 = MASK & (load_3(s + 26) >> 2);
   int64_t s11 = MASK & (load_4(s + 28) >> 7);
   int64_t s12 = MASK & (load_4(s + 31) >> 4);
   int64_t s13 = MASK & (load_3(s + 34) >> 1);
   int64_t s14 = MASK & (load_4(s + 36) >> 6);
   int64_t s15 = MASK & (load_3(s + 39) >> 3);
   int64_t s16 = MASK & load_3(s + 42);
   int64_t s17 = MASK & (load_4(s + 44) >> 5);
   int64_t s18 = MASK & (load_3(s + 47) >> 2);
   int64_t s19 = MASK & (load_4(s + 49) >> 7);
   int64_t s20 = MASK & (load_4(s + 52) >> 4);
   int64_t s21 = MASK & (load_3(s + 55) >> 1);
   int64_t s22 = MASK & (load_4(s + 57) >> 6);
   int64_t s23 = (load_4(s + 60) >> 3);

   redc_mul(s11, s12, s13, s14, s15, s16, s23);
   redc_mul(s10, s11, s12, s13, s14, s15, s22);
   redc_mul( s9, s10, s11, s12, s13, s14, s21);
   redc_mul( s8,  s9, s10, s11, s12, s13, s20);
   redc_mul( s7,  s8,  s9, s10, s11, s12, s19);
   redc_mul( s6,  s7,  s8,  s9, s10, s11, s18);

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
   carry0<21>(s11, s12);

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

}
