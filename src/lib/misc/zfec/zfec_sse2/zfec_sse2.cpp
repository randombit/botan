/*
* (C) 2009,2010,2021 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/zfec.h>
#include <immintrin.h>

namespace Botan {

BOTAN_FUNC_ISA("sse2")
size_t ZFEC::addmul_sse2(uint8_t z[], const uint8_t x[], uint8_t y, size_t size)
   {
   // we assume the caller has aligned z to 16 for us!

   const __m128i polynomial = _mm_set1_epi8(0x1D);
   const __m128i zero = _mm_setzero_si128();

   const size_t orig_size = size;

   // unrolled out to cache line size
   while(size >= 64)
      {
      __m128i x_1 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(x));
      __m128i x_2 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(x + 16));
      __m128i x_3 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(x + 32));
      __m128i x_4 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(x + 48));

      __m128i z_1 = _mm_load_si128(reinterpret_cast<const __m128i*>(z));
      __m128i z_2 = _mm_load_si128(reinterpret_cast<const __m128i*>(z + 16));
      __m128i z_3 = _mm_load_si128(reinterpret_cast<const __m128i*>(z + 32));
      __m128i z_4 = _mm_load_si128(reinterpret_cast<const __m128i*>(z + 48));

      if(y & 0x01)
         {
         z_1 = _mm_xor_si128(z_1, x_1);
         z_2 = _mm_xor_si128(z_2, x_2);
         z_3 = _mm_xor_si128(z_3, x_3);
         z_4 = _mm_xor_si128(z_4, x_4);
         }

      for(size_t j = 1; j != 8; ++j)
         {
         /*
         * Each byte of each mask is either 0 or the polynomial 0x1D,
         * depending on if the high bit of x_i is set or not.
         */

         // flip operation?
         __m128i mask_1 = _mm_cmpgt_epi8(zero, x_1);
         __m128i mask_2 = _mm_cmpgt_epi8(zero, x_2);
         __m128i mask_3 = _mm_cmpgt_epi8(zero, x_3);
         __m128i mask_4 = _mm_cmpgt_epi8(zero, x_4);

         // x <<= 1
         x_1 = _mm_add_epi8(x_1, x_1);
         x_2 = _mm_add_epi8(x_2, x_2);
         x_3 = _mm_add_epi8(x_3, x_3);
         x_4 = _mm_add_epi8(x_4, x_4);

         mask_1 = _mm_and_si128(mask_1, polynomial);
         mask_2 = _mm_and_si128(mask_2, polynomial);
         mask_3 = _mm_and_si128(mask_3, polynomial);
         mask_4 = _mm_and_si128(mask_4, polynomial);

         x_1 = _mm_xor_si128(x_1, mask_1);
         x_2 = _mm_xor_si128(x_2, mask_2);
         x_3 = _mm_xor_si128(x_3, mask_3);
         x_4 = _mm_xor_si128(x_4, mask_4);

         if((y >> j) & 1)
            {
            z_1 = _mm_xor_si128(z_1, x_1);
            z_2 = _mm_xor_si128(z_2, x_2);
            z_3 = _mm_xor_si128(z_3, x_3);
            z_4 = _mm_xor_si128(z_4, x_4);
            }
         }

      _mm_store_si128(reinterpret_cast<__m128i*>(z     ), z_1);
      _mm_store_si128(reinterpret_cast<__m128i*>(z + 16), z_2);
      _mm_store_si128(reinterpret_cast<__m128i*>(z + 32), z_3);
      _mm_store_si128(reinterpret_cast<__m128i*>(z + 48), z_4);

      x += 64;
      z += 64;
      size -= 64;
      }

   return orig_size - size;
   }

}
