/*
* (C) 2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/zfec.h>

#include <botan/internal/bit_ops.h>
#include <botan/internal/isa_extn.h>
#include <array>
#include <immintrin.h>

namespace Botan {

namespace {

/*
* Multiplication by a fixed y in GF(2^8) is linear over GF(2), so it can be
* expressed as an 8x8 bit matrix, which vgf2p8affineqb applies to each of
* the 64 bytes of a vector. Column b of the matrix is y*x^b reduced by the
* field polynomial; qword byte r holds the row producing output bit (7 - r).
*/
consteval std::array<uint64_t, 256> zfec_gfni_mul_matrix() {
   std::array<uint64_t, 256> tbl = {};

   for(size_t y = 0; y != 256; ++y) {
      uint64_t q = 0;
      for(size_t r = 0; r != 8; ++r) {
         const size_t out_bit = 7 - r;
         uint8_t byte_r = 0;
         for(size_t b = 0; b != 8; ++b) {
            const uint8_t prod = poly_mul<0x1D>(static_cast<uint8_t>(1U << b), static_cast<uint8_t>(y));
            if(((prod >> out_bit) & 1) != 0) {
               byte_r |= static_cast<uint8_t>(1U << b);
            }
         }
         q |= static_cast<uint64_t>(byte_r) << (8 * r);
      }
      tbl[y] = q;
   }

   return tbl;
}

alignas(256) constexpr auto ZFEC_GFNI_MUL_MATRIX = zfec_gfni_mul_matrix();

}  // namespace

/*
* Computes z[] = x[0][] * y[0] + x[1][] * y[1] + ... + x[k-1][] * y[k-1]
*/
BOTAN_FN_ISA_AVX512_GFNI void ZFEC::linear_combination_gfni(
   uint8_t z[], const uint8_t* const x[], const uint8_t y[], size_t k, size_t size) {
   size_t off = 0;

   while(off + 128 <= size) {
      __m512i acc0 = _mm512_setzero_si512();
      __m512i acc1 = _mm512_setzero_si512();

      for(size_t j = 0; j != k; ++j) {
         const __m512i mat = _mm512_set1_epi64(static_cast<int64_t>(ZFEC_GFNI_MUL_MATRIX[y[j]]));
         const __m512i x0 = _mm512_loadu_si512(x[j] + off);
         const __m512i x1 = _mm512_loadu_si512(x[j] + off + 64);
         acc0 = _mm512_xor_si512(acc0, _mm512_gf2p8affine_epi64_epi8(x0, mat, 0));
         acc1 = _mm512_xor_si512(acc1, _mm512_gf2p8affine_epi64_epi8(x1, mat, 0));
      }

      _mm512_storeu_si512(z + off, acc0);
      _mm512_storeu_si512(z + off + 64, acc1);

      off += 128;
   }

   while(off + 64 <= size) {
      __m512i acc = _mm512_setzero_si512();

      for(size_t j = 0; j != k; ++j) {
         const __m512i mat = _mm512_set1_epi64(static_cast<int64_t>(ZFEC_GFNI_MUL_MATRIX[y[j]]));
         acc = _mm512_xor_si512(acc, _mm512_gf2p8affine_epi64_epi8(_mm512_loadu_si512(x[j] + off), mat, 0));
      }

      _mm512_storeu_si512(z + off, acc);

      off += 64;
   }

   if(off < size) {
      const __mmask64 mask = (uint64_t(1) << (size - off)) - 1;

      __m512i acc = _mm512_setzero_si512();

      for(size_t j = 0; j != k; ++j) {
         const __m512i mat = _mm512_set1_epi64(static_cast<int64_t>(ZFEC_GFNI_MUL_MATRIX[y[j]]));
         const __m512i xv = _mm512_maskz_loadu_epi8(mask, x[j] + off);
         acc = _mm512_xor_si512(acc, _mm512_gf2p8affine_epi64_epi8(xv, mat, 0));
      }

      _mm512_mask_storeu_epi8(z + off, mask, acc);
   }
}

}  // namespace Botan
