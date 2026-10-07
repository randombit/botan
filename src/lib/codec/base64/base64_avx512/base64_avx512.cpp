/*
* (C) 2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/base64_avx512.h>

#include <botan/internal/isa_extn.h>
#include <algorithm>
#include <array>
#include <immintrin.h>

namespace Botan {

/*
* The encoding and decoding kernels follow the AVX-512VBMI algorithms of
* W. Mula and D. Lemire, "Base64 encoding and decoding at almost the
* speed of a memory copy" (https://arxiv.org/abs/1910.05109)
*/

BOTAN_FN_ISA_AVX512 size_t base64_encode_avx512(char out[], const uint8_t in[], size_t length) {
   // Expands each 3 byte input group g to the 4 bytes [b1,b0,b2,b1], placing
   // the group in a 32-bit word where vpmultishiftqb can reach each 6-bit field
   alignas(64) constexpr auto B64_ENC_SHUFFLE = []() {
      std::array<uint8_t, 64> idx = {};
      for(size_t g = 0; g != 16; ++g) {
         idx[4 * g + 0] = static_cast<uint8_t>(3 * g + 1);
         idx[4 * g + 1] = static_cast<uint8_t>(3 * g + 0);
         idx[4 * g + 2] = static_cast<uint8_t>(3 * g + 2);
         idx[4 * g + 3] = static_cast<uint8_t>(3 * g + 1);
      }
      return idx;
   }();

   alignas(64) constexpr char B64_ENC_TABLE[65] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
   constexpr __mmask64 LOW_48 = 0x0000FFFFFFFFFFFF;

   const __m512i shuffle = _mm512_load_si512(B64_ENC_SHUFFLE.data());
   const __m512i lookup = _mm512_load_si512(B64_ENC_TABLE);
   // Byte i of each output qword takes 8 bits starting at bit multishift[i]
   const __m512i multishift = _mm512_set1_epi64(0x3036242A1016040A);

   size_t consumed = 0;

   while(length - consumed >= 48) {
      const __m512i x = _mm512_maskz_loadu_epi8(LOW_48, in + consumed);

      const __m512i expanded = _mm512_permutexvar_epi8(shuffle, x);
      // The two high junk bits of each extracted byte are ignored by vpermb
      const __m512i indices = _mm512_multishift_epi64_epi8(multishift, expanded);
      const __m512i chars = _mm512_permutexvar_epi8(indices, lookup);

      _mm512_storeu_si512(out, chars);

      out += 64;
      consumed += 48;
   }

   return consumed;
}

BOTAN_FN_ISA_AVX512_POPCNT size_t base64_strip_ws_avx512(uint8_t out[], const uint8_t in[], size_t length) {
   size_t written = 0;
   size_t pos = 0;

   while(pos < length) {
      const size_t todo = std::min<size_t>(64, length - pos);
      const __mmask64 valid = (todo == 64) ? ~__mmask64(0) : ((__mmask64(1) << todo) - 1);

      const __m512i x = _mm512_maskz_loadu_epi8(valid, in + pos);

      const __mmask64 ws =
         _mm512_cmpeq_epi8_mask(x, _mm512_set1_epi8(' ')) | _mm512_cmpeq_epi8_mask(x, _mm512_set1_epi8('\n')) |
         _mm512_cmpeq_epi8_mask(x, _mm512_set1_epi8('\t')) | _mm512_cmpeq_epi8_mask(x, _mm512_set1_epi8('\r'));

      const __mmask64 keep = valid & ~ws;
      _mm512_mask_compressstoreu_epi8(out + written, keep, x);
      written += static_cast<size_t>(_mm_popcnt_u64(keep));
      pos += todo;
   }

   return written;
}

BOTAN_FN_ISA_AVX512_POPCNT size_t base64_decode_avx512(uint8_t out[], const uint8_t in[], size_t length) {
   // Maps the low 7 bits of an ASCII character to its base64 value; any
   // character that is not one of the 64 data characters maps to 0x80
   alignas(64) constexpr auto B64_DEC_TABLE = []() {
      std::array<uint8_t, 128> tbl = {};
      for(auto& b : tbl) {
         b = 0x80;
      }
      for(size_t i = 0; i != 26; ++i) {
         tbl['A' + i] = static_cast<uint8_t>(i);
         tbl['a' + i] = static_cast<uint8_t>(26 + i);
      }
      for(size_t i = 0; i != 10; ++i) {
         tbl['0' + i] = static_cast<uint8_t>(52 + i);
      }
      tbl['+'] = 62;
      tbl['/'] = 63;
      return tbl;
   }();

   // After the multiply-adds, dword g holds the three decoded bytes of group
   // g as its bytes [2,1,0]; gather them into 48 contiguous output bytes
   alignas(64) constexpr auto B64_DEC_PACK = []() {
      std::array<uint8_t, 64> idx = {};
      for(size_t g = 0; g != 16; ++g) {
         idx[3 * g + 0] = static_cast<uint8_t>(4 * g + 2);
         idx[3 * g + 1] = static_cast<uint8_t>(4 * g + 1);
         idx[3 * g + 2] = static_cast<uint8_t>(4 * g + 0);
      }
      return idx;
   }();

   constexpr __mmask64 LOW_48 = 0x0000FFFFFFFFFFFF;

   const __m512i lut_lo = _mm512_load_si512(B64_DEC_TABLE.data());
   const __m512i lut_hi = _mm512_load_si512(&B64_DEC_TABLE[64]);
   const __m512i pack_shuffle = _mm512_load_si512(B64_DEC_PACK.data());

   // Merge the 6 bit values a,b,c,d of each group first into the pair
   // (a*64 + b, c*64 + d) and then into a*2^18 + b*2^12 + c*2^6 + d
   const __m512i pack_mul1 = _mm512_set1_epi16(0x0140);
   const __m512i pack_mul2 = _mm512_set1_epi32(0x00011000);

   size_t consumed = 0;

   while(length - consumed > 64) {
      const __m512i x = _mm512_loadu_si512(in + consumed);

      const __m512i values = _mm512_permutex2var_epi8(lut_lo, x, lut_hi);

      // Padding, whitespace, invalid, or non-ASCII input sets a high bit
      if(_mm512_movepi8_mask(_mm512_or_si512(x, values)) != 0) {
         break;
      }

      const __m512i merged16 = _mm512_maddubs_epi16(values, pack_mul1);
      const __m512i merged32 = _mm512_madd_epi16(merged16, pack_mul2);
      const __m512i packed = _mm512_permutexvar_epi8(pack_shuffle, merged32);

      _mm512_mask_storeu_epi8(out, LOW_48, packed);

      out += 48;
      consumed += 64;
   }

   return consumed;
}

}  // namespace Botan
