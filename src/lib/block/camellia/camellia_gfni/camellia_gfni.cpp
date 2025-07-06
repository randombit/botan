/*
* (C) 2025 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/camellia_gfni.h>

#include <botan/internal/loadstor.h>
#include <botan/internal/rotate.h>
#include <botan/internal/simd_avx2_gfni.h>

namespace Botan {

namespace {

namespace Camellia_GFNI {

inline BOTAN_FN_ISA_AVX2_GFNI __m256i camellia_s1234(__m256i x) {
   constexpr uint64_t pre123_a = gfni_matrix(R"(
      1 1 1 0 1 1 0 1
      0 0 1 1 0 0 1 0
      1 1 0 1 0 0 0 0
      1 0 1 1 0 0 1 1
      0 0 0 0 1 1 0 0
      1 0 1 0 0 1 0 0
      0 0 1 0 1 1 0 0
      1 0 0 0 0 1 1 0)");

   constexpr uint64_t pre4_a = gfni_matrix(R"(
      1 1 0 1 1 0 1 1
      0 1 1 0 0 1 0 0
      1 0 1 0 0 0 0 1
      0 1 1 0 0 1 1 1
      0 0 0 1 1 0 0 0
      0 1 0 0 1 0 0 1
      0 1 0 1 1 0 0 0
      0 0 0 0 1 1 0 1)");

   constexpr uint8_t pre_c = 0b01000101;
   const auto pre = _mm256_set_epi64x(pre4_a, pre123_a, pre123_a, pre123_a);

   constexpr uint64_t post2_a = gfni_matrix(R"(
      0 0 0 1 1 1 0 0
      0 0 0 0 0 0 0 1
      0 1 1 0 0 1 1 0
      1 0 1 1 1 1 1 0
      0 0 0 1 1 0 1 1
      1 0 0 0 1 1 1 0
      0 1 0 1 1 1 1 0
      0 1 1 1 1 1 1 1)");

   constexpr uint64_t post3_a = gfni_matrix(R"(
      0 1 1 0 0 1 1 0
      1 0 1 1 1 1 1 0
      0 0 0 1 1 0 1 1
      1 0 0 0 1 1 1 0
      0 1 0 1 1 1 1 0
      0 1 1 1 1 1 1 1
      0 0 0 1 1 1 0 0
      0 0 0 0 0 0 0 1)");

   constexpr uint64_t post14_a = gfni_matrix(R"(
      0 0 0 0 0 0 0 1
      0 1 1 0 0 1 1 0
      1 0 1 1 1 1 1 0
      0 0 0 1 1 0 1 1
      1 0 0 0 1 1 1 0
      0 1 0 1 1 1 1 0
      0 1 1 1 1 1 1 1
      0 0 0 1 1 1 0 0)");

   const auto post_a = _mm256_set_epi64x(post14_a, post3_a, post2_a, post14_a);

   const auto post_c =
      _mm256_set_epi64x(0x6E6E6E6E6E6E6E6E, 0x3737373737373737, 0xDCDCDCDCDCDCDCDC, 0x6E6E6E6E6E6E6E6E);

   auto y = _mm256_gf2p8affine_epi64_epi8(x, pre, pre_c);
   return _mm256_xor_si256(post_c, _mm256_gf2p8affineinv_epi64_epi8(y, post_a, 0));
}

inline BOTAN_FN_ISA_AVX2_GFNI uint64_t F(uint64_t x) {
   // All 4 Camellia Sboxes in parallel
   auto s_vec = camellia_s1234(_mm256_set1_epi64x(x));

   // The linear transformation just sprays bytes about which can be done with two byte shuffles
   auto Z0 = _mm256_shuffle_epi8(
      s_vec, _mm256_set_epi64x(0x0C0CFF0CFFFF0C0C, 0x05FF0505FF0505FF, 0xFF0E0E0E0E0EFFFF, 0x070707FF07FFFF07));

   auto Z1 = _mm256_shuffle_epi8(
      s_vec, _mm256_set_epi64x(0x0909FF090909FF09, 0x02FF020202FF0202, 0xFF0B0B0BFF0B0B0B, 0x000000FF000000FF));

   Z0 = _mm256_xor_si256(Z0, Z1);

   uint64_t Z[4];
   _mm256_store_si256(reinterpret_cast<__m256i*>(Z), Z0);

   // My kingdom for a horizontal XOR (even AVX-512 doesn't have this, only OR/AND)
   return Z[0] ^ Z[1] ^ Z[2] ^ Z[3];
}

inline uint64_t FL(uint64_t v, uint64_t K) {
   uint32_t x1 = static_cast<uint32_t>(v >> 32);
   uint32_t x2 = static_cast<uint32_t>(v & 0xFFFFFFFF);

   const uint32_t k1 = static_cast<uint32_t>(K >> 32);
   const uint32_t k2 = static_cast<uint32_t>(K & 0xFFFFFFFF);

   x2 ^= rotl<1>(x1 & k1);
   x1 ^= (x2 | k2);

   return ((static_cast<uint64_t>(x1) << 32) | x2);
}

inline uint64_t FLINV(uint64_t v, uint64_t K) {
   uint32_t x1 = static_cast<uint32_t>(v >> 32);
   uint32_t x2 = static_cast<uint32_t>(v & 0xFFFFFFFF);

   const uint32_t k1 = static_cast<uint32_t>(K >> 32);
   const uint32_t k2 = static_cast<uint32_t>(K & 0xFFFFFFFF);

   x1 ^= (x2 | k2);
   x2 ^= rotl<1>(x1 & k1);

   return ((static_cast<uint64_t>(x1) << 32) | x2);
}

}  // namespace Camellia_GFNI

}  // namespace

BOTAN_FN_ISA_AVX2_GFNI void camellia_gfni_encrypt9(const uint8_t in[],
                                                   uint8_t out[],
                                                   size_t blocks,
                                                   std::span<const uint64_t> SK) {
   using namespace Camellia_GFNI;

   for(size_t i = 0; i < blocks; ++i) {
      uint64_t D1 = load_be<uint64_t>(in, 2 * i + 0);
      uint64_t D2 = load_be<uint64_t>(in, 2 * i + 1);

      D1 ^= SK[0];
      D2 ^= SK[1];

      D2 ^= F(D1 ^ SK[2]);
      D1 ^= F(D2 ^ SK[3]);
      D2 ^= F(D1 ^ SK[4]);
      D1 ^= F(D2 ^ SK[5]);
      D2 ^= F(D1 ^ SK[6]);
      D1 ^= F(D2 ^ SK[7]);

      D1 = FL(D1, SK[8]);
      D2 = FLINV(D2, SK[9]);

      D2 ^= F(D1 ^ SK[10]);
      D1 ^= F(D2 ^ SK[11]);
      D2 ^= F(D1 ^ SK[12]);
      D1 ^= F(D2 ^ SK[13]);
      D2 ^= F(D1 ^ SK[14]);
      D1 ^= F(D2 ^ SK[15]);

      D1 = FL(D1, SK[16]);
      D2 = FLINV(D2, SK[17]);

      D2 ^= F(D1 ^ SK[18]);
      D1 ^= F(D2 ^ SK[19]);
      D2 ^= F(D1 ^ SK[20]);
      D1 ^= F(D2 ^ SK[21]);
      D2 ^= F(D1 ^ SK[22]);
      D1 ^= F(D2 ^ SK[23]);

      D2 ^= SK[24];
      D1 ^= SK[25];

      store_be(out + 16 * i, D2, D1);
   }
}

BOTAN_FN_ISA_AVX2_GFNI void camellia_gfni_decrypt9(const uint8_t in[],
                                                   uint8_t out[],
                                                   size_t blocks,
                                                   std::span<const uint64_t> SK) {
   using namespace Camellia_GFNI;

   for(size_t i = 0; i < blocks; ++i) {
      uint64_t D1 = load_be<uint64_t>(in, 2 * i + 0);
      uint64_t D2 = load_be<uint64_t>(in, 2 * i + 1);

      D2 ^= SK[25];
      D1 ^= SK[24];

      D2 ^= F(D1 ^ SK[23]);
      D1 ^= F(D2 ^ SK[22]);

      D2 ^= F(D1 ^ SK[21]);
      D1 ^= F(D2 ^ SK[20]);

      D2 ^= F(D1 ^ SK[19]);
      D1 ^= F(D2 ^ SK[18]);

      D1 = FL(D1, SK[17]);
      D2 = FLINV(D2, SK[16]);

      D2 ^= F(D1 ^ SK[15]);
      D1 ^= F(D2 ^ SK[14]);
      D2 ^= F(D1 ^ SK[13]);
      D1 ^= F(D2 ^ SK[12]);
      D2 ^= F(D1 ^ SK[11]);
      D1 ^= F(D2 ^ SK[10]);

      D1 = FL(D1, SK[9]);
      D2 = FLINV(D2, SK[8]);

      D2 ^= F(D1 ^ SK[7]);
      D1 ^= F(D2 ^ SK[6]);
      D2 ^= F(D1 ^ SK[5]);
      D1 ^= F(D2 ^ SK[4]);
      D2 ^= F(D1 ^ SK[3]);
      D1 ^= F(D2 ^ SK[2]);

      D1 ^= SK[1];
      D2 ^= SK[0];

      store_be(out + 16 * i, D2, D1);
   }
}

BOTAN_FN_ISA_AVX2_GFNI void camellia_gfni_encrypt12(const uint8_t in[],
                                                    uint8_t out[],
                                                    size_t blocks,
                                                    std::span<const uint64_t> SK) {
   using namespace Camellia_GFNI;

   for(size_t i = 0; i < blocks; ++i) {
      uint64_t D1 = load_be<uint64_t>(in, 2 * i + 0);
      uint64_t D2 = load_be<uint64_t>(in, 2 * i + 1);

      D1 ^= SK[0];
      D2 ^= SK[1];

      D2 ^= F(D1 ^ SK[2]);
      D1 ^= F(D2 ^ SK[3]);
      D2 ^= F(D1 ^ SK[4]);
      D1 ^= F(D2 ^ SK[5]);
      D2 ^= F(D1 ^ SK[6]);
      D1 ^= F(D2 ^ SK[7]);

      D1 = FL(D1, SK[8]);
      D2 = FLINV(D2, SK[9]);

      D2 ^= F(D1 ^ SK[10]);
      D1 ^= F(D2 ^ SK[11]);
      D2 ^= F(D1 ^ SK[12]);
      D1 ^= F(D2 ^ SK[13]);
      D2 ^= F(D1 ^ SK[14]);
      D1 ^= F(D2 ^ SK[15]);

      D1 = FL(D1, SK[16]);
      D2 = FLINV(D2, SK[17]);

      D2 ^= F(D1 ^ SK[18]);
      D1 ^= F(D2 ^ SK[19]);
      D2 ^= F(D1 ^ SK[20]);
      D1 ^= F(D2 ^ SK[21]);
      D2 ^= F(D1 ^ SK[22]);
      D1 ^= F(D2 ^ SK[23]);

      D1 = FL(D1, SK[24]);
      D2 = FLINV(D2, SK[25]);

      D2 ^= F(D1 ^ SK[26]);
      D1 ^= F(D2 ^ SK[27]);
      D2 ^= F(D1 ^ SK[28]);
      D1 ^= F(D2 ^ SK[29]);
      D2 ^= F(D1 ^ SK[30]);
      D1 ^= F(D2 ^ SK[31]);

      D2 ^= SK[32];
      D1 ^= SK[33];

      store_be(out + 16 * i, D2, D1);
   }
}

BOTAN_FN_ISA_AVX2_GFNI void camellia_gfni_decrypt12(const uint8_t in[],
                                                    uint8_t out[],
                                                    size_t blocks,
                                                    std::span<const uint64_t> SK) {
   using namespace Camellia_GFNI;

   for(size_t i = 0; i < blocks; ++i) {
      uint64_t D1 = load_be<uint64_t>(in, 2 * i + 0);
      uint64_t D2 = load_be<uint64_t>(in, 2 * i + 1);

      D2 ^= SK[33];
      D1 ^= SK[32];

      D2 ^= F(D1 ^ SK[31]);
      D1 ^= F(D2 ^ SK[30]);

      D2 ^= F(D1 ^ SK[29]);
      D1 ^= F(D2 ^ SK[28]);

      D2 ^= F(D1 ^ SK[27]);
      D1 ^= F(D2 ^ SK[26]);

      D1 = FL(D1, SK[25]);
      D2 = FLINV(D2, SK[24]);
      D2 ^= F(D1 ^ SK[23]);
      D1 ^= F(D2 ^ SK[22]);
      D2 ^= F(D1 ^ SK[21]);
      D1 ^= F(D2 ^ SK[20]);
      D2 ^= F(D1 ^ SK[19]);
      D1 ^= F(D2 ^ SK[18]);

      D1 = FL(D1, SK[17]);
      D2 = FLINV(D2, SK[16]);
      D2 ^= F(D1 ^ SK[15]);
      D1 ^= F(D2 ^ SK[14]);
      D2 ^= F(D1 ^ SK[13]);
      D1 ^= F(D2 ^ SK[12]);
      D2 ^= F(D1 ^ SK[11]);
      D1 ^= F(D2 ^ SK[10]);

      D1 = FL(D1, SK[9]);
      D2 = FLINV(D2, SK[8]);
      D2 ^= F(D1 ^ SK[7]);
      D1 ^= F(D2 ^ SK[6]);
      D2 ^= F(D1 ^ SK[5]);
      D1 ^= F(D2 ^ SK[4]);
      D2 ^= F(D1 ^ SK[3]);
      D1 ^= F(D2 ^ SK[2]);

      D1 ^= SK[1];
      D2 ^= SK[0];

      store_be(out + 16 * i, D2, D1);
   }
}

}  // namespace Botan
