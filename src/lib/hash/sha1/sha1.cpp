/*
* SHA-1
* (C) 1999-2008,2011 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/sha1.h>

#include <botan/internal/bit_ops.h>
#include <botan/internal/loadstor.h>
#include <botan/internal/rotate.h>
#include <botan/internal/sha1_f.h>
#include <array>

#if defined(BOTAN_HAS_CPUID)
   #include <botan/internal/cpuid.h>
#endif

namespace Botan {

/*
* SHA-1 Compression Function
*/
void SHA_1::compress_n(digest_type& digest, std::span<const uint8_t> input, size_t blocks) {
   using namespace SHA1_F;

#if defined(BOTAN_HAS_SHA1_X86_SHA_NI)
   if(CPUID::has(CPUID::Feature::SHA)) {
      return sha1_compress_x86(digest, input, blocks);
   }
#endif

#if defined(BOTAN_HAS_SHA1_ARMV8)
   if(CPUID::has(CPUID::Feature::SHA1)) {
      return sha1_armv8_compress_n(digest, input, blocks);
   }
#endif

#if defined(BOTAN_HAS_SHA1_AVX2)
   if(CPUID::has(CPUID::Feature::AVX2, CPUID::Feature::BMI)) {
      return avx2_compress_n(digest, input, blocks);
   }
#endif

#if defined(BOTAN_HAS_SHA1_SIMD_4X32)
   if(CPUID::has(CPUID::Feature::SIMD_4X32)) {
      return simd_compress_n(digest, input, blocks);
   }
#endif

   uint32_t A = digest[0], B = digest[1], C = digest[2], D = digest[3], E = digest[4];
   std::array<uint32_t, 80> W{};
   auto W_in = std::span{W}.first<block_bytes / sizeof(uint32_t)>();

   BufferSlicer in(input);

   for(size_t i = 0; i != blocks; ++i) {
      load_be(W_in, in.take<block_bytes>());

      // clang-format off

      for(size_t j = 16; j != 80; j += 8) {
         W[j + 0] = rotl<1>(W[j - 3] ^ W[j - 8] ^ W[j - 14] ^ W[j - 16]);
         W[j + 1] = rotl<1>(W[j - 2] ^ W[j - 7] ^ W[j - 13] ^ W[j - 15]);
         W[j + 2] = rotl<1>(W[j - 1] ^ W[j - 6] ^ W[j - 12] ^ W[j - 14]);
         W[j + 3] = rotl<1>(W[j    ] ^ W[j - 5] ^ W[j - 11] ^ W[j - 13]);
         W[j + 4] = rotl<1>(W[j + 1] ^ W[j - 4] ^ W[j - 10] ^ W[j - 12]);
         W[j + 5] = rotl<1>(W[j + 2] ^ W[j - 3] ^ W[j -  9] ^ W[j - 11]);
         W[j + 6] = rotl<1>(W[j + 3] ^ W[j - 2] ^ W[j -  8] ^ W[j - 10]);
         W[j + 7] = rotl<1>(W[j + 4] ^ W[j - 1] ^ W[j -  7] ^ W[j -  9]);
      }

      // clang-format on

      F1(A, B, C, D, E, W[0] + K1);
      F1(E, A, B, C, D, W[1] + K1);
      F1(D, E, A, B, C, W[2] + K1);
      F1(C, D, E, A, B, W[3] + K1);
      F1(B, C, D, E, A, W[4] + K1);
      F1(A, B, C, D, E, W[5] + K1);
      F1(E, A, B, C, D, W[6] + K1);
      F1(D, E, A, B, C, W[7] + K1);
      F1(C, D, E, A, B, W[8] + K1);
      F1(B, C, D, E, A, W[9] + K1);
      F1(A, B, C, D, E, W[10] + K1);
      F1(E, A, B, C, D, W[11] + K1);
      F1(D, E, A, B, C, W[12] + K1);
      F1(C, D, E, A, B, W[13] + K1);
      F1(B, C, D, E, A, W[14] + K1);
      F1(A, B, C, D, E, W[15] + K1);
      F1(E, A, B, C, D, W[16] + K1);
      F1(D, E, A, B, C, W[17] + K1);
      F1(C, D, E, A, B, W[18] + K1);
      F1(B, C, D, E, A, W[19] + K1);

      F2(A, B, C, D, E, W[20] + K2);
      F2(E, A, B, C, D, W[21] + K2);
      F2(D, E, A, B, C, W[22] + K2);
      F2(C, D, E, A, B, W[23] + K2);
      F2(B, C, D, E, A, W[24] + K2);
      F2(A, B, C, D, E, W[25] + K2);
      F2(E, A, B, C, D, W[26] + K2);
      F2(D, E, A, B, C, W[27] + K2);
      F2(C, D, E, A, B, W[28] + K2);
      F2(B, C, D, E, A, W[29] + K2);
      F2(A, B, C, D, E, W[30] + K2);
      F2(E, A, B, C, D, W[31] + K2);
      F2(D, E, A, B, C, W[32] + K2);
      F2(C, D, E, A, B, W[33] + K2);
      F2(B, C, D, E, A, W[34] + K2);
      F2(A, B, C, D, E, W[35] + K2);
      F2(E, A, B, C, D, W[36] + K2);
      F2(D, E, A, B, C, W[37] + K2);
      F2(C, D, E, A, B, W[38] + K2);
      F2(B, C, D, E, A, W[39] + K2);

      F3(A, B, C, D, E, W[40] + K3);
      F3(E, A, B, C, D, W[41] + K3);
      F3(D, E, A, B, C, W[42] + K3);
      F3(C, D, E, A, B, W[43] + K3);
      F3(B, C, D, E, A, W[44] + K3);
      F3(A, B, C, D, E, W[45] + K3);
      F3(E, A, B, C, D, W[46] + K3);
      F3(D, E, A, B, C, W[47] + K3);
      F3(C, D, E, A, B, W[48] + K3);
      F3(B, C, D, E, A, W[49] + K3);
      F3(A, B, C, D, E, W[50] + K3);
      F3(E, A, B, C, D, W[51] + K3);
      F3(D, E, A, B, C, W[52] + K3);
      F3(C, D, E, A, B, W[53] + K3);
      F3(B, C, D, E, A, W[54] + K3);
      F3(A, B, C, D, E, W[55] + K3);
      F3(E, A, B, C, D, W[56] + K3);
      F3(D, E, A, B, C, W[57] + K3);
      F3(C, D, E, A, B, W[58] + K3);
      F3(B, C, D, E, A, W[59] + K3);

      F4(A, B, C, D, E, W[60] + K4);
      F4(E, A, B, C, D, W[61] + K4);
      F4(D, E, A, B, C, W[62] + K4);
      F4(C, D, E, A, B, W[63] + K4);
      F4(B, C, D, E, A, W[64] + K4);
      F4(A, B, C, D, E, W[65] + K4);
      F4(E, A, B, C, D, W[66] + K4);
      F4(D, E, A, B, C, W[67] + K4);
      F4(C, D, E, A, B, W[68] + K4);
      F4(B, C, D, E, A, W[69] + K4);
      F4(A, B, C, D, E, W[70] + K4);
      F4(E, A, B, C, D, W[71] + K4);
      F4(D, E, A, B, C, W[72] + K4);
      F4(C, D, E, A, B, W[73] + K4);
      F4(B, C, D, E, A, W[74] + K4);
      F4(A, B, C, D, E, W[75] + K4);
      F4(E, A, B, C, D, W[76] + K4);
      F4(D, E, A, B, C, W[77] + K4);
      F4(C, D, E, A, B, W[78] + K4);
      F4(B, C, D, E, A, W[79] + K4);

      A = (digest[0] += A);
      B = (digest[1] += B);
      C = (digest[2] += C);
      D = (digest[3] += D);
      E = (digest[4] += E);
   }
}

/*
* Clear memory of sensitive data
*/
void SHA_1::init(digest_type& digest) {
   digest.assign({0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0});
}

std::string SHA_1::provider() const {
#if defined(BOTAN_HAS_SHA1_X86_SHA_NI)
   if(auto feat = CPUID::check(CPUID::Feature::SHA)) {
      return *feat;
   }
#endif

#if defined(BOTAN_HAS_SHA1_ARMV8)
   if(auto feat = CPUID::check(CPUID::Feature::SHA1)) {
      return *feat;
   }
#endif

#if defined(BOTAN_HAS_SHA1_AVX2)
   if(auto feat = CPUID::check(CPUID::Feature::AVX2, CPUID::Feature::BMI)) {
      return *feat;
   }
#endif

#if defined(BOTAN_HAS_SHA1_SIMD_4X32)
   if(auto feat = CPUID::check(CPUID::Feature::SIMD_4X32)) {
      return *feat;
   }
#endif

   return "base";
}

std::unique_ptr<HashFunction> SHA_1::new_object() const {
   return std::make_unique<SHA_1>();
}

std::unique_ptr<HashFunction> SHA_1::copy_state() const {
   return std::make_unique<SHA_1>(*this);
}

void SHA_1::add_data(std::span<const uint8_t> input) {
   m_md.update(input);
}

void SHA_1::final_result(std::span<uint8_t> output) {
   m_md.final(output);
}

}  // namespace Botan
