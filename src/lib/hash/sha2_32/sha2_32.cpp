/*
* SHA-{224,256}
* (C) 1999-2010,2017 Jack Lloyd
*     2007 FlexSecure GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/sha2_32.h>

#include <botan/internal/buffer_slicer.h>
#include <botan/internal/loadstor.h>
#include <botan/internal/sha2_32_f.h>
#include <botan/internal/stack_scrubbing.h>

#if defined(BOTAN_HAS_CPUID)
   #include <botan/internal/cpuid.h>
#endif

namespace Botan {

namespace {

std::string sha256_provider() {
#if defined(BOTAN_HAS_SHA2_32_ARMV8)
   if(auto feat = CPUID::check(CPUID::Feature::SHA2)) {
      return *feat;
   }
#endif

#if defined(BOTAN_HAS_SHA2_32_X86)
   if(auto feat = CPUID::check(CPUID::Feature::SHA)) {
      return *feat;
   }
#endif

#if defined(BOTAN_HAS_SHA2_32_X86_AVX2)
   if(auto feat = CPUID::check(CPUID::Feature::AVX2, CPUID::Feature::BMI)) {
      return *feat;
   }
#endif

#if defined(BOTAN_HAS_SHA2_32_SIMD)
   if(auto feat = CPUID::check(CPUID::Feature::SIMD_4X32)) {
      return *feat;
   }
#endif

   return "base";
}

}  // namespace

/*
* SHA-224 / SHA-256 compression function
*/
void BOTAN_SCRUB_STACK_AFTER_RETURN SHA_256::compress_digest(digest_type& digest,
                                                             std::span<const uint8_t> input,
                                                             size_t blocks) {
#if defined(BOTAN_HAS_SHA2_32_X86)
   if(CPUID::has(CPUID::Feature::SHA)) {
      return SHA_256::compress_digest_x86(digest, input, blocks);
   }
#endif

#if defined(BOTAN_HAS_SHA2_32_ARMV8)
   if(CPUID::has(CPUID::Feature::SHA2)) {
      return SHA_256::compress_digest_armv8(digest, input, blocks);
   }
#endif

#if defined(BOTAN_HAS_SHA2_32_X86_AVX2)
   if(CPUID::has(CPUID::Feature::AVX2, CPUID::Feature::BMI)) {
      return SHA_256::compress_digest_x86_avx2(digest, input, blocks);
   }
#endif

#if defined(BOTAN_HAS_SHA2_32_SIMD)
   if(CPUID::has(CPUID::Feature::SIMD_4X32)) {
      return SHA_256::compress_digest_x86_simd(digest, input, blocks);
   }
#endif

   uint32_t A = digest[0];
   uint32_t B = digest[1];
   uint32_t C = digest[2];
   uint32_t D = digest[3];
   uint32_t E = digest[4];
   uint32_t F = digest[5];
   uint32_t G = digest[6];
   uint32_t H = digest[7];

   std::array<uint32_t, 16> W{};

   BufferSlicer in(input);

   for(size_t i = 0; i != blocks; ++i) {
      load_be(W, in.take<block_bytes>());

      // clang-format off

      SHA2_32_F(A, B, C, D, E, F, G, H, W[ 0], W[14], W[ 9], W[ 1], SHA256_K[ 0]);
      SHA2_32_F(H, A, B, C, D, E, F, G, W[ 1], W[15], W[10], W[ 2], SHA256_K[ 1]);
      SHA2_32_F(G, H, A, B, C, D, E, F, W[ 2], W[ 0], W[11], W[ 3], SHA256_K[ 2]);
      SHA2_32_F(F, G, H, A, B, C, D, E, W[ 3], W[ 1], W[12], W[ 4], SHA256_K[ 3]);
      SHA2_32_F(E, F, G, H, A, B, C, D, W[ 4], W[ 2], W[13], W[ 5], SHA256_K[ 4]);
      SHA2_32_F(D, E, F, G, H, A, B, C, W[ 5], W[ 3], W[14], W[ 6], SHA256_K[ 5]);
      SHA2_32_F(C, D, E, F, G, H, A, B, W[ 6], W[ 4], W[15], W[ 7], SHA256_K[ 6]);
      SHA2_32_F(B, C, D, E, F, G, H, A, W[ 7], W[ 5], W[ 0], W[ 8], SHA256_K[ 7]);
      SHA2_32_F(A, B, C, D, E, F, G, H, W[ 8], W[ 6], W[ 1], W[ 9], SHA256_K[ 8]);
      SHA2_32_F(H, A, B, C, D, E, F, G, W[ 9], W[ 7], W[ 2], W[10], SHA256_K[ 9]);
      SHA2_32_F(G, H, A, B, C, D, E, F, W[10], W[ 8], W[ 3], W[11], SHA256_K[10]);
      SHA2_32_F(F, G, H, A, B, C, D, E, W[11], W[ 9], W[ 4], W[12], SHA256_K[11]);
      SHA2_32_F(E, F, G, H, A, B, C, D, W[12], W[10], W[ 5], W[13], SHA256_K[12]);
      SHA2_32_F(D, E, F, G, H, A, B, C, W[13], W[11], W[ 6], W[14], SHA256_K[13]);
      SHA2_32_F(C, D, E, F, G, H, A, B, W[14], W[12], W[ 7], W[15], SHA256_K[14]);
      SHA2_32_F(B, C, D, E, F, G, H, A, W[15], W[13], W[ 8], W[ 0], SHA256_K[15]);

      SHA2_32_F(A, B, C, D, E, F, G, H, W[ 0], W[14], W[ 9], W[ 1], SHA256_K[16]);
      SHA2_32_F(H, A, B, C, D, E, F, G, W[ 1], W[15], W[10], W[ 2], SHA256_K[17]);
      SHA2_32_F(G, H, A, B, C, D, E, F, W[ 2], W[ 0], W[11], W[ 3], SHA256_K[18]);
      SHA2_32_F(F, G, H, A, B, C, D, E, W[ 3], W[ 1], W[12], W[ 4], SHA256_K[19]);
      SHA2_32_F(E, F, G, H, A, B, C, D, W[ 4], W[ 2], W[13], W[ 5], SHA256_K[20]);
      SHA2_32_F(D, E, F, G, H, A, B, C, W[ 5], W[ 3], W[14], W[ 6], SHA256_K[21]);
      SHA2_32_F(C, D, E, F, G, H, A, B, W[ 6], W[ 4], W[15], W[ 7], SHA256_K[22]);
      SHA2_32_F(B, C, D, E, F, G, H, A, W[ 7], W[ 5], W[ 0], W[ 8], SHA256_K[23]);
      SHA2_32_F(A, B, C, D, E, F, G, H, W[ 8], W[ 6], W[ 1], W[ 9], SHA256_K[24]);
      SHA2_32_F(H, A, B, C, D, E, F, G, W[ 9], W[ 7], W[ 2], W[10], SHA256_K[25]);
      SHA2_32_F(G, H, A, B, C, D, E, F, W[10], W[ 8], W[ 3], W[11], SHA256_K[26]);
      SHA2_32_F(F, G, H, A, B, C, D, E, W[11], W[ 9], W[ 4], W[12], SHA256_K[27]);
      SHA2_32_F(E, F, G, H, A, B, C, D, W[12], W[10], W[ 5], W[13], SHA256_K[28]);
      SHA2_32_F(D, E, F, G, H, A, B, C, W[13], W[11], W[ 6], W[14], SHA256_K[29]);
      SHA2_32_F(C, D, E, F, G, H, A, B, W[14], W[12], W[ 7], W[15], SHA256_K[30]);
      SHA2_32_F(B, C, D, E, F, G, H, A, W[15], W[13], W[ 8], W[ 0], SHA256_K[31]);

      SHA2_32_F(A, B, C, D, E, F, G, H, W[ 0], W[14], W[ 9], W[ 1], SHA256_K[32]);
      SHA2_32_F(H, A, B, C, D, E, F, G, W[ 1], W[15], W[10], W[ 2], SHA256_K[33]);
      SHA2_32_F(G, H, A, B, C, D, E, F, W[ 2], W[ 0], W[11], W[ 3], SHA256_K[34]);
      SHA2_32_F(F, G, H, A, B, C, D, E, W[ 3], W[ 1], W[12], W[ 4], SHA256_K[35]);
      SHA2_32_F(E, F, G, H, A, B, C, D, W[ 4], W[ 2], W[13], W[ 5], SHA256_K[36]);
      SHA2_32_F(D, E, F, G, H, A, B, C, W[ 5], W[ 3], W[14], W[ 6], SHA256_K[37]);
      SHA2_32_F(C, D, E, F, G, H, A, B, W[ 6], W[ 4], W[15], W[ 7], SHA256_K[38]);
      SHA2_32_F(B, C, D, E, F, G, H, A, W[ 7], W[ 5], W[ 0], W[ 8], SHA256_K[39]);
      SHA2_32_F(A, B, C, D, E, F, G, H, W[ 8], W[ 6], W[ 1], W[ 9], SHA256_K[40]);
      SHA2_32_F(H, A, B, C, D, E, F, G, W[ 9], W[ 7], W[ 2], W[10], SHA256_K[41]);
      SHA2_32_F(G, H, A, B, C, D, E, F, W[10], W[ 8], W[ 3], W[11], SHA256_K[42]);
      SHA2_32_F(F, G, H, A, B, C, D, E, W[11], W[ 9], W[ 4], W[12], SHA256_K[43]);
      SHA2_32_F(E, F, G, H, A, B, C, D, W[12], W[10], W[ 5], W[13], SHA256_K[44]);
      SHA2_32_F(D, E, F, G, H, A, B, C, W[13], W[11], W[ 6], W[14], SHA256_K[45]);
      SHA2_32_F(C, D, E, F, G, H, A, B, W[14], W[12], W[ 7], W[15], SHA256_K[46]);
      SHA2_32_F(B, C, D, E, F, G, H, A, W[15], W[13], W[ 8], W[ 0], SHA256_K[47]);

      SHA2_32_F(A, B, C, D, E, F, G, H, W[ 0], W[14], W[ 9], W[ 1], SHA256_K[48]);
      SHA2_32_F(H, A, B, C, D, E, F, G, W[ 1], W[15], W[10], W[ 2], SHA256_K[49]);
      SHA2_32_F(G, H, A, B, C, D, E, F, W[ 2], W[ 0], W[11], W[ 3], SHA256_K[50]);
      SHA2_32_F(F, G, H, A, B, C, D, E, W[ 3], W[ 1], W[12], W[ 4], SHA256_K[51]);
      SHA2_32_F(E, F, G, H, A, B, C, D, W[ 4], W[ 2], W[13], W[ 5], SHA256_K[52]);
      SHA2_32_F(D, E, F, G, H, A, B, C, W[ 5], W[ 3], W[14], W[ 6], SHA256_K[53]);
      SHA2_32_F(C, D, E, F, G, H, A, B, W[ 6], W[ 4], W[15], W[ 7], SHA256_K[54]);
      SHA2_32_F(B, C, D, E, F, G, H, A, W[ 7], W[ 5], W[ 0], W[ 8], SHA256_K[55]);
      SHA2_32_F(A, B, C, D, E, F, G, H, W[ 8], W[ 6], W[ 1], W[ 9], SHA256_K[56]);
      SHA2_32_F(H, A, B, C, D, E, F, G, W[ 9], W[ 7], W[ 2], W[10], SHA256_K[57]);
      SHA2_32_F(G, H, A, B, C, D, E, F, W[10], W[ 8], W[ 3], W[11], SHA256_K[58]);
      SHA2_32_F(F, G, H, A, B, C, D, E, W[11], W[ 9], W[ 4], W[12], SHA256_K[59]);
      SHA2_32_F(E, F, G, H, A, B, C, D, W[12], W[10], W[ 5], W[13], SHA256_K[60]);
      SHA2_32_F(D, E, F, G, H, A, B, C, W[13], W[11], W[ 6], W[14], SHA256_K[61]);
      SHA2_32_F(C, D, E, F, G, H, A, B, W[14], W[12], W[ 7], W[15], SHA256_K[62]);
      SHA2_32_F(B, C, D, E, F, G, H, A, W[15], W[13], W[ 8], W[ 0], SHA256_K[63]);

      // clang-format on

      A = (digest[0] += A);
      B = (digest[1] += B);
      C = (digest[2] += C);
      D = (digest[3] += D);
      E = (digest[4] += E);
      F = (digest[5] += F);
      G = (digest[6] += G);
      H = (digest[7] += H);
   }
}

std::string SHA_224::provider() const {
   return sha256_provider();
}

void SHA_224::compress_n(digest_type& digest, std::span<const uint8_t> input, size_t blocks) {
   SHA_256::compress_digest(digest, input, blocks);
}

void SHA_224::init(digest_type& digest) {
   digest.assign({0xC1059ED8, 0x367CD507, 0x3070DD17, 0xF70E5939, 0xFFC00B31, 0x68581511, 0x64F98FA7, 0xBEFA4FA4});
}

std::unique_ptr<HashFunction> SHA_224::new_object() const {
   return std::make_unique<SHA_224>();
}

std::unique_ptr<HashFunction> SHA_224::copy_state() const {
   return std::make_unique<SHA_224>(*this);
}

void SHA_224::add_data(std::span<const uint8_t> input) {
   m_md.update(input);
}

void SHA_224::final_result(std::span<uint8_t> output) {
   m_md.final(output);
}

std::string SHA_256::provider() const {
   return sha256_provider();
}

void SHA_256::compress_n(digest_type& digest, std::span<const uint8_t> input, size_t blocks) {
   SHA_256::compress_digest(digest, input, blocks);
}

void SHA_256::init(digest_type& digest) {
   digest.assign({0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19});
}

std::unique_ptr<HashFunction> SHA_256::new_object() const {
   return std::make_unique<SHA_256>();
}

std::unique_ptr<HashFunction> SHA_256::copy_state() const {
   return std::make_unique<SHA_256>(*this);
}

void SHA_256::add_data(std::span<const uint8_t> input) {
   m_md.update(input);
}

void SHA_256::final_result(std::span<uint8_t> output) {
   m_md.final(output);
}

}  // namespace Botan
