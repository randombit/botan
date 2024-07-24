/*
* SHA-{224,256}
* (C) 1999-2010,2017 Jack Lloyd
*     2007 FlexSecure GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/sha2_32.h>

#include <botan/internal/bit_ops.h>
#include <botan/internal/cpuid.h>
#include <botan/internal/loadstor.h>
#include <botan/internal/rotate.h>
#include <botan/internal/sha2_32_f.h>
#include <botan/internal/stl_util.h>

namespace Botan {

namespace {

std::string sha256_provider() {
#if defined(BOTAN_HAS_SHA2_32_X86)
   if(CPUID::has_intel_sha()) {
      return "shani";
   }
#endif

#if defined(BOTAN_HAS_SHA2_32_X86_BMI2)
   if(CPUID::has_bmi2()) {
      return "bmi2";
   }
#endif

#if defined(BOTAN_HAS_SHA2_32_ARMV8)
   if(CPUID::has_arm_sha2()) {
      return "armv8";
   }
#endif

   return "base";
}

}  // namespace

/*
* SHA-224 / SHA-256 compression function
*/
void SHA_256::compress_digest(digest_type& digest, std::span<const uint8_t> input, size_t blocks) {
#if defined(BOTAN_HAS_SHA2_32_X86)
   if(CPUID::has_intel_sha()) {
      return SHA_256::compress_digest_x86(digest, input, blocks);
   }
#endif

#if defined(BOTAN_HAS_SHA2_32_X86_BMI2)
   if(CPUID::has_bmi2()) {
      return SHA_256::compress_digest_x86_bmi2(digest, input, blocks);
   }
#endif

#if defined(BOTAN_HAS_SHA2_32_ARMV8)
   if(CPUID::has_arm_sha2()) {
      return SHA_256::compress_digest_armv8(digest, input, blocks);
   }
#endif

   uint32_t A = digest[0], B = digest[1], C = digest[2], D = digest[3], E = digest[4], F = digest[5], G = digest[6],
            H = digest[7];

   std::array<uint32_t, 16> W;

   BufferSlicer in(input);

   for(size_t i = 0; i != blocks; ++i) {
      load_be(W, in.take<block_bytes>());

      // clang-format off

      SHA2_32_F(A, B, C, D, E, F, G, H, W[ 0], W[14], W[ 9], W[ 1], 0x428A2F98);
      SHA2_32_F(H, A, B, C, D, E, F, G, W[ 1], W[15], W[10], W[ 2], 0x71374491);
      SHA2_32_F(G, H, A, B, C, D, E, F, W[ 2], W[ 0], W[11], W[ 3], 0xB5C0FBCF);
      SHA2_32_F(F, G, H, A, B, C, D, E, W[ 3], W[ 1], W[12], W[ 4], 0xE9B5DBA5);
      SHA2_32_F(E, F, G, H, A, B, C, D, W[ 4], W[ 2], W[13], W[ 5], 0x3956C25B);
      SHA2_32_F(D, E, F, G, H, A, B, C, W[ 5], W[ 3], W[14], W[ 6], 0x59F111F1);
      SHA2_32_F(C, D, E, F, G, H, A, B, W[ 6], W[ 4], W[15], W[ 7], 0x923F82A4);
      SHA2_32_F(B, C, D, E, F, G, H, A, W[ 7], W[ 5], W[ 0], W[ 8], 0xAB1C5ED5);
      SHA2_32_F(A, B, C, D, E, F, G, H, W[ 8], W[ 6], W[ 1], W[ 9], 0xD807AA98);
      SHA2_32_F(H, A, B, C, D, E, F, G, W[ 9], W[ 7], W[ 2], W[10], 0x12835B01);
      SHA2_32_F(G, H, A, B, C, D, E, F, W[10], W[ 8], W[ 3], W[11], 0x243185BE);
      SHA2_32_F(F, G, H, A, B, C, D, E, W[11], W[ 9], W[ 4], W[12], 0x550C7DC3);
      SHA2_32_F(E, F, G, H, A, B, C, D, W[12], W[10], W[ 5], W[13], 0x72BE5D74);
      SHA2_32_F(D, E, F, G, H, A, B, C, W[13], W[11], W[ 6], W[14], 0x80DEB1FE);
      SHA2_32_F(C, D, E, F, G, H, A, B, W[14], W[12], W[ 7], W[15], 0x9BDC06A7);
      SHA2_32_F(B, C, D, E, F, G, H, A, W[15], W[13], W[ 8], W[ 0], 0xC19BF174);

      SHA2_32_F(A, B, C, D, E, F, G, H, W[ 0], W[14], W[ 9], W[ 1], 0xE49B69C1);
      SHA2_32_F(H, A, B, C, D, E, F, G, W[ 1], W[15], W[10], W[ 2], 0xEFBE4786);
      SHA2_32_F(G, H, A, B, C, D, E, F, W[ 2], W[ 0], W[11], W[ 3], 0x0FC19DC6);
      SHA2_32_F(F, G, H, A, B, C, D, E, W[ 3], W[ 1], W[12], W[ 4], 0x240CA1CC);
      SHA2_32_F(E, F, G, H, A, B, C, D, W[ 4], W[ 2], W[13], W[ 5], 0x2DE92C6F);
      SHA2_32_F(D, E, F, G, H, A, B, C, W[ 5], W[ 3], W[14], W[ 6], 0x4A7484AA);
      SHA2_32_F(C, D, E, F, G, H, A, B, W[ 6], W[ 4], W[15], W[ 7], 0x5CB0A9DC);
      SHA2_32_F(B, C, D, E, F, G, H, A, W[ 7], W[ 5], W[ 0], W[ 8], 0x76F988DA);
      SHA2_32_F(A, B, C, D, E, F, G, H, W[ 8], W[ 6], W[ 1], W[ 9], 0x983E5152);
      SHA2_32_F(H, A, B, C, D, E, F, G, W[ 9], W[ 7], W[ 2], W[10], 0xA831C66D);
      SHA2_32_F(G, H, A, B, C, D, E, F, W[10], W[ 8], W[ 3], W[11], 0xB00327C8);
      SHA2_32_F(F, G, H, A, B, C, D, E, W[11], W[ 9], W[ 4], W[12], 0xBF597FC7);
      SHA2_32_F(E, F, G, H, A, B, C, D, W[12], W[10], W[ 5], W[13], 0xC6E00BF3);
      SHA2_32_F(D, E, F, G, H, A, B, C, W[13], W[11], W[ 6], W[14], 0xD5A79147);
      SHA2_32_F(C, D, E, F, G, H, A, B, W[14], W[12], W[ 7], W[15], 0x06CA6351);
      SHA2_32_F(B, C, D, E, F, G, H, A, W[15], W[13], W[ 8], W[ 0], 0x14292967);

      SHA2_32_F(A, B, C, D, E, F, G, H, W[ 0], W[14], W[ 9], W[ 1], 0x27B70A85);
      SHA2_32_F(H, A, B, C, D, E, F, G, W[ 1], W[15], W[10], W[ 2], 0x2E1B2138);
      SHA2_32_F(G, H, A, B, C, D, E, F, W[ 2], W[ 0], W[11], W[ 3], 0x4D2C6DFC);
      SHA2_32_F(F, G, H, A, B, C, D, E, W[ 3], W[ 1], W[12], W[ 4], 0x53380D13);
      SHA2_32_F(E, F, G, H, A, B, C, D, W[ 4], W[ 2], W[13], W[ 5], 0x650A7354);
      SHA2_32_F(D, E, F, G, H, A, B, C, W[ 5], W[ 3], W[14], W[ 6], 0x766A0ABB);
      SHA2_32_F(C, D, E, F, G, H, A, B, W[ 6], W[ 4], W[15], W[ 7], 0x81C2C92E);
      SHA2_32_F(B, C, D, E, F, G, H, A, W[ 7], W[ 5], W[ 0], W[ 8], 0x92722C85);
      SHA2_32_F(A, B, C, D, E, F, G, H, W[ 8], W[ 6], W[ 1], W[ 9], 0xA2BFE8A1);
      SHA2_32_F(H, A, B, C, D, E, F, G, W[ 9], W[ 7], W[ 2], W[10], 0xA81A664B);
      SHA2_32_F(G, H, A, B, C, D, E, F, W[10], W[ 8], W[ 3], W[11], 0xC24B8B70);
      SHA2_32_F(F, G, H, A, B, C, D, E, W[11], W[ 9], W[ 4], W[12], 0xC76C51A3);
      SHA2_32_F(E, F, G, H, A, B, C, D, W[12], W[10], W[ 5], W[13], 0xD192E819);
      SHA2_32_F(D, E, F, G, H, A, B, C, W[13], W[11], W[ 6], W[14], 0xD6990624);
      SHA2_32_F(C, D, E, F, G, H, A, B, W[14], W[12], W[ 7], W[15], 0xF40E3585);
      SHA2_32_F(B, C, D, E, F, G, H, A, W[15], W[13], W[ 8], W[ 0], 0x106AA070);

      SHA2_32_F(A, B, C, D, E, F, G, H, W[ 0], W[14], W[ 9], W[ 1], 0x19A4C116);
      SHA2_32_F(H, A, B, C, D, E, F, G, W[ 1], W[15], W[10], W[ 2], 0x1E376C08);
      SHA2_32_F(G, H, A, B, C, D, E, F, W[ 2], W[ 0], W[11], W[ 3], 0x2748774C);
      SHA2_32_F(F, G, H, A, B, C, D, E, W[ 3], W[ 1], W[12], W[ 4], 0x34B0BCB5);
      SHA2_32_F(E, F, G, H, A, B, C, D, W[ 4], W[ 2], W[13], W[ 5], 0x391C0CB3);
      SHA2_32_F(D, E, F, G, H, A, B, C, W[ 5], W[ 3], W[14], W[ 6], 0x4ED8AA4A);
      SHA2_32_F(C, D, E, F, G, H, A, B, W[ 6], W[ 4], W[15], W[ 7], 0x5B9CCA4F);
      SHA2_32_F(B, C, D, E, F, G, H, A, W[ 7], W[ 5], W[ 0], W[ 8], 0x682E6FF3);
      SHA2_32_F(A, B, C, D, E, F, G, H, W[ 8], W[ 6], W[ 1], W[ 9], 0x748F82EE);
      SHA2_32_F(H, A, B, C, D, E, F, G, W[ 9], W[ 7], W[ 2], W[10], 0x78A5636F);
      SHA2_32_F(G, H, A, B, C, D, E, F, W[10], W[ 8], W[ 3], W[11], 0x84C87814);
      SHA2_32_F(F, G, H, A, B, C, D, E, W[11], W[ 9], W[ 4], W[12], 0x8CC70208);
      SHA2_32_F(E, F, G, H, A, B, C, D, W[12], W[10], W[ 5], W[13], 0x90BEFFFA);
      SHA2_32_F(D, E, F, G, H, A, B, C, W[13], W[11], W[ 6], W[14], 0xA4506CEB);
      SHA2_32_F(C, D, E, F, G, H, A, B, W[14], W[12], W[ 7], W[15], 0xBEF9A3F7);
      SHA2_32_F(B, C, D, E, F, G, H, A, W[15], W[13], W[ 8], W[ 0], 0xC67178F2);

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
