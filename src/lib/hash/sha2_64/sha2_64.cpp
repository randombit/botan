/*
* SHA-{384,512}
* (C) 1999-2011,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/sha2_64.h>

#include <botan/internal/buffer_slicer.h>
#include <botan/internal/loadstor.h>
#include <botan/internal/sha2_64_f.h>

#if defined(BOTAN_HAS_CPUID)
   #include <botan/internal/cpuid.h>
#endif

namespace Botan {

namespace {

std::string sha512_provider() {
#if defined(BOTAN_HAS_SHA2_64_X86)
   if(auto feat = CPUID::check(CPUID::Feature::SHA512)) {
      return *feat;
   }
#endif

#if defined(BOTAN_HAS_SHA2_64_ARMV8)
   if(auto feat = CPUID::check(CPUID::Feature::SHA2_512)) {
      return *feat;
   }
#endif

#if defined(BOTAN_HAS_SHA2_64_X86_AVX512)
   if(auto feat = CPUID::check(CPUID::Feature::AVX512, CPUID::Feature::BMI)) {
      return *feat;
   }
#endif

#if defined(BOTAN_HAS_SHA2_64_X86_AVX2)
   if(auto feat = CPUID::check(CPUID::Feature::AVX2, CPUID::Feature::BMI)) {
      return *feat;
   }
#endif

   return "base";
}

}  // namespace

/*
* SHA-{384,512} Compression Function
*/
//static
void SHA_512::compress_digest(digest_type& digest, std::span<const uint8_t> input, size_t blocks) {
#if defined(BOTAN_HAS_SHA2_64_X86)
   if(CPUID::has(CPUID::Feature::SHA512)) {
      return compress_digest_x86(digest, input, blocks);
   }
#endif

#if defined(BOTAN_HAS_SHA2_64_ARMV8)
   if(CPUID::has(CPUID::Feature::SHA2_512)) {
      return compress_digest_armv8(digest, input, blocks);
   }
#endif

#if defined(BOTAN_HAS_SHA2_64_X86_AVX512)
   if(CPUID::has(CPUID::Feature::AVX512, CPUID::Feature::BMI)) {
      return compress_digest_x86_avx512(digest, input, blocks);
   }
#endif

#if defined(BOTAN_HAS_SHA2_64_X86_AVX2)
   if(CPUID::has(CPUID::Feature::AVX2, CPUID::Feature::BMI)) {
      return compress_digest_x86_avx2(digest, input, blocks);
   }
#endif

   uint64_t A = digest[0];
   uint64_t B = digest[1];
   uint64_t C = digest[2];
   uint64_t D = digest[3];
   uint64_t E = digest[4];
   uint64_t F = digest[5];
   uint64_t G = digest[6];
   uint64_t H = digest[7];

   std::array<uint64_t, 16> W{};

   BufferSlicer in(input);

   for(size_t i = 0; i != blocks; ++i) {
      load_be(W, in.take<block_bytes>());

      // clang-format off

      SHA2_64_F(A, B, C, D, E, F, G, H, W[ 0], W[14], W[ 9], W[ 1], SHA512_K[ 0]);
      SHA2_64_F(H, A, B, C, D, E, F, G, W[ 1], W[15], W[10], W[ 2], SHA512_K[ 1]);
      SHA2_64_F(G, H, A, B, C, D, E, F, W[ 2], W[ 0], W[11], W[ 3], SHA512_K[ 2]);
      SHA2_64_F(F, G, H, A, B, C, D, E, W[ 3], W[ 1], W[12], W[ 4], SHA512_K[ 3]);
      SHA2_64_F(E, F, G, H, A, B, C, D, W[ 4], W[ 2], W[13], W[ 5], SHA512_K[ 4]);
      SHA2_64_F(D, E, F, G, H, A, B, C, W[ 5], W[ 3], W[14], W[ 6], SHA512_K[ 5]);
      SHA2_64_F(C, D, E, F, G, H, A, B, W[ 6], W[ 4], W[15], W[ 7], SHA512_K[ 6]);
      SHA2_64_F(B, C, D, E, F, G, H, A, W[ 7], W[ 5], W[ 0], W[ 8], SHA512_K[ 7]);
      SHA2_64_F(A, B, C, D, E, F, G, H, W[ 8], W[ 6], W[ 1], W[ 9], SHA512_K[ 8]);
      SHA2_64_F(H, A, B, C, D, E, F, G, W[ 9], W[ 7], W[ 2], W[10], SHA512_K[ 9]);
      SHA2_64_F(G, H, A, B, C, D, E, F, W[10], W[ 8], W[ 3], W[11], SHA512_K[10]);
      SHA2_64_F(F, G, H, A, B, C, D, E, W[11], W[ 9], W[ 4], W[12], SHA512_K[11]);
      SHA2_64_F(E, F, G, H, A, B, C, D, W[12], W[10], W[ 5], W[13], SHA512_K[12]);
      SHA2_64_F(D, E, F, G, H, A, B, C, W[13], W[11], W[ 6], W[14], SHA512_K[13]);
      SHA2_64_F(C, D, E, F, G, H, A, B, W[14], W[12], W[ 7], W[15], SHA512_K[14]);
      SHA2_64_F(B, C, D, E, F, G, H, A, W[15], W[13], W[ 8], W[ 0], SHA512_K[15]);
      SHA2_64_F(A, B, C, D, E, F, G, H, W[ 0], W[14], W[ 9], W[ 1], SHA512_K[16]);
      SHA2_64_F(H, A, B, C, D, E, F, G, W[ 1], W[15], W[10], W[ 2], SHA512_K[17]);
      SHA2_64_F(G, H, A, B, C, D, E, F, W[ 2], W[ 0], W[11], W[ 3], SHA512_K[18]);
      SHA2_64_F(F, G, H, A, B, C, D, E, W[ 3], W[ 1], W[12], W[ 4], SHA512_K[19]);
      SHA2_64_F(E, F, G, H, A, B, C, D, W[ 4], W[ 2], W[13], W[ 5], SHA512_K[20]);
      SHA2_64_F(D, E, F, G, H, A, B, C, W[ 5], W[ 3], W[14], W[ 6], SHA512_K[21]);
      SHA2_64_F(C, D, E, F, G, H, A, B, W[ 6], W[ 4], W[15], W[ 7], SHA512_K[22]);
      SHA2_64_F(B, C, D, E, F, G, H, A, W[ 7], W[ 5], W[ 0], W[ 8], SHA512_K[23]);
      SHA2_64_F(A, B, C, D, E, F, G, H, W[ 8], W[ 6], W[ 1], W[ 9], SHA512_K[24]);
      SHA2_64_F(H, A, B, C, D, E, F, G, W[ 9], W[ 7], W[ 2], W[10], SHA512_K[25]);
      SHA2_64_F(G, H, A, B, C, D, E, F, W[10], W[ 8], W[ 3], W[11], SHA512_K[26]);
      SHA2_64_F(F, G, H, A, B, C, D, E, W[11], W[ 9], W[ 4], W[12], SHA512_K[27]);
      SHA2_64_F(E, F, G, H, A, B, C, D, W[12], W[10], W[ 5], W[13], SHA512_K[28]);
      SHA2_64_F(D, E, F, G, H, A, B, C, W[13], W[11], W[ 6], W[14], SHA512_K[29]);
      SHA2_64_F(C, D, E, F, G, H, A, B, W[14], W[12], W[ 7], W[15], SHA512_K[30]);
      SHA2_64_F(B, C, D, E, F, G, H, A, W[15], W[13], W[ 8], W[ 0], SHA512_K[31]);
      SHA2_64_F(A, B, C, D, E, F, G, H, W[ 0], W[14], W[ 9], W[ 1], SHA512_K[32]);
      SHA2_64_F(H, A, B, C, D, E, F, G, W[ 1], W[15], W[10], W[ 2], SHA512_K[33]);
      SHA2_64_F(G, H, A, B, C, D, E, F, W[ 2], W[ 0], W[11], W[ 3], SHA512_K[34]);
      SHA2_64_F(F, G, H, A, B, C, D, E, W[ 3], W[ 1], W[12], W[ 4], SHA512_K[35]);
      SHA2_64_F(E, F, G, H, A, B, C, D, W[ 4], W[ 2], W[13], W[ 5], SHA512_K[36]);
      SHA2_64_F(D, E, F, G, H, A, B, C, W[ 5], W[ 3], W[14], W[ 6], SHA512_K[37]);
      SHA2_64_F(C, D, E, F, G, H, A, B, W[ 6], W[ 4], W[15], W[ 7], SHA512_K[38]);
      SHA2_64_F(B, C, D, E, F, G, H, A, W[ 7], W[ 5], W[ 0], W[ 8], SHA512_K[39]);
      SHA2_64_F(A, B, C, D, E, F, G, H, W[ 8], W[ 6], W[ 1], W[ 9], SHA512_K[40]);
      SHA2_64_F(H, A, B, C, D, E, F, G, W[ 9], W[ 7], W[ 2], W[10], SHA512_K[41]);
      SHA2_64_F(G, H, A, B, C, D, E, F, W[10], W[ 8], W[ 3], W[11], SHA512_K[42]);
      SHA2_64_F(F, G, H, A, B, C, D, E, W[11], W[ 9], W[ 4], W[12], SHA512_K[43]);
      SHA2_64_F(E, F, G, H, A, B, C, D, W[12], W[10], W[ 5], W[13], SHA512_K[44]);
      SHA2_64_F(D, E, F, G, H, A, B, C, W[13], W[11], W[ 6], W[14], SHA512_K[45]);
      SHA2_64_F(C, D, E, F, G, H, A, B, W[14], W[12], W[ 7], W[15], SHA512_K[46]);
      SHA2_64_F(B, C, D, E, F, G, H, A, W[15], W[13], W[ 8], W[ 0], SHA512_K[47]);
      SHA2_64_F(A, B, C, D, E, F, G, H, W[ 0], W[14], W[ 9], W[ 1], SHA512_K[48]);
      SHA2_64_F(H, A, B, C, D, E, F, G, W[ 1], W[15], W[10], W[ 2], SHA512_K[49]);
      SHA2_64_F(G, H, A, B, C, D, E, F, W[ 2], W[ 0], W[11], W[ 3], SHA512_K[50]);
      SHA2_64_F(F, G, H, A, B, C, D, E, W[ 3], W[ 1], W[12], W[ 4], SHA512_K[51]);
      SHA2_64_F(E, F, G, H, A, B, C, D, W[ 4], W[ 2], W[13], W[ 5], SHA512_K[52]);
      SHA2_64_F(D, E, F, G, H, A, B, C, W[ 5], W[ 3], W[14], W[ 6], SHA512_K[53]);
      SHA2_64_F(C, D, E, F, G, H, A, B, W[ 6], W[ 4], W[15], W[ 7], SHA512_K[54]);
      SHA2_64_F(B, C, D, E, F, G, H, A, W[ 7], W[ 5], W[ 0], W[ 8], SHA512_K[55]);
      SHA2_64_F(A, B, C, D, E, F, G, H, W[ 8], W[ 6], W[ 1], W[ 9], SHA512_K[56]);
      SHA2_64_F(H, A, B, C, D, E, F, G, W[ 9], W[ 7], W[ 2], W[10], SHA512_K[57]);
      SHA2_64_F(G, H, A, B, C, D, E, F, W[10], W[ 8], W[ 3], W[11], SHA512_K[58]);
      SHA2_64_F(F, G, H, A, B, C, D, E, W[11], W[ 9], W[ 4], W[12], SHA512_K[59]);
      SHA2_64_F(E, F, G, H, A, B, C, D, W[12], W[10], W[ 5], W[13], SHA512_K[60]);
      SHA2_64_F(D, E, F, G, H, A, B, C, W[13], W[11], W[ 6], W[14], SHA512_K[61]);
      SHA2_64_F(C, D, E, F, G, H, A, B, W[14], W[12], W[ 7], W[15], SHA512_K[62]);
      SHA2_64_F(B, C, D, E, F, G, H, A, W[15], W[13], W[ 8], W[ 0], SHA512_K[63]);
      SHA2_64_F(A, B, C, D, E, F, G, H, W[ 0], W[14], W[ 9], W[ 1], SHA512_K[64]);
      SHA2_64_F(H, A, B, C, D, E, F, G, W[ 1], W[15], W[10], W[ 2], SHA512_K[65]);
      SHA2_64_F(G, H, A, B, C, D, E, F, W[ 2], W[ 0], W[11], W[ 3], SHA512_K[66]);
      SHA2_64_F(F, G, H, A, B, C, D, E, W[ 3], W[ 1], W[12], W[ 4], SHA512_K[67]);
      SHA2_64_F(E, F, G, H, A, B, C, D, W[ 4], W[ 2], W[13], W[ 5], SHA512_K[68]);
      SHA2_64_F(D, E, F, G, H, A, B, C, W[ 5], W[ 3], W[14], W[ 6], SHA512_K[69]);
      SHA2_64_F(C, D, E, F, G, H, A, B, W[ 6], W[ 4], W[15], W[ 7], SHA512_K[70]);
      SHA2_64_F(B, C, D, E, F, G, H, A, W[ 7], W[ 5], W[ 0], W[ 8], SHA512_K[71]);
      SHA2_64_F(A, B, C, D, E, F, G, H, W[ 8], W[ 6], W[ 1], W[ 9], SHA512_K[72]);
      SHA2_64_F(H, A, B, C, D, E, F, G, W[ 9], W[ 7], W[ 2], W[10], SHA512_K[73]);
      SHA2_64_F(G, H, A, B, C, D, E, F, W[10], W[ 8], W[ 3], W[11], SHA512_K[74]);
      SHA2_64_F(F, G, H, A, B, C, D, E, W[11], W[ 9], W[ 4], W[12], SHA512_K[75]);
      SHA2_64_F(E, F, G, H, A, B, C, D, W[12], W[10], W[ 5], W[13], SHA512_K[76]);
      SHA2_64_F(D, E, F, G, H, A, B, C, W[13], W[11], W[ 6], W[14], SHA512_K[77]);
      SHA2_64_F(C, D, E, F, G, H, A, B, W[14], W[12], W[ 7], W[15], SHA512_K[78]);
      SHA2_64_F(B, C, D, E, F, G, H, A, W[15], W[13], W[ 8], W[ 0], SHA512_K[79]);

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

std::string SHA_512_256::provider() const {
   return sha512_provider();
}

std::string SHA_384::provider() const {
   return sha512_provider();
}

std::string SHA_512::provider() const {
   return sha512_provider();
}

void SHA_512_256::compress_n(digest_type& digest, std::span<const uint8_t> input, size_t blocks) {
   SHA_512::compress_digest(digest, input, blocks);
}

void SHA_384::compress_n(digest_type& digest, std::span<const uint8_t> input, size_t blocks) {
   SHA_512::compress_digest(digest, input, blocks);
}

void SHA_512::compress_n(digest_type& digest, std::span<const uint8_t> input, size_t blocks) {
   SHA_512::compress_digest(digest, input, blocks);
}

void SHA_512_256::init(digest_type& digest) {
   digest.assign({0x22312194FC2BF72C,
                  0x9F555FA3C84C64C2,
                  0x2393B86B6F53B151,
                  0x963877195940EABD,
                  0x96283EE2A88EFFE3,
                  0xBE5E1E2553863992,
                  0x2B0199FC2C85B8AA,
                  0x0EB72DDC81C52CA2});
}

void SHA_384::init(digest_type& digest) {
   digest.assign({0xCBBB9D5DC1059ED8,
                  0x629A292A367CD507,
                  0x9159015A3070DD17,
                  0x152FECD8F70E5939,
                  0x67332667FFC00B31,
                  0x8EB44A8768581511,
                  0xDB0C2E0D64F98FA7,
                  0x47B5481DBEFA4FA4});
}

void SHA_512::init(digest_type& digest) {
   digest.assign({0x6A09E667F3BCC908,
                  0xBB67AE8584CAA73B,
                  0x3C6EF372FE94F82B,
                  0xA54FF53A5F1D36F1,
                  0x510E527FADE682D1,
                  0x9B05688C2B3E6C1F,
                  0x1F83D9ABFB41BD6B,
                  0x5BE0CD19137E2179});
}

std::unique_ptr<HashFunction> SHA_384::new_object() const {
   return std::make_unique<SHA_384>();
}

std::unique_ptr<HashFunction> SHA_512::new_object() const {
   return std::make_unique<SHA_512>();
}

std::unique_ptr<HashFunction> SHA_512_256::new_object() const {
   return std::make_unique<SHA_512_256>();
}

std::unique_ptr<HashFunction> SHA_384::copy_state() const {
   return std::make_unique<SHA_384>(*this);
}

std::unique_ptr<HashFunction> SHA_512::copy_state() const {
   return std::make_unique<SHA_512>(*this);
}

std::unique_ptr<HashFunction> SHA_512_256::copy_state() const {
   return std::make_unique<SHA_512_256>(*this);
}

void SHA_384::add_data(std::span<const uint8_t> input) {
   m_md.update(input);
}

void SHA_512::add_data(std::span<const uint8_t> input) {
   m_md.update(input);
}

void SHA_512_256::add_data(std::span<const uint8_t> input) {
   m_md.update(input);
}

void SHA_384::final_result(std::span<uint8_t> output) {
   m_md.final(output);
}

void SHA_512::final_result(std::span<uint8_t> output) {
   m_md.final(output);
}

void SHA_512_256::final_result(std::span<uint8_t> output) {
   m_md.final(output);
}

}  // namespace Botan
