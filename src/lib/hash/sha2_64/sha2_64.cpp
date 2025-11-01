/*
* SHA-{384,512}
* (C) 1999-2011,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/sha2_64.h>

#include <botan/internal/loadstor.h>
#include <botan/internal/sha2_64_f.h>
#include <botan/internal/stl_util.h>

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

      SHA2_64_F(A, B, C, D, E, F, G, H, W[ 0], W[14], W[ 9], W[ 1], 0x428A2F98D728AE22);
      SHA2_64_F(H, A, B, C, D, E, F, G, W[ 1], W[15], W[10], W[ 2], 0x7137449123EF65CD);
      SHA2_64_F(G, H, A, B, C, D, E, F, W[ 2], W[ 0], W[11], W[ 3], 0xB5C0FBCFEC4D3B2F);
      SHA2_64_F(F, G, H, A, B, C, D, E, W[ 3], W[ 1], W[12], W[ 4], 0xE9B5DBA58189DBBC);
      SHA2_64_F(E, F, G, H, A, B, C, D, W[ 4], W[ 2], W[13], W[ 5], 0x3956C25BF348B538);
      SHA2_64_F(D, E, F, G, H, A, B, C, W[ 5], W[ 3], W[14], W[ 6], 0x59F111F1B605D019);
      SHA2_64_F(C, D, E, F, G, H, A, B, W[ 6], W[ 4], W[15], W[ 7], 0x923F82A4AF194F9B);
      SHA2_64_F(B, C, D, E, F, G, H, A, W[ 7], W[ 5], W[ 0], W[ 8], 0xAB1C5ED5DA6D8118);
      SHA2_64_F(A, B, C, D, E, F, G, H, W[ 8], W[ 6], W[ 1], W[ 9], 0xD807AA98A3030242);
      SHA2_64_F(H, A, B, C, D, E, F, G, W[ 9], W[ 7], W[ 2], W[10], 0x12835B0145706FBE);
      SHA2_64_F(G, H, A, B, C, D, E, F, W[10], W[ 8], W[ 3], W[11], 0x243185BE4EE4B28C);
      SHA2_64_F(F, G, H, A, B, C, D, E, W[11], W[ 9], W[ 4], W[12], 0x550C7DC3D5FFB4E2);
      SHA2_64_F(E, F, G, H, A, B, C, D, W[12], W[10], W[ 5], W[13], 0x72BE5D74F27B896F);
      SHA2_64_F(D, E, F, G, H, A, B, C, W[13], W[11], W[ 6], W[14], 0x80DEB1FE3B1696B1);
      SHA2_64_F(C, D, E, F, G, H, A, B, W[14], W[12], W[ 7], W[15], 0x9BDC06A725C71235);
      SHA2_64_F(B, C, D, E, F, G, H, A, W[15], W[13], W[ 8], W[ 0], 0xC19BF174CF692694);
      SHA2_64_F(A, B, C, D, E, F, G, H, W[ 0], W[14], W[ 9], W[ 1], 0xE49B69C19EF14AD2);
      SHA2_64_F(H, A, B, C, D, E, F, G, W[ 1], W[15], W[10], W[ 2], 0xEFBE4786384F25E3);
      SHA2_64_F(G, H, A, B, C, D, E, F, W[ 2], W[ 0], W[11], W[ 3], 0x0FC19DC68B8CD5B5);
      SHA2_64_F(F, G, H, A, B, C, D, E, W[ 3], W[ 1], W[12], W[ 4], 0x240CA1CC77AC9C65);
      SHA2_64_F(E, F, G, H, A, B, C, D, W[ 4], W[ 2], W[13], W[ 5], 0x2DE92C6F592B0275);
      SHA2_64_F(D, E, F, G, H, A, B, C, W[ 5], W[ 3], W[14], W[ 6], 0x4A7484AA6EA6E483);
      SHA2_64_F(C, D, E, F, G, H, A, B, W[ 6], W[ 4], W[15], W[ 7], 0x5CB0A9DCBD41FBD4);
      SHA2_64_F(B, C, D, E, F, G, H, A, W[ 7], W[ 5], W[ 0], W[ 8], 0x76F988DA831153B5);
      SHA2_64_F(A, B, C, D, E, F, G, H, W[ 8], W[ 6], W[ 1], W[ 9], 0x983E5152EE66DFAB);
      SHA2_64_F(H, A, B, C, D, E, F, G, W[ 9], W[ 7], W[ 2], W[10], 0xA831C66D2DB43210);
      SHA2_64_F(G, H, A, B, C, D, E, F, W[10], W[ 8], W[ 3], W[11], 0xB00327C898FB213F);
      SHA2_64_F(F, G, H, A, B, C, D, E, W[11], W[ 9], W[ 4], W[12], 0xBF597FC7BEEF0EE4);
      SHA2_64_F(E, F, G, H, A, B, C, D, W[12], W[10], W[ 5], W[13], 0xC6E00BF33DA88FC2);
      SHA2_64_F(D, E, F, G, H, A, B, C, W[13], W[11], W[ 6], W[14], 0xD5A79147930AA725);
      SHA2_64_F(C, D, E, F, G, H, A, B, W[14], W[12], W[ 7], W[15], 0x06CA6351E003826F);
      SHA2_64_F(B, C, D, E, F, G, H, A, W[15], W[13], W[ 8], W[ 0], 0x142929670A0E6E70);
      SHA2_64_F(A, B, C, D, E, F, G, H, W[ 0], W[14], W[ 9], W[ 1], 0x27B70A8546D22FFC);
      SHA2_64_F(H, A, B, C, D, E, F, G, W[ 1], W[15], W[10], W[ 2], 0x2E1B21385C26C926);
      SHA2_64_F(G, H, A, B, C, D, E, F, W[ 2], W[ 0], W[11], W[ 3], 0x4D2C6DFC5AC42AED);
      SHA2_64_F(F, G, H, A, B, C, D, E, W[ 3], W[ 1], W[12], W[ 4], 0x53380D139D95B3DF);
      SHA2_64_F(E, F, G, H, A, B, C, D, W[ 4], W[ 2], W[13], W[ 5], 0x650A73548BAF63DE);
      SHA2_64_F(D, E, F, G, H, A, B, C, W[ 5], W[ 3], W[14], W[ 6], 0x766A0ABB3C77B2A8);
      SHA2_64_F(C, D, E, F, G, H, A, B, W[ 6], W[ 4], W[15], W[ 7], 0x81C2C92E47EDAEE6);
      SHA2_64_F(B, C, D, E, F, G, H, A, W[ 7], W[ 5], W[ 0], W[ 8], 0x92722C851482353B);
      SHA2_64_F(A, B, C, D, E, F, G, H, W[ 8], W[ 6], W[ 1], W[ 9], 0xA2BFE8A14CF10364);
      SHA2_64_F(H, A, B, C, D, E, F, G, W[ 9], W[ 7], W[ 2], W[10], 0xA81A664BBC423001);
      SHA2_64_F(G, H, A, B, C, D, E, F, W[10], W[ 8], W[ 3], W[11], 0xC24B8B70D0F89791);
      SHA2_64_F(F, G, H, A, B, C, D, E, W[11], W[ 9], W[ 4], W[12], 0xC76C51A30654BE30);
      SHA2_64_F(E, F, G, H, A, B, C, D, W[12], W[10], W[ 5], W[13], 0xD192E819D6EF5218);
      SHA2_64_F(D, E, F, G, H, A, B, C, W[13], W[11], W[ 6], W[14], 0xD69906245565A910);
      SHA2_64_F(C, D, E, F, G, H, A, B, W[14], W[12], W[ 7], W[15], 0xF40E35855771202A);
      SHA2_64_F(B, C, D, E, F, G, H, A, W[15], W[13], W[ 8], W[ 0], 0x106AA07032BBD1B8);
      SHA2_64_F(A, B, C, D, E, F, G, H, W[ 0], W[14], W[ 9], W[ 1], 0x19A4C116B8D2D0C8);
      SHA2_64_F(H, A, B, C, D, E, F, G, W[ 1], W[15], W[10], W[ 2], 0x1E376C085141AB53);
      SHA2_64_F(G, H, A, B, C, D, E, F, W[ 2], W[ 0], W[11], W[ 3], 0x2748774CDF8EEB99);
      SHA2_64_F(F, G, H, A, B, C, D, E, W[ 3], W[ 1], W[12], W[ 4], 0x34B0BCB5E19B48A8);
      SHA2_64_F(E, F, G, H, A, B, C, D, W[ 4], W[ 2], W[13], W[ 5], 0x391C0CB3C5C95A63);
      SHA2_64_F(D, E, F, G, H, A, B, C, W[ 5], W[ 3], W[14], W[ 6], 0x4ED8AA4AE3418ACB);
      SHA2_64_F(C, D, E, F, G, H, A, B, W[ 6], W[ 4], W[15], W[ 7], 0x5B9CCA4F7763E373);
      SHA2_64_F(B, C, D, E, F, G, H, A, W[ 7], W[ 5], W[ 0], W[ 8], 0x682E6FF3D6B2B8A3);
      SHA2_64_F(A, B, C, D, E, F, G, H, W[ 8], W[ 6], W[ 1], W[ 9], 0x748F82EE5DEFB2FC);
      SHA2_64_F(H, A, B, C, D, E, F, G, W[ 9], W[ 7], W[ 2], W[10], 0x78A5636F43172F60);
      SHA2_64_F(G, H, A, B, C, D, E, F, W[10], W[ 8], W[ 3], W[11], 0x84C87814A1F0AB72);
      SHA2_64_F(F, G, H, A, B, C, D, E, W[11], W[ 9], W[ 4], W[12], 0x8CC702081A6439EC);
      SHA2_64_F(E, F, G, H, A, B, C, D, W[12], W[10], W[ 5], W[13], 0x90BEFFFA23631E28);
      SHA2_64_F(D, E, F, G, H, A, B, C, W[13], W[11], W[ 6], W[14], 0xA4506CEBDE82BDE9);
      SHA2_64_F(C, D, E, F, G, H, A, B, W[14], W[12], W[ 7], W[15], 0xBEF9A3F7B2C67915);
      SHA2_64_F(B, C, D, E, F, G, H, A, W[15], W[13], W[ 8], W[ 0], 0xC67178F2E372532B);
      SHA2_64_F(A, B, C, D, E, F, G, H, W[ 0], W[14], W[ 9], W[ 1], 0xCA273ECEEA26619C);
      SHA2_64_F(H, A, B, C, D, E, F, G, W[ 1], W[15], W[10], W[ 2], 0xD186B8C721C0C207);
      SHA2_64_F(G, H, A, B, C, D, E, F, W[ 2], W[ 0], W[11], W[ 3], 0xEADA7DD6CDE0EB1E);
      SHA2_64_F(F, G, H, A, B, C, D, E, W[ 3], W[ 1], W[12], W[ 4], 0xF57D4F7FEE6ED178);
      SHA2_64_F(E, F, G, H, A, B, C, D, W[ 4], W[ 2], W[13], W[ 5], 0x06F067AA72176FBA);
      SHA2_64_F(D, E, F, G, H, A, B, C, W[ 5], W[ 3], W[14], W[ 6], 0x0A637DC5A2C898A6);
      SHA2_64_F(C, D, E, F, G, H, A, B, W[ 6], W[ 4], W[15], W[ 7], 0x113F9804BEF90DAE);
      SHA2_64_F(B, C, D, E, F, G, H, A, W[ 7], W[ 5], W[ 0], W[ 8], 0x1B710B35131C471B);
      SHA2_64_F(A, B, C, D, E, F, G, H, W[ 8], W[ 6], W[ 1], W[ 9], 0x28DB77F523047D84);
      SHA2_64_F(H, A, B, C, D, E, F, G, W[ 9], W[ 7], W[ 2], W[10], 0x32CAAB7B40C72493);
      SHA2_64_F(G, H, A, B, C, D, E, F, W[10], W[ 8], W[ 3], W[11], 0x3C9EBE0A15C9BEBC);
      SHA2_64_F(F, G, H, A, B, C, D, E, W[11], W[ 9], W[ 4], W[12], 0x431D67C49C100D4C);
      SHA2_64_F(E, F, G, H, A, B, C, D, W[12], W[10], W[ 5], W[13], 0x4CC5D4BECB3E42B6);
      SHA2_64_F(D, E, F, G, H, A, B, C, W[13], W[11], W[ 6], W[14], 0x597F299CFC657E2A);
      SHA2_64_F(C, D, E, F, G, H, A, B, W[14], W[12], W[ 7], W[15], 0x5FCB6FAB3AD6FAEC);
      SHA2_64_F(B, C, D, E, F, G, H, A, W[15], W[13], W[ 8], W[ 0], 0x6C44198C4A475817);

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
