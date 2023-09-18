/*
* SHA-1
* (C) 1999-2008,2011 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/sha1.h>

#include <botan/internal/bit_ops.h>
#include <botan/internal/cpuid.h>
#include <botan/internal/loadstor.h>
#include <botan/internal/rotate.h>
#include <botan/internal/stl_util.h>

#include <array>

namespace Botan {

namespace SHA1_F {

namespace {

/*
* SHA-1 F1 Function
*/
inline void F1(uint32_t A, uint32_t& B, uint32_t C, uint32_t D, uint32_t& E, uint32_t msg) {
   E += choose(B, C, D) + msg + 0x5A827999 + rotl<5>(A);
   B = rotl<30>(B);
}

/*
* SHA-1 F2 Function
*/
inline void F2(uint32_t A, uint32_t& B, uint32_t C, uint32_t D, uint32_t& E, uint32_t msg) {
   E += (B ^ C ^ D) + msg + 0x6ED9EBA1 + rotl<5>(A);
   B = rotl<30>(B);
}

/*
* SHA-1 F3 Function
*/
inline void F3(uint32_t A, uint32_t& B, uint32_t C, uint32_t D, uint32_t& E, uint32_t msg) {
   E += majority(B, C, D) + msg + 0x8F1BBCDC + rotl<5>(A);
   B = rotl<30>(B);
}

/*
* SHA-1 F4 Function
*/
inline void F4(uint32_t A, uint32_t& B, uint32_t C, uint32_t D, uint32_t& E, uint32_t msg) {
   E += (B ^ C ^ D) + msg + 0xCA62C1D6 + rotl<5>(A);
   B = rotl<30>(B);
}

}  // namespace

}  // namespace SHA1_F

/*
* SHA-1 Compression Function
*/
void SHA_1::compress_n(digest_type& digest, std::span<const uint8_t> input, size_t blocks) {
   using namespace SHA1_F;

#if defined(BOTAN_HAS_SHA1_X86_SHA_NI)
   if(CPUID::has_intel_sha()) {
      return sha1_compress_x86(digest, input, blocks);
   }
#endif

#if defined(BOTAN_HAS_SHA1_ARMV8)
   if(CPUID::has_arm_sha1()) {
      return sha1_armv8_compress_n(digest, input, blocks);
   }
#endif

#if defined(BOTAN_HAS_SHA1_SSE2)
   if(CPUID::has_sse2()) {
      return sse2_compress_n(digest, input, blocks);
   }

#endif

   uint32_t A = digest[0], B = digest[1], C = digest[2], D = digest[3], E = digest[4];
   std::array<uint32_t, 80> W;

   BufferSlicer in(input);

   for(size_t i = 0; i != blocks; ++i) {
      load_be(W.data(), in.take(block_bytes).data(), 16);

      for(size_t j = 16; j != 80; j += 8) {
         W[j] = rotl<1>(W[j - 3] ^ W[j - 8] ^ W[j - 14] ^ W[j - 16]);
         W[j + 1] = rotl<1>(W[j - 2] ^ W[j - 7] ^ W[j - 13] ^ W[j - 15]);
         W[j + 2] = rotl<1>(W[j - 1] ^ W[j - 6] ^ W[j - 12] ^ W[j - 14]);
         W[j + 3] = rotl<1>(W[j] ^ W[j - 5] ^ W[j - 11] ^ W[j - 13]);
         W[j + 4] = rotl<1>(W[j + 1] ^ W[j - 4] ^ W[j - 10] ^ W[j - 12]);
         W[j + 5] = rotl<1>(W[j + 2] ^ W[j - 3] ^ W[j - 9] ^ W[j - 11]);
         W[j + 6] = rotl<1>(W[j + 3] ^ W[j - 2] ^ W[j - 8] ^ W[j - 10]);
         W[j + 7] = rotl<1>(W[j + 4] ^ W[j - 1] ^ W[j - 7] ^ W[j - 9]);
      }

      F1(A, B, C, D, E, W[0]);
      F1(E, A, B, C, D, W[1]);
      F1(D, E, A, B, C, W[2]);
      F1(C, D, E, A, B, W[3]);
      F1(B, C, D, E, A, W[4]);
      F1(A, B, C, D, E, W[5]);
      F1(E, A, B, C, D, W[6]);
      F1(D, E, A, B, C, W[7]);
      F1(C, D, E, A, B, W[8]);
      F1(B, C, D, E, A, W[9]);
      F1(A, B, C, D, E, W[10]);
      F1(E, A, B, C, D, W[11]);
      F1(D, E, A, B, C, W[12]);
      F1(C, D, E, A, B, W[13]);
      F1(B, C, D, E, A, W[14]);
      F1(A, B, C, D, E, W[15]);
      F1(E, A, B, C, D, W[16]);
      F1(D, E, A, B, C, W[17]);
      F1(C, D, E, A, B, W[18]);
      F1(B, C, D, E, A, W[19]);

      F2(A, B, C, D, E, W[20]);
      F2(E, A, B, C, D, W[21]);
      F2(D, E, A, B, C, W[22]);
      F2(C, D, E, A, B, W[23]);
      F2(B, C, D, E, A, W[24]);
      F2(A, B, C, D, E, W[25]);
      F2(E, A, B, C, D, W[26]);
      F2(D, E, A, B, C, W[27]);
      F2(C, D, E, A, B, W[28]);
      F2(B, C, D, E, A, W[29]);
      F2(A, B, C, D, E, W[30]);
      F2(E, A, B, C, D, W[31]);
      F2(D, E, A, B, C, W[32]);
      F2(C, D, E, A, B, W[33]);
      F2(B, C, D, E, A, W[34]);
      F2(A, B, C, D, E, W[35]);
      F2(E, A, B, C, D, W[36]);
      F2(D, E, A, B, C, W[37]);
      F2(C, D, E, A, B, W[38]);
      F2(B, C, D, E, A, W[39]);

      F3(A, B, C, D, E, W[40]);
      F3(E, A, B, C, D, W[41]);
      F3(D, E, A, B, C, W[42]);
      F3(C, D, E, A, B, W[43]);
      F3(B, C, D, E, A, W[44]);
      F3(A, B, C, D, E, W[45]);
      F3(E, A, B, C, D, W[46]);
      F3(D, E, A, B, C, W[47]);
      F3(C, D, E, A, B, W[48]);
      F3(B, C, D, E, A, W[49]);
      F3(A, B, C, D, E, W[50]);
      F3(E, A, B, C, D, W[51]);
      F3(D, E, A, B, C, W[52]);
      F3(C, D, E, A, B, W[53]);
      F3(B, C, D, E, A, W[54]);
      F3(A, B, C, D, E, W[55]);
      F3(E, A, B, C, D, W[56]);
      F3(D, E, A, B, C, W[57]);
      F3(C, D, E, A, B, W[58]);
      F3(B, C, D, E, A, W[59]);

      F4(A, B, C, D, E, W[60]);
      F4(E, A, B, C, D, W[61]);
      F4(D, E, A, B, C, W[62]);
      F4(C, D, E, A, B, W[63]);
      F4(B, C, D, E, A, W[64]);
      F4(A, B, C, D, E, W[65]);
      F4(E, A, B, C, D, W[66]);
      F4(D, E, A, B, C, W[67]);
      F4(C, D, E, A, B, W[68]);
      F4(B, C, D, E, A, W[69]);
      F4(A, B, C, D, E, W[70]);
      F4(E, A, B, C, D, W[71]);
      F4(D, E, A, B, C, W[72]);
      F4(C, D, E, A, B, W[73]);
      F4(B, C, D, E, A, W[74]);
      F4(A, B, C, D, E, W[75]);
      F4(E, A, B, C, D, W[76]);
      F4(D, E, A, B, C, W[77]);
      F4(C, D, E, A, B, W[78]);
      F4(B, C, D, E, A, W[79]);

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
   if(CPUID::has_intel_sha()) {
      return "intel_sha";
   }
#endif

#if defined(BOTAN_HAS_SHA1_ARMV8)
   if(CPUID::has_arm_sha1()) {
      return "armv8_sha";
   }
#endif

#if defined(BOTAN_HAS_SHA1_SSE2)
   if(CPUID::has_sse2()) {
      return "sse2";
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
