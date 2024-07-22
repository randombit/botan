/*
* SM3
* (C) 2017 Ribose Inc.
* (C) 2021 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/sm3.h>

#include <botan/internal/bit_ops.h>
#include <botan/internal/loadstor.h>
#include <botan/internal/rotate.h>
#include <botan/internal/stl_util.h>

namespace Botan {

namespace {

inline uint32_t P0(uint32_t X) {
   return X ^ rotl<9>(X) ^ rotl<17>(X);
}

inline void R1(uint32_t A,
               uint32_t& B,
               uint32_t C,
               uint32_t& D,
               uint32_t E,
               uint32_t& F,
               uint32_t G,
               uint32_t& H,
               uint32_t TJ,
               uint32_t Wi,
               uint32_t Wj) {
   const uint32_t A12 = rotl<12>(A);
   const uint32_t SS1 = rotl<7>(A12 + E + TJ);
   const uint32_t TT1 = (A ^ B ^ C) + D + (SS1 ^ A12) + Wj;
   const uint32_t TT2 = (E ^ F ^ G) + H + SS1 + Wi;

   B = rotl<9>(B);
   D = TT1;
   F = rotl<19>(F);
   H = P0(TT2);
}

inline void R2(uint32_t A,
               uint32_t& B,
               uint32_t C,
               uint32_t& D,
               uint32_t E,
               uint32_t& F,
               uint32_t G,
               uint32_t& H,
               uint32_t TJ,
               uint32_t Wi,
               uint32_t Wj) {
   const uint32_t A12 = rotl<12>(A);
   const uint32_t SS1 = rotl<7>(A12 + E + TJ);
   const uint32_t TT1 = majority(A, B, C) + D + (SS1 ^ A12) + Wj;
   const uint32_t TT2 = choose(E, F, G) + H + SS1 + Wi;

   B = rotl<9>(B);
   D = TT1;
   F = rotl<19>(F);
   H = P0(TT2);
}

inline uint32_t P1(uint32_t X) {
   return X ^ rotl<15>(X) ^ rotl<23>(X);
}

inline uint32_t SM3_E(uint32_t W0, uint32_t W7, uint32_t W13, uint32_t W3, uint32_t W10) {
   return P1(W0 ^ W7 ^ rotl<15>(W13)) ^ rotl<7>(W3) ^ W10;
}

}  // namespace

/*
* SM3 Compression Function
*/
void SM3::compress_n(digest_type& digest, std::span<const uint8_t> input, size_t blocks) {
   uint32_t A = digest[0], B = digest[1], C = digest[2], D = digest[3], E = digest[4], F = digest[5], G = digest[6],
            H = digest[7];
   std::array<uint32_t, 16> W;

   BufferSlicer in(input);

   for(size_t i = 0; i != blocks; ++i) {
      load_be(W, in.take<block_bytes>());

      // clang-format off

      R1(A, B, C, D, E, F, G, H, 0x79CC4519, W[ 0], W[ 0] ^ W[ 4]);
      W[ 0] = SM3_E(W[ 0], W[ 7], W[13], W[ 3], W[10]);
      R1(D, A, B, C, H, E, F, G, 0xF3988A32, W[ 1], W[ 1] ^ W[ 5]);
      W[ 1] = SM3_E(W[ 1], W[ 8], W[14], W[ 4], W[11]);
      R1(C, D, A, B, G, H, E, F, 0xE7311465, W[ 2], W[ 2] ^ W[ 6]);
      W[ 2] = SM3_E(W[ 2], W[ 9], W[15], W[ 5], W[12]);
      R1(B, C, D, A, F, G, H, E, 0xCE6228CB, W[ 3], W[ 3] ^ W[ 7]);
      W[ 3] = SM3_E(W[ 3], W[10], W[ 0], W[ 6], W[13]);
      R1(A, B, C, D, E, F, G, H, 0x9CC45197, W[ 4], W[ 4] ^ W[ 8]);
      W[ 4] = SM3_E(W[ 4], W[11], W[ 1], W[ 7], W[14]);
      R1(D, A, B, C, H, E, F, G, 0x3988A32F, W[ 5], W[ 5] ^ W[ 9]);
      W[ 5] = SM3_E(W[ 5], W[12], W[ 2], W[ 8], W[15]);
      R1(C, D, A, B, G, H, E, F, 0x7311465E, W[ 6], W[ 6] ^ W[10]);
      W[ 6] = SM3_E(W[ 6], W[13], W[ 3], W[ 9], W[ 0]);
      R1(B, C, D, A, F, G, H, E, 0xE6228CBC, W[ 7], W[ 7] ^ W[11]);
      W[ 7] = SM3_E(W[ 7], W[14], W[ 4], W[10], W[ 1]);
      R1(A, B, C, D, E, F, G, H, 0xCC451979, W[ 8], W[ 8] ^ W[12]);
      W[ 8] = SM3_E(W[ 8], W[15], W[ 5], W[11], W[ 2]);
      R1(D, A, B, C, H, E, F, G, 0x988A32F3, W[ 9], W[ 9] ^ W[13]);
      W[ 9] = SM3_E(W[ 9], W[ 0], W[ 6], W[12], W[ 3]);
      R1(C, D, A, B, G, H, E, F, 0x311465E7, W[10], W[10] ^ W[14]);
      W[10] = SM3_E(W[10], W[ 1], W[ 7], W[13], W[ 4]);
      R1(B, C, D, A, F, G, H, E, 0x6228CBCE, W[11], W[11] ^ W[15]);
      W[11] = SM3_E(W[11], W[ 2], W[ 8], W[14], W[ 5]);
      R1(A, B, C, D, E, F, G, H, 0xC451979C, W[12], W[12] ^ W[ 0]);
      W[12] = SM3_E(W[12], W[ 3], W[ 9], W[15], W[ 6]);
      R1(D, A, B, C, H, E, F, G, 0x88A32F39, W[13], W[13] ^ W[ 1]);
      W[13] = SM3_E(W[13], W[ 4], W[10], W[ 0], W[ 7]);
      R1(C, D, A, B, G, H, E, F, 0x11465E73, W[14], W[14] ^ W[ 2]);
      W[14] = SM3_E(W[14], W[ 5], W[11], W[ 1], W[ 8]);
      R1(B, C, D, A, F, G, H, E, 0x228CBCE6, W[15], W[15] ^ W[ 3]);
      W[15] = SM3_E(W[15], W[ 6], W[12], W[ 2], W[ 9]);
      R2(A, B, C, D, E, F, G, H, 0x9D8A7A87, W[ 0], W[ 0] ^ W[ 4]);
      W[ 0] = SM3_E(W[ 0], W[ 7], W[13], W[ 3], W[10]);
      R2(D, A, B, C, H, E, F, G, 0x3B14F50F, W[ 1], W[ 1] ^ W[ 5]);
      W[ 1] = SM3_E(W[ 1], W[ 8], W[14], W[ 4], W[11]);
      R2(C, D, A, B, G, H, E, F, 0x7629EA1E, W[ 2], W[ 2] ^ W[ 6]);
      W[ 2] = SM3_E(W[ 2], W[ 9], W[15], W[ 5], W[12]);
      R2(B, C, D, A, F, G, H, E, 0xEC53D43C, W[ 3], W[ 3] ^ W[ 7]);
      W[ 3] = SM3_E(W[ 3], W[10], W[ 0], W[ 6], W[13]);
      R2(A, B, C, D, E, F, G, H, 0xD8A7A879, W[ 4], W[ 4] ^ W[ 8]);
      W[ 4] = SM3_E(W[ 4], W[11], W[ 1], W[ 7], W[14]);
      R2(D, A, B, C, H, E, F, G, 0xB14F50F3, W[ 5], W[ 5] ^ W[ 9]);
      W[ 5] = SM3_E(W[ 5], W[12], W[ 2], W[ 8], W[15]);
      R2(C, D, A, B, G, H, E, F, 0x629EA1E7, W[ 6], W[ 6] ^ W[10]);
      W[ 6] = SM3_E(W[ 6], W[13], W[ 3], W[ 9], W[ 0]);
      R2(B, C, D, A, F, G, H, E, 0xC53D43CE, W[ 7], W[ 7] ^ W[11]);
      W[ 7] = SM3_E(W[ 7], W[14], W[ 4], W[10], W[ 1]);
      R2(A, B, C, D, E, F, G, H, 0x8A7A879D, W[ 8], W[ 8] ^ W[12]);
      W[ 8] = SM3_E(W[ 8], W[15], W[ 5], W[11], W[ 2]);
      R2(D, A, B, C, H, E, F, G, 0x14F50F3B, W[ 9], W[ 9] ^ W[13]);
      W[ 9] = SM3_E(W[ 9], W[ 0], W[ 6], W[12], W[ 3]);
      R2(C, D, A, B, G, H, E, F, 0x29EA1E76, W[10], W[10] ^ W[14]);
      W[10] = SM3_E(W[10], W[ 1], W[ 7], W[13], W[ 4]);
      R2(B, C, D, A, F, G, H, E, 0x53D43CEC, W[11], W[11] ^ W[15]);
      W[11] = SM3_E(W[11], W[ 2], W[ 8], W[14], W[ 5]);
      R2(A, B, C, D, E, F, G, H, 0xA7A879D8, W[12], W[12] ^ W[ 0]);
      W[12] = SM3_E(W[12], W[ 3], W[ 9], W[15], W[ 6]);
      R2(D, A, B, C, H, E, F, G, 0x4F50F3B1, W[13], W[13] ^ W[ 1]);
      W[13] = SM3_E(W[13], W[ 4], W[10], W[ 0], W[ 7]);
      R2(C, D, A, B, G, H, E, F, 0x9EA1E762, W[14], W[14] ^ W[ 2]);
      W[14] = SM3_E(W[14], W[ 5], W[11], W[ 1], W[ 8]);
      R2(B, C, D, A, F, G, H, E, 0x3D43CEC5, W[15], W[15] ^ W[ 3]);
      W[15] = SM3_E(W[15], W[ 6], W[12], W[ 2], W[ 9]);
      R2(A, B, C, D, E, F, G, H, 0x7A879D8A, W[ 0], W[ 0] ^ W[ 4]);
      W[ 0] = SM3_E(W[ 0], W[ 7], W[13], W[ 3], W[10]);
      R2(D, A, B, C, H, E, F, G, 0xF50F3B14, W[ 1], W[ 1] ^ W[ 5]);
      W[ 1] = SM3_E(W[ 1], W[ 8], W[14], W[ 4], W[11]);
      R2(C, D, A, B, G, H, E, F, 0xEA1E7629, W[ 2], W[ 2] ^ W[ 6]);
      W[ 2] = SM3_E(W[ 2], W[ 9], W[15], W[ 5], W[12]);
      R2(B, C, D, A, F, G, H, E, 0xD43CEC53, W[ 3], W[ 3] ^ W[ 7]);
      W[ 3] = SM3_E(W[ 3], W[10], W[ 0], W[ 6], W[13]);
      R2(A, B, C, D, E, F, G, H, 0xA879D8A7, W[ 4], W[ 4] ^ W[ 8]);
      W[ 4] = SM3_E(W[ 4], W[11], W[ 1], W[ 7], W[14]);
      R2(D, A, B, C, H, E, F, G, 0x50F3B14F, W[ 5], W[ 5] ^ W[ 9]);
      W[ 5] = SM3_E(W[ 5], W[12], W[ 2], W[ 8], W[15]);
      R2(C, D, A, B, G, H, E, F, 0xA1E7629E, W[ 6], W[ 6] ^ W[10]);
      W[ 6] = SM3_E(W[ 6], W[13], W[ 3], W[ 9], W[ 0]);
      R2(B, C, D, A, F, G, H, E, 0x43CEC53D, W[ 7], W[ 7] ^ W[11]);
      W[ 7] = SM3_E(W[ 7], W[14], W[ 4], W[10], W[ 1]);
      R2(A, B, C, D, E, F, G, H, 0x879D8A7A, W[ 8], W[ 8] ^ W[12]);
      W[ 8] = SM3_E(W[ 8], W[15], W[ 5], W[11], W[ 2]);
      R2(D, A, B, C, H, E, F, G, 0x0F3B14F5, W[ 9], W[ 9] ^ W[13]);
      W[ 9] = SM3_E(W[ 9], W[ 0], W[ 6], W[12], W[ 3]);
      R2(C, D, A, B, G, H, E, F, 0x1E7629EA, W[10], W[10] ^ W[14]);
      W[10] = SM3_E(W[10], W[ 1], W[ 7], W[13], W[ 4]);
      R2(B, C, D, A, F, G, H, E, 0x3CEC53D4, W[11], W[11] ^ W[15]);
      W[11] = SM3_E(W[11], W[ 2], W[ 8], W[14], W[ 5]);
      R2(A, B, C, D, E, F, G, H, 0x79D8A7A8, W[12], W[12] ^ W[ 0]);
      W[12] = SM3_E(W[12], W[ 3], W[ 9], W[15], W[ 6]);
      R2(D, A, B, C, H, E, F, G, 0xF3B14F50, W[13], W[13] ^ W[ 1]);
      W[13] = SM3_E(W[13], W[ 4], W[10], W[ 0], W[ 7]);
      R2(C, D, A, B, G, H, E, F, 0xE7629EA1, W[14], W[14] ^ W[ 2]);
      W[14] = SM3_E(W[14], W[ 5], W[11], W[ 1], W[ 8]);
      R2(B, C, D, A, F, G, H, E, 0xCEC53D43, W[15], W[15] ^ W[ 3]);
      W[15] = SM3_E(W[15], W[ 6], W[12], W[ 2], W[ 9]);
      R2(A, B, C, D, E, F, G, H, 0x9D8A7A87, W[ 0], W[ 0] ^ W[ 4]);
      W[ 0] = SM3_E(W[ 0], W[ 7], W[13], W[ 3], W[10]);
      R2(D, A, B, C, H, E, F, G, 0x3B14F50F, W[ 1], W[ 1] ^ W[ 5]);
      W[ 1] = SM3_E(W[ 1], W[ 8], W[14], W[ 4], W[11]);
      R2(C, D, A, B, G, H, E, F, 0x7629EA1E, W[ 2], W[ 2] ^ W[ 6]);
      W[ 2] = SM3_E(W[ 2], W[ 9], W[15], W[ 5], W[12]);
      R2(B, C, D, A, F, G, H, E, 0xEC53D43C, W[ 3], W[ 3] ^ W[ 7]);
      W[ 3] = SM3_E(W[ 3], W[10], W[ 0], W[ 6], W[13]);
      R2(A, B, C, D, E, F, G, H, 0xD8A7A879, W[ 4], W[ 4] ^ W[ 8]);
      R2(D, A, B, C, H, E, F, G, 0xB14F50F3, W[ 5], W[ 5] ^ W[ 9]);
      R2(C, D, A, B, G, H, E, F, 0x629EA1E7, W[ 6], W[ 6] ^ W[10]);
      R2(B, C, D, A, F, G, H, E, 0xC53D43CE, W[ 7], W[ 7] ^ W[11]);
      R2(A, B, C, D, E, F, G, H, 0x8A7A879D, W[ 8], W[ 8] ^ W[12]);
      R2(D, A, B, C, H, E, F, G, 0x14F50F3B, W[ 9], W[ 9] ^ W[13]);
      R2(C, D, A, B, G, H, E, F, 0x29EA1E76, W[10], W[10] ^ W[14]);
      R2(B, C, D, A, F, G, H, E, 0x53D43CEC, W[11], W[11] ^ W[15]);
      R2(A, B, C, D, E, F, G, H, 0xA7A879D8, W[12], W[12] ^ W[ 0]);
      R2(D, A, B, C, H, E, F, G, 0x4F50F3B1, W[13], W[13] ^ W[ 1]);
      R2(C, D, A, B, G, H, E, F, 0x9EA1E762, W[14], W[14] ^ W[ 2]);
      R2(B, C, D, A, F, G, H, E, 0x3D43CEC5, W[15], W[15] ^ W[ 3]);

      // clang-format on

      A = (digest[0] ^= A);
      B = (digest[1] ^= B);
      C = (digest[2] ^= C);
      D = (digest[3] ^= D);
      E = (digest[4] ^= E);
      F = (digest[5] ^= F);
      G = (digest[6] ^= G);
      H = (digest[7] ^= H);
   }
}

void SM3::init(digest_type& digest) {
   digest.assign(
      {0x7380166fUL, 0x4914b2b9UL, 0x172442d7UL, 0xda8a0600UL, 0xa96f30bcUL, 0x163138aaUL, 0xe38dee4dUL, 0xb0fb0e4eUL});
}

std::unique_ptr<HashFunction> SM3::new_object() const {
   return std::make_unique<SM3>();
}

std::unique_ptr<HashFunction> SM3::copy_state() const {
   return std::make_unique<SM3>(*this);
}

void SM3::add_data(std::span<const uint8_t> input) {
   m_md.update(input);
}

void SM3::final_result(std::span<uint8_t> output) {
   m_md.final(output);
}

}  // namespace Botan
