/*
* MD4
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/md4.h>

#include <botan/internal/bit_ops.h>
#include <botan/internal/loadstor.h>
#include <botan/internal/rotate.h>

namespace Botan {

namespace {

inline void FF4(uint32_t& A, uint32_t& B, uint32_t& C, uint32_t& D, uint32_t M0, uint32_t M1, uint32_t M2, uint32_t M3)

{
   A += choose(B, C, D) + M0;
   A = rotl<3>(A);

   D += choose(A, B, C) + M1;
   D = rotl<7>(D);

   C += choose(D, A, B) + M2;
   C = rotl<11>(C);

   B += choose(C, D, A) + M3;
   B = rotl<19>(B);
}

inline void GG4(uint32_t& A, uint32_t& B, uint32_t& C, uint32_t& D, uint32_t M0, uint32_t M1, uint32_t M2, uint32_t M3)

{
   /*
   These are choose(D, B | C, B & C) but the below expression
   takes advantage of the fact that B & C is a subset of B | C
   to eliminate an and
   */

   A += ((B & C) | (D & (B | C))) + M0 + 0x5A827999;
   A = rotl<3>(A);

   D += ((A & B) | (C & (A | B))) + M1 + 0x5A827999;
   D = rotl<5>(D);

   C += ((D & A) | (B & (D | A))) + M2 + 0x5A827999;
   C = rotl<9>(C);

   B += ((C & D) | (A & (C | D))) + M3 + 0x5A827999;
   B = rotl<13>(B);
}

inline void HH4(uint32_t& A, uint32_t& B, uint32_t& C, uint32_t& D, uint32_t M0, uint32_t M1, uint32_t M2, uint32_t M3)

{
   A += (B ^ C ^ D) + M0 + 0x6ED9EBA1;
   A = rotl<3>(A);

   D += (A ^ B ^ C) + M1 + 0x6ED9EBA1;
   D = rotl<9>(D);

   C += (A ^ B ^ D) + M2 + 0x6ED9EBA1;
   C = rotl<11>(C);

   B += (A ^ C ^ D) + M3 + 0x6ED9EBA1;
   B = rotl<15>(B);
}

}  // namespace

/*
* MD4 Compression Function
*/
void MD4::compress_n(digest_type& digest, std::span<const uint8_t> input, size_t blocks) {
   uint32_t A = digest[0], B = digest[1], C = digest[2], D = digest[3];

   BufferSlicer in(input);

   std::array<uint32_t, 16> M;

   for(size_t i = 0; i != blocks; ++i) {
      load_le(M, in.take<block_bytes>());

      // clang-format off

      FF4(A, B, C, D, M[ 0], M[ 1], M[ 2], M[ 3]);
      FF4(A, B, C, D, M[ 4], M[ 5], M[ 6], M[ 7]);
      FF4(A, B, C, D, M[ 8], M[ 9], M[10], M[11]);
      FF4(A, B, C, D, M[12], M[13], M[14], M[15]);

      GG4(A, B, C, D, M[ 0], M[ 4], M[ 8], M[12]);
      GG4(A, B, C, D, M[ 1], M[ 5], M[ 9], M[13]);
      GG4(A, B, C, D, M[ 2], M[ 6], M[10], M[14]);
      GG4(A, B, C, D, M[ 3], M[ 7], M[11], M[15]);

      HH4(A, B, C, D, M[ 0], M[ 8], M[ 4], M[12]);
      HH4(A, B, C, D, M[ 2], M[10], M[ 6], M[14]);
      HH4(A, B, C, D, M[ 1], M[ 9], M[ 5], M[13]);
      HH4(A, B, C, D, M[ 3], M[11], M[ 7], M[15]);

      // clang-format on

      A = (digest[0] += A);
      B = (digest[1] += B);
      C = (digest[2] += C);
      D = (digest[3] += D);
   }

   BOTAN_ASSERT_NOMSG(in.empty());
}

void MD4::init(digest_type& digest) {
   digest.assign({0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476});
}

std::unique_ptr<HashFunction> MD4::new_object() const {
   return std::make_unique<MD4>();
}

std::unique_ptr<HashFunction> MD4::copy_state() const {
   return std::make_unique<MD4>(*this);
}

void MD4::add_data(std::span<const uint8_t> input) {
   m_md.update(input);
}

void MD4::final_result(std::span<uint8_t> output) {
   m_md.final(output);
}

}  // namespace Botan
