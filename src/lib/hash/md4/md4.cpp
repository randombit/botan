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

   for(size_t i = 0; i != blocks; ++i) {
      const auto block = in.take(block_bytes).data();

      uint32_t M00 = load_le<uint32_t>(block, 0);
      uint32_t M01 = load_le<uint32_t>(block, 1);
      uint32_t M02 = load_le<uint32_t>(block, 2);
      uint32_t M03 = load_le<uint32_t>(block, 3);
      uint32_t M04 = load_le<uint32_t>(block, 4);
      uint32_t M05 = load_le<uint32_t>(block, 5);
      uint32_t M06 = load_le<uint32_t>(block, 6);
      uint32_t M07 = load_le<uint32_t>(block, 7);
      uint32_t M08 = load_le<uint32_t>(block, 8);
      uint32_t M09 = load_le<uint32_t>(block, 9);
      uint32_t M10 = load_le<uint32_t>(block, 10);
      uint32_t M11 = load_le<uint32_t>(block, 11);
      uint32_t M12 = load_le<uint32_t>(block, 12);
      uint32_t M13 = load_le<uint32_t>(block, 13);
      uint32_t M14 = load_le<uint32_t>(block, 14);
      uint32_t M15 = load_le<uint32_t>(block, 15);

      FF4(A, B, C, D, M00, M01, M02, M03);
      FF4(A, B, C, D, M04, M05, M06, M07);
      FF4(A, B, C, D, M08, M09, M10, M11);
      FF4(A, B, C, D, M12, M13, M14, M15);

      GG4(A, B, C, D, M00, M04, M08, M12);
      GG4(A, B, C, D, M01, M05, M09, M13);
      GG4(A, B, C, D, M02, M06, M10, M14);
      GG4(A, B, C, D, M03, M07, M11, M15);

      HH4(A, B, C, D, M00, M08, M04, M12);
      HH4(A, B, C, D, M02, M10, M06, M14);
      HH4(A, B, C, D, M01, M09, M05, M13);
      HH4(A, B, C, D, M03, M11, M07, M15);

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
