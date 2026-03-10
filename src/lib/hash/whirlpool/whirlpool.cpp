/*
* Whirlpool
* (C) 1999-2007,2020,2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/whirlpool.h>

#include <botan/internal/buffer_slicer.h>
#include <botan/internal/loadstor.h>
#include <botan/internal/rotate.h>
#include <array>

namespace Botan {

namespace {

// GF(2^8) multiplication with irreducible polynomial x^8 + x^4 + x^3 + x^2 + 1
constexpr uint64_t whirlpool_poly_mul(uint64_t x, uint8_t y) {
   constexpr uint64_t lo_bit = 0x0101010101010101;
   constexpr uint64_t mask = 0x7F7F7F7F7F7F7F7F;
   constexpr uint64_t poly = 0x1D;

   uint64_t r = 0;
   while(x > 0 && y > 0) {
      if((y & 1) != 0) {
         r ^= x;
      }
      x = ((x & mask) << 1) ^ (((x >> 7) & lo_bit) * poly);
      y >>= 1;
   }
   return r;
}

// Derive the 256-byte S-box from the Whirlpool E and R mini-boxes
consteval std::array<uint8_t, 256> whirlpool_sbox() noexcept {
   constexpr uint8_t Ebox[16] = {1, 11, 9, 12, 13, 6, 15, 3, 14, 8, 7, 4, 10, 2, 5, 0};
   constexpr uint8_t Rbox[16] = {7, 12, 11, 13, 14, 4, 9, 15, 6, 3, 8, 10, 2, 5, 1, 0};

   // Derive the inverse of the E table
   uint8_t Eibox[16] = {};
   for(size_t i = 0; i != 16; ++i) {
      Eibox[Ebox[i]] = static_cast<uint8_t>(i);
   }

   std::array<uint8_t, 256> S = {};
   for(size_t i = 0; i != 256; ++i) {
      const uint8_t L = Ebox[i >> 4];
      const uint8_t R = Eibox[i & 0x0F];
      const uint8_t T = Rbox[L ^ R];
      S[i] = static_cast<uint8_t>((Ebox[L ^ T] << 4) | Eibox[R ^ T]);
   }
   return S;
}

// Combined S-box + MDS diffusion table
consteval std::array<uint64_t, 256> whirlpool_T_table(const std::array<uint8_t, 256>& S) noexcept {
   // MDS circulant matrix first row: [1, 1, 4, 1, 8, 5, 2, 9] over GF(2^8)
   constexpr uint64_t MDS = 0x0101040108050209;

   std::array<uint64_t, 256> T = {};
   for(size_t i = 0; i != 256; ++i) {
      T[i] = whirlpool_poly_mul(MDS, S[i]);
   }
   return T;
}

// Round constants are from the first 64 elements of the sbox
consteval std::array<uint64_t, 10> whirlpool_rc(const std::array<uint8_t, 256>& S) noexcept {
   std::array<uint64_t, 10> RC = {};
   for(size_t r = 0; r != 10; ++r) {
      RC[r] = load_be<uint64_t>(S.data(), r);
   }
   return RC;
}

constexpr auto WHIRL_S = whirlpool_sbox();
alignas(256) constexpr auto WHIRL_T = whirlpool_T_table(WHIRL_S);
constexpr auto WHIRL_RC = whirlpool_rc(WHIRL_S);

uint64_t whirl(uint64_t x0, uint64_t x1, uint64_t x2, uint64_t x3, uint64_t x4, uint64_t x5, uint64_t x6, uint64_t x7) {
   const uint64_t s0 = WHIRL_T[get_byte<0>(x0)];
   const uint64_t s1 = WHIRL_T[get_byte<1>(x1)];
   const uint64_t s2 = WHIRL_T[get_byte<2>(x2)];
   const uint64_t s3 = WHIRL_T[get_byte<3>(x3)];
   const uint64_t s4 = WHIRL_T[get_byte<4>(x4)];
   const uint64_t s5 = WHIRL_T[get_byte<5>(x5)];
   const uint64_t s6 = WHIRL_T[get_byte<6>(x6)];
   const uint64_t s7 = WHIRL_T[get_byte<7>(x7)];

   return s0 ^ rotr<8>(s1) ^ rotr<16>(s2) ^ rotr<24>(s3) ^ rotr<32>(s4) ^ rotr<40>(s5) ^ rotr<48>(s6) ^ rotr<56>(s7);
}

}  // namespace

/*
* Whirlpool Compression Function
*/
void Whirlpool::compress_n(digest_type& digest, std::span<const uint8_t> input, size_t blocks) {
   BufferSlicer in(input);

   for(size_t i = 0; i != blocks; ++i) {
      const auto block = in.take(block_bytes);

      uint64_t K[11 * 8] = {0};

      K[0] = digest[0];
      K[1] = digest[1];
      K[2] = digest[2];
      K[3] = digest[3];
      K[4] = digest[4];
      K[5] = digest[5];
      K[6] = digest[6];
      K[7] = digest[7];

      // Whirlpool key schedule:
      for(size_t r = 1; r != 11; ++r) {
         const uint64_t PK0 = K[8 * (r - 1) + 0];
         const uint64_t PK1 = K[8 * (r - 1) + 1];
         const uint64_t PK2 = K[8 * (r - 1) + 2];
         const uint64_t PK3 = K[8 * (r - 1) + 3];
         const uint64_t PK4 = K[8 * (r - 1) + 4];
         const uint64_t PK5 = K[8 * (r - 1) + 5];
         const uint64_t PK6 = K[8 * (r - 1) + 6];
         const uint64_t PK7 = K[8 * (r - 1) + 7];

         K[8 * r + 0] = whirl(PK0, PK7, PK6, PK5, PK4, PK3, PK2, PK1) ^ WHIRL_RC[r - 1];
         K[8 * r + 1] = whirl(PK1, PK0, PK7, PK6, PK5, PK4, PK3, PK2);
         K[8 * r + 2] = whirl(PK2, PK1, PK0, PK7, PK6, PK5, PK4, PK3);
         K[8 * r + 3] = whirl(PK3, PK2, PK1, PK0, PK7, PK6, PK5, PK4);
         K[8 * r + 4] = whirl(PK4, PK3, PK2, PK1, PK0, PK7, PK6, PK5);
         K[8 * r + 5] = whirl(PK5, PK4, PK3, PK2, PK1, PK0, PK7, PK6);
         K[8 * r + 6] = whirl(PK6, PK5, PK4, PK3, PK2, PK1, PK0, PK7);
         K[8 * r + 7] = whirl(PK7, PK6, PK5, PK4, PK3, PK2, PK1, PK0);
      }

      uint64_t M[8] = {0};
      load_be(M, block.data(), 8);

      // First round (key masking)
      uint64_t B0 = M[0] ^ K[0];
      uint64_t B1 = M[1] ^ K[1];
      uint64_t B2 = M[2] ^ K[2];
      uint64_t B3 = M[3] ^ K[3];
      uint64_t B4 = M[4] ^ K[4];
      uint64_t B5 = M[5] ^ K[5];
      uint64_t B6 = M[6] ^ K[6];
      uint64_t B7 = M[7] ^ K[7];

      for(size_t r = 1; r != 11; ++r) {
         const uint64_t T0 = whirl(B0, B7, B6, B5, B4, B3, B2, B1) ^ K[8 * r + 0];
         const uint64_t T1 = whirl(B1, B0, B7, B6, B5, B4, B3, B2) ^ K[8 * r + 1];
         const uint64_t T2 = whirl(B2, B1, B0, B7, B6, B5, B4, B3) ^ K[8 * r + 2];
         const uint64_t T3 = whirl(B3, B2, B1, B0, B7, B6, B5, B4) ^ K[8 * r + 3];
         const uint64_t T4 = whirl(B4, B3, B2, B1, B0, B7, B6, B5) ^ K[8 * r + 4];
         const uint64_t T5 = whirl(B5, B4, B3, B2, B1, B0, B7, B6) ^ K[8 * r + 5];
         const uint64_t T6 = whirl(B6, B5, B4, B3, B2, B1, B0, B7) ^ K[8 * r + 6];
         const uint64_t T7 = whirl(B7, B6, B5, B4, B3, B2, B1, B0) ^ K[8 * r + 7];

         B0 = T0;
         B1 = T1;
         B2 = T2;
         B3 = T3;
         B4 = T4;
         B5 = T5;
         B6 = T6;
         B7 = T7;
      }

      digest[0] ^= B0 ^ M[0];
      digest[1] ^= B1 ^ M[1];
      digest[2] ^= B2 ^ M[2];
      digest[3] ^= B3 ^ M[3];
      digest[4] ^= B4 ^ M[4];
      digest[5] ^= B5 ^ M[5];
      digest[6] ^= B6 ^ M[6];
      digest[7] ^= B7 ^ M[7];
   }
}

void Whirlpool::init(digest_type& digest) {
   digest.resize(8);
   zeroise(digest);
}

std::unique_ptr<HashFunction> Whirlpool::new_object() const {
   return std::make_unique<Whirlpool>();
}

std::unique_ptr<HashFunction> Whirlpool::copy_state() const {
   return std::make_unique<Whirlpool>(*this);
}

void Whirlpool::add_data(std::span<const uint8_t> input) {
   m_md.update(input);
}

void Whirlpool::final_result(std::span<uint8_t> output) {
   m_md.final(output);
}

}  // namespace Botan
