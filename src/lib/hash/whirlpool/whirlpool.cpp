/*
* Whirlpool
* (C) 1999-2007,2020,2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/whirlpool.h>

#include <botan/compiler.h>
#include <botan/internal/bit_ops.h>
#include <botan/internal/buffer_slicer.h>
#include <botan/internal/loadstor.h>
#include <botan/internal/rotate.h>
#include <botan/internal/target_info.h>
#include <array>

#if defined(BOTAN_HAS_CPUID)
   #include <botan/internal/cpuid.h>
#endif

namespace Botan {

namespace {

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

#if defined(BOTAN_TARGET_ARCH_IS_ARM64) || defined(BOTAN_TARGET_ARCH_IS_X86_64) || defined(BOTAN_TARGET_ARCH_IS_PPC64)
constexpr bool WhirlpoolUnalignedTables = true;
#else
constexpr bool WhirlpoolUnalignedTables = false;
#endif

// Combined S-box + MDS diffusion table
consteval std::array<uint64_t, 256> whirlpool_T_table(const std::array<uint8_t, 256>& S) noexcept {
   // MDS circulant matrix first row: [1, 1, 4, 1, 8, 5, 2, 9] over GF(2^8)
   constexpr uint64_t MDS = 0x0101040108050209;

   std::array<uint64_t, 256> T = {};
   for(size_t i = 0; i != 256; ++i) {
      T[i] = poly_mul<0x1D>(MDS, S[i]);
   }
   return T;
}

constexpr size_t WHIRL_U_STRIDE = 2 * sizeof(uint64_t);

[[maybe_unused]] consteval std::array<uint8_t, 256 * WHIRL_U_STRIDE> whirlpool_U_table(
   const std::array<uint64_t, 256>& T) noexcept {
   // Duplicating each entry permits unaligned loads to perform the rotations
   std::array<uint8_t, 256 * WHIRL_U_STRIDE> U = {};

   for(size_t i = 0; i != 256; ++i) {
      for(size_t j = 0; j != sizeof(uint64_t); ++j) {
         U[WHIRL_U_STRIDE * i + j] = static_cast<uint8_t>(T[i] >> (8 * j));
         U[WHIRL_U_STRIDE * i + sizeof(uint64_t) + j] = static_cast<uint8_t>(T[i] >> (8 * j));
      }
   }
   return U;
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
constexpr auto WHIRL_RC = whirlpool_rc(WHIRL_S);

BOTAN_FORCE_INLINE uint64_t
whirl(uint64_t x0, uint64_t x1, uint64_t x2, uint64_t x3, uint64_t x4, uint64_t x5, uint64_t x6, uint64_t x7) {
   if constexpr(WhirlpoolUnalignedTables) {
      alignas(256) static constexpr auto WHIRL_U = whirlpool_U_table(whirlpool_T_table(WHIRL_S));

      const uint64_t s0 = load_le<uint64_t>(WHIRL_U.data() + WHIRL_U_STRIDE * get_byte<0>(x0), 0);
      const uint64_t s1 = load_le<uint64_t>(WHIRL_U.data() + WHIRL_U_STRIDE * get_byte<1>(x1) + 1, 0);
      const uint64_t s2 = load_le<uint64_t>(WHIRL_U.data() + WHIRL_U_STRIDE * get_byte<2>(x2) + 2, 0);
      const uint64_t s3 = load_le<uint64_t>(WHIRL_U.data() + WHIRL_U_STRIDE * get_byte<3>(x3) + 3, 0);
      const uint64_t s4 = load_le<uint64_t>(WHIRL_U.data() + WHIRL_U_STRIDE * get_byte<4>(x4) + 4, 0);
      const uint64_t s5 = load_le<uint64_t>(WHIRL_U.data() + WHIRL_U_STRIDE * get_byte<5>(x5) + 5, 0);
      const uint64_t s6 = load_le<uint64_t>(WHIRL_U.data() + WHIRL_U_STRIDE * get_byte<6>(x6) + 6, 0);
      const uint64_t s7 = load_le<uint64_t>(WHIRL_U.data() + WHIRL_U_STRIDE * get_byte<7>(x7) + 7, 0);

      return s0 ^ s1 ^ s2 ^ s3 ^ s4 ^ s5 ^ s6 ^ s7;
   } else {
      alignas(256) static constexpr auto WHIRL_T = whirlpool_T_table(WHIRL_S);

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
}

}  // namespace

std::string Whirlpool::provider() const {
#if defined(BOTAN_HAS_WHIRLPOOL_AVX512)
   if(auto feat = CPUID::check(CPUID::Feature::AVX512)) {
      return *feat;
   }
#endif

#if defined(BOTAN_HAS_WHIRLPOOL_SIMD8X32)
   if(auto feat = CPUID::check(CPUID::Feature::SIMD_8X32)) {
      return *feat;
   }
#endif

   return "base";
}

/*
* Whirlpool Compression Function
*/
void Whirlpool::compress_n(digest_type& digest, std::span<const uint8_t> input, size_t blocks) {
#if defined(BOTAN_HAS_WHIRLPOOL_AVX512)
   if(CPUID::has(CPUID::Feature::AVX512)) {
      return compress_n_avx512(digest, input, blocks);
   }
#endif

#if defined(BOTAN_HAS_WHIRLPOOL_SIMD8X32)
   if(CPUID::has(CPUID::Feature::SIMD_8X32)) {
      return compress_n_simd8x32(digest, input, blocks);
   }
#endif

   BufferSlicer in(input);

   for(size_t i = 0; i != blocks; ++i) {
      const auto block = in.take(block_bytes);

      uint64_t K[8];

      K[0] = digest[0];
      K[1] = digest[1];
      K[2] = digest[2];
      K[3] = digest[3];
      K[4] = digest[4];
      K[5] = digest[5];
      K[6] = digest[6];
      K[7] = digest[7];

      uint64_t M[8];
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

      for(size_t r = 0; r != 10; ++r) {
         const uint64_t K0 = whirl(K[0], K[7], K[6], K[5], K[4], K[3], K[2], K[1]) ^ WHIRL_RC[r];
         const uint64_t K1 = whirl(K[1], K[0], K[7], K[6], K[5], K[4], K[3], K[2]);
         const uint64_t K2 = whirl(K[2], K[1], K[0], K[7], K[6], K[5], K[4], K[3]);
         const uint64_t K3 = whirl(K[3], K[2], K[1], K[0], K[7], K[6], K[5], K[4]);
         const uint64_t K4 = whirl(K[4], K[3], K[2], K[1], K[0], K[7], K[6], K[5]);
         const uint64_t K5 = whirl(K[5], K[4], K[3], K[2], K[1], K[0], K[7], K[6]);
         const uint64_t K6 = whirl(K[6], K[5], K[4], K[3], K[2], K[1], K[0], K[7]);
         const uint64_t K7 = whirl(K[7], K[6], K[5], K[4], K[3], K[2], K[1], K[0]);

         const uint64_t T0 = whirl(B0, B7, B6, B5, B4, B3, B2, B1) ^ K0;
         const uint64_t T1 = whirl(B1, B0, B7, B6, B5, B4, B3, B2) ^ K1;
         const uint64_t T2 = whirl(B2, B1, B0, B7, B6, B5, B4, B3) ^ K2;
         const uint64_t T3 = whirl(B3, B2, B1, B0, B7, B6, B5, B4) ^ K3;
         const uint64_t T4 = whirl(B4, B3, B2, B1, B0, B7, B6, B5) ^ K4;
         const uint64_t T5 = whirl(B5, B4, B3, B2, B1, B0, B7, B6) ^ K5;
         const uint64_t T6 = whirl(B6, B5, B4, B3, B2, B1, B0, B7) ^ K6;
         const uint64_t T7 = whirl(B7, B6, B5, B4, B3, B2, B1, B0) ^ K7;

         K[0] = K0;
         K[1] = K1;
         K[2] = K2;
         K[3] = K3;
         K[4] = K4;
         K[5] = K5;
         K[6] = K6;
         K[7] = K7;

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
