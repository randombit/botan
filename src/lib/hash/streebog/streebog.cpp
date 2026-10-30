/*
* Streebog (GOST R 34.11-2012)
* (C) 2017 Ribose Inc.
* (C) 2018,2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/streebog.h>

#include <botan/exceptn.h>
#include <botan/internal/bit_ops.h>
#include <botan/internal/bswap.h>
#include <botan/internal/buffer_slicer.h>
#include <botan/internal/fmt.h>
#include <botan/internal/loadstor.h>
#include <botan/internal/streebog_const.h>
#include <array>
#include <bit>

#if defined(BOTAN_HAS_CPUID)
   #include <botan/internal/cpuid.h>
#endif

namespace Botan {

namespace {

// Build the combined T-tables at compile time
consteval std::array<std::array<uint64_t, 256>, 8> streebog_Ax_table() noexcept {
   std::array<std::array<uint64_t, 256>, 8> Ax = {};

   for(size_t j = 0; j != 8; ++j) {
      for(size_t x = 0; x != 256; ++x) {
         Ax[j][x] = poly_mul<0x1D>(STREEBOG_L[j], STREEBOG_S[x]);
      }
   }

   return Ax;
}

const constinit auto STREEBOG_Ax = streebog_Ax_table();

inline uint64_t force_le(uint64_t x) {
   if constexpr(std::endian::native == std::endian::little) {
      return x;
   } else if constexpr(std::endian::native == std::endian::big) {
      return reverse_bytes(x);
   } else {
      store_le(x, reinterpret_cast<uint8_t*>(&x));
      return x;
   }
}

inline void lps(uint64_t block[8]) {
   const uint64_t block2[8] = {block[0], block[1], block[2], block[3], block[4], block[5], block[6], block[7]};
   const std::span<const uint8_t> r{reinterpret_cast<const uint8_t*>(block2), 64};

   for(int i = 0; i < 8; ++i) {
      block[i] = force_le(STREEBOG_Ax[0][r[i + 0 * 8]]) ^ force_le(STREEBOG_Ax[1][r[i + 1 * 8]]) ^
                 force_le(STREEBOG_Ax[2][r[i + 2 * 8]]) ^ force_le(STREEBOG_Ax[3][r[i + 3 * 8]]) ^
                 force_le(STREEBOG_Ax[4][r[i + 4 * 8]]) ^ force_le(STREEBOG_Ax[5][r[i + 5 * 8]]) ^
                 force_le(STREEBOG_Ax[6][r[i + 6 * 8]]) ^ force_le(STREEBOG_Ax[7][r[i + 7 * 8]]);
   }
}

#if defined(BOTAN_TARGET_ARCH_IS_ARM64) && \
   (defined(BOTAN_BUILD_COMPILER_IS_CLANG) || defined(BOTAN_BUILD_COMPILER_IS_XCODE))
// Apply two independent LPS transformations together. This exposes the table
// lookups from both states to the compiler, improving instruction scheduling in
// the compression loop where A and hN are transformed back-to-back. This
// formulation regresses performance on x86_64 and with GCC on ARM64.
inline void lps2(uint64_t block_a[8], uint64_t block_b[8]) {
   const uint64_t block2_a[8] = {
      block_a[0], block_a[1], block_a[2], block_a[3], block_a[4], block_a[5], block_a[6], block_a[7]};
   const uint64_t block2_b[8] = {
      block_b[0], block_b[1], block_b[2], block_b[3], block_b[4], block_b[5], block_b[6], block_b[7]};

   const std::span<const uint8_t> a{reinterpret_cast<const uint8_t*>(block2_a), 64};
   const std::span<const uint8_t> b{reinterpret_cast<const uint8_t*>(block2_b), 64};

   uint64_t acc_a[8];
   uint64_t acc_b[8];

   for(int i = 0; i < 8; ++i) {
      acc_a[i] = force_le(STREEBOG_Ax[0][a[i]]);
      acc_b[i] = force_le(STREEBOG_Ax[0][b[i]]);
   }

   for(int k = 1; k < 8; ++k) {
      for(int i = 0; i < 8; ++i) {
         acc_a[i] ^= force_le(STREEBOG_Ax[k][a[i + k * 8]]);
         acc_b[i] ^= force_le(STREEBOG_Ax[k][b[i + k * 8]]);
      }
   }

   for(int i = 0; i < 8; ++i) {
      block_a[i] = acc_a[i];
      block_b[i] = acc_b[i];
   }
}
#endif

}  //namespace

std::unique_ptr<HashFunction> Streebog::copy_state() const {
   return std::make_unique<Streebog>(*this);
}

Streebog::Streebog(size_t output_bits) : m_output_bits(output_bits), m_count(0), m_h(8), m_S(8) {
   if(output_bits != 256 && output_bits != 512) {
      throw Invalid_Argument(fmt("Streebog: Invalid output length {}", output_bits));
   }

   clear();
}

std::string Streebog::name() const {
   return fmt("Streebog-{}", m_output_bits);
}

std::string Streebog::provider() const {
#if defined(BOTAN_HAS_STREEBOG_AVX512_GFNI)
   if(auto feat = CPUID::check(CPUID::Feature::AVX512, CPUID::Feature::GFNI)) {
      return *feat;
   }
#endif

   return "base";
}

/*
* Clear memory of sensitive data
*/
void Streebog::clear() {
   m_count = 0;
   m_buffer.clear();
   zeroise(m_S);

   const uint64_t fill = (m_output_bits == 512) ? 0 : 0x0101010101010101;
   std::fill(m_h.begin(), m_h.end(), fill);
}

/*
* Update the hash
*/
void Streebog::add_data(std::span<const uint8_t> input) {
   BufferSlicer in(input);

   while(!in.empty()) {
      if(const auto one_block = m_buffer.handle_unaligned_data(in)) {
         compress(one_block->data());
         m_count += 512;
      }

      if(m_buffer.in_alignment()) {
         while(const auto aligned_block = m_buffer.next_aligned_block_to_process(in)) {
            compress(aligned_block->data());
            m_count += 512;
         }
      }
   }
}

/*
* Finalize a hash
*/
void Streebog::final_result(std::span<uint8_t> output) {
   const auto pos = m_buffer.elements_in_buffer();

   const uint8_t padding = 0x01;
   m_buffer.append({&padding, 1});
   m_buffer.fill_up_with_zeros();

   compress(m_buffer.consume().data());
   m_count += pos * 8;

   m_buffer.fill_up_with_zeros();
   store_le(m_count, m_buffer.directly_modify_first(sizeof(m_count)).data());
   compress(m_buffer.consume().data(), true);

   compress_64(m_S.data(), true);

   const size_t offset = 8 - output_length() / 8;
   const size_t count = output_length() / sizeof(uint64_t);
   typecast_copy(output, std::span<const uint64_t>(&m_h[offset], count));
   clear();
}

void Streebog::compress(const uint8_t input[], bool last_block) {
   uint64_t M[8];
   typecast_copy(M, std::span<const uint8_t>(input, 64));
   compress_64(M, last_block);
}

namespace {

void increment_s(bool last_block, const uint64_t M[8], uint64_t S[8]) {
   if(!last_block) {
      uint64_t carry = 0;
      for(int i = 0; i < 8; i++) {
         const uint64_t m = force_le(M[i]);
         const uint64_t hi = force_le(S[i]);
         const uint64_t t = hi + m + carry;

         S[i] = force_le(t);
         if(t != m) {
            carry = (t < m) ? 1 : 0;
         }
      }
   }
}

}  // namespace

void Streebog::compress_64(const uint64_t M[], bool last_block) {
   const uint64_t N = last_block ? 0 : force_le(m_count);

#if defined(BOTAN_HAS_STREEBOG_AVX512_GFNI)
   if(CPUID::has(CPUID::Feature::AVX512, CPUID::Feature::GFNI)) {
      compress_64_avx512_gfni(m_h.data(), M, N);
      increment_s(last_block, M, m_S.data());
      return;
   }
#endif

   uint64_t hN[8];
   uint64_t A[8];

   copy_mem(hN, m_h.data(), 8);
   hN[0] ^= N;
   lps(hN);

   copy_mem(A, hN, 8);

   for(size_t i = 0; i != 8; ++i) {
      hN[i] ^= M[i];
   }

   for(size_t i = 0; i < 12; ++i) {  // NOLINT(modernize-loop-convert)
      for(size_t j = 0; j != 8; ++j) {
         A[j] ^= force_le(STREEBOG_C[i][7 - j]);
      }
#if defined(BOTAN_TARGET_ARCH_IS_ARM64) && \
   (defined(BOTAN_BUILD_COMPILER_IS_CLANG) || defined(BOTAN_BUILD_COMPILER_IS_XCODE))
      lps2(A, hN);
#else
      lps(A);
      lps(hN);
#endif
      for(size_t j = 0; j != 8; ++j) {
         hN[j] ^= A[j];
      }
   }

   for(size_t i = 0; i != 8; ++i) {
      m_h[i] ^= hN[i] ^ M[i];
   }

   increment_s(last_block, M, m_S.data());
}

}  // namespace Botan
