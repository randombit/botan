/*
* Streebog (GOST R 34.11-2012)
* (C) 2017 Ribose Inc.
* (C) 2018,2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/streebog.h>

#include <botan/exceptn.h>
#include <botan/internal/bswap.h>
#include <botan/internal/buffer_slicer.h>
#include <botan/internal/fmt.h>
#include <botan/internal/loadstor.h>
#include <array>
#include <bit>

namespace Botan {

namespace {

// GF(2^8) multiplication with polynomial x^8+x^4+x^3+x^2+1 (0x1D)
constexpr uint64_t streebog_poly_mul(uint64_t x, uint8_t y) {
   const uint64_t lo_bit = 0x0101010101010101;
   const uint64_t mask = 0x7F7F7F7F7F7F7F7F;
   const uint64_t poly = 0x1D;

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

// Build the combined T-tables at compile time
consteval std::array<std::array<uint64_t, 256>, 8> streebog_Ax_table() noexcept {
   // Streebog sbox (same as Kuznyechik's), RFC 6986 Section 6.2
   alignas(256) const constexpr uint8_t S[256] = {
      252, 238, 221, 17,  207, 110, 49,  22,  251, 196, 250, 218, 35,  197, 4,   77,  233, 119, 240, 219, 147, 46,
      153, 186, 23,  54,  241, 187, 20,  205, 95,  193, 249, 24,  101, 90,  226, 92,  239, 33,  129, 28,  60,  66,
      139, 1,   142, 79,  5,   132, 2,   174, 227, 106, 143, 160, 6,   11,  237, 152, 127, 212, 211, 31,  235, 52,
      44,  81,  234, 200, 72,  171, 242, 42,  104, 162, 253, 58,  206, 204, 181, 112, 14,  86,  8,   12,  118, 18,
      191, 114, 19,  71,  156, 183, 93,  135, 21,  161, 150, 41,  16,  123, 154, 199, 243, 145, 120, 111, 157, 158,
      178, 177, 50,  117, 25,  61,  255, 53,  138, 126, 109, 84,  198, 128, 195, 189, 13,  87,  223, 245, 36,  169,
      62,  168, 67,  201, 215, 121, 214, 246, 124, 34,  185, 3,   224, 15,  236, 222, 122, 148, 176, 188, 220, 232,
      40,  80,  78,  51,  10,  74,  167, 151, 96,  115, 30,  0,   98,  68,  26,  184, 56,  130, 100, 159, 38,  65,
      173, 69,  70,  146, 39,  94,  85,  47,  140, 163, 165, 125, 105, 213, 149, 59,  7,   88,  179, 64,  134, 172,
      29,  247, 48,  55,  107, 228, 136, 217, 231, 137, 225, 27,  131, 73,  76,  63,  248, 254, 141, 83,  170, 144,
      202, 216, 133, 97,  32,  113, 103, 164, 45,  43,  9,   91,  203, 155, 37,  208, 190, 229, 108, 82,  89,  166,
      116, 210, 230, 244, 180, 192, 209, 102, 175, 194, 57,  75,  99,  182,
   };

   // Columns of the 8x8 linear transformation matrix over GF(2^8)
   const constexpr uint64_t L[8] = {
      0x641c314b2b8ee083,
      0xa48b474f9ef5dc18,
      0xf97d86d98a327728,
      0x5b068c651810a89e,
      0x0321658cba93c138,
      0xaccc9ca9328a8950,
      0x46b60f011a83988e,
      0x83478b07b2468764,
   };

   std::array<std::array<uint64_t, 256>, 8> Ax = {};

   for(size_t j = 0; j != 8; ++j) {
      for(size_t x = 0; x != 256; ++x) {
         Ax[j][x] = streebog_poly_mul(L[j], S[x]);
      }
   }

   return Ax;
}

const constinit auto STREEBOG_Ax = streebog_Ax_table();

// Iteration constants C[1]..C[12] from GOST R 34.11-2012 (RFC 6986 Section 6.5)
// Word order matches the RFC (big-endian presentation); indexed with 7-j below
// clang-format off
const constexpr uint64_t STREEBOG_C[12][8] = {
   {0xb1085bda1ecadae9, 0xebcb2f81c0657c1f, 0x2f6a76432e45d016, 0x714eb88d7585c4fc,
    0x4b7ce09192676901, 0xa2422a08a460d315, 0x05767436cc744d23, 0xdd806559f2a64507},
   {0x6fa3b58aa99d2f1a, 0x4fe39d460f70b5d7, 0xf3feea720a232b98, 0x61d55e0f16b50131,
    0x9ab5176b12d69958, 0x5cb561c2db0aa7ca, 0x55dda21bd7cbcd56, 0xe679047021b19bb7},
   {0xf574dcac2bce2fc7, 0x0a39fc286a3d8435, 0x06f15e5f529c1f8b, 0xf2ea7514b1297b7b,
    0xd3e20fe490359eb1, 0xc1c93a376062db09, 0xc2b6f443867adb31, 0x991e96f50aba0ab2},
   {0xef1fdfb3e81566d2, 0xf948e1a05d71e4dd, 0x488e857e335c3c7d, 0x9d721cad685e353f,
    0xa9d72c82ed03d675, 0xd8b71333935203be, 0x3453eaa193e837f1, 0x220cbebc84e3d12e},
   {0x4bea6bacad474799, 0x9a3f410c6ca92363, 0x7f151c1f1686104a, 0x359e35d7800fffbd,
    0xbfcd1747253af5a3, 0xdfff00b723271a16, 0x7a56a27ea9ea63f5, 0x601758fd7c6cfe57},
   {0xae4faeae1d3ad3d9, 0x6fa4c33b7a3039c0, 0x2d66c4f95142a46c, 0x187f9ab49af08ec6,
    0xcffaa6b71c9ab7b4, 0x0af21f66c2bec6b6, 0xbf71c57236904f35, 0xfa68407a46647d6e},
   {0xf4c70e16eeaac5ec, 0x51ac86febf240954, 0x399ec6c7e6bf87c9, 0xd3473e33197a93c9,
    0x0992abc52d822c37, 0x06476983284a0504, 0x3517454ca23c4af3, 0x8886564d3a14d493},
   {0x9b1f5b424d93c9a7, 0x03e7aa020c6e4141, 0x4eb7f8719c36de1e, 0x89b4443b4ddbc49a,
    0xf4892bcb929b0690, 0x69d18d2bd1a5c42f, 0x36acc2355951a8d9, 0xa47f0dd4bf02e71e},
   {0x378f5a541631229b, 0x944c9ad8ec165fde, 0x3a7d3a1b25894224, 0x3cd955b7e00d0984,
    0x800a440bdbb2ceb1, 0x7b2b8a9aa6079c54, 0x0e38dc92cb1f2a60, 0x7261445183235adb},
   {0xabbedea680056f52, 0x382ae548b2e4f3f3, 0x8941e71cff8a78db, 0x1fffe18a1b336103,
    0x9fe76702af69334b, 0x7a1e6c303b7652f4, 0x3698fad1153bb6c3, 0x74b4c7fb98459ced},
   {0x7bcd9ed0efc889fb, 0x3002c6cd635afe94, 0xd8fa6bbbebab0761, 0x2001802114846679,
    0x8a1d71efea48b9ca, 0xefbacd1d7d476e98, 0xdea2594ac06fd85d, 0x6bcaa4cd81f32d1b},
   {0x378ee767f11631ba, 0xd21380b00449b17a, 0xcda43c32bcdf1d77, 0xf82012d430219f9b,
    0x5d80ef9d1891cc86, 0xe71da4aa88e12852, 0xfaf417d5d9b21b99, 0x48bc924af11bd720},
};

// clang-format on

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
   // FIXME
   std::memcpy(output.data(), &m_h[8 - output_length() / 8], output_length());
   clear();
}

void Streebog::compress(const uint8_t input[], bool last_block) {
   uint64_t M[8];
   std::memcpy(M, input, 64);

   compress_64(M, last_block);
}

void Streebog::compress_64(const uint64_t M[], bool last_block) {
   const uint64_t N = last_block ? 0 : force_le(m_count);

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
      lps(A);

      lps(hN);
      for(size_t j = 0; j != 8; ++j) {
         hN[j] ^= A[j];
      }
   }

   for(size_t i = 0; i != 8; ++i) {
      m_h[i] ^= hN[i] ^ M[i];
   }

   if(!last_block) {
      uint64_t carry = 0;
      for(int i = 0; i < 8; i++) {
         const uint64_t m = force_le(M[i]);
         const uint64_t hi = force_le(m_S[i]);
         const uint64_t t = hi + m + carry;

         m_S[i] = force_le(t);
         if(t != m) {
            carry = (t < m) ? 1 : 0;
         }
      }
   }
}

}  // namespace Botan
