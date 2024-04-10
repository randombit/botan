/*
* Streebog
* (C) 2017 Ribose Inc.
* (C) 2018 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/streebog.h>

#include <botan/exceptn.h>
#include <botan/internal/bswap.h>
#include <botan/internal/fmt.h>
#include <botan/internal/loadstor.h>
#include <botan/internal/stl_util.h>

namespace Botan {

extern const uint64_t STREEBOG_Ax[8][256];
extern const uint64_t STREEBOG_C[12][8];

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

namespace {

inline uint64_t force_le(uint64_t x) {
#if defined(BOTAN_TARGET_CPU_IS_LITTLE_ENDIAN)
   return x;
#elif defined(BOTAN_TARGET_CPU_IS_BIG_ENDIAN)
   return reverse_bytes(x);
#else
   store_le(x, reinterpret_cast<uint8_t*>(&x));
   return x;
#endif
}

inline void lps(uint64_t block[8]) {
   uint8_t r[64];
   // FIXME
   std::memcpy(r, block, 64);

   for(int i = 0; i < 8; ++i) {
      block[i] = force_le(STREEBOG_Ax[0][r[i + 0 * 8]]) ^ force_le(STREEBOG_Ax[1][r[i + 1 * 8]]) ^
                 force_le(STREEBOG_Ax[2][r[i + 2 * 8]]) ^ force_le(STREEBOG_Ax[3][r[i + 3 * 8]]) ^
                 force_le(STREEBOG_Ax[4][r[i + 4 * 8]]) ^ force_le(STREEBOG_Ax[5][r[i + 5 * 8]]) ^
                 force_le(STREEBOG_Ax[6][r[i + 6 * 8]]) ^ force_le(STREEBOG_Ax[7][r[i + 7 * 8]]);
   }
}

}  //namespace

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

   for(size_t i = 0; i < 12; ++i) {
      for(size_t j = 0; j != 8; ++j) {
         A[j] ^= force_le(STREEBOG_C[i][j]);
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
            carry = (t < m);
         }
      }
   }
}

}  // namespace Botan
