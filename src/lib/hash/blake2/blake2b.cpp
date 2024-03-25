/*
* BLAKE2b
* (C) 2016 cynecx
* (C) 2017 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/blake2b.h>

#include <botan/exceptn.h>
#include <botan/mem_ops.h>
#include <botan/internal/fmt.h>
#include <botan/internal/loadstor.h>
#include <botan/internal/rotate.h>
#include <botan/internal/stl_util.h>

#include <algorithm>
#include <array>

namespace Botan {

namespace {

constexpr std::array<uint64_t, 8> blake2b_IV{0x6a09e667f3bcc908,
                                             0xbb67ae8584caa73b,
                                             0x3c6ef372fe94f82b,
                                             0xa54ff53a5f1d36f1,
                                             0x510e527fade682d1,
                                             0x9b05688c2b3e6c1f,
                                             0x1f83d9abfb41bd6b,
                                             0x5be0cd19137e2179};

}  // namespace

BLAKE2b::BLAKE2b(size_t output_bits) : m_output_bits(output_bits), m_H(blake2b_IV.size()), m_T(), m_F(), m_key_size(0) {
   if(output_bits == 0 || output_bits > 512 || output_bits % 8 != 0) {
      throw Invalid_Argument("Bad output bits size for BLAKE2b");
   }

   state_init();
}

void BLAKE2b::state_init() {
   copy_mem(m_H.data(), blake2b_IV.data(), blake2b_IV.size());
   m_H[0] ^= (0x01010000 | (static_cast<uint8_t>(m_key_size) << 8) | static_cast<uint8_t>(output_length()));
   m_T[0] = m_T[1] = 0;
   m_F = 0;

   m_buffer.clear();
   if(m_key_size > 0) {
      m_buffer.append(m_padded_key_buffer);
   }
}

namespace {

BOTAN_FORCE_INLINE void G(uint64_t& a, uint64_t& b, uint64_t& c, uint64_t& d, uint64_t M0, uint64_t M1) {
   a = a + b + M0;
   d = rotr<32>(d ^ a);
   c = c + d;
   b = rotr<24>(b ^ c);
   a = a + b + M1;
   d = rotr<16>(d ^ a);
   c = c + d;
   b = rotr<63>(b ^ c);
}

template <size_t i0,
          size_t i1,
          size_t i2,
          size_t i3,
          size_t i4,
          size_t i5,
          size_t i6,
          size_t i7,
          size_t i8,
          size_t i9,
          size_t iA,
          size_t iB,
          size_t iC,
          size_t iD,
          size_t iE,
          size_t iF>
BOTAN_FORCE_INLINE void ROUND(uint64_t* v, const uint64_t* M) {
   G(v[0], v[4], v[8], v[12], M[i0], M[i1]);
   G(v[1], v[5], v[9], v[13], M[i2], M[i3]);
   G(v[2], v[6], v[10], v[14], M[i4], M[i5]);
   G(v[3], v[7], v[11], v[15], M[i6], M[i7]);
   G(v[0], v[5], v[10], v[15], M[i8], M[i9]);
   G(v[1], v[6], v[11], v[12], M[iA], M[iB]);
   G(v[2], v[7], v[8], v[13], M[iC], M[iD]);
   G(v[3], v[4], v[9], v[14], M[iE], M[iF]);
}

}  // namespace

void BLAKE2b::compress(const uint8_t* input, size_t blocks, uint64_t increment) {
   for(size_t b = 0; b != blocks; ++b) {
      m_T[0] += increment;
      if(m_T[0] < increment) {
         m_T[1]++;
      }

      uint64_t M[16];
      uint64_t v[16];
      load_le(M, input, 16);

      input += BLAKE2B_BLOCKBYTES;

      for(size_t i = 0; i < 8; i++) {
         v[i] = m_H[i];
      }
      for(size_t i = 0; i != 8; ++i) {
         v[i + 8] = blake2b_IV[i];
      }

      v[12] ^= m_T[0];
      v[13] ^= m_T[1];
      v[14] ^= m_F;

      ROUND<0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15>(v, M);
      ROUND<14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3>(v, M);
      ROUND<11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4>(v, M);
      ROUND<7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8>(v, M);
      ROUND<9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13>(v, M);
      ROUND<2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9>(v, M);
      ROUND<12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11>(v, M);
      ROUND<13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10>(v, M);
      ROUND<6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5>(v, M);
      ROUND<10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0>(v, M);
      ROUND<0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15>(v, M);
      ROUND<14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3>(v, M);

      for(size_t i = 0; i < 8; i++) {
         m_H[i] ^= v[i] ^ v[i + 8];
      }
   }
}

void BLAKE2b::add_data(std::span<const uint8_t> input) {
   BufferSlicer in(input);

   while(!in.empty()) {
      if(const auto one_block = m_buffer.handle_unaligned_data(in)) {
         compress(one_block->data(), 1, BLAKE2B_BLOCKBYTES);
      }

      if(m_buffer.in_alignment()) {
         const auto [aligned_data, full_blocks] = m_buffer.aligned_data_to_process(in);
         if(full_blocks > 0) {
            compress(aligned_data.data(), full_blocks, BLAKE2B_BLOCKBYTES);
         }
      }
   }
}

void BLAKE2b::final_result(std::span<uint8_t> output) {
   const auto pos = m_buffer.elements_in_buffer();
   m_buffer.fill_up_with_zeros();

   m_F = 0xFFFFFFFFFFFFFFFF;
   compress(m_buffer.consume().data(), 1, pos);
   copy_out_le(output.first(output_length()), m_H);
   state_init();
}

Key_Length_Specification BLAKE2b::key_spec() const {
   return Key_Length_Specification(1, 64);
}

std::string BLAKE2b::name() const {
   return fmt("BLAKE2b({})", m_output_bits);
}

std::unique_ptr<HashFunction> BLAKE2b::new_object() const {
   return std::make_unique<BLAKE2b>(m_output_bits);
}

std::unique_ptr<HashFunction> BLAKE2b::copy_state() const {
   return std::make_unique<BLAKE2b>(*this);
}

bool BLAKE2b::has_keying_material() const {
   return m_key_size > 0;
}

void BLAKE2b::key_schedule(std::span<const uint8_t> key) {
   BOTAN_ASSERT_NOMSG(key.size() <= m_buffer.size());

   m_key_size = key.size();
   m_padded_key_buffer.resize(m_buffer.size());

   if(m_padded_key_buffer.size() > m_key_size) {
      size_t padding = m_padded_key_buffer.size() - m_key_size;
      clear_mem(m_padded_key_buffer.data() + m_key_size, padding);
   }

   copy_mem(m_padded_key_buffer.data(), key.data(), key.size());
   state_init();
}

void BLAKE2b::clear() {
   zeroise(m_H);
   m_buffer.clear();
   zeroise(m_padded_key_buffer);
   m_key_size = 0;
   state_init();
}

}  // namespace Botan
