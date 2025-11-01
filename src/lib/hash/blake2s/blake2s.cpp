/*
 * BLAKE2s
 * (C) 2023, 2025       Richard Huveneers
 * (C) 2025             Kagan Can Sit
 * (C) 2025             René Meusel, Rohde & Schwarz Cybersecurity
 *
 * Based on the RFC7693 reference implementation
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#include <botan/internal/blake2s.h>

#include <botan/exceptn.h>
#include <botan/internal/fmt.h>
#include <botan/internal/loadstor.h>
#include <botan/internal/rotate.h>
#include <botan/internal/stl_util.h>

namespace Botan {

namespace {

// Initialization Vector.

constexpr std::array<uint32_t, 8> blake2s_iv{
   0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19};

// Mixing function G.

template <uint8_t a, uint8_t b, uint8_t c, uint8_t d>
   requires(a < 16 && b < 16 && c < 16 && d < 16)
constexpr void B2S_G(uint32_t x, uint32_t y, std::span<uint32_t, 16> v) {
   v[a] = v[a] + v[b] + x;
   v[d] = rotr<16>(v[d] ^ v[a]);
   v[c] = v[c] + v[d];
   v[b] = rotr<12>(v[b] ^ v[c]);
   v[a] = v[a] + v[b] + y;
   v[d] = rotr<8>(v[d] ^ v[a]);
   v[c] = v[c] + v[d];
   v[b] = rotr<7>(v[b] ^ v[c]);
}

}  // namespace

std::string BLAKE2s::name() const {
   return fmt("BLAKE2s({})", m_outlen << 3);
}

// BLAKE2s is specified as a message authentication code. For that, the
// key would need to be zero-padded and incorporated into the initial hash
// state. See RFC 7693 Section 3.3 and Appendix D.2 `blake2s_init()`.
void BLAKE2s::state_init(size_t outlen) {
   m_h = blake2s_iv;  // state, "param block"
   m_h[0] ^= 0x01010000 ^ outlen;

   m_bytes_processed = 0;
   m_outlen = outlen;
   m_buffer.clear();
}

// Compression function. "last" flag indicates last block.
void BLAKE2s::compress(bool last, std::span<const uint8_t> buf) {
   BOTAN_ASSERT_NOMSG(buf.size() == block_size);
   constexpr std::array<std::array<uint8_t, 16>, 10> sigma{{{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
                                                            {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
                                                            {11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4},
                                                            {7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
                                                            {9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13},
                                                            {2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
                                                            {12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11},
                                                            {13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
                                                            {6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5},
                                                            {10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0}}};

   // init work variables
   std::array<uint32_t, 16> v = concat(m_h, blake2s_iv);

   v[12] ^= static_cast<uint32_t>(m_bytes_processed);
   v[13] ^= static_cast<uint32_t>(m_bytes_processed >> 32);
   if(last) {  // last block flag set ?
      v[14] = ~v[14];
   }

   const auto m = load_le<std::array<uint32_t, 16>>(buf);  // get little-endian words

   for(const auto& perm : sigma) {  // ten rounds
      B2S_G<0, 4, 8, 12>(m[perm[0]], m[perm[1]], v);
      B2S_G<1, 5, 9, 13>(m[perm[2]], m[perm[3]], v);
      B2S_G<2, 6, 10, 14>(m[perm[4]], m[perm[5]], v);
      B2S_G<3, 7, 11, 15>(m[perm[6]], m[perm[7]], v);
      B2S_G<0, 5, 10, 15>(m[perm[8]], m[perm[9]], v);
      B2S_G<1, 6, 11, 12>(m[perm[10]], m[perm[11]], v);
      B2S_G<2, 7, 8, 13>(m[perm[12]], m[perm[13]], v);
      B2S_G<3, 4, 9, 14>(m[perm[14]], m[perm[15]], v);
   }

   for(size_t i = 0; i < 8; ++i) {
      m_h[i] ^= v[i] ^ v[i + 8];
   }
}

/*
 * Clear memory of sensitive data
 */
void BLAKE2s::clear() {
   state_init(m_outlen);
}

void BLAKE2s::add_data(std::span<const uint8_t> input) {
   BufferSlicer in(input);

   while(!in.empty()) {
      if(const auto one_block = m_buffer.handle_unaligned_data(in)) {
         m_bytes_processed += block_size;
         compress(false, *one_block);
      }

      if(m_buffer.in_alignment()) {
         while(const auto aligned_block = m_buffer.next_aligned_block_to_process(in)) {
            m_bytes_processed += block_size;
            compress(false, *aligned_block);
         }
      }
   }
}

void BLAKE2s::final_result(std::span<uint8_t> out) {
   m_bytes_processed += m_buffer.elements_in_buffer();

   m_buffer.fill_up_with_zeros();
   compress(true, m_buffer.consume());

   // little endian convert and store
   copy_out_le(out.first(output_length()), m_h);

   clear();
}

std::unique_ptr<HashFunction> BLAKE2s::copy_state() const {
   return std::make_unique<BLAKE2s>(*this);
}

/*
 * BLAKE2s Constructor
 */
BLAKE2s::BLAKE2s(size_t output_bits) {
   if(output_bits == 0 || output_bits > 256 || output_bits % 8 != 0) {
      throw Invalid_Argument("Bad output bits size for BLAKE2s");
   }
   state_init(output_bits >> 3);
}

BLAKE2s::~BLAKE2s() {
   secure_scrub_memory(m_h);
}

}  // namespace Botan
