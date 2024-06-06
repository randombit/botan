/*
 * BLAKE2s
 * (C) 2023           Richard Huveneers
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

namespace Botan {

namespace {

// Initialization Vector.

const uint32_t blake2s_iv[8] = {
   0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19};

// Mixing function G.

inline void B2S_G(uint8_t a, uint8_t b, uint8_t c, uint8_t d, uint32_t x, uint32_t y, uint32_t* v) {
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

//      Secret key (also <= 32 bytes) is optional (keylen = 0).
//      (keylen=0: no key)

void BLAKE2s::state_init(size_t outlen, const uint8_t* key, size_t keylen) {
   for(size_t i = 0; i < 8; i++) {  // state, "param block"
      m_h[i] = blake2s_iv[i];
   }
   m_h[0] ^= 0x01010000 ^ (keylen << 8) ^ outlen;

   m_t[0] = 0;  // input count low word
   m_t[1] = 0;  // input count high word
   m_c = 0;     // pointer within buffer
   m_outlen = outlen;

   for(size_t i = keylen; i < 64; i++) {  // zero input block
      m_b[i] = 0;
   }
   if(keylen > 0) {
      add_data(std::span<const uint8_t>(key, keylen));
      m_c = 64;  // at the end
   }
}

// Compression function. "last" flag indicates last block.

void BLAKE2s::compress(bool last) {
   const uint8_t sigma[10][16] = {{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
                                  {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
                                  {11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4},
                                  {7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
                                  {9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13},
                                  {2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
                                  {12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11},
                                  {13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
                                  {6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5},
                                  {10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0}};
   uint32_t v[16], m[16];

   for(size_t i = 0; i < 8; i++) {  // init work variables
      v[i] = m_h[i];
      v[i + 8] = blake2s_iv[i];
   }

   v[12] ^= m_t[0];  // low 32 bits of offset
   v[13] ^= m_t[1];  // high 32 bits
   if(last) {        // last block flag set ?
      v[14] = ~v[14];
   }
   load_le<uint32_t>(m, m_b, 16);  // get little-endian words

   for(size_t i = 0; i < 10; i++) {  // ten rounds
      B2S_G(0, 4, 8, 12, m[sigma[i][0]], m[sigma[i][1]], v);
      B2S_G(1, 5, 9, 13, m[sigma[i][2]], m[sigma[i][3]], v);
      B2S_G(2, 6, 10, 14, m[sigma[i][4]], m[sigma[i][5]], v);
      B2S_G(3, 7, 11, 15, m[sigma[i][6]], m[sigma[i][7]], v);
      B2S_G(0, 5, 10, 15, m[sigma[i][8]], m[sigma[i][9]], v);
      B2S_G(1, 6, 11, 12, m[sigma[i][10]], m[sigma[i][11]], v);
      B2S_G(2, 7, 8, 13, m[sigma[i][12]], m[sigma[i][13]], v);
      B2S_G(3, 4, 9, 14, m[sigma[i][14]], m[sigma[i][15]], v);
   }

   for(size_t i = 0; i < 8; ++i) {
      m_h[i] ^= v[i] ^ v[i + 8];
   }
}

/*
 * Clear memory of sensitive data
 */
void BLAKE2s::clear() {
   state_init(m_outlen, nullptr, 0);
}

void BLAKE2s::add_data(std::span<const uint8_t> in) {
   for(size_t i = 0; i < in.size(); i++) {
      if(m_c == 64) {        // buffer full ?
         m_t[0] += m_c;      // add counters
         if(m_t[0] < m_c) {  // carry overflow ?
            m_t[1]++;        // high word
         }
         compress(false);  // compress (not last)
         m_c = 0;          // counter to zero
      }
      m_b[m_c++] = in[i];
   }
}

void BLAKE2s::final_result(std::span<uint8_t> out) {
   m_t[0] += m_c;      // mark last block offset
   if(m_t[0] < m_c) {  // carry overflow
      m_t[1]++;        // high word
   }

   while(m_c < 64) {  // fill up with zeros
      m_b[m_c++] = 0;
   }
   compress(true);  // final block flag = 1

   // little endian convert and store
   copy_out_le(out.first(output_length()), m_h);

   clear();
}

std::unique_ptr<HashFunction> BLAKE2s::copy_state() const {
   std::unique_ptr<BLAKE2s> h = std::make_unique<BLAKE2s>(m_outlen << 3);
   memcpy(h->m_b, m_b, sizeof(m_b));
   memcpy(h->m_h, m_h, sizeof(m_h));
   memcpy(h->m_t, m_t, sizeof(m_t));
   h->m_c = m_c;
   return h;
}

/*
 * BLAKE2s Constructor
 */
BLAKE2s::BLAKE2s(size_t output_bits) {
   if(output_bits == 0 || output_bits > 256 || output_bits % 8 != 0) {
      throw Invalid_Argument("Bad output bits size for BLAKE2s");
   };
   state_init(output_bits >> 3, nullptr, 0);
}

BLAKE2s::~BLAKE2s() {
   secure_scrub_memory(m_b, sizeof(m_b));
   secure_scrub_memory(m_h, sizeof(m_h));
   secure_scrub_memory(m_t, sizeof(m_t));
}

}  // namespace Botan
