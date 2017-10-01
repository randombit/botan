/*
* Streebog
* (C) 2017 Ribose Inc.
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/streebog.h>
#include <botan/exceptn.h>

namespace Botan {

extern const uint64_t STREEBOG_Ax[8][256];
extern const uint64_t STREEBOG_C[12][8];

std::unique_ptr<HashFunction> Streebog::copy_state() const
   {
   return std::unique_ptr<HashFunction>(new Streebog(*this));
   }

namespace {

static inline void addm(const uint8_t* m, uint64_t* h)
   {
   uint64_t carry = false;
   for(int i = 0; i < 8; i++)
      {
      const uint64_t m64 = load_le<uint64_t>(m, i);
      const uint64_t hi = load_le<uint64_t>(reinterpret_cast<uint8_t*>(h), i);
      const uint64_t t = hi + m64;

      const uint64_t overflow = (t < hi ? 1 : 0) | (t < m64 ? 1 : 0);
      store_le(t + carry, reinterpret_cast<uint8_t*>(&h[i]));
      carry = overflow;
      }
   }

inline void lps(uint64_t* block)
   {
   uint8_t r[64];
   std::memcpy(r, block, 64);

   for(int i = 0; i < 8; ++i)
      {
      block[i] =  load_le<uint64_t>(reinterpret_cast<const uint8_t*>(&STREEBOG_Ax[0][r[i]]), 0) ^
                  load_le<uint64_t>(reinterpret_cast<const uint8_t*>(&STREEBOG_Ax[1][r[i + 8]]), 0) ^
                  load_le<uint64_t>(reinterpret_cast<const uint8_t*>(&STREEBOG_Ax[2][r[i + 16]]), 0) ^
                  load_le<uint64_t>(reinterpret_cast<const uint8_t*>(&STREEBOG_Ax[3][r[i + 24]]), 0) ^
                  load_le<uint64_t>(reinterpret_cast<const uint8_t*>(&STREEBOG_Ax[4][r[i + 32]]), 0) ^
                  load_le<uint64_t>(reinterpret_cast<const uint8_t*>(&STREEBOG_Ax[5][r[i + 40]]), 0) ^
                  load_le<uint64_t>(reinterpret_cast<const uint8_t*>(&STREEBOG_Ax[6][r[i + 48]]), 0) ^
                  load_le<uint64_t>(reinterpret_cast<const uint8_t*>(&STREEBOG_Ax[7][r[i + 56]]), 0);
      }
   }

inline void e(uint64_t* K, const uint64_t* m)
   {
   uint64_t A[8];
   uint64_t C[8];

   copy_mem(A, K, 8);

   for(size_t i = 0; i != 8; ++i)
      {
      K[i] ^= m[i];
      }

   for(size_t i = 0; i < 12; ++i)
      {
      lps(K);
      load_le(C, reinterpret_cast<const uint8_t*>(&STREEBOG_C[i][0]), 8);

      for(size_t j = 0; j != 8; ++j)
         A[j] ^= C[j];
      lps(A);
      for(size_t j = 0; j != 8; ++j)
         K[j] ^= A[j];
      }
   }

inline void g(uint64_t* h, const uint8_t* m, uint64_t N)
   {
   uint64_t hN[8];

   // force N to little-endian
   store_le(N, reinterpret_cast<uint8_t*>(&N));

   copy_mem(hN, h, 8);
   hN[0] ^= N;
   lps(hN);
   const uint64_t* m64 = reinterpret_cast<const uint64_t*>(m);

   e(hN, m64);

   for(size_t i = 0; i != 8; ++i)
      {
      h[i] ^= hN[i] ^ m64[i];
      }
   }

} //namespace

Streebog::Streebog(size_t output_bits) :
   m_output_bits(output_bits),
   m_count(0),
   m_position(0),
   m_buffer(64),
   m_h(8),
   m_S(8)
   {
   if(output_bits != 256 && output_bits != 512)
      throw Invalid_Argument("Streebog: Invalid output length " +
                             std::to_string(output_bits));

   clear();
   }

std::string Streebog::name() const
   {
   return "Streebog-" + std::to_string(m_output_bits);
   }

/*
* Clear memory of sensitive data
*/
void Streebog::clear()
   {
   m_count = 0;
   m_position = 0;
   zeroise(m_buffer);
   zeroise(m_S);

   const uint64_t fill = (m_output_bits == 512) ? 0 : 0x0101010101010101;
   std::fill(m_h.begin(), m_h.end(), fill);
   }

/*
* Update the hash
*/
void Streebog::add_data(const uint8_t input[], size_t length)
   {
   while(m_position + length >= 64)
      {
      buffer_insert(m_buffer, m_position, input, 64 - m_position);
      compress(m_buffer.data());
      m_count += 512;
      input += (64 - m_position);
      length -= (64 - m_position);
      m_position = 0;
      }

   buffer_insert(m_buffer, m_position, input, length);
   m_position += length;
   }

/*
* Finalize a hash
*/
void Streebog::final_result(uint8_t output[])
   {
   m_buffer[m_position++] = 0x01;

   if(m_position != m_buffer.size())
      clear_mem(&m_buffer[m_position], m_buffer.size() - m_position);

   compress(m_buffer.data());
   m_count += (m_position - 1) * 8;

   zeroise(m_buffer);
   store_le(m_count, m_buffer.data());
   compress(m_buffer.data(), true);

   compress(reinterpret_cast<const uint8_t*>(m_S.data()), true);
   std::memcpy(output, &m_h[8 - output_length() / 8], output_length());
   clear();
   }

void Streebog::compress(const uint8_t input[], bool last_block)
   {
   g(m_h.data(), input, last_block ? 0ULL : m_count);
   if(!last_block)
      { addm(input, m_S.data()); }
   }

}
