/*
* BLAKE2b
* (C) 2016 cynecx
* (C) 2017 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/blake2b.h>
#include <botan/exceptn.h>
#include <botan/mem_ops.h>
#include <botan/loadstor.h>
#include <botan/rotate.h>
#include <algorithm>

namespace Botan {

namespace {

enum blake2b_constant {
  BLAKE2B_BLOCKBYTES = 128,
  BLAKE2B_IVU64COUNT = 8
};

const uint64_t blake2b_IV[BLAKE2B_IVU64COUNT] = {
   0x6a09e667f3bcc908, 0xbb67ae8584caa73b,
   0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
   0x510e527fade682d1, 0x9b05688c2b3e6c1f,
   0x1f83d9abfb41bd6b, 0x5be0cd19137e2179
};

}

BLAKE2b::BLAKE2b(size_t output_bits) :
   m_output_bits(output_bits),
   m_buffer(BLAKE2B_BLOCKBYTES),
   m_bufpos(0),
   m_H(BLAKE2B_IVU64COUNT)
   {
   if(output_bits == 0 || output_bits > 512 || output_bits % 8 != 0)
      {
      throw Invalid_Argument("Bad output bits size for BLAKE2b");
      }

   state_init();
   }

void BLAKE2b::state_init()
   {
   copy_mem(m_H.data(), blake2b_IV, BLAKE2B_IVU64COUNT);
   m_H[0] ^= 0x01010000 ^ static_cast<uint8_t>(output_length());
   m_T[0] = m_T[1] = 0;
   m_F[0] = m_F[1] = 0;
   m_bufpos = 0;
   }

namespace {

BOTAN_FORCE_INLINE void G(uint64_t& a, uint64_t& b, uint64_t& c, uint64_t& d,
                          uint64_t M0, uint64_t M1)
   {
   a = a + b + M0;
   d = rotr<32>(d ^ a);
   c = c + d;
   b = rotr<24>(b ^ c);
   a = a + b + M1;
   d = rotr<16>(d ^ a);
   c = c + d;
   b = rotr<63>(b ^ c);
   }

template<size_t i0, size_t i1, size_t i2, size_t i3, size_t i4, size_t i5, size_t i6, size_t i7,
         size_t i8, size_t i9, size_t iA, size_t iB, size_t iC, size_t iD, size_t iE, size_t iF>
BOTAN_FORCE_INLINE void ROUND(uint64_t* v, const uint64_t* M)
   {
   G(v[ 0], v[ 4], v[ 8], v[12], M[i0], M[i1]);
   G(v[ 1], v[ 5], v[ 9], v[13], M[i2], M[i3]);
   G(v[ 2], v[ 6], v[10], v[14], M[i4], M[i5]);
   G(v[ 3], v[ 7], v[11], v[15], M[i6], M[i7]);
   G(v[ 0], v[ 5], v[10], v[15], M[i8], M[i9]);
   G(v[ 1], v[ 6], v[11], v[12], M[iA], M[iB]);
   G(v[ 2], v[ 7], v[ 8], v[13], M[iC], M[iD]);
   G(v[ 3], v[ 4], v[ 9], v[14], M[iE], M[iF]);
   }


}

void BLAKE2b::compress(const uint8_t* input, size_t blocks, uint64_t increment)
   {
   for(size_t b = 0; b != blocks; ++b)
      {
      m_T[0] += increment;
      if(m_T[0] < increment)
         {
         m_T[1]++;
         }

      uint64_t M[16];
      uint64_t v[16];
      load_le(M, input, 16);

      input += BLAKE2B_BLOCKBYTES;

      for(size_t i = 0; i < 8; i++)
         v[i] = m_H[i];
      for(size_t i = 0; i != 8; ++i)
         v[i + 8] = blake2b_IV[i];

      v[12] ^= m_T[0];
      v[13] ^= m_T[1];
      v[14] ^= m_F[0];
      v[15] ^= m_F[1];

      ROUND< 0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15>(v, M);
      ROUND<14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3>(v, M);
      ROUND<11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4>(v, M);
      ROUND< 7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8>(v, M);
      ROUND< 9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13>(v, M);
      ROUND< 2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9>(v, M);
      ROUND<12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11>(v, M);
      ROUND<13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10>(v, M);
      ROUND< 6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5>(v, M);
      ROUND<10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13,  0>(v, M);
      ROUND< 0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15>(v, M);
      ROUND<14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3>(v, M);

      for(size_t i = 0; i < 8; i++)
         {
         m_H[i] ^= v[i] ^ v[i + 8];
         }
      }
   }

void BLAKE2b::add_data(const uint8_t input[], size_t length)
   {
   if(length == 0)
      return;

   if(m_bufpos > 0)
      {
      if(m_bufpos < BLAKE2B_BLOCKBYTES)
         {
         const size_t take = std::min(BLAKE2B_BLOCKBYTES - m_bufpos, length);
         copy_mem(&m_buffer[m_bufpos], input, take);
         m_bufpos += take;
         length -= take;
         input += take;
         }

      if(m_bufpos == m_buffer.size() && length > 0)
         {
         compress(m_buffer.data(), 1, BLAKE2B_BLOCKBYTES);
         m_bufpos = 0;
         }
      }

   if(length > BLAKE2B_BLOCKBYTES)
      {
      const size_t full_blocks = ((length-1) / BLAKE2B_BLOCKBYTES);
      compress(input, full_blocks, BLAKE2B_BLOCKBYTES);

      input += full_blocks * BLAKE2B_BLOCKBYTES;
      length -= full_blocks * BLAKE2B_BLOCKBYTES;
      }

   if(length > 0)
      {
      copy_mem(&m_buffer[m_bufpos], input, length);
      m_bufpos += length;
      }
   }

void BLAKE2b::final_result(uint8_t output[])
   {
   if(m_bufpos != BLAKE2B_BLOCKBYTES)
      clear_mem(&m_buffer[m_bufpos], BLAKE2B_BLOCKBYTES - m_bufpos);
   m_F[0] = 0xFFFFFFFFFFFFFFFF;
   compress(m_buffer.data(), 1, m_bufpos);
   copy_out_vec_le(output, output_length(), m_H);
   state_init();
   }

std::string BLAKE2b::name() const
   {
   return "BLAKE2b(" + std::to_string(m_output_bits) + ")";
   }

HashFunction* BLAKE2b::clone() const
   {
   return new BLAKE2b(m_output_bits);
   }

std::unique_ptr<HashFunction> BLAKE2b::copy_state() const
   {
   return std::unique_ptr<HashFunction>(new BLAKE2b(*this));
   }

void BLAKE2b::clear()
   {
   zeroise(m_H);
   zeroise(m_buffer);
   m_bufpos = 0;
   state_init();
   }

}
