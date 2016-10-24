/*
* Blake2b
* (C) 2016 cynecx
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

const u64bit blake2b_IV[BLAKE2B_IVU64COUNT] = {
   0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL,
   0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
   0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
   0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL
};

const u64bit blake2b_sigma[12][16] = {
   {  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 } ,
   { 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 } ,
   { 11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4 } ,
   {  7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8 } ,
   {  9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13 } ,
   {  2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9 } ,
   { 12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11 } ,
   { 13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10 } ,
   {  6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5 } ,
   { 10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13 , 0 } ,
   {  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 } ,
   { 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 }
};
}

Blake2b::Blake2b(size_t output_bits) :
   m_output_bits(output_bits),
   m_buffer(BLAKE2B_BLOCKBYTES),
   m_buflen(0),
   m_H(BLAKE2B_IVU64COUNT)
   {
   if(output_bits == 0 || output_bits % 8 != 0
      || output_bits / 8 > BLAKE2B_OUTBYTES)
      {
      throw Invalid_Argument("Bad output bits size for Blake2b");
      }

   state_init();
   }

void Blake2b::state_init()
   {
   std::copy(std::begin(blake2b_IV), std::end(blake2b_IV), m_H.begin());
   m_H[0] ^= 0x01010000 ^ static_cast<byte>(output_length());
   m_T[0] = m_T[1] = 0;
   m_F[0] = m_F[1] = 0;
   }

void Blake2b::compress(bool lastblock)
   {
   u64bit m[16];
   u64bit v[16];
   u64bit* const H = m_H.data();
   const byte* const block = m_buffer.data();

   if(lastblock)
      {
      m_F[0] = ~0ULL;
      }

   for(int i = 0; i < 16; i++)
      {
      m[i] = load_le<u64bit>(block, i);
      }

   for(int i = 0; i < 8; i++)
      {
      v[i] = H[i];
      v[i + 8] = blake2b_IV[i];
      }

   v[12] ^= m_T[0];
   v[13] ^= m_T[1];
   v[14] ^= m_F[0];
   v[15] ^= m_F[1];

#define G(r, i, a, b, c, d)                     \
   do {                                         \
   a = a + b + m[blake2b_sigma[r][2 * i + 0]];  \
   d = rotate_right<u64bit>(d ^ a, 32);         \
   c = c + d;                                   \
   b = rotate_right<u64bit>(b ^ c, 24);         \
   a = a + b + m[blake2b_sigma[r][2 * i + 1]];  \
   d = rotate_right<u64bit>(d ^ a, 16);         \
   c = c + d;                                   \
   b = rotate_right<u64bit>(b ^ c, 63);         \
   } while(0)

#define ROUND(r)                                \
   do {                                         \
   G(r, 0, v[0], v[4], v[8], v[12]);            \
   G(r, 1, v[1], v[5], v[9], v[13]);            \
   G(r, 2, v[2], v[6], v[10], v[14]);           \
   G(r, 3, v[3], v[7], v[11], v[15]);           \
   G(r, 4, v[0], v[5], v[10], v[15]);           \
   G(r, 5, v[1], v[6], v[11], v[12]);           \
   G(r, 6, v[2], v[7], v[8], v[13]);            \
   G(r, 7, v[3], v[4], v[9], v[14]);            \
   } while(0)

   ROUND(0);
   ROUND(1);
   ROUND(2);
   ROUND(3);
   ROUND(4);
   ROUND(5);
   ROUND(6);
   ROUND(7);
   ROUND(8);
   ROUND(9);
   ROUND(10);
   ROUND(11);

   for(int i = 0; i < 8; i++)
      {
      H[i] ^= v[i] ^ v[i + 8];
      }

#undef G
#undef ROUND
   }

void Blake2b::increment_counter(const u64bit inc)
   {
   m_T[0] += inc;
   if(m_T[0] < inc)
      {
      m_T[1]++;
      }
   }

void Blake2b::add_data(const byte input[], size_t length)
   {
   if(!input || length == 0)
      {
      return;
      }

   byte* const buffer = m_buffer.data();

   while(length > 0)
      {
      size_t fill = BLAKE2B_BLOCKBYTES - m_buflen;

      if(length <= fill)
         {
         std::memcpy(buffer + m_buflen, input, length);
         m_buflen += length;
         return;
         }

      std::memcpy(buffer + m_buflen, input, fill);
      increment_counter(BLAKE2B_BLOCKBYTES);
      compress();

      m_buflen = 0;
      input += fill;
      length -= fill;
      }
   }

void Blake2b::final_result(byte output[])
   {
   if(!output)
      {
      return;
      }

   byte* const buffer = m_buffer.data();
   const u64bit* const H = static_cast<const u64bit*>(m_H.data());
   u16bit outlen = static_cast<u16bit>(output_length());

   std::memset(buffer + m_buflen, 0, BLAKE2B_BLOCKBYTES - m_buflen);
   increment_counter(m_buflen);
   compress(true);

   for (u16bit i = 0; i < outlen; i++)
      {
      output[i] = (H[i >> 3] >> (8 * (i & 7))) & 0xFF;
      }

   clear();
   }

std::string Blake2b::name() const
   {
   return "Blake2b(" + std::to_string(m_output_bits) + ")";
   }

HashFunction* Blake2b::clone() const
   {
   return new Blake2b(m_output_bits);
   }

void Blake2b::clear()
   {
   zeroise(m_H);
   zeroise(m_buffer);
   m_buflen = 0;
   state_init();
   }

}
