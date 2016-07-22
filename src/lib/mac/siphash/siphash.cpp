/*
* SipHash
* (C) 2014,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/siphash.h>

namespace Botan {

namespace {

void SipRounds(u64bit M, secure_vector<u64bit>& V, size_t r)
   {
   u64bit V0 = V[0], V1 = V[1], V2 = V[2], V3 = V[3];

   V3 ^= M;
   for(size_t i = 0; i != r; ++i)
      {
      V0 += V1; V2 += V3;
      V1 = rotate_left(V1, 13);
      V3 = rotate_left(V3, 16);
      V1 ^= V0; V3 ^= V2;
      V0 = rotate_left(V0, 32);

      V2 += V1; V0 += V3;
      V1 = rotate_left(V1, 17);
      V3 = rotate_left(V3, 21);
      V1 ^= V2; V3 ^= V0;
      V2 = rotate_left(V2, 32);
      }
   V0 ^= M;

   V[0] = V0; V[1] = V1; V[2] = V2; V[3] = V3;
   }

}

void SipHash::add_data(const byte input[], size_t length)
   {
   m_words += length;

   if(m_mbuf_pos)
      {
      while(length && m_mbuf_pos != 8)
         {
         m_mbuf = (m_mbuf >> 8) | (static_cast<u64bit>(input[0]) << 56);
         ++m_mbuf_pos;
         ++input;
         length--;
         }

      if(m_mbuf_pos == 8)
         {
         SipRounds(m_mbuf, m_V, m_C);
         m_mbuf_pos = 0;
         m_mbuf = 0;
         }
      }

   while(length >= 8)
      {
      SipRounds(load_le<u64bit>(input, 0), m_V, m_C);
      input += 8;
      length -= 8;
      }

   for(size_t i = 0; i != length; ++i)
      {
      m_mbuf = (m_mbuf >> 8) | (static_cast<u64bit>(input[i]) << 56);
      m_mbuf_pos++;
      }
   }

void SipHash::final_result(byte mac[])
   {
   m_mbuf = (m_mbuf >> (64-m_mbuf_pos*8)) | (static_cast<u64bit>(m_words) << 56);
   SipRounds(m_mbuf, m_V, m_C);

   m_V[2] ^= 0xFF;
   SipRounds(0, m_V, m_D);

   const u64bit X = m_V[0] ^ m_V[1] ^ m_V[2] ^ m_V[3];

   store_le(X, mac);

   clear();
   }

void SipHash::key_schedule(const byte key[], size_t)
   {
   const u64bit K0 = load_le<u64bit>(key, 0);
   const u64bit K1 = load_le<u64bit>(key, 1);

   m_V.resize(4);
   m_V[0] = K0 ^ 0x736F6D6570736575;
   m_V[1] = K1 ^ 0x646F72616E646F6D;
   m_V[2] = K0 ^ 0x6C7967656E657261;
   m_V[3] = K1 ^ 0x7465646279746573;
   }

void SipHash::clear()
   {
   m_V.clear();
   m_mbuf = 0;
   m_mbuf_pos = 0;
   m_words = 0;
   }

std::string SipHash::name() const
   {
   return "SipHash(" + std::to_string(m_C) + "," + std::to_string(m_D) + ")";
   }

MessageAuthenticationCode* SipHash::clone() const
   {
   return new SipHash(m_C, m_D);
   }

}
