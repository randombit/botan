/*
* SHA-160
* (C) 1999-2008,2011 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/sha160.h>
#include <botan/loadstor.h>
#include <botan/rotate.h>
#include <botan/cpuid.h>

namespace Botan {

std::unique_ptr<HashFunction> SHA_160::copy_state() const
   {
   return std::unique_ptr<HashFunction>(new SHA_160(*this));
   }

namespace SHA1_F {

namespace {

/*
* SHA-160 F1 Function
*/
inline void F1(uint32_t A, uint32_t& B, uint32_t C, uint32_t D, uint32_t& E, uint32_t msg)
   {
   E += (D ^ (B & (C ^ D))) + msg + 0x5A827999 + rotl<5>(A);
   B  = rotl<30>(B);
   }

/*
* SHA-160 F2 Function
*/
inline void F2(uint32_t A, uint32_t& B, uint32_t C, uint32_t D, uint32_t& E, uint32_t msg)
   {
   E += (B ^ C ^ D) + msg + 0x6ED9EBA1 + rotl<5>(A);
   B  = rotl<30>(B);
   }

/*
* SHA-160 F3 Function
*/
inline void F3(uint32_t A, uint32_t& B, uint32_t C, uint32_t D, uint32_t& E, uint32_t msg)
   {
   E += ((B & C) | ((B | C) & D)) + msg + 0x8F1BBCDC + rotl<5>(A);
   B  = rotl<30>(B);
   }

/*
* SHA-160 F4 Function
*/
inline void F4(uint32_t A, uint32_t& B, uint32_t C, uint32_t D, uint32_t& E, uint32_t msg)
   {
   E += (B ^ C ^ D) + msg + 0xCA62C1D6 + rotl<5>(A);
   B  = rotl<30>(B);
   }

}

}

/*
* SHA-160 Compression Function
*/
void SHA_160::compress_n(const uint8_t input[], size_t blocks)
   {
   using namespace SHA1_F;

#if defined(BOTAN_HAS_SHA1_X86_SHA_NI)
   if(CPUID::has_intel_sha())
      {
      return sha1_compress_x86(m_digest, input, blocks);
      }
#endif

#if defined(BOTAN_HAS_SHA1_ARMV8)
   if(CPUID::has_arm_sha1())
      {
      return sha1_armv8_compress_n(m_digest, input, blocks);
      }
#endif

#if defined(BOTAN_HAS_SHA1_SSE2)
   if(CPUID::has_sse2())
      {
      return sse2_compress_n(m_digest, input, blocks);
      }

#endif

   uint32_t A = m_digest[0], B = m_digest[1], C = m_digest[2],
          D = m_digest[3], E = m_digest[4];

   m_W.resize(80);

   for(size_t i = 0; i != blocks; ++i)
      {
      load_be(m_W.data(), input, 16);

      for(size_t j = 16; j != 80; j += 8)
         {
         m_W[j  ] = rotl<1>(m_W[j-3] ^ m_W[j-8] ^ m_W[j-14] ^ m_W[j-16]);
         m_W[j+1] = rotl<1>(m_W[j-2] ^ m_W[j-7] ^ m_W[j-13] ^ m_W[j-15]);
         m_W[j+2] = rotl<1>(m_W[j-1] ^ m_W[j-6] ^ m_W[j-12] ^ m_W[j-14]);
         m_W[j+3] = rotl<1>(m_W[j  ] ^ m_W[j-5] ^ m_W[j-11] ^ m_W[j-13]);
         m_W[j+4] = rotl<1>(m_W[j+1] ^ m_W[j-4] ^ m_W[j-10] ^ m_W[j-12]);
         m_W[j+5] = rotl<1>(m_W[j+2] ^ m_W[j-3] ^ m_W[j- 9] ^ m_W[j-11]);
         m_W[j+6] = rotl<1>(m_W[j+3] ^ m_W[j-2] ^ m_W[j- 8] ^ m_W[j-10]);
         m_W[j+7] = rotl<1>(m_W[j+4] ^ m_W[j-1] ^ m_W[j- 7] ^ m_W[j- 9]);
         }

      F1(A, B, C, D, E, m_W[ 0]);   F1(E, A, B, C, D, m_W[ 1]);
      F1(D, E, A, B, C, m_W[ 2]);   F1(C, D, E, A, B, m_W[ 3]);
      F1(B, C, D, E, A, m_W[ 4]);   F1(A, B, C, D, E, m_W[ 5]);
      F1(E, A, B, C, D, m_W[ 6]);   F1(D, E, A, B, C, m_W[ 7]);
      F1(C, D, E, A, B, m_W[ 8]);   F1(B, C, D, E, A, m_W[ 9]);
      F1(A, B, C, D, E, m_W[10]);   F1(E, A, B, C, D, m_W[11]);
      F1(D, E, A, B, C, m_W[12]);   F1(C, D, E, A, B, m_W[13]);
      F1(B, C, D, E, A, m_W[14]);   F1(A, B, C, D, E, m_W[15]);
      F1(E, A, B, C, D, m_W[16]);   F1(D, E, A, B, C, m_W[17]);
      F1(C, D, E, A, B, m_W[18]);   F1(B, C, D, E, A, m_W[19]);

      F2(A, B, C, D, E, m_W[20]);   F2(E, A, B, C, D, m_W[21]);
      F2(D, E, A, B, C, m_W[22]);   F2(C, D, E, A, B, m_W[23]);
      F2(B, C, D, E, A, m_W[24]);   F2(A, B, C, D, E, m_W[25]);
      F2(E, A, B, C, D, m_W[26]);   F2(D, E, A, B, C, m_W[27]);
      F2(C, D, E, A, B, m_W[28]);   F2(B, C, D, E, A, m_W[29]);
      F2(A, B, C, D, E, m_W[30]);   F2(E, A, B, C, D, m_W[31]);
      F2(D, E, A, B, C, m_W[32]);   F2(C, D, E, A, B, m_W[33]);
      F2(B, C, D, E, A, m_W[34]);   F2(A, B, C, D, E, m_W[35]);
      F2(E, A, B, C, D, m_W[36]);   F2(D, E, A, B, C, m_W[37]);
      F2(C, D, E, A, B, m_W[38]);   F2(B, C, D, E, A, m_W[39]);

      F3(A, B, C, D, E, m_W[40]);   F3(E, A, B, C, D, m_W[41]);
      F3(D, E, A, B, C, m_W[42]);   F3(C, D, E, A, B, m_W[43]);
      F3(B, C, D, E, A, m_W[44]);   F3(A, B, C, D, E, m_W[45]);
      F3(E, A, B, C, D, m_W[46]);   F3(D, E, A, B, C, m_W[47]);
      F3(C, D, E, A, B, m_W[48]);   F3(B, C, D, E, A, m_W[49]);
      F3(A, B, C, D, E, m_W[50]);   F3(E, A, B, C, D, m_W[51]);
      F3(D, E, A, B, C, m_W[52]);   F3(C, D, E, A, B, m_W[53]);
      F3(B, C, D, E, A, m_W[54]);   F3(A, B, C, D, E, m_W[55]);
      F3(E, A, B, C, D, m_W[56]);   F3(D, E, A, B, C, m_W[57]);
      F3(C, D, E, A, B, m_W[58]);   F3(B, C, D, E, A, m_W[59]);

      F4(A, B, C, D, E, m_W[60]);   F4(E, A, B, C, D, m_W[61]);
      F4(D, E, A, B, C, m_W[62]);   F4(C, D, E, A, B, m_W[63]);
      F4(B, C, D, E, A, m_W[64]);   F4(A, B, C, D, E, m_W[65]);
      F4(E, A, B, C, D, m_W[66]);   F4(D, E, A, B, C, m_W[67]);
      F4(C, D, E, A, B, m_W[68]);   F4(B, C, D, E, A, m_W[69]);
      F4(A, B, C, D, E, m_W[70]);   F4(E, A, B, C, D, m_W[71]);
      F4(D, E, A, B, C, m_W[72]);   F4(C, D, E, A, B, m_W[73]);
      F4(B, C, D, E, A, m_W[74]);   F4(A, B, C, D, E, m_W[75]);
      F4(E, A, B, C, D, m_W[76]);   F4(D, E, A, B, C, m_W[77]);
      F4(C, D, E, A, B, m_W[78]);   F4(B, C, D, E, A, m_W[79]);

      A = (m_digest[0] += A);
      B = (m_digest[1] += B);
      C = (m_digest[2] += C);
      D = (m_digest[3] += D);
      E = (m_digest[4] += E);

      input += hash_block_size();
      }
   }

/*
* Copy out the digest
*/
void SHA_160::copy_out(uint8_t output[])
   {
   copy_out_vec_be(output, output_length(), m_digest);
   }

/*
* Clear memory of sensitive data
*/
void SHA_160::clear()
   {
   MDx_HashFunction::clear();
   zeroise(m_W);
   m_digest[0] = 0x67452301;
   m_digest[1] = 0xEFCDAB89;
   m_digest[2] = 0x98BADCFE;
   m_digest[3] = 0x10325476;
   m_digest[4] = 0xC3D2E1F0;
   }

}
