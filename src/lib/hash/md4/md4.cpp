/*
* MD4
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/md4.h>

namespace Botan {

std::unique_ptr<HashFunction> MD4::copy_state() const
   {
   return std::unique_ptr<HashFunction>(new MD4(*this));
   }

namespace {

/*
* MD4 FF Function
*/
inline void FF(uint32_t& A, uint32_t B, uint32_t C, uint32_t D, uint32_t M, uint8_t S)
   {
   A += (D ^ (B & (C ^ D))) + M;
   A  = rotate_left(A, S);
   }

/*
* MD4 GG Function
*/
inline void GG(uint32_t& A, uint32_t B, uint32_t C, uint32_t D, uint32_t M, uint8_t S)
   {
   A += ((B & C) | (D & (B | C))) + M + 0x5A827999;
   A  = rotate_left(A, S);
   }

/*
* MD4 HH Function
*/
inline void HH(uint32_t& A, uint32_t B, uint32_t C, uint32_t D, uint32_t M, uint8_t S)
   {
   A += (B ^ C ^ D) + M + 0x6ED9EBA1;
   A  = rotate_left(A, S);
   }

}

/*
* MD4 Compression Function
*/
void MD4::compress_n(const uint8_t input[], size_t blocks)
   {
   uint32_t A = m_digest[0], B = m_digest[1], C = m_digest[2], D = m_digest[3];

   for(size_t i = 0; i != blocks; ++i)
      {
      load_le(m_M.data(), input, m_M.size());

      FF(A,B,C,D,m_M[ 0], 3);   FF(D,A,B,C,m_M[ 1], 7);
      FF(C,D,A,B,m_M[ 2],11);   FF(B,C,D,A,m_M[ 3],19);
      FF(A,B,C,D,m_M[ 4], 3);   FF(D,A,B,C,m_M[ 5], 7);
      FF(C,D,A,B,m_M[ 6],11);   FF(B,C,D,A,m_M[ 7],19);
      FF(A,B,C,D,m_M[ 8], 3);   FF(D,A,B,C,m_M[ 9], 7);
      FF(C,D,A,B,m_M[10],11);   FF(B,C,D,A,m_M[11],19);
      FF(A,B,C,D,m_M[12], 3);   FF(D,A,B,C,m_M[13], 7);
      FF(C,D,A,B,m_M[14],11);   FF(B,C,D,A,m_M[15],19);

      GG(A,B,C,D,m_M[ 0], 3);   GG(D,A,B,C,m_M[ 4], 5);
      GG(C,D,A,B,m_M[ 8], 9);   GG(B,C,D,A,m_M[12],13);
      GG(A,B,C,D,m_M[ 1], 3);   GG(D,A,B,C,m_M[ 5], 5);
      GG(C,D,A,B,m_M[ 9], 9);   GG(B,C,D,A,m_M[13],13);
      GG(A,B,C,D,m_M[ 2], 3);   GG(D,A,B,C,m_M[ 6], 5);
      GG(C,D,A,B,m_M[10], 9);   GG(B,C,D,A,m_M[14],13);
      GG(A,B,C,D,m_M[ 3], 3);   GG(D,A,B,C,m_M[ 7], 5);
      GG(C,D,A,B,m_M[11], 9);   GG(B,C,D,A,m_M[15],13);

      HH(A,B,C,D,m_M[ 0], 3);   HH(D,A,B,C,m_M[ 8], 9);
      HH(C,D,A,B,m_M[ 4],11);   HH(B,C,D,A,m_M[12],15);
      HH(A,B,C,D,m_M[ 2], 3);   HH(D,A,B,C,m_M[10], 9);
      HH(C,D,A,B,m_M[ 6],11);   HH(B,C,D,A,m_M[14],15);
      HH(A,B,C,D,m_M[ 1], 3);   HH(D,A,B,C,m_M[ 9], 9);
      HH(C,D,A,B,m_M[ 5],11);   HH(B,C,D,A,m_M[13],15);
      HH(A,B,C,D,m_M[ 3], 3);   HH(D,A,B,C,m_M[11], 9);
      HH(C,D,A,B,m_M[ 7],11);   HH(B,C,D,A,m_M[15],15);

      A = (m_digest[0] += A);
      B = (m_digest[1] += B);
      C = (m_digest[2] += C);
      D = (m_digest[3] += D);

      input += hash_block_size();
      }
   }

/*
* Copy out the digest
*/
void MD4::copy_out(uint8_t output[])
   {
   copy_out_vec_le(output, output_length(), m_digest);
   }

/*
* Clear memory of sensitive data
*/
void MD4::clear()
   {
   MDx_HashFunction::clear();
   zeroise(m_M);
   m_digest[0] = 0x67452301;
   m_digest[1] = 0xEFCDAB89;
   m_digest[2] = 0x98BADCFE;
   m_digest[3] = 0x10325476;
   }

}
