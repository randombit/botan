/*
* MD5
* (C) 1999-2008 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/md5.h>
#include <botan/loadstor.h>
#include <botan/rotate.h>

namespace Botan {

std::unique_ptr<HashFunction> MD5::copy_state() const
   {
   return std::unique_ptr<HashFunction>(new MD5(*this));
   }

namespace {

/*
* MD5 FF Function
*/
template<size_t S>
inline void FF(uint32_t& A, uint32_t B, uint32_t C, uint32_t D, uint32_t M)
   {
   A += (D ^ (B & (C ^ D))) + M;
   A  = rotl<S>(A) + B;
   }

/*
* MD5 GG Function
*/
template<size_t S>
inline void GG(uint32_t& A, uint32_t B, uint32_t C, uint32_t D, uint32_t M)
   {
   A += (C ^ (D & (B ^ C))) + M;
   A  = rotl<S>(A) + B;
   }

/*
* MD5 HH Function
*/
template<size_t S>
inline void HH(uint32_t& A, uint32_t B, uint32_t C, uint32_t D, uint32_t M)
   {
   A += (B ^ C ^ D) + M;
   A  = rotl<S>(A) + B;
   }

/*
* MD5 II Function
*/
template<size_t S>
inline void II(uint32_t& A, uint32_t B, uint32_t C, uint32_t D, uint32_t M)
   {
   A += (C ^ (B | ~D)) + M;
   A  = rotl<S>(A) + B;
   }

}

/*
* MD5 Compression Function
*/
void MD5::compress_n(const uint8_t input[], size_t blocks)
   {
   uint32_t A = m_digest[0], B = m_digest[1], C = m_digest[2], D = m_digest[3];

   for(size_t i = 0; i != blocks; ++i)
      {
      load_le(m_M.data(), input, m_M.size());

      FF< 7>(A,B,C,D,m_M[ 0]+0xD76AA478);   FF<12>(D,A,B,C,m_M[ 1]+0xE8C7B756);
      FF<17>(C,D,A,B,m_M[ 2]+0x242070DB);   FF<22>(B,C,D,A,m_M[ 3]+0xC1BDCEEE);
      FF< 7>(A,B,C,D,m_M[ 4]+0xF57C0FAF);   FF<12>(D,A,B,C,m_M[ 5]+0x4787C62A);
      FF<17>(C,D,A,B,m_M[ 6]+0xA8304613);   FF<22>(B,C,D,A,m_M[ 7]+0xFD469501);
      FF< 7>(A,B,C,D,m_M[ 8]+0x698098D8);   FF<12>(D,A,B,C,m_M[ 9]+0x8B44F7AF);
      FF<17>(C,D,A,B,m_M[10]+0xFFFF5BB1);   FF<22>(B,C,D,A,m_M[11]+0x895CD7BE);
      FF< 7>(A,B,C,D,m_M[12]+0x6B901122);   FF<12>(D,A,B,C,m_M[13]+0xFD987193);
      FF<17>(C,D,A,B,m_M[14]+0xA679438E);   FF<22>(B,C,D,A,m_M[15]+0x49B40821);

      GG< 5>(A,B,C,D,m_M[ 1]+0xF61E2562);   GG< 9>(D,A,B,C,m_M[ 6]+0xC040B340);
      GG<14>(C,D,A,B,m_M[11]+0x265E5A51);   GG<20>(B,C,D,A,m_M[ 0]+0xE9B6C7AA);
      GG< 5>(A,B,C,D,m_M[ 5]+0xD62F105D);   GG< 9>(D,A,B,C,m_M[10]+0x02441453);
      GG<14>(C,D,A,B,m_M[15]+0xD8A1E681);   GG<20>(B,C,D,A,m_M[ 4]+0xE7D3FBC8);
      GG< 5>(A,B,C,D,m_M[ 9]+0x21E1CDE6);   GG< 9>(D,A,B,C,m_M[14]+0xC33707D6);
      GG<14>(C,D,A,B,m_M[ 3]+0xF4D50D87);   GG<20>(B,C,D,A,m_M[ 8]+0x455A14ED);
      GG< 5>(A,B,C,D,m_M[13]+0xA9E3E905);   GG< 9>(D,A,B,C,m_M[ 2]+0xFCEFA3F8);
      GG<14>(C,D,A,B,m_M[ 7]+0x676F02D9);   GG<20>(B,C,D,A,m_M[12]+0x8D2A4C8A);

      HH< 4>(A,B,C,D,m_M[ 5]+0xFFFA3942);   HH<11>(D,A,B,C,m_M[ 8]+0x8771F681);
      HH<16>(C,D,A,B,m_M[11]+0x6D9D6122);   HH<23>(B,C,D,A,m_M[14]+0xFDE5380C);
      HH< 4>(A,B,C,D,m_M[ 1]+0xA4BEEA44);   HH<11>(D,A,B,C,m_M[ 4]+0x4BDECFA9);
      HH<16>(C,D,A,B,m_M[ 7]+0xF6BB4B60);   HH<23>(B,C,D,A,m_M[10]+0xBEBFBC70);
      HH< 4>(A,B,C,D,m_M[13]+0x289B7EC6);   HH<11>(D,A,B,C,m_M[ 0]+0xEAA127FA);
      HH<16>(C,D,A,B,m_M[ 3]+0xD4EF3085);   HH<23>(B,C,D,A,m_M[ 6]+0x04881D05);
      HH< 4>(A,B,C,D,m_M[ 9]+0xD9D4D039);   HH<11>(D,A,B,C,m_M[12]+0xE6DB99E5);
      HH<16>(C,D,A,B,m_M[15]+0x1FA27CF8);   HH<23>(B,C,D,A,m_M[ 2]+0xC4AC5665);

      II< 6>(A,B,C,D,m_M[ 0]+0xF4292244);   II<10>(D,A,B,C,m_M[ 7]+0x432AFF97);
      II<15>(C,D,A,B,m_M[14]+0xAB9423A7);   II<21>(B,C,D,A,m_M[ 5]+0xFC93A039);
      II< 6>(A,B,C,D,m_M[12]+0x655B59C3);   II<10>(D,A,B,C,m_M[ 3]+0x8F0CCC92);
      II<15>(C,D,A,B,m_M[10]+0xFFEFF47D);   II<21>(B,C,D,A,m_M[ 1]+0x85845DD1);
      II< 6>(A,B,C,D,m_M[ 8]+0x6FA87E4F);   II<10>(D,A,B,C,m_M[15]+0xFE2CE6E0);
      II<15>(C,D,A,B,m_M[ 6]+0xA3014314);   II<21>(B,C,D,A,m_M[13]+0x4E0811A1);
      II< 6>(A,B,C,D,m_M[ 4]+0xF7537E82);   II<10>(D,A,B,C,m_M[11]+0xBD3AF235);
      II<15>(C,D,A,B,m_M[ 2]+0x2AD7D2BB);   II<21>(B,C,D,A,m_M[ 9]+0xEB86D391);

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
void MD5::copy_out(uint8_t output[])
   {
   copy_out_vec_le(output, output_length(), m_digest);
   }

/*
* Clear memory of sensitive data
*/
void MD5::clear()
   {
   MDx_HashFunction::clear();
   zeroise(m_M);
   m_digest[0] = 0x67452301;
   m_digest[1] = 0xEFCDAB89;
   m_digest[2] = 0x98BADCFE;
   m_digest[3] = 0x10325476;
   }

}
