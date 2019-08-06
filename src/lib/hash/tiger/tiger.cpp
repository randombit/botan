/*
* Tiger
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/tiger.h>
#include <botan/loadstor.h>
#include <botan/exceptn.h>

namespace Botan {

std::unique_ptr<HashFunction> Tiger::copy_state() const
   {
   return std::unique_ptr<HashFunction>(new Tiger(*this));
   }

namespace {

/*
* Tiger Mixing Function
*/
inline void mix(secure_vector<uint64_t>& X)
   {
   X[0] -= X[7] ^ 0xA5A5A5A5A5A5A5A5;
   X[1] ^= X[0];
   X[2] += X[1];
   X[3] -= X[2] ^ ((~X[1]) << 19);
   X[4] ^= X[3];
   X[5] += X[4];
   X[6] -= X[5] ^ ((~X[4]) >> 23);
   X[7] ^= X[6];

   X[0] += X[7];
   X[1] -= X[0] ^ ((~X[7]) << 19);
   X[2] ^= X[1];
   X[3] += X[2];
   X[4] -= X[3] ^ ((~X[2]) >> 23);
   X[5] ^= X[4];
   X[6] += X[5];
   X[7] -= X[6] ^ 0x0123456789ABCDEF;
   }

}

/*
* Tiger Compression Function
*/
void Tiger::compress_n(const uint8_t input[], size_t blocks)
   {
   uint64_t A = m_digest[0], B = m_digest[1], C = m_digest[2];

   for(size_t i = 0; i != blocks; ++i)
      {
      load_le(m_X.data(), input, m_X.size());

      pass(A, B, C, m_X, 5); mix(m_X);
      pass(C, A, B, m_X, 7); mix(m_X);
      pass(B, C, A, m_X, 9);

      for(size_t j = 3; j != m_passes; ++j)
         {
         mix(m_X);
         pass(A, B, C, m_X, 9);
         uint64_t T = A; A = C; C = B; B = T;
         }

      A = (m_digest[0] ^= A);
      B = m_digest[1] = B - m_digest[1];
      C = (m_digest[2] += C);

      input += hash_block_size();
      }
   }

/*
* Copy out the digest
*/
void Tiger::copy_out(uint8_t output[])
   {
   copy_out_vec_le(output, output_length(), m_digest);
   }

/*
* Tiger Pass
*/
void Tiger::pass(uint64_t& A, uint64_t& B, uint64_t& C,
                 const secure_vector<uint64_t>& X,
                 uint8_t mul)
   {
   C ^= X[0];
   A -= SBOX1[get_byte(7, C)] ^ SBOX2[get_byte(5, C)] ^
        SBOX3[get_byte(3, C)] ^ SBOX4[get_byte(1, C)];
   B += SBOX1[get_byte(0, C)] ^ SBOX2[get_byte(2, C)] ^
        SBOX3[get_byte(4, C)] ^ SBOX4[get_byte(6, C)];
   B *= mul;

   A ^= X[1];
   B -= SBOX1[get_byte(7, A)] ^ SBOX2[get_byte(5, A)] ^
        SBOX3[get_byte(3, A)] ^ SBOX4[get_byte(1, A)];
   C += SBOX1[get_byte(0, A)] ^ SBOX2[get_byte(2, A)] ^
        SBOX3[get_byte(4, A)] ^ SBOX4[get_byte(6, A)];
   C *= mul;

   B ^= X[2];
   C -= SBOX1[get_byte(7, B)] ^ SBOX2[get_byte(5, B)] ^
        SBOX3[get_byte(3, B)] ^ SBOX4[get_byte(1, B)];
   A += SBOX1[get_byte(0, B)] ^ SBOX2[get_byte(2, B)] ^
        SBOX3[get_byte(4, B)] ^ SBOX4[get_byte(6, B)];
   A *= mul;

   C ^= X[3];
   A -= SBOX1[get_byte(7, C)] ^ SBOX2[get_byte(5, C)] ^
        SBOX3[get_byte(3, C)] ^ SBOX4[get_byte(1, C)];
   B += SBOX1[get_byte(0, C)] ^ SBOX2[get_byte(2, C)] ^
        SBOX3[get_byte(4, C)] ^ SBOX4[get_byte(6, C)];
   B *= mul;

   A ^= X[4];
   B -= SBOX1[get_byte(7, A)] ^ SBOX2[get_byte(5, A)] ^
        SBOX3[get_byte(3, A)] ^ SBOX4[get_byte(1, A)];
   C += SBOX1[get_byte(0, A)] ^ SBOX2[get_byte(2, A)] ^
        SBOX3[get_byte(4, A)] ^ SBOX4[get_byte(6, A)];
   C *= mul;

   B ^= X[5];
   C -= SBOX1[get_byte(7, B)] ^ SBOX2[get_byte(5, B)] ^
        SBOX3[get_byte(3, B)] ^ SBOX4[get_byte(1, B)];
   A += SBOX1[get_byte(0, B)] ^ SBOX2[get_byte(2, B)] ^
        SBOX3[get_byte(4, B)] ^ SBOX4[get_byte(6, B)];
   A *= mul;

   C ^= X[6];
   A -= SBOX1[get_byte(7, C)] ^ SBOX2[get_byte(5, C)] ^
        SBOX3[get_byte(3, C)] ^ SBOX4[get_byte(1, C)];
   B += SBOX1[get_byte(0, C)] ^ SBOX2[get_byte(2, C)] ^
        SBOX3[get_byte(4, C)] ^ SBOX4[get_byte(6, C)];
   B *= mul;

   A ^= X[7];
   B -= SBOX1[get_byte(7, A)] ^ SBOX2[get_byte(5, A)] ^
        SBOX3[get_byte(3, A)] ^ SBOX4[get_byte(1, A)];
   C += SBOX1[get_byte(0, A)] ^ SBOX2[get_byte(2, A)] ^
        SBOX3[get_byte(4, A)] ^ SBOX4[get_byte(6, A)];
   C *= mul;
   }

/*
* Clear memory of sensitive data
*/
void Tiger::clear()
   {
   MDx_HashFunction::clear();
   zeroise(m_X);
   m_digest[0] = 0x0123456789ABCDEF;
   m_digest[1] = 0xFEDCBA9876543210;
   m_digest[2] = 0xF096A5B4C3B2E187;
   }

/*
* Return the name of this type
*/
std::string Tiger::name() const
   {
   return "Tiger(" + std::to_string(output_length()) + "," +
                     std::to_string(m_passes) + ")";
   }

/*
* Tiger Constructor
*/
Tiger::Tiger(size_t hash_len, size_t passes) :
   MDx_HashFunction(64, false, false),
   m_X(8),
   m_digest(3),
   m_hash_len(hash_len),
   m_passes(passes)
   {
   if(output_length() != 16 && output_length() != 20 && output_length() != 24)
      throw Invalid_Argument("Tiger: Illegal hash output size: " +
                             std::to_string(output_length()));

   if(passes < 3)
      throw Invalid_Argument("Tiger: Invalid number of passes: "
                             + std::to_string(passes));
   clear();
   }

}
