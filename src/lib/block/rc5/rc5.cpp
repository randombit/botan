/*
* RC5
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/rc5.h>
#include <botan/loadstor.h>
#include <botan/parsing.h>

namespace Botan {

/*
* RC5 Encryption
*/
void RC5::encrypt_n(const byte in[], byte out[], size_t blocks) const
   {
   for(size_t i = 0; i != blocks; ++i)
      {
      u32bit A = load_le<u32bit>(in, 0);
      u32bit B = load_le<u32bit>(in, 1);

      A += m_S[0]; B += m_S[1];
      for(size_t j = 0; j != m_rounds; j += 4)
         {
         A = rotate_left(A ^ B, B % 32) + m_S[2*j+2];
         B = rotate_left(B ^ A, A % 32) + m_S[2*j+3];

         A = rotate_left(A ^ B, B % 32) + m_S[2*j+4];
         B = rotate_left(B ^ A, A % 32) + m_S[2*j+5];

         A = rotate_left(A ^ B, B % 32) + m_S[2*j+6];
         B = rotate_left(B ^ A, A % 32) + m_S[2*j+7];

         A = rotate_left(A ^ B, B % 32) + m_S[2*j+8];
         B = rotate_left(B ^ A, A % 32) + m_S[2*j+9];
         }

      store_le(out, A, B);

      in += BLOCK_SIZE;
      out += BLOCK_SIZE;
      }
   }

/*
* RC5 Decryption
*/
void RC5::decrypt_n(const byte in[], byte out[], size_t blocks) const
   {
   for(size_t i = 0; i != blocks; ++i)
      {
      u32bit A = load_le<u32bit>(in, 0);
      u32bit B = load_le<u32bit>(in, 1);

      for(size_t j = m_rounds; j != 0; j -= 4)
         {
         B = rotate_right(B - m_S[2*j+1], A % 32) ^ A;
         A = rotate_right(A - m_S[2*j  ], B % 32) ^ B;

         B = rotate_right(B - m_S[2*j-1], A % 32) ^ A;
         A = rotate_right(A - m_S[2*j-2], B % 32) ^ B;

         B = rotate_right(B - m_S[2*j-3], A % 32) ^ A;
         A = rotate_right(A - m_S[2*j-4], B % 32) ^ B;

         B = rotate_right(B - m_S[2*j-5], A % 32) ^ A;
         A = rotate_right(A - m_S[2*j-6], B % 32) ^ B;
         }
      B -= m_S[1]; A -= m_S[0];

      store_le(out, A, B);

      in += BLOCK_SIZE;
      out += BLOCK_SIZE;
      }
   }

/*
* RC5 Key Schedule
*/
void RC5::key_schedule(const byte key[], size_t length)
   {
   m_S.resize(2*m_rounds + 2);

   const size_t WORD_KEYLENGTH = (((length - 1) / 4) + 1);
   const size_t MIX_ROUNDS     = 3 * std::max(WORD_KEYLENGTH, m_S.size());

   m_S[0] = 0xB7E15163;
   for(size_t i = 1; i != m_S.size(); ++i)
      m_S[i] = m_S[i-1] + 0x9E3779B9;

   secure_vector<u32bit> K(8);

   for(s32bit i = length-1; i >= 0; --i)
      K[i/4] = (K[i/4] << 8) + key[i];

   u32bit A = 0, B = 0;

   for(size_t i = 0; i != MIX_ROUNDS; ++i)
      {
      A = rotate_left(m_S[i % m_S.size()] + A + B, 3);
      B = rotate_left(K[i % WORD_KEYLENGTH] + A + B, (A + B) % 32);
      m_S[i % m_S.size()] = A;
      K[i % WORD_KEYLENGTH] = B;
      }
   }

void RC5::clear()
   {
   zap(m_S);
   }

/*
* Return the name of this type
*/
std::string RC5::name() const
   {
   return "RC5(" + std::to_string(m_rounds) + ")";
   }

/*
* RC5 Constructor
*/
RC5::RC5(size_t r) : m_rounds(r)
   {
   if(m_rounds < 8 || m_rounds > 32 || (m_rounds % 4 != 0))
      throw Invalid_Argument("RC5: Invalid number of rounds " +
                             std::to_string(m_rounds));
   }

}
