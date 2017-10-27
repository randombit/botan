/*
* DES
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/desx.h>

namespace Botan {

/*
* DESX Encryption
*/
void DESX::encrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const
   {
   verify_key_set(m_K1.empty() == false);

   for(size_t i = 0; i != blocks; ++i)
      {
      xor_buf(out, in, m_K1.data(), BLOCK_SIZE);
      m_des.encrypt(out);
      xor_buf(out, m_K2.data(), BLOCK_SIZE);

      in += BLOCK_SIZE;
      out += BLOCK_SIZE;
      }
   }

/*
* DESX Decryption
*/
void DESX::decrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const
   {
   verify_key_set(m_K1.empty() == false);

   for(size_t i = 0; i != blocks; ++i)
      {
      xor_buf(out, in, m_K2.data(), BLOCK_SIZE);
      m_des.decrypt(out);
      xor_buf(out, m_K1.data(), BLOCK_SIZE);

      in += BLOCK_SIZE;
      out += BLOCK_SIZE;
      }
   }

/*
* DESX Key Schedule
*/
void DESX::key_schedule(const uint8_t key[], size_t)
   {
   m_K1.assign(key, key + 8);
   m_des.set_key(key + 8, 8);
   m_K2.assign(key + 16, key + 24);
   }

void DESX::clear()
   {
   m_des.clear();
   zap(m_K1);
   zap(m_K2);
   }

}
