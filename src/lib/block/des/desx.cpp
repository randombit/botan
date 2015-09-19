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
void DESX::encrypt_n(const byte in[], byte out[], size_t blocks) const
   {
   for(size_t i = 0; i != blocks; ++i)
      {
      xor_buf(out, in, K1.data(), BLOCK_SIZE);
      des.encrypt(out);
      xor_buf(out, K2.data(), BLOCK_SIZE);

      in += BLOCK_SIZE;
      out += BLOCK_SIZE;
      }
   }

/*
* DESX Decryption
*/
void DESX::decrypt_n(const byte in[], byte out[], size_t blocks) const
   {
   for(size_t i = 0; i != blocks; ++i)
      {
      xor_buf(out, in, K2.data(), BLOCK_SIZE);
      des.decrypt(out);
      xor_buf(out, K1.data(), BLOCK_SIZE);

      in += BLOCK_SIZE;
      out += BLOCK_SIZE;
      }
   }

/*
* DESX Key Schedule
*/
void DESX::key_schedule(const byte key[], size_t)
   {
   K1.assign(key, key + 8);
   des.set_key(key + 8, 8);
   K2.assign(key + 16, key + 24);
   }

void DESX::clear()
   {
   des.clear();
   zap(K1);
   zap(K2);
   }

}
