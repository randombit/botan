/*
* DES
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/desx.h>
#include <botan/internal/xor_buf.h>

namespace Botan {

/*
* DESX Encryption
*/
void DESX::encrypt_n(const byte in[], byte out[], u32bit blocks) const
   {
   for(u32bit i = 0; i != blocks; ++i)
      {
      xor_buf(out, in, K1.begin(), BLOCK_SIZE);
      des.encrypt(out);
      xor_buf(out, K2.begin(), BLOCK_SIZE);

      in += BLOCK_SIZE;
      out += BLOCK_SIZE;
      }
   }

/*
* DESX Decryption
*/
void DESX::decrypt_n(const byte in[], byte out[], u32bit blocks) const
   {
   for(u32bit i = 0; i != blocks; ++i)
      {
      xor_buf(out, in, K2.begin(), BLOCK_SIZE);
      des.decrypt(out);
      xor_buf(out, K1.begin(), BLOCK_SIZE);

      in += BLOCK_SIZE;
      out += BLOCK_SIZE;
      }
   }

/*
* DESX Key Schedule
*/
void DESX::key_schedule(const byte key[], u32bit)
   {
   K1.copy(key, 8);
   des.set_key(key + 8, 8);
   K2.copy(key + 16, 8);
   }

}
