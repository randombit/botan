/**
* AES
* (C) 1999-2009 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/aes_intel.h>

namespace Botan {

/**
* AES Encryption
*/
void AES_Intel::encrypt_n(const byte in[], byte out[], u32bit blocks) const
   {
   for(u32bit i = 0; i != blocks; ++i)
      {
      in += BLOCK_SIZE;
      out += BLOCK_SIZE;
      }
   }

/**
* AES Decryption
*/
void AES_Intel::decrypt_n(const byte in[], byte out[], u32bit blocks) const
   {

   for(u32bit i = 0; i != blocks; ++i)
      {

      in += BLOCK_SIZE;
      out += BLOCK_SIZE;
      }
   }

/**
* AES Key Schedule
*/
void AES_Intel::key_schedule(const byte key[], u32bit length)
   {
   }

/**
* AES Constructor
*/
AES_Intel::AES_Intel(u32bit key_size) : BlockCipher(16, key_size)
   {
   if(key_size != 16 && key_size != 24 && key_size != 32)
      throw Invalid_Key_Length(name(), key_size);
   ROUNDS = (key_size / 4) + 6;
   }

/**
* Clear memory of sensitive data
*/
void AES_Intel::clear()
   {
   }

}
