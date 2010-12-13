/*
* (C) 2009 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/


/*
  We don't use the standard issue ECB filter, because we also want to check
  that the encryption and decryption operations are inverses (ie, it works).

  This class only works with NoPadding mode, unlike the regular ECB filters
*/

#include <iostream>
#include <string>
#include <cstdlib>
#include <botan/filter.h>
#include <botan/lookup.h>
using namespace Botan;

#include "common.h"

class ECB_Encryption_ErrorCheck : public Filter
   {
   public:
      std::string name() const
         { return "ECB_ErrCheck(" + cipher->name() + ")"; }

      void write(const byte[], size_t);

      void end_msg();

      ECB_Encryption_ErrorCheck(const std::string& cipher_name,
                                const std::string&,
                                const SymmetricKey& key) :
         BLOCKSIZE(block_size_of(cipher_name))
         {
         const std::string HASH = "CRC32";

         cipher = get_block_cipher(cipher_name);
         input_hash = get_hash(HASH);
         decrypt_hash = get_hash(HASH);
         buffer.resize(BLOCKSIZE);
         cipher->set_key(key);
         position = 0;
         }

      ~ECB_Encryption_ErrorCheck()
         {
         delete cipher;
         delete input_hash;
         delete decrypt_hash;
         }

   private:
      const size_t BLOCKSIZE;
      BlockCipher* cipher;
      SecureVector<byte> buffer;
      size_t position;
      HashFunction* input_hash, *decrypt_hash;
   };

void ECB_Encryption_ErrorCheck::write(const byte input[], size_t length)
   {
   input_hash->update(input, length);
   buffer.copy(position, input, length);
   if(position + length >= BLOCKSIZE)
      {
      cipher->encrypt(buffer);
      send(buffer, BLOCKSIZE);
      cipher->decrypt(buffer);
      decrypt_hash->update(&buffer[0], BLOCKSIZE);
      input += (BLOCKSIZE - position);
      length -= (BLOCKSIZE - position);
      while(length >= BLOCKSIZE)
         {
         cipher->encrypt(input, &buffer[0]);
         send(buffer, BLOCKSIZE);
         cipher->decrypt(buffer);
         decrypt_hash->update(&buffer[0], BLOCKSIZE);
         input += BLOCKSIZE;
         length -= BLOCKSIZE;
         }
      buffer.copy(input, length);
      position = 0;
      }
   position += length;
   }

void ECB_Encryption_ErrorCheck::end_msg()
   {
   SecureVector<byte> hash1 = input_hash->final();
   SecureVector<byte> hash2 = decrypt_hash->final();

   if(hash1 != hash2)
      {
      std::cout << "In " << cipher->name()
                << " decryption check failed." << std::endl;
      }

   if(position)
      throw Encoding_Error("ECB: input was not in full blocks");
   }

Filter* lookup_block(const std::string& algname, const std::string& key)
   {
   Filter* cipher = 0;
   try {
      cipher = new ECB_Encryption_ErrorCheck(algname, "NoPadding", key);
      }
   catch(Algorithm_Not_Found) {}

   return cipher;
   }
