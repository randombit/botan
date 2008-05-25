
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

class ECB_Encryption_ErrorCheck : public Filter
   {
   public:
      void write(const byte[], u32bit);
      void end_msg();
      ECB_Encryption_ErrorCheck(const std::string& cipher_name,
                                const std::string&,
                                const SymmetricKey& key) :
         BLOCKSIZE(block_size_of(cipher_name))
         {
         const std::string HASH = "SHA-1";

         cipher = BlockCipher::AutoBlockCipherPtr(get_block_cipher(cipher_name).release());
         input_hash = HashFunction::AutoHashFunctionPtr(get_hash(HASH).release());
         decrypt_hash = HashFunction::AutoHashFunctionPtr(get_hash(HASH).release());
         buffer.create(BLOCKSIZE);
         cipher->set_key(key);
         position = 0;
         }
      ~ECB_Encryption_ErrorCheck()
         { }
   private:
      const u32bit BLOCKSIZE;
      BlockCipher::AutoBlockCipherPtr cipher;
      SecureVector<byte> buffer;
      u32bit position;
      HashFunction::AutoHashFunctionPtr input_hash, decrypt_hash;
   };

void ECB_Encryption_ErrorCheck::write(const byte input[], u32bit length)
   {
   input_hash->update(input, length);
   buffer.copy(position, input, length);
   if(position + length >= BLOCKSIZE)
      {
      cipher->encrypt(buffer);
      send(buffer, BLOCKSIZE);
      cipher->decrypt(buffer);
      decrypt_hash->update(buffer, BLOCKSIZE);
      input += (BLOCKSIZE - position);
      length -= (BLOCKSIZE - position);
      while(length >= BLOCKSIZE)
         {
         cipher->encrypt(input, buffer);
         send(buffer, BLOCKSIZE);
         cipher->decrypt(buffer);
         decrypt_hash->update(buffer, BLOCKSIZE);
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
      throw Exception("ECB: input was not in full blocks");
   }

Filter::AutoFilterPtr lookup_block(const std::string& algname, const std::string& key)
   {
   Filter::AutoFilterPtr cipher;
   try {
      cipher = create_auto_ptr<ECB_Encryption_ErrorCheck>(algname, "NoPadding", key);
      }
   catch(Algorithm_Not_Found) {}

   return cipher;
   }
