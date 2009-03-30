/*
* CTS Mode
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_CTS_H__
#define BOTAN_CTS_H__

#include <botan/modebase.h>
#include <botan/block_cipher.h>

namespace Botan {

/*
* CTS Encryption
*/
class BOTAN_DLL CTS_Encryption : public BlockCipherMode
   {
   public:
      CTS_Encryption(BlockCipher* ciph) :
         BlockCipherMode(ciph, "CTS", ciph->BLOCK_SIZE, 0, 2) {}

      CTS_Encryption(BlockCipher* ciph,
                     const SymmetricKey& key,
                     const InitializationVector& iv) :
         BlockCipherMode(ciph, "CTS", ciph->BLOCK_SIZE, 0, 2)
         { set_key(key); set_iv(iv); }
   private:
      void write(const byte[], u32bit);
      void end_msg();
      void encrypt(const byte[]);
   };

/*
* CTS Decryption
*/
class BOTAN_DLL CTS_Decryption : public BlockCipherMode
   {
   public:
      CTS_Decryption(BlockCipher* ciph) :
         BlockCipherMode(ciph, "CTS", ciph->BLOCK_SIZE, 0, 2)
         { temp.create(BLOCK_SIZE); }

      CTS_Decryption(BlockCipher* ciph,
                     const SymmetricKey& key,
                     const InitializationVector& iv) :
         BlockCipherMode(ciph, "CTS", ciph->BLOCK_SIZE, 0, 2)
         { set_key(key); set_iv(iv); temp.create(BLOCK_SIZE); }
   private:
      void write(const byte[], u32bit);
      void end_msg();
      void decrypt(const byte[]);
      SecureVector<byte> temp;
   };

}

#endif
