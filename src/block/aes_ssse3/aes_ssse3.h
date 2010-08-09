/*
* AES using SSSE3
* (C) 2010 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_AES_SSSE3_H__
#define BOTAN_AES_SSSE3_H__

#include <botan/block_cipher.h>

namespace Botan {

/**
* AES-128 using SSSE3
*/
class BOTAN_DLL AES_128_SSSE3 : public BlockCipher
   {
   public:
      void encrypt_n(const byte in[], byte out[], u32bit blocks) const;
      void decrypt_n(const byte in[], byte out[], u32bit blocks) const;

      void clear();
      std::string name() const { return "AES-128"; }
      BlockCipher* clone() const { return new AES_128_SSSE3; }

      AES_128_SSSE3() : BlockCipher(16, 16) {}
   private:
      void key_schedule(const byte[], u32bit);

      SecureVector<u32bit, 44> EK, DK;
   };

}

#endif
