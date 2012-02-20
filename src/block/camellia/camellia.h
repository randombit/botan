/*
* Camellia
* (C) 2012 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_CAMELLIA_H__
#define BOTAN_CAMELLIA_H__

#include <botan/block_cipher.h>

namespace Botan {

/**
* Camellia
*/
class BOTAN_DLL Camellia : public Block_Cipher_Fixed_Params<16, 16, 32, 8>
   {
   public:
      void encrypt_n(const byte in[], byte out[], size_t blocks) const;
      void decrypt_n(const byte in[], byte out[], size_t blocks) const;

      void clear() { SK.clear(); }
      std::string name() const { return "Camellia"; }
      BlockCipher* clone() const { return new Camellia; }
   private:
      void key_schedule(const byte key[], size_t length);

      SecureVector<u64bit> SK;
   };

}

#endif
