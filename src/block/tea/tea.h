/*
* TEA
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_TEA_H__
#define BOTAN_TEA_H__

#include <botan/block_cipher.h>

namespace Botan {

/**
* TEA
*/
class BOTAN_DLL TEA : public BlockCipher
   {
   public:
      void encrypt_n(const byte in[], byte out[], size_t blocks) const;
      void decrypt_n(const byte in[], byte out[], size_t blocks) const;

      void clear() { zeroise(K); }
      std::string name() const { return "TEA"; }
      BlockCipher* clone() const { return new TEA; }

      TEA() : BlockCipher(8, 16), K(4) {}
   private:
      void key_schedule(const byte[], size_t);
      SecureVector<u32bit> K;
   };

}

#endif
