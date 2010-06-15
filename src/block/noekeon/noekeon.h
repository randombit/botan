/*
* Noekeon
* (C) 1999-2008 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_NOEKEON_H__
#define BOTAN_NOEKEON_H__

#include <botan/block_cipher.h>

namespace Botan {

/**
* Noekeon
*/
class BOTAN_DLL Noekeon : public BlockCipher
   {
   public:
      void encrypt_n(const byte in[], byte out[], u32bit blocks) const;
      void decrypt_n(const byte in[], byte out[], u32bit blocks) const;

      void clear();
      std::string name() const { return "Noekeon"; }
      BlockCipher* clone() const { return new Noekeon; }

      Noekeon() : BlockCipher(16, 16) {}
   private:
      void key_schedule(const byte[], u32bit);
   protected: // for access by SIMD subclass
      static const byte RC[17];

      SecureVector<u32bit, 4> EK, DK;
   };

}

#endif
