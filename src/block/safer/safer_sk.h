/*
* SAFER-SK
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_SAFER_SK_H__
#define BOTAN_SAFER_SK_H__

#include <botan/block_cipher.h>

namespace Botan {

/**
* SAFER-SK
*/
class BOTAN_DLL SAFER_SK : public BlockCipher
   {
   public:
      void encrypt_n(const byte in[], byte out[], u32bit blocks) const;
      void decrypt_n(const byte in[], byte out[], u32bit blocks) const;

      void clear() { EK.clear(); }
      std::string name() const;
      BlockCipher* clone() const;

      /**
      * @param rounds the number of rounds to use - must be between 1
      * and 13
      */
      SAFER_SK(u32bit rounds);
   private:
      void key_schedule(const byte[], u32bit);

      static const byte EXP[256];
      static const byte LOG[512];
      static const byte BIAS[208];
      static const byte KEY_INDEX[208];

      SecureVector<byte> EK;
      const u32bit ROUNDS;
   };

}

#endif
