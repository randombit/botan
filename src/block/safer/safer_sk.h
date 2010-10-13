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
class BOTAN_DLL SAFER_SK : public BlockCipher_Fixed_Block_Size<8>
   {
   public:
      void encrypt_n(const byte in[], byte out[], size_t blocks) const;
      void decrypt_n(const byte in[], byte out[], size_t blocks) const;

      void clear() { zeroise(EK); }
      std::string name() const;
      BlockCipher* clone() const;

      /**
      * @param rounds the number of rounds to use - must be between 1
      * and 13
      */
      SAFER_SK(size_t rounds);
   private:
      void key_schedule(const byte[], size_t);

      static const byte EXP[256];
      static const byte LOG[512];
      static const byte BIAS[208];
      static const byte KEY_INDEX[208];

      SecureVector<byte> EK;
      const size_t ROUNDS;
   };

}

#endif
