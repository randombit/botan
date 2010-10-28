/*
* Skipjack
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_SKIPJACK_H__
#define BOTAN_SKIPJACK_H__

#include <botan/block_cipher.h>

namespace Botan {

/**
* Skipjack, a NSA designed cipher used in Fortezza
*/
class BOTAN_DLL Skipjack : public Block_Cipher_Fixed_Params<8, 10>
   {
   public:
      void encrypt_n(const byte in[], byte out[], size_t blocks) const;
      void decrypt_n(const byte in[], byte out[], size_t blocks) const;

      void clear();
      std::string name() const { return "Skipjack"; }
      BlockCipher* clone() const { return new Skipjack; }

      Skipjack() : FTAB(2560) {}
   private:
      void key_schedule(const byte[], size_t);

      SecureVector<byte> FTAB;
   };

}

#endif
