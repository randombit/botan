/*
* RC5
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_RC5_H__
#define BOTAN_RC5_H__

#include <botan/block_cipher.h>

namespace Botan {

/**
* RC5
*/
class BOTAN_DLL RC5 : public Block_Cipher_Fixed_Params<8, 1, 32>
   {
   public:
      void encrypt_n(const byte in[], byte out[], size_t blocks) const;
      void decrypt_n(const byte in[], byte out[], size_t blocks) const;

      void clear() { zeroise(S); }
      std::string name() const;
      BlockCipher* clone() const { return new RC5(get_rounds()); }

      /**
      * @param rounds the number of RC5 rounds to run. Must be between
      * 8 and 32 and a multiple of 4.
      */
      RC5(size_t rounds);
   private:
      size_t get_rounds() const { return (S.size() - 2) / 2; }

      void key_schedule(const byte[], size_t);

      SecureVector<u32bit> S;
   };

}

#endif
