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

/*
* RC5
*/
class BOTAN_DLL RC5 : public BlockCipher
   {
   public:
      void encrypt_n(const byte in[], byte out[], u32bit blocks) const;
      void decrypt_n(const byte in[], byte out[], u32bit blocks) const;

      void clear() { S.clear(); }
      std::string name() const;
      BlockCipher* clone() const { return new RC5(ROUNDS); }

      RC5(u32bit);
   private:
      void key_schedule(const byte[], u32bit);
      SecureVector<u32bit> S;
      const u32bit ROUNDS;
   };

}

#endif
