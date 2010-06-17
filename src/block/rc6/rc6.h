/*
* RC6
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_RC6_H__
#define BOTAN_RC6_H__

#include <botan/block_cipher.h>

namespace Botan {

/**
* RC6, Ron Rivest's AES candidate
*/
class BOTAN_DLL RC6 : public BlockCipher
   {
   public:
      void encrypt_n(const byte in[], byte out[], u32bit blocks) const;
      void decrypt_n(const byte in[], byte out[], u32bit blocks) const;

      void clear() { S.clear(); }
      std::string name() const { return "RC6"; }
      BlockCipher* clone() const { return new RC6; }

      RC6() : BlockCipher(16, 1, 32) {}
   private:
      void key_schedule(const byte[], u32bit);

      SecureVector<u32bit, 44> S;
   };

}

#endif
