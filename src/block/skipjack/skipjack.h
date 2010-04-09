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

/*
* Skipjack
*/
class BOTAN_DLL Skipjack : public BlockCipher
   {
   public:
      void encrypt_n(const byte in[], byte out[], u32bit blocks) const;
      void decrypt_n(const byte in[], byte out[], u32bit blocks) const;

      void clear();
      std::string name() const { return "Skipjack"; }
      BlockCipher* clone() const { return new Skipjack; }

      Skipjack() : BlockCipher(8, 10) {}
   private:
      void key_schedule(const byte[], u32bit);

      SecureVector<byte, 2560> FTAB;
   };

}

#endif
