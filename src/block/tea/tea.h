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

/*
* TEA
*/
class BOTAN_DLL TEA : public BlockCipher
   {
   public:
      void encrypt_n(const byte in[], byte out[], u32bit blocks) const;
      void decrypt_n(const byte in[], byte out[], u32bit blocks) const;

      void clear() { K.clear(); }
      std::string name() const { return "TEA"; }
      BlockCipher* clone() const { return new TEA; }

      TEA() : BlockCipher(8, 16) {}
   private:
      void key_schedule(const byte[], u32bit);
      SecureVector<u32bit, 4> K;
   };

}

#endif
