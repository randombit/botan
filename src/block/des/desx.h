/*
* DESX
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_DESX_H__
#define BOTAN_DESX_H__

#include <botan/des.h>

namespace Botan {

/**
* DESX
*/
class BOTAN_DLL DESX : public BlockCipher
   {
   public:
      void encrypt_n(const byte in[], byte out[], u32bit blocks) const;
      void decrypt_n(const byte in[], byte out[], u32bit blocks) const;

      void clear() { des.clear(); K1.clear(); K2.clear(); }
      std::string name() const { return "DESX"; }
      BlockCipher* clone() const { return new DESX; }

      DESX() : BlockCipher(8, 24) {}
   private:
      void key_schedule(const byte[], u32bit);
      SecureVector<byte, 8> K1, K2;
      DES des;
   };

}

#endif
