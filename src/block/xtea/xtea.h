/*
* XTEA
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_XTEA_H__
#define BOTAN_XTEA_H__

#include <botan/block_cipher.h>

namespace Botan {

/*
* XTEA
*/
class BOTAN_DLL XTEA : public BlockCipher
   {
   public:
      void encrypt_n(const byte in[], byte out[], u32bit blocks) const;
      void decrypt_n(const byte in[], byte out[], u32bit blocks) const;

      void clear() throw() { EK.clear(); }
      std::string name() const { return "XTEA"; }
      BlockCipher* clone() const { return new XTEA; }

      XTEA() : BlockCipher(8, 16) {}
   private:
      void key_schedule(const byte[], u32bit);
      SecureBuffer<u32bit, 64> EK;
   };

}

#endif
