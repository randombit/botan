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
      void clear() throw() { EK.clear(); }
      std::string name() const { return "XTEA"; }
      BlockCipher* clone() const { return new XTEA; }
      XTEA() : BlockCipher(8, 16) {}
   private:
      void enc(const byte[], byte[]) const;
      void dec(const byte[], byte[]) const;
      void key_schedule(const byte[], u32bit);
      SecureBuffer<u32bit, 64> EK;
   };

}

#endif
