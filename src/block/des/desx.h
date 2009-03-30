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

/*
* DESX
*/
class BOTAN_DLL DESX : public BlockCipher
   {
   public:
      void clear() throw() { des.clear(); K1.clear(); K2.clear(); }
      std::string name() const { return "DESX"; }
      BlockCipher* clone() const { return new DESX; }
      DESX() : BlockCipher(8, 24) {}
   private:
      void enc(const byte[], byte[]) const;
      void dec(const byte[], byte[]) const;
      void key_schedule(const byte[], u32bit);
      SecureBuffer<byte, 8> K1, K2;
      DES des;
   };

}

#endif
