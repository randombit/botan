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
      void clear() throw() { K.clear(); }
      std::string name() const { return "TEA"; }
      BlockCipher* clone() const { return new TEA; }
      TEA() : BlockCipher(8, 16) {}
   private:
      void enc(const byte[], byte[]) const;
      void dec(const byte[], byte[]) const;
      void key_schedule(const byte[], u32bit);
      SecureBuffer<u32bit, 4> K;
   };

}

#endif
