/*
* IDEA
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_IDEA_H__
#define BOTAN_IDEA_H__

#include <botan/block_cipher.h>

namespace Botan {

/*
* IDEA
*/
class BOTAN_DLL IDEA : public BlockCipher
   {
   public:
      void clear() throw() { EK.clear(); DK.clear(); }
      std::string name() const { return "IDEA"; }
      BlockCipher* clone() const { return new IDEA; }
      IDEA() : BlockCipher(8, 16) {}
   private:
      void enc(const byte[], byte[]) const;
      void dec(const byte[], byte[]) const;
      void key_schedule(const byte[], u32bit);
      SecureBuffer<u16bit, 52> EK, DK;
   };

}

#endif
