/**
* MISTY1
* (C) 1999-2008 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_MISTY1_H__
#define BOTAN_MISTY1_H__

#include <botan/block_cipher.h>

namespace Botan {

/**
* MISTY1
*/
class BOTAN_DLL MISTY1 : public BlockCipher
   {
   public:
      void clear() throw() { EK.clear(); DK.clear(); }
      std::string name() const { return "MISTY1"; }
      BlockCipher* clone() const { return new MISTY1; }
      MISTY1(u32bit = 8);
   private:
      void enc(const byte[], byte[]) const;
      void dec(const byte[], byte[]) const;
      void key_schedule(const byte[], u32bit);

      SecureBuffer<u16bit, 100> EK, DK;
   };

}

#endif
