/*************************************************
* GOST Header File                               *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#ifndef BOTAN_GOST_H__
#define BOTAN_GOST_H__

#include <botan/base.h>

namespace Botan {

/*************************************************
* GOST                                           *
*************************************************/
class GOST : public BlockCipher
   {
   public:
      void clear() throw() { EK.clear(); }
      std::string name() const { return "GOST"; }
      BlockCipher* clone() const { return new GOST; }
      GOST() : BlockCipher(8, 32) {}
   private:
      void enc(const byte[], byte[]) const;
      void dec(const byte[], byte[]) const;
      void key(const byte[], u32bit);

      static const u32bit SBOX1[256], SBOX2[256], SBOX3[256], SBOX4[256];

      SecureBuffer<u32bit, 32> EK;
   };

}

#endif
