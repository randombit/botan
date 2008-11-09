/*************************************************
* GOST Header File                               *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#ifndef BOTAN_GOST_H__
#define BOTAN_GOST_H__

#include <botan/block_cipher.h>

namespace Botan {

/*************************************************
* GOST                                           *
*************************************************/
class BOTAN_DLL GOST : public BlockCipher
   {
   public:
      void clear() throw() { EK.clear(); }
      std::string name() const { return "GOST"; }
      BlockCipher* clone() const { return new GOST; }
      GOST() : BlockCipher(8, 32) {}
   private:
      void enc(const byte[], byte[]) const;
      void dec(const byte[], byte[]) const;
      void key_schedule(const byte[], u32bit);

      static const u32bit SBOX1[256];
      static const u32bit SBOX2[256];
      static const u32bit SBOX3[256];
      static const u32bit SBOX4[256];

      SecureBuffer<u32bit, 32> EK;
   };

}

#endif
