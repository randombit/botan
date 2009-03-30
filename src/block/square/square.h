/*
* Square
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_SQUARE_H__
#define BOTAN_SQUARE_H__

#include <botan/block_cipher.h>

namespace Botan {

/*
* Square
*/
class BOTAN_DLL Square : public BlockCipher
   {
   public:
      void clear() throw();
      std::string name() const { return "Square"; }
      BlockCipher* clone() const { return new Square; }
      Square() : BlockCipher(16, 16) {}
   private:
      void enc(const byte[], byte[]) const;
      void dec(const byte[], byte[]) const;
      void key_schedule(const byte[], u32bit);

      static void transform(u32bit[4]);

      static const byte SE[256];
      static const byte SD[256];
      static const byte Log[256];
      static const byte ALog[255];

      static const u32bit TE0[256];
      static const u32bit TE1[256];
      static const u32bit TE2[256];
      static const u32bit TE3[256];
      static const u32bit TD0[256];
      static const u32bit TD1[256];
      static const u32bit TD2[256];
      static const u32bit TD3[256];

      SecureBuffer<u32bit, 28> EK, DK;
      SecureBuffer<byte, 32> ME, MD;
   };

}

#endif
