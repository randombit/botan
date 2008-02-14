/*************************************************
* Square Header File                             *
* (C) 1999-2008 The Botan Project                *
*************************************************/

#ifndef BOTAN_SQUARE_H__
#define BOTAN_SQUARE_H__

#include <botan/base.h>

namespace Botan {

/*************************************************
* Square                                         *
*************************************************/
class Square : public BlockCipher
   {
   public:
      void clear() throw();
      std::string name() const { return "Square"; }
      BlockCipher* clone() const { return new Square; }
      Square() : BlockCipher(16, 16) {}
   private:
      void enc(const byte[], byte[]) const;
      void dec(const byte[], byte[]) const;
      void key(const byte[], u32bit);

      static void transform(u32bit[4]);

      static const byte SE[256], SD[256], Log[256], ALog[255];
      static const u32bit TE0[256], TE1[256], TE2[256], TE3[256],
                          TD0[256], TD1[256], TD2[256], TD3[256];

      SecureBuffer<u32bit, 28> EK, DK;
      SecureBuffer<byte, 32> ME, MD;
   };

}

#endif
