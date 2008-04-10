/*************************************************
* MISTY1 Header File                             *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#ifndef BOTAN_MISTY1_H__
#define BOTAN_MISTY1_H__

#include <botan/base.h>

namespace Botan {

/*************************************************
* MISTY1                                         *
*************************************************/
class MISTY1 : public BlockCipher
   {
   public:
      void clear() throw() { EK.clear(); DK.clear(); }
      std::string name() const { return "MISTY1"; }
      BlockCipher* clone() const { return new MISTY1; }
      MISTY1(u32bit = 8);
   private:
      void enc(const byte[], byte[]) const;
      void dec(const byte[], byte[]) const;
      void key(const byte[], u32bit);

      static const byte EK_ORDER[100], DK_ORDER[100];
      SecureBuffer<u16bit, 100> EK, DK;
   };

extern const byte MISTY1_SBOX_S7[128];
extern const u16bit MISTY1_SBOX_S9[512];


}

#endif
