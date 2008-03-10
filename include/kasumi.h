/*************************************************
* KASUMI Header File                             *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#ifndef BOTAN_KASUMI_H__
#define BOTAN_KASUMI_H__

#include <botan/base.h>

namespace Botan {

/*************************************************
* KASUMI                                         *
*************************************************/
class KASUMI : public BlockCipher
   {
   public:
      void clear() throw() { EK.clear(); }
      std::string name() const { return "KASUMI"; }
      BlockCipher* clone() const { return new KASUMI; }

      KASUMI() : BlockCipher(8, 16) {}
   private:
      void enc(const byte[], byte[]) const;
      void dec(const byte[], byte[]) const;
      void key(const byte[], u32bit);

      SecureBuffer<u16bit, 64> EK;
   };

extern const byte KASUMI_SBOX_S7[128];
extern const u16bit KASUMI_SBOX_S9[512];


}

#endif
