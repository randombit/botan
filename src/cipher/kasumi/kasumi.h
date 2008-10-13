/*************************************************
* KASUMI Header File                             *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#ifndef BOTAN_KASUMI_H__
#define BOTAN_KASUMI_H__

#include <botan/base.h>

namespace Botan {

/*************************************************
* KASUMI                                         *
*************************************************/
class BOTAN_DLL KASUMI : public BlockCipher
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

}

#endif
