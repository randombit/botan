/*************************************************
* SAFER-SK Header File                           *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#ifndef BOTAN_SAFER_SK_H__
#define BOTAN_SAFER_SK_H__

#include <botan/block_cipher.h>

namespace Botan {

/*************************************************
* SAFER-SK                                       *
*************************************************/
class BOTAN_DLL SAFER_SK : public BlockCipher
   {
   public:
      void clear() throw() { EK.clear(); }
      std::string name() const;
      BlockCipher* clone() const;
      SAFER_SK(u32bit);
   private:
      void enc(const byte[], byte[]) const;
      void dec(const byte[], byte[]) const;
      void key(const byte[], u32bit);

      static const byte EXP[256];
      static const byte LOG[512];
      static const byte BIAS[208];
      static const byte KEY_INDEX[208];
      SecureVector<byte> EK;
      const u32bit ROUNDS;
   };

}

#endif
