/*
* Noekeon
* (C) 1999-2008 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_NOEKEON_H__
#define BOTAN_NOEKEON_H__

#include <botan/block_cipher.h>

namespace Botan {

/*
* Noekeon
*/
class BOTAN_DLL Noekeon : public BlockCipher
   {
   public:
      void clear() throw();
      std::string name() const { return "Noekeon"; }
      BlockCipher* clone() const { return new Noekeon; }
      Noekeon() : BlockCipher(16, 16) {}
   private:
      void enc(const byte[], byte[]) const;
      void dec(const byte[], byte[]) const;
      void key_schedule(const byte[], u32bit);

      static const byte RC[17];

      SecureBuffer<u32bit, 4> EK, DK;
   };

}

#endif
