/*************************************************
* CAST-256 Header File                           *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#ifndef BOTAN_CAST256_H__
#define BOTAN_CAST256_H__

#include <botan/base.h>

namespace Botan {

/*************************************************
* CAST-256                                       *
*************************************************/
class CAST_256 : public BlockCipher
   {
   public:
      void clear() throw() { MK.clear(); RK.clear(); }
      std::string name() const { return "CAST-256"; }
      BlockCipher* clone() const { return new CAST_256; }
      CAST_256() : BlockCipher(16, 4, 32, 4) {}
   private:
      void enc(const byte[], byte[]) const;
      void dec(const byte[], byte[]) const;
      void key(const byte[], u32bit);

      static const u32bit KEY_MASK[192];
      static const byte   KEY_ROT[32];

      SecureBuffer<u32bit, 48> MK;
      SecureBuffer<byte, 48> RK;
   };

extern const u32bit CAST_SBOX1[256];
extern const u32bit CAST_SBOX2[256];
extern const u32bit CAST_SBOX3[256];
extern const u32bit CAST_SBOX4[256];

}

#endif
