/*************************************************
* CAST-128 Header File                           *
* (C) 1999-2006 The Botan Project                *
*************************************************/

#ifndef BOTAN_CAST128_H__
#define BOTAN_CAST128_H__

#include <botan/base.h>

namespace Botan {

/*************************************************
* CAST-128                                       *
*************************************************/
class CAST_128 : public BlockCipher
   {
   public:
      void clear() throw() { MK.clear(); RK.clear(); }
      std::string name() const { return "CAST-128"; }
      BlockCipher* clone() const { return new CAST_128; }
      CAST_128() : BlockCipher(8, 11, 16) {}
   private:
      void enc(const byte[], byte[]) const;
      void dec(const byte[], byte[]) const;
      void key(const byte[], u32bit);

      static void key_schedule(u32bit[16], u32bit[4]);

      static const u32bit S5[256], S6[256], S7[256], S8[256];

      SecureBuffer<u32bit, 16> MK, RK;
   };

extern const u32bit CAST_SBOX1[256];
extern const u32bit CAST_SBOX2[256];
extern const u32bit CAST_SBOX3[256];
extern const u32bit CAST_SBOX4[256];

}

#endif
