/*
* CAST-128
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_CAST128_H__
#define BOTAN_CAST128_H__

#include <botan/block_cipher.h>

namespace Botan {

/*
* CAST-128
*/
class BOTAN_DLL CAST_128 : public BlockCipher
   {
   public:
      void clear() throw() { MK.clear(); RK.clear(); }
      std::string name() const { return "CAST-128"; }
      BlockCipher* clone() const { return new CAST_128; }
      CAST_128() : BlockCipher(8, 11, 16) {}
   private:
      void enc(const byte[], byte[]) const;
      void dec(const byte[], byte[]) const;
      void key_schedule(const byte[], u32bit);

      static void key_schedule(u32bit[16], u32bit[4]);

      static const u32bit S5[256];
      static const u32bit S6[256];
      static const u32bit S7[256];
      static const u32bit S8[256];

      SecureBuffer<u32bit, 16> MK, RK;
   };

extern const u32bit CAST_SBOX1[256];
extern const u32bit CAST_SBOX2[256];
extern const u32bit CAST_SBOX3[256];
extern const u32bit CAST_SBOX4[256];

}

#endif
