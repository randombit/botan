/*************************************************
* Twofish Header File                            *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#ifndef BOTAN_TWOFISH_H__
#define BOTAN_TWOFISH_H__

#include <botan/base.h>

namespace Botan {

/*************************************************
* Twofish                                        *
*************************************************/
class Twofish : public BlockCipher
   {
   public:
      void clear() throw();
      std::string name() const { return "Twofish"; }
      BlockCipher* clone() const { return new Twofish; }
      Twofish() : BlockCipher(16, 16, 32, 8) {}
   private:
      void enc(const byte[], byte[]) const;
      void dec(const byte[], byte[]) const;
      void key(const byte[], u32bit);

      static void rs_mul(byte[4], byte, u32bit);

      static const u32bit MDS0[256], MDS1[256], MDS2[256], MDS3[256];
      static const byte Q0[256], Q1[256], RS[32];
      static const byte EXP_TO_POLY[255], POLY_TO_EXP[255];

      SecureBuffer<u32bit, 256> SBox0, SBox1, SBox2, SBox3;
      SecureBuffer<u32bit, 40> round_key;
   };

}

#endif
