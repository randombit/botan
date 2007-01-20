/*************************************************
* Blowfish Header File                           *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#ifndef BOTAN_BLOWFISH_H__
#define BOTAN_BLOWFISH_H__

#include <botan/base.h>

namespace Botan {

/*************************************************
* Blowfish                                       *
*************************************************/
class Blowfish : public BlockCipher
   {
   public:
      void clear() throw();
      std::string name() const { return "Blowfish"; }
      BlockCipher* clone() const { return new Blowfish; }
      Blowfish() : BlockCipher(8, 1, 56) {}
   private:
      void enc(const byte[], byte[]) const;
      void dec(const byte[], byte[]) const;
      void key(const byte[], u32bit);
      void generate_sbox(u32bit[], u32bit, u32bit&, u32bit&) const;

      static const u32bit PBOX[18], SBOX1[256], SBOX2[256],
                                    SBOX3[256], SBOX4[256];

      SecureBuffer<u32bit, 256> S1, S2, S3, S4;
      SecureBuffer<u32bit, 18> P;
   };

}

#endif
