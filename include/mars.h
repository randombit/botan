/*************************************************
* MARS Header File                               *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#ifndef BOTAN_MARS_H__
#define BOTAN_MARS_H__

#include <botan/base.h>

namespace Botan {

class MARS : public BlockCipher
   {
   public:
      void clear() throw() { EK.clear(); }
      std::string name() const { return "MARS"; }
      BlockCipher* clone() const { return new MARS; }
      MARS() : BlockCipher(16, 16, 32, 4) {}
   private:
      void enc(const byte[], byte[]) const;
      void dec(const byte[], byte[]) const;
      void key(const byte[], u32bit);

      void encrypt_round(u32bit&, u32bit&, u32bit&, u32bit&, u32bit) const;
      void decrypt_round(u32bit&, u32bit&, u32bit&, u32bit&, u32bit) const;
      static void forward_mix(u32bit&, u32bit&, u32bit&, u32bit&);
      static void reverse_mix(u32bit&, u32bit&, u32bit&, u32bit&);

      static const u32bit SBOX[512];
      SecureBuffer<u32bit, 40> EK;
   };

}

#endif
