/*
* MARS
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_MARS_H__
#define BOTAN_MARS_H__

#include <botan/block_cipher.h>

namespace Botan {

class BOTAN_DLL MARS : public BlockCipher
   {
   public:
      void clear() throw() { EK.clear(); }
      std::string name() const { return "MARS"; }
      BlockCipher* clone() const { return new MARS; }
      MARS() : BlockCipher(16, 16, 32, 4) {}
   private:
      void enc(const byte[], byte[]) const;
      void dec(const byte[], byte[]) const;
      void key_schedule(const byte[], u32bit);

      void encrypt_round(u32bit&, u32bit&, u32bit&, u32bit&, u32bit) const;
      void decrypt_round(u32bit&, u32bit&, u32bit&, u32bit&, u32bit) const;
      static void forward_mix(u32bit&, u32bit&, u32bit&, u32bit&);
      static void reverse_mix(u32bit&, u32bit&, u32bit&, u32bit&);

      static const u32bit SBOX[512];
      SecureBuffer<u32bit, 40> EK;
   };

}

#endif
