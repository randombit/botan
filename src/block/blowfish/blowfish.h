/*
* Blowfish
* (C) 1999-2008 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_BLOWFISH_H__
#define BOTAN_BLOWFISH_H__

#include <botan/block_cipher.h>

namespace Botan {

/*
* Blowfish
*/
class BOTAN_DLL Blowfish : public BlockCipher
   {
   public:
      void clear() throw();
      std::string name() const { return "Blowfish"; }
      BlockCipher* clone() const { return new Blowfish; }
      Blowfish() : BlockCipher(8, 1, 56) {}
   private:
      void enc(const byte[], byte[]) const;
      void dec(const byte[], byte[]) const;
      void key_schedule(const byte[], u32bit);
      void generate_sbox(u32bit[], u32bit, u32bit&, u32bit&) const;

      static const u32bit P_INIT[18];
      static const u32bit S_INIT[1024];

      SecureBuffer<u32bit, 1024> S;
      SecureBuffer<u32bit, 18> P;
   };

}

#endif
