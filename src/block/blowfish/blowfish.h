/*
* Blowfish
* (C) 1999-2009 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_BLOWFISH_H__
#define BOTAN_BLOWFISH_H__

#include <botan/block_cipher.h>

namespace Botan {

/**
* Blowfish
*/
class BOTAN_DLL Blowfish : public BlockCipher
   {
   public:
      void encrypt_n(const byte in[], byte out[], size_t blocks) const;
      void decrypt_n(const byte in[], byte out[], size_t blocks) const;

      void clear();
      std::string name() const { return "Blowfish"; }
      BlockCipher* clone() const { return new Blowfish; }

      Blowfish() : BlockCipher(8, 1, 56), S(1024), P(18) {}
   private:
      void key_schedule(const byte[], u32bit);
      void generate_sbox(MemoryRegion<u32bit>& box,
                         u32bit& L, u32bit& R) const;

      static const u32bit P_INIT[18];
      static const u32bit S_INIT[1024];

      SecureVector<u32bit> S;
      SecureVector<u32bit> P;
   };

}

#endif
