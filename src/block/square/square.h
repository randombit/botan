/*
* Square
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_SQUARE_H__
#define BOTAN_SQUARE_H__

#include <botan/block_cipher.h>

namespace Botan {

/**
* Square
*/
class BOTAN_DLL Square : public Block_Cipher_Fixed_Params<16, 16>
   {
   public:
      void encrypt_n(const byte in[], byte out[], size_t blocks) const;
      void decrypt_n(const byte in[], byte out[], size_t blocks) const;

      void clear();
      std::string name() const { return "Square"; }
      BlockCipher* clone() const { return new Square; }

      Square() : EK(28), DK(28), ME(32), MD(32) {}
   private:
      void key_schedule(const byte[], size_t);

      static void transform(u32bit[4]);

      static const byte SE[256];
      static const byte SD[256];
      static const byte Log[256];
      static const byte ALog[255];

      static const u32bit TE0[256];
      static const u32bit TE1[256];
      static const u32bit TE2[256];
      static const u32bit TE3[256];
      static const u32bit TD0[256];
      static const u32bit TD1[256];
      static const u32bit TD2[256];
      static const u32bit TD3[256];

      SecureVector<u32bit> EK, DK;
      SecureVector<byte> ME, MD;
   };

}

#endif
