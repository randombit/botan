/*
* Twofish
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_TWOFISH_H__
#define BOTAN_TWOFISH_H__

#include <botan/block_cipher.h>

namespace Botan {

/**
* Twofish, an AES finalist
*/
class BOTAN_DLL Twofish : public BlockCipher
   {
   public:
      void encrypt_n(const byte in[], byte out[], u32bit blocks) const;
      void decrypt_n(const byte in[], byte out[], u32bit blocks) const;

      void clear();
      std::string name() const { return "Twofish"; }
      BlockCipher* clone() const { return new Twofish; }

      Twofish() : BlockCipher(16, 16, 32, 8) {}
   private:
      void key_schedule(const byte[], u32bit);

      static void rs_mul(byte[4], byte, u32bit);

      static const u32bit MDS0[256];
      static const u32bit MDS1[256];
      static const u32bit MDS2[256];
      static const u32bit MDS3[256];
      static const byte Q0[256];
      static const byte Q1[256];
      static const byte RS[32];
      static const byte EXP_TO_POLY[255];
      static const byte POLY_TO_EXP[255];

      SecureVector<u32bit, 256> SBox0, SBox1, SBox2, SBox3;
      SecureVector<u32bit, 40> round_key;
   };

}

#endif
