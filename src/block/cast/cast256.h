/*
* CAST-256
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_CAST256_H__
#define BOTAN_CAST256_H__

#include <botan/block_cipher.h>

namespace Botan {

/**
* CAST-256
*/
class BOTAN_DLL CAST_256 : public Block_Cipher_Fixed_Params<16, 4, 32, 4>
   {
   public:
      void encrypt_n(const byte in[], byte out[], size_t blocks) const;
      void decrypt_n(const byte in[], byte out[], size_t blocks) const;

      void clear() { zeroise(MK); zeroise(RK); }
      std::string name() const { return "CAST-256"; }
      BlockCipher* clone() const { return new CAST_256; }

      CAST_256() : MK(48), RK(48) {}
   private:
      void key_schedule(const byte[], size_t);

      static const u32bit KEY_MASK[192];
      static const byte   KEY_ROT[32];

      SecureVector<u32bit> MK;
      SecureVector<byte> RK;
   };

extern const u32bit CAST_SBOX1[256];
extern const u32bit CAST_SBOX2[256];
extern const u32bit CAST_SBOX3[256];
extern const u32bit CAST_SBOX4[256];

}

#endif
