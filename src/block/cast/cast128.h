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

/**
* CAST-128
*/
class BOTAN_DLL CAST_128 : public Block_Cipher_Fixed_Params<8, 11, 16>
   {
   public:
      void encrypt_n(const byte in[], byte out[], size_t blocks) const;
      void decrypt_n(const byte in[], byte out[], size_t blocks) const;

      void clear() { zeroise(MK); zeroise(RK); }
      std::string name() const { return "CAST-128"; }
      BlockCipher* clone() const { return new CAST_128; }

      CAST_128() : MK(16), RK(16) {}
   private:
      void key_schedule(const byte[], size_t);

      static void cast_ks(MemoryRegion<u32bit>& ks,
                          MemoryRegion<u32bit>& user_key);

      static const u32bit S5[256];
      static const u32bit S6[256];
      static const u32bit S7[256];
      static const u32bit S8[256];

      SecureVector<u32bit> MK, RK;
   };

extern const u32bit CAST_SBOX1[256];
extern const u32bit CAST_SBOX2[256];
extern const u32bit CAST_SBOX3[256];
extern const u32bit CAST_SBOX4[256];

}

#endif
