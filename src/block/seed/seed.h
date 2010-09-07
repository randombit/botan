/*
* SEED
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_SEED_H__
#define BOTAN_SEED_H__

#include <botan/block_cipher.h>

namespace Botan {

/**
* SEED, a Korean block cipher
*/
class BOTAN_DLL SEED : public BlockCipher
   {
   public:
      void encrypt_n(const byte in[], byte out[], u32bit blocks) const;
      void decrypt_n(const byte in[], byte out[], u32bit blocks) const;

      void clear() { zeroise(K); }
      std::string name() const { return "SEED"; }
      BlockCipher* clone() const { return new SEED; }

      SEED() : BlockCipher(16, 16) {}
   private:
      void key_schedule(const byte[], u32bit);

      class G_FUNC
         {
         public:
            u32bit operator()(u32bit) const;
         private:
            static const u32bit S0[256], S1[256], S2[256], S3[256];
         };

      SecureVector<u32bit, 32> K;
   };

}

#endif
