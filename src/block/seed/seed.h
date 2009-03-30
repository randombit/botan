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

/*
* SEED
*/
class BOTAN_DLL SEED : public BlockCipher
   {
   public:
      void clear() throw() { K.clear(); }
      std::string name() const { return "SEED"; }
      BlockCipher* clone() const { return new SEED; }
      SEED() : BlockCipher(16, 16) {}
   private:
      void enc(const byte[], byte[]) const;
      void dec(const byte[], byte[]) const;
      void key_schedule(const byte[], u32bit);

      class G_FUNC
         {
         public:
            u32bit operator()(u32bit) const;
         private:
            static const u32bit S0[256], S1[256], S2[256], S3[256];
         };

      SecureBuffer<u32bit, 32> K;
   };

}

#endif
