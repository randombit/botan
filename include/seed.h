/*************************************************
* SEED Header File                               *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#ifndef BOTAN_SEED_H__
#define BOTAN_SEED_H__

#include <botan/base.h>

namespace Botan {

/*************************************************
* SEED                                           *
*************************************************/
class SEED : public BlockCipher
   {
   public:
      void clear() throw() { K.clear(); }
      std::string name() const { return "SEED"; }
      AutoBlockCipherPtr clone() const { return AutoBlockCipherPtr(new SEED); }
      SEED() : BlockCipher(16, 16) {}
   private:
      void enc(const byte[], byte[]) const;
      void dec(const byte[], byte[]) const;
      void key(const byte[], u32bit);

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
