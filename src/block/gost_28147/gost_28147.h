/*
* GOST 28147-89
* (C) 1999-2009 Jack Lloyd
*/

#ifndef BOTAN_GOST_28147_89_H__
#define BOTAN_GOST_28147_89_H__

#include <botan/block_cipher.h>

namespace Botan {

/**
* GOST 28147-89
*/
class BOTAN_DLL GOST_28147_89 : public BlockCipher
   {
   public:
      void clear() throw() { EK.clear(); }

      std::string name() const { return "GOST-28147-89"; }
      BlockCipher* clone() const { return new GOST_28147_89; }

      GOST_28147_89();
   private:
      void enc(const byte[], byte[]) const;
      void dec(const byte[], byte[]) const;
      void key_schedule(const byte[], u32bit);

      SecureBuffer<u32bit, 1024> SBOX;
      SecureBuffer<u32bit, 32> EK;
   };

}

#endif
