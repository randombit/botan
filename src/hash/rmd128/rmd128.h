/*
* RIPEMD-128
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_RIPEMD_128_H__
#define BOTAN_RIPEMD_128_H__

#include <botan/mdx_hash.h>

namespace Botan {

/**
* RIPEMD-128
*/
class BOTAN_DLL RIPEMD_128 : public MDx_HashFunction
   {
   public:
      void clear();
      std::string name() const { return "RIPEMD-128"; }
      HashFunction* clone() const { return new RIPEMD_128; }

      RIPEMD_128() : MDx_HashFunction(16, 64, false, true), M(16), digest(4)
         { clear(); }
   private:
      void compress_n(const byte[], size_t blocks);
      void copy_out(byte[]);

      SecureVector<u32bit> M, digest;
   };

}

#endif
