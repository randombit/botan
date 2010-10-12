/*
* MD4
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_MD4_H__
#define BOTAN_MD4_H__

#include <botan/mdx_hash.h>

namespace Botan {

/**
* MD4
*/
class BOTAN_DLL MD4 : public MDx_HashFunction
   {
   public:
      void clear();
      std::string name() const { return "MD4"; }
      HashFunction* clone() const { return new MD4; }

      MD4() : MDx_HashFunction(16, 64, false, true), M(16), digest(4)
         { clear(); }
   protected:
      void compress_n(const byte input[], size_t blocks);
      void copy_out(byte[]);

      SecureVector<u32bit> M, digest;
   };

}

#endif
