/*
* MD5
* (C) 1999-2008 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_MD5_H__
#define BOTAN_MD5_H__

#include <botan/mdx_hash.h>

namespace Botan {

/**
* MD5
*/
class BOTAN_DLL MD5 : public MDx_HashFunction
   {
   public:
      void clear();
      std::string name() const { return "MD5"; }
      HashFunction* clone() const { return new MD5; }

      MD5() : MDx_HashFunction(16, 64, false, true), M(16), digest(4)
         { clear(); }
   protected:
      void compress_n(const byte[], size_t blocks);
      void copy_out(byte[]);

      SecureVector<u32bit> M, digest;
   };

}

#endif
