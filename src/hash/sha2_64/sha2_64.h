/*
* SHA-{384,512}
* (C) 1999-2010 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_SHA_64BIT_H__
#define BOTAN_SHA_64BIT_H__

#include <botan/mdx_hash.h>

namespace Botan {

/**
* SHA-384
*/
class BOTAN_DLL SHA_384 : public MDx_HashFunction
   {
   public:
      void clear();
      std::string name() const { return "SHA-384"; }
      HashFunction* clone() const { return new SHA_384; }

      SHA_384() : MDx_HashFunction(48, 128, true, true, 16), W(80), digest(8)
         { clear(); }
   private:
      void compress_n(const byte[], size_t blocks);
      void copy_out(byte[]);

      SecureVector<u64bit> W, digest;
   };

/**
* SHA-512
*/
class BOTAN_DLL SHA_512 : public MDx_HashFunction
   {
   public:
      void clear();
      std::string name() const { return "SHA-512"; }
      HashFunction* clone() const { return new SHA_512; }
      SHA_512() : MDx_HashFunction(64, 128, true, true, 16), W(80), digest(8)
         { clear(); }
   private:
      void compress_n(const byte[], size_t blocks);
      void copy_out(byte[]);

      SecureVector<u64bit> W, digest;
   };

}

#endif
