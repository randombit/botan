/*
* SHA-{224,256}
* (C) 1999-2010 Jack Lloyd
*     2007 FlexSecure GmbH
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_SHA_224_256_H__
#define BOTAN_SHA_224_256_H__

#include <botan/mdx_hash.h>

namespace Botan {

/**
* SHA-224
*/
class BOTAN_DLL SHA_224 : public MDx_HashFunction
   {
   public:
      void clear();
      std::string name() const { return "SHA-224"; }
      HashFunction* clone() const { return new SHA_224; }

      SHA_224() : MDx_HashFunction(28, 64, true, true), W(64), digest(8)
         { clear(); }
   private:
      void compress_n(const byte[], u32bit blocks);
      void copy_out(byte[]);

      SecureVector<u32bit> W, digest;
   };

/**
* SHA-256
*/
class BOTAN_DLL SHA_256 : public MDx_HashFunction
   {
   public:
      void clear();
      std::string name() const { return "SHA-256"; }
      HashFunction* clone() const { return new SHA_256; }

      SHA_256() : MDx_HashFunction(32, 64, true, true), W(64), digest(8)
         { clear(); }
   private:
      void compress_n(const byte[], u32bit blocks);
      void copy_out(byte[]);

      SecureVector<u32bit> W, digest;
   };

}

#endif
