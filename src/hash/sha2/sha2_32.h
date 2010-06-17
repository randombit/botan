/*
* SHA-{224,256}
* (C) 1999-2008 Jack Lloyd
*     2007 FlexSecure GmbH
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_SHA_256_H__
#define BOTAN_SHA_256_H__

#include <botan/mdx_hash.h>

namespace Botan {

/**
* Base class for the 32-bit SHA-2 hashes (SHA-224 and SHA-256)
*/
class BOTAN_DLL SHA_224_256_BASE : public MDx_HashFunction
   {
   protected:
      void clear();

      /**
      * @param out output size in bytes
      */
      SHA_224_256_BASE(u32bit out) :
         MDx_HashFunction(out, 64, true, true) { clear(); }

      SecureVector<u32bit, 64> W;
      SecureVector<u32bit, 8> digest;
   private:
      void compress_n(const byte[], u32bit blocks);
      void copy_out(byte[]);
   };

/**
* SHA-224
*/
class BOTAN_DLL SHA_224 : public SHA_224_256_BASE
   {
   public:
      void clear();
      std::string name() const { return "SHA-224"; }
      HashFunction* clone() const { return new SHA_224; }
      SHA_224() : SHA_224_256_BASE(28) { clear(); }
   };

/**
* SHA-256
*/
class BOTAN_DLL SHA_256 : public SHA_224_256_BASE
   {
   public:
      void clear();
      std::string name() const { return "SHA-256"; }
      HashFunction* clone() const { return new SHA_256; }
      SHA_256() : SHA_224_256_BASE(32) { clear (); }
   };

}

#endif
