/*
* SHA-{384,512}
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_SHA_64BIT_H__
#define BOTAN_SHA_64BIT_H__

#include <botan/mdx_hash.h>

namespace Botan {

/*
* SHA-{384,512} Base
*/
class BOTAN_DLL SHA_384_512_BASE : public MDx_HashFunction
   {
   protected:
      void clear() throw();

      SHA_384_512_BASE(u32bit out) :
         MDx_HashFunction(out, 128, true, true, 16) {}

      SecureBuffer<u64bit, 8> digest;
   private:
      void compress_n(const byte[], u32bit blocks);
      void copy_out(byte[]);

      SecureBuffer<u64bit, 80> W;
   };

/*
* SHA-384
*/
class BOTAN_DLL SHA_384 : public SHA_384_512_BASE
   {
   public:
      void clear() throw();
      std::string name() const { return "SHA-384"; }
      HashFunction* clone() const { return new SHA_384; }
      SHA_384() : SHA_384_512_BASE(48) { clear(); }
   };

/*
* SHA-512
*/
class BOTAN_DLL SHA_512 : public SHA_384_512_BASE
   {
   public:
      void clear() throw();
      std::string name() const { return "SHA-512"; }
      HashFunction* clone() const { return new SHA_512; }
      SHA_512() : SHA_384_512_BASE(64) { clear(); }
   };

}

#endif
