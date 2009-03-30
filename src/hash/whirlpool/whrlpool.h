/*
* Whirlpool
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_WHIRLPOOL_H__
#define BOTAN_WHIRLPOOL_H__

#include <botan/mdx_hash.h>

namespace Botan {

/*
* Whirlpool
*/
class BOTAN_DLL Whirlpool : public MDx_HashFunction
   {
   public:
      void clear() throw();
      std::string name() const { return "Whirlpool"; }
      HashFunction* clone() const { return new Whirlpool; }
      Whirlpool() : MDx_HashFunction(64, 64, true, true, 32) { clear(); }
   private:
      void compress_n(const byte[], u32bit blocks);
      void copy_out(byte[]);

      static const u64bit C0[256];
      static const u64bit C1[256];
      static const u64bit C2[256];
      static const u64bit C3[256];
      static const u64bit C4[256];
      static const u64bit C5[256];
      static const u64bit C6[256];
      static const u64bit C7[256];
      SecureBuffer<u64bit, 8> M, digest;
   };

}

#endif
