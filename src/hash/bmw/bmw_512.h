/*
* Blue Midnight Wish 512 (Round 2 tweaked)
* (C) 2009 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_BMW_512_H__
#define BOTAN_BMW_512_H__

#include <botan/mdx_hash.h>

namespace Botan {

class BOTAN_DLL BMW_512 : public MDx_HashFunction
   {
   public:
      void clear();
      std::string name() const { return "BMW512"; }
      HashFunction* clone() const { return new BMW_512; }
      BMW_512() : MDx_HashFunction(64, 128, false, true) { clear(); }
   private:
      void compress_n(const byte input[], u32bit blocks);
      void copy_out(byte output[]);

      SecureBuffer<u64bit, 16> H, M;
      SecureBuffer<u64bit, 32> Q;
   };

}

#endif
