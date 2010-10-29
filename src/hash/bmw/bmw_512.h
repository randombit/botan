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

/**
* Blue Midnight Wish 512 (Round 2 tweaked version)
*/
class BOTAN_DLL BMW_512 : public MDx_HashFunction
   {
   public:
      std::string name() const { return "BMW512"; }
      size_t output_length() const { return 64; }
      HashFunction* clone() const { return new BMW_512; }

      void clear();

      BMW_512() : MDx_HashFunction(128, false, true), H(16), M(16), Q(32)
         { clear(); }
   private:
      void compress_n(const byte input[], size_t blocks);
      void copy_out(byte output[]);

      SecureVector<u64bit> H, M, Q;
   };

}

#endif
