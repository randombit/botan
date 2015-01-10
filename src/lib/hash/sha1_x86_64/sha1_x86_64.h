/*
* SHA-160 (x86-64)
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_SHA_160_X86_64_H__
#define BOTAN_SHA_160_X86_64_H__

#include <botan/sha160.h>

namespace Botan {

/**
* SHA-160 in x86-64 assembly
*/
class BOTAN_DLL SHA_160_X86_64 : public SHA_160
   {
   public:
      HashFunction* clone() const { return new SHA_160_X86_64; }
   private:
      void compress_n(const byte[], size_t blocks);
   };

}

#endif
