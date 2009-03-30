/*
* SHA-160 (IA-32)
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_SHA_160_IA32_H__
#define BOTAN_SHA_160_IA32_H__

#include <botan/sha160.h>

namespace Botan {

/*
* SHA-160
*/
class BOTAN_DLL SHA_160_IA32 : public SHA_160
   {
   public:
      HashFunction* clone() const { return new SHA_160_IA32; }

      // Note 81 instead of normal 80: IA-32 asm needs an extra temp
      SHA_160_IA32() : SHA_160(81) {}
   private:
      void compress_n(const byte[], u32bit blocks);
   };

}

#endif
