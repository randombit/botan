/*
* MD4 (x86-32)
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_MD4_X86_32_H__
#define BOTAN_MD4_X86_32_H__

#include <botan/md4.h>

namespace Botan {

/**
* MD4 using x86 assembly
*/
class BOTAN_DLL MD4_X86_32 : public MD4
   {
   public:
      HashFunction* clone() const { return new MD4_X86_32; }
   private:
      void compress_n(const byte[], size_t blocks);
   };

}

#endif
