/*
* MD5 (x86-32)
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_MD5_X86_32_H__
#define BOTAN_MD5_X86_32_H__

#include <botan/md5.h>

namespace Botan {

/**
* MD5 in x86 assembly
*/
class BOTAN_DLL MD5_X86_32 : public MD5
   {
   public:
      HashFunction* clone() const { return new MD5_X86_32; }
   private:
      void compress_n(const byte[], size_t blocks);
   };

}

#endif
