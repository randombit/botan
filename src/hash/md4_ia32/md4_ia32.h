/*************************************************
* MD4 (IA-32) Header File                        *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#ifndef BOTAN_MD4_IA32_H__
#define BOTAN_MD4_IA32_H__

#include <botan/md4.h>

namespace Botan {

/*************************************************
* MD4                                            *
*************************************************/
class BOTAN_DLL MD4_IA32 : public MD4
   {
   public:
      HashFunction* clone() const { return new MD4_IA32; }
   private:
      void compress_n(const byte[], u32bit blocks);
   };

}

#endif
