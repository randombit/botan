/*************************************************
* MD5 (IA-32) Header File                        *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#ifndef BOTAN_MD5_IA32_H__
#define BOTAN_MD5_IA32_H__

#include <botan/md5.h>

namespace Botan {

/*************************************************
* MD5                                            *
*************************************************/
class BOTAN_DLL MD5_IA32 : public MD5
   {
   public:
      HashFunction* clone() const { return new MD5_IA32; }
   private:
      void compress_n(const byte[], u32bit blocks);
   };

}

#endif
