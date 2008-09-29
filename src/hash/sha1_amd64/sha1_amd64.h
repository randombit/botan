/*************************************************
* SHA-160 (x86-64) Header File                   *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#ifndef BOTAN_SHA_160_AMD64_H__
#define BOTAN_SHA_160_AMD64_H__

#include <botan/sha160.h>

namespace Botan {

/*************************************************
* SHA-160                                        *
*************************************************/
class BOTAN_DLL SHA_160_AMD64 : public SHA_160
   {
   public:
      HashFunction* clone() const { return new SHA_160_AMD64; }
   private:
      void hash(const byte[]);
   };

}

#endif
