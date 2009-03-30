/*
* MGF1
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_MGF1_H__
#define BOTAN_MGF1_H__

#include <botan/kdf.h>
#include <botan/hash.h>

namespace Botan {

/*
* MGF1 (Mask Generation Function)
*/
class BOTAN_DLL MGF1 : public MGF
   {
   public:
      void mask(const byte[], u32bit, byte[], u32bit) const;

      /**
      MGF1 constructor: takes ownership of hash
      */
      MGF1(HashFunction* hash);

      ~MGF1();
   private:
      HashFunction* hash;
   };

}

#endif
