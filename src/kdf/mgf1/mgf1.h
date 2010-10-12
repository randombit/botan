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

/**
* MGF1 from PKCS #1 v2.0
*/
class BOTAN_DLL MGF1 : public MGF
   {
   public:
      void mask(const byte[], size_t, byte[], size_t) const;

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
