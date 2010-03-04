/*
* PK Operation Types
* (C) 2010 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_PK_OPERATIONS_H__
#define BOTAN_PK_OPERATIONS_H__

#include <botan/secmem.h>

namespace Botan {

namespace PK_Ops {

/*
* A generic Key Agreement Operation (eg DH or ECDH)
*/
class BOTAN_DLL KA_Operation
   {
   public:
      /*
      * Perform a key agreement operation
      * @param w the other key value
      * @param w_len the length of w in bytes
      * @returns the agreed key
      */
      virtual SecureVector<byte> agree(const byte w[], u32bit w_len) const = 0;

      virtual ~KA_Operation() {}
   };

}

}

#endif
