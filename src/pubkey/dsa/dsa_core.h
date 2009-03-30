/*
* DSA Core
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_DSA_CORE_H__
#define BOTAN_DSA_CORE_H__

#include <botan/dsa_op.h>
#include <botan/dl_group.h>

namespace Botan {

/*
* DSA Core
*/
class BOTAN_DLL DSA_Core
   {
   public:
      SecureVector<byte> sign(const byte[], u32bit, const BigInt&) const;
      bool verify(const byte[], u32bit, const byte[], u32bit) const;

      DSA_Core& operator=(const DSA_Core&);

      DSA_Core() { op = 0; }
      DSA_Core(const DSA_Core&);
      DSA_Core(const DL_Group&, const BigInt&, const BigInt& = 0);
      ~DSA_Core() { delete op; }
   private:
      DSA_Operation* op;
   };

}

#endif
