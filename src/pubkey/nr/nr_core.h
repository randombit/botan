/*
* NR Core
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_NR_CORE_H__
#define BOTAN_NR_CORE_H__

#include <botan/nr_op.h>
#include <botan/dl_group.h>

namespace Botan {

/*
* NR Core
*/
class BOTAN_DLL NR_Core
   {
   public:
      SecureVector<byte> sign(const byte[], u32bit, const BigInt&) const;
      SecureVector<byte> verify(const byte[], u32bit) const;

      NR_Core& operator=(const NR_Core&);

      NR_Core() { op = 0; }
      NR_Core(const NR_Core&);
      NR_Core(const DL_Group&, const BigInt&, const BigInt& = 0);
      ~NR_Core() { delete op; }
   private:
      NR_Operation* op;
   };

}

#endif
