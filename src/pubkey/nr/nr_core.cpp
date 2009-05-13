/*
* NR Core
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/nr_core.h>
#include <botan/numthry.h>
#include <botan/pk_engine.h>
#include <botan/parsing.h>
#include <algorithm>

namespace Botan {

/*
* NR_Core Constructor
*/
NR_Core::NR_Core(const DL_Group& group, const BigInt& y, const BigInt& x)
   {
   op = Engine_Core::nr_op(group, y, x);
   }

/*
* NR_Core Copy Constructor
*/
NR_Core::NR_Core(const NR_Core& core)
   {
   op = 0;
   if(core.op)
      op = core.op->clone();
   }

/*
* NR_Core Assignment Operator
*/
NR_Core& NR_Core::operator=(const NR_Core& core)
   {
   delete op;
   if(core.op)
      op = core.op->clone();
   return (*this);
   }

/*
* NR Verification Operation
*/
SecureVector<byte> NR_Core::verify(const byte in[], u32bit length) const
   {
   return op->verify(in, length);
   }

/*
* NR Signature Operation
*/
SecureVector<byte> NR_Core::sign(const byte in[], u32bit length,
                                 const BigInt& k) const
   {
   return op->sign(in, length, k);
   }

}
