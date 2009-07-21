/*
* DSA Core
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/dsa_core.h>
#include <botan/numthry.h>
#include <botan/pk_engine.h>
#include <botan/parsing.h>
#include <algorithm>

namespace Botan {

/*
* DSA_Core Constructor
*/
DSA_Core::DSA_Core(const DL_Group& group, const BigInt& y, const BigInt& x)
   {
   op = Engine_Core::dsa_op(group, y, x);
   }

/*
* DSA_Core Copy Constructor
*/
DSA_Core::DSA_Core(const DSA_Core& core)
   {
   op = 0;
   if(core.op)
      op = core.op->clone();
   }

/*
* DSA_Core Assignment Operator
*/
DSA_Core& DSA_Core::operator=(const DSA_Core& core)
   {
   delete op;
   if(core.op)
      op = core.op->clone();
   return (*this);
   }

/*
* DSA Verification Operation
*/
bool DSA_Core::verify(const byte msg[], u32bit msg_length,
                      const byte sig[], u32bit sig_length) const
   {
   return op->verify(msg, msg_length, sig, sig_length);
   }

/*
* DSA Signature Operation
*/
SecureVector<byte> DSA_Core::sign(const byte in[], u32bit length,
                                  const BigInt& k) const
   {
   return op->sign(in, length, k);
   }

}
