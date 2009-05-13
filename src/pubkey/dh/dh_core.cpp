/*
* PK Algorithm Core
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/dh_core.h>
#include <botan/numthry.h>
#include <botan/pk_engine.h>
#include <botan/parsing.h>
#include <algorithm>

namespace Botan {

namespace {

const u32bit BLINDING_BITS = BOTAN_PRIVATE_KEY_OP_BLINDING_BITS;

}

/*
* DH_Core Constructor
*/
DH_Core::DH_Core(RandomNumberGenerator& rng,
                 const DL_Group& group, const BigInt& x)
   {
   op = Engine_Core::dh_op(group, x);

   const BigInt& p = group.get_p();

   BigInt k(rng, std::min(p.bits()-1, BLINDING_BITS));

   if(k != 0)
      blinder = Blinder(k, power_mod(inverse_mod(k, p), x, p), p);
   }

/*
* DH_Core Copy Constructor
*/
DH_Core::DH_Core(const DH_Core& core)
   {
   op = 0;
   if(core.op)
      op = core.op->clone();
   blinder = core.blinder;
   }

/*
* DH_Core Assignment Operator
*/
DH_Core& DH_Core::operator=(const DH_Core& core)
   {
   delete op;
   if(core.op)
      op = core.op->clone();
   blinder = core.blinder;
   return (*this);
   }

/*
* DH Operation
*/
BigInt DH_Core::agree(const BigInt& i) const
   {
   return blinder.unblind(op->agree(blinder.blind(i)));
   }

}
