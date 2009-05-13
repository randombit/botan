/*
* IF Algorithm Core
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/if_core.h>
#include <botan/numthry.h>
#include <botan/pk_engine.h>
#include <botan/parsing.h>
#include <algorithm>

namespace Botan {

namespace {

const u32bit BLINDING_BITS = BOTAN_PRIVATE_KEY_OP_BLINDING_BITS;

}

/*
* IF_Core Constructor
*/
IF_Core::IF_Core(const BigInt& e, const BigInt& n)
   {
   op = Engine_Core::if_op(e, n, 0, 0, 0, 0, 0, 0);
   }


/*
* IF_Core Constructor
*/
IF_Core::IF_Core(RandomNumberGenerator& rng,
                 const BigInt& e, const BigInt& n, const BigInt& d,
                 const BigInt& p, const BigInt& q,
                 const BigInt& d1, const BigInt& d2, const BigInt& c)
   {
   op = Engine_Core::if_op(e, n, d, p, q, d1, d2, c);

   if(BLINDING_BITS)
      {
      BigInt k(rng, std::min(n.bits()-1, BLINDING_BITS));
      blinder = Blinder(power_mod(k, e, n), inverse_mod(k, n), n);
      }
   }

/*
* IF_Core Copy Constructor
*/
IF_Core::IF_Core(const IF_Core& core)
   {
   op = 0;
   if(core.op)
      op = core.op->clone();
   blinder = core.blinder;
   }

/*
* IF_Core Assignment Operator
*/
IF_Core& IF_Core::operator=(const IF_Core& core)
   {
   delete op;
   if(core.op)
      op = core.op->clone();
   blinder = core.blinder;
   return (*this);
   }

/*
* IF Public Operation
*/
BigInt IF_Core::public_op(const BigInt& i) const
   {
   return op->public_op(i);
   }

/*
* IF Private Operation
*/
BigInt IF_Core::private_op(const BigInt& i) const
   {
   return blinder.unblind(op->private_op(blinder.blind(i)));
   }

}
