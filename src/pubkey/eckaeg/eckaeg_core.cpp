/*
* ECKAEG Core
* (C) 1999-2007 Jack Lloyd
* (C) 2007 FlexSecure GmbH
*
* Distributed under the terms of the Botan license
*/

#include <botan/eckaeg_core.h>
#include <botan/numthry.h>
#include <botan/pk_engine.h>
#include <botan/parsing.h>
#include <algorithm>

namespace Botan {

/*
* ECKAEG_Core Constructor
*/
ECKAEG_Core::ECKAEG_Core(const EC_Domain_Params& dom_pars,
                         const BigInt& priv_key,
                         const PointGFp& pub_key)
   {
   op = Engine_Core::eckaeg_op(dom_pars, priv_key, pub_key);
   }

/*
* ECKAEG_Core Copy Constructor
*/
ECKAEG_Core::ECKAEG_Core(const ECKAEG_Core& core)
   {
   op = 0;
   if(core.op)
      op = core.op->clone();
   blinder = core.blinder;
   }

/*
* ECKAEG_Core Assignment Operator
*/
ECKAEG_Core& ECKAEG_Core::operator=(const ECKAEG_Core& core)
   {
   delete op;
   if(core.op)
      op = core.op->clone();
   blinder = core.blinder;
   return (*this);
   }

/*
* ECKAEG Operation
*/
SecureVector<byte> ECKAEG_Core::agree(const PointGFp& otherKey) const
   {
   //assert(op.get());
   return op->agree(otherKey);
   }

}
