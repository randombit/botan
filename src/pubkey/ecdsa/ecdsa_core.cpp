/*
* ECDSA Core
* (C) 1999-2007 Jack Lloyd
* (C) 2007 FlexSecure GmbH
*
* Distributed under the terms of the Botan license
*/

#include <botan/ecdsa_core.h>
#include <botan/numthry.h>
#include <botan/pk_engine.h>
#include <botan/parsing.h>
#include <algorithm>

namespace Botan {

/*
* ECDSA Operation
*/
bool ECDSA_Core::verify(const byte signature[], u32bit sig_len,
                        const byte message[], u32bit mess_len) const
   {
   //assert(op.get());
   return op->verify(signature, sig_len, message, mess_len);
   }

SecureVector<byte> ECDSA_Core::sign(const byte message[],
                                    u32bit mess_len,
                                    RandomNumberGenerator& rng) const
   {
   //assert(op.get());
   return op->sign(message, mess_len, rng);
   }

ECDSA_Core& ECDSA_Core::operator=(const ECDSA_Core& core)
   {
   delete op;
   if(core.op)
      op = core.op->clone();
   return (*this);
   }

ECDSA_Core::ECDSA_Core(const ECDSA_Core& core)
   {
   op = 0;
   if(core.op)
      op = core.op->clone();
   }

ECDSA_Core::ECDSA_Core(EC_Domain_Params const& dom_pars, const BigInt& priv_key, PointGFp const& pub_key)
   {
   op = Engine_Core::ecdsa_op(dom_pars, priv_key, pub_key);
   }

}
