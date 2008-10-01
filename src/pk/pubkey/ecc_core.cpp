/*************************************************
* ECDSA/ECKAEG Core Source File                  *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#include <botan/pk_core.h>
#include <botan/numthry.h>
#include <botan/engine.h>
#include <botan/parsing.h>
#include <algorithm>

namespace Botan {

#if defined(BOTAN_HAS_ECDSA)

/*************************************************
* ECKAEG_Core Constructor                        *
*************************************************/
ECKAEG_Core::ECKAEG_Core(const EC_Domain_Params& dom_pars,
                         const BigInt& priv_key,
                         const PointGFp& pub_key)
   {
   op = Engine_Core::eckaeg_op(dom_pars, priv_key, pub_key);
   }

/*************************************************
* ECKAEG_Core Copy Constructor                   *
*************************************************/
ECKAEG_Core::ECKAEG_Core(const ECKAEG_Core& core)
   {
   op = 0;
   if(core.op)
      op = core.op->clone();
   blinder = core.blinder;
   }

/*************************************************
* ECKAEG_Core Assignment Operator                *
*************************************************/
ECKAEG_Core& ECKAEG_Core::operator=(const ECKAEG_Core& core)
   {
   delete op;
   if(core.op)
      op = core.op->clone();
   blinder = core.blinder;
   return (*this);
   }

/*************************************************
* ECKAEG Operation                               *
*************************************************/
SecureVector<byte> ECKAEG_Core::agree(const PointGFp& otherKey) const
   {
   //assert(op.get());
   return op->agree(otherKey);
   }

/*************************************************
* ECDSA Operation                                *
*************************************************/
bool ECDSA_Core::verify(const byte signature[], u32bit sig_len,
                        const byte message[], u32bit mess_len) const
   {
   //assert(op.get());
   return op->verify(signature, sig_len, message, mess_len);
   }

SecureVector<byte> ECDSA_Core::sign(const byte message[], u32bit mess_len) const
   {
   //assert(op.get());
   return op->sign(message, mess_len);
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
#endif

}
