/*
* ElGamal Core
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/elg_core.h>
#include <botan/numthry.h>
#include <botan/pk_engine.h>
#include <botan/parsing.h>
#include <algorithm>

namespace Botan {

namespace {

const u32bit BLINDING_BITS = BOTAN_PRIVATE_KEY_OP_BLINDING_BITS;

}

/*
* ELG_Core Constructor
*/
ELG_Core::ELG_Core(const DL_Group& group, const BigInt& y)
   {
   op = Engine_Core::elg_op(group, y, 0);
   p_bytes = 0;
   }

/*
* ELG_Core Constructor
*/
ELG_Core::ELG_Core(RandomNumberGenerator& rng,
                   const DL_Group& group, const BigInt& y, const BigInt& x)
   {
   op = Engine_Core::elg_op(group, y, x);

   const BigInt& p = group.get_p();
   p_bytes = p.bytes();

   if(BLINDING_BITS)
      {
      BigInt k(rng, std::min(p.bits()-1, BLINDING_BITS));
      blinder = Blinder(k, power_mod(k, x, p), p);
      }
   }

/*
* ELG_Core Copy Constructor
*/
ELG_Core::ELG_Core(const ELG_Core& core)
   {
   op = 0;
   if(core.op)
      op = core.op->clone();
   blinder = core.blinder;
   p_bytes = core.p_bytes;
   }

/*
* ELG_Core Assignment Operator
*/
ELG_Core& ELG_Core::operator=(const ELG_Core& core)
   {
   delete op;
   if(core.op)
      op = core.op->clone();
   blinder = core.blinder;
   p_bytes = core.p_bytes;
   return (*this);
   }

/*
* ElGamal Encrypt Operation
*/
SecureVector<byte> ELG_Core::encrypt(const byte in[], u32bit length,
                                     const BigInt& k) const
   {
   return op->encrypt(in, length, k);
   }

/*
* ElGamal Decrypt Operation
*/
SecureVector<byte> ELG_Core::decrypt(const byte in[], u32bit length) const
   {
   if(length != 2*p_bytes)
      throw Invalid_Argument("ELG_Core::decrypt: Invalid message");

   BigInt a(in, p_bytes);
   BigInt b(in + p_bytes, p_bytes);

   return BigInt::encode(blinder.unblind(op->decrypt(blinder.blind(a), b)));
   }

}
