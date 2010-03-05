/*
* DSA
* (C) 1999-2010 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/dsa.h>
#include <botan/numthry.h>
#include <botan/keypair.h>
#include <botan/look_pk.h>

namespace Botan {

/*
* DSA_PublicKey Constructor
*/
DSA_PublicKey::DSA_PublicKey(const DL_Group& grp, const BigInt& y1)
   {
   group = grp;
   y = y1;
   core = DSA_Core(group, y);
   }

/*
* DSA Verification Function
*/
bool DSA_PublicKey::verify(const byte msg[], u32bit msg_len,
                           const byte sig[], u32bit sig_len) const
   {
   return core.verify(msg, msg_len, sig, sig_len);
   }

/*
* Create a DSA private key
*/
DSA_PrivateKey::DSA_PrivateKey(RandomNumberGenerator& rng,
                               const DL_Group& grp,
                               const BigInt& x_arg)
   {
   group = grp;
   x = x_arg;

   if(x == 0)
      x = BigInt::random_integer(rng, 2, group_q() - 1);

   y = power_mod(group_g(), x, group_p());

   core = DSA_Core(group, y, x);

   if(x_arg == 0)
      gen_check(rng);
   else
      load_check(rng);
   }

DSA_PrivateKey::DSA_PrivateKey(const AlgorithmIdentifier& alg_id,
                               const MemoryRegion<byte>& key_bits,
                               RandomNumberGenerator& rng) :
   DL_Scheme_PrivateKey(alg_id, key_bits, DL_Group::ANSI_X9_57)
   {
   y = power_mod(group_g(), x, group_p());
   core = DSA_Core(group, y, x);

   load_check(rng);
   }

/*
* Check Private DSA Parameters
*/
bool DSA_PrivateKey::check_key(RandomNumberGenerator& rng, bool strong) const
   {
   if(!DL_Scheme_PrivateKey::check_key(rng, strong) || x >= group_q())
      return false;

   if(!strong)
      return true;

   try
      {
      KeyPair::check_key(rng,
                         get_pk_signer(*this, "EMSA1(SHA-1)"),
                         get_pk_verifier(*this, "EMSA1(SHA-1)")
         );
      }
   catch(Self_Test_Failure)
      {
      return false;
      }

   return true;
   }

DSA_Signature_Operation::DSA_Signature_Operation(const DSA_PrivateKey& dsa) :
   q(dsa.group_q()),
   x(dsa.get_x()),
   powermod_g_p(dsa.group_g(), dsa.group_p()),
   mod_q(dsa.group_q())
   {
   }

SecureVector<byte> DSA_Signature_Operation::sign(const byte msg[],
                                                 u32bit msg_len,
                                                 RandomNumberGenerator& rng)
   {
   rng.add_entropy(msg, msg_len);

   BigInt k;
   do
      k.randomize(rng, q.bits());
   while(k >= q);

   BigInt i(msg, msg_len);

   BigInt r = mod_q.reduce(powermod_g_p(k));
   BigInt s = mod_q.multiply(inverse_mod(k, q), mul_add(x, r, i));

   if(r.is_zero() || s.is_zero())
      throw Internal_Error("DSA signature gen failure: r or s was zero");

   SecureVector<byte> output(2*q.bytes());
   r.binary_encode(output + (output.size() / 2 - r.bytes()));
   s.binary_encode(output + (output.size() - s.bytes()));
   return output;
   }

}
