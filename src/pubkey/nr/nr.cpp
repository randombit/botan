/*
* Nyberg-Rueppel
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/nr.h>
#include <botan/numthry.h>
#include <botan/keypair.h>
#include <botan/look_pk.h>

namespace Botan {

NR_PublicKey::NR_PublicKey(const AlgorithmIdentifier& alg_id,
                           const MemoryRegion<byte>& key_bits) :
   DL_Scheme_PublicKey(alg_id, key_bits, DL_Group::ANSI_X9_57)
   {
   core = NR_Core(group, y);
   }

/*
* NR_PublicKey Constructor
*/
NR_PublicKey::NR_PublicKey(const DL_Group& grp, const BigInt& y1)
   {
   group = grp;
   y = y1;

   core = NR_Core(group, y);
   }

/*
* Nyberg-Rueppel Verification Function
*/
SecureVector<byte> NR_PublicKey::verify(const byte sig[], u32bit sig_len) const
   {
   return core.verify(sig, sig_len);
   }

/*
* Create a NR private key
*/
NR_PrivateKey::NR_PrivateKey(RandomNumberGenerator& rng,
                             const DL_Group& grp,
                             const BigInt& x_arg)
   {
   group = grp;
   x = x_arg;

   if(x == 0)
      x = BigInt::random_integer(rng, 2, group_q() - 1);

   y = power_mod(group_g(), x, group_p());

   core = NR_Core(group, y, x);

   if(x_arg == 0)
      gen_check(rng);
   else
      load_check(rng);
   }

NR_PrivateKey::NR_PrivateKey(const AlgorithmIdentifier& alg_id,
                             const MemoryRegion<byte>& key_bits,
                             RandomNumberGenerator& rng) :
   DL_Scheme_PrivateKey(alg_id, key_bits, DL_Group::ANSI_X9_57)
   {
   y = power_mod(group_g(), x, group_p());

   core = NR_Core(group, y, x);

   load_check(rng);
   }

/*
* Nyberg-Rueppel Signature Operation
*/
SecureVector<byte> NR_PrivateKey::sign(const byte in[], u32bit length,
                                       RandomNumberGenerator& rng) const
   {
   const BigInt& q = group_q();

   BigInt k;
   do
      k.randomize(rng, q.bits());
   while(k >= q);

   return core.sign(in, length, k);
   }

/*
* Check Private Nyberg-Rueppel Parameters
*/
bool NR_PrivateKey::check_key(RandomNumberGenerator& rng, bool strong) const
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

}
