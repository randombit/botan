/*
* ElGamal
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/elgamal.h>
#include <botan/numthry.h>
#include <botan/keypair.h>
#include <botan/look_pk.h>
#include <botan/internal/workfactor.h>

namespace Botan {

/*
* ElGamal_PublicKey Constructor
*/
ElGamal_PublicKey::ElGamal_PublicKey(const DL_Group& grp, const BigInt& y1)
   {
   group = grp;
   y = y1;
   core = ELG_Core(group, y);
   }

/*
* ElGamal Encryption Function
*/
SecureVector<byte>
ElGamal_PublicKey::encrypt(const byte in[], u32bit length,
                           RandomNumberGenerator& rng) const
   {
   BigInt k(rng, 2 * dl_work_factor(group_p().bits()));
   return core.encrypt(in, length, k);
   }

/*
* ElGamal_PrivateKey Constructor
*/
ElGamal_PrivateKey::ElGamal_PrivateKey(RandomNumberGenerator& rng,
                                       const DL_Group& grp,
                                       const BigInt& x_arg)
   {
   group = grp;
   x = x_arg;

   if(x == 0)
      x.randomize(rng, 2 * dl_work_factor(group_p().bits()));

   y = power_mod(group_g(), x, group_p());

   core = ELG_Core(rng, group, y, x);

   if(x_arg == 0)
      gen_check(rng);
   else
      load_check(rng);
   }

ElGamal_PrivateKey::ElGamal_PrivateKey(const AlgorithmIdentifier& alg_id,
                                       const MemoryRegion<byte>& key_bits,
                                       RandomNumberGenerator& rng) :
   DL_Scheme_PrivateKey(alg_id, key_bits, DL_Group::ANSI_X9_42)
   {
   y = power_mod(group_g(), x, group_p());
   core = ELG_Core(rng, group, y, x);
   load_check(rng);
   }

/*
* ElGamal Decryption Function
*/
SecureVector<byte> ElGamal_PrivateKey::decrypt(const byte in[],
                                               u32bit length) const
   {
   return core.decrypt(in, length);
   }

/*
* Check Private ElGamal Parameters
*/
bool ElGamal_PrivateKey::check_key(RandomNumberGenerator& rng,
                                   bool strong) const
   {
   if(!DL_Scheme_PrivateKey::check_key(rng, strong))
      return false;

   if(!strong)
      return true;

   try
      {
      KeyPair::check_key(rng,
                         get_pk_encryptor(*this, "EME1(SHA-1)"),
                         get_pk_decryptor(*this, "EME1(SHA-1)")
         );
      }
   catch(Self_Test_Failure)
      {
      return false;
      }

   return true;
   }

}
