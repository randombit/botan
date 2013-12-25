/*
* ElGamal
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/elgamal.h>
#include <botan/numthry.h>
#include <botan/keypair.h>
#include <botan/internal/workfactor.h>

namespace Botan {

/*
* ElGamal_PublicKey Constructor
*/
ElGamal_PublicKey::ElGamal_PublicKey(const DL_Group& grp, const BigInt& y1)
   {
   group = grp;
   y = y1;
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

   if(x_arg == 0)
      gen_check(rng);
   else
      load_check(rng);
   }

ElGamal_PrivateKey::ElGamal_PrivateKey(const AlgorithmIdentifier& alg_id,
                                       const secure_vector<byte>& key_bits,
                                       RandomNumberGenerator& rng) :
   DL_Scheme_PrivateKey(alg_id, key_bits, DL_Group::ANSI_X9_42)
   {
   y = power_mod(group_g(), x, group_p());
   load_check(rng);
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

   return KeyPair::encryption_consistency_check(rng, *this, "EME1(SHA-1)");
   }

ElGamal_Encryption_Operation::ElGamal_Encryption_Operation(const ElGamal_PublicKey& key)
   {
   const BigInt& p = key.group_p();

   powermod_g_p = Fixed_Base_Power_Mod(key.group_g(), p);
   powermod_y_p = Fixed_Base_Power_Mod(key.get_y(), p);
   mod_p = Modular_Reducer(p);
   }

secure_vector<byte>
ElGamal_Encryption_Operation::encrypt(const byte msg[], size_t msg_len,
                                      RandomNumberGenerator& rng)
   {
   const BigInt& p = mod_p.get_modulus();

   BigInt m(msg, msg_len);

   if(m >= p)
      throw Invalid_Argument("ElGamal encryption: Input is too large");

   BigInt k(rng, 2 * dl_work_factor(p.bits()));

   BigInt a = powermod_g_p(k);
   BigInt b = mod_p.multiply(m, powermod_y_p(k));

   secure_vector<byte> output(2*p.bytes());
   a.binary_encode(&output[p.bytes() - a.bytes()]);
   b.binary_encode(&output[output.size() / 2 + (p.bytes() - b.bytes())]);
   return output;
   }

ElGamal_Decryption_Operation::ElGamal_Decryption_Operation(const ElGamal_PrivateKey& key,
                                                           RandomNumberGenerator& rng)
   {
   const BigInt& p = key.group_p();

   powermod_x_p = Fixed_Exponent_Power_Mod(key.get_x(), p);
   mod_p = Modular_Reducer(p);

   BigInt k(rng, p.bits() - 1);
   blinder = Blinder(k, powermod_x_p(k), p);
   }

secure_vector<byte>
ElGamal_Decryption_Operation::decrypt(const byte msg[], size_t msg_len)
   {
   const BigInt& p = mod_p.get_modulus();

   const size_t p_bytes = p.bytes();

   if(msg_len != 2 * p_bytes)
      throw Invalid_Argument("ElGamal decryption: Invalid message");

   BigInt a(msg, p_bytes);
   BigInt b(msg + p_bytes, p_bytes);

   if(a >= p || b >= p)
      throw Invalid_Argument("ElGamal decryption: Invalid message");

   a = blinder.blind(a);

   BigInt r = mod_p.multiply(b, inverse_mod(powermod_x_p(a), p));

   return BigInt::encode_locked(blinder.unblind(r));
   }

}
