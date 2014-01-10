/*
* RSA
* (C) 1999-2010 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/rsa.h>
#include <botan/parsing.h>
#include <botan/numthry.h>
#include <botan/keypair.h>
#include <future>

namespace Botan {

/*
* Create a RSA private key
*/
RSA_PrivateKey::RSA_PrivateKey(RandomNumberGenerator& rng,
                               size_t bits, size_t exp)
   {
   if(bits < 1024)
      throw Invalid_Argument(algo_name() + ": Can't make a key that is only " +
                             std::to_string(bits) + " bits long");
   if(exp < 3 || exp % 2 == 0)
      throw Invalid_Argument(algo_name() + ": Invalid encryption exponent");

   e = exp;

   do
      {
      p = random_prime(rng, (bits + 1) / 2, e);
      q = random_prime(rng, bits - p.bits(), e);
      n = p * q;
      } while(n.bits() != bits);

   d = inverse_mod(e, lcm(p - 1, q - 1));
   d1 = d % (p - 1);
   d2 = d % (q - 1);
   c = inverse_mod(q, p);

   gen_check(rng);
   }

/*
* Check Private RSA Parameters
*/
bool RSA_PrivateKey::check_key(RandomNumberGenerator& rng, bool strong) const
   {
   if(!IF_Scheme_PrivateKey::check_key(rng, strong))
      return false;

   if(!strong)
      return true;

   if((e * d) % lcm(p - 1, q - 1) != 1)
      return false;

   return KeyPair::signature_consistency_check(rng, *this, "EMSA4(SHA-1)");
   }

RSA_Private_Operation::RSA_Private_Operation(const RSA_PrivateKey& rsa,
                                             RandomNumberGenerator& rng) :
   n(rsa.get_n()),
   q(rsa.get_q()),
   c(rsa.get_c()),
   powermod_e_n(rsa.get_e(), rsa.get_n()),
   powermod_d1_p(rsa.get_d1(), rsa.get_p()),
   powermod_d2_q(rsa.get_d2(), rsa.get_q()),
   mod_p(rsa.get_p())
   {
   BigInt k(rng, n.bits() - 1);
   blinder = Blinder(powermod_e_n(k), inverse_mod(k, n), n);
   }

BigInt RSA_Private_Operation::private_op(const BigInt& m) const
   {
   if(m >= n)
      throw Invalid_Argument("RSA private op - input is too large");

   auto future_j1 = std::async(std::launch::async, powermod_d1_p, m);
   BigInt j2 = powermod_d2_q(m);
   BigInt j1 = future_j1.get();

   j1 = mod_p.reduce(sub_mul(j1, j2, c));

   return mul_add(j1, q, j2);
   }

secure_vector<byte>
RSA_Private_Operation::sign(const byte msg[], size_t msg_len,
                            RandomNumberGenerator& rng)
   {
   rng.add_entropy(msg, msg_len);

   /* We don't check signatures against powermod_e_n here because
      PK_Signer checks verification consistency for all signature
      algorithms.
   */

   const BigInt m(msg, msg_len);
   const BigInt x = blinder.unblind(private_op(blinder.blind(m)));
   return BigInt::encode_1363(x, n.bytes());
   }

/*
* RSA Decryption Operation
*/
secure_vector<byte>
RSA_Private_Operation::decrypt(const byte msg[], size_t msg_len)
   {
   const BigInt m(msg, msg_len);
   const BigInt x = blinder.unblind(private_op(blinder.blind(m)));

   BOTAN_ASSERT(m == powermod_e_n(x),
                "RSA decrypt passed consistency check");

   return BigInt::encode_locked(x);
   }

}
