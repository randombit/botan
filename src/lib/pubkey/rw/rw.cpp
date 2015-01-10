/*
* Rabin-Williams
* (C) 1999-2008 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/rw.h>
#include <botan/numthry.h>
#include <botan/keypair.h>
#include <botan/parsing.h>
#include <algorithm>
#include <future>

namespace Botan {

/*
* Create a Rabin-Williams private key
*/
RW_PrivateKey::RW_PrivateKey(RandomNumberGenerator& rng,
                             size_t bits, size_t exp)
   {
   if(bits < 1024)
      throw Invalid_Argument(algo_name() + ": Can't make a key that is only " +
                             std::to_string(bits) + " bits long");
   if(exp < 2 || exp % 2 == 1)
      throw Invalid_Argument(algo_name() + ": Invalid encryption exponent");

   e = exp;

   do
      {
      p = random_prime(rng, (bits + 1) / 2, e / 2, 3, 4);
      q = random_prime(rng, bits - p.bits(), e / 2, ((p % 8 == 3) ? 7 : 3), 8);
      n = p * q;
      } while(n.bits() != bits);

   d = inverse_mod(e, lcm(p - 1, q - 1) >> 1);
   d1 = d % (p - 1);
   d2 = d % (q - 1);
   c = inverse_mod(q, p);

   gen_check(rng);
   }

/*
* Check Private Rabin-Williams Parameters
*/
bool RW_PrivateKey::check_key(RandomNumberGenerator& rng, bool strong) const
   {
   if(!IF_Scheme_PrivateKey::check_key(rng, strong))
      return false;

   if(!strong)
      return true;

   if((e * d) % (lcm(p - 1, q - 1) / 2) != 1)
      return false;

   return KeyPair::signature_consistency_check(rng, *this, "EMSA2(SHA-1)");
   }

RW_Signature_Operation::RW_Signature_Operation(const RW_PrivateKey& rw) :
   n(rw.get_n()),
   e(rw.get_e()),
   q(rw.get_q()),
   c(rw.get_c()),
   powermod_d1_p(rw.get_d1(), rw.get_p()),
   powermod_d2_q(rw.get_d2(), rw.get_q()),
   mod_p(rw.get_p())
   {
   }

secure_vector<byte>
RW_Signature_Operation::sign(const byte msg[], size_t msg_len,
                             RandomNumberGenerator& rng)
   {
   rng.add_entropy(msg, msg_len);

   if(!blinder.initialized())
      {
      BigInt k(rng, std::min<size_t>(160, n.bits() - 1));
      blinder = Blinder(power_mod(k, e, n), inverse_mod(k, n), n);
      }

   BigInt i(msg, msg_len);

   if(i >= n || i % 16 != 12)
      throw Invalid_Argument("Rabin-Williams: invalid input");

   if(jacobi(i, n) != 1)
      i >>= 1;

   i = blinder.blind(i);

   auto future_j1 = std::async(std::launch::async, powermod_d1_p, i);
   const BigInt j2 = powermod_d2_q(i);
   BigInt j1 = future_j1.get();

   j1 = mod_p.reduce(sub_mul(j1, j2, c));

   const BigInt r = blinder.unblind(mul_add(j1, q, j2));

   return BigInt::encode_1363(std::min(r, n - r), n.bytes());
   }

secure_vector<byte>
RW_Verification_Operation::verify_mr(const byte msg[], size_t msg_len)
   {
   BigInt m(msg, msg_len);

   if((m > (n >> 1)) || m.is_negative())
      throw Invalid_Argument("RW signature verification: m > n / 2 || m < 0");

   BigInt r = powermod_e_n(m);
   if(r % 16 == 12)
      return BigInt::encode_locked(r);
   if(r % 8 == 6)
      return BigInt::encode_locked(2*r);

   r = n - r;
   if(r % 16 == 12)
      return BigInt::encode_locked(r);
   if(r % 8 == 6)
      return BigInt::encode_locked(2*r);

   throw Invalid_Argument("RW signature verification: Invalid signature");
   }

}
