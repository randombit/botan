/*
* Rabin-Williams
* (C) 1999-2008 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/rw.h>
#include <botan/numthry.h>
#include <botan/keypair.h>
#include <botan/look_pk.h>
#include <botan/parsing.h>
#include <algorithm>

namespace Botan {

/*
* RW_PublicKey Constructor
*/
RW_PublicKey::RW_PublicKey(const BigInt& mod, const BigInt& exp)
   {
   n = mod;
   e = exp;
   X509_load_hook();
   }

/*
* Rabin-Williams Public Operation
*/
BigInt RW_PublicKey::public_op(const BigInt& i) const
   {
   if((i > (n >> 1)) || i.is_negative())
      throw Invalid_Argument(algo_name() + "::public_op: i > n / 2 || i < 0");

   BigInt r = core.public_op(i);
   if(r % 16 == 12) return r;
   if(r % 8 == 6)   return 2*r;

   r = n - r;
   if(r % 16 == 12) return r;
   if(r % 8 == 6)   return 2*r;

   throw Invalid_Argument(algo_name() + "::public_op: Invalid input");
   }

/*
* Rabin-Williams Verification Function
*/
SecureVector<byte> RW_PublicKey::verify(const byte in[], u32bit len) const
   {
   BigInt i(in, len);
   return BigInt::encode(public_op(i));
   }

/*
* Create a Rabin-Williams private key
*/
RW_PrivateKey::RW_PrivateKey(RandomNumberGenerator& rng,
                             u32bit bits, u32bit exp)
   {
   if(bits < 512)
      throw Invalid_Argument(algo_name() + ": Can't make a key that is only " +
                             to_string(bits) + " bits long");
   if(exp < 2 || exp % 2 == 1)
      throw Invalid_Argument(algo_name() + ": Invalid encryption exponent");

   e = exp;
   p = random_prime(rng, (bits + 1) / 2, e / 2, 3, 4);
   q = random_prime(rng, bits - p.bits(), e / 2, ((p % 8 == 3) ? 7 : 3), 8);
   d = inverse_mod(e, lcm(p - 1, q - 1) >> 1);

   PKCS8_load_hook(rng, true);

   if(n.bits() != bits)
      throw Self_Test_Failure(algo_name() + " private key generation failed");
   }

/*
* RW_PrivateKey Constructor
*/
RW_PrivateKey::RW_PrivateKey(RandomNumberGenerator& rng,
                             const BigInt& prime1, const BigInt& prime2,
                             const BigInt& exp, const BigInt& d_exp,
                             const BigInt& mod)
   {
   p = prime1;
   q = prime2;
   e = exp;
   d = d_exp;
   n = mod;

   if(d == 0)
      d = inverse_mod(e, lcm(p - 1, q - 1) >> 1);

   PKCS8_load_hook(rng);
   }

/*
* Rabin-Williams Signature Operation
*/
SecureVector<byte> RW_PrivateKey::sign(const byte in[], u32bit len,
                                       RandomNumberGenerator&) const
   {
   BigInt i(in, len);
   if(i >= n || i % 16 != 12)
      throw Invalid_Argument(algo_name() + "::sign: Invalid input");

   BigInt r;
   if(jacobi(i, n) == 1) r = core.private_op(i);
   else                  r = core.private_op(i >> 1);

   r = std::min(r, n - r);
   if(i != public_op(r))
      throw Self_Test_Failure(algo_name() + " private operation check failed");

   return BigInt::encode_1363(r, n.bytes());
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

   try
      {
      KeyPair::check_key(rng,
                         get_pk_signer(*this, "EMSA2(SHA-1)"),
                         get_pk_verifier(*this, "EMSA2(SHA-1)")
         );
      }
   catch(Self_Test_Failure)
      {
      return false;
      }

   return true;
   }

}
