/*
* RSA
* (C) 1999-2008 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/rsa.h>
#include <botan/parsing.h>
#include <botan/numthry.h>
#include <botan/keypair.h>
#include <botan/look_pk.h>

namespace Botan {

/*
* RSA Public Operation
*/
BigInt RSA_PublicKey::public_op(const BigInt& i) const
   {
   if(i >= n)
      throw Invalid_Argument(algo_name() + "::public_op: input is too large");
   return core.public_op(i);
   }

/*
* RSA Encryption Function
*/
SecureVector<byte> RSA_PublicKey::encrypt(const byte in[], u32bit len,
                                          RandomNumberGenerator&) const
   {
   BigInt i(in, len);
   return BigInt::encode_1363(public_op(i), n.bytes());
   }

/*
* Create a RSA private key
*/
RSA_PrivateKey::RSA_PrivateKey(RandomNumberGenerator& rng,
                               u32bit bits, u32bit exp)
   {
   if(bits < 512)
      throw Invalid_Argument(algo_name() + ": Can't make a key that is only " +
                             to_string(bits) + " bits long");
   if(exp < 3 || exp % 2 == 0)
      throw Invalid_Argument(algo_name() + ": Invalid encryption exponent");

   e = exp;
   p = random_prime(rng, (bits + 1) / 2, e);
   q = random_prime(rng, bits - p.bits(), e);
   n = p * q;

   if(n.bits() != bits)
      throw Self_Test_Failure(algo_name() + " private key generation failed");

   d = inverse_mod(e, lcm(p - 1, q - 1));
   d1 = d % (p - 1);
   d2 = d % (q - 1);
   c = inverse_mod(q, p);

   core = IF_Core(rng, e, n, d, p, q, d1, d2, c);

   gen_check(rng);
   }

/*
* RSA Private Operation
*/
BigInt RSA_PrivateKey::private_op(const byte in[], u32bit length) const
   {
   BigInt i(in, length);
   if(i >= n)
      throw Invalid_Argument(algo_name() + "::private_op: input is too large");

   BigInt r = core.private_op(i);
   if(i != public_op(r))
      throw Self_Test_Failure(algo_name() + " private operation check failed");
   return r;
   }

/*
* RSA Decryption Operation
*/
SecureVector<byte> RSA_PrivateKey::decrypt(const byte in[], u32bit len) const
   {
   return BigInt::encode(private_op(in, len));
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

   try
      {
      KeyPair::check_key(rng,
                         get_pk_encryptor(*this, "EME1(SHA-1)"),
                         get_pk_decryptor(*this, "EME1(SHA-1)")
         );

      KeyPair::check_key(rng,
                         get_pk_signer(*this, "EMSA4(SHA-1)"),
                         get_pk_verifier(*this, "EMSA4(SHA-1)")
         );
      }
   catch(Self_Test_Failure)
      {
      return false;
      }

   return true;
   }

RSA_Signature_Operation::RSA_Signature_Operation(const RSA_PrivateKey& rsa) :
   q(rsa.get_q()),
   c(rsa.get_c()),
   powermod_d1_p(rsa.get_d1(), rsa.get_p()),
   powermod_d2_q(rsa.get_d2(), rsa.get_q()),
   mod_p(rsa.get_p()),
   n_bits(rsa.get_n().bits())
   {
   }

SecureVector<byte>
RSA_Signature_Operation::sign(const byte msg[], u32bit msg_len,
                              RandomNumberGenerator&) const
   {
   const u32bit n_bytes = (n_bits + 7) / 8;

   BigInt i(msg, msg_len);
   BigInt j1 = powermod_d1_p(i);
   BigInt j2 = powermod_d2_q(i);

   j1 = mod_p.reduce(sub_mul(j1, j2, c));

   return BigInt::encode_1363(mul_add(j1, q, j2), n_bytes);
   }

}
