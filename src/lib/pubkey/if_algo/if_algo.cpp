/*
* IF Scheme
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/if_algo.h>
#include <botan/numthry.h>
#include <botan/workfactor.h>
#include <botan/der_enc.h>
#include <botan/ber_dec.h>

namespace Botan {

size_t IF_Scheme_PublicKey::estimated_strength() const
   {
   return if_work_factor(n.bits());
   }

AlgorithmIdentifier IF_Scheme_PublicKey::algorithm_identifier() const
   {
   return AlgorithmIdentifier(get_oid(),
                              AlgorithmIdentifier::USE_NULL_PARAM);
   }

std::vector<byte> IF_Scheme_PublicKey::x509_subject_public_key() const
   {
   return DER_Encoder()
      .start_cons(SEQUENCE)
         .encode(n)
         .encode(e)
      .end_cons()
      .get_contents_unlocked();
   }

IF_Scheme_PublicKey::IF_Scheme_PublicKey(const AlgorithmIdentifier&,
                                         const secure_vector<byte>& key_bits)
   {
   BER_Decoder(key_bits)
      .start_cons(SEQUENCE)
        .decode(n)
        .decode(e)
      .verify_end()
      .end_cons();
   }

/*
* Check IF Scheme Public Parameters
*/
bool IF_Scheme_PublicKey::check_key(RandomNumberGenerator&, bool) const
   {
   if(n < 35 || n.is_even() || e < 2)
      return false;
   return true;
   }

secure_vector<byte> IF_Scheme_PrivateKey::pkcs8_private_key() const
   {
   return DER_Encoder()
      .start_cons(SEQUENCE)
         .encode(static_cast<size_t>(0))
         .encode(n)
         .encode(e)
         .encode(d)
         .encode(p)
         .encode(q)
         .encode(d1)
         .encode(d2)
         .encode(c)
      .end_cons()
   .get_contents();
   }

IF_Scheme_PrivateKey::IF_Scheme_PrivateKey(RandomNumberGenerator& rng,
                                           const AlgorithmIdentifier&,
                                           const secure_vector<byte>& key_bits)
   {
   BER_Decoder(key_bits)
      .start_cons(SEQUENCE)
         .decode_and_check<size_t>(0, "Unknown PKCS #1 key format version")
         .decode(n)
         .decode(e)
         .decode(d)
         .decode(p)
         .decode(q)
         .decode(d1)
         .decode(d2)
         .decode(c)
      .end_cons();

   load_check(rng);
   }

IF_Scheme_PrivateKey::IF_Scheme_PrivateKey(RandomNumberGenerator& rng,
                                           const BigInt& prime1,
                                           const BigInt& prime2,
                                           const BigInt& exp,
                                           const BigInt& d_exp,
                                           const BigInt& mod)
   {
   p = prime1;
   q = prime2;
   e = exp;
   d = d_exp;
   n = mod.is_nonzero() ? mod : p * q;

   if(d == 0)
      {
      BigInt inv_for_d = lcm(p - 1, q - 1);
      if(e.is_even())
         inv_for_d >>= 1;

      d = inverse_mod(e, inv_for_d);
      }

   d1 = d % (p - 1);
   d2 = d % (q - 1);
   c = inverse_mod(q, p);

   load_check(rng);
   }

/*
* Check IF Scheme Private Parameters
*/
bool IF_Scheme_PrivateKey::check_key(RandomNumberGenerator& rng,
                                     bool strong) const
   {
   if(n < 35 || n.is_even() || e < 2 || d < 2 || p < 3 || q < 3 || p*q != n)
      return false;

   if(d1 != d % (p - 1) || d2 != d % (q - 1) || c != inverse_mod(q, p))
      return false;

   const size_t prob = (strong) ? 56 : 12;

   if(!is_prime(p, rng, prob) || !is_prime(q, rng, prob))
      return false;
   return true;
   }

}
