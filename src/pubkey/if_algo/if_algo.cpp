/*
* IF Scheme
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/if_algo.h>
#include <botan/numthry.h>
#include <botan/der_enc.h>
#include <botan/ber_dec.h>

namespace Botan {

AlgorithmIdentifier IF_Scheme_PublicKey::algorithm_identifier() const
   {
   return AlgorithmIdentifier(get_oid(),
                              AlgorithmIdentifier::USE_NULL_PARAM);
   }

MemoryVector<byte> IF_Scheme_PublicKey::x509_subject_public_key() const
   {
   return DER_Encoder()
      .start_cons(SEQUENCE)
         .encode(n)
         .encode(e)
      .end_cons()
      .get_contents();
   }

IF_Scheme_PublicKey::IF_Scheme_PublicKey(const AlgorithmIdentifier&,
                                         const MemoryRegion<byte>& key_bits)
   {
   BER_Decoder(key_bits)
      .start_cons(SEQUENCE)
        .decode(n)
        .decode(e)
      .verify_end()
      .end_cons();
   }

MemoryVector<byte> IF_Scheme_PrivateKey::pkcs8_private_key() const
   {
   return DER_Encoder()
      .start_cons(SEQUENCE)
         .encode(static_cast<u32bit>(0))
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

IF_Scheme_PrivateKey::IF_Scheme_PrivateKey(const AlgorithmIdentifier&,
                                           const MemoryRegion<byte>& key_bits)
   {
   u32bit version;

   BER_Decoder(key_bits)
      .start_cons(SEQUENCE)
         .decode(version)
         .decode(n)
         .decode(e)
         .decode(d)
         .decode(p)
         .decode(q)
         .decode(d1)
         .decode(d2)
         .decode(c)
      .end_cons();

   if(version != 0)
      throw Decoding_Error("Unknown PKCS #1 key format version");
   }

/*
* Algorithm Specific X.509 Initialization Code
*/
void IF_Scheme_PublicKey::X509_load_hook()
   {
   core = IF_Core(e, n);
   }

/*
* Algorithm Specific PKCS #8 Initialization Code
*/
void IF_Scheme_PrivateKey::PKCS8_load_hook(RandomNumberGenerator& rng,
                                           bool generated)
   {
   if(n == 0)  n = p * q;
   if(d1 == 0) d1 = d % (p - 1);
   if(d2 == 0) d2 = d % (q - 1);
   if(c == 0)  c = inverse_mod(q, p);

   core = IF_Core(rng, e, n, d, p, q, d1, d2, c);

   if(generated)
      gen_check(rng);
   else
      load_check(rng);
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

/*
* Check IF Scheme Private Parameters
*/
bool IF_Scheme_PrivateKey::check_key(RandomNumberGenerator& rng,
                                     bool strong) const
   {
   if(n < 35 || n.is_even() || e < 2 || d < 2 || p < 3 || q < 3 || p*q != n)
      return false;

   if(!strong)
      return true;

   if(d1 != d % (p - 1) || d2 != d % (q - 1) || c != inverse_mod(q, p))
      return false;
   if(!check_prime(p, rng) || !check_prime(q, rng))
      return false;
   return true;
   }

}
