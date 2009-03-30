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

/*
* Return the X.509 public key encoder
*/
X509_Encoder* IF_Scheme_PublicKey::x509_encoder() const
   {
   class IF_Scheme_Encoder : public X509_Encoder
      {
      public:
         AlgorithmIdentifier alg_id() const
            {
            return AlgorithmIdentifier(key->get_oid(),
                                       AlgorithmIdentifier::USE_NULL_PARAM);
            }

         MemoryVector<byte> key_bits() const
            {
            return DER_Encoder()
               .start_cons(SEQUENCE)
                  .encode(key->n)
                  .encode(key->e)
               .end_cons()
            .get_contents();
            }

         IF_Scheme_Encoder(const IF_Scheme_PublicKey* k) : key(k) {}
      private:
         const IF_Scheme_PublicKey* key;
      };

   return new IF_Scheme_Encoder(this);
   }

/*
* Return the X.509 public key decoder
*/
X509_Decoder* IF_Scheme_PublicKey::x509_decoder()
   {
   class IF_Scheme_Decoder : public X509_Decoder
      {
      public:
         void alg_id(const AlgorithmIdentifier&) {}

         void key_bits(const MemoryRegion<byte>& bits)
            {
            BER_Decoder(bits)
               .start_cons(SEQUENCE)
               .decode(key->n)
               .decode(key->e)
               .verify_end()
               .end_cons();

            key->X509_load_hook();
            }

         IF_Scheme_Decoder(IF_Scheme_PublicKey* k) : key(k) {}
      private:
         IF_Scheme_PublicKey* key;
      };

   return new IF_Scheme_Decoder(this);
   }

/*
* Return the PKCS #8 public key encoder
*/
PKCS8_Encoder* IF_Scheme_PrivateKey::pkcs8_encoder() const
   {
   class IF_Scheme_Encoder : public PKCS8_Encoder
      {
      public:
         AlgorithmIdentifier alg_id() const
            {
            return AlgorithmIdentifier(key->get_oid(),
                                       AlgorithmIdentifier::USE_NULL_PARAM);
            }

         MemoryVector<byte> key_bits() const
            {
            return DER_Encoder()
               .start_cons(SEQUENCE)
                  .encode(static_cast<u32bit>(0))
                  .encode(key->n)
                  .encode(key->e)
                  .encode(key->d)
                  .encode(key->p)
                  .encode(key->q)
                  .encode(key->d1)
                  .encode(key->d2)
                  .encode(key->c)
               .end_cons()
            .get_contents();
            }

         IF_Scheme_Encoder(const IF_Scheme_PrivateKey* k) : key(k) {}
      private:
         const IF_Scheme_PrivateKey* key;
      };

   return new IF_Scheme_Encoder(this);
   }

/*
* Return the PKCS #8 public key decoder
*/
PKCS8_Decoder* IF_Scheme_PrivateKey::pkcs8_decoder(RandomNumberGenerator& rng)
   {
   class IF_Scheme_Decoder : public PKCS8_Decoder
      {
      public:
         void alg_id(const AlgorithmIdentifier&) {}

         void key_bits(const MemoryRegion<byte>& bits)
            {
            u32bit version;

            BER_Decoder(bits)
               .start_cons(SEQUENCE)
                  .decode(version)
                  .decode(key->n)
                  .decode(key->e)
                  .decode(key->d)
                  .decode(key->p)
                  .decode(key->q)
                  .decode(key->d1)
                  .decode(key->d2)
                  .decode(key->c)
               .end_cons();

            if(version != 0)
               throw Decoding_Error("Unknown PKCS #1 key format version");

            key->PKCS8_load_hook(rng);
            }

         IF_Scheme_Decoder(IF_Scheme_PrivateKey* k, RandomNumberGenerator& r) :
            key(k), rng(r) {}
      private:
         IF_Scheme_PrivateKey* key;
         RandomNumberGenerator& rng;
      };

   return new IF_Scheme_Decoder(this, rng);
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
