/*
* DL Scheme
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/dl_algo.h>
#include <botan/numthry.h>
#include <botan/der_enc.h>
#include <botan/ber_dec.h>

namespace Botan {

/*
* Return the X.509 public key encoder
*/
X509_Encoder* DL_Scheme_PublicKey::x509_encoder() const
   {
   class DL_Scheme_Encoder : public X509_Encoder
      {
      public:
         AlgorithmIdentifier alg_id() const
            {
            MemoryVector<byte> group =
               key->group.DER_encode(key->group_format());

            return AlgorithmIdentifier(key->get_oid(), group);
            }

         MemoryVector<byte> key_bits() const
            {
            return DER_Encoder().encode(key->y).get_contents();
            }

         DL_Scheme_Encoder(const DL_Scheme_PublicKey* k) : key(k) {}
      private:
         const DL_Scheme_PublicKey* key;
      };

   return new DL_Scheme_Encoder(this);
   }

/*
* Return the X.509 public key decoder
*/
X509_Decoder* DL_Scheme_PublicKey::x509_decoder()
   {
   class DL_Scheme_Decoder : public X509_Decoder
      {
      public:
         void alg_id(const AlgorithmIdentifier& alg_id)
            {
            DataSource_Memory source(alg_id.parameters);
            key->group.BER_decode(source, key->group_format());
            }

         void key_bits(const MemoryRegion<byte>& bits)
            {
            BER_Decoder(bits).decode(key->y);
            key->X509_load_hook();
            }

         DL_Scheme_Decoder(DL_Scheme_PublicKey* k) : key(k) {}
      private:
         DL_Scheme_PublicKey* key;
      };

   return new DL_Scheme_Decoder(this);
   }

/*
* Return the PKCS #8 private key encoder
*/
PKCS8_Encoder* DL_Scheme_PrivateKey::pkcs8_encoder() const
   {
   class DL_Scheme_Encoder : public PKCS8_Encoder
      {
      public:
         AlgorithmIdentifier alg_id() const
            {
            MemoryVector<byte> group =
               key->group.DER_encode(key->group_format());

            return AlgorithmIdentifier(key->get_oid(), group);
            }

         MemoryVector<byte> key_bits() const
            {
            return DER_Encoder().encode(key->x).get_contents();
            }

         DL_Scheme_Encoder(const DL_Scheme_PrivateKey* k) : key(k) {}
      private:
         const DL_Scheme_PrivateKey* key;
      };

   return new DL_Scheme_Encoder(this);
   }

/*
* Return the PKCS #8 private key decoder
*/
PKCS8_Decoder* DL_Scheme_PrivateKey::pkcs8_decoder(RandomNumberGenerator& rng)
   {
   class DL_Scheme_Decoder : public PKCS8_Decoder
      {
      public:
         void alg_id(const AlgorithmIdentifier& alg_id)
            {
            DataSource_Memory source(alg_id.parameters);
            key->group.BER_decode(source, key->group_format());
            }

         void key_bits(const MemoryRegion<byte>& bits)
            {
            BER_Decoder(bits).decode(key->x);
            key->PKCS8_load_hook(rng);
            }

         DL_Scheme_Decoder(DL_Scheme_PrivateKey* k, RandomNumberGenerator& r) :
            key(k), rng(r) {}
      private:
         DL_Scheme_PrivateKey* key;
         RandomNumberGenerator& rng;
      };

   return new DL_Scheme_Decoder(this, rng);
   }

/*
* Check Public DL Parameters
*/
bool DL_Scheme_PublicKey::check_key(RandomNumberGenerator& rng,
                                    bool strong) const
   {
   if(y < 2 || y >= group_p())
      return false;
   if(!group.verify_group(rng, strong))
      return false;
   return true;
   }

/*
* Check DL Scheme Private Parameters
*/
bool DL_Scheme_PrivateKey::check_key(RandomNumberGenerator& rng,
                                     bool strong) const
   {
   const BigInt& p = group_p();
   const BigInt& g = group_g();

   if(y < 2 || y >= p || x < 2 || x >= p)
      return false;
   if(!group.verify_group(rng, strong))
      return false;

   if(!strong)
      return true;

   if(y != power_mod(g, x, p))
      return false;

   return true;
   }

}
