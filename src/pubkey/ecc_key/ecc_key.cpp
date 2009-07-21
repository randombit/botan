/*
* ECC Key implemenation
* (C) 2007 Manuel Hartl, FlexSecure GmbH
*          Falko Strenzke, FlexSecure GmbH
*     2008 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/ecc_key.h>
#include <botan/x509_key.h>
#include <botan/numthry.h>
#include <botan/util.h>
#include <botan/der_enc.h>
#include <botan/ber_dec.h>
#include <botan/secmem.h>
#include <botan/point_gfp.h>

namespace Botan {

/*
* EC_PublicKey
*/
void EC_PublicKey::affirm_init() const // virtual
   {
   if((mp_dom_pars.get() == 0) || (mp_public_point.get() == 0))
      throw Invalid_State("cannot use uninitialized EC_Key");
   }

const EC_Domain_Params& EC_PublicKey::domain_parameters() const
   {
   if(!mp_dom_pars.get())
      throw Invalid_State("EC_PublicKey::domain_parameters(): "
                          "ec domain parameters are not yet set");

   return *mp_dom_pars;
   }

const PointGFp& EC_PublicKey::public_point() const
   {
   if(!mp_public_point.get())
      throw Invalid_State("EC_PublicKey::public_point(): public point not set");

   return *mp_public_point;
   }

bool EC_PublicKey::domain_parameters_set()
   {
   return mp_dom_pars.get();
   }

void EC_PublicKey::X509_load_hook()
   {
   try
      {
      // the base point is checked to be on curve already when decoding it
      affirm_init();
      mp_public_point->check_invariants();
      }
   catch(Illegal_Point)
      {
      throw Decoding_Error("decoded public point was found not to lie on curve");
      }
   }

X509_Encoder* EC_PublicKey::x509_encoder() const
   {
   class EC_Key_Encoder : public X509_Encoder
      {
      public:
         AlgorithmIdentifier alg_id() const
            {
            key->affirm_init();

            SecureVector<byte> params =
               encode_der_ec_dompar(key->domain_parameters(), key->m_param_enc);

            return AlgorithmIdentifier(key->get_oid(), params);
            }

         MemoryVector<byte> key_bits() const
            {
            key->affirm_init();
            return EC2OSP(*(key->mp_public_point), PointGFp::COMPRESSED);
            }

         EC_Key_Encoder(const EC_PublicKey* k): key(k) {}
      private:
         const EC_PublicKey* key;
      };

   return new EC_Key_Encoder(this);
   }

X509_Decoder* EC_PublicKey::x509_decoder()
   {
   class EC_Key_Decoder : public X509_Decoder
      {
      public:
         void alg_id(const AlgorithmIdentifier& alg_id)
            {
            key->mp_dom_pars.reset(new EC_Domain_Params(decode_ber_ec_dompar(alg_id.parameters)));
            }

         void key_bits(const MemoryRegion<byte>& bits)
            {
            key->mp_public_point.reset(
               new PointGFp(
                  OS2ECP(bits, key->domain_parameters().get_curve())
                  ));

            key->X509_load_hook();
            }

         EC_Key_Decoder(EC_PublicKey* k): key(k) {}
      private:
         EC_PublicKey* key;
      };

   return new EC_Key_Decoder(this);
   }

void EC_PublicKey::set_parameter_encoding(EC_dompar_enc type)
   {
   if((type != ENC_EXPLICIT) && (type != ENC_IMPLICITCA) && (type != ENC_OID))
      throw Invalid_Argument("Invalid encoding type for EC-key object specified");

   affirm_init();

   if((type == ENC_OID) && (mp_dom_pars->get_oid() == ""))
      throw Invalid_Argument("Invalid encoding type ENC_OID specified for "
                             "EC-key object whose corresponding domain "
                             "parameters are without oid");

   m_param_enc = type;
   }

/********************************
* EC_PrivateKey
********************************/
void EC_PrivateKey::affirm_init() const // virtual
   {
   if(m_private_value == 0)
      throw Invalid_State("cannot use EC_PrivateKey when private key is uninitialized");

   EC_PublicKey::affirm_init();
   }

const BigInt& EC_PrivateKey::private_value() const
   {
   if(m_private_value == 0)
      throw Invalid_State("cannot use EC_PrivateKey when private key is uninitialized");

   return m_private_value;
   }

/**
* EC_PrivateKey generator
**/
void EC_PrivateKey::generate_private_key(RandomNumberGenerator& rng)
   {
   if(mp_dom_pars.get() == 0)
      {
      throw Invalid_State("cannot generate private key when domain parameters are not set");
      }

   BigInt tmp_private_value(0);
   tmp_private_value = BigInt::random_integer(rng, 1, mp_dom_pars->get_order());
   mp_public_point = std::auto_ptr<PointGFp>( new PointGFp (mp_dom_pars->get_base_point()));
   mp_public_point->mult_this_secure(tmp_private_value,
                                     mp_dom_pars->get_order(),
                                     mp_dom_pars->get_order()-1);

   //assert(mp_public_point.get() != 0);
   tmp_private_value.swap(m_private_value);
   }

/**
* Return the PKCS #8 public key encoder
**/
PKCS8_Encoder* EC_PrivateKey::pkcs8_encoder() const
   {
   class EC_Key_Encoder : public PKCS8_Encoder
      {
      public:
         AlgorithmIdentifier alg_id() const
            {
            key->affirm_init();

            SecureVector<byte> params =
               encode_der_ec_dompar(key->domain_parameters(), ENC_EXPLICIT);

            return AlgorithmIdentifier(key->get_oid(), params);
            }

         MemoryVector<byte> key_bits() const
            {
            key->affirm_init();
            SecureVector<byte> octstr_secret =
               BigInt::encode_1363(key->m_private_value, key->m_private_value.bytes());

            return DER_Encoder()
               .start_cons(SEQUENCE)
               .encode(BigInt(1))
               .encode(octstr_secret, OCTET_STRING)
               .end_cons()
               .get_contents();
            }

         EC_Key_Encoder(const EC_PrivateKey* k): key(k) {}
      private:
         const EC_PrivateKey* key;
      };

   return new EC_Key_Encoder(this);
   }

/**
* Return the PKCS #8 public key decoder
*/
PKCS8_Decoder* EC_PrivateKey::pkcs8_decoder(RandomNumberGenerator&)
   {
   class EC_Key_Decoder : public PKCS8_Decoder
      {
      public:
         void alg_id(const AlgorithmIdentifier& alg_id)
            {
            key->mp_dom_pars.reset(new EC_Domain_Params(decode_ber_ec_dompar(alg_id.parameters)));
            }

         void key_bits(const MemoryRegion<byte>& bits)
            {
            u32bit version;
            SecureVector<byte> octstr_secret;

            BER_Decoder(bits)
               .start_cons(SEQUENCE)
               .decode(version)
               .decode(octstr_secret, OCTET_STRING)
               .verify_end()
               .end_cons();

            key->m_private_value = BigInt::decode(octstr_secret, octstr_secret.size());

            if(version != 1)
               throw Decoding_Error("Wrong PKCS #1 key format version for EC key");

            key->PKCS8_load_hook();
            }

         EC_Key_Decoder(EC_PrivateKey* k): key(k) {}
      private:
         EC_PrivateKey* key;
      };

   return new EC_Key_Decoder(this);
   }

void EC_PrivateKey::PKCS8_load_hook(bool)
   {
   // we cannot use affirm_init() here because mp_public_point might still be null
   if(mp_dom_pars.get() == 0)
      throw Invalid_State("attempt to set public point for an uninitialized key");

   mp_public_point.reset(new PointGFp(m_private_value * mp_dom_pars->get_base_point()));
   mp_public_point->check_invariants();
   }

}
