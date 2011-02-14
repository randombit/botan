/*
* ECC Key implemenation
* (C) 2007 Manuel Hartl, FlexSecure GmbH
*          Falko Strenzke, FlexSecure GmbH
*     2008-2010 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/ecc_key.h>
#include <botan/x509_key.h>
#include <botan/numthry.h>
#include <botan/der_enc.h>
#include <botan/ber_dec.h>
#include <botan/secmem.h>
#include <botan/point_gfp.h>
#include <botan/internal/assert.h>

namespace Botan {

EC_PublicKey::EC_PublicKey(const EC_Domain_Params& dom_par,
                           const PointGFp& pub_point) :
   domain_params(dom_par), public_key(pub_point),
   domain_encoding(EC_DOMPAR_ENC_EXPLICIT)
   {
   if(domain().get_curve() != public_point().get_curve())
      throw Invalid_Argument("EC_PublicKey: curve mismatch in constructor");
   }

EC_PublicKey::EC_PublicKey(const AlgorithmIdentifier& alg_id,
                           const MemoryRegion<byte>& key_bits)
   {
   domain_params = EC_Domain_Params(alg_id.parameters);
   domain_encoding = EC_DOMPAR_ENC_EXPLICIT;

   public_key = OS2ECP(key_bits, domain().get_curve());
   }

bool EC_PublicKey::check_key(RandomNumberGenerator&,
                             bool) const
   {
   return public_point().on_the_curve();
   }

AlgorithmIdentifier EC_PublicKey::algorithm_identifier() const
   {
   return AlgorithmIdentifier(get_oid(), DER_domain());
   }

MemoryVector<byte> EC_PublicKey::x509_subject_public_key() const
   {
   return EC2OSP(public_point(), PointGFp::COMPRESSED);
   }

void EC_PublicKey::set_parameter_encoding(EC_Domain_Params_Encoding form)
   {
   if(form != EC_DOMPAR_ENC_EXPLICIT &&
      form != EC_DOMPAR_ENC_IMPLICITCA &&
      form != EC_DOMPAR_ENC_OID)
      throw Invalid_Argument("Invalid encoding form for EC-key object specified");

   if((form == EC_DOMPAR_ENC_OID) && (domain_params.get_oid() == ""))
      throw Invalid_Argument("Invalid encoding form OID specified for "
                             "EC-key object whose corresponding domain "
                             "parameters are without oid");

   domain_encoding = form;
   }

const BigInt& EC_PrivateKey::private_value() const
   {
   if(private_key == 0)
      throw Invalid_State("EC_PrivateKey::private_value - uninitialized");

   return private_key;
   }

/**
* EC_PrivateKey generator
*/
EC_PrivateKey::EC_PrivateKey(const EC_Domain_Params& dom_par,
                             const BigInt& priv_key)
   {
   domain_params = dom_par;
   domain_encoding = EC_DOMPAR_ENC_EXPLICIT;

   public_key = domain().get_base_point() * priv_key;
   private_key = priv_key;
   }

/**
* EC_PrivateKey generator
*/
EC_PrivateKey::EC_PrivateKey(RandomNumberGenerator& rng,
                             const EC_Domain_Params& dom_par)
   {
   domain_params = dom_par;
   domain_encoding = EC_DOMPAR_ENC_EXPLICIT;

   private_key = BigInt::random_integer(rng, 1, domain().get_order());
   public_key = domain().get_base_point() * private_key;

   BOTAN_ASSERT(public_key.on_the_curve(),
                "generated ECC private key was not on the curve");
   }

MemoryVector<byte> EC_PrivateKey::pkcs8_private_key() const
   {
   return DER_Encoder()
      .start_cons(SEQUENCE)
         .encode(static_cast<size_t>(1))
         .encode(BigInt::encode_1363(private_key, private_key.bytes()),
                 OCTET_STRING)
      .end_cons()
      .get_contents();
   }

EC_PrivateKey::EC_PrivateKey(const AlgorithmIdentifier& alg_id,
                             const MemoryRegion<byte>& key_bits)
   {
   domain_params = EC_Domain_Params(alg_id.parameters);
   domain_encoding = EC_DOMPAR_ENC_EXPLICIT;

   BER_Decoder(key_bits)
      .start_cons(SEQUENCE)
         .decode_and_check<size_t>(1, "Unknown version code for ECC key")
         .decode_octet_string_bigint(private_key)
      .verify_end()
      .end_cons();

   public_key = domain().get_base_point() * private_key;

   BOTAN_ASSERT(public_key.on_the_curve(),
                "Loaded ECC private key not on the curve");
   }

}
