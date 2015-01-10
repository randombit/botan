/*
* ECC Key implemenation
* (C) 2007 Manuel Hartl, FlexSecure GmbH
*          Falko Strenzke, FlexSecure GmbH
*     2008-2010 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/ecc_key.h>
#include <botan/x509_key.h>
#include <botan/numthry.h>
#include <botan/der_enc.h>
#include <botan/ber_dec.h>
#include <botan/secmem.h>
#include <botan/point_gfp.h>
#include <botan/workfactor.h>

namespace Botan {

size_t EC_PublicKey::estimated_strength() const
   {
   return ecp_work_factor(domain().get_curve().get_p().bits());
   }

EC_PublicKey::EC_PublicKey(const EC_Group& dom_par,
                           const PointGFp& pub_point) :
   domain_params(dom_par), public_key(pub_point),
   domain_encoding(EC_DOMPAR_ENC_EXPLICIT)
   {
   if(domain().get_curve() != public_point().get_curve())
      throw Invalid_Argument("EC_PublicKey: curve mismatch in constructor");
   }

EC_PublicKey::EC_PublicKey(const AlgorithmIdentifier& alg_id,
                           const secure_vector<byte>& key_bits)
   {
   domain_params = EC_Group(alg_id.parameters);
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

std::vector<byte> EC_PublicKey::x509_subject_public_key() const
   {
   return unlock(EC2OSP(public_point(), PointGFp::COMPRESSED));
   }

void EC_PublicKey::set_parameter_encoding(EC_Group_Encoding form)
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
* EC_PrivateKey constructor
*/
EC_PrivateKey::EC_PrivateKey(RandomNumberGenerator& rng,
                             const EC_Group& ec_group,
                             const BigInt& x)
   {
   domain_params = ec_group;
   domain_encoding = EC_DOMPAR_ENC_EXPLICIT;

   if(x == 0)
      private_key = BigInt::random_integer(rng, 1, domain().get_order());
   else
      private_key = x;

   public_key = domain().get_base_point() * private_key;

   BOTAN_ASSERT(public_key.on_the_curve(),
                "Generated public key point was on the curve");
   }

secure_vector<byte> EC_PrivateKey::pkcs8_private_key() const
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
                             const secure_vector<byte>& key_bits)
   {
   domain_params = EC_Group(alg_id.parameters);
   domain_encoding = EC_DOMPAR_ENC_EXPLICIT;

   OID key_parameters;
   secure_vector<byte> public_key_bits;

   BER_Decoder(key_bits)
      .start_cons(SEQUENCE)
         .decode_and_check<size_t>(1, "Unknown version code for ECC key")
         .decode_octet_string_bigint(private_key)
         .decode_optional(key_parameters, ASN1_Tag(0), PRIVATE)
         .decode_optional_string(public_key_bits, BIT_STRING, 1, PRIVATE)
      .end_cons();

   if(!key_parameters.empty() && key_parameters != alg_id.oid)
      throw Decoding_Error("EC_PrivateKey - inner and outer OIDs did not match");

   if(public_key_bits.empty())
      {
      public_key = domain().get_base_point() * private_key;

      BOTAN_ASSERT(public_key.on_the_curve(),
                   "Public point derived from loaded key was on the curve");
      }
   else
      {
      public_key = OS2ECP(public_key_bits, domain().get_curve());
      // OS2ECP verifies that the point is on the curve
      }
   }

}
