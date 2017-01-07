/*
* ECC Domain Parameters
*
* (C) 2007 Falko Strenzke, FlexSecure GmbH
*     2008 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/ec_group.h>
#include <botan/ber_dec.h>
#include <botan/der_enc.h>
#include <botan/oids.h>
#include <botan/pem.h>

namespace Botan {

EC_Group::EC_Group(const OID& domain_oid)
   {
   const std::string pem = PEM_for_named_group(OIDS::lookup(domain_oid));

   if(pem == "")
      throw Lookup_Error("No ECC domain data for " + domain_oid.as_string());

   *this = EC_Group(pem);
   m_oid = domain_oid.as_string();
   }

EC_Group::EC_Group(const std::string& str)
   {
   if(str == "")
      return; // no initialization / uninitialized

   try
      {
      std::vector<uint8_t> ber =
         unlock(PEM_Code::decode_check_label(str, "EC PARAMETERS"));

      *this = EC_Group(ber);
      }
   catch(Decoding_Error) // hmm, not PEM?
      {
      *this = EC_Group(OIDS::lookup(str));
      }
   }

EC_Group::EC_Group(const std::vector<uint8_t>& ber_data)
   {
   BER_Decoder ber(ber_data);
   BER_Object obj = ber.get_next_object();

   if(obj.type_tag == NULL_TAG)
      throw Decoding_Error("Cannot handle ImplicitCA ECDSA parameters");
   else if(obj.type_tag == OBJECT_ID)
      {
      OID dom_par_oid;
      BER_Decoder(ber_data).decode(dom_par_oid);
      *this = EC_Group(dom_par_oid);
      }
   else if(obj.type_tag == SEQUENCE)
      {
      BigInt p, a, b;
      std::vector<uint8_t> sv_base_point;

      BER_Decoder(ber_data)
         .start_cons(SEQUENCE)
           .decode_and_check<size_t>(1, "Unknown ECC param version code")
           .start_cons(SEQUENCE)
            .decode_and_check(OID("1.2.840.10045.1.1"),
                              "Only prime ECC fields supported")
             .decode(p)
           .end_cons()
           .start_cons(SEQUENCE)
             .decode_octet_string_bigint(a)
             .decode_octet_string_bigint(b)
           .end_cons()
           .decode(sv_base_point, OCTET_STRING)
           .decode(m_order)
           .decode(m_cofactor)
         .end_cons()
         .verify_end();

      m_curve = CurveGFp(p, a, b);
      m_base_point = OS2ECP(sv_base_point, m_curve);
      }
   else
      throw Decoding_Error("Unexpected tag while decoding ECC domain params");
   }

std::vector<uint8_t>
EC_Group::DER_encode(EC_Group_Encoding form) const
   {
   if(form == EC_DOMPAR_ENC_EXPLICIT)
      {
      const size_t ecpVers1 = 1;
      OID curve_type("1.2.840.10045.1.1");

      const size_t p_bytes = m_curve.get_p().bytes();

      return DER_Encoder()
         .start_cons(SEQUENCE)
            .encode(ecpVers1)
            .start_cons(SEQUENCE)
               .encode(curve_type)
               .encode(m_curve.get_p())
            .end_cons()
            .start_cons(SEQUENCE)
               .encode(BigInt::encode_1363(m_curve.get_a(), p_bytes),
                       OCTET_STRING)
               .encode(BigInt::encode_1363(m_curve.get_b(), p_bytes),
                       OCTET_STRING)
            .end_cons()
            .encode(EC2OSP(m_base_point, PointGFp::UNCOMPRESSED), OCTET_STRING)
            .encode(m_order)
            .encode(m_cofactor)
         .end_cons()
         .get_contents_unlocked();
      }
   else if(form == EC_DOMPAR_ENC_OID)
      return DER_Encoder().encode(OID(get_oid())).get_contents_unlocked();
   else if(form == EC_DOMPAR_ENC_IMPLICITCA)
      return DER_Encoder().encode_null().get_contents_unlocked();
   else
      throw Internal_Error("EC_Group::DER_encode: Unknown encoding");
   }

std::string EC_Group::PEM_encode() const
   {
   const std::vector<uint8_t> der = DER_encode(EC_DOMPAR_ENC_EXPLICIT);
   return PEM_Code::encode(der, "EC PARAMETERS");
   }

}
