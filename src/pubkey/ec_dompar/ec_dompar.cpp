/*
* ECC Domain Parameters
*
* (C) 2007 Falko Strenzke, FlexSecure GmbH
*     2008 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/ec_dompar.h>
#include <botan/ber_dec.h>
#include <botan/der_enc.h>
#include <botan/libstate.h>
#include <botan/oids.h>
#include <botan/pem.h>

namespace Botan {

EC_Domain_Params::EC_Domain_Params(const OID& domain_oid)
   {
   std::string pem =
      global_state().get("ec", OIDS::lookup(domain_oid));

   if(pem == "")
      throw Lookup_Error("No ECC domain data for " + domain_oid.as_string());

   *this = EC_Domain_Params(pem);
   }

EC_Domain_Params::EC_Domain_Params(const std::string& pem)
   {
   DataSource_Memory input(pem);

   *this = EC_Domain_Params(
      PEM_Code::decode_check_label(input, "ECC DOMAIN PARAMETERS"));
   }

EC_Domain_Params::EC_Domain_Params(const MemoryRegion<byte>& ber_data)
   {
   BER_Decoder ber(ber_data);
   BER_Object obj = ber.get_next_object();

   if(obj.type_tag == NULL_TAG)
      throw Decoding_Error("Cannot handle ImplicitCA ECDSA parameters");
   else if(obj.type_tag == OBJECT_ID)
      {
      OID dom_par_oid;
      BER_Decoder(ber_data).decode(dom_par_oid);
      *this = EC_Domain_Params(dom_par_oid);
      }
   else if(obj.type_tag == SEQUENCE)
      {
      BigInt ecpVers1(1);
      OID curve_type;
      SecureVector<byte> sv_a;
      SecureVector<byte> sv_b;
      BigInt p;
      SecureVector<byte> sv_base_point;

      BER_Decoder(ber_data)
         .start_cons(SEQUENCE)
           .decode(ecpVers1)
           .start_cons(SEQUENCE)
             .decode(curve_type)
             .decode(p)
           .end_cons()
           .start_cons(SEQUENCE)
             .decode(sv_a, OCTET_STRING)
             .decode(sv_b, OCTET_STRING)
           .end_cons()
           .decode(sv_base_point, OCTET_STRING)
           .decode(order)
           .decode(cofactor)
         .end_cons()
         .verify_end();

      if(ecpVers1 != 1)
         throw Decoding_Error("EC_Domain_Params: Unknown version code");

      // Only prime curves supported
      if(curve_type.as_string() != "1.2.840.10045.1.1")
         throw Decoding_Error("Unexpected curve type " + curve_type.as_string());

      curve = CurveGFp(p,
                       BigInt::decode(sv_a, sv_a.size()),
                       BigInt::decode(sv_b, sv_b.size()));

      base_point = OS2ECP(sv_base_point, curve);
      base_point.check_invariants();
      }
   else
      throw Decoding_Error("Unexpected tag while decoding ECC domain params");
   }

SecureVector<byte>
EC_Domain_Params::DER_encode(EC_Domain_Params_Encoding form) const
   {
   if(form == EC_DOMPAR_ENC_EXPLICIT)
      {
      u32bit ecpVers1 = 1;
      OID curve_type("1.2.840.10045.1.1");

      const u32bit p_bytes = curve.get_p().bytes();

      return DER_Encoder()
         .start_cons(SEQUENCE)
            .encode(ecpVers1)
            .start_cons(SEQUENCE)
               .encode(curve_type)
               .encode(curve.get_p())
            .end_cons()
            .start_cons(SEQUENCE)
               .encode(BigInt::encode_1363(curve.get_a(), p_bytes), OCTET_STRING)
               .encode(BigInt::encode_1363(curve.get_b(), p_bytes), OCTET_STRING)
            .end_cons()
            .encode(EC2OSP(base_point, PointGFp::UNCOMPRESSED), OCTET_STRING)
            .encode(order)
            .encode(cofactor)
         .end_cons()
         .get_contents();
      }
   else if(form == EC_DOMPAR_ENC_OID)
      return DER_Encoder().encode(get_oid()).get_contents();
   else if(form == EC_DOMPAR_ENC_IMPLICITCA)
      return DER_Encoder().encode_null().get_contents();

   throw Internal_Error("EC_Domain_Params::encode_DER: Unknown encoding");
   }

std::string EC_Domain_Params::PEM_encode() const
   {
   SecureVector<byte> der = DER_encode(EC_DOMPAR_ENC_EXPLICIT);
   return PEM_Code::encode(der, "ECC DOMAIN PARAMETERS");
   }

}
