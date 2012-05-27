/*
* OCSP
* (C) 2012 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/ocsp.h>
#include <botan/der_enc.h>
#include <botan/ber_dec.h>
#include <botan/x509_ext.h>
#include <botan/base64.h>

#include <iostream>
#include <botan/hex.h>

namespace Botan {

namespace OCSP {

namespace {

void decode_optional_list(BER_Decoder& ber,
                          ASN1_Tag tag,
                          std::vector<X509_Certificate>& output)
   {
   BER_Object obj = ber.get_next_object();

   if(obj.type_tag != tag || obj.class_tag != (CONTEXT_SPECIFIC | CONSTRUCTED))
      {
      ber.push_back(obj);
      return;
      }

   BER_Decoder list(obj.value);

   while(list.more_items())
      {
      BER_Object certbits = list.get_next_object();
      X509_Certificate cert(unlock(certbits.value));
      output.push_back(std::move(cert));
      }
   }

}

std::vector<byte> Request::BER_encode() const
   {
   CertID certid(m_issuer, m_subject);

   return DER_Encoder().start_cons(SEQUENCE)
        .start_cons(SEQUENCE)
          .start_explicit(0)
            .encode(static_cast<size_t>(0)) // version #
          .end_explicit()
            .start_cons(SEQUENCE)
              .start_cons(SEQUENCE)
                .encode(certid)
              .end_cons()
            .end_cons()
          .end_cons()
      .end_cons().get_contents_unlocked();
   }

std::string Request::base64_encode() const
   {
   return Botan::base64_encode(BER_encode());
   }

Response::Response(const std::vector<byte>& response_bits)
   {
   BER_Decoder ber(response_bits);

   BER_Decoder response_outer = ber.start_cons(SEQUENCE);

   size_t resp_status = 0;

   response_outer.decode(resp_status, ENUMERATED, UNIVERSAL);

   if(response_outer.more_items())
      {
      BER_Decoder response_bytes =
         response_outer.start_cons(ASN1_Tag(0), CONTEXT_SPECIFIC).start_cons(SEQUENCE);

      response_bytes.decode_and_check(OID("1.3.6.1.5.5.7.48.1.1"),
                                      "Unknown response OID in OCSP response");

      std::vector<byte> response_vec;
      response_bytes.decode(response_vec, OCTET_STRING);

      BER_Decoder basicresponse_x(response_vec);

      BER_Decoder basicresponse = basicresponse_x.start_cons(SEQUENCE);
      BER_Decoder tbs_response = basicresponse.start_cons(SEQUENCE);

      AlgorithmIdentifier sig_algo;
      std::vector<byte> signature;

      basicresponse.decode(sig_algo);
      basicresponse.decode(signature, BIT_STRING);

      std::vector<X509_Certificate> certs;
      decode_optional_list(basicresponse, ASN1_Tag(0), certs);

      size_t responsedata_version = 0;
      X509_DN name;
      std::vector<byte> key_hash;
      X509_Time produced_at;

      // decode_optional_and_check(0,  ASN1_Tag(0), ASN1_Tag(CONSTRUCTED | CONTEXT_SPECIFIC));
      tbs_response.decode_optional(responsedata_version, ASN1_Tag(0),
                                   ASN1_Tag(CONSTRUCTED | CONTEXT_SPECIFIC));

      // Technically a choice: enforce that?
      tbs_response.decode_optional(name, ASN1_Tag(1),
                                   ASN1_Tag(CONSTRUCTED | CONTEXT_SPECIFIC));

      tbs_response.decode_optional_string(key_hash, ASN1_Tag(2),
                                          ASN1_Tag(CONSTRUCTED | CONTEXT_SPECIFIC));

      tbs_response.decode(produced_at);

      tbs_response.decode_list(m_responses);

      Extensions extensions;
      tbs_response.decode_optional(extensions, ASN1_Tag(1),
                                   ASN1_Tag(CONSTRUCTED | CONTEXT_SPECIFIC));
      }

   response_outer.end_cons();

   }

bool Response::affirmative_response_for(const Request& req)
   {
   for(auto response : m_responses)
      if(response.affirmative_response_for(req.issuer(), req.subject()))
         return true;

   return false;
   }

}

}
