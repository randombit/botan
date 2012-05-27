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
#include <botan/oids.h>
#include <botan/base64.h>
#include <botan/pubkey.h>
#include <botan/x509path.h>
#include <memory>

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

bool check_signature(const std::vector<byte>& tbs_response,
                     const AlgorithmIdentifier& sig_algo,
                     const std::vector<byte>& signature,
                     const X509_Certificate& cert)
   {
   try
      {
      std::unique_ptr<Public_Key> pub_key(cert.subject_public_key());

      const std::vector<std::string> sig_info =
         split_on(OIDS::lookup(sig_algo.oid), '/');

      if(sig_info.size() != 2 || sig_info[0] != pub_key->algo_name())
         return false;

      std::string padding = sig_info[1];
      Signature_Format format =
         (pub_key->message_parts() >= 2) ? DER_SEQUENCE : IEEE_1363;

      PK_Verifier verifier(*pub_key, padding, format);

      return verifier.verify_message(
         ASN1::put_in_sequence(tbs_response), signature);
      }
   catch(std::exception& e)
      {
      return false;
      }
   }

bool check_signature(const std::vector<byte>& tbs_response,
                     const AlgorithmIdentifier& sig_algo,
                     const std::vector<byte>& signature,
                     const Certificate_Store& trusted_roots,
                     const std::vector<X509_Certificate>& certs)
   {
   if(trusted_roots.certificate_known(certs[0]))
      return check_signature(tbs_response, sig_algo, signature, certs[0]);

   // Otherwise attempt to chain the signing cert to a trust root

   Path_Validation_Result result =
      x509_path_validate(certs,
                         Path_Validation_Restrictions(),
                         trusted_roots);

   if(!result.successful_validation())
      throw std::runtime_error("Certificate validation failure: " + result.result_string());

   if(!trusted_roots.certificate_known(result.trust_root()))
      throw std::runtime_error("Certificate chain roots in unknown/untrusted CA");

   return check_signature(tbs_response, sig_algo, signature, result.cert_path()[0]);
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

Response::Response(const Certificate_Store& trusted_roots,
                   const std::vector<byte>& response_bits)
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
                                      "Unknown response type in OCSP response");

      std::vector<byte> response_vec;
      response_bytes.decode(response_vec, OCTET_STRING);

      BER_Decoder basicresponse_x(response_vec);

      BER_Decoder basicresponse = basicresponse_x.start_cons(SEQUENCE);

      std::vector<byte> tbs_bits;
      AlgorithmIdentifier sig_algo;
      std::vector<byte> signature;
      std::vector<X509_Certificate> certs;

      basicresponse.start_cons(SEQUENCE)
           .raw_bytes(tbs_bits)
         .end_cons()
         .decode(sig_algo)
         .decode(signature, BIT_STRING);
      decode_optional_list(basicresponse, ASN1_Tag(0), certs);

      BER_Decoder tbs_response(tbs_bits);

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

      if(certs.empty())
         {
         certs = trusted_roots.find_cert_by_subject_and_key_id(name, std::vector<byte>());
         if(certs.empty())
            throw std::runtime_error("Could not find certificate that signed OCSP response");
         }

      if(!check_signature(tbs_bits, sig_algo, signature, trusted_roots, certs))
         throw std::runtime_error("Invalid OCSP response");
      }

   response_outer.end_cons();

   }

bool Response::affirmative_response_for(const X509_Certificate& issuer,
                                        const X509_Certificate& subject) const
   {
   for(auto response : m_responses)
      if(response.affirmative_response_for(issuer, subject))
         return true;

   return false;
   }

}

}
