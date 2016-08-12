/*
* OCSP
* (C) 2012,2013 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/ocsp.h>
#include <botan/certstor.h>
#include <botan/der_enc.h>
#include <botan/ber_dec.h>
#include <botan/x509_ext.h>
#include <botan/oids.h>
#include <botan/base64.h>
#include <botan/pubkey.h>
#include <botan/x509path.h>
#include <botan/http_util.h>

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

void check_signature(const std::vector<byte>& tbs_response,
                     const AlgorithmIdentifier& sig_algo,
                     const std::vector<byte>& signature,
                     const X509_Certificate& cert)
   {
   std::unique_ptr<Public_Key> pub_key(cert.subject_public_key());

   const std::vector<std::string> sig_info =
      split_on(OIDS::lookup(sig_algo.oid), '/');

   if(sig_info.size() != 2 || sig_info[0] != pub_key->algo_name())
      throw Exception("Information in OCSP response does not match cert");

   std::string padding = sig_info[1];
   Signature_Format format =
      (pub_key->message_parts() >= 2) ? DER_SEQUENCE : IEEE_1363;

   PK_Verifier verifier(*pub_key, padding, format);

   if(!verifier.verify_message(ASN1::put_in_sequence(tbs_response), signature))
      throw Exception("Signature on OCSP response does not verify");
   }

void check_signature(const std::vector<byte>& tbs_response,
                     const AlgorithmIdentifier& sig_algo,
                     const std::vector<byte>& signature,
                     const Certificate_Store& trusted_roots,
                     const std::vector<X509_Certificate>& certs)
   {
   if(certs.size() < 1)
      throw Invalid_Argument("Short cert chain for check_signature");

   if(trusted_roots.certificate_known(certs[0]))
      return check_signature(tbs_response, sig_algo, signature, certs[0]);

   // Otherwise attempt to chain the signing cert to a trust root

   if(!certs[0].allowed_extended_usage("PKIX.OCSPSigning"))
      throw Exception("OCSP response cert does not allow OCSP signing");

   auto result = x509_path_validate(certs, Path_Validation_Restrictions(), trusted_roots);

   if(!result.successful_validation())
      throw Exception("Certificate validation failure: " + result.result_string());

   if(!trusted_roots.certificate_known(result.trust_root())) // not needed anymore?
      throw Exception("Certificate chain roots in unknown/untrusted CA");

   const std::vector<X509_Certificate>& cert_path = result.cert_path();

   check_signature(tbs_response, sig_algo, signature, cert_path[0]);
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
   BER_Decoder response_outer = BER_Decoder(response_bits).start_cons(SEQUENCE);

   size_t resp_status = 0;

   response_outer.decode(resp_status, ENUMERATED, UNIVERSAL);

   if(resp_status != 0)
      throw Exception("OCSP response status " + std::to_string(resp_status));

   if(response_outer.more_items())
      {
      BER_Decoder response_bytes =
         response_outer.start_cons(ASN1_Tag(0), CONTEXT_SPECIFIC).start_cons(SEQUENCE);

      response_bytes.decode_and_check(OID("1.3.6.1.5.5.7.48.1.1"),
                                      "Unknown response type in OCSP response");

      BER_Decoder basicresponse =
         BER_Decoder(response_bytes.get_next_octet_string()).start_cons(SEQUENCE);

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

      size_t responsedata_version = 0;
      X509_DN name;
      std::vector<byte> key_hash;
      X509_Time produced_at;
      Extensions extensions;

      BER_Decoder(tbs_bits)
         .decode_optional(responsedata_version, ASN1_Tag(0),
                          ASN1_Tag(CONSTRUCTED | CONTEXT_SPECIFIC))

         .decode_optional(name, ASN1_Tag(1),
                          ASN1_Tag(CONSTRUCTED | CONTEXT_SPECIFIC))

         .decode_optional_string(key_hash, OCTET_STRING, 2,
                                 ASN1_Tag(CONSTRUCTED | CONTEXT_SPECIFIC))

         .decode(produced_at)

         .decode_list(m_responses)

         .decode_optional(extensions, ASN1_Tag(1),
                          ASN1_Tag(CONSTRUCTED | CONTEXT_SPECIFIC));

      if(certs.empty())
         {
         if(auto cert = trusted_roots.find_cert(name, std::vector<byte>()))
            certs.push_back(*cert);
         else
            throw Exception("Could not find certificate that signed OCSP response");
         }

      check_signature(tbs_bits, sig_algo, signature, trusted_roots, certs);
      }

   response_outer.end_cons();
   }

Certificate_Status_Code Response::status_for(const X509_Certificate& issuer,
                                                   const X509_Certificate& subject) const
   {
   for(const auto& response : m_responses)
      {
      if(response.certid().is_id_for(issuer, subject))
         {
         X509_Time current_time(std::chrono::system_clock::now());

         if(response.cert_status() == 1)
            return Certificate_Status_Code::CERT_IS_REVOKED;

         if(response.this_update() > current_time)
            return Certificate_Status_Code::OCSP_NOT_YET_VALID;

         if(response.next_update().time_is_set() && current_time > response.next_update())
            return Certificate_Status_Code::OCSP_HAS_EXPIRED;

         if(response.cert_status() == 0)
            return Certificate_Status_Code::OCSP_RESPONSE_GOOD;
         else
            return Certificate_Status_Code::OCSP_BAD_STATUS;
         }
      }

   return Certificate_Status_Code::OCSP_CERT_NOT_LISTED;
   }

Response online_check(const X509_Certificate& issuer,
                      const X509_Certificate& subject,
                      const Certificate_Store* trusted_roots)
   {
   const std::string responder_url = subject.ocsp_responder();

   if(responder_url.empty())
      throw Exception("No OCSP responder specified");

   OCSP::Request req(issuer, subject);

   auto http = HTTP::POST_sync(responder_url,
                               "application/ocsp-request",
                               req.BER_encode());

   http.throw_unless_ok();

   // Check the MIME type?

   OCSP::Response response(*trusted_roots, http.body());

   return response;
   }

}

}
