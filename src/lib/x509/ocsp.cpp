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
#include <botan/parsing.h>

#if defined(BOTAN_HAS_HTTP_UTIL)
  #include <botan/http_util.h>
#endif

namespace Botan {

namespace OCSP {

namespace {

// TODO: should this be in a header somewhere?
void decode_optional_list(BER_Decoder& ber,
                          ASN1_Tag tag,
                          std::vector<X509_Certificate>& output)
   {
   BER_Object obj = ber.get_next_object();

   if(obj.is_a(tag, ASN1_Tag(CONTEXT_SPECIFIC | CONSTRUCTED)) == false)
      {
      ber.push_back(obj);
      return;
      }

   BER_Decoder list(obj);

   while(list.more_items())
      {
      BER_Object certbits = list.get_next_object();
      X509_Certificate cert(certbits.bits(), certbits.length());
      output.push_back(std::move(cert));
      }
   }

}

Request::Request(const X509_Certificate& issuer_cert,
                 const X509_Certificate& subject_cert) :
   m_issuer(issuer_cert),
   m_certid(m_issuer, BigInt::decode(subject_cert.serial_number()))
   {
   if(subject_cert.issuer_dn() != issuer_cert.subject_dn())
      throw Invalid_Argument("Invalid cert pair to OCSP::Request (mismatched issuer,subject args?)");
   }

Request::Request(const X509_Certificate& issuer_cert,
                 const BigInt& subject_serial) :
   m_issuer(issuer_cert),
   m_certid(m_issuer, subject_serial)
   {
   }

std::vector<uint8_t> Request::BER_encode() const
   {
   std::vector<uint8_t> output;
   DER_Encoder(output).start_cons(SEQUENCE)
        .start_cons(SEQUENCE)
          .start_explicit(0)
            .encode(static_cast<size_t>(0)) // version #
          .end_explicit()
            .start_cons(SEQUENCE)
              .start_cons(SEQUENCE)
                .encode(m_certid)
              .end_cons()
            .end_cons()
          .end_cons()
      .end_cons();

   return output;
   }

std::string Request::base64_encode() const
   {
   return Botan::base64_encode(BER_encode());
   }

Response::Response(Certificate_Status_Code status)
   {
   m_status = Response_Status_Code::Successful;
   m_dummy_response_status = status;
   }

Response::Response(const uint8_t response_bits[], size_t response_bits_len) :
   m_response_bits(response_bits, response_bits + response_bits_len)
   {
   m_dummy_response_status = Certificate_Status_Code::OCSP_RESPONSE_INVALID;

   BER_Decoder response_outer = BER_Decoder(m_response_bits).start_cons(SEQUENCE);

   size_t resp_status = 0;

   response_outer.decode(resp_status, ENUMERATED, UNIVERSAL);

   m_status = static_cast<Response_Status_Code>(resp_status);

   if(m_status != Response_Status_Code::Successful)
      { return; }

   if(response_outer.more_items())
      {
      BER_Decoder response_bytes =
         response_outer.start_cons(ASN1_Tag(0), CONTEXT_SPECIFIC).start_cons(SEQUENCE);

      response_bytes.decode_and_check(OID("1.3.6.1.5.5.7.48.1.1"),
                                      "Unknown response type in OCSP response");

      BER_Decoder basicresponse =
         BER_Decoder(response_bytes.get_next_octet_string()).start_cons(SEQUENCE);

      basicresponse.start_cons(SEQUENCE)
           .raw_bytes(m_tbs_bits)
         .end_cons()
         .decode(m_sig_algo)
         .decode(m_signature, BIT_STRING);
      decode_optional_list(basicresponse, ASN1_Tag(0), m_certs);

      size_t responsedata_version = 0;
      Extensions extensions;

      BER_Decoder(m_tbs_bits)
         .decode_optional(responsedata_version, ASN1_Tag(0),
                          ASN1_Tag(CONSTRUCTED | CONTEXT_SPECIFIC))

         .decode_optional(m_signer_name, ASN1_Tag(1),
                          ASN1_Tag(CONSTRUCTED | CONTEXT_SPECIFIC))

         .decode_optional_string(m_key_hash, OCTET_STRING, 2,
                                 ASN1_Tag(CONSTRUCTED | CONTEXT_SPECIFIC))

         .decode(m_produced_at)

         .decode_list(m_responses)

         .decode_optional(extensions, ASN1_Tag(1),
                          ASN1_Tag(CONSTRUCTED | CONTEXT_SPECIFIC));
      }

   response_outer.end_cons();
   }

Certificate_Status_Code Response::verify_signature(const X509_Certificate& issuer) const
   {
   if (m_responses.empty())
      return m_dummy_response_status;

   try
      {
      std::unique_ptr<Public_Key> pub_key(issuer.subject_public_key());

      const std::vector<std::string> sig_info =
         split_on(m_sig_algo.get_oid().to_formatted_string(), '/');

      if(sig_info.size() != 2 || sig_info[0] != pub_key->algo_name())
         return Certificate_Status_Code::OCSP_RESPONSE_INVALID;

      std::string padding = sig_info[1];
      const Signature_Format format = pub_key->default_x509_signature_format();

      PK_Verifier verifier(*pub_key, padding, format);

      if(verifier.verify_message(ASN1::put_in_sequence(m_tbs_bits), m_signature))
         return Certificate_Status_Code::OCSP_SIGNATURE_OK;
      else
         return Certificate_Status_Code::OCSP_SIGNATURE_ERROR;
      }
   catch(Exception&)
      {
      return Certificate_Status_Code::OCSP_SIGNATURE_ERROR;
      }
   }

Certificate_Status_Code Response::check_signature(const std::vector<Certificate_Store*>& trusted_roots,
                                                  const std::vector<std::shared_ptr<const X509_Certificate>>& ee_cert_path) const
   {
   if (m_responses.empty())
      return m_dummy_response_status;

   std::shared_ptr<const X509_Certificate> signing_cert;

   for(size_t i = 0; i != trusted_roots.size(); ++i)
      {
      if(m_signer_name.empty() && m_key_hash.empty())
         return Certificate_Status_Code::OCSP_RESPONSE_INVALID;

      if(!m_signer_name.empty())
         {
         signing_cert = trusted_roots[i]->find_cert(m_signer_name, std::vector<uint8_t>());
         if(signing_cert)
            {
            break;
            }
         }

      if(m_key_hash.size() > 0)
         {
         signing_cert = trusted_roots[i]->find_cert_by_pubkey_sha1(m_key_hash);
         if(signing_cert)
            {
            break;
            }
         }
      }

   if(!signing_cert && ee_cert_path.size() > 1)
      {
      // End entity cert is not allowed to sign their own OCSP request :)
      for(size_t i = 1; i < ee_cert_path.size(); ++i)
         {
         // Check all CA certificates in the (assumed validated) EE cert path
         if(!m_signer_name.empty() && ee_cert_path[i]->subject_dn() == m_signer_name)
            {
            signing_cert = ee_cert_path[i];
            break;
            }

         if(m_key_hash.size() > 0 && ee_cert_path[i]->subject_public_key_bitstring_sha1() == m_key_hash)
            {
            signing_cert = ee_cert_path[i];
            break;
            }
         }
      }

   if(!signing_cert && m_certs.size() > 0)
      {
      for(size_t i = 0; i < m_certs.size(); ++i)
         {
         // Check all CA certificates in the (assumed validated) EE cert path
         if(!m_signer_name.empty() && m_certs[i].subject_dn() == m_signer_name)
            {
            signing_cert = std::make_shared<const X509_Certificate>(m_certs[i]);
            break;
            }

         if(m_key_hash.size() > 0 && m_certs[i].subject_public_key_bitstring_sha1() == m_key_hash)
            {
            signing_cert = std::make_shared<const X509_Certificate>(m_certs[i]);
            break;
            }
         }
      }

   if(!signing_cert)
      return Certificate_Status_Code::OCSP_ISSUER_NOT_FOUND;

   if(!signing_cert->allowed_usage(CRL_SIGN) &&
      !signing_cert->allowed_extended_usage("PKIX.OCSPSigning"))
      {
      return Certificate_Status_Code::OCSP_RESPONSE_MISSING_KEYUSAGE;
      }

   return this->verify_signature(*signing_cert);
   }

Certificate_Status_Code Response::status_for(const X509_Certificate& issuer,
      const X509_Certificate& subject,
      std::chrono::system_clock::time_point ref_time,
      std::chrono::seconds max_age) const
   {
   if(m_responses.empty())
      { return m_dummy_response_status; }

   for(const auto& response : m_responses)
      {
      if(response.certid().is_id_for(issuer, subject))
         {
         X509_Time x509_ref_time(ref_time);

         if(response.cert_status() == 1)
            { return Certificate_Status_Code::CERT_IS_REVOKED; }

         if(response.this_update() > x509_ref_time)
            { return Certificate_Status_Code::OCSP_NOT_YET_VALID; }

         if(response.next_update().time_is_set())
            {
            if(x509_ref_time > response.next_update())
               { return Certificate_Status_Code::OCSP_HAS_EXPIRED; }
            }
         else if(max_age > std::chrono::seconds::zero() && ref_time - response.this_update().to_std_timepoint() > max_age)
            { return Certificate_Status_Code::OCSP_IS_TOO_OLD; }

         if(response.cert_status() == 0)
            { return Certificate_Status_Code::OCSP_RESPONSE_GOOD; }
         else
            { return Certificate_Status_Code::OCSP_BAD_STATUS; }
         }
      }

   return Certificate_Status_Code::OCSP_CERT_NOT_LISTED;
   }

#if defined(BOTAN_HAS_HTTP_UTIL)

Response online_check(const X509_Certificate& issuer,
                      const BigInt& subject_serial,
                      const std::string& ocsp_responder,
                      Certificate_Store* trusted_roots,
                      std::chrono::milliseconds timeout)
   {
   if(ocsp_responder.empty())
      throw Invalid_Argument("No OCSP responder specified");

   OCSP::Request req(issuer, subject_serial);

   auto http = HTTP::POST_sync(ocsp_responder,
                               "application/ocsp-request",
                               req.BER_encode(),
                               1,
                               timeout);

   http.throw_unless_ok();

   // Check the MIME type?

   OCSP::Response response(http.body());

   std::vector<Certificate_Store*> trusted_roots_vec;
   trusted_roots_vec.push_back(trusted_roots);

   if(trusted_roots)
      response.check_signature(trusted_roots_vec);

   return response;
   }


Response online_check(const X509_Certificate& issuer,
                      const X509_Certificate& subject,
                      Certificate_Store* trusted_roots,
                      std::chrono::milliseconds timeout)
   {
   if(subject.issuer_dn() != issuer.subject_dn())
      throw Invalid_Argument("Invalid cert pair to OCSP::online_check (mismatched issuer,subject args?)");

   return online_check(issuer,
                       BigInt::decode(subject.serial_number()),
                       subject.ocsp_responder(),
                       trusted_roots,
                       timeout);
   }

#endif

}

}
