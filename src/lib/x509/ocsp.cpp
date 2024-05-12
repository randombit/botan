/*
* OCSP
* (C) 2012,2013 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/ocsp.h>

#include <botan/base64.h>
#include <botan/ber_dec.h>
#include <botan/certstor.h>
#include <botan/der_enc.h>
#include <botan/pubkey.h>
#include <botan/x509_ext.h>
#include <botan/internal/parsing.h>

#include <functional>

#if defined(BOTAN_HAS_HTTP_UTIL)
   #include <botan/internal/http_util.h>
#endif

namespace Botan::OCSP {

namespace {

// TODO: should this be in a header somewhere?
void decode_optional_list(BER_Decoder& ber, ASN1_Type tag, std::vector<X509_Certificate>& output) {
   BER_Object obj = ber.get_next_object();

   if(obj.is_a(tag, ASN1_Class::ContextSpecific | ASN1_Class::Constructed) == false) {
      ber.push_back(obj);
      return;
   }

   BER_Decoder list(obj);

   while(list.more_items()) {
      BER_Object certbits = list.get_next_object();
      X509_Certificate cert(certbits.bits(), certbits.length());
      output.push_back(std::move(cert));
   }
}

}  // namespace

Request::Request(const X509_Certificate& issuer_cert, const X509_Certificate& subject_cert) :
      m_issuer(issuer_cert), m_certid(m_issuer, BigInt::from_bytes(subject_cert.serial_number())) {
   if(subject_cert.issuer_dn() != issuer_cert.subject_dn()) {
      throw Invalid_Argument("Invalid cert pair to OCSP::Request (mismatched issuer,subject args?)");
   }
}

Request::Request(const X509_Certificate& issuer_cert, const BigInt& subject_serial) :
      m_issuer(issuer_cert), m_certid(m_issuer, subject_serial) {}

std::vector<uint8_t> Request::BER_encode() const {
   std::vector<uint8_t> output;
   DER_Encoder(output)
      .start_sequence()
      .start_sequence()
      .start_explicit(0)
      .encode(static_cast<size_t>(0))  // version #
      .end_explicit()
      .start_sequence()
      .start_sequence()
      .encode(m_certid)
      .end_cons()
      .end_cons()
      .end_cons()
      .end_cons();

   return output;
}

std::string Request::base64_encode() const {
   return Botan::base64_encode(BER_encode());
}

Response::Response(Certificate_Status_Code status) :
      m_status(Response_Status_Code::Successful), m_dummy_response_status(status) {}

Response::Response(const uint8_t response_bits[], size_t response_bits_len) :
      m_response_bits(response_bits, response_bits + response_bits_len) {
   BER_Decoder response_outer = BER_Decoder(m_response_bits).start_sequence();

   size_t resp_status = 0;

   response_outer.decode(resp_status, ASN1_Type::Enumerated, ASN1_Class::Universal);

   m_status = static_cast<Response_Status_Code>(resp_status);

   if(m_status != Response_Status_Code::Successful) {
      return;
   }

   if(response_outer.more_items()) {
      BER_Decoder response_bytes = response_outer.start_context_specific(0).start_sequence();

      response_bytes.decode_and_check(OID("1.3.6.1.5.5.7.48.1.1"), "Unknown response type in OCSP response");

      BER_Decoder basicresponse = BER_Decoder(response_bytes.get_next_octet_string()).start_sequence();

      basicresponse.start_sequence()
         .raw_bytes(m_tbs_bits)
         .end_cons()
         .decode(m_sig_algo)
         .decode(m_signature, ASN1_Type::BitString);
      decode_optional_list(basicresponse, ASN1_Type(0), m_certs);

      size_t responsedata_version = 0;
      Extensions extensions;

      BER_Decoder(m_tbs_bits)
         .decode_optional(responsedata_version, ASN1_Type(0), ASN1_Class::ContextSpecific | ASN1_Class::Constructed)

         .decode_optional(m_signer_name, ASN1_Type(1), ASN1_Class::ContextSpecific | ASN1_Class::Constructed)

         .decode_optional_string(
            m_key_hash, ASN1_Type::OctetString, 2, ASN1_Class::ContextSpecific | ASN1_Class::Constructed)

         .decode(m_produced_at)

         .decode_list(m_responses)

         .decode_optional(extensions, ASN1_Type(1), ASN1_Class::ContextSpecific | ASN1_Class::Constructed);

      const bool has_signer = !m_signer_name.empty();
      const bool has_key_hash = !m_key_hash.empty();

      if(has_signer && has_key_hash) {
         throw Decoding_Error("OCSP response includes both byName and byKey in responderID field");
      }
      if(!has_signer && !has_key_hash) {
         throw Decoding_Error("OCSP response contains neither byName nor byKey in responderID field");
      }
   }

   response_outer.end_cons();
}

bool Response::is_issued_by(const X509_Certificate& candidate) const {
   if(!m_signer_name.empty()) {
      return (candidate.subject_dn() == m_signer_name);
   }

   if(!m_key_hash.empty()) {
      return (candidate.subject_public_key_bitstring_sha1() == m_key_hash);
   }

   return false;
}

Certificate_Status_Code Response::verify_signature(const X509_Certificate& issuer) const {
   if(m_dummy_response_status) {
      return m_dummy_response_status.value();
   }

   if(m_signer_name.empty() && m_key_hash.empty()) {
      return Certificate_Status_Code::OCSP_RESPONSE_INVALID;
   }

   if(!is_issued_by(issuer)) {
      return Certificate_Status_Code::OCSP_ISSUER_NOT_FOUND;
   }

   try {
      auto pub_key = issuer.subject_public_key();

      PK_Verifier verifier(*pub_key, m_sig_algo);

      if(verifier.verify_message(ASN1::put_in_sequence(m_tbs_bits), m_signature)) {
         return Certificate_Status_Code::OCSP_SIGNATURE_OK;
      } else {
         return Certificate_Status_Code::OCSP_SIGNATURE_ERROR;
      }
   } catch(Exception&) {
      return Certificate_Status_Code::OCSP_SIGNATURE_ERROR;
   }
}

std::optional<X509_Certificate> Response::find_signing_certificate(
   const X509_Certificate& issuer_certificate, const Certificate_Store* trusted_ocsp_responders) const {
   using namespace std::placeholders;

   // Check whether the CA issuing the certificate in question also signed this
   if(is_issued_by(issuer_certificate)) {
      return issuer_certificate;
   }

   // Then try to find a delegated responder certificate in the stapled certs
   auto match = std::find_if(m_certs.begin(), m_certs.end(), std::bind(&Response::is_issued_by, this, _1));
   if(match != m_certs.end()) {
      return *match;
   }

   // Last resort: check the additionally provides trusted OCSP responders
   if(trusted_ocsp_responders) {
      if(!m_key_hash.empty()) {
         auto signing_cert = trusted_ocsp_responders->find_cert_by_pubkey_sha1(m_key_hash);
         if(signing_cert) {
            return signing_cert;
         }
      }

      if(!m_signer_name.empty()) {
         auto signing_cert = trusted_ocsp_responders->find_cert(m_signer_name, {});
         if(signing_cert) {
            return signing_cert;
         }
      }
   }

   return std::nullopt;
}

Certificate_Status_Code Response::status_for(const X509_Certificate& issuer,
                                             const X509_Certificate& subject,
                                             std::chrono::system_clock::time_point ref_time,
                                             std::chrono::seconds max_age) const {
   if(m_dummy_response_status) {
      return m_dummy_response_status.value();
   }

   for(const auto& response : m_responses) {
      if(response.certid().is_id_for(issuer, subject)) {
         X509_Time x509_ref_time(ref_time);

         if(response.cert_status() == 1) {
            return Certificate_Status_Code::CERT_IS_REVOKED;
         }

         if(response.this_update() > x509_ref_time) {
            return Certificate_Status_Code::OCSP_NOT_YET_VALID;
         }

         if(response.next_update().time_is_set()) {
            if(x509_ref_time > response.next_update()) {
               return Certificate_Status_Code::OCSP_HAS_EXPIRED;
            }
         } else if(max_age > std::chrono::seconds::zero() &&
                   ref_time - response.this_update().to_std_timepoint() > max_age) {
            return Certificate_Status_Code::OCSP_IS_TOO_OLD;
         }

         if(response.cert_status() == 0) {
            return Certificate_Status_Code::OCSP_RESPONSE_GOOD;
         } else {
            return Certificate_Status_Code::OCSP_BAD_STATUS;
         }
      }
   }

   return Certificate_Status_Code::OCSP_CERT_NOT_LISTED;
}

#if defined(BOTAN_HAS_HTTP_UTIL)

Response online_check(const X509_Certificate& issuer,
                      const BigInt& subject_serial,
                      std::string_view ocsp_responder,
                      std::chrono::milliseconds timeout) {
   if(ocsp_responder.empty()) {
      throw Invalid_Argument("No OCSP responder specified");
   }

   OCSP::Request req(issuer, subject_serial);

   auto http = HTTP::POST_sync(ocsp_responder, "application/ocsp-request", req.BER_encode(), 1, timeout);

   http.throw_unless_ok();

   // Check the MIME type?

   return OCSP::Response(http.body());
}

Response online_check(const X509_Certificate& issuer,
                      const X509_Certificate& subject,
                      std::chrono::milliseconds timeout) {
   if(subject.issuer_dn() != issuer.subject_dn()) {
      throw Invalid_Argument("Invalid cert pair to OCSP::online_check (mismatched issuer,subject args?)");
   }

   return online_check(issuer, BigInt::from_bytes(subject.serial_number()), subject.ocsp_responder(), timeout);
}

#endif

}  // namespace Botan::OCSP
