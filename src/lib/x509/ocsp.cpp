/*
* OCSP
* (C) 2012,2013 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/ocsp.h>

#include <botan/assert.h>
#include <botan/base64.h>
#include <botan/ber_dec.h>
#include <botan/certstor.h>
#include <botan/der_enc.h>
#include <botan/hash.h>
#include <botan/pubkey.h>
#include <botan/uri.h>
#include <botan/x509_ext.h>
#include <botan/x509path.h>

#if defined(BOTAN_HAS_HTTP_UTIL)
   #include <botan/internal/http_util.h>
#endif

namespace Botan::OCSP {

CertID::CertID(const X509_Certificate& issuer, const BigInt& subject_serial) : m_subject_serial(subject_serial) {
   /*
   In practice it seems some responders, including, notably,
   ocsp.verisign.com, will reject anything but SHA-1 here
   */
   auto hash = HashFunction::create_or_throw("SHA-1");

   m_hash_id = AlgorithmIdentifier(hash->name(), AlgorithmIdentifier::USE_NULL_PARAM);
   m_issuer_key_hash = hash->process<std::vector<uint8_t>>(issuer.subject_public_key_bitstring());
   m_issuer_dn_hash = hash->process<std::vector<uint8_t>>(issuer.raw_subject_dn());
}

bool CertID::is_id_for(const X509_Certificate& issuer, const X509_Certificate& subject) const {
   try {
      if(BigInt::from_bytes(subject.serial_number()) != m_subject_serial) {
         return false;
      }

      const std::string hash_algo = m_hash_id.oid().to_formatted_string();

      if(hash_algo != "SHA-1" && hash_algo != "SHA-256") {
         return false;
      }

      auto hash = HashFunction::create_or_throw(hash_algo);

      /*
      RFC 6960 4.1.1
         issuerNameHash is the hash of the issuer's distinguished name (DN).
         The hash shall be calculated over the DER encoding of the issuer's name
         field in the certificate being checked.
      */
      if(m_issuer_dn_hash != hash->process<std::vector<uint8_t>>(subject.raw_issuer_dn())) {
         return false;
      }

      if(m_issuer_key_hash != hash->process<std::vector<uint8_t>>(issuer.subject_public_key_bitstring())) {
         return false;
      }
   } catch(...) {
      return false;
   }

   return true;
}

void CertID::encode_into(DER_Encoder& to) const {
   to.start_sequence()
      .encode(m_hash_id)
      .encode(m_issuer_dn_hash, ASN1_Type::OctetString)
      .encode(m_issuer_key_hash, ASN1_Type::OctetString)
      .encode(m_subject_serial)
      .end_cons();
}

void CertID::decode_from(BER_Decoder& from) {
   /*
   * RFC 6960 Section 4.1.1
   *
   * CertID ::= SEQUENCE {
   *    hashAlgorithm       AlgorithmIdentifier,
   *    issuerNameHash      OCTET STRING,
   *    issuerKeyHash       OCTET STRING,
   *    serialNumber        CertificateSerialNumber }
   */
   from.start_sequence()
      .decode(m_hash_id)
      .decode(m_issuer_dn_hash, ASN1_Type::OctetString)
      .decode(m_issuer_key_hash, ASN1_Type::OctetString)
      .decode(m_subject_serial)
      .end_cons();
}

void SingleResponse::encode_into(DER_Encoder& /*to*/) const {
   throw Not_Implemented("SingleResponse::encode_into");
}

void SingleResponse::decode_from(BER_Decoder& from) {
   /*
   * RFC 6960 Section 4.2.1
   *
   * SingleResponse ::= SEQUENCE {
   *    certID                       CertID,
   *    certStatus                   CertStatus,
   *    thisUpdate                   GeneralizedTime,
   *    nextUpdate         [0]       EXPLICIT GeneralizedTime OPTIONAL,
   *    singleExtensions   [1]       EXPLICIT Extensions OPTIONAL }
   *
   * CertStatus ::= CHOICE {
   *    good        [0]     IMPLICIT NULL,
   *    revoked     [1]     IMPLICIT RevokedInfo,
   *    unknown     [2]     IMPLICIT UnknownInfo }
   *
   * RevokedInfo ::= SEQUENCE {
   *    revocationTime              GeneralizedTime,
   *    revocationReason    [0]     EXPLICIT CRLReason OPTIONAL }
   */
   BER_Object cert_status;
   Extensions extensions;

   auto seq = from.start_sequence();
   seq.decode(m_certid)
      .get_next(cert_status)
      .decode(m_thisupdate)
      .decode_optional(m_nextupdate, ASN1_Type(0), ASN1_Class::ContextSpecific | ASN1_Class::Constructed);

   if(seq.more_items()) {
      const BER_Object next = seq.get_next_object();
      if(next.is_a(1, ASN1_Class::ContextSpecific | ASN1_Class::Constructed)) {
         BER_Decoder ext_decoder(next, BER_Decoder::Limits::DER());
         extensions.decode_from(ext_decoder, Extension_Context::OCSP_Response);
         ext_decoder.verify_end();
      } else {
         throw Decoding_Error("Unexpected tag in OCSP SingleResponse");
      }
   }
   seq.end_cons();

   const auto cert_status_class = cert_status.get_class();
   if(cert_status_class != ASN1_Class::ContextSpecific &&
      cert_status_class != (ASN1_Class::ContextSpecific | ASN1_Class::Constructed)) {
      throw Decoding_Error("OCSP::SingleResponse: certStatus has unexpected class tag");
   }

   // TODO: should verify the cert_status body and decode RevokedInfo
   m_cert_status = static_cast<uint32_t>(cert_status.type());
   if(m_cert_status > 2) {
      throw Decoding_Error("Unknown OCSP CertStatus tag");
   }

   // We don't currently recognize any extensions here so if any are critical we should reject
   m_has_unknown_critical_ext = !extensions.critical_extensions().empty();
}

namespace {

// TODO: should this be in a header somewhere?
void decode_optional_list(BER_Decoder& ber, ASN1_Type tag, std::vector<X509_Certificate>& output) {
   const BER_Object obj = ber.get_next_object();

   if(!obj.is_a(tag, ASN1_Class::ContextSpecific | ASN1_Class::Constructed)) {
      ber.push_back(obj);
      return;
   }

   BER_Decoder list(obj, BER_Decoder::Limits::DER());
   auto seq = list.start_sequence();
   while(seq.more_items()) {
      output.push_back([&] {
         X509_Certificate cert;
         cert.decode_from(seq);
         return cert;
      }());
   }
   seq.end_cons();
   list.verify_end();
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
   /*
   * RFC 6960 Section 4.1.1
   *
   * OCSPRequest ::= SEQUENCE {
   *    tbsRequest                  TBSRequest,
   *    optionalSignature   [0]    EXPLICIT Signature OPTIONAL }
   *
   * TBSRequest ::= SEQUENCE {
   *    version             [0]    EXPLICIT Version DEFAULT v1,
   *    requestList                SEQUENCE OF Request }
   *
   * Request ::= SEQUENCE {
   *    reqCert                    CertID }
   */
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
   /*
   * RFC 6960 Section 4.2.1
   *
   * OCSPResponse ::= SEQUENCE {
   *    responseStatus         OCSPResponseStatus,
   *    responseBytes      [0] EXPLICIT ResponseBytes OPTIONAL }
   *
   * OCSPResponseStatus ::= ENUMERATED { ... }
   *
   * ResponseBytes ::= SEQUENCE {
   *    responseType   OBJECT IDENTIFIER,
   *    response       OCTET STRING }
   */
   BER_Decoder outer_decoder(m_response_bits, BER_Decoder::Limits::DER());
   BER_Decoder response_outer = outer_decoder.start_sequence();

   size_t resp_status = 0;

   response_outer.decode(resp_status, ASN1_Type::Enumerated, ASN1_Class::Universal);

   /*
   RFC 6960 4.2.1

   OCSPResponseStatus ::= ENUMERATED {
       successful            (0),  -- Response has valid confirmations
       malformedRequest      (1),  -- Illegal confirmation request
       internalError         (2),  -- Internal error in issuer
       tryLater              (3),  -- Try again later
                                   -- (4) is not used
       sigRequired           (5),  -- Must sign the request
       unauthorized          (6)   -- Request unauthorized
   }
   */
   if(resp_status == 4 || resp_status >= 7) {
      throw Decoding_Error("Unknown OCSPResponseStatus code");
   }

   m_status = static_cast<Response_Status_Code>(resp_status);

   /*
   * RFC 6960 4.2.1: "If the value of responseStatus is one of the error
   * conditions, the responseBytes field is not set."
   */
   const bool successful = (m_status == Response_Status_Code::Successful);
   const bool has_response_bytes = response_outer.more_items();

   if(successful && !has_response_bytes) {
      throw Decoding_Error("OCSP response with successful status is missing responseBytes");
   }
   if(!successful && has_response_bytes) {
      throw Decoding_Error("OCSP response with non-successful status includes responseBytes");
   }

   if(successful) {
      BER_Decoder response_bytes_ctx = response_outer.start_context_specific(0);
      BER_Decoder response_bytes = response_bytes_ctx.start_sequence();

      response_bytes.decode_and_check(OID({1, 3, 6, 1, 5, 5, 7, 48, 1, 1}), "Unknown response type in OCSP response");

      /*
      * RFC 6960 Section 4.2.1
      *
      * BasicOCSPResponse ::= SEQUENCE {
      *    tbsResponseData      ResponseData,
      *    signatureAlgorithm   AlgorithmIdentifier,
      *    signature            BIT STRING,
      *    certs            [0] EXPLICIT SEQUENCE OF Certificate OPTIONAL }
      */
      BER_Decoder basic_response_decoder(response_bytes.get_next_octet_string(), BER_Decoder::Limits::DER());
      BER_Decoder basicresponse = basic_response_decoder.start_sequence();

      basicresponse.start_sequence()
         .raw_bytes(m_tbs_bits)
         .end_cons()
         .decode(m_sig_algo)
         .decode(m_signature, ASN1_Type::BitString);
      decode_optional_list(basicresponse, ASN1_Type(0), m_certs);

      basicresponse.verify_end();
      basic_response_decoder.verify_end();

      /*
      * RFC 6960 Section 4.2.1
      *
      * ResponseData ::= SEQUENCE {
      *    version              [0] EXPLICIT Version DEFAULT v1,
      *    responderID              ResponderID,
      *    producedAt               GeneralizedTime,
      *    responses                SEQUENCE OF SingleResponse,
      *    responseExtensions   [1] EXPLICIT Extensions OPTIONAL }
      *
      * ResponderID ::= CHOICE {
      *    byName   [1] Name,
      *    byKey    [2] KeyHash }
      */
      size_t responsedata_version = 0;
      Extensions extensions;

      BER_Decoder tbs_decoder(m_tbs_bits, BER_Decoder::Limits::DER());
      tbs_decoder
         .decode_optional(responsedata_version, ASN1_Type(0), ASN1_Class::ContextSpecific | ASN1_Class::Constructed)

         .decode_optional(m_signer_name, ASN1_Type(1), ASN1_Class::ContextSpecific | ASN1_Class::Constructed)

         .decode_optional_string(
            m_key_hash, ASN1_Type::OctetString, 2, ASN1_Class::ContextSpecific | ASN1_Class::Constructed)

         .decode(m_produced_at)

         .decode_list(m_responses);

      if(tbs_decoder.more_items()) {
         const BER_Object next = tbs_decoder.get_next_object();
         if(next.is_a(1, ASN1_Class::ContextSpecific | ASN1_Class::Constructed)) {
            BER_Decoder ext_decoder(next, BER_Decoder::Limits::DER());
            extensions.decode_from(ext_decoder, Extension_Context::OCSP_Response);
            ext_decoder.verify_end();
         } else {
            throw Decoding_Error("Unexpected tag in OCSP ResponseData");
         }
      }
      tbs_decoder.verify_end();

      const bool has_signer = !m_signer_name.empty();
      const bool has_key_hash = !m_key_hash.empty();

      if(has_signer && has_key_hash) {
         throw Decoding_Error("OCSP response includes both byName and byKey in responderID field");
      }
      if(!has_signer && !has_key_hash) {
         throw Decoding_Error("OCSP response contains neither byName nor byKey in responderID field");
      }
      if(has_key_hash && m_key_hash.size() != 20) {
         // KeyHash ::= OCTET STRING -- SHA-1 hash of responder's public key
         throw Decoding_Error("OCSP response contains a byKey with invalid length");
      }

      response_bytes.verify_end();
      response_bytes_ctx.verify_end();

      // We don't currently recognize any extensions here so if any are critical we should reject
      m_has_unknown_critical_ext = !extensions.critical_extensions().empty();
   }

   response_outer.verify_end();
   outer_decoder.verify_end();

   if(m_has_unknown_critical_ext == false) {
      // Check all of the SingleResponse extensions
      for(const auto& sr : m_responses) {
         if(sr.has_unknown_critical_extension()) {
            m_has_unknown_critical_ext = true;
            break;
         }
      }
   }
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
   const Path_Validation_Restrictions restrictions;

   return this->verify_signature(issuer, restrictions);
}

Certificate_Status_Code Response::verify_signature(const X509_Certificate& issuer,
                                                   const Path_Validation_Restrictions& restrictions) const {
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

      const bool valid_signature = verifier.verify_message(ASN1::put_in_sequence(m_tbs_bits), m_signature);

      if(valid_signature == false) {
         return Certificate_Status_Code::OCSP_SIGNATURE_ERROR;
      }

      if(m_has_unknown_critical_ext) {
         return Certificate_Status_Code::UNKNOWN_CRITICAL_EXTENSION;
      }

      const auto& trusted_hashes = restrictions.trusted_hashes();
      if(!trusted_hashes.empty() && !trusted_hashes.contains(verifier.hash_function())) {
         return Certificate_Status_Code::UNTRUSTED_HASH;
      }

      if(pub_key->estimated_strength() < restrictions.minimum_key_strength()) {
         return Certificate_Status_Code::SIGNATURE_METHOD_TOO_WEAK;
      }

      return Certificate_Status_Code::OCSP_SIGNATURE_OK;
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
   for(const auto& cert : m_certs) {
      if(this->is_issued_by(cert)) {
         return cert;
      }
   }

   // Last resort: check the additionally provides trusted OCSP responders
   if(trusted_ocsp_responders != nullptr) {
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
         const X509_Time x509_ref_time(ref_time);

         /*
         * We check certificate status prior to checking expiration, since otherwise it's
         * possible to take an OCSP response indicating revocation, wait for it to expire,
         * and then staple it. If such a response was reported as "expired" rather than
         * "revoked" it's easy to dismiss as a clock issue or other misconfiguration.
         */

         if(response.cert_status() == 1) {
            return Certificate_Status_Code::CERT_IS_REVOKED;
         }

         try {
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
         } catch(Exception&) {
            // This can occur if eg the OCSP time is not representable by the system clock
            return Certificate_Status_Code::OCSP_RESPONSE_INVALID;
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

   if(auto uri = URI::parse(ocsp_responder)) {
      return online_check(issuer, subject_serial, *uri, timeout);
   } else {
      throw Invalid_Argument("Unparsable URI for OCSP responder");
   }
}

Response online_check(const X509_Certificate& issuer,
                      const BigInt& subject_serial,
                      const URI& ocsp_responder,
                      std::chrono::milliseconds timeout) {
   const OCSP::Request req(issuer, subject_serial);

   auto http = HTTP::POST_sync(ocsp_responder,
                               "application/ocsp-request",
                               req.BER_encode(),
                               HTTP::RequestLimits().set_timeout(timeout).set_max_body_size(64 * 1024));

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

   const auto responders = URI::filter_scheme("http", subject.ocsp_responder_uris());

   if(responders.empty()) {
      throw Invalid_Argument("No HTTP OCSP responder URLs available for this certificate");
   }

   const auto subject_serial = BigInt::from_bytes(subject.serial_number());

   // Try the first N - 1 responder addresses in sequence, ignoring errors
   for(size_t i = 0; i + 1 < responders.size(); ++i) {
      try {
         return online_check(issuer, subject_serial, responders[i], timeout);
      } catch(...) {}
   }

   // Now try the final responder and let any errors propagate
   return online_check(issuer, subject_serial, responders.back(), timeout);
}

#endif

}  // namespace Botan::OCSP
