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
#include <botan/internal/fmt.h>

#if defined(BOTAN_HAS_HTTP_UTIL)
   #include <botan/internal/http_util.h>
#endif

namespace Botan::OCSP {

namespace {

/*
* RFC 6960 requires producedAt, thisUpdate, nextUpdate, and revocationTime
* to be encoded as GeneralizedTime. ASN1_Time also accepts UTCTime since that
* is required for X.509 certificates and CRLs (RFC 5280), so enforce the
* stricter OCSP requirement at the call site.
*/
void check_generalized_time(const ASN1_Time& time, const char* field) {
   if(time.tagging() != ASN1_Type::GeneralizedTime) {
      throw Decoding_Error(fmt("OCSP response {} was not encoded as GeneralizedTime", field));
   }
}

}  // namespace

CertID::CertID(const X509_Certificate& issuer, const BigInt& subject_serial) :
      CertID(issuer, X509_Serial_Number(subject_serial)) {}

CertID::CertID(const X509_Certificate& issuer, const X509_Serial_Number& subject_serial) :
      m_subject_serial(subject_serial) {
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
      if(subject.serial() != m_subject_serial) {
         return false;
      }

      const auto hash_algo = m_hash_id.oid().registered_name();

      /*
      RFC 6960 4.1.1
         issuerNameHash is the hash of the issuer's distinguished name (DN).
         The hash shall be calculated over the DER encoding of the issuer's name
         field in the certificate being checked.

         issuerKeyHash is the hash of the issuer's public key. The hash shall be
         calculated over the value (excluding tag and length) of the subject public key
         field in the issuer's certificate.
      */

      if(hash_algo == "SHA-1") {
         if(!std::ranges::equal(m_issuer_dn_hash, subject.raw_issuer_dn_sha1())) {
            return false;
         }
         if(!std::ranges::equal(m_issuer_key_hash, issuer.subject_public_key_bitstring_sha1())) {
            return false;
         }
      } else if(hash_algo == "SHA-256") {
         if(!std::ranges::equal(m_issuer_dn_hash, subject.raw_issuer_dn_sha256())) {
            return false;
         }
         if(!std::ranges::equal(m_issuer_key_hash, issuer.subject_public_key_bitstring_sha256())) {
            return false;
         }
      } else {
         // Exotic hashes are unlikely to occur in OCSP
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

   if(!m_hash_id.parameters_are_null_or_empty()) {
      throw Decoding_Error("OCSP CertID hashAlgorithm has unexpected parameters");
   }
}

//static
SingleResponse SingleResponse::good(CertID certid, X509_Time this_update, X509_Time next_update) {
   return SingleResponse(
      std::move(certid), 0, std::nullopt, std::nullopt, std::move(this_update), std::move(next_update));
}

//static
SingleResponse SingleResponse::unknown(CertID certid, X509_Time this_update, X509_Time next_update) {
   return SingleResponse(
      std::move(certid), 2, std::nullopt, std::nullopt, std::move(this_update), std::move(next_update));
}

//static
SingleResponse SingleResponse::revoked(CertID certid,
                                       X509_Time revocation_time,
                                       std::optional<CRL_Code> reason,
                                       X509_Time this_update,
                                       X509_Time next_update) {
   return SingleResponse(
      std::move(certid), 1, std::move(revocation_time), reason, std::move(this_update), std::move(next_update));
}

SingleResponse::SingleResponse(CertID certid,
                               size_t cert_status,
                               std::optional<X509_Time> revocation_time,
                               std::optional<CRL_Code> revocation_reason,
                               X509_Time this_update,
                               X509_Time next_update) :
      m_certid(std::move(certid)),
      m_cert_status(cert_status),
      m_thisupdate(std::move(this_update)),
      m_nextupdate(std::move(next_update)),
      m_revocation_time(std::move(revocation_time)),
      m_revocation_reason(revocation_reason) {
   const auto require_generalized_time = [](const X509_Time& t, const char* field) {
      if(t.tagging() != ASN1_Type::GeneralizedTime) {
         throw Invalid_Argument(fmt("OCSP SingleResponse {} must be a GeneralizedTime", field));
      }
   };

   require_generalized_time(m_thisupdate, "thisUpdate");
   if(m_nextupdate.time_is_set()) {
      require_generalized_time(m_nextupdate, "nextUpdate");
   }
   if(m_cert_status == 1) {
      if(!m_revocation_time.has_value()) {
         throw Invalid_Argument("Revoked OCSP SingleResponse lacks a revocation time");
      }
      require_generalized_time(*m_revocation_time, "revocationTime");
   }
}

void SingleResponse::encode_into(DER_Encoder& to) const {
   // The SingleResponse / CertStatus / RevokedInfo ASN.1 is quoted in
   // decode_from below
   to.start_sequence();
   to.encode(m_certid);
   if(m_cert_status == 1) {
      // NOLINTNEXTLINE(clang-analyzer-optin.core.EnumCastOutOfRange)
      to.start_cons(ASN1_Type(1), ASN1_Class::ContextSpecific).encode(m_revocation_time.value());
      if(m_revocation_reason.has_value() && *m_revocation_reason != CRL_Code::Unspecified) {
         to.start_explicit(0)
            .encode(static_cast<size_t>(*m_revocation_reason), ASN1_Type::Enumerated, ASN1_Class::Universal)
            .end_explicit();
      }
      to.end_cons();
   } else {
      // good [0] / unknown [2], both IMPLICIT NULL
      const std::span<const uint8_t> empty;
      // NOLINTNEXTLINE(clang-analyzer-optin.core.EnumCastOutOfRange)
      to.add_object(ASN1_Type(m_cert_status), ASN1_Class::ContextSpecific, empty);
   }
   to.encode(m_thisupdate);
   if(m_nextupdate.time_is_set()) {
      to.start_explicit(0).encode(m_nextupdate).end_explicit();
   }
   to.end_cons();
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

   check_generalized_time(m_thisupdate, "thisUpdate");
   if(m_nextupdate.time_is_set()) {
      check_generalized_time(m_nextupdate, "nextUpdate");
   }

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

   m_cert_status = static_cast<uint32_t>(cert_status.type());
   if(m_cert_status > 2) {
      throw Decoding_Error("Unknown OCSP CertStatus tag");
   }

   m_revocation_time.reset();
   m_revocation_reason.reset();

   if(m_cert_status == 1) {
      BER_Decoder revoked_info(cert_status, BER_Decoder::Limits::DER());
      X509_Time revocation_time;
      revoked_info.decode(revocation_time);
      check_generalized_time(revocation_time, "revocationTime");
      m_revocation_time = std::move(revocation_time);

      if(revoked_info.peek_next_object().is_a(0, ASN1_Class::ContextSpecific | ASN1_Class::Constructed)) {
         size_t reason = 0;
         revoked_info.start_context_specific(0).decode(reason, ASN1_Type::Enumerated, ASN1_Class::Universal).end_cons();
         if(reason == 7 || reason > 10) {
            throw Decoding_Error(fmt("CRLReason has unknown enumeration value {}", reason));
         }
         m_revocation_reason = static_cast<CRL_Code>(reason);
      }
      revoked_info.verify_end();
   } else if(cert_status.length() != 0) {
      // good [0] / unknown [2] are both IMPLICIT NULL
      throw Decoding_Error("OCSP CertStatus has unexpected content");
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
      m_issuer(issuer_cert), m_certid(m_issuer, subject_cert.serial()) {
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

      response_bytes.decode_and_check(OID::from_string("PKIX.OCSP.BasicResponse"),
                                      "Unknown response type in OCSP response");

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
         .decode_octet_aligned_bitstring(m_signature);
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

      check_generalized_time(m_produced_at, "producedAt");

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
      verifier.update(ASN1::der_sequence_header(m_tbs_bits.size()));
      verifier.update(m_tbs_bits);
      const bool valid_signature = verifier.check_signature(m_signature);

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

   if(auto uri = URI::from_string(ocsp_responder)) {
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

   const auto subject_serial = subject.serial().to_bigint();

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
