/*
* Alert Message
* (C) 2004-2006,2011 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/tls_alert.h>

#include <botan/tls_exceptn.h>

namespace Botan::TLS {

Alert::Alert(const secure_vector<uint8_t>& buf) {
   if(buf.size() != 2) {
      throw Decoding_Error("Bad size (" + std::to_string(buf.size()) + ") for TLS alert message");
   }

   if(buf[0] == 1) {
      m_fatal = false;
   } else if(buf[0] == 2) {
      m_fatal = true;
   } else {
      throw TLS_Exception(Alert::IllegalParameter, "Bad code for TLS alert level");
   }

   const uint8_t dc = buf[1];

   m_type_code = static_cast<Type>(dc);
}

std::vector<uint8_t> Alert::serialize() const {
   return std::vector<uint8_t>({static_cast<uint8_t>(is_fatal() ? 2 : 1), static_cast<uint8_t>(type())});
}

namespace {

const char* alert_type_to_string(AlertType type) {
   switch(type) {
      case AlertType::CloseNotify:
         return "close_notify";
      case AlertType::UnexpectedMessage:
         return "unexpected_message";
      case AlertType::BadRecordMac:
         return "bad_record_mac";
      case AlertType::DecryptionFailed:
         return "decryption_failed";
      case AlertType::RecordOverflow:
         return "record_overflow";
      case AlertType::DecompressionFailure:
         return "decompression_failure";
      case AlertType::HandshakeFailure:
         return "handshake_failure";
      case AlertType::NoCertificate:
         return "no_certificate";
      case AlertType::BadCertificate:
         return "bad_certificate";
      case AlertType::UnsupportedCertificate:
         return "unsupported_certificate";
      case AlertType::CertificateRevoked:
         return "certificate_revoked";
      case AlertType::CertificateExpired:
         return "certificate_expired";
      case AlertType::CertificateUnknown:
         return "certificate_unknown";
      case AlertType::IllegalParameter:
         return "illegal_parameter";
      case AlertType::UnknownCA:
         return "unknown_ca";
      case AlertType::AccessDenied:
         return "access_denied";
      case AlertType::DecodeError:
         return "decode_error";
      case AlertType::DecryptError:
         return "decrypt_error";
      case AlertType::ExportRestriction:
         return "export_restriction";
      case AlertType::ProtocolVersion:
         return "protocol_version";
      case AlertType::InsufficientSecurity:
         return "insufficient_security";
      case AlertType::InternalError:
         return "internal_error";
      case AlertType::InappropriateFallback:
         return "inappropriate_fallback";
      case AlertType::UserCanceled:
         return "user_canceled";
      case AlertType::NoRenegotiation:
         return "no_renegotiation";
      case AlertType::MissingExtension:
         return "missing_extension";
      case AlertType::UnsupportedExtension:
         return "unsupported_extension";
      case AlertType::CertificateUnobtainable:
         return "certificate_unobtainable";
      case AlertType::UnrecognizedName:
         return "unrecognized_name";
      case AlertType::BadCertificateStatusResponse:
         return "bad_certificate_status_response";
      case AlertType::BadCertificateHashValue:
         return "bad_certificate_hash_value";
      case AlertType::UnknownPSKIdentity:
         return "unknown_psk_identity";
      case AlertType::CertificateRequired:
         return "certificate_required";
      case AlertType::NoApplicationProtocol:
         return "no_application_protocol";

      case AlertType::None:
         return "none";
   }

   return nullptr;
}

}  // namespace

std::string Alert::type_string() const {
   if(const char* known_alert = alert_type_to_string(type())) {
      return std::string(known_alert);
   }

   return "unrecognized_alert_" + std::to_string(static_cast<size_t>(type()));
}

}  // namespace Botan::TLS
