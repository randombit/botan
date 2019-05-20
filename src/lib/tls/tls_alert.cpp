/*
* Alert Message
* (C) 2004-2006,2011 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/tls_alert.h>
#include <botan/tls_exceptn.h>

namespace Botan {

namespace TLS {

Alert::Alert(const secure_vector<uint8_t>& buf)
   {
   if(buf.size() != 2)
      throw Decoding_Error("Bad size (" + std::to_string(buf.size()) +
                           ") for TLS alert message");

   if(buf[0] == 1)      m_fatal = false;
   else if(buf[0] == 2) m_fatal = true;
   else
      throw TLS_Exception(Alert::ILLEGAL_PARAMETER, "Bad code for TLS alert level");

   const uint8_t dc = buf[1];

   m_type_code = static_cast<Type>(dc);
   }

std::vector<uint8_t> Alert::serialize() const
   {
   return std::vector<uint8_t>({
      static_cast<uint8_t>(is_fatal() ? 2 : 1),
      static_cast<uint8_t>(type())
      });
   }

std::string Alert::type_string() const
   {
   switch(type())
      {
      case CLOSE_NOTIFY:
         return "close_notify";
      case UNEXPECTED_MESSAGE:
         return "unexpected_message";
      case BAD_RECORD_MAC:
         return "bad_record_mac";
      case DECRYPTION_FAILED:
         return "decryption_failed";
      case RECORD_OVERFLOW:
         return "record_overflow";
      case DECOMPRESSION_FAILURE:
         return "decompression_failure";
      case HANDSHAKE_FAILURE:
         return "handshake_failure";
      case NO_CERTIFICATE:
         return "no_certificate";
      case BAD_CERTIFICATE:
         return "bad_certificate";
      case UNSUPPORTED_CERTIFICATE:
         return "unsupported_certificate";
      case CERTIFICATE_REVOKED:
         return "certificate_revoked";
      case CERTIFICATE_EXPIRED:
         return "certificate_expired";
      case CERTIFICATE_UNKNOWN:
         return "certificate_unknown";
      case ILLEGAL_PARAMETER:
         return "illegal_parameter";
      case UNKNOWN_CA:
         return "unknown_ca";
      case ACCESS_DENIED:
         return "access_denied";
      case DECODE_ERROR:
         return "decode_error";
      case DECRYPT_ERROR:
         return "decrypt_error";
      case EXPORT_RESTRICTION:
         return "export_restriction";
      case PROTOCOL_VERSION:
         return "protocol_version";
      case INSUFFICIENT_SECURITY:
         return "insufficient_security";
      case INTERNAL_ERROR:
         return "internal_error";
      case INAPPROPRIATE_FALLBACK:
         return "inappropriate_fallback";
      case USER_CANCELED:
         return "user_canceled";
      case NO_RENEGOTIATION:
         return "no_renegotiation";

      case UNSUPPORTED_EXTENSION:
         return "unsupported_extension";
      case CERTIFICATE_UNOBTAINABLE:
         return "certificate_unobtainable";
      case UNRECOGNIZED_NAME:
         return "unrecognized_name";
      case BAD_CERTIFICATE_STATUS_RESPONSE:
         return "bad_certificate_status_response";
      case BAD_CERTIFICATE_HASH_VALUE:
         return "bad_certificate_hash_value";
      case UNKNOWN_PSK_IDENTITY:
         return "unknown_psk_identity";
      case CERTIFICATE_REQUIRED:
         return "certificate_required";
      case NO_APPLICATION_PROTOCOL:
         return "no_application_protocol";

      case NULL_ALERT:
         return "none";
      }

   /*
   * This is effectively the default case for the switch above, but we
   * leave it out so that when an alert type is added to the enum the
   * compiler can warn us that it is not included in the switch
   * statement.
   */
   return "unrecognized_alert_" + std::to_string(type());
   }

}

}
