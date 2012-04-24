/*
* Alert Message
* (C) 2004-2006,2011 Jack Lloyd
*
* Released under the terms of the Botan license
*/

#ifndef BOTAN_TLS_ALERT_H__
#define BOTAN_TLS_ALERT_H__

#include <botan/secmem.h>
#include <string>

namespace Botan {

namespace TLS {

/**
* SSL/TLS Alert Message
*/
class BOTAN_DLL Alert
   {
   public:
      enum Type {
         CLOSE_NOTIFY                    = 0,
         UNEXPECTED_MESSAGE              = 10,
         BAD_RECORD_MAC                  = 20,
         DECRYPTION_FAILED               = 21,
         RECORD_OVERFLOW                 = 22,
         DECOMPRESSION_FAILURE           = 30,
         HANDSHAKE_FAILURE               = 40,
         NO_CERTIFICATE                  = 41, // SSLv3 only
         BAD_CERTIFICATE                 = 42,
         UNSUPPORTED_CERTIFICATE         = 43,
         CERTIFICATE_REVOKED             = 44,
         CERTIFICATE_EXPIRED             = 45,
         CERTIFICATE_UNKNOWN             = 46,
         ILLEGAL_PARAMETER               = 47,
         UNKNOWN_CA                      = 48,
         ACCESS_DENIED                   = 49,
         DECODE_ERROR                    = 50,
         DECRYPT_ERROR                   = 51,
         EXPORT_RESTRICTION              = 60,
         PROTOCOL_VERSION                = 70,
         INSUFFICIENT_SECURITY           = 71,
         INTERNAL_ERROR                  = 80,
         USER_CANCELED                   = 90,
         NO_RENEGOTIATION                = 100,
         UNSUPPORTED_EXTENSION           = 110,
         CERTIFICATE_UNOBTAINABLE        = 111,
         UNRECOGNIZED_NAME               = 112,
         BAD_CERTIFICATE_STATUS_RESPONSE = 113,
         BAD_CERTIFICATE_HASH_VALUE      = 114,
         UNKNOWN_PSK_IDENTITY            = 115,

         NULL_ALERT                      = 255,

         HEARTBEAT_PAYLOAD               = 256
      };

      /**
      * @return true iff this alert is non-empty
      */
      bool is_valid() const { return (type_code != NULL_ALERT); }

      /**
      * @return if this alert is a fatal one or not
      */
      bool is_fatal() const { return fatal; }

      /**
      * @return type of alert
      */
      Type type() const { return type_code; }

      /**
      * @return type of alert
      */
      std::string type_string() const;

      /**
      * Deserialize an Alert message
      * @param buf the serialized alert
      */
      Alert(const MemoryRegion<byte>& buf);

      Alert(Type alert_type, bool is_fatal = false) :
         fatal(is_fatal), type_code(alert_type) {}

      Alert() : fatal(false), type_code(NULL_ALERT) {}
   private:
      bool fatal;
      Type type_code;
   };

}

}

#endif
