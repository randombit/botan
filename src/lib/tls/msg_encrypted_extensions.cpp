/*
* TLS Hello Request and Client Hello Messages
* (C) 2022 Jack Lloyd
*     2022 René Meusel, Hannes Rantzsch - neXenio GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/build.h>
#if defined(BOTAN_HAS_TLS_13)

#include <botan/tls_messages.h>
#include <botan/tls_exceptn.h>
#include <botan/internal/tls_reader.h>

namespace Botan::TLS {

Encrypted_Extensions::Encrypted_Extensions(const std::vector<uint8_t>& buf)
   {
   TLS_Data_Reader reader("encrypted extensions reader", buf);

   // Encrypted Extensions contains a list of extensions. This list may legally
   // be empty. However, in that case we should at least see a two-byte length
   // field that reads 0x00 0x00.
   if(buf.size() < 2)
      {
      throw TLS_Exception(Alert::DECODE_ERROR,
                          "Server sent an empty Encrypted Extensions message");
      }

   m_extensions.deserialize(reader, Connection_Side::SERVER, type());

   // RFC 8446 4.2
   //    If an implementation receives an extension which it recognizes and
   //    which is not specified for the message in which it appears, it MUST
   //    abort the handshake with an "illegal_parameter" alert.
   //
   // Note that we cannot encounter any extensions that we don't recognize here,
   // since only extensions we previously offered are allowed in EE.
   const auto allowed_exts = std::set<Handshake_Extension_Type>
      {
      // Allowed extensions listed in RFC 8446 and implemented in Botan
      Handshake_Extension_Type::TLSEXT_SERVER_NAME_INDICATION,
      // MAX_FRAGMENT_LENGTH
      Handshake_Extension_Type::TLSEXT_SUPPORTED_GROUPS,
      Handshake_Extension_Type::TLSEXT_USE_SRTP,
      // HEARTBEAT
      Handshake_Extension_Type::TLSEXT_ALPN,
      // CLIENT_CERTIFICATE_TYPE
      // SERVER_CERTIFICATE_TYPE
      // EARLY_DATA

      // Allowed extensions not listed in RFC 8446 but acceptable as Botan implements them
      Handshake_Extension_Type::TLSEXT_RECORD_SIZE_LIMIT,
      };
   if(m_extensions.contains_implemented_extensions_other_than(allowed_exts))
      {
      throw TLS_Exception(Alert::ILLEGAL_PARAMETER,
                          "Encrypted Extensions contained an extension that is not allowed");
      }

   }

}

#endif
