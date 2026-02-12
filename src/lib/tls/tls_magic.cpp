/*
* TLS Magic Values
* (C) 2004-2006,2011,2012,2015,2016 Jack Lloyd
*     2026 René Meusel - Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/tls_magic.h>

#include <botan/tls_exceptn.h>

namespace Botan::TLS {

const char* handshake_type_to_string(Handshake_Type type) {
   switch(type) {
      case Handshake_Type::HelloVerifyRequest:
         return "hello_verify_request";

      case Handshake_Type::HelloRequest:
         return "hello_request";

      case Handshake_Type::ClientHello:
         return "client_hello";

      case Handshake_Type::ServerHello:
         return "server_hello";

      case Handshake_Type::HelloRetryRequest:
         return "hello_retry_request";

      case Handshake_Type::Certificate:
         return "certificate";

      case Handshake_Type::CertificateUrl:
         return "certificate_url";

      case Handshake_Type::CertificateStatus:
         return "certificate_status";

      case Handshake_Type::ServerKeyExchange:
         return "server_key_exchange";

      case Handshake_Type::CertificateRequest:
         return "certificate_request";

      case Handshake_Type::ServerHelloDone:
         return "server_hello_done";

      case Handshake_Type::CertificateVerify:
         return "certificate_verify";

      case Handshake_Type::ClientKeyExchange:
         return "client_key_exchange";

      case Handshake_Type::NewSessionTicket:
         return "new_session_ticket";

      case Handshake_Type::HandshakeCCS:
         return "change_cipher_spec";

      case Handshake_Type::Finished:
         return "finished";

      case Handshake_Type::EndOfEarlyData:
         return "end_of_early_data";

      case Handshake_Type::EncryptedExtensions:
         return "encrypted_extensions";

      case Handshake_Type::KeyUpdate:
         return "key_update";

      case Handshake_Type::None:
         return "invalid";
   }

   throw TLS_Exception(Alert::UnexpectedMessage,
                       "Unknown TLS handshake message type " + std::to_string(static_cast<size_t>(type)));
}

}  // namespace Botan::TLS
