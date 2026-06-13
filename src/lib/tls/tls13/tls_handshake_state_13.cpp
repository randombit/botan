/*
* TLS handshake state (machine) implementation for TLS 1.3
* (C) 2022 Jack Lloyd
*     2022 Hannes Rantzsch, René Meusel - neXenio GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/tls_handshake_state_13.h>

#include <botan/assert.h>

namespace Botan::TLS::Internal {

Client_Hello_13& Handshake_State_13_Base::store(Client_Hello_13 client_hello, const bool /*from_peer*/) {
   if(m_client_hello) {
      // Make sure that the updated Client Hello is compatible to the initial one.
      BOTAN_STATE_CHECK(has_hello_retry_request());
      m_client_hello->validate_updates(client_hello);
   }

   m_client_hello = std::move(client_hello);
   return m_client_hello.value();
}

Client_Hello_12_Shim& Handshake_State_13_Base::store(Client_Hello_12_Shim client_hello, const bool /*from_peer*/) {
   BOTAN_STATE_CHECK(!m_client_hello_12.has_value());
   m_client_hello_12 = std::move(client_hello);
   return m_client_hello_12.value();
}

Server_Hello_13& Handshake_State_13_Base::store(Server_Hello_13 server_hello, const bool /*from_peer*/) {
   BOTAN_STATE_CHECK(!m_server_hello.has_value());
   m_server_hello = std::move(server_hello);
   return m_server_hello.value();
}

Server_Hello_12_Shim& Handshake_State_13_Base::store(Server_Hello_12_Shim server_hello, const bool /*from_peer*/) {
   BOTAN_STATE_CHECK(!m_server_hello_12.has_value());
   m_server_hello_12 = std::move(server_hello);
   return m_server_hello_12.value();
}

Hello_Retry_Request& Handshake_State_13_Base::store(Hello_Retry_Request hello_retry_request, const bool /*from_peer*/) {
   // RFC 8446 4.1.4
   //    If a client receives a second HelloRetryRequest in the same connection
   //    [...], it MUST abort the handshake with an "unexpected_message" alert.
   BOTAN_STATE_CHECK(!m_hello_retry_request.has_value());
   m_hello_retry_request = std::move(hello_retry_request);
   return m_hello_retry_request.value();
}

Encrypted_Extensions& Handshake_State_13_Base::store(Encrypted_Extensions encrypted_extensions,
                                                     const bool /*from_peer*/) {
   BOTAN_STATE_CHECK(!m_encrypted_extensions.has_value());
   m_encrypted_extensions = std::move(encrypted_extensions);
   return m_encrypted_extensions.value();
}

Certificate_Request_13& Handshake_State_13_Base::store(Certificate_Request_13 certificate_request,
                                                       const bool /*from_peer*/) {
   BOTAN_STATE_CHECK(!m_certificate_request.has_value());
   m_certificate_request = std::move(certificate_request);
   return m_certificate_request.value();
}

Certificate_13& Handshake_State_13_Base::store(Certificate_13 certificate, const bool from_peer) {
   auto& target = ((m_side == Connection_Side::Client) == from_peer) ? m_server_certificate : m_client_certificate;
   BOTAN_STATE_CHECK(!target.has_value());
   target = std::move(certificate);
   return target.value();
}

Certificate_Verify_13& Handshake_State_13_Base::store(Certificate_Verify_13 certificate_verify, const bool from_peer) {
   auto& target =
      ((m_side == Connection_Side::Client) == from_peer) ? m_server_certificate_verify : m_client_certificate_verify;
   BOTAN_STATE_CHECK(!target.has_value());
   target = std::move(certificate_verify);
   return target.value();
}

Finished_13& Handshake_State_13_Base::store(Finished_13 finished, const bool from_peer) {
   auto& target = ((m_side == Connection_Side::Client) == from_peer) ? m_server_finished : m_client_finished;
   BOTAN_STATE_CHECK(!target.has_value());
   target = std::move(finished);
   return target.value();
}

}  // namespace Botan::TLS::Internal
