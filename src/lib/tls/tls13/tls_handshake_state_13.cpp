/*
* TLS handshake state (machine) implementation for TLS 1.3
* (C) 2022 Jack Lloyd
*     2022 Hannes Rantzsch, René Meusel - neXenio GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/tls_handshake_state_13.h>

namespace Botan::TLS::Internal {

Client_Hello_13& Handshake_State_13_Base::store(Client_Hello_13 client_hello, const bool)
{
    m_client_hello = std::move(client_hello);
    return m_client_hello.value();
}

Server_Hello_13& Handshake_State_13_Base::store(Server_Hello_13 server_hello, const bool)
{
    m_server_hello = std::move(server_hello);
    return m_server_hello.value();
}

Server_Hello_12& Handshake_State_13_Base::store(Server_Hello_12 server_hello, const bool)
{
    m_server_hello_12 = std::move(server_hello);
    return m_server_hello_12.value();
}

Hello_Retry_Request& Handshake_State_13_Base::store(Hello_Retry_Request hello_retry_request, const bool)
{
    m_hello_retry_request = std::move(hello_retry_request);
    return m_hello_retry_request.value();
}

Encrypted_Extensions& Handshake_State_13_Base::store(Encrypted_Extensions encrypted_extensions, const bool)
{
    m_encrypted_extensions = std::move(encrypted_extensions);
    return m_encrypted_extensions.value();
}

Certificate_13& Handshake_State_13_Base::store(Certificate_13 certificate, const bool)
{
    m_server_certs = std::move(certificate);
    return m_server_certs.value();
}

Certificate_Verify_13& Handshake_State_13_Base::store(Certificate_Verify_13 certificate_verify, const bool)
{
    m_server_verify = std::move(certificate_verify);
    return m_server_verify.value();
}

Finished_13& Handshake_State_13_Base::store(Finished_13 finished, const bool from_peer)
{
   auto& target = ((m_side == CLIENT) == from_peer)
          ? m_server_finished
          : m_client_finished;
   target = std::move(finished);
   return target.value();
}

}
