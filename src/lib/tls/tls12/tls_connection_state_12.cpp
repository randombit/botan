/*
* (C) 2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/tls_connection_state_12.h>

#include <botan/tls_messages_12.h>
#include <botan/internal/tls_handshake_io.h>
#include <botan/internal/tls_handshake_state.h>

namespace Botan::TLS {

Active_Connection_State_12::~Active_Connection_State_12() = default;
Active_Connection_State_12::Active_Connection_State_12(Active_Connection_State_12&&) noexcept = default;
Active_Connection_State_12& Active_Connection_State_12::operator=(Active_Connection_State_12&&) noexcept = default;

Active_Connection_State_12::Active_Connection_State_12(const Handshake_State& state, std::string application_protocol) :
      m_version(state.version()),
      m_ciphersuite_code(state.server_hello()->ciphersuite()),
      m_application_protocol(std::move(application_protocol)),
      m_peer_certs(state.peer_cert_chain()),
      m_client_random(state.client_hello()->random()),
      m_psk_identity(state.psk_identity()),
      m_server_random(state.server_hello()->random()),
      m_session_id(state.server_hello()->session_id()),
      m_master_secret(state.session_keys().master_secret()),
      m_prf_algo(state.ciphersuite().prf_algo()),
      m_client_supports_secure_renegotiation(state.client_hello()->secure_renegotiation()),
      m_server_supports_secure_renegotiation(state.server_hello()->secure_renegotiation()),
      m_client_finished_verify_data(state.client_finished()->verify_data()),
      m_server_finished_verify_data(state.server_finished()->verify_data()),
      m_supports_extended_master_secret(state.server_hello()->supports_extended_master_secret()),
      m_encrypt_then_mac_used(state.server_hello()->supports_encrypt_then_mac()) {}

Active_Connection_State_12::Active_Connection_State_12(const Handshake_State& state,
                                                       std::string application_protocol,
                                                       std::unique_ptr<Handshake_IO> io) :
      Active_Connection_State_12(state, std::move(application_protocol)) {
   BOTAN_ASSERT_NOMSG(m_version.is_datagram_protocol());
   auto* dtls_io = dynamic_cast<Datagram_Handshake_IO*>(io.get());
   BOTAN_ASSERT_NOMSG(dtls_io != nullptr);
   m_dtls_handshake_io.reset(dtls_io);
   io.release();  // NOLINT(*-unused-return-value)
}

}  // namespace Botan::TLS
