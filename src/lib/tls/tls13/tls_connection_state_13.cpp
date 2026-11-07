/*
* (C) 2026 Jack Lloyd
*     2026 René Meusel - Rohde & Schwarz Networks and Cybersecurity GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/tls_connection_state_13.h>

#include <botan/tls_extensions.h>
#include <botan/internal/tls_handshake_state_13.h>

namespace Botan::TLS {

namespace {

std::string extract_alpn(const Internal::Handshake_State_13_Base& state) {
   const auto& eee = state.encrypted_extensions().extensions();
   if(const auto* alpn = eee.get<Application_Layer_Protocol_Notification>()) {
      return alpn->single_protocol();
   }
   return {};
}

uint16_t extract_srtp_profile(const Internal::Handshake_State_13_Base& state) {
   const auto& eee = state.encrypted_extensions().extensions();
   if(const auto* srtp = eee.get<SRTP_Protection_Profiles>()) {
      const auto& profiles = srtp->profiles();
      // The handshake logic guarantees that a negotiated "use_srtp" extension
      // carries exactly one protection profile (RFC 5764 4.1.2): the server
      // selects a single profile and the client validates the selection.
      BOTAN_ASSERT_NOMSG(profiles.size() == 1);
      return profiles.front();
   }
   return 0;
}

}  // namespace

Active_Connection_State_13::~Active_Connection_State_13() = default;
Active_Connection_State_13::Active_Connection_State_13(Active_Connection_State_13&&) noexcept = default;
Active_Connection_State_13& Active_Connection_State_13::operator=(Active_Connection_State_13&&) noexcept = default;

Active_Connection_State_13::Active_Connection_State_13(const Internal::Handshake_State_13_Base& state,
                                                       std::vector<X509_Certificate> peer_certs,
                                                       std::shared_ptr<const Public_Key> peer_raw_public_key,
                                                       std::optional<std::string> psk_identity,
                                                       std::string sni_hostname,
                                                       bool peer_supports_psk_dhe_ke) :
      m_version(state.server_hello().selected_version()),
      m_ciphersuite_code(state.server_hello().ciphersuite()),
      m_application_protocol(extract_alpn(state)),
      m_srtp_profile(extract_srtp_profile(state)),
      m_peer_certs(std::move(peer_certs)),
      m_client_random(state.client_hello().random()),
      m_psk_identity(std::move(psk_identity)),
      m_peer_raw_public_key(std::move(peer_raw_public_key)),
      m_sni_hostname(std::move(sni_hostname)),
      m_peer_supports_psk_dhe_ke(peer_supports_psk_dhe_ke) {}

}  // namespace Botan::TLS
