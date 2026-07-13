/*
* (C) 2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_TLS_CONNECTION_STATE_12_H_
#define BOTAN_TLS_CONNECTION_STATE_12_H_

#include <botan/secmem.h>
#include <botan/tls_session_id.h>
#include <botan/tls_version.h>
#include <botan/x509cert.h>

#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace Botan::TLS {

class Handshake_IO;
class Datagram_Handshake_IO;
class Handshake_State;

/**
* Captures the state of a completed TLS 1.2 handshake that is needed
* for the lifetime of an active connection.
 */
class Active_Connection_State_12 final {
   public:
      ~Active_Connection_State_12();

      Active_Connection_State_12(Active_Connection_State_12&&) noexcept;
      Active_Connection_State_12& operator=(Active_Connection_State_12&&) noexcept;

      Active_Connection_State_12(const Active_Connection_State_12&) = delete;
      Active_Connection_State_12& operator=(const Active_Connection_State_12&) = delete;

      Active_Connection_State_12(const Handshake_State& state, std::string application_protocol);

      // DTLS variant: retains handshake IO for retransmission validation and
      // reactive replay of the terminal flight when appropriate.
      Active_Connection_State_12(const Handshake_State& state,
                                 std::string application_protocol,
                                 std::unique_ptr<Handshake_IO> io);

      Protocol_Version version() const { return m_version; }

      uint16_t ciphersuite_code() const { return m_ciphersuite_code; }

      const std::string& application_protocol() const { return m_application_protocol; }

      const std::vector<X509_Certificate>& peer_certs() const { return m_peer_certs; }

      const std::vector<uint8_t>& client_random() const { return m_client_random; }

      const std::optional<std::string>& psk_identity() const { return m_psk_identity; }

      const std::vector<uint8_t>& server_random() const { return m_server_random; }

      const Session_ID& session_id() const { return m_session_id; }

      const secure_vector<uint8_t>& master_secret() const { return m_master_secret; }

      const std::string& prf_algo() const { return m_prf_algo; }

      bool client_supports_secure_renegotiation() const { return m_client_supports_secure_renegotiation; }

      bool server_supports_secure_renegotiation() const { return m_server_supports_secure_renegotiation; }

      const std::vector<uint8_t>& client_finished_verify_data() const { return m_client_finished_verify_data; }

      const std::vector<uint8_t>& server_finished_verify_data() const { return m_server_finished_verify_data; }

      bool supports_extended_master_secret() const { return m_supports_extended_master_secret; }

      /**
       * For DTLS: the handshake IO from the completed handshake, needed to
       * validate retransmissions and, for the terminal-flight sender, replay
       * the final flight. Null for stream TLS.
       */
      Datagram_Handshake_IO* dtls_handshake_io() { return m_dtls_handshake_io.get(); }

      const Datagram_Handshake_IO* dtls_handshake_io() const { return m_dtls_handshake_io.get(); }

      // Protected application data proves that the peer processed our final
      // handshake flight, so timeout-driven replay is no longer necessary.
      bool peer_sent_protected_application_data() const { return m_peer_sent_protected_application_data; }

      void mark_peer_as_having_sent_protected_application_data() { m_peer_sent_protected_application_data = true; }

   private:
      Protocol_Version m_version;
      uint16_t m_ciphersuite_code = 0;
      std::string m_application_protocol;
      std::vector<X509_Certificate> m_peer_certs;
      std::vector<uint8_t> m_client_random;
      std::optional<std::string> m_psk_identity;
      std::vector<uint8_t> m_server_random;
      Session_ID m_session_id;
      secure_vector<uint8_t> m_master_secret;
      std::string m_prf_algo;
      bool m_client_supports_secure_renegotiation = false;
      bool m_server_supports_secure_renegotiation = false;
      std::vector<uint8_t> m_client_finished_verify_data;
      std::vector<uint8_t> m_server_finished_verify_data;
      bool m_supports_extended_master_secret = false;
      std::unique_ptr<Datagram_Handshake_IO> m_dtls_handshake_io;
      bool m_peer_sent_protected_application_data = false;
};

}  // namespace Botan::TLS

#endif
