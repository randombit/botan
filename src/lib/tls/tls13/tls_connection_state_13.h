/*
* (C) 2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_TLS_CONNECTION_STATE_13_H_
#define BOTAN_TLS_CONNECTION_STATE_13_H_

#include <botan/tls_version.h>
#include <botan/x509cert.h>

#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace Botan {

class Public_Key;

}  // namespace Botan

namespace Botan::TLS {

namespace Internal {
class Handshake_State_13_Base;
}

/**
* Captures the state of a completed TLS 1.3 handshake that is needed
* for the lifetime of an active connection.
*/
class Active_Connection_State_13 final {
   public:
      Active_Connection_State_13(const Internal::Handshake_State_13_Base& state,
                                 std::vector<X509_Certificate> peer_certs,
                                 std::shared_ptr<const Public_Key> peer_raw_public_key,
                                 std::optional<std::string> psk_identity,
                                 std::string sni_hostname,
                                 bool peer_supports_psk_dhe_ke);

      ~Active_Connection_State_13();
      Active_Connection_State_13(Active_Connection_State_13&&) noexcept;
      Active_Connection_State_13& operator=(Active_Connection_State_13&&) noexcept;

      Active_Connection_State_13(const Active_Connection_State_13&) = delete;
      Active_Connection_State_13& operator=(const Active_Connection_State_13&) = delete;

      Protocol_Version version() const { return m_version; }

      uint16_t ciphersuite_code() const { return m_ciphersuite_code; }

      const std::string& application_protocol() const { return m_application_protocol; }

      uint16_t srtp_profile() const { return m_srtp_profile; }

      const std::vector<X509_Certificate>& peer_certs() const { return m_peer_certs; }

      const std::vector<uint8_t>& client_random() const { return m_client_random; }

      const std::optional<std::string>& psk_identity() const { return m_psk_identity; }

      const std::shared_ptr<const Public_Key>& peer_raw_public_key() const { return m_peer_raw_public_key; }

      const std::string& sni_hostname() const { return m_sni_hostname; }

      bool peer_supports_psk_dhe_ke() const { return m_peer_supports_psk_dhe_ke; }

   private:
      Protocol_Version m_version;
      uint16_t m_ciphersuite_code = 0;
      std::string m_application_protocol;
      uint16_t m_srtp_profile = 0;
      std::vector<X509_Certificate> m_peer_certs;
      std::vector<uint8_t> m_client_random;
      std::optional<std::string> m_psk_identity;
      std::shared_ptr<const Public_Key> m_peer_raw_public_key;
      std::string m_sni_hostname;
      bool m_peer_supports_psk_dhe_ke = false;
};

}  // namespace Botan::TLS

#endif
