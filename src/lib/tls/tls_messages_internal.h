/*
* TLS Client/Server Hello Internal Data Containers
* (C) 2004-2026 Jack Lloyd
*     2021 Elektrobit Automotive GmbH
*     2022 René Meusel, Hannes Rantzsch - neXenio GmbH
*     2026 René Meusel - Rohde & Schwarz Cybersecurity GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_TLS_MESSAGES_INTERNAL_H_
#define BOTAN_TLS_MESSAGES_INTERNAL_H_

#include <botan/tls_extensions.h>
#include <botan/tls_session.h>
#include <botan/tls_version.h>
#include <vector>

namespace Botan {
class RandomNumberGenerator;

namespace TLS {
class Callbacks;
class Policy;
}  // namespace TLS

}  // namespace Botan

namespace Botan::TLS {

/**
 * Generate a server hello random value for the given protocol version.
 *
 * Depending on the protocol version, the random value is generated differently.
 * For instance, TLS 1.2 requested a timestamp in the random value. Also, when
 * downgrading to TLS 1.2 from a peer that could also negotiate TLS 1.3, the
 * random value must be slightly modified to signal the downgrade.
 */
std::vector<uint8_t> make_server_hello_random(RandomNumberGenerator& rng,
                                              Protocol_Version offered_version,
                                              Callbacks& cb,
                                              const Policy& policy);

/**
* Version-agnostic internal server hello data container that allows
* parsing Server_Hello messages without prior knowledge of the contained
* protocol version.
*/
class Server_Hello_Internal final {
   public:
      /**
       * Deserialize a Server Hello message
       */
      explicit Server_Hello_Internal(const std::vector<uint8_t>& buf);

      Server_Hello_Internal(Protocol_Version lv,
                            Session_ID sid,
                            std::vector<uint8_t> r,
                            const uint16_t cs,
                            const uint8_t cm,
                            bool is_hrr = false) :
            m_legacy_version(lv),
            m_session_id(std::move(sid)),
            m_random(std::move(r)),
            m_is_hello_retry_request(is_hrr),
            m_ciphersuite(cs),
            m_comp_method(cm) {}

      Protocol_Version version() const;

      Protocol_Version legacy_version() const { return m_legacy_version; }

      const Session_ID& session_id() const { return m_session_id; }

      const std::vector<uint8_t>& random() const { return m_random; }

      uint16_t ciphersuite() const { return m_ciphersuite; }

      uint8_t comp_method() const { return m_comp_method; }

      bool is_hello_retry_request() const { return m_is_hello_retry_request; }

      const Extensions& extensions() const { return m_extensions; }

      Extensions& extensions() { return m_extensions; }

   private:
      Protocol_Version m_legacy_version;
      Session_ID m_session_id;
      std::vector<uint8_t> m_random;
      bool m_is_hello_retry_request;
      uint16_t m_ciphersuite;
      uint8_t m_comp_method;

      Extensions m_extensions;
};

}  // namespace Botan::TLS

#endif
