/**
 * TLS 1.3 Preshared Key identity and importer
 * (C) 2023 Jack Lloyd
 *     2023 René Meusel - Rohde & Schwarz Cybersecurity
 *     2023 Fabian Albert, René Meusel - Rohde & Schwarz Cybersecurity
 *     2025,2026 Jack Lloyd
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#ifndef BOTAN_TLS_PSK_13_H_
#define BOTAN_TLS_PSK_13_H_

#include <botan/strong_type.h>
#include <botan/tls_external_psk.h>
#include <botan/tls_session.h>  // TODO remove this dep
#include <botan/tls_version.h>
#include <botan/types.h>
#include <chrono>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace Botan::TLS {

/// @brief holds a PSK identity as used in TLS 1.3
using PresharedKeyID = Strong<std::string, struct PresharedKeyID_>;

/**
 * Represents a TLS 1.3 PSK identity as found in the Preshared Key extension
 * with an opaque identity and an associated (obfuscated) ticket age. The latter
 * is not applicable for externally provided PSKs.
 */
class BOTAN_PUBLIC_API(3, 1) PskIdentity {
   public:
      /**
       * Construct from information provided in the peer's ClientHello
       */
      PskIdentity(std::vector<uint8_t> identity, const uint32_t obfuscated_age) :
            m_identity(std::move(identity)), m_obfuscated_age(obfuscated_age) {}

      /**
       * Construct from a session stored by the client
       */
      PskIdentity(Opaque_Session_Handle identity, std::chrono::milliseconds age, uint32_t ticket_age_add);

      /**
       * Construct from an externally provided PSK in the client
       */
      BOTAN_FUTURE_EXPLICIT PskIdentity(PresharedKeyID identity);

      const std::vector<uint8_t>& identity() const { return m_identity; }

      std::string identity_as_string() const;

      /**
       * If this represents a PSK for session resumption, it returns the
       * session's age given the de-obfuscation parameter @p ticket_age_add. For
       * externally provided PSKs this method does not provide any meaningful
       * information.
       */
      std::chrono::milliseconds age(uint32_t ticket_age_add) const;

      uint32_t obfuscated_age() const { return m_obfuscated_age; }

   private:
      std::vector<uint8_t> m_identity;
      uint32_t m_obfuscated_age;
};

/**
 * Botan 3.0.0 used the class name "Ticket". In Botan 3.1.0 we decided to
 * re-name it to the more generic term "PskIdentity" to better reflect its dual
 * use case for resumption and externally provided PSKs.
 */
BOTAN_DEPRECATED("Use PskIdentity") typedef PskIdentity Ticket;

/**
 * RFC 9258 PSK Importer.
 *
 * Holds the base key material and identity for a pre-shared key and
 * derives imported PSKs for specific TLS protocol versions and cipher
 * suite hash algorithms using the PSK importer mechanism
 */
class BOTAN_PUBLIC_API(3, 12) PSKImporter {
   public:
      /**
       * @param key the base pre-shared key
       * @param identity the external PSK identity
       * @param context optional importer context
       * @param hash the hash algorithm provisioned with this PSK ("SHA-256" or "SHA-384")
       *        which defaults to SHA-256 due to RFC 9258's "If the EPSK does not have [...]
       *        an associated hash function, SHA-256 SHOULD be used."
       */
      PSKImporter(std::span<const uint8_t> key,
                  std::span<const uint8_t> identity,
                  std::span<const uint8_t> context,
                  std::string_view hash = "SHA-256");

      /**
       * Derive an imported PSK for the given target protocol version and
       * cipher suite hash algorithm.
       *
       * @param version target TLS protocol version (must be TLS 1.3)
       * @param target_hash hash algorithm of the target cipher suite ("SHA-256" or "SHA-384")
       * @return an ExternalPSK ready for use in a TLS 1.3 handshake
       */
      ExternalPSK derive_imported_psk(Protocol_Version version, std::string_view target_hash) const;

      ExternalPSK derive_imported_psk(Protocol_Version version,
                                      std::string_view target_hash,
                                      const CryptoOperations& crypto) const;

   private:
      secure_vector<uint8_t> m_key;
      std::vector<uint8_t> m_identity;
      std::vector<uint8_t> m_context;
      std::string m_hash;
};

}  // namespace Botan::TLS

#endif
