/**
 * Wrapper type for a TLS 1.3 session ticket
 * (C) 2023 Jack Lloyd
 *     2023 René Meusel - Rohde & Schwarz Cybersecurity
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#ifndef BOTAN_TLS_13_TICKET_H_
#define BOTAN_TLS_13_TICKET_H_

#include <botan/tls_session.h>
#include <botan/types.h>

#include <chrono>
#include <cstdint>
#include <vector>

namespace Botan::TLS {

/**
 * Represents a TLS 1.3 ticket with an opaque identity and an associated
 * (obfuscated) ticket age.
 *
 * RFC 8446 4.6.1
 *    The ticket itself is an opaque label. It MAY be either a database
 *    lookup key or a self-encrypted and self-authenticated value.
 */
class BOTAN_PUBLIC_API(3, 0) Ticket {
   public:
      Ticket(Opaque_Session_Handle identity, const uint32_t obfuscated_age) :
            m_identity(std::move(identity)), m_obfuscated_age(obfuscated_age) {}

      Ticket(Opaque_Session_Handle identity, const std::chrono::milliseconds age, const uint32_t ticket_age_add);

      const Opaque_Session_Handle& identity() const { return m_identity; }

      std::chrono::milliseconds age(const uint32_t ticket_age_add) const;

      uint32_t obfuscated_age() const { return m_obfuscated_age; }

   private:
      Opaque_Session_Handle m_identity;
      uint32_t m_obfuscated_age;
};

}  // namespace Botan::TLS

#endif
