/**
 * Wrapper type for a TLS 1.3 session ticket
 * (C) 2023 Jack Lloyd
 *     2023 René Meusel - Rohde & Schwarz Cybersecurity
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#include <botan/tls_psk_identity_13.h>

#include <botan/internal/stl_util.h>

namespace Botan::TLS {

namespace {

uint32_t obfuscate_ticket_age(const uint64_t in, const uint64_t ticket_age_add) {
   // RFC 8446 4.2.11.1
   //    The "obfuscated_ticket_age" field of each PskIdentity contains an
   //    obfuscated version of the ticket age formed by taking the age in
   //    milliseconds and adding the "ticket_age_add" value that was included
   //    with the ticket, modulo 2^32.
   return static_cast<uint32_t>(in + ticket_age_add);
}

}  // namespace

PskIdentity::PskIdentity(Opaque_Session_Handle identity,
                         const std::chrono::milliseconds age,
                         const uint32_t ticket_age_add) :
      PskIdentity(std::move(identity.get()), obfuscate_ticket_age(age.count(), ticket_age_add)) {}

PskIdentity::PskIdentity(PresharedKeyID identity) :
      m_identity(to_byte_vector(identity.get())),

      // RFC 8446 4.2.11
      //    For identities established externally, an obfuscated_ticket_age of
      //    0 SHOULD be used, and servers MUST ignore the value.
      m_obfuscated_age(0) {}

std::chrono::milliseconds PskIdentity::age(const uint32_t ticket_age_add) const {
   return std::chrono::milliseconds(obfuscate_ticket_age(m_obfuscated_age, ticket_age_add));
}

std::string PskIdentity::identity_as_string() const {
   return Botan::to_string(m_identity);
}

}  // namespace Botan::TLS
