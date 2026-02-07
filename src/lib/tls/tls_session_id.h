/*
* (C) 2022 René Meusel - Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_TLS_SESSION_ID_H_
#define BOTAN_TLS_SESSION_ID_H_

#include <botan/strong_type.h>
#include <botan/types.h>
#include <algorithm>
#include <optional>
#include <variant>
#include <vector>

namespace Botan::TLS {

// Different flavors of session handles are used, depending on the usage
// scenario and the TLS protocol version.

/// @brief holds a TLS 1.2 session ID for stateful resumption
using Session_ID = Strong<std::vector<uint8_t>, struct Session_ID_>;

/// @brief holds a TLS 1.2 session ticket for stateless resumption
using Session_Ticket = Strong<std::vector<uint8_t>, struct Session_Ticket_>;

/// @brief holds an opaque session handle as used in TLS 1.3 that could be
///        either a ticket for stateless resumption or a database handle.
using Opaque_Session_Handle = Strong<std::vector<uint8_t>, struct Opaque_Session_Handle_>;

inline auto operator<(const Session_ID& id1, const Session_ID& id2) {
   // TODO: C++20 better use std::lexicographical_compare_three_way
   //       that was not available on all target platforms at the time
   //       of this writing.
   return std::lexicographical_compare(id1.begin(), id1.end(), id2.begin(), id2.end());
}

/**
 * @brief Helper class to embody a session handle in all protocol versions
 *
 * Sessions in TLS 1.2 are identified by an arbitrary and unique ID of up to
 * 32 bytes or by a self-contained arbitrary-length ticket (RFC 5077).
 *
 * TLS 1.3 does not distinct between the two and handles both as tickets. Also
 * a TLS 1.3 server can issue multiple tickets in one connection and the
 * resumption mechanism is compatible with the PSK establishment.
 *
 * Concrete implementations of Session_Manager use this helper to distinguish
 * the different states and manage sessions for TLS 1.2 and 1.3 connections.
 *
 * Note that all information stored in a Session_Handle might be transmitted in
 * unprotected form. Hence, it should not contain any confidential information.
 */
class BOTAN_PUBLIC_API(3, 0) Session_Handle {
   public:
      // NOLINTBEGIN(*-explicit-conversions)

      /**
       * Constructs a Session_Handle from a session ID which is an
       * arbitrary byte vector that must be 32 bytes long at most.
       */
      Session_Handle(Session_ID id) : m_handle(std::move(id)) { validate_constraints(); }

      /**
       * Constructs a Session_Handle from a session ticket which is a
       * non-empty byte vector that must be 64kB long at most.
       * Typically, tickets facilitate stateless server implementations
       * and contain all relevant context in encrypted/authenticated form.
       *
       * Note that (for technical reasons) we enforce that tickets are
       * longer than 32 bytes.
       */
      Session_Handle(Session_Ticket ticket) : m_handle(std::move(ticket)) { validate_constraints(); }

      /**
       * Constructs a Session_Handle from an Opaque_Handle such as TLS 1.3
       * uses them in its resumption mechanism. This could be either a
       * Session_ID or a Session_Ticket and it is up to the Session_Manager
       * to figure out what it actually is.
       */
      Session_Handle(Opaque_Session_Handle ticket) : m_handle(std::move(ticket)) { validate_constraints(); }

      // NOLINTEND(*-explicit-conversions)

      bool is_id() const { return std::holds_alternative<Session_ID>(m_handle); }

      bool is_ticket() const { return std::holds_alternative<Session_Ticket>(m_handle); }

      bool is_opaque_handle() const { return std::holds_alternative<Opaque_Session_Handle>(m_handle); }

      /**
       * Returns the Session_Handle as an opaque handle. If the object was not
       * constructed as an Opaque_Session_Handle, the contained value is
       * converted.
       */
      Opaque_Session_Handle opaque_handle() const;

      /**
       * If the Session_Handle was constructed with a Session_ID or an
       * Opaque_Session_Handle that can be converted to a Session_ID (up to
       * 32 bytes long), this returns the handle as a Session_ID. Otherwise,
       * std::nullopt is returned.
       */
      std::optional<Session_ID> id() const;

      /**
       * If the Session_Handle was constructed with a Session_Ticket or an
       * Opaque_Session_Handle this returns the handle as a Session_ID.
       * Otherwise, std::nullopt is returned.
       */
      std::optional<Session_Ticket> ticket() const;

      decltype(auto) get() const { return m_handle; }

   private:
      void validate_constraints() const;

   private:
      std::variant<Session_ID, Session_Ticket, Opaque_Session_Handle> m_handle;
};

}  // namespace Botan::TLS

#endif
