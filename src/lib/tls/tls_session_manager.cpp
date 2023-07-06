/**
 * TLS Session Manger base class implementations
 * (C) 2011-2023 Jack Lloyd
 *     2022-2023 René Meusel - Rohde & Schwarz Cybersecurity
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#include <botan/tls_session_manager.h>

#include <botan/rng.h>
#include <botan/tls_callbacks.h>
#include <botan/tls_policy.h>

namespace Botan::TLS {

Session_Manager::Session_Manager(const std::shared_ptr<RandomNumberGenerator>& rng) : m_rng(rng) {
   BOTAN_ASSERT_NONNULL(m_rng);
}

std::optional<Session_Handle> Session_Manager::establish(const Session& session,
                                                         const std::optional<Session_ID>& id,
                                                         bool tls12_no_ticket) {
   // Establishing a session does not require locking at this level as
   // concurrent TLS instances on a server will create unique sessions.

   // By default, the session manager does not emit session tickets anyway
   BOTAN_UNUSED(tls12_no_ticket);
   BOTAN_ASSERT(session.side() == Connection_Side::Server, "Client tried to establish a session");

   Session_Handle handle(id.value_or(m_rng->random_vec<Session_ID>(32)));
   store(session, handle);
   return handle;
}

std::optional<Session> Session_Manager::retrieve(const Session_Handle& handle,
                                                 Callbacks& callbacks,
                                                 const Policy& policy) {
   // Retrieving a session for a given handle does not require locking on this
   // level. Concurrent threads might handle the removal of an expired ticket
   // more than once, but removing an already removed ticket is a harmless NOOP.

   auto session = retrieve_one(handle);
   if(!session.has_value()) {
      return std::nullopt;
   }

   // A value of '0' means: No policy restrictions.
   const std::chrono::seconds policy_lifetime =
      (policy.session_ticket_lifetime().count() > 0) ? policy.session_ticket_lifetime() : std::chrono::seconds::max();

   // RFC 5077 3.3 -- "Old Session Tickets"
   //    A server MAY treat a ticket as valid for a shorter or longer period of
   //    time than what is stated in the ticket_lifetime_hint.
   //
   // RFC 5246 F.1.4 -- TLS 1.2
   //    If either party suspects that the session may have been compromised, or
   //    that certificates may have expired or been revoked, it should force a
   //    full handshake.  An upper limit of 24 hours is suggested for session ID
   //    lifetimes.
   //
   // RFC 8446 4.6.1 -- TLS 1.3
   //    A server MAY treat a ticket as valid for a shorter period of time than
   //    what is stated in the ticket_lifetime.
   //
   // Note: This disregards what is stored in the session (e.g. "lifetime_hint")
   //       and only takes the local policy into account. The lifetime stored in
   //       the sessions was taken from the same policy anyways and changes by
   //       the application should have an immediate effect.
   const auto ticket_age =
      std::chrono::duration_cast<std::chrono::seconds>(callbacks.tls_current_timestamp() - session->start_time());
   const bool expired = ticket_age > policy_lifetime;

   if(expired) {
      remove(handle);
      return std::nullopt;
   } else {
      return session;
   }
}

std::vector<Session_with_Handle> Session_Manager::find_and_filter(const Server_Information& info,
                                                                  Callbacks& callbacks,
                                                                  const Policy& policy) {
   // A value of '0' means: No policy restrictions. Session ticket lifetimes as
   // communicated by the server apply regardless.
   const std::chrono::seconds policy_lifetime =
      (policy.session_ticket_lifetime().count() > 0) ? policy.session_ticket_lifetime() : std::chrono::seconds::max();

   const size_t max_sessions_hint = std::max(policy.maximum_session_tickets_per_client_hello(), size_t(1));
   const auto now = callbacks.tls_current_timestamp();

   // An arbitrary number of loop iterations to perform before giving up
   // to avoid a potential endless loop with a misbehaving session manager.
   constexpr unsigned int max_attempts = 10;
   std::vector<Session_with_Handle> sessions_and_handles;

   // Query the session manager implementation for new sessions until at least
   // one session passes the filter or no more sessions are found.
   for(unsigned int attempt = 0; attempt < max_attempts && sessions_and_handles.empty(); ++attempt) {
      sessions_and_handles = find_some(info, max_sessions_hint);

      // ... underlying implementation didn't find anything. Early exit.
      if(sessions_and_handles.empty()) {
         break;
      }

      // TODO: C++20, use std::ranges::remove_if() once XCode and Android NDK caught up.
      sessions_and_handles.erase(
         std::remove_if(sessions_and_handles.begin(),
                        sessions_and_handles.end(),
                        [&](const auto& session) {
                           const auto age =
                              std::chrono::duration_cast<std::chrono::seconds>(now - session.session.start_time());

                           // RFC 5077 3.3 -- "Old Session Tickets"
                           //    The ticket_lifetime_hint field contains a hint from the
                           //    server about how long the ticket should be stored. [...]
                           //    A client SHOULD delete the ticket and associated state when
                           //    the time expires. It MAY delete the ticket earlier based on
                           //    local policy.
                           //
                           // RFC 5246 F.1.4 -- TLS 1.2
                           //    If either party suspects that the session may have been
                           //    compromised, or that certificates may have expired or been
                           //    revoked, it should force a full handshake.  An upper limit of
                           //    24 hours is suggested for session ID lifetimes.
                           //
                           // RFC 8446 4.2.11.1 -- TLS 1.3
                           //    The client's view of the age of a ticket is the time since the
                           //    receipt of the NewSessionTicket message.  Clients MUST NOT
                           //    attempt to use tickets which have ages greater than the
                           //    "ticket_lifetime" value which was provided with the ticket.
                           //
                           // RFC 8446 4.6.1 -- TLS 1.3
                           //    Clients MUST NOT cache tickets for longer than 7 days,
                           //    regardless of the ticket_lifetime, and MAY delete tickets
                           //    earlier based on local policy.
                           //
                           // Note: TLS 1.3 tickets with a lifetime longer than 7 days are
                           //       rejected during parsing with an "Illegal Parameter" alert.
                           //       Other suggestions are left to the application via
                           //       Policy::session_ticket_lifetime(). Session lifetimes as
                           //       communicated by the server via the "lifetime_hint" are
                           //       obeyed regardless of the policy setting.
                           const auto session_lifetime_hint = session.session.lifetime_hint();
                           const bool expired = age > std::min(policy_lifetime, session_lifetime_hint);

                           if(expired) {
                              remove(session.handle);
                           }

                           return expired;
                        }),
         sessions_and_handles.end());
   }

   return sessions_and_handles;
}

std::vector<Session_with_Handle> Session_Manager::find(const Server_Information& info,
                                                       Callbacks& callbacks,
                                                       const Policy& policy) {
   auto allow_reusing_tickets = policy.reuse_session_tickets();

   // Session_Manager::find() must be an atomic getter if ticket reuse is not
   // allowed. I.e. each ticket handed to concurrently requesting threads must
   // be unique. In that case we must hold a lock while retrieving a ticket.
   // Otherwise, no locking is required on this level.
   std::optional<lock_guard_type<recursive_mutex_type>> lk;
   if(!allow_reusing_tickets) {
      lk.emplace(mutex());
   }

   auto sessions_and_handles = find_and_filter(info, callbacks, policy);

   // std::vector::resize() cannot be used as the vector's members aren't
   // default constructible.
   const auto session_limit = policy.maximum_session_tickets_per_client_hello();
   while(session_limit > 0 && sessions_and_handles.size() > session_limit) {
      sessions_and_handles.pop_back();
   }

   // RFC 8446 Appendix C.4
   //    Clients SHOULD NOT reuse a ticket for multiple connections. Reuse of
   //    a ticket allows passive observers to correlate different connections.
   //
   // When reuse of session tickets is not allowed, remove all tickets to be
   // returned from the implementation's internal storage.
   if(!allow_reusing_tickets) {
      // The lock must be held here, otherwise we cannot guarantee the
      // transactional retrieval of tickets to concurrently requesting clients.
      BOTAN_ASSERT_NOMSG(lk.has_value());
      for(const auto& [session, handle] : sessions_and_handles) {
         if(!session.version().is_pre_tls_13() || !handle.is_id()) {
            remove(handle);
         }
      }
   }

   return sessions_and_handles;
}

#if defined(BOTAN_HAS_TLS_13)

std::optional<std::pair<Session, uint16_t>> Session_Manager::choose_from_offered_tickets(
   const std::vector<PskIdentity>& tickets,
   std::string_view hash_function,
   Callbacks& callbacks,
   const Policy& policy) {
   // Note that the TLS server currently does not ensure that tickets aren't
   // reused. As a result, no locking is required on this level.

   for(uint16_t i = 0; const auto& ticket : tickets) {
      auto session = retrieve(Opaque_Session_Handle(ticket.identity()), callbacks, policy);
      if(session.has_value() && session->ciphersuite().prf_algo() == hash_function &&
         session->version().is_tls_13_or_later()) {
         return std::pair{std::move(session.value()), i};
      }

      // RFC 8446 4.2.10
      //    For PSKs provisioned via NewSessionTicket, a server MUST validate
      //    that the ticket age for the selected PSK identity [...] is within a
      //    small tolerance of the time since the ticket was issued.  If it is
      //    not, the server SHOULD proceed with the handshake but reject 0-RTT,
      //    and SHOULD NOT take any other action that assumes that this
      //    ClientHello is fresh.
      //
      // TODO: The ticket-age is currently not checked (as 0-RTT is not
      //       implemented) and we simply take the SHOULD at face value.
      //       Instead we could add a policy check letting the user decide.

      ++i;
   }

   return std::nullopt;
}

#endif

}  // namespace Botan::TLS
