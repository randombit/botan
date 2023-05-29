/**
 * Hybrid Session Manager that emits both IDs and Tickets
 * (C) 2023 Jack Lloyd
 *     2023 René Meusel - Rohde & Schwarz Cybersecurity
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#include <botan/tls_session_manager_hybrid.h>

#include <botan/rng.h>

#include <functional>

namespace Botan::TLS {

Session_Manager_Hybrid::Session_Manager_Hybrid(std::unique_ptr<Session_Manager> stateful,
                                               const std::shared_ptr<Credentials_Manager>& credentials_manager,
                                               const std::shared_ptr<RandomNumberGenerator>& rng,
                                               bool prefer_tickets) :
      Session_Manager(rng),
      m_stateful(std::move(stateful)),
      m_stateless(credentials_manager, rng),
      m_prefer_tickets(prefer_tickets) {
   BOTAN_ASSERT_NONNULL(m_stateful);
}

std::optional<Session_Handle> Session_Manager_Hybrid::establish(const Session& session,
                                                                const std::optional<Session_ID>& id,
                                                                bool tls12_no_ticket) {
   auto create_ticket = [&]() -> std::optional<Session_Handle> {
      if(tls12_no_ticket) {
         return std::nullopt;
      }

      auto ticket_handle = m_stateless.establish(session, id, false /* always allow tickets */);
      BOTAN_ASSERT_IMPLICATION(ticket_handle.has_value(),
                               ticket_handle->is_ticket(),
                               "Session_Manager_Stateless produced unexpected Session_Handle");
      return ticket_handle;
   };

   auto create_id = [&] {
      // If we're dealing with a TLS 1.2 connection, we opportunistically
      // disable tickets for the underlying manager.
      auto id_handle = m_stateful->establish(session, id, session.version().is_pre_tls_13());
      BOTAN_ASSERT_IMPLICATION(
         id_handle.has_value(), id_handle->is_id(), "Session_Manager_In_Memory produced unexpected Session_Handle");
      return id_handle;
   };

   std::function preferred = create_ticket;
   std::function fallback = create_id;

   if(!m_prefer_tickets) {
      std::swap(preferred, fallback);
   }

   if(auto result = preferred()) {
      return result;
   }

   return fallback();
}

std::optional<Session> Session_Manager_Hybrid::retrieve(const Session_Handle& handle,
                                                        Callbacks& callbacks,
                                                        const Policy& policy) {
   std::reference_wrapper<Session_Manager> preferred = m_stateless;
   std::reference_wrapper<Session_Manager> fallback = *m_stateful;

   if(!m_prefer_tickets) {
      std::swap(preferred, fallback);
   }

   if(auto session = preferred.get().retrieve(handle, callbacks, policy)) {
      return session;
   }

   return fallback.get().retrieve(handle, callbacks, policy);
}

bool Session_Manager_Hybrid::emits_session_tickets() {
   return m_stateless.emits_session_tickets() || m_stateful->emits_session_tickets();
}

}  // namespace Botan::TLS
