/**
 * TLS Stateless Session Manager for stateless servers
 * (C) 2023 Jack Lloyd
 *     2023 René Meusel - Rohde & Schwarz Cybersecurity
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#include <botan/tls_session_manager_stateless.h>

#include <botan/assert.h>
#include <botan/credentials_manager.h>
#include <botan/exceptn.h>
#include <botan/rng.h>
#include <botan/tls_session.h>

namespace Botan::TLS {

Session_Manager_Stateless::Session_Manager_Stateless(const std::shared_ptr<Credentials_Manager>& creds,
                                                     const std::shared_ptr<RandomNumberGenerator>& rng) :
      Session_Manager(rng), m_credentials_manager(creds) {
   BOTAN_ASSERT_NONNULL(m_credentials_manager);
}

std::vector<Session_with_Handle> Session_Manager_Stateless::find_some(const Server_Information& /*info*/,
                                                                      size_t /*max_sessions_hint*/) {
   return {};
}

std::optional<Session_Handle> Session_Manager_Stateless::establish(const Session& session,
                                                                   const std::optional<Session_ID>& /*session_id*/,
                                                                   bool tls12_no_ticket) {
   BOTAN_ASSERT(session.side() == Connection_Side::Server, "Client tried to establish a session");
   if(tls12_no_ticket) {
      return std::nullopt;
   }

   const auto key = get_ticket_key();
   if(!key.has_value()) {
      return std::nullopt;
   }

   return Session_Handle(Session_Ticket{session.encrypt(key.value(), *m_rng)});
}

void Session_Manager_Stateless::store(const Session& /*session*/, const Session_Handle& /*handle*/) {
   throw Invalid_Argument("A stateless Session Manager cannot store Sessions with their handle");
}

std::optional<Session> Session_Manager_Stateless::retrieve_one(const Session_Handle& handle) {
   auto ticket = handle.ticket();
   if(!ticket.has_value()) {
      return std::nullopt;
   }

   const auto key = get_ticket_key();
   if(!key.has_value()) {
      return std::nullopt;
   }

   try {
      return Session::decrypt(ticket.value(), key.value());
   } catch(const std::exception&) {
      // RFC 8446 4.2.11
      //    Any unknown PSKs (e.g., ones not in the PSK database or encrypted
      //    with an unknown key) SHOULD simply be ignored.
      return std::nullopt;
   }
}

bool Session_Manager_Stateless::emits_session_tickets() {
   return get_ticket_key().has_value();
}

std::optional<SymmetricKey> Session_Manager_Stateless::get_ticket_key() noexcept {
   try {
      auto key = m_credentials_manager->psk("tls-server", "session-ticket", "");
      if(key.empty()) {
         return std::nullopt;
      }
      return key;
   } catch(...) {
      return std::nullopt;
   }
}

}  // namespace Botan::TLS
