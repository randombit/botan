/**
 * TLS Session Management
 * (C) 2011,2012 Jack Lloyd
 *     2023 René Meusel - Rohde & Schwarz Cybersecurity
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#include <botan/tls_session_manager_memory.h>

#include <botan/rng.h>
#include <botan/internal/stl_util.h>
#include <algorithm>
#include <functional>
#include <tuple>

namespace Botan::TLS {

Session_Manager_In_Memory::Session_Manager_In_Memory(const std::shared_ptr<RandomNumberGenerator>& rng,
                                                     size_t max_sessions) :
      Session_Manager(rng), m_max_sessions(max_sessions) {
   if(max_sessions > 0) {
      m_fifo.emplace();
   }
}

void Session_Manager_In_Memory::store(const Session& session, const Session_Handle& handle) {
   // TODO: C++20 allows CTAD for template aliases (read: lock_guard_type), so
   //       technically we should be able to omit the explicit mutex type.
   //       Unfortunately clang does not agree, yet.
   const lock_guard_type<recursive_mutex_type> lk(mutex());

   if(m_fifo.has_value()) {
      while(m_sessions.size() >= capacity()) {
         BOTAN_ASSERT_NOMSG(m_sessions.size() <= m_fifo->size());
         m_sessions.erase(m_fifo->front());
         m_fifo->pop_front();
      }
   }

   // Generate a random session ID if the peer did not provide one. Note that
   // this ID is just for internal use and won't be returned on ::find().
   auto id = handle.id().value_or(m_rng->random_vec<Session_ID>(32));
   m_sessions.emplace(id, Stored_Session{Session_with_Handle{session, handle}, m_next_sequence_number++});

   if(m_fifo.has_value()) {
      m_fifo->emplace_back(std::move(id));
   }
}

std::optional<Session> Session_Manager_In_Memory::retrieve_one(const Session_Handle& handle) {
   const lock_guard_type<recursive_mutex_type> lk(mutex());

   if(auto id = handle.id()) {
      const auto session = m_sessions.find(id.value());
      if(session != m_sessions.end()) {
         return session->second.session_and_handle.session;
      }
   }

   return std::nullopt;
}

std::vector<Session_with_Handle> Session_Manager_In_Memory::find_some(const Server_Information& info,
                                                                      const size_t max_sessions_hint) {
   BOTAN_UNUSED(max_sessions_hint);

   const lock_guard_type<recursive_mutex_type> lk(mutex());

   std::vector<std::reference_wrapper<const Stored_Session>> matches;
   for(const auto& [_, stored] : m_sessions) {
      if(stored.session_and_handle.session.server_info() == info) {
         matches.emplace_back(stored);
      }
   }

   // Prefer the most recently established session, i.e. the freshest ticket.
   // Insertion order breaks ties, e.g. between tickets received within the
   // same connection or from applications with a coarse-grained clock.
   std::ranges::sort(matches, [](const Stored_Session& a, const Stored_Session& b) {
      const auto a_start = a.session_and_handle.session.start_time();
      const auto b_start = b.session_and_handle.session.start_time();
      return std::tie(a_start, a.sequence_number) > std::tie(b_start, b.sequence_number);
   });

   std::vector<Session_with_Handle> found_sessions;
   found_sessions.reserve(matches.size());
   for(const Stored_Session& stored : matches) {
      found_sessions.emplace_back(stored.session_and_handle);
   }

   return found_sessions;
}

size_t Session_Manager_In_Memory::remove(const Session_Handle& handle) {
   const lock_guard_type<recursive_mutex_type> lk(mutex());
   return remove_internal(handle);
}

size_t Session_Manager_In_Memory::remove_internal(const Session_Handle& handle) {
   return std::visit(overloaded{
                        // We deliberately leave the deleted session in m_fifo. Finding it would be
                        // another O(n) operation. Instead, purging will run in a loop and skip m_fifo
                        // entries that were not found anymore.
                        [&](const Session_Ticket& ticket) -> size_t {
                           // TODO: This is an O(n) operation. Typically, the Session_Manager will
                           //       not contain a plethora of sessions and this should be fine. If
                           //       it's not, we'll need to consider another index on tickets.
                           return std::erase_if(m_sessions, [&](const auto& item) {
                              const auto& [_unused1, stored] = item;
                              const auto& [_unused2, this_handle] = stored.session_and_handle;
                              // TLS 1.3 clients store their tickets as Opaque_Session_Handle
                              const auto this_ticket = this_handle.ticket();
                              return this_ticket.has_value() && this_ticket.value() == ticket;
                           });
                        },
                        [&](const Session_ID& id) -> size_t { return m_sessions.erase(id); },
                        [&](const Opaque_Session_Handle&) -> size_t {
                           if(auto id = handle.id()) {
                              auto removed = remove_internal(Session_Handle(id.value()));
                              if(removed > 0) {
                                 return removed;
                              }
                           }

                           if(auto ticket = handle.ticket()) {
                              return remove_internal(Session_Handle(ticket.value()));
                           }

                           return 0;
                        },
                     },
                     handle.get());
}

size_t Session_Manager_In_Memory::remove_all() {
   const lock_guard_type<recursive_mutex_type> lk(mutex());

   const auto sessions = m_sessions.size();
   m_sessions.clear();
   if(m_fifo.has_value()) {
      m_fifo->clear();
   }

   return sessions;
}

}  // namespace Botan::TLS
