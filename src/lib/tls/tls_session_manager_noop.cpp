/*
* TLS Session Manager Noop
* (C) 2011 Jack Lloyd
*     2023 René Meusel - Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/tls_session_manager_noop.h>

#include <botan/rng.h>
#include <botan/tls_session.h>

namespace Botan::TLS {

Session_Manager_Noop::Session_Manager_Noop() : Session_Manager(std::make_shared<Null_RNG>()) {}

std::optional<Session_Handle> Session_Manager_Noop::establish(const Session& /*session*/,
                                                              const std::optional<Session_ID>& /*session_id*/,
                                                              bool /*tls12_no_ticket*/) {
   return {};
}

std::optional<Session> Session_Manager_Noop::retrieve_one(const Session_Handle& /*handle*/) {
   return {};
}

std::vector<Session_with_Handle> Session_Manager_Noop::find_some(const Server_Information& /*info*/,
                                                                 size_t /*max_sessions_hint*/) {
   return {};
}

}  // namespace Botan::TLS
