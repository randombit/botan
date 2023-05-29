/*
* TLS Session Manager Noop
* (C) 2011 Jack Lloyd
*     2023 René Meusel - Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/tls_session_manager_noop.h>

#include <botan/rng.h>

namespace Botan::TLS {

Session_Manager_Noop::Session_Manager_Noop() : Session_Manager(std::make_shared<Null_RNG>()) {}

}  // namespace Botan::TLS
