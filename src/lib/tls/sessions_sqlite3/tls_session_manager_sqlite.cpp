/*
* SQLite TLS Session Manager
* (C) 2012 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/tls_session_manager_sqlite.h>

#include <botan/sqlite3.h>

namespace Botan::TLS {

Session_Manager_SQLite::Session_Manager_SQLite(std::string_view passphrase,
                                               const std::shared_ptr<RandomNumberGenerator>& rng,
                                               std::string_view db_filename,
                                               size_t max_sessions) :
      Session_Manager_SQL(std::make_shared<Sqlite3_Database>(db_filename), passphrase, rng, max_sessions) {}

}  // namespace Botan::TLS
