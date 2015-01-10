/*
* SQLite TLS Session Manager
* (C) 2012 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/tls_session_manager_sqlite.h>
#include <botan/sqlite3.h>

namespace Botan {

namespace TLS {

Session_Manager_SQLite::Session_Manager_SQLite(const std::string& passphrase,
                                               RandomNumberGenerator& rng,
                                               const std::string& db_filename,
                                               size_t max_sessions,
                                               std::chrono::seconds session_lifetime) :
   Session_Manager_SQL(std::make_shared<Sqlite3_Database>(db_filename),
                       passphrase,
                       rng,
                       max_sessions,
                       session_lifetime)
   {}

}

}
